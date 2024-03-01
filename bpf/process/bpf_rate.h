// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __RATE_H__
#define __RATE_H__

#include "bpf_tracing.h"
#include "bpf_time.h"

struct cgroup_rate_key {
	__u8 op;
	__u8 pad[7];
	__u64 cgroupid;
};

struct cgroup_rate_value {
	__u64 lastns;
	__u64 tokens;
	__u64 throttlens;
};

struct cgroup_rate_settings {
	__u64 tokens;
	__u64 interval_ns;
	__u64 throttle_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, struct cgroup_rate_key);
	__type(value, struct cgroup_rate_value);
} cgroup_rate_map SEC(".maps");

struct msg_throttle {
	struct msg_common common;
	struct msg_execve_key current;
	__u8 type;
	__u8 event;
	__u8 pad[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_throttle);
} throttle_heap_map SEC(".maps");

enum {
	CGROUP_RATE_THROTTLE_NONE,
	CGROUP_RATE_THROTTLE_START,
	CGROUP_RATE_THROTTLE_STOP,
};

static inline __attribute__((always_inline)) bool
cgroup_rate(struct cgroup_rate_key *key, __u64 ns,
	    const struct cgroup_rate_settings *settings,
	    int *throttle)
{
	bool do_throttle = settings->throttle_ns != 0;
	struct cgroup_rate_value *value, new_value;
	__u64 since_lastns;

	*throttle = CGROUP_RATE_THROTTLE_NONE;

	value = map_lookup_elem(&cgroup_rate_map, key);
	if (value == NULL) {
		new_value.lastns = ns;
		new_value.tokens = settings->tokens - 1;
		new_value.throttlens = 0;
		map_update_elem(&cgroup_rate_map, key, &new_value, BPF_ANY);
		return true;
	}

	if (do_throttle && value->throttlens) {
		__u64 delta = ns - value->throttlens;

		if (delta < settings->throttle_ns)
			return false;
		*throttle = CGROUP_RATE_THROTTLE_STOP;
		value->throttlens = 0;
	}

	since_lastns = ns - value->lastns;
	if (since_lastns > settings->interval_ns) {
		value->tokens = settings->tokens;
		value->lastns = ns;
	}

	if (value->tokens > 0) {
		value->tokens--;
		return true;
	}

	if (do_throttle) {
		value->throttlens = ns;
		*throttle = CGROUP_RATE_THROTTLE_START;
	}

	return false;
}

static inline __attribute__((always_inline)) void
send_throttle(struct sched_execve_args *ctx, __u8 throttle, __u8 event)
{
	struct msg_throttle *msg;
	struct execve_map_value *curr;
	size_t size;
	__u32 pid;

	if (throttle == CGROUP_RATE_THROTTLE_NONE)
		return;

	msg = map_lookup_elem(&throttle_heap_map, &(__u32){ 0 });
	if (!msg)
		return;

	pid = (get_current_pid_tgid() >> 32);
	curr = execve_map_get_noinit(pid);
	if (!curr)
		return;

	msg->current.pid = curr->key.pid;
	msg->current.ktime = curr->key.ktime;

	msg->common.size = size = sizeof(*msg);
	msg->common.ktime = ktime_get_ns();
	msg->common.op = MSG_OP_THROTTLE;
	msg->common.flags = 0;

	msg->type = throttle;
	msg->event = event;

	perf_event_output_metric(ctx, MSG_OP_THROTTLE, &tcpmon_map,
				 BPF_F_CURRENT_CPU, msg, size);
}

static inline __attribute__((always_inline)) bool
execve_cgroup_rate(struct sched_execve_args *ctx)
{
	struct cgroup_rate_key key = { .op = EVENT_EXECVE };
	struct cgroup_rate_settings settings = {
		.tokens      = 1000,
		.interval_ns = 1*NSEC_PER_SEC,
		.throttle_ns = 5*NSEC_PER_SEC,
	};
	struct msg_execve_event *msg;
	int throttle;
	bool send;

	msg = map_lookup_elem(&execve_msg_heap_map, &(__u32){ 0 });
	if (!msg)
		return 0;

	key.cgroupid = msg->kube.cgrpid;
	send = cgroup_rate(&key, msg->common.ktime, &settings, &throttle);
	send_throttle(ctx, throttle, MSG_OP_EXECVE);
	return send;
}

#endif /* __RATE_H__ */
