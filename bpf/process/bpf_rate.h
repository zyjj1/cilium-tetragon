// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __RATE_H__
#define __RATE_H__

#include "bpf_tracing.h"

struct execve_cgroup_rate {
	__u64 lastns;
	__u64 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, struct execve_cgroup_rate);
} execve_rate_map SEC(".maps");

#define MS 1000000ULL
#define NS 1000000000ULL
#define WND (5 * NS)
#define THRESHOLD (1000)

static inline __attribute__((always_inline)) int
execve_cgroupid_rate(struct sched_execve_args *ctx,
		     struct msg_execve_event *msg)
{
	struct msg_throttle_event *throttle;
	struct execve_cgroup_rate *ptr, data = {
		.count = 1,
	};
	uint64_t delta, rate, size;

	ptr = map_lookup_elem(&execve_rate_map, &msg->kube.cgrpid);
	if (ptr == NULL) {
		data.lastns = msg->common.ktime;
		map_update_elem(&execve_rate_map, &msg->kube.cgrpid, &data, BPF_ANY);
		return 1;
	}

	delta = msg->common.ktime - ptr->lastns;

	/* if we are pass the WND time window, update to 1 NS average */
	if (delta > WND) {
		ptr->lastns = msg->common.ktime - NS;
		ptr->count = ptr->count * NS / delta;
	}

	ptr->count++;

	rate = (NS * ptr->count) / delta;
	if (rate < THRESHOLD)
		return 1;

	/* send throttle message */
	throttle = (struct msg_throttle_event *) msg;
	throttle->common.op = MSG_OP_THROTTLE;
	throttle->common.flags = 0;
	throttle->rate = rate;

	size = sizeof(struct msg_common) +
		sizeof(struct msg_k8s) +
		sizeof(struct msg_execve_key) +
		sizeof(__u64) +
		sizeof(__u64);

	perf_event_output_metric(ctx, MSG_OP_THROTTLE, &tcpmon_map, BPF_F_CURRENT_CPU, throttle, size);
	return 0;
}

#endif /* __RATE_H__ */
