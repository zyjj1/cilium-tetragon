// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __RATE_H__
#define __RATE_H__

#include "bpf_tracing.h"

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

#endif /* __RATE_H__ */
