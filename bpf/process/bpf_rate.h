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
};

struct cgroup_rate_settings {
	__u64 tokens;
	__u64 interval_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, struct cgroup_rate_key);
	__type(value, struct cgroup_rate_value);
} cgroup_rate_map SEC(".maps");

static inline __attribute__((always_inline)) bool
cgroup_rate(struct cgroup_rate_key *key, __u64 ns,
	    const struct cgroup_rate_settings *settings)
{
	struct cgroup_rate_value *value, new_value;
	__u64 since_lastns;

	value = map_lookup_elem(&cgroup_rate_map, key);
	if (value == NULL) {
		new_value.lastns = ns;
		new_value.tokens = settings->tokens - 1;
		map_update_elem(&cgroup_rate_map, key, &new_value, BPF_ANY);
		return true;
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

	return false;
}

#endif /* __RATE_H__ */
