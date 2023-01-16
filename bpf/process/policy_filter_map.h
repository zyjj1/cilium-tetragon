// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef POLICY_FILTER_MAPS_H__
#define POLICY_FILTER_MAPS_H__

#include "bpf_tracing.h"

#define POLICY_FILTER_MAX_POLICIES 128

struct policy_filter_key {
	u64 policy_id;
	u64 cgroup_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, POLICY_FILTER_MAX_POLICIES);
	__uint(key_size, sizeof(u64)); /* policy id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u64);    /* group id */
			__type(value, __u8);   /* empty  */
		});
} policy_filter_maps SEC(".maps");

#endif /* POLICY_FILTER_MAPS_H__ */
