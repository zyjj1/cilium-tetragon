// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __RATE_H__
#define __RATE_H__

#include "bpf_tracing.h"
#include "bpf_helpers.h"

struct cgroup_rate_key {
	__u64 id;
};

struct cgroup_rate_value {
	__u64 curr;
	__u64 prev;
	__u64 time;
	__u64 rate;
	__u64 throttled;
};

struct cgroup_rate_options {
	__u64 events;
	__u64 interval;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct cgroup_rate_key);
	__type(value, struct cgroup_rate_value);
} cgroup_rate_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cgroup_rate_options);
} cgroup_rate_options_map SEC(".maps");

#define NS (1000ULL * 1000ULL * 1000UL)

static inline __attribute__((always_inline)) bool
cgroup_rate(void *ctx, struct msg_k8s *kube, __u64 time)
{
	struct cgroup_rate_options *opt;
	struct cgroup_rate_key key = {
		.id = kube->cgrpid,
	};
	struct cgroup_rate_value *val;
	__u64 delta, interval, slide;
	__u32 zero = 0;

	opt = map_lookup_elem(&cgroup_rate_options_map, &zero);
	if (!opt)
		return true;

	interval = opt->interval;
	if (!interval)
		return true;

	val = map_lookup_elem(&cgroup_rate_map, &key);
	if (!val) {
		struct cgroup_rate_value new_value = {
			.time = (time / interval) * interval,
			.curr = 1,
		};

		map_update_elem(&cgroup_rate_map, &key, &new_value, 0);
		return true;
	}

	/*
	 * We split the time in interval windows and keep track of events
	 * of events count in current (val->curr) and previous (val->prev)
	 * intervals.
	 */

	delta = time - val->time;
	if (delta > interval) {
		if (delta > 2 * interval) {
			val->prev = 0;
			val->time = (time / interval) * interval;
		} else {
			val->prev = val->curr;
			val->time += interval;
		}
		val->curr = 0;
	}

	val->curr++;

	/*
	 * We compute the size of the slide window in previous interval and
	 * based on that we compute partial amount of events from previous
	 * interval window. Then we add current interval count and we have
	 * rate value.
	 *
	 *                       val->time
	 *                       |
	 *   <--- interval ----->|<--- interval ----->|
	 *                       |
	 *    val->prev          | val->curr
	 *   |-------------------|-----------
	 *         val->rate
	 *        |-------------------|
	 *                            time
	 */

	slide = interval - (time - val->time);
	val->rate = (slide * val->prev) / interval + val->curr;

	if (!val->throttled && val->rate >= opt->events)
		val->throttled = time;

	return !val->throttled;
}

#endif /* __RATE_H__ */
