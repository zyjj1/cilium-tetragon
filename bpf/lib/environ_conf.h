// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __ENVIRON_CONF_
#define __ENVIRON_CONF_

/* Tetragon runtime configuration */
struct tetragon_conf {
	__u32 tg_cgrp_hierarchy; /* Tetragon tracked hierarchy ID */
	__u32 tg_cgrp_subsys_idx; /* Tetragon tracked cgroup subsystem state index at compile time */
};

struct bpf_map_def __attribute__((section("maps"), used)) tg_conf_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__s32),
	.value_size = sizeof(struct tetragon_conf),
	.max_entries = 1,
};

#endif // __ENVIRON_CONF_
