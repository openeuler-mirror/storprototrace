/*
 * Copyright (c) KylinSoft Co., Ltd. 2024-2025.All rights reserved.
 * storprototrace is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *         http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "iscsi_stats_ebpf.h"
#include "iscsi_stats.skel.h"
#include "cli_parser.h"
#include "common.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <vector>

bool exiting = false;

static struct iscsi_stats_bpf *skel;

struct reported_stats {
    struct iscsi_stats_key key;
    unsigned long count;
};

static std::vector<struct reported_stats> last_reported_stats;

static bool same_stats_key(const struct iscsi_stats_key *left,
                           const struct iscsi_stats_key *right)
{
    return left->sid == right->sid && left->cid == right->cid &&
           left->direction == right->direction &&
           memcmp(left->lun, right->lun, sizeof(left->lun)) == 0;
}

static bool stats_changed(const struct iscsi_stats_key *key,
                          const struct iscsi_stats *stats)
{
    /* Ignore entries for tasks that never produced a complete sample. */
    if (stats->count == 0)
        return false;

    for (struct reported_stats &reported : last_reported_stats) {
        if (!same_stats_key(&reported.key, key))
            continue;

        if (reported.count == stats->count)
            return false;

        reported.count = stats->count;
        return true;
    }

    last_reported_stats.push_back({*key, stats->count});
    return true;
}

static void forget_stats(const struct iscsi_stats_key *key)
{
    for (auto it = last_reported_stats.begin(); it != last_reported_stats.end(); ++it) {
        if (same_stats_key(&it->key, key)) {
            last_reported_stats.erase(it);
            return;
        }
    }
}

bool iscsi_stats_ebpf_load_and_attach() {
    int err;
    // open skeleton
    skel = iscsi_stats_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return false;
    }

	// verbose to ebpf
	skel->rodata->verbose = FLAGS_verbose;

    // load BPF 
    err = iscsi_stats_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // attach BPF
    err = iscsi_stats_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    return true;
cleanup:
    iscsi_stats_bpf__destroy(skel);
    return false;
}


bool iscsi_stats_ebpf_loop(int(*handle)(struct iscsi_stats *stats)) {
    struct iscsi_stats stats = {};
    struct iscsi_stats_key key = {};
    struct iscsi_stats_key next_key;
    int err=0;
    int map_fd;
    map_fd = bpf_map__fd(skel->maps.stats_map);
    while (!exiting && !err) {
        sleep(FLAGS_interval);
        memset(&key, 0, sizeof(struct iscsi_stats_key));
        while (!exiting) {
            err = bpf_map_get_next_key(map_fd, &key, &next_key);
            if (err) {
                if (errno == ENOENT) {
                    err = 0;
                } else {
                    fprintf(stderr, "Failed to get next key: %s\n", strerror(errno));
                }
                break;
            }
            err = bpf_map_lookup_elem(map_fd, &next_key, &stats);
            if (err) {
                fprintf(stderr, "Failed to lookup map element: %s\n", strerror(errno));
                break;
            }
            if (stats_changed(&next_key, &stats))
                handle(&stats);
            if (FLAGS_once) {
                if (bpf_map_delete_elem(map_fd, &next_key)) {
                    fprintf(stderr, "Failed to delete map element: %s\n", strerror(errno));
                }
                forget_stats(&next_key);
            }
            key = next_key;
        }
    }

    iscsi_stats_bpf__destroy(skel);
    return err == 0;
}
