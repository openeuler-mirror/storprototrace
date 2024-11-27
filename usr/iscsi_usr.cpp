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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <libgen.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common.h"
#include "iscsi_stats.skel.h"

static bool exiting = false;

void print_stats(struct iscsi_stats *stats) {

	char waiting[64];
	char sending[64];
	char complete[64];
	snprintf(waiting, sizeof(waiting), "%lu(%lu)", stats->waiting, stats->waiting_cycle);
	snprintf(sending, sizeof(sending), "%lu(%lu)", stats->sending, stats->send_cycle);
	snprintf(complete, sizeof(complete), "%lu(%lu)", stats->complete, stats->complete_cycle);

	printf("%-10lu %-10lu| %-15s %-15s %-15s| %-15lu %-15lu %-15lu\n",
			stats->count, stats->total_bytes,
			waiting, sending, complete,
			stats->max_waiting,
			stats->max_sending,
			stats->max_complete);
}

void filt_targetname_print_stats(struct iscsi_stats *stats, const char *targetname) {
    if (strcmp(stats->target_name, targetname) == 0) {
        printf("targetname: %s\n", stats->target_name);
        print_stats(stats);
        printf("\n\n");
    }
    return;
}

static void sig_handler(int sig)
{
	exiting = true;
}


int main() {
    struct bpf_map *map = NULL;
    struct iscsi_stats stats = {};
    __u64 key;
    __u64 next_key;
    int err;
    int map_fd;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    struct iscsi_stats_bpf *skel;

    // open skeleton
    skel = iscsi_stats_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

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
    printf("BPF program loaded and attached successfully.\n");
    printf("%-20s | %-45s  | %-50s\n", "RW", "Toal Interval(ns)", "Max Interval(ns)");
    printf("%-10s %-10s| %-15s %-15s %-15s| %-15s %-15s %-15s\n",
		    "Count", "total","Waiting", "Sending", "Complete", "Waiting", "Sending", "Complete");
    
    map_fd = bpf_map__fd(skel->maps.stats_map);
    while (true) {
	    sleep(1);
	    key = 0;
        while (true) {
            err = bpf_map_get_next_key(map_fd, &key, &next_key);
	    if (err) {
	        if (errno == ENOENT)
			err = 0;
		break;
	    }
            err = bpf_map_lookup_elem(map_fd, &next_key, &stats);
            if (err == 0) {
                print_stats(&stats);
            } else {
                fprintf(stderr, "Failed to lookup map element\n");
            }
	    if (exiting)
		break;
        }
        key = next_key;
	if (exiting)
		break;
    }

cleanup:
    iscsi_stats_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}

