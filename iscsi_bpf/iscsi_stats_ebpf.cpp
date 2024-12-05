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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

bool exiting = false;

static struct iscsi_stats_bpf *skel;

bool iscsi_stats_ebpf_load_and_attach() {
    int err;
    // open skeleton
    skel = iscsi_stats_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return false;
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
    return true;
cleanup:
    iscsi_stats_bpf__destroy(skel);
    return false;
}


bool iscsi_stats_ebpf_loop(int(*handle)(struct iscsi_stats *stats)) {
    struct iscsi_stats stats = {};
    __u64 key;
    __u64 next_key;
    int err=0;
    int map_fd;
    map_fd = bpf_map__fd(skel->maps.stats_map);
    while (!exiting && !err) {
        sleep(1);
        key = 0;
        int scan_count = 0; // 添加计数器，防止死循环
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
            handle(&stats);
            if (FLAGS_once) {
                if (bpf_map_delete_elem(map_fd, &next_key)) {
                    fprintf(stderr, "Failed to delete map element: %s\n", strerror(errno));
                }
            }
            key = next_key;

            // 增加扫描计数
            scan_count++;
            if (scan_count > 1000) { // 防止死循环
                fprintf(stderr, "Too many iterations, exiting...\n");
                break;
            }
        }
    }

    iscsi_stats_bpf__destroy(skel);
    return err == 0;
}
