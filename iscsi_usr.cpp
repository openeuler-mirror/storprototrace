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

#include "iscsi_stats_ebpf.h"
#include "cli_parser.h"

extern bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}


int main(int argc, char *argv[])
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (!cli_parser(argc, argv))
	    return 1;

    if (!iscsi_stats_ebpf_load_and_attach())
    	return 1;

    printf("BPF program loaded and attached successfully.\n");
    printf("%-11s | %-21s | %-47s | %-47s | %-64s | %-64s | %-32s\n","Connect", "RW", "Toal Interval(ns)", "Max Interval(ns)", "initiator", "target", "LUN");
    printf("%-5s %-5s | %-10s %-10s | %-15s %-15s %-15s | %-15s %-15s %-15s | %-64s | %-64s | %-32s\n",
		    "sid", "cid", "Count", "total","Waiting", "Sending", "Complete", "Waiting", "Sending", "Complete", "name", "name", "lun");

    if (!iscsi_stats_ebpf_loop(filter_apply))
		return 1;

    return 0;
}

