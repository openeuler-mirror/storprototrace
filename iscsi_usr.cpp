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

#include "iscsi_stats_ebpf.h"

char *program = NULL;
struct cli_params {
	int cid;
	int sid;

	char *target;
	char *initatorname;
};

extern bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

void usage()
{
	fprintf(stdout, "Usgae: %s [-h] [-c CID] [-s SID] [-t TARGET] [-i INITATORNAME]\n", program);
}

/*
 * parse command args
 */
bool parse_args(int argc, char *argv[], struct cli_params *cli_params)
{
	int err, c;
	int cid, sid;
	int errno;

	program = basename(argv[0]);

	while ((c = getopt(argc, argv, "c:s:t:i:h")) != EOF) {
		switch (c) {
		case 'c':
			errno = 0;
			cid = strtol(optarg, NULL, 10);
			if (errno == ERANGE && (cid == INT_MAX || cid == INT_MIN))
				goto bad;

			cli_params->cid = cid;
			break;

		case 's':
			errno = 0;
			sid = strtol(optarg, NULL, 10);
			if (errno == ERANGE && (sid == INT_MAX || sid == INT_MIN))
				goto bad;

			cli_params->sid = sid;
			break;


		case 't':
			cli_params->target = optarg;
			break;

		case 'i':
			cli_params->target = optarg;
			break;

		case 'h':
			usage();
			break;

		default:
			break;
		}
	}

	return true;

bad:
	usage();
	return false;
}

int main(int argc, char *argv[])
{
	struct cli_params cli_params = {};

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

	if (!parse_args(argc, argv, &cli_params))
		return 1;

    if (!iscsi_stats_ebpf_load_and_attach())
    	return 1;

    printf("BPF program loaded and attached successfully.\n");
    printf("%-20s | %-45s  | %-50s\n", "RW", "Toal Interval(ns)", "Max Interval(ns)");
    printf("%-10s %-10s| %-15s %-15s %-15s| %-15s %-15s %-15s\n",
		    "Count", "total","Waiting", "Sending", "Complete", "Waiting", "Sending", "Complete");

    if (!iscsi_stats_ebpf_loop(print_stats))
		return 1;

    return 0;
}

