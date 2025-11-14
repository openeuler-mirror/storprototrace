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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <libgen.h>

#include "common.h"
#include "cli_parser.h"

#define OP_BITS 8
#define OP_MASK ((1 << OP_BITS) - 1)
#define bio_op(bi_opf) \
        (bi_opf & OP_MASK)

int op_is_write(unsigned int op)
{
        return (op & 1);
}

#define bio_data_dir(bi_opf) \
        (op_is_write(bio_op(bi_opf)) ? WRITE : READ)

void format_lun(char *buf, size_t size, uint8_t *lun)
{
    int i;

    for (i = 0; i < 8; i++)
        snprintf(buf++, size--, "%x", lun[i]);
}


void print_stats(struct iscsi_stats *stats) {

	char waiting[64];
	char sending[64];
	char complete[64];
	char buf[32];
	snprintf(waiting, sizeof(waiting), "%lu(%lu)", stats->waiting, stats->waiting_cycle);
	snprintf(sending, sizeof(sending), "%lu(%lu)", stats->sending, stats->send_cycle);
	snprintf(complete, sizeof(complete), "%lu(%lu)", stats->complete, stats->complete_cycle);
	format_lun(buf, sizeof(buf), stats->lun);

	printf("%-5u %-5u | %-10lu %-10lu | %-15s %-15s %-15s | %-15lu %-15lu %-15lu | %-64s | %-64s | %-32s\n",
			stats->sid, stats->cid,
			stats->count, stats->total_bytes,
			waiting, sending, complete,
			stats->max_waiting,
			stats->max_sending,
			stats->max_complete,
			stats->initiator_name,
			stats->target_name,
			buf);
}

int filter_targetname_print_stats(struct iscsi_stats *stats, const char *targetname) {
    if (strcmp(stats->target_name, targetname) == 0) {
        printf("targetname: %s\n", stats->target_name);
        print_stats(stats);
        printf("\n\n");
        return 0;
    }
    return 1;
}

int filter_initiatorname_print_stats(struct iscsi_stats *stats, const char *initiatorname)
{
    if(stats == NULL){
        printf("stats is NULL!\n");
        return 1;
    }
    else if(initiatorname == NULL){
        printf("initiatorname is NUll!\n");
        return 1;
    }

    if (strcmp(stats->initiator_name, initiatorname) == 0) {
        printf("initiatorname: %s\n", stats->initiator_name);
        print_stats(stats);
        printf("\n\n");
        return 0;
    }

    return 1;
}

int filter_sid_print_stats(struct iscsi_stats *stats, const unsigned int sid) {
    if (stats->sid == sid) {
        printf("sid: %u\n", stats->sid);
        print_stats(stats);
        printf("\n\n");
        return 0;
    }
    return 1;
}

int filter_cid_print_stats(struct iscsi_stats *stats, const unsigned int cid) {
    if (stats->cid == cid) {
        printf("cid: %u\n", stats->cid);
        print_stats(stats);
        printf("\n\n");
        return 0;
    }
    return 1;
}

int filter_apply(struct iscsi_stats *stats)
{
    bool has_filter = false;
    gflags::CommandLineFlagInfo info;
    if(GetCommandLineFlagInfo("cid" ,&info) && !info.is_default) {
        has_filter = true;
        if(!filter_cid_print_stats(stats, FLAGS_cid)) {
            return 0;
        }
    }
    if(GetCommandLineFlagInfo("sid" ,&info) && !info.is_default) {
        has_filter = true;
        if(!filter_sid_print_stats(stats, FLAGS_sid)) {
		return 0;
	}
    }
    if(GetCommandLineFlagInfo("target" ,&info) && !info.is_default) {
        has_filter = true;
        if(!filter_targetname_print_stats(stats, FLAGS_target.c_str())) {
		return 0;
	}
    }

    if (GetCommandLineFlagInfo("initiatorname", &info) && !info.is_default) {
        has_filter = true;

        if (!filter_initiatorname_print_stats(stats, FLAGS_initiatorname.c_str()))
			return 0;
    }

    if(!has_filter)
        print_stats(stats);
    return 0;
}
