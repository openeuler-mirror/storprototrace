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
#ifndef __COMMON_H
#define __COMMON_H

enum {
	ISCSI_TASK_FREE,
	ISCSI_TASK_COMPLETED,
};

struct iscsi_stats {
    unsigned int sid;
    unsigned int cid;
    char  target_name[64];
    char  initiator_name[64];
    char  lun[64];
    unsigned long count;
    unsigned long total_bytes;
    unsigned long waiting;
    unsigned long waiting_cycle;
    unsigned long sending;
    unsigned long send_cycle;
    unsigned long complete;
    unsigned long complete_cycle;
    unsigned long max_waiting;
    unsigned long max_sending;
    unsigned long max_complete;
};

extern int op_is_write(unsigned int op);

void print_stats(struct iscsi_stats *stats);
int filt_targetname_print_stats(struct iscsi_stats *stats, const char *targetname);

#endif /* __COMMON_H */
