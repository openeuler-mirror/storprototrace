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
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "addon_bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int verbose = 0;

#define trace_log(fmt, ...)                    \
    do {                                       \
	if (verbose)                           \
            bpf_printk(fmt, ##__VA_ARGS__);    \
    } while(0)


#define DEFINE_VAR(TYPE, SIZE)			\
struct {					\
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);\
	__uint(max_entries, SIZE);		\
	__type(key, uint32_t);			\
	__type(value, struct TYPE);		\
} TYPE SEC(".maps");

#define INIT_VAR() \
uint32_t VAR_KEY=0;

#define USE_VAR(TYPE, NAME, INDEX)						\
VAR_KEY=INDEX;									\
struct TYPE *NAME = bpf_map_lookup_elem(&TYPE, &VAR_KEY); if(!NAME) return 0;

DEFINE_VAR(iscsi_task, 1);
DEFINE_VAR(iscsi_conn, 1);
DEFINE_VAR(iscsi_session, 1);

static inline void *scsi_cmd_priv(struct scsi_cmnd *cmd)
{
    return cmd + 1;
}

static inline struct iscsi_cmd *iscsi_cmd(struct scsi_cmnd *cmd)
{
    return scsi_cmd_priv(cmd);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct iscsi_connection);
    __type(value, struct iscsi_time);
    __uint(max_entries, 1024);
} time_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct iscsi_connection);
    __type(value, struct iscsi_stats);
    __uint(max_entries, 1024);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct request *);
	__type(value, struct request_info);
	__uint(max_entries, 1024);
} request_map SEC(".maps");

static __always_inline int bpf_probe_read_ptr(void *dst, size_t size, const void *src) {
    return bpf_probe_read_kernel(dst, size, src);
}

static int get_cid(struct iscsi_task *task)
{
    struct iscsi_conn *conn;
    bpf_probe_read(&conn, sizeof(conn), &task->conn);
    if (!conn) {
        return 0;
    }

    int cid = 0;
    bpf_probe_read(&cid, sizeof(cid), &conn->id);

    return cid;
}

static int get_sid(struct iscsi_task *task)
{
    struct iscsi_conn *conn;
    bpf_probe_read(&conn, sizeof(conn), &task->conn);
    if (!conn) {
        return 0;
    }

    struct iscsi_session *session;
    bpf_probe_read(&session, sizeof(session), &conn->session);
    if (!session) {
        return 0;
    }

    struct iscsi_cls_session *cls_session;
    bpf_probe_read(&cls_session, sizeof(cls_session), &session->cls_session);
    if (!cls_session) {
        return 0;
    }
    int sid = 0;
    bpf_probe_read(&sid, sizeof(sid), &cls_session->sid);

    return sid;
}

static inline __attribute__((always_inline)) int
get_targetname(struct iscsi_stats *stats, struct iscsi_task *task)
{
    INIT_VAR();
    USE_VAR(iscsi_task, taskp, 0);
    USE_VAR(iscsi_conn, conn, 0);
    USE_VAR(iscsi_session, session, 0);

    bpf_probe_read(taskp, sizeof(struct iscsi_task), task);
    bpf_probe_read(conn, sizeof(struct iscsi_conn), taskp->conn);
    bpf_probe_read(session, sizeof(struct iscsi_session), conn->session);
    bpf_probe_read_str(stats->target_name, sizeof(stats->target_name),
                        session->targetname);

    return 0;
}

static inline __attribute__((always_inline)) int
get_initiator(struct iscsi_stats *stats, struct iscsi_task *task)
{
    INIT_VAR();
    USE_VAR(iscsi_task, taskp, 0);
    if (stats == NULL || task == NULL)
        return 1;

    bpf_probe_read(taskp, sizeof(struct iscsi_task), task);
    bpf_probe_read_str(stats->initiator_name, sizeof(stats->initiator_name),
                        BPF_CORE_READ(taskp, conn, session, initiatorname));
    return 0;
}

static void get_lun(struct iscsi_stats *stats, struct iscsi_task *task)
{
    if (stats == NULL || task == NULL)
        return;

    bpf_probe_read_ptr(stats->lun, sizeof(stats->lun), &task->lun);
}

static int get_op(struct iscsi_task *task)
{
    int flag = 0;
    int op = OP_READ;

    flag = (int)BPF_CORE_READ(task, sc->sc_data_direction);
    if (op_is_write(flag))
        op = OP_WRITE;

    return op;
}

SEC("fexit/iscsi_queuecommand")
int BPF_PROG(iscsi_queuecommand, struct Scsi_Host *host, struct scsi_cmnd *sc)
{
    struct workqueue_struct *wq;
    bpf_probe_read(&wq, sizeof(wq), &((struct iscsi_host *)host->hostdata)->workq);

    if (!wq) {
        bpf_printk("Get iscsi work queue error\n");
        return 0;
    }

    struct iscsi_task *task = (struct iscsi_task *)BPF_CORE_READ(iscsi_cmd(sc), task);
    if (!task) {
        bpf_printk("Get iscsi task error\n");
        return 0;
    }

    struct iscsi_connection conn = {};
    conn.cid = get_cid(task);
    conn.sid = get_sid(task);

    struct iscsi_time zero_time = {};
    struct iscsi_time *time = bpf_map_lookup_elem(&time_map, &conn);
    if (!time) {
        bpf_map_update_elem(&time_map, &conn, &zero_time, BPF_NOEXIST);
        time = bpf_map_lookup_elem(&time_map, &conn);
    }

    if (time) {
        if (time->queue_time == 0) {
            time->queue_time = bpf_ktime_get_ns();
            trace_log("Get queue time,now queue = %llu, send = %llu, complete = %llu\n",
                      time->queue_time, time->prep_send_time, time->complete_time);
        }
    } else {
        bpf_printk("Failed to find or initialize time struct in iscsi_queuecommand.\n");
    }

    return 0;
}


SEC("kprobe/iscsi_prep_scsi_cmd_pdu")
int BPF_KPROBE(kpiscsi_prep_scsi_cmd_pdu, struct iscsi_task *task)
{
    __u64 queue_time = 0;
    struct iscsi_connection conn = {};
    conn.cid = get_cid(task);
    conn.sid = get_sid(task);

    struct iscsi_time *time = bpf_map_lookup_elem(&time_map, &conn);
    if (time) {
        if (time->prep_send_time == 0) {
            time->prep_send_time = bpf_ktime_get_ns();
            trace_log("Get perp send time,now queue = %llu, send = %llu, complete = %llu\n",
                      time->queue_time, time->prep_send_time, time->complete_time);
        }
    } else {
        bpf_printk("Failed to find or initialize time struct in iscsi_prep_scsi_cmd_pdu.\n");
    }

    return 0;
}

SEC("kprobe/iscsi_complete_task")
int BPF_KPROBE(kpiscsi_complete_task, struct iscsi_task *task, int state)
{
    struct scsi_cmnd *sc;
    struct iscsi_time *time;
    struct iscsi_stats zero_stats = {};
    struct iscsi_stats *stats;

    if (state != ISCSI_TASK_COMPLETED) 
        return 0;

    bpf_probe_read(&sc, sizeof(sc), &task->sc);
    if (!sc) {
        return 0;
    }

    struct iscsi_connection conn = {};
    conn.cid = get_cid(task);
    conn.sid = get_sid(task);

    stats = bpf_map_lookup_elem(&stats_map, &conn);
    if (!stats) {
        bpf_map_update_elem(&stats_map, &conn, &zero_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&stats_map, &conn);
    }

    if (stats == NULL) {
        return 0;
    }

    // 获取targetname
    get_targetname(stats, task);
    // 获取initiator
    get_initiator(stats, task);

    stats->cid = conn.cid;
    stats->sid = conn.sid;

    time = bpf_map_lookup_elem(&time_map, &conn);
    if (time && state == ISCSI_TASK_COMPLETED && time->complete_time == 0) {
        time->complete_time = bpf_ktime_get_ns();
        trace_log("Get complete time,now queue = %llu, send = %llu, complete = %llu\n",
                  time->queue_time, time->prep_send_time, time->complete_time);

        int bytes = 0;
        bpf_probe_read(&bytes, sizeof(bytes), &sc->sdb.length);

        if (time->queue_time != 0) {
            stats->waiting = time->prep_send_time - time->queue_time;
            stats->waiting_cycle++;
            if (stats->waiting > stats->max_waiting) {
                stats->max_waiting = stats->waiting;
            }

            stats->complete = time->complete_time - time->queue_time;
            stats->complete_cycle++;
            if (stats->complete > stats->max_complete) {
                stats->max_complete = stats->complete;
            }
        }

        if (time->prep_send_time != 0) {
            stats->sending = time->complete_time - time->prep_send_time;
            stats->send_cycle++;
            if (stats->sending > stats->max_sending) {
                stats->max_sending = stats->sending;
            }
        }

        stats->count++;
        stats->total_bytes += bytes;

        // 更新统计信息并删除时间记录
        bpf_map_update_elem(&stats_map, &conn, stats, BPF_EXIST);
        trace_log("Update stats map, now count = %u, waiting = %llu, sending = %llu, complete = %llu\n",
                  stats->count, stats->waiting, stats->sending, stats->complete);
        bpf_map_delete_elem(&time_map, &conn);
    }

    return 0;
}

// D point
SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *rq)
{
	struct request_info *req;

	req = bpf_map_lookup_elem(&request_map, &rq);
	if (req) {
		req->dispatch_time = bpf_ktime_get_ns();

		bpf_map_update_elem(&request_map, &rq, req, BPF_NOEXIST);
	}

	return 0;
}

// C point
SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error, unsigned int nr_bytes)
{
	struct request_info *req;

	req = bpf_map_lookup_elem(&request_map, &rq);
	if (req) {
		req->req = rq;
		req->complete_time = bpf_ktime_get_ns();
		req->result = error;

		bpf_map_update_elem(&request_map, &rq, req, BPF_NOEXIST);
	}

	if (error)
		trace_log("block_rq_complete rq 0x%llu error %d", rq, error);

	return 0;
}

// I point
SEC("tp_btf/block_rq_insert")
int BPF_PROG(block_rq_insert, struct request *rq)
{
	struct request_info ri, *req;

	req = bpf_map_lookup_elem(&request_map, &rq);
	if (!req) {
		ri.req = rq;
		ri.insert_time = bpf_ktime_get_ns();
		ri.result = 0;

		bpf_map_update_elem(&request_map, &rq, &ri, BPF_NOEXIST);
	}

	return 0;
}

