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

const volatile bool verbose = 0;

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
    /* Each iSCSI task has an independent latency timeline. */
    __type(key, struct iscsi_task *);
    __type(value, struct iscsi_time);
    __uint(max_entries, 1024);
} time_map SEC(".maps");

struct {
    /* A task is allocated inside iscsi_queuecommand, so retain the
     * command timestamp until iscsi_prep_scsi_cmd_pdu receives the task. */
    /* Rejected commands do not reach the prep probe; LRU eviction bounds
     * their retained timestamps without affecting active commands. */
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct scsi_cmnd *);
    __type(value, __u64);
    __uint(max_entries, 1024);
} queue_time_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct iscsi_stats_key);
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
    struct iscsi_conn *conn = BPF_CORE_READ(task, conn);
    if (!conn) {
        return 0;
    }

    return BPF_CORE_READ(conn, id);
}

static int get_sid(struct iscsi_task *task)
{
    struct iscsi_conn *conn = BPF_CORE_READ(task, conn);
    if (!conn) {
        return 0;
    }

    struct iscsi_session *session = BPF_CORE_READ(conn, session);
    if (!session) {
        return 0;
    }

    struct iscsi_cls_session *cls_session = BPF_CORE_READ(session, cls_session);
    if (!cls_session) {
        return 0;
    }

    return BPF_CORE_READ(cls_session, sid);
}

static inline __attribute__((always_inline)) int
get_targetname(struct iscsi_stats *stats, struct iscsi_task *task)
{
    struct iscsi_session *session = BPF_CORE_READ(task, conn, session);
    char *targetname;

    if (!session)
        return 1;

    targetname = BPF_CORE_READ(session, targetname);
    bpf_probe_read_str(stats->target_name, sizeof(stats->target_name),
                        targetname);

    return 0;
}

static inline __attribute__((always_inline)) int
get_initiator(struct iscsi_stats *stats, struct iscsi_task *task)
{
    if (stats == NULL || task == NULL)
        return 1;

    bpf_probe_read_str(stats->initiator_name, sizeof(stats->initiator_name),
                        BPF_CORE_READ(task, conn, session, initiatorname));
    return 0;
}

// get_lun removed as it is now read directly into stats_key

static int get_op(struct scsi_cmnd *sc)
{
    int flag = DMA_NONE;
    int op = ISCSI_IO_READ;

    bpf_core_read(&flag, sizeof(flag), &sc->sc_data_direction);
    if (flag == DMA_TO_DEVICE)
        op = ISCSI_IO_WRITE;

    return op;
}

SEC("fentry/iscsi_queuecommand")
int BPF_PROG(iscsi_queuecommand_enter, struct Scsi_Host *host, struct scsi_cmnd *sc)
{
    __u64 queue_time = bpf_ktime_get_ns();

    bpf_map_update_elem(&queue_time_map, &sc, &queue_time, BPF_ANY);
    trace_log("Get queue time, now queue = %llu\n", queue_time);

    return 0;
}

SEC("kprobe/iscsi_prep_scsi_cmd_pdu")
int BPF_KPROBE(kpiscsi_prep_scsi_cmd_pdu, struct iscsi_task *task)
{
    struct scsi_cmnd *sc = BPF_CORE_READ(task, sc);
    __u64 *queue_time = bpf_map_lookup_elem(&queue_time_map, &sc);
    if (!queue_time)
        return 0;

    struct iscsi_time time = {};
    time.queue_time = *queue_time;
    time.prep_send_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&time_map, &task, &time, BPF_ANY);
    bpf_map_delete_elem(&queue_time_map, &sc);
    trace_log("Get prep send time, now queue = %llu, send = %llu\n",
              time.queue_time, time.prep_send_time);

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

    struct iscsi_stats_key stats_key = {};
    stats_key.cid = conn.cid;
    stats_key.sid = conn.sid;
    bpf_core_read(&stats_key.lun, sizeof(stats_key.lun), &task->lun.scsi_lun);
    stats_key.direction = get_op(sc);

    stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (!stats) {
        bpf_map_update_elem(&stats_map, &stats_key, &zero_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    }

    if (stats == NULL) {
        return 0;
    }

    // 获取targetname
    get_targetname(stats, task);
    // 获取initiator
    get_initiator(stats, task);
    // LUN is already read into stats_key
    __builtin_memcpy(stats->lun, stats_key.lun, sizeof(stats->lun));
    stats->direction = stats_key.direction;

    stats->cid = conn.cid;
    stats->sid = conn.sid;

    time = bpf_map_lookup_elem(&time_map, &task);
    if (time && state == ISCSI_TASK_COMPLETED && time->complete_time == 0) {
        time->complete_time = bpf_ktime_get_ns();
        trace_log("Get complete time,now queue = %llu, send = %llu, complete = %llu\n",
                  time->queue_time, time->prep_send_time, time->complete_time);

        int bytes = 0;
        unsigned long interval = 0;
        bpf_probe_read(&bytes, sizeof(bytes), &sc->sdb.length);

		if (time->queue_time == 0 ||
		    time->prep_send_time == 0 ||
		    time->prep_send_time < time->queue_time ||
		    time->complete_time < time->prep_send_time) {
			; // abnormal route, do nothing here
		} else {
			interval = time->prep_send_time - time->queue_time;
			stats->waiting += interval;
			if (interval > stats->max_waiting)
				stats->max_waiting = interval;

			interval = time->complete_time - time->queue_time;
			stats->complete += interval;
			if (interval > stats->max_complete)
				stats->max_complete = interval;

			interval = time->complete_time - time->prep_send_time;
			stats->sending += interval;
			if (interval > stats->max_sending)
				stats->max_sending = interval;

			stats->count++;
			stats->total_bytes += bytes;

			bpf_map_update_elem(&stats_map, &stats_key, stats, BPF_EXIST);
			trace_log("Update stats map, now count = %u, waiting = %llu, sending = %llu, complete = %llu\n",
					stats->count, stats->waiting, stats->sending, stats->complete);
		}

        // 更新统计信息并删除时间记录
        bpf_map_delete_elem(&time_map, &task);
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

		// The block request is complete, delete it from the map to prevent memory leak
		bpf_map_delete_elem(&request_map, &rq);
	}

	if (error)
		trace_log("block_rq_complete rq 0x%p error %d", rq, error);

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
