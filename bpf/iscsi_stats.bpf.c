#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct iscsi_time {
    __u64 queue_time;
    __u64 prep_send_time;
    __u64 complete_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct scsi_cmnd *);
    __type(value, struct iscsi_time);
    __uint(max_entries, 1024);
} time_map SEC(".maps");

struct {
    //__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct iscsi_stats);
    __uint(max_entries, 1024);
} stats_map SEC(".maps");

SEC("kprobe/iscsi_queuecommand")
int BPF_KPROBE(kpiscsi_queuecommand, struct Scsi_Host *host, struct scsi_cmnd *sc)
{
    struct iscsi_time zero_time = {};
    struct iscsi_time *time = bpf_map_lookup_elem(&time_map, &sc);
    
    if (!time) {
        bpf_map_update_elem(&time_map, &sc, &zero_time, BPF_NOEXIST);
        time = bpf_map_lookup_elem(&time_map, &sc);
    }

    if (time) {
        if (time->queue_time == 0) {
            time->queue_time = bpf_ktime_get_ns();
            bpf_printk("Get queue time,now queue = %llu, send = %llu, complete = %llu\n",
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
    struct scsi_cmnd *sc;
    bpf_probe_read(&sc, sizeof(sc), &task->sc);

    if (!sc) {
        return 0;
    }

    struct iscsi_time *time = bpf_map_lookup_elem(&time_map, &sc);
    if (time) {
        if (time->prep_send_time == 0) {
            time->prep_send_time = bpf_ktime_get_ns();
            bpf_printk("Get perp send time,now queue = %llu, send = %llu, complete = %llu\n",
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
    __u64 sc_ptr;
    struct iscsi_time *time;
    struct iscsi_stats zero_stats = {};
    struct iscsi_stats *stats;
    
    if (state != ISCSI_TASK_COMPLETED) 
        return 0;

    bpf_probe_read(&sc, sizeof(sc), &task->sc);
    if (!sc) {
        return 0;
    }

    sc_ptr = (__u64)sc;

    stats = bpf_map_lookup_elem(&stats_map, &sc_ptr);
    if (!stats) {
        bpf_map_update_elem(&stats_map, &sc_ptr, &zero_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&stats_map, &sc_ptr);
    }

    if (stats == NULL) {
        return 0;
    }

    time = bpf_map_lookup_elem(&time_map, &sc_ptr);
    if (time && state == ISCSI_TASK_COMPLETED && time->complete_time == 0) {
        time->complete_time = bpf_ktime_get_ns();
        bpf_printk("Get complete time,now queue = %llu, send = %llu, complete = %llu\n",
                   time->queue_time, time->prep_send_time, time->complete_time);

        int op = flag;

        if (time->queue_time != 0) {
            stats->waiting = time->prep_send_time - time->queue_time;
            stats->waiting_cycle++;
            if (stats->waiting > stats->max_waiting) {
                stats->max_waiting = stats->waiting;
            }
        }

        if (time->prep_send_time != 0) {
            stats->sending = time->complete_time - time->prep_send_time;
            stats->send_cycle++;
            if (stats->sending > stats->max_sending) {
                stats->max_sending = stats->sending;
            }
        }

        if (time->queue_time != 0) {
            stats->complete = time->complete_time - time->queue_time;
            stats->complete_cycle++;
            if (stats->complete > stats->max_complete) {
                stats->max_complete = stats->complete;
            }
        }
	
	stats->count++;
        stats->total_bytes += bytes;

        // 更新统计信息并删除时间记录
        bpf_map_update_elem(&stats_map, &sc_ptr, stats, BPF_EXIST);
        bpf_printk("Update stats map, now count = %u, waiting = %llu, sending = %llu, complete = %llu\n",
                   stats->count, stats->waiting, stats->sending, stats->complete);
        bpf_map_delete_elem(&time_map, &sc_ptr);
    }

    return 0;
}

