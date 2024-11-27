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

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

struct iscsi_host {
    char *initiatorname;
    char *hwaddress;
    char *netdevv;
    wait_queue_head_t session_removal_wq;
    spinlock_t lock;
    int num_sessions;
    int state;
    struct workqueue_struct *workq;
    char workq_name[20];
};

struct iscsi_tm {
        uint8_t opcode;
        uint8_t flags;
        uint8_t rsvd1[2];
        uint8_t hlength;
        uint8_t dlength[3];
        struct scsi_lun lun;
        uint32_t itt;   
        uint32_t rtt;   
        __be32  cmdsn;
        __be32  exp_statsn;
        __be32  refcmdsn;
        __be32  exp_datasn;
        uint8_t rsvd2[8];
};

struct iscsi_pool {
        struct kfifo            queue;          
        void                    **pool;         
        int                     max;            
};

struct iscsi_cls_session {
        struct list_head sess_list;             
        struct iscsi_transport *transport;
        spinlock_t lock;
        struct work_struct block_work;
        struct work_struct unblock_work;
        struct work_struct scan_work;
        struct work_struct unbind_work;
        struct work_struct destroy_work;
        int recovery_tmo;
        bool recovery_tmo_sysfs_override;
        struct delayed_work recovery_work;

        struct workqueue_struct *workq;

        unsigned int target_id;
        bool ida_used;
        pid_t creator;
        int state;
        int target_state;     
        int sid;                                
        void *dd_data;                          
        struct device dev;      
};

struct iscsi_session {
        struct iscsi_cls_session *cls_session;
        struct mutex            eh_mutex;
        wait_queue_head_t       ehwait;         
        struct iscsi_tm         tmhdr;
        struct timer_list       tmf_timer;
        int                     tmf_state;      
        struct iscsi_task       *running_aborted_task;
        uint32_t                cmdsn;
        uint32_t                exp_cmdsn;
        uint32_t                max_cmdsn;
        uint32_t                queued_cmdsn;
        int                     abort_timeout;
        int                     lu_reset_timeout;
        int                     tgt_reset_timeout;
        int                     initial_r2t_en;
        unsigned short          max_r2t;
        int                     imm_data_en;
        unsigned                first_burst;
        unsigned                max_burst;
        int                     time2wait;
        int                     time2retain;
        int                     pdu_inorder_en;
        int                     dataseq_inorder_en;
        int                     erl;
        int                     fast_abort;
        int                     tpgt;
        char                    *username;
        char                    *username_in;
        char                    *password;
        char                    *password_in;
        char                    *targetname;
        char                    *targetalias;
        char                    *ifacename;
        char                    *initiatorname;
        char                    *boot_root;
        char                    *boot_nic;
        char                    *boot_target;
        char                    *portal_type;
        char                    *discovery_parent_type;
        uint16_t                discovery_parent_idx;
        uint16_t                def_taskmgmt_tmo;
        uint16_t                tsid;
        uint8_t                 auto_snd_tgt_disable;
        uint8_t                 discovery_sess;
        uint8_t                 chap_auth_en;
        uint8_t                 discovery_logout_en;
        uint8_t                 bidi_chap_en;
        uint8_t                 discovery_auth_optional;
        uint8_t                 isid[6];
        struct iscsi_transport  *tt;
        struct Scsi_Host        *host;
        struct iscsi_conn       *leadconn;      
        spinlock_t              frwd_lock;      
        spinlock_t              back_lock;      
        int                     state;          
        int                     age;            

        int                     scsi_cmds_max;  
        int                     cmds_max;       
        struct iscsi_task       **cmds;         
        struct iscsi_pool       cmdpool;        
        void                    *dd_data;       
};


struct iscsi_conn {
        struct iscsi_cls_conn   *cls_conn;      
        void                    *dd_data;       
        struct iscsi_session    *session;       
        int                     stop_stage;
        struct timer_list       transport_timer;
        unsigned long           last_recv;
        unsigned long           last_ping;
        int                     ping_timeout;
        int                     recv_timeout;
        struct iscsi_task       *ping_task;
        uint32_t                exp_statsn;
        uint32_t                statsn;
        int                     id;             
        int                     c_stage;        
        char                    *data;
        struct iscsi_task       *login_task;    
        struct iscsi_task       *task;          
        struct list_head        mgmtqueue;      
        struct list_head        cmdqueue;       
        struct list_head        requeue;        
        struct work_struct      xmitwork;       
        struct work_struct      recvwork;
        unsigned long           flags;          
        unsigned                max_recv_dlength; 
        unsigned                max_xmit_dlength; 
        int                     hdrdgst_en;
        int                     datadgst_en;
        int                     ifmarker_en;
        int                     ofmarker_en;
        int                     persistent_port;
        char                    *persistent_address;

        unsigned                max_segment_size;
        unsigned                tcp_xmit_wsf;
        unsigned                tcp_recv_wsf;
        uint16_t                keepalive_tmo;
        uint16_t                local_port;
        uint8_t                 tcp_timestamp_stat;
        uint8_t                 tcp_nagle_disable;
        uint8_t                 tcp_wsf_disable;
        uint8_t                 tcp_timer_scale;
        uint8_t                 tcp_timestamp_en;
        uint8_t                 fragment_disable;
        uint8_t                 ipv4_tos;
        uint8_t                 ipv6_traffic_class;
        uint8_t                 ipv6_flow_label;
        uint8_t                 is_fw_assigned_ipv6;
        char                    *local_ipaddr;
        uint64_t                txdata_octets;
        uint64_t                rxdata_octets;
        uint32_t                scsicmd_pdus_cnt;
        uint32_t                dataout_pdus_cnt;
        uint32_t                scsirsp_pdus_cnt;
        uint32_t                datain_pdus_cnt;
        uint32_t                r2t_pdus_cnt;
        uint32_t                tmfcmd_pdus_cnt;
        int32_t                 tmfrsp_pdus_cnt;
        uint32_t                eh_abort_cnt;
        uint32_t                fmr_unalign_cnt;
};

DEFINE_VAR(iscsi_conn, 1);
DEFINE_VAR(iscsi_session, 1);

static inline void *scsi_cmd_priv(struct scsi_cmnd *cmd)
{
    return cmd + 1;
}

struct iscsi_cmd {
    struct iscsi_task       *task;
    int                     age;
};

static inline struct iscsi_cmd *iscsi_cmd(struct scsi_cmnd *cmd)
{
    return scsi_cmd_priv(cmd);
}

struct iscsi_r2t_info {
    __be32 ttt;
    __be32 exp_statsn;
    uint32_t data_length;
    uint32_t data_offset;
    int data_count;
    int datasn;
    int sent;
};

struct iscsi_task {
    struct iscsi_hdr *hdr;
    unsigned short hdr_max;
    unsigned short hdr_len;
    uint32_t hdr_itt;
    __be32 cmdsn;
    struct scsi_lun lun;
    int itt;
    unsigned imm_count;
    struct iscsi_r2t_info unsol_r2t;
    char *data;
    unsigned data_count;
    struct scsi_cmnd *sc;
    struct iscsi_conn *conn;
    unsigned long last_xfer;
    unsigned long last_timeout;
    bool have_checked_conn;bool protected;int state;
    refcount_t refcount;
    struct list_head running;
    void *dd_data;
};

struct iscsi_connection {
    __u64 sid;
    __u64 cid;
};

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct iscsi_stats);
    __uint(max_entries, 1024);
} stats_map SEC(".maps");

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

static void get_initiator(struct iscsi_stats *stats, struct iscsi_task *task)
{
    if (stats == NULL || task == NULL)
        return;

    bpf_probe_read_ptr(stats->initiator_name, sizeof(stats->initiator_name), &task->conn->session->initiatorname);
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

SEC("kprobe/iscsi_queuecommand")
int BPF_KPROBE(kpiscsi_queuecommand, struct Scsi_Host *host, struct scsi_cmnd *sc)
{
    struct workqueue_struct *wq;
    bpf_probe_read(&wq, sizeof(wq), &((struct iscsi_host *)host->hostdata)->workq);

    if (wq) {
        return 0;
    }

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

    INIT_VAR();
    USE_VAR(iscsi_conn, conn, 0);
    USE_VAR(iscsi_session, session, 0);
    
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

    bpf_probe_read(conn, sizeof(struct iscsi_conn), BPF_CORE_READ(task,conn));
    bpf_probe_read(session, sizeof(struct iscsi_session), conn->session);
    bpf_probe_read_str(stats->target_name, sizeof(stats->target_name),
                        session->targetname);

    time = bpf_map_lookup_elem(&time_map, &sc_ptr);
    if (time && state == ISCSI_TASK_COMPLETED && time->complete_time == 0) {
        time->complete_time = bpf_ktime_get_ns();
        bpf_printk("Get complete time,now queue = %llu, send = %llu, complete = %llu\n",
                   time->queue_time, time->prep_send_time, time->complete_time);

        int bytes = 0;
        bpf_probe_read(&bytes, sizeof(bytes), &sc->sdb.length);

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

