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

#ifndef __ADDON_BPF_H
#define __ADDON_BPF_H

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

/*
 * trace IO request based on ISCSI
 */
struct request_info {
    struct request *req;
    struct scsi_cmnd *cmnd;

    u64 queue_time;     // Q
    u64 getrq_time;     // G
    u64 insert_time;    // I
    u64 dispatch_time;  // D
    u64 complete_time;  // C

    u64 iscsi_q_time;   // iscsi_task queue time
    u64 iscsi_p_time;   // iscsi_task pre send time
    u64 iscsi_c_time;   // iscsi_task complete time

    int result;         // status code from LLD
};

struct iscsi_cmd {
    struct iscsi_task       *task;
    int                     age;
};

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

struct iscsi_time {
    __u64 queue_time;
    __u64 prep_send_time;
    __u64 complete_time;
};

#endif /* __ADDON_BPF_H */