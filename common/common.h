#ifndef __COMMON_H
#define __COMMON_H

//typedef unsigned long long __64;

enum {
	ISCSI_TASK_FREE,
	ISCSI_TASK_COMPLETED,
};

struct iscsi_stats {
    unsigned int sid;
    unsigned int cid;
    char  target_name[64];
    char  initiator_name[64];
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
    unsigned long queue_time;
    unsigned long prep_send_time;
};

struct iscsi_r2t_info {
        unsigned int            ttt;
        unsigned int            exp_statsn;
        unsigned int            data_length;
        unsigned int            data_offset;
        int                     data_count;
        int                     datasn;
        int                     sent;
};

struct iscsi_task {
        struct iscsi_hdr        *hdr;
        unsigned short          hdr_max;
        unsigned short          hdr_len;
        unsigned int            hdr_itt;
        unsigned int            cmdsn;
        unsigned char           lun[8];
        int                     itt;
        unsigned                imm_count;
        struct iscsi_r2t_info   unsol_r2t;
        char                    *data;
        unsigned                data_count;
        struct scsi_cmnd        *sc;
        struct iscsi_conn       *conn;
        unsigned long           last_xfer;
        unsigned long           last_timeout;
        bool                    have_checked_conn;
        bool                    protected;
        int                     state;
        int                     refcount;
        unsigned char           running[32];
        void                    *dd_data;
};

extern int op_is_write(unsigned int op);

#endif /* __COMMON_H */
