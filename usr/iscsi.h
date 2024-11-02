#ifndef __ISCSI_H
#define __ISCSI_H

#include "common.h"

#define OP_READ  25
#define OP_WRITE 38

struct scsi_lun {
        __u8 scsi_lun[8];
};

#endif
