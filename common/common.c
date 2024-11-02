#include <stdio.h>
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

