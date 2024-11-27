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

