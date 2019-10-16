/* socketcan.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Busmaster log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SOCKETCAN_H__
#define SOCKETCAN_H__

#include <gmodule.h>

#define CAN_MAX_DLEN   8
#define CANFD_MAX_DLEN 64

typedef struct can_frame {
    guint32 can_id;                       /* 32 bit CAN_ID + EFF/RTR/ERR flags */
    guint8  can_dlc;                      /* frame payload length in byte (0 .. CAN_MAX_DLEN) */
    guint8  __pad;                        /* padding */
    guint8  __res0;                       /* reserved / padding */
    guint8  __res1;                       /* reserved / padding */
    guint8  data[CAN_MAX_DLEN];
} can_frame_t;

typedef struct canfd_frame {
    guint32 can_id;                       /* 32 bit CAN_ID + EFF flag */
    guint8  len;                          /* frame payload length in byte */
    guint8  flags;                        /* additional flags for CAN FD */
    guint8  __res0;                       /* reserved / padding */
    guint8  __res1;                       /* reserved / padding */
    guint8  data[CANFD_MAX_DLEN];
} canfd_frame_t;

#endif  /* SOCKETCAN_H__ */
