/** @file
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
    uint32_t can_id;                       /* 32 bit CAN_ID + EFF/RTR/ERR flags */
    uint8_t can_dlc;                      /* frame payload length in byte (0 .. CAN_MAX_DLEN) */
    uint8_t __pad;                        /* padding */
    uint8_t __res0;                       /* reserved / padding */
    uint8_t __res1;                       /* reserved / padding */
    uint8_t data[CAN_MAX_DLEN];
} can_frame_t;

typedef struct canfd_frame {
    uint32_t can_id;                       /* 32 bit CAN_ID + EFF flag */
    uint8_t len;                          /* frame payload length in byte */
    uint8_t flags;                        /* additional flags for CAN FD */
    uint8_t __res0;                       /* reserved / padding */
    uint8_t __res1;                       /* reserved / padding */
    uint8_t data[CANFD_MAX_DLEN];
} canfd_frame_t;

#endif  /* SOCKETCAN_H__ */
