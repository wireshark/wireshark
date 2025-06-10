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
#include <wtap-int.h>

#define CAN_MAX_DLEN   8
#define CANFD_MAX_DLEN 64

typedef enum {
    MSG_TYPE_STD,
    MSG_TYPE_EXT,
    MSG_TYPE_STD_RTR,
    MSG_TYPE_EXT_RTR,
    MSG_TYPE_STD_FD,
    MSG_TYPE_EXT_FD,
    MSG_TYPE_ERR,
} wtap_can_msg_type_t;

typedef struct {
    uint8_t    length;
    uint8_t    data[CANFD_MAX_DLEN];
} wtap_can_msg_data_t;

typedef struct {
    nstime_t   ts;
    uint32_t   id;
    wtap_can_msg_type_t type;
    uint8_t    flags;
    wtap_can_msg_data_t data;
} wtap_can_msg_t;

extern void
wtap_set_as_socketcan(wtap* wth, int file_type_subtype, int tsprec);

extern bool
wtap_socketcan_gen_packet(wtap* wth, wtap_rec* rec, const wtap_can_msg_t* msg, char* module_name, int* err, char** err_info);

#endif  /* SOCKETCAN_H__ */
