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
    unsigned int interface_id;
} wtap_can_msg_t;

#define WTAP_SOCKETCAN_INVALID_INTERFACE_ID     0xFFFFFFFF

/* Setup a wiretap to use SOCKETCAN encapsulation format */
extern void
wtap_set_as_socketcan(wtap* wth, int file_type_subtype, int tsprec, void* tap_priv, void (*tap_close)(void*));

/* Helper function to generate a SOCKETCAN packet from provided CAN data */
extern bool
wtap_socketcan_gen_packet(wtap* wth, wtap_rec* rec, const wtap_can_msg_t* msg, char* module_name, int* err, char** err_info);

/* Find or create a PCAPNG interface block
 * Return value is the interface ID used for the packet
 */
extern uint32_t
wtap_socketcan_find_or_create_new_interface(wtap* wth, const char* name);

/* Access to a wiretap's individual private data */
extern void*
wtap_socketcan_get_private_data(wtap* wth);

#endif  /* SOCKETCAN_H__ */
