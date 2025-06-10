/** @file
 *
 * Common functionality for all wiretaps handling SocketCAN encapsulation
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"
#include "socketcan.h"
#include <epan/dissectors/packet-socketcan.h>

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

void
wtap_set_as_socketcan(wtap* wth, int file_type_subtype, int tsprec)
{
    wth->file_type_subtype = file_type_subtype;
    wth->file_encap = WTAP_ENCAP_SOCKETCAN;
    wth->file_tsprec = tsprec;
}

bool
wtap_socketcan_gen_packet(wtap* wth, wtap_rec* rec, const wtap_can_msg_t* msg, char* module_name, int* err, char** err_info)
{
    bool is_fd = false,
         is_eff = false,
         is_rtr = false,
         is_err = false;

    switch (msg->type)
    {
    case MSG_TYPE_STD:
        //No flags
        break;
    case MSG_TYPE_EXT:
        is_eff = true;
        break;
    case MSG_TYPE_STD_RTR:
        is_rtr = true;
        break;
    case MSG_TYPE_EXT_RTR:
        is_rtr = is_eff = true;
        break;
    case MSG_TYPE_STD_FD:
        is_fd = true;
        break;
    case MSG_TYPE_EXT_FD:
        is_fd = is_eff = true;
        break;
    case MSG_TYPE_ERR:
        is_err = true;
        break;

    }

    /* Generate Exported PDU tags for the packet info */
    ws_buffer_clean(&rec->data);

    if (is_fd)
    {
        canfd_frame_t canfd_frame = { 0 };

        /*
         * There's a maximum of CANFD_MAX_DLEN bytes in a CAN-FD frame.
         */
        if (msg->data.length > CANFD_MAX_DLEN) {
            *err = WTAP_ERR_BAD_FILE;
            if (err_info != NULL) {
                *err_info = ws_strdup_printf("%s: File has %u-byte CAN FD packet, bigger than maximum of %u",
                    module_name, msg->data.length, CANFD_MAX_DLEN);
            }
            return false;
        }

        canfd_frame.can_id = g_htonl((msg->id & (is_eff ? CAN_EFF_MASK : CAN_SFF_MASK)) |
            (is_eff ? CAN_EFF_FLAG : 0) |
            (is_err ? CAN_ERR_FLAG : 0));
        canfd_frame.flags = msg->flags | CANFD_FDF;
        canfd_frame.len = msg->data.length;
        memcpy(canfd_frame.data, msg->data.data, msg->data.length);

        ws_buffer_append(&rec->data, (uint8_t*)&canfd_frame, sizeof(canfd_frame));
    }
    else
    {
        can_frame_t can_frame = { 0 };

        /*
         * There's a maximum of CAN_MAX_DLEN bytes in a CAN frame.
         */
        if (msg->data.length > CAN_MAX_DLEN) {
            *err = WTAP_ERR_BAD_FILE;
            if (err_info != NULL) {
                *err_info = ws_strdup_printf("%s: File has %u-byte CAN packet, bigger than maximum of %u",
                    module_name, msg->data.length, CAN_MAX_DLEN);
            }
            return false;
        }

        can_frame.can_id = g_htonl((msg->id & (is_eff ? CAN_EFF_MASK : CAN_SFF_MASK)) |
            (is_rtr ? CAN_RTR_FLAG : 0) |
            (is_eff ? CAN_EFF_FLAG : 0) |
            (is_err ? CAN_ERR_FLAG : 0));
        can_frame.can_dlc = msg->data.length;
        memcpy(can_frame.data, msg->data.data, msg->data.length);

        ws_buffer_append(&rec->data, (uint8_t*)&can_frame, sizeof(can_frame));
    }

    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;
    rec->ts = msg->ts;
    rec->tsprec = wth->file_tsprec;

    rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
    rec->rec_header.packet_header.len = (uint32_t)ws_buffer_length(&rec->data);

    return true;

}
