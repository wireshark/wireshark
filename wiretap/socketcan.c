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

typedef struct can_priv_data {
    GHashTable* interface_ids;	/* map name/description/link-layer type to interface ID */
    unsigned num_interface_ids;	/* Number of interface IDs assigned */

    void (*tap_close)(void*);
    void* tap_priv;

} can_priv_data_t;

/*
 * Hash table to map interface name to interface ID.
 */

static gboolean
destroy_if_name(void* key, void* value _U_, void* user_data _U_)
{
    char* name = (char*)key;

    g_free(name);

    return true;
}

static void
add_new_if_name(can_priv_data_t* can_data, const char* name, void** result)
{
    char* new_name;

    new_name = g_strdup(name);
    *result = GUINT_TO_POINTER(can_data->num_interface_ids);
    g_hash_table_insert(can_data->interface_ids, (void*)new_name, *result);
    can_data->num_interface_ids++;
}

static void
wtap_socketcan_close(wtap* wth)
{
    //Clean up wiretap data
    can_priv_data_t* data = (can_priv_data_t*)wth->priv;
    if (data->tap_close != NULL)
        data->tap_close(data->tap_priv);

    //Cleanup our interface data
    g_hash_table_foreach_remove(data->interface_ids, destroy_if_name, NULL);
    g_hash_table_destroy(data->interface_ids);
    g_free(data);

    wth->priv = NULL;
}

void*
wtap_socketcan_get_private_data(wtap* wth)
{
    can_priv_data_t* socket_can_data = (can_priv_data_t*)wth->priv;
    return socket_can_data->tap_priv;
}

void
wtap_set_as_socketcan(wtap* wth, int file_type_subtype, int tsprec, void* tap_priv, void (*tap_close)(void*))
{
    //Create the private data that wraps over the wiretap's private data
    can_priv_data_t* socketcan_priv_data = g_new0(can_priv_data_t, 1);
    socketcan_priv_data->interface_ids = g_hash_table_new(g_str_hash, g_str_equal);

    socketcan_priv_data->tap_priv = tap_priv;
    socketcan_priv_data->tap_close = tap_close;

    wth->file_type_subtype = file_type_subtype;
    wth->file_encap = WTAP_ENCAP_SOCKETCAN;
    wth->file_tsprec = tsprec;
    wth->subtype_close = wtap_socketcan_close;
    wth->priv = socketcan_priv_data;
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

    if (msg->interface_id != 0xFFFFFFFF) {
        rec->presence_flags |= WTAP_HAS_INTERFACE_ID;
        rec->rec_header.packet_header.interface_id = msg->interface_id;
    }

    return true;
}

uint32_t
wtap_socketcan_find_or_create_new_interface(wtap* wth, const char* name)
{
    void* result = NULL;
    can_priv_data_t* can_data = (can_priv_data_t*)wth->priv;

    if (!g_hash_table_lookup_extended(can_data->interface_ids, name, NULL, &result))
    {
        wtap_block_t int_data;
        wtapng_if_descr_mandatory_t* int_data_mand;

        /*
         * Not found; make a new entry.
         */
        add_new_if_name(can_data, name, &result);

        /*
         * Now make a new IDB and add it.
         */
        int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
        int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);

        int_data_mand->wtap_encap = WTAP_ENCAP_SOCKETCAN;
        int_data_mand->tsprecision = WTAP_TSPREC_USEC;
        int_data_mand->time_units_per_second = 1000000; /* Microsecond resolution */
        int_data_mand->snap_len = WTAP_MAX_PACKET_SIZE_STANDARD;	/* XXX - not known */

        wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 0x06); /* microsecond resolution */
        /* Interface statistics */
        int_data_mand->num_stat_entries = 0;
        int_data_mand->interface_statistics = NULL;

        wtap_block_set_string_option_value(int_data, OPT_IDB_NAME, name, strlen(name));
        wtap_add_idb(wth, int_data);
    }
    return GPOINTER_TO_UINT(result);
}
