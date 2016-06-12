/* packet-adb.c
 * Routines for Android Debug Bridge Transport Protocol
 *
 * Copyright 2014 Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See thehf_class
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>

#include "packet-adb_service.h"
#include "packet-usb.h"

static int proto_adb                                                       = -1;
static int hf_command                                                      = -1;
static int hf_argument_0                                                   = -1;
static int hf_argument_1                                                   = -1;
static int hf_data_length                                                  = -1;
static int hf_data_crc32                                                   = -1;
static int hf_magic                                                        = -1;
static int hf_local_id                                                     = -1;
static int hf_remote_id                                                    = -1;
static int hf_version                                                      = -1;
static int hf_max_data                                                     = -1;
static int hf_zero                                                         = -1;
static int hf_sequence                                                     = -1;
static int hf_online                                                       = -1;
static int hf_auth_type                                                    = -1;
static int hf_data                                                         = -1;
static int hf_service                                                      = -1;
static int hf_data_fragment                                                = -1;
static int hf_command_in_frame                                             = -1;
static int hf_completed_in_frame                                           = -1;
static int hf_service_start_in_frame                                       = -1;
static int hf_close_local_in_frame                                         = -1;
static int hf_close_remote_in_frame                                        = -1;
static int hf_connection_info                                              = -1;

static gint ett_adb                                                        = -1;
static gint ett_adb_arg0                                                   = -1;
static gint ett_adb_arg1                                                   = -1;
static gint ett_adb_crc                                                    = -1;
static gint ett_adb_magic                                                  = -1;

static expert_field ei_invalid_magic                                  = EI_INIT;
static expert_field ei_invalid_crc                                    = EI_INIT;

static dissector_handle_t  adb_handle;
static dissector_handle_t  adb_service_handle;

static gint proto_tcp = -1;
static gint proto_usb = -1;

static wmem_tree_t *command_info = NULL;
static wmem_tree_t *service_info = NULL;

typedef struct service_data_t {
    guint32  start_in_frame;

    guint32  close_local_in_frame;
    guint32  close_remote_in_frame;

    guint32  local_id;
    guint32  remote_id;

    const guint8  *service;
} service_data_t;

typedef struct command_data_t {
    guint32   command;

    guint32   command_in_frame;
    guint32   response_in_frame;

    guint32   arg0;
    guint32   arg1;

    guint32   data_length;
    guint32   crc32;

    guint32   completed_in_frame;
    guint32   reassemble_data_length;
    guint8   *reassemble_data;
} command_data_t;

static guint32 max_in_frame = G_MAXUINT32;

static const value_string command_vals[] = {
    { 0x434e5953,  "Synchronize" },
    { 0x45534c43,  "Close" },
    { 0x45545257,  "Write" },
    { 0x48545541,  "Authenticate" },
    { 0x4e584e43,  "Connect" },
    { 0x4e45504f,  "Open" },
    { 0x59414b4f,  "Okay" },
    { 0, NULL }
};

static const value_string magic_vals[] = {
    { 0xFFFFFFFF ^ 0x434e5953,  "Synchronize" },
    { 0xFFFFFFFF ^ 0x45534c43,  "Close" },
    { 0xFFFFFFFF ^ 0x45545257,  "Write" },
    { 0xFFFFFFFF ^ 0x48545541,  "Authenticate" },
    { 0xFFFFFFFF ^ 0x4e584e43,  "Connect" },
    { 0xFFFFFFFF ^ 0x4e45504f,  "Open" },
    { 0xFFFFFFFF ^ 0x59414b4f,  "Okay" },
    { 0, NULL }
};

static const value_string auth_type_vals[] = {
    { 1,  "Token" },
    { 2,  "Signature" },
    { 3,  "RSA Public Key" },
    { 0, NULL }
};

#define A_SYNC  0x434e5953
#define A_CLSE  0x45534c43
#define A_WRTE  0x45545257
#define A_AUTH  0x48545541
#define A_CNXN  0x4e584e43
#define A_OPEN  0x4e45504f
#define A_OKAY  0x59414b4f

#define ADB_TCP_PORT  5555

void proto_register_adb(void);
void proto_reg_handoff_adb(void);

static void
save_command(guint32 cmd, guint32 arg0, guint32 arg1, guint32 data_length,
        guint32 crc32, service_data_t *service_data, gint proto, void *data,
        packet_info *pinfo, service_data_t **returned_service_data,
        command_data_t **returned_command_data)
{
    wmem_tree_key_t  key[6];
    guint32          interface_id;
    guint32          bus_id;
    guint32          device_address;
    guint32          side_id;
    guint32          frame_number;
    command_data_t  *command_data;
    wmem_tree_t     *wmem_tree;
    gint             direction = P2P_DIR_UNKNOWN;
    usb_conv_info_t *usb_conv_info = (usb_conv_info_t *) data;

    frame_number = pinfo->num;

    if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
        interface_id = pinfo->phdr->interface_id;
    else
        interface_id = 0;

    if (proto == proto_usb) {
        usb_conv_info = (usb_conv_info_t *) data;
        DISSECTOR_ASSERT(usb_conv_info);

        direction = usb_conv_info->direction;

        bus_id             = usb_conv_info->bus_id;
        device_address     = usb_conv_info->device_address;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &bus_id;
        key[2].length = 1;
        key[2].key = &device_address;
        key[3].length = 1;
        key[3].key = &side_id;
        key[4].length = 1;
        key[4].key = &frame_number;
        key[5].length = 0;
        key[5].key = NULL;
    } else { /* tcp */
        if (pinfo->destport == ADB_TCP_PORT)
            direction = P2P_DIR_SENT;
        else
            direction = P2P_DIR_RECV;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[2].length = 1;
        if (direction == P2P_DIR_SENT) {
            key[1].key = &pinfo->srcport;
            key[2].key = &pinfo->destport;
        } else {
            key[1].key = &pinfo->destport;
            key[2].key = &pinfo->srcport;
        }
        key[3].length = 1;
        key[3].key = &side_id;
        key[4].length = 1;
        key[4].key = &frame_number;
        key[5].length = 0;
        key[5].key = NULL;
    }

    if (direction == P2P_DIR_SENT)
        if (cmd == A_CLSE)
            side_id = arg1; /* OUT: local id */
        else
            side_id = arg0; /* OUT: local id */
    else
        side_id = arg1; /* IN: remote id */

    if (cmd == A_OPEN) {
        service_data = wmem_new(wmem_file_scope(), service_data_t);

        service_data->start_in_frame = pinfo->num;
        service_data->close_local_in_frame = max_in_frame;
        service_data->close_remote_in_frame = max_in_frame;

        service_data->local_id = arg0;
        service_data->remote_id = arg1;

        service_data->service = "unknown";

        wmem_tree_insert32_array(service_info, key, service_data);
    }

    command_data = wmem_new(wmem_file_scope(), command_data_t);

    command_data->command = cmd;
    command_data->arg0 = arg0;
    command_data->arg1 = arg1;

    command_data->command_in_frame = pinfo->num;
    command_data->response_in_frame = max_in_frame;

    command_data->crc32 = crc32;
    command_data->data_length = data_length;
    if (data_length == 0)
        command_data->completed_in_frame = pinfo->num;
    else
        command_data->completed_in_frame = max_in_frame;
    command_data->reassemble_data_length = 0;
    command_data->reassemble_data = (guint8 *) wmem_alloc(wmem_file_scope(), command_data->data_length);

    key[3].length = 1;
    key[3].key = &frame_number;
    key[4].length = 0;
    key[4].key = NULL;
    wmem_tree_insert32_array(command_info, key, command_data);

    if (direction == P2P_DIR_SENT)
        if (command_data->command == A_CLSE)
            side_id = command_data->arg1; /* OUT: local id */
        else
            side_id = command_data->arg0; /* OUT: local id */
    else
        side_id = command_data->arg1; /* IN: remote id */

    key[3].length = 1;
    key[3].key = &side_id;
    key[4].length = 0;
    key[4].key = NULL;

    wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(service_info, key);
    if (wmem_tree) {
        service_data = (service_data_t *) wmem_tree_lookup32_le(wmem_tree, frame_number);
    }

    if (cmd == A_OKAY) {
        if (!service_data) {
            if (direction == P2P_DIR_SENT)
                side_id = command_data->arg0; /* OUT: local id */
            else
                side_id = command_data->arg1; /* IN: remote id */

            wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(service_info, key);
            if (wmem_tree) {
                service_data = (service_data_t *) wmem_tree_lookup32_le(wmem_tree, frame_number);
            }
        }

        if  (service_data && service_data->remote_id == 0 && direction == P2P_DIR_RECV) {
            if (direction == P2P_DIR_SENT) {
                service_data->remote_id = arg1;
            } else {
                service_data->remote_id = arg0;
            }

            side_id = service_data->remote_id;

            key[4].length = 1;
            key[4].key = &frame_number;
            key[5].length = 0;
            key[5].key = NULL;

            wmem_tree_insert32_array(service_info, key, service_data);
        }
    } else if (cmd == A_CLSE) {
        if (service_data) {
            if (direction == P2P_DIR_RECV && service_data->local_id == arg1)
                service_data->close_local_in_frame = pinfo->num;
            else if (direction == P2P_DIR_SENT  && service_data->remote_id == arg1)
                service_data->close_remote_in_frame = pinfo->num;
        }
    }

    DISSECTOR_ASSERT(returned_service_data && returned_command_data);
    *returned_service_data = service_data;
    *returned_command_data = command_data;
}

static gint
dissect_adb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item      *main_item;
    proto_tree      *main_tree;
    proto_item      *arg0_item;
    proto_tree      *arg0_tree;
    proto_item      *arg1_item;
    proto_tree      *arg1_tree;
    proto_item      *magic_item;
    proto_item      *crc_item;
    proto_tree      *crc_tree = NULL;
    proto_item      *sub_item;
    gint             offset = 0;
    guint32          command;
    guint32          arg0;
    guint32          arg1;
    guint32          data_length = 0;
    guint32          crc32 = 0;
    usb_conv_info_t *usb_conv_info = NULL;
    wmem_tree_key_t  key[5];
    guint32          interface_id;
    guint32          bus_id;
    guint32          device_address;
    guint32          side_id;
    guint32          frame_number;
    gboolean         is_command = TRUE;
    gboolean         is_next_fragment = FALSE;
    gboolean         is_service = FALSE;
    gint             proto;
    gint             direction = P2P_DIR_UNKNOWN;
    wmem_tree_t     *wmem_tree;
    command_data_t  *command_data = NULL;
    service_data_t  *service_data = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADB");
    col_clear(pinfo->cinfo, COL_INFO);

    main_item = proto_tree_add_item(tree, proto_adb, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_adb);

    frame_number       = pinfo->num;

    /* XXX: Why? If interface is USB only first try is correct
     * (and seems strange...), in other cases standard check for
     * previous protocol is correct */
    proto = (gint) GPOINTER_TO_INT(wmem_list_frame_data(/*wmem_list_frame_prev*/(wmem_list_tail(pinfo->layers))));
    if (proto != proto_usb) {
        proto = (gint) GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_frame_prev(wmem_list_tail(pinfo->layers))));
    }

    if (proto == proto_usb) {
        usb_conv_info = (usb_conv_info_t *) data;
        DISSECTOR_ASSERT(usb_conv_info);

        direction = usb_conv_info->direction;
    } else if (proto == proto_tcp) {
        if (pinfo->destport == ADB_TCP_PORT)
            direction = P2P_DIR_SENT;
        else
            direction = P2P_DIR_RECV;
    } else {
        return offset;
    }

    if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
        interface_id = pinfo->phdr->interface_id;
    else
        interface_id = 0;

    if (proto == proto_usb) {
        bus_id             = usb_conv_info->bus_id;
        device_address     = usb_conv_info->device_address;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &bus_id;
        key[2].length = 1;
        key[2].key = &device_address;
        key[3].length = 0;
        key[3].key = NULL;
    } else { /* tcp */
        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[2].length = 1;
        if (direction == P2P_DIR_SENT) {
            key[1].key = &pinfo->srcport;
            key[2].key = &pinfo->destport;
        } else {
            key[1].key = &pinfo->destport;
            key[2].key = &pinfo->srcport;
        }
        key[3].length = 0;
        key[3].key = NULL;
    }

    wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(command_info, key);
    if (wmem_tree) {
        command_data = (command_data_t *) wmem_tree_lookup32_le(wmem_tree, frame_number);
        if (command_data && command_data->completed_in_frame >= frame_number &&
                command_data->command_in_frame <= frame_number) {

            if (command_data->command_in_frame != frame_number) {
                is_command = FALSE;
                is_next_fragment = TRUE;
            }

            data_length = command_data->data_length;
            crc32 = command_data->crc32;

            if (direction == P2P_DIR_SENT)
                if (command_data->command == A_CLSE)
                    side_id = command_data->arg1; /* OUT: local id */
                else
                    side_id = command_data->arg0; /* OUT: local id */
            else
                if (command_data->command == A_OKAY) {
                    side_id = command_data->arg1; /* IN: remote id */
                } else
                    side_id = command_data->arg1; /* IN: remote id */

            key[3].length = 1;
            key[3].key = &side_id;
            key[4].length = 0;
            key[4].key = NULL;

            wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(service_info, key);
            if (wmem_tree) {
                service_data = (service_data_t *) wmem_tree_lookup32_le(wmem_tree, frame_number);
                if (service_data && command_data->command == A_OPEN) {
                    is_service = TRUE;
                }
            }
        }
    }

/* Simple heuristics to check if packet is command or data */
    if ((command_data && command_data->completed_in_frame <= frame_number) || !command_data) {
        if (tvb_reported_length(tvb) < 24) {
            is_command = FALSE;
        } else if (tvb_reported_length(tvb) >= 24) {
            command = tvb_get_letohl(tvb, offset);

            if (command != A_SYNC && command != A_CLSE && command != A_WRTE &&
                    command != A_AUTH && command != A_CNXN && command != A_OPEN && command != A_OKAY)
                is_command = FALSE;
            else if (command != (0xFFFFFFFF ^ tvb_get_letohl(tvb, offset + 20)))
                is_command = FALSE;

            if (is_command) {
                data_length = tvb_get_letohl(tvb, offset + 12);
                crc32 = tvb_get_letohl(tvb, offset + 16);
            }
            if (command == A_OPEN) is_service = TRUE;
        }
    }

    if (service_data && !(command_data->command == A_OPEN && is_next_fragment)) {
        sub_item = proto_tree_add_string(main_tree, hf_service, tvb, offset, 0, service_data->service);
        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    if (service_data) {
        sub_item = proto_tree_add_uint(main_tree, hf_service_start_in_frame, tvb, offset, 0, service_data->start_in_frame);
        PROTO_ITEM_SET_GENERATED(sub_item);

        if (service_data->close_local_in_frame < max_in_frame) {
            sub_item = proto_tree_add_uint(main_tree, hf_close_local_in_frame, tvb, offset, 0, service_data->close_local_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (service_data->close_remote_in_frame < max_in_frame) {
            sub_item = proto_tree_add_uint(main_tree, hf_close_remote_in_frame, tvb, offset, 0, service_data->close_remote_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    if (is_command) {
        proto_tree_add_item(main_tree, hf_command, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        command = tvb_get_letohl(tvb, offset);
        offset += 4;

        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(command, command_vals, "Unknown command"));

        arg0_item = proto_tree_add_item(main_tree, hf_argument_0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        arg0_tree = proto_item_add_subtree(arg0_item, ett_adb_arg0);
        arg0 = tvb_get_letohl(tvb, offset);
        offset += 4;

        arg1_item = proto_tree_add_item(main_tree, hf_argument_1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        arg1_tree = proto_item_add_subtree(arg1_item, ett_adb_arg1);
        arg1 = tvb_get_letohl(tvb, offset);
        offset += 4;

        switch (command) {
        case A_CNXN:
            proto_tree_add_item(arg0_tree, hf_version, tvb, offset - 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(arg1_tree, hf_max_data, tvb, offset - 4, 4, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "(version=%u.%u.%u, max_data=%u)", tvb_get_guint8(tvb, offset - 5), tvb_get_guint8(tvb, offset - 6), tvb_get_letohs(tvb, offset - 7), tvb_get_letohl(tvb, offset - 4));
            break;
        case A_AUTH:
            proto_tree_add_item(arg0_tree, hf_auth_type, tvb, offset - 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(arg1_tree, hf_zero, tvb, offset - 4, 4, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "(type=%s, 0)", val_to_str_const(tvb_get_letohl(tvb, offset - 8), auth_type_vals, "Unknown"));
            break;
        case A_OPEN:
            proto_tree_add_item(arg0_tree, hf_local_id, tvb, offset - 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(arg1_tree, hf_zero, tvb, offset - 4, 4, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "(local=%u, 0)", tvb_get_letohl(tvb, offset - 8));
            break;
        case A_WRTE:
            proto_tree_add_item(arg0_tree, hf_zero, tvb, offset - 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(arg1_tree, hf_remote_id, tvb, offset - 4, 4, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "(0, remote=%u)", tvb_get_letohl(tvb, offset - 4));
            break;
        case A_CLSE:
        case A_OKAY:
            proto_tree_add_item(arg0_tree, hf_local_id, tvb, offset - 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(arg1_tree, hf_remote_id, tvb, offset - 4, 4, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "(local=%u, remote=%u)", tvb_get_letohl(tvb, offset - 8), tvb_get_letohl(tvb, offset - 4));
            break;
        case A_SYNC:
            proto_tree_add_item(arg0_tree, hf_online, tvb, offset - 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(arg1_tree, hf_sequence, tvb, offset - 4, 4, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "(online=%s, sequence=%u)", tvb_get_letohl(tvb, offset - 8) ? "Yes": "No", tvb_get_letohl(tvb, offset - 4));
            break;
        }

        proto_tree_add_item(main_tree, hf_data_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        if (data_length > 0)
            col_append_fstr(pinfo->cinfo, COL_INFO, " length=%u ", data_length);

        crc_item = proto_tree_add_item(main_tree, hf_data_crc32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        crc_tree = proto_item_add_subtree(crc_item, ett_adb_crc);
        crc32 = tvb_get_letohl(tvb, offset);
        offset += 4;

        magic_item = proto_tree_add_item(main_tree, hf_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        if ((tvb_get_letohl(tvb, offset) ^ 0xFFFFFFFF) != command) {
            proto_tree  *expert_tree;

            expert_tree = proto_item_add_subtree(magic_item, ett_adb_magic);
            proto_tree_add_expert(expert_tree, pinfo, &ei_invalid_magic, tvb, offset, 4);
        }

        if (!pinfo->fd->flags.visited)
            save_command(command, arg0, arg1, data_length, crc32, service_data, proto, data, pinfo, &service_data, &command_data);
        offset += 4;
    }

    if (!pinfo->fd->flags.visited && command_data) {
            if (command_data->command_in_frame != frame_number) {
                is_command = FALSE;
                is_next_fragment = TRUE;
            }

            data_length = command_data->data_length;
            crc32 = command_data->crc32;

            if ((command_data->command_in_frame != frame_number && tvb_captured_length(tvb) == data_length) ||
                (command_data->command_in_frame == frame_number && tvb_captured_length(tvb) == data_length + 24)
            ) {
                command_data->reassemble_data_length = command_data->data_length;
                command_data->completed_in_frame = frame_number;
            }
    }

    if (is_next_fragment && command_data) {
        sub_item = proto_tree_add_uint(main_tree, hf_command_in_frame, tvb, offset, 0, command_data->command_in_frame);
        PROTO_ITEM_SET_GENERATED(sub_item);

        sub_item = proto_tree_add_uint(main_tree, hf_command, tvb, offset, 0, command_data->command);
        PROTO_ITEM_SET_GENERATED(sub_item);

        sub_item = proto_tree_add_uint(main_tree, hf_data_length, tvb, offset, 0, command_data->data_length);
        PROTO_ITEM_SET_GENERATED(sub_item);

        crc_item = proto_tree_add_uint(main_tree, hf_data_crc32, tvb, offset, 0, command_data->crc32);
        crc_tree = proto_item_add_subtree(crc_item, ett_adb_crc);
        PROTO_ITEM_SET_GENERATED(crc_item);
    }

    if (command_data && command_data->completed_in_frame != frame_number) {
        sub_item = proto_tree_add_uint(main_tree, hf_completed_in_frame, tvb, offset, 0, command_data->completed_in_frame);
        PROTO_ITEM_SET_GENERATED(sub_item);
    }


    if (tvb_captured_length_remaining(tvb, offset) > 0 && (!is_command || data_length > 0)) {
        guint32 crc = 0;
        guint32 i_offset;

        if ((!pinfo->fd->flags.visited && command_data && command_data->reassemble_data_length < command_data->data_length) || data_length > (guint32) tvb_captured_length_remaining(tvb, offset)) { /* need reassemble */
            if (!pinfo->fd->flags.visited && command_data && command_data->reassemble_data_length < command_data->data_length) {
                tvb_memcpy(tvb, command_data->reassemble_data + command_data->reassemble_data_length, offset, tvb_captured_length_remaining(tvb, offset));
                command_data->reassemble_data_length += tvb_captured_length_remaining(tvb, offset);

                if (command_data->reassemble_data_length >= command_data->data_length)
                    command_data->completed_in_frame = frame_number;
            }

            proto_tree_add_item(main_tree, hf_data_fragment, tvb, offset, -1, ENC_NA);
            col_append_str(pinfo->cinfo, COL_INFO, "Data Fragment");
            offset = tvb_captured_length(tvb);

            if (service_data && command_data && command_data->reassemble_data_length >= command_data->data_length && frame_number == command_data->completed_in_frame) {
                tvbuff_t            *next_tvb;
                adb_service_data_t   adb_service_data;

                next_tvb = tvb_new_child_real_data(tvb, command_data->reassemble_data, command_data->reassemble_data_length, command_data->reassemble_data_length);
                add_new_data_source(pinfo, next_tvb, "ADB Reassembled Data");

                adb_service_data.service = service_data->service;
                adb_service_data.direction = direction;

                adb_service_data.session_key_length = 3;
                adb_service_data.session_key = (guint32 *) wmem_alloc(wmem_packet_scope(), adb_service_data.session_key_length * sizeof(guint32));
                adb_service_data.session_key[0] = interface_id;

                if (proto == proto_usb) {
                    adb_service_data.session_key[1] = usb_conv_info->bus_id;
                    adb_service_data.session_key[2] = usb_conv_info->device_address;
                } else { /* tcp */
                    if (direction == P2P_DIR_SENT) {
                        adb_service_data.session_key[1] = pinfo->srcport;
                        adb_service_data.session_key[2] = pinfo->destport;
                    } else {
                        adb_service_data.session_key[1] = pinfo->destport;
                        adb_service_data.session_key[2] = pinfo->srcport;
                    }
                }

                call_dissector_with_data(adb_service_handle, next_tvb, pinfo, tree, &adb_service_data);
            }
        } else { /* full message */
            for (i_offset = 0; i_offset < data_length; ++i_offset)
                crc += tvb_get_guint8(tvb, offset + i_offset);

            if (crc32 > 0 && crc32 != crc)
                proto_tree_add_expert(crc_tree, pinfo, &ei_invalid_crc, tvb, offset, -1);

            if (is_service) {
                proto_tree_add_item(main_tree, hf_service, tvb, offset, -1, ENC_ASCII | ENC_NA);
                if (!pinfo->fd->flags.visited && service_data) {
                    service_data->service = tvb_get_stringz_enc(wmem_file_scope(), tvb, offset, NULL, ENC_ASCII);
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, "Service: %s", tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, NULL, ENC_ASCII));
                offset = tvb_captured_length(tvb);
            } else if (command_data && command_data->command == A_CNXN) {
                    gchar       *info;
                    gint         len;

                info = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_ASCII);
                col_append_fstr(pinfo->cinfo, COL_INFO, "Connection Info: %s", info);
                proto_tree_add_item(main_tree, hf_connection_info, tvb, offset, len, ENC_ASCII | ENC_NA);
                offset += len;
            } else {
                col_append_str(pinfo->cinfo, COL_INFO, "Data");

                /* Decode service payload */
                if (service_data) {
                    tvbuff_t           *next_tvb;
                    adb_service_data_t  adb_service_data;

                    adb_service_data.service = service_data->service;
                    adb_service_data.direction = direction;

                    adb_service_data.session_key_length = 3;
                    adb_service_data.session_key = (guint32 *) wmem_alloc(wmem_packet_scope(), adb_service_data.session_key_length * sizeof(guint32));
                    adb_service_data.session_key[0] = interface_id;

                    if (proto == proto_usb) {
                        adb_service_data.session_key[1] = usb_conv_info->bus_id;
                        adb_service_data.session_key[2] = usb_conv_info->device_address;
                    } else { /* tcp */
                        if (direction == P2P_DIR_SENT) {
                            adb_service_data.session_key[1] = pinfo->srcport;
                            adb_service_data.session_key[2] = pinfo->destport;
                        } else {
                            adb_service_data.session_key[1] = pinfo->destport;
                            adb_service_data.session_key[2] = pinfo->srcport;
                        }
                    }

                    next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset), tvb_captured_length_remaining(tvb, offset));
                    call_dissector_with_data(adb_service_handle, next_tvb, pinfo, tree, &adb_service_data);

                } else {
                    proto_item  *data_item;
                    gchar       *data_str;

                    data_item = proto_tree_add_item(main_tree, hf_data, tvb, offset, data_length, ENC_NA);
                    data_str = tvb_format_text(tvb, offset, data_length);
                    proto_item_append_text(data_item, ": %s", data_str);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Raw: %s", data_str);
                }

                offset = tvb_captured_length(tvb);
            }
        }
    }

    return offset;
}

void
proto_register_adb(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_command,
            { "Command",                         "adb.command",
            FT_UINT32, BASE_HEX, VALS(command_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_argument_0,
            { "Argument 0",                      "adb.argument.0",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_argument_1,
            { "Argument 0",                      "adb.argument.1",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data_length,
            { "Data Length",                      "adb.data_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data_crc32,
            { "Data CRC32",                      "adb.data_crc32",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_magic,
            { "Magic",                           "adb.magic",
            FT_UINT32, BASE_HEX, VALS(magic_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_version,
            { "Version",                         "adb.version",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_max_data,
            { "Max Data",                        "adb.max_data",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_auth_type,
            { "Type",                            "adb.auth_type",
            FT_UINT32, BASE_HEX, VALS(auth_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_online,
            { "Online",                          "adb.online",
            FT_BOOLEAN, 32, TFS(&tfs_no_yes), 0x00,
            NULL, HFILL }
        },
        { &hf_sequence,
            { "Sequence",                        "adb.sequence",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_zero,
            { "Zero",                            "adb.zero",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_local_id,
            { "Local ID",                        "adb.local_id",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_remote_id,
            { "Remote ID",                       "adb.remote_id",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data,
            { "Data",                            "adb.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_service,
            { "Service",                         "adb.service",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data_fragment,
            { "Data Fragment",                   "adb.data_fragment",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_service_start_in_frame,
            { "Service Start in Frame",          "adb.service_start_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_close_local_in_frame,
            { "Local Service Close in Frame",    "adb.close_local_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_close_remote_in_frame,
            { "Remote Service Close in Frame",   "adb.close_remote_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_command_in_frame,
            { "Command in Frame",                "adb.command_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_completed_in_frame,
            { "Completed in Frame",              "adb.completed_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_connection_info,
            { "Info",                            "adb.connection_info",
            FT_STRINGZ, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_adb,
        &ett_adb_arg0,
        &ett_adb_arg1,
        &ett_adb_crc,
        &ett_adb_magic
    };

    static ei_register_info ei[] = {
        { &ei_invalid_magic,          { "adb.expert.invalid_magic", PI_PROTOCOL, PI_WARN, "Invalid Magic", EXPFILL }},
        { &ei_invalid_crc,            { "adb.expert.crc_error", PI_PROTOCOL, PI_ERROR, "CRC32 Error", EXPFILL }},
    };

    command_info         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    service_info         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_adb = proto_register_protocol("Android Debug Bridge", "ADB", "adb");
    adb_handle = register_dissector("adb", dissect_adb, proto_adb);

    proto_register_field_array(proto_adb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module = expert_register_protocol(proto_adb);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_adb, NULL);
    prefs_register_static_text_preference(module, "version",
            "ADB protocol version is compatible prior to: adb 1.0.31",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_adb(void)
{
    adb_service_handle = find_dissector_add_dependency("adb_service", proto_adb);

    dissector_add_for_decode_as("tcp.port",     adb_handle);
    dissector_add_for_decode_as("usb.device",   adb_handle);
    dissector_add_for_decode_as("usb.product",  adb_handle);
    dissector_add_for_decode_as("usb.protocol", adb_handle);

    proto_tcp = proto_get_id_by_filter_name("tcp");
    proto_usb = proto_get_id_by_filter_name("usb");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
