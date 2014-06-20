/* packet-adb_cs.c
 * Routines for Android Debug Bridge Client-Server Protocol
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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
#include <epan/wmem/wmem.h>
#include <wiretap/wtap.h>

static int proto_adb_cs                                                    = -1;

static int hf_role                                                         = -1;
static int hf_hex_ascii_length                                             = -1;
static int hf_length                                                       = -1;
static int hf_hex_ascii_version                                            = -1;
static int hf_version                                                      = -1;
static int hf_service                                                      = -1;
static int hf_status                                                       = -1;
static int hf_fragment                                                     = -1;
static int hf_data                                                         = -1;
static int hf_fail_reason                                                  = -1;
static int hf_framebuffer_version                                          = -1;
static int hf_framebuffer_depth                                            = -1;
static int hf_framebuffer_size                                             = -1;
static int hf_framebuffer_width                                            = -1;
static int hf_framebuffer_height                                           = -1;
static int hf_framebuffer_red_offset                                       = -1;
static int hf_framebuffer_red_length                                       = -1;
static int hf_framebuffer_blue_offset                                      = -1;
static int hf_framebuffer_blue_length                                      = -1;
static int hf_framebuffer_green_offset                                     = -1;
static int hf_framebuffer_green_length                                     = -1;
static int hf_framebuffer_alpha_offset                                     = -1;
static int hf_framebuffer_alpha_length                                     = -1;
static int hf_framebuffer_pixel                                            = -1;
static int hf_framebuffer_red_5                                            = -1;
static int hf_framebuffer_green_6                                          = -1;
static int hf_framebuffer_blue_5                                           = -1;
static int hf_framebuffer_red                                              = -1;
static int hf_framebuffer_green                                            = -1;
static int hf_framebuffer_blue                                             = -1;
static int hf_framebuffer_alpha                                            = -1;
static int hf_framebuffer_unused                                           = -1;
static int hf_devices                                                      = -1;
static int hf_stdin                                                        = -1;
static int hf_stdout                                                       = -1;
static int hf_pids                                                         = -1;
static int hf_result                                                       = -1;

static gint ett_adb_cs                                                     = -1;
static gint ett_length                                                     = -1;
static gint ett_version                                                    = -1;
static gint ett_pixel                                                      = -1;
static gint ett_data                                                       = -1;

static expert_field ei_incomplete_message                             = EI_INIT;

static dissector_handle_t  adb_cs_handle;
static dissector_handle_t  logcat_handle;
static dissector_handle_t  data_handle;

static wmem_tree_t *client_requests = NULL;
static wmem_tree_t *fragments = NULL;

static guint server_port = 5037;
static gboolean pref_dissect_more_detail_framebuffer = FALSE;

typedef struct _framebuffer_data_t {
    guint32 red_offset;
    guint32 red_length;
    guint32 green_offset;
    guint32 green_length;
    guint32 blue_offset;
    guint32 blue_length;
    guint32 alpha_offset;
    guint32 alpha_length;
} framebuffer_data_t;

typedef struct _client_request_t {
    guint16   service_length;
    guint8   *service;
    guint32   first_in;
    gint64    service_in;
    gint64    data_in;
    gint64    response_frame;

    guint8    status;
    gint      data_length;
    union {
        void               *allocated;
        framebuffer_data_t *framebuffer_data;
    } data;
} client_request_t;

typedef struct _fragment_t {
    gint64    reassembled_in_frame;
    gint      length;
    guint8   *data;
} fragment_t;

static const value_string role_vals[] = {
    { 0x00,   "Unknown" },
    { 0x01,   "Server" },
    { 0x02,   "Client" },
    { 0, NULL }
};

#define SERVICE_NONE  NULL

#define STATUS_UNKNOWN  0
#define STATUS_OKAY     1
#define STATUS_FAIL     2

void proto_register_adb_cs(void);
void proto_reg_handoff_adb_cs(void);


static gint
dissect_ascii_data_length(proto_tree *tree, tvbuff_t *tvb, gint offset, gint *data_length)
{
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    guint8       hex_ascii[5];

    DISSECTOR_ASSERT(data_length);

    tvb_memcpy(tvb, hex_ascii, offset, 4);
    hex_ascii[4]='\0';

    sub_item = proto_tree_add_item(tree, hf_hex_ascii_length, tvb, offset, 4, ENC_NA | ENC_ASCII);
    sub_tree = proto_item_add_subtree(sub_item, ett_length);
    *data_length = (gint)g_ascii_strtoull(hex_ascii, NULL, 16);
    proto_tree_add_uint(sub_tree, hf_length, tvb, offset, 4, *data_length);
    offset += 4;

    return offset;
}

static gint
dissect_adb_cs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *main_item;
    proto_tree  *main_tree;
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    proto_item  *p_item;
    gint         offset = 0;
    gint         length = -1;
    guint8      *hex_ascii;
    gboolean     client_request_service = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADB CS");
    col_clear(pinfo->cinfo, COL_INFO);

    main_item = proto_tree_add_item(tree, proto_adb_cs, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_adb_cs);

    if (pinfo->destport == server_port) { /* Client sent to Server */
        client_request_t  *client_request;
        guint8            *service = SERVICE_NONE;
        guint32            wireshark_interface_id = 0;
        wmem_tree_t       *subtree;
        wmem_tree_key_t    key[5];

        p_item = proto_tree_add_uint(main_tree, hf_role, tvb, offset, 0, 0x02);
        PROTO_ITEM_SET_GENERATED(p_item);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Client");

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            wireshark_interface_id = pinfo->phdr->interface_id;

        key[0].length = 1;
        key[0].key = &wireshark_interface_id;
        key[1].length = 1;
        key[1].key = &pinfo->srcport;
        key[2].length = 1;
        key[2].key = &pinfo->destport;
        key[3].length = 0;
        key[3].key = NULL;

        subtree = (wmem_tree_t *) wmem_tree_lookup32_array(client_requests, key);
        client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num) : NULL;
        if (client_request && client_request->service_in > -1 && client_request->service_in < pinfo->fd->num) {
            p_item = proto_tree_add_string(main_tree, hf_service, tvb, offset, 0, client_request->service);
            PROTO_ITEM_SET_GENERATED(p_item);
            service = client_request->service;
            client_request_service = TRUE;
        } else {
            if (client_request && client_request->service_in > -1 && client_request->service_in <= pinfo->fd->num)
               client_request_service = TRUE;
            client_request = NULL;
        }

        /* heuristic to recognize type of (partial) packet */
        if (tvb_length_remaining(tvb, offset) >= 4) {
            guint8  hex_ascii_length[5];

            hex_ascii_length[4] = 0;

            tvb_memcpy(tvb, hex_ascii_length, offset, 4);
            if (g_ascii_xdigit_value(hex_ascii_length[0]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[1]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[2]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[3]) >= 0) {
                /* probably 4 bytes ascii hex length field */
                offset = dissect_ascii_data_length(main_tree, tvb, offset, &length);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Length=%u", length);
            }
        }

        if (length == -1 && service) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);

            if (g_str_has_prefix(service, "shell:")) {
                proto_tree_add_item(main_tree, hf_stdin, tvb, offset, -1, ENC_NA | ENC_ASCII);
                offset = tvb_length(tvb);
            } else {
                proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
                offset = tvb_length(tvb);
            }

            return offset;
        }

        if (!pinfo->fd->flags.visited && length > 0) { /* save Length to client_requests */
            if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
                wireshark_interface_id = pinfo->phdr->interface_id;

            key[0].length = 1;
            key[0].key = &wireshark_interface_id;
            key[1].length = 1;
            key[1].key = &pinfo->srcport;
            key[2].length = 1;
            key[2].key = &pinfo->destport;
            key[3].length = 1;
            key[3].key = &pinfo->fd->num;
            key[4].length = 0;
            key[4].key = NULL;

            client_request = wmem_new(wmem_file_scope(), client_request_t);

            client_request->service_length = length;
            client_request->service = SERVICE_NONE;
            client_request->response_frame = -1;
            client_request->first_in = pinfo->fd->num;
            client_request->service_in = -1;
            client_request->data_in = -1;
            client_request->data.allocated = NULL;
            client_request->data_length = -1;
            wmem_tree_insert32_array(client_requests, key, client_request);
        }

        if (!pinfo->fd->flags.visited && (length == -1 || (client_request && client_request->service_in == -1 && tvb_length_remaining(tvb, offset) > 0))) { /* save Service to client_requests */
            if (!client_request) {
                if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
                    wireshark_interface_id = pinfo->phdr->interface_id;

                key[0].length = 1;
                key[0].key = &wireshark_interface_id;
                key[1].length = 1;
                key[1].key = &pinfo->srcport;
                key[2].length = 1;
                key[2].key = &pinfo->destport;
                key[3].length = 0;
                key[3].key = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(client_requests, key);
                client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num - 1) : NULL;
            }

            if (client_request) {
                client_request->service = (guint8 *) wmem_alloc(wmem_file_scope(), client_request->service_length + 1);
                tvb_memcpy(tvb, client_request->service, offset, client_request->service_length);
                client_request->service[client_request->service_length] = '\0';
                client_request->service_in = pinfo->fd->num;
            }
        }

        if (!client_request_service && tvb_length_remaining(tvb, offset) > 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Unknown service");
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_length(tvb);
        } else if (tvb_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(main_tree, hf_service, tvb, offset, -1, ENC_NA | ENC_ASCII);

            service = (guint8 *) wmem_alloc(wmem_packet_scope(), tvb_length_remaining(tvb, offset) + 1);
            tvb_memcpy(tvb, service, offset, tvb_length_remaining(tvb, offset));
            service[tvb_length_remaining(tvb, offset)] = '\0';
            col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);

            offset += tvb_length_remaining(tvb, offset);
        }

    } else if (pinfo->srcport == server_port) { /* Server sent to Client */
        guint32           wireshark_interface_id = 0;
        guint8           *service = SERVICE_NONE;
        wmem_tree_t      *subtree;
        wmem_tree_key_t   key[5];
        client_request_t *client_request;
        gint64            response_frame = -1;
        gint64            data_in = -1;
        guint8            status = STATUS_UNKNOWN;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            wireshark_interface_id = pinfo->phdr->interface_id;

        key[0].length = 1;
        key[0].key = &wireshark_interface_id;
        key[1].length = 1;
        key[1].key = &pinfo->destport;
        key[2].length = 1;
        key[2].key = &pinfo->srcport;
        key[3].length = 0;
        key[3].key = NULL;

        subtree = (wmem_tree_t *) wmem_tree_lookup32_array(client_requests, key);
        client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num - 1) : NULL;
        if (client_request) {
            service = client_request->service;
            status = client_request->status;
            length = client_request->data_length;
            response_frame = client_request->response_frame;
            data_in = client_request->data_in;
        }

        p_item = proto_tree_add_uint(main_tree, hf_role, tvb, offset, 0, 0x01);
        PROTO_ITEM_SET_GENERATED(p_item);

        p_item = proto_tree_add_string(main_tree, hf_service, tvb, offset, 0, service);
        PROTO_ITEM_SET_GENERATED(p_item);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Server");

        if (!service) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Unknown service");
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_length(tvb);

            return offset;
        }

        if (response_frame == -1 || response_frame == (gint64) pinfo->fd->num) {
            proto_tree_add_item(main_tree, hf_status, tvb, offset, 4, ENC_NA | ENC_ASCII);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Status=%c%c%c%c", tvb_get_guint8(tvb, offset),
            tvb_get_guint8(tvb, offset + 1), tvb_get_guint8(tvb, offset + 2), tvb_get_guint8(tvb, offset + 3));
            offset += 4;

            if (tvb_memeql(tvb, offset - 4, "FAIL", 4) == 0) {
                offset = dissect_ascii_data_length(main_tree, tvb, offset, &length);

                status = STATUS_FAIL;
            } else if (tvb_memeql(tvb, offset - 4, "OKAY", 4) == 0) {
                status = STATUS_OKAY;
                length = -1;
            }

            if (!pinfo->fd->flags.visited && client_request) {
                client_request->response_frame = pinfo->fd->num;
                client_request->status = status;
                client_request->data_length = length;
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);

        if (tvb_length_remaining(tvb, offset) <= 0) return offset;

        if (!pinfo->fd->flags.visited && client_request && client_request->data_in == -1) {
            client_request->data_in = pinfo->fd->num;
            data_in = client_request->data_in;
        }

        if (status == STATUS_FAIL) {
            sub_item = proto_tree_add_item(main_tree, hf_fail_reason, tvb, offset, -1, ENC_NA | ENC_ASCII);
            if (length < tvb_length_remaining(tvb, offset)) {
                expert_add_info(pinfo, sub_item, &ei_incomplete_message);
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " Fail=<%s>", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tvb_length_remaining(tvb, offset), ENC_ASCII));
            offset = tvb_length(tvb);
            return offset;
        }

        if (g_strcmp0(service, "host:version") == 0) {
            guint    version;
            gint     data_length;

            offset = dissect_ascii_data_length(main_tree, tvb, offset, &data_length);

            hex_ascii = (guint8 *) wmem_alloc(wmem_packet_scope(), data_length + 1);
            tvb_memcpy(tvb, hex_ascii, offset, data_length);
            hex_ascii[data_length]='\0';

            sub_item = proto_tree_add_item(main_tree, hf_hex_ascii_version, tvb, offset, 4, ENC_NA | ENC_ASCII);
            sub_tree = proto_item_add_subtree(sub_item, ett_version);
            version = (guint)g_ascii_strtoull(hex_ascii, NULL, 16);
            proto_tree_add_uint(sub_tree, hf_version, tvb, offset, 4, version);
            offset += 4;

            col_append_fstr(pinfo->cinfo, COL_INFO, " Version=%u", version);
        } else if (g_strcmp0(service, "host:devices") == 0 ||
                g_strcmp0(service, "host:devices-l") == 0 ||
                g_strcmp0(service, "host:track-devices") == 0) {
            gint  data_length;

            offset = dissect_ascii_data_length(main_tree, tvb, offset, &data_length);

            sub_item = proto_tree_add_item(main_tree, hf_devices, tvb, offset, -1, ENC_NA | ENC_ASCII);
            if (data_length < tvb_length_remaining(tvb, offset)) {
                expert_add_info(pinfo, sub_item, &ei_incomplete_message);
            }
        } else if (g_strcmp0(service, "host:get-state") == 0 ||
                g_strcmp0(service, "host:get-serialno") == 0 ||
                g_strcmp0(service, "host:get-devpath") == 0 ||
                g_str_has_prefix(service, "connect:") ||
                g_str_has_prefix(service, "disconnect:")) {
            gint  data_length;

            offset = dissect_ascii_data_length(main_tree, tvb, offset, &data_length);

            sub_item = proto_tree_add_item(main_tree, hf_result, tvb, offset, -1, ENC_NA | ENC_ASCII);
            if (data_length < tvb_length_remaining(tvb, offset)) {
                expert_add_info(pinfo, sub_item, &ei_incomplete_message);
            }
        } else if (g_str_has_prefix(service, "framebuffer:")) {
            if (data_in == pinfo->fd->num) {
                if (!pinfo->fd->flags.visited && client_request && client_request->data.allocated == NULL) {
                    client_request->data.framebuffer_data = wmem_new(wmem_file_scope(), framebuffer_data_t);
                    memset(client_request->data.framebuffer_data, 0, sizeof(framebuffer_data_t));
                }

                proto_tree_add_item(main_tree, hf_framebuffer_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_red_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (!pinfo->fd->flags.visited && client_request && client_request->data.framebuffer_data)
                    client_request->data.framebuffer_data->red_offset = tvb_get_letohl(tvb, offset);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_red_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (!pinfo->fd->flags.visited && client_request && client_request->data.framebuffer_data)
                    client_request->data.framebuffer_data->red_length = tvb_get_letohl(tvb, offset);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_blue_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (!pinfo->fd->flags.visited && client_request && client_request->data.framebuffer_data)
                    client_request->data.framebuffer_data->blue_offset = tvb_get_letohl(tvb, offset);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_blue_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (!pinfo->fd->flags.visited && client_request && client_request->data.framebuffer_data)
                    client_request->data.framebuffer_data->blue_length = tvb_get_letohl(tvb, offset);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_green_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (!pinfo->fd->flags.visited && client_request && client_request->data.framebuffer_data)
                    client_request->data.framebuffer_data->green_offset = tvb_get_letohl(tvb, offset);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_green_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (!pinfo->fd->flags.visited && client_request && client_request->data.framebuffer_data)
                    client_request->data.framebuffer_data->green_length = tvb_get_letohl(tvb, offset);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_alpha_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (!pinfo->fd->flags.visited && client_request && client_request->data.framebuffer_data)
                    client_request->data.framebuffer_data->alpha_offset = tvb_get_letohl(tvb, offset);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_alpha_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (!pinfo->fd->flags.visited && client_request && client_request->data.framebuffer_data)
                    client_request->data.framebuffer_data->alpha_length = tvb_get_letohl(tvb, offset);
                offset += 4;
            }

            if (tvb_length_remaining(tvb, offset) > 0) {
                proto_item  *pixel_item;
                proto_tree  *pixel_tree;

                sub_item = proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_data);

                if (pref_dissect_more_detail_framebuffer) {
                    if (client_request && client_request->data.framebuffer_data &&
                        client_request->data.framebuffer_data->red_length == 5 &&
                        client_request->data.framebuffer_data->green_length == 6 &&
                        client_request->data.framebuffer_data->blue_length == 5 &&
                        client_request->data.framebuffer_data->red_offset == 11 &&
                        client_request->data.framebuffer_data->green_offset == 5 &&
                        client_request->data.framebuffer_data->blue_offset == 0) {
                        while (tvb_length_remaining(tvb, offset) > 0) {
                            if (tvb_length_remaining(tvb, offset) < 2) {
                                proto_tree_add_item(main_tree, hf_fragment, tvb, offset, -1, ENC_NA);
                                offset += 1;
                            }

                            pixel_item = proto_tree_add_item(sub_tree, hf_framebuffer_pixel, tvb, offset, 2, ENC_NA);
                            pixel_tree = proto_item_add_subtree(pixel_item, ett_pixel);

                            proto_tree_add_item(pixel_tree, hf_framebuffer_blue_5, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(pixel_tree, hf_framebuffer_green_6, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(pixel_tree, hf_framebuffer_red_5, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                            offset += 2;
                        }
                    } else if (client_request && client_request->data.framebuffer_data &&
                            client_request->data.framebuffer_data->red_length == 8 &&
                            client_request->data.framebuffer_data->green_length == 8 &&
                            client_request->data.framebuffer_data->blue_length == 8 &&
                            (client_request->data.framebuffer_data->alpha_length == 0 ||
                            client_request->data.framebuffer_data->alpha_length == 8)) {
                        while (tvb_length_remaining(tvb, offset) > 0) {
                            if (tvb_length_remaining(tvb, offset) < 3 || (tvb_length_remaining(tvb, offset) < 4 && client_request->data.framebuffer_data->alpha_offset > 0)) {
                                proto_tree_add_item(main_tree, hf_fragment, tvb, offset, -1, ENC_NA);
                                offset = tvb_length(tvb);
                                break;
                            }

                            pixel_item = proto_tree_add_item(sub_tree, hf_framebuffer_pixel, tvb, offset, 3, ENC_NA);
                            pixel_tree = proto_item_add_subtree(pixel_item, ett_pixel);

                            proto_tree_add_item(pixel_tree, hf_framebuffer_red, tvb, offset + client_request->data.framebuffer_data->red_offset / 8, 1, ENC_NA);
                            proto_tree_add_item(pixel_tree, hf_framebuffer_green, tvb, offset + client_request->data.framebuffer_data->green_offset / 8, 1, ENC_NA);
                            proto_tree_add_item(pixel_tree, hf_framebuffer_blue, tvb, offset + client_request->data.framebuffer_data->blue_offset / 8, 1, ENC_NA);

                            if (client_request->data.framebuffer_data->alpha_offset > 0) {
                                if (client_request->data.framebuffer_data->alpha_length == 0)
                                    proto_tree_add_item(pixel_tree, hf_framebuffer_unused, tvb, offset + client_request->data.framebuffer_data->alpha_offset / 8, 1, ENC_NA);
                                else
                                    proto_tree_add_item(pixel_tree, hf_framebuffer_alpha, tvb, offset + client_request->data.framebuffer_data->alpha_offset / 8, 1, ENC_NA);
                                offset += 1;
                                proto_item_set_len(pixel_item, 4);
                            }
                            offset += 3;
                        }
                    } else {
                        offset = tvb_length(tvb);
                    }
                } else {
                    offset = tvb_length(tvb);
                }
            }
        } else if (g_strcmp0(service, "track-jdwp") == 0) {
            gint  data_length;

            offset = dissect_ascii_data_length(main_tree, tvb, offset, &data_length);

            if (tvb_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_pids, tvb, offset, -1, ENC_NA | ENC_ASCII);
                if (data_length < tvb_length_remaining(tvb, offset)) {
                    expert_add_info(pinfo, sub_item, &ei_incomplete_message);
                }
            }
            offset = tvb_length(tvb);
        } else if ((g_strcmp0(service, "shell:export ANDROID_LOG_TAGS=\"\" ; exec logcat -B") == 0) ||
                (g_strcmp0(service, "shell:logcat -B") == 0)) {
            tvbuff_t    *next_tvb;
            tvbuff_t    *new_tvb;
            guint8      *buffer = NULL;
            gint         size = 0;
            gint         i_offset = offset;
            gint         old_offset;
            gint         i_char = 0;
            guint8       c1;
            guint8       c2 = '\0';
            guint16      payload_length;
            guint16      try_header_size;
            gint         logcat_length = 0;
            fragment_t  *fragment;

            if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
                wireshark_interface_id = pinfo->phdr->interface_id;

            key[0].length = 1;
            key[0].key = &wireshark_interface_id;
            key[1].length = 1;
            key[1].key = &pinfo->destport;
            key[2].length = 1;
            key[2].key = &pinfo->srcport;
            key[3].length = 0;
            key[3].key = NULL;

            subtree = (wmem_tree_t *) wmem_tree_lookup32_array(fragments, key);
            fragment = (subtree) ? (fragment_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num - 1) : NULL;
            if (fragment) {
                if (!pinfo->fd->flags.visited && fragment->reassembled_in_frame == -1)
                    fragment->reassembled_in_frame = pinfo->fd->num;

                if (fragment->reassembled_in_frame == pinfo->fd->num) {
                    size += fragment->length;
                    i_char += fragment->length;
                }
            }

            size += tvb_length_remaining(tvb, i_offset);
            if (size > 0) {
                buffer = (guint8 *) wmem_alloc(pinfo->pool, size);
                if (fragment && i_char > 0)
                    memcpy(buffer, fragment->data, i_char);

                if (i_char >= 1 && buffer[i_char - 1] == '\r' && tvb_get_guint8(tvb, i_offset) == '\n') {
                    buffer[i_char - 1] = '\n';
                    i_offset += 1;
                }

                c1 = tvb_get_guint8(tvb, i_offset);
                i_offset += 1;
                old_offset = i_offset;

                while (tvb_length_remaining(tvb, i_offset) > 0) {
                    c2 = tvb_get_guint8(tvb, i_offset);

                    if (c1 == '\r' && c2 == '\n') {
                        buffer[i_char] = c2;
                        if (tvb_length_remaining(tvb, i_offset) > 1) {
                            c1 = tvb_get_guint8(tvb, i_offset + 1);
                            i_offset += 2;
                            i_char += 1;
                        } else {
                            i_offset += 1;
                        }

                        continue;
                    }

                    buffer[i_char] = c1;
                    c1 = c2;
                    i_char += 1;
                    i_offset += 1;
                }

                if (tvb_length_remaining(tvb, old_offset) == 0) {
                    buffer[i_char] = c1;
                    i_char += 1;
                } else if (tvb_length_remaining(tvb, old_offset) > 0) {
                    buffer[i_char] = c2;
                    i_char += 1;
                }

                next_tvb = tvb_new_child_real_data(tvb, buffer, i_char, i_char);
                add_new_data_source(pinfo, next_tvb, "Logcat");

                i_offset = 0;
                while (tvb_length_remaining(next_tvb, i_offset) > 0) {
                    if (tvb_length_remaining(next_tvb, i_offset) >= 4) {
                        payload_length = tvb_get_letohs(next_tvb, i_offset);
                        try_header_size = tvb_get_letohs(next_tvb, i_offset + 2);

                        if (try_header_size == 0 || try_header_size != 24)
                            logcat_length = payload_length + 20;
                        else
                            logcat_length = payload_length + 24;
                    }

                    if (tvb_length_remaining(next_tvb, i_offset) >= 4 && tvb_length_remaining(next_tvb, i_offset) >= logcat_length) {
                        new_tvb = tvb_new_subset_length(next_tvb, i_offset, logcat_length);

                        call_dissector(logcat_handle, new_tvb, pinfo, main_tree);
                        i_offset += logcat_length;
                    } else {

                        if (!pinfo->fd->flags.visited) {
                            if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
                                wireshark_interface_id = pinfo->phdr->interface_id;

                            key[0].length = 1;
                            key[0].key = &wireshark_interface_id;
                            key[1].length = 1;
                            key[1].key = &pinfo->destport;
                            key[2].length = 1;
                            key[2].key = &pinfo->srcport;
                            key[3].length = 1;
                            key[3].key = &pinfo->fd->num;
                            key[4].length = 0;
                            key[4].key = NULL;

                            fragment = wmem_new(wmem_file_scope(), fragment_t);

                            fragment->length = tvb_length_remaining(next_tvb, i_offset);
                            fragment->data = (guint8 *) wmem_alloc(wmem_file_scope(), fragment->length);
                            tvb_memcpy(next_tvb, fragment->data, i_offset, fragment->length);
                            fragment->reassembled_in_frame = -1;

                            wmem_tree_insert32_array(fragments, key, fragment);
                        }

                        proto_tree_add_item(main_tree, hf_fragment, next_tvb, i_offset, -1, ENC_NA);
                        i_offset = tvb_length(next_tvb);
                    }
                }
            }

            offset = tvb_length(tvb);
        } else if (g_str_has_prefix(service, "shell:")) {
            proto_tree_add_item(main_tree, hf_stdout, tvb, offset, -1, ENC_NA | ENC_ASCII);
            offset = tvb_length(tvb);
        } else if (g_str_has_prefix(service, "jdwp:")) {
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_length(tvb);
        } else if (g_str_has_prefix(service, "sync:")) {
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_length(tvb);
        } else if (g_strcmp0(service, "host:list-forward") == 0 ||
                g_str_has_prefix(service, "root:") ||
                g_str_has_prefix(service, "remount:")  ||
                g_str_has_prefix(service, "tcpip:")  ||
                g_str_has_prefix(service, "usb:")) {
            if (tvb_length_remaining(tvb, offset)) {
                proto_tree_add_item(main_tree, hf_result, tvb, offset, -1, ENC_NA | ENC_ASCII);
                offset = tvb_length(tvb);
            }
        } else {
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_length(tvb);
        }

    } else {
        tvbuff_t         *next_tvb;

        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown role");

        p_item = proto_tree_add_uint(main_tree, hf_role, tvb, offset, 0, 0x00);
        PROTO_ITEM_SET_GENERATED(p_item);

        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(data_handle, next_tvb, pinfo, main_tree);
        offset += tvb_length_remaining(tvb, offset);
    }

    return offset;
}

void
proto_register_adb_cs(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_role,
            { "Role",                            "adb_cs.role",
            FT_UINT8, BASE_HEX, VALS(role_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_hex_ascii_length,
            { "Hex ASCII Length",                "adb_cs.hex_ascii_length",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_length,
            { "Length",                          "adb_cs.length",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hex_ascii_version,
            { "Hex ASCII String Version",        "adb_cs.hex_ascii_version",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_version,
            { "Version",                         "adb_cs.version",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_service,
            { "Service",                         "adb_cs.service",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_fail_reason,
            { "Fail Reason",                     "adb_cs.fail_reason",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_status,
            { "Status",                          "adb_cs.status",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_fragment,
            { "Fragment",                        "adb_cs.fragment",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data,
            { "Data",                            "adb_cs.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_version,
            { "Version",                         "adb_cs.framebuffer.version",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_depth,
            { "Depth",                           "adb_cs.framebuffer.depth",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_size,
            { "Size",                           "adb_cs.framebuffer.size",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_width,
            { "Width",                           "adb_cs.framebuffer.width",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_height,
            { "Height",                          "adb_cs.framebuffer.height",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_red_offset,
            { "Red Offset",                      "adb_cs.framebuffer.red_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_red_length,
            { "Red Length",                      "adb_cs.framebuffer.red_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_blue_offset,
            { "Blue Offset",                     "adb_cs.framebuffer.blue_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_blue_length,
            { "Blue Length",                     "adb_cs.framebuffer.blue_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_green_offset,
            { "Green Offset",                    "adb_cs.framebuffer.green_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_green_length,
            { "Green Length",                    "adb_cs.framebuffer.green_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_alpha_offset,
            { "Alpha Offset",                    "adb_cs.framebuffer.alpha_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_alpha_length,
            { "Alpha Length",                    "adb_cs.framebuffer.alpha_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_pixel,
            { "Pixel",                           "adb_cs.framebuffer.pixel",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_blue_5,
            { "Blue",                            "adb_cs.framebuffer.pixel.blue",
            FT_UINT16, BASE_DEC, NULL, 0xF800,
            NULL, HFILL }
        },
        { &hf_framebuffer_green_6,
            { "Green",                           "adb_cs.framebuffer.pixel.green",
            FT_UINT16, BASE_DEC, NULL, 0x07E0,
            NULL, HFILL }
        },
        { &hf_framebuffer_red_5,
            { "Red",                             "adb_cs.framebuffer.pixel.red",
            FT_UINT16, BASE_DEC, NULL, 0x001F,
            NULL, HFILL }
        },
        { &hf_framebuffer_blue,
            { "Blue",                            "adb_cs.framebuffer.pixel.blue",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_green,
            { "Green",                           "adb_cs.framebuffer.pixel.green",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_red,
            { "Red",                             "adb_cs.framebuffer.pixel.red",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_alpha,
            { "Alpha",                           "adb_cs.framebuffer.pixel.alpha",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_unused,
            { "Unused",                          "adb_cs.framebuffer.pixel.unused",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_devices,
            { "Devices",                         "adb_cs.devices",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_stdin,
            { "Stdin",                           "adb_cs.stdin",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_stdout,
            { "Stdout",                          "adb_cs.stdout",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_result,
            { "Result",                          "adb_cs.result",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pids,
            { "PIDs",                            "adb_cs.pids",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_adb_cs,
        &ett_length,
        &ett_version,
        &ett_pixel,
        &ett_data
    };

    static ei_register_info ei[] = {
        { &ei_incomplete_message,         { "adb_cs.expert.incomplete_message", PI_PROTOCOL, PI_WARN, "Incomplete message", EXPFILL }},
    };

    client_requests = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    fragments = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_adb_cs = proto_register_protocol("Android Debug Bridge Client-Server", "ADB CS", "adb_cs");
    adb_cs_handle = new_register_dissector("adb_cs", dissect_adb_cs, proto_adb_cs);

    proto_register_field_array(proto_adb_cs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module = expert_register_protocol(proto_adb_cs);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_adb_cs, NULL);
    prefs_register_static_text_preference(module, "version",
            "ADB CS protocol version is compatibile pior to: adb 1.0.31",
            "Version of protocol supported by this dissector.");

    prefs_register_uint_preference(module, "server_port",
         "Server Port",
         "Server Port",
         10, &server_port);

    prefs_register_bool_preference(module, "framebuffer_more_details",
            "Dissect more detail for framebuffer service",
            "Dissect more detail for framebuffer service",
            &pref_dissect_more_detail_framebuffer);
}

void
proto_reg_handoff_adb_cs(void)
{
    logcat_handle = find_dissector("logcat");
    data_handle   = find_dissector("data");

    dissector_add_for_decode_as("tcp.port", adb_cs_handle);
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
