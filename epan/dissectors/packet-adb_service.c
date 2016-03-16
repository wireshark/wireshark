/* packet-adb_service.c
 * Routines for Android Debug Bridge Services
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

#include "packet-adb_service.h"

static int proto_adb_service                                               = -1;

static int hf_service                                                      = -1;
static int hf_fragment                                                     = -1;
static int hf_data                                                         = -1;
static int hf_hex_ascii_length                                             = -1;
static int hf_length                                                       = -1;
static int hf_version                                                      = -1;
static int hf_hex_ascii_version                                            = -1;
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
static int hf_sync_id                                                      = -1;
static int hf_sync_length                                                  = -1;
static int hf_sync_mode                                                    = -1;
static int hf_sync_size                                                    = -1;
static int hf_sync_time                                                    = -1;
static int hf_sync_unused                                                  = -1;
static int hf_sync_data                                                    = -1;

static expert_field ei_incomplete_message                             = EI_INIT;

static gint ett_adb_service                                                = -1;
static gint ett_length                                                     = -1;
static gint ett_version                                                    = -1;
static gint ett_pixel                                                      = -1;
static gint ett_data                                                       = -1;

static dissector_handle_t  adb_service_handle;
static dissector_handle_t  logcat_handle;

static gboolean pref_dissect_more_detail_framebuffer = FALSE;

static wmem_tree_t *fragments = NULL;
static wmem_tree_t *framebuffer_infos = NULL;
static wmem_tree_t *continuation_infos = NULL;

typedef struct _framebuffer_data_t {
    guint32 data_in;
    guint32 current_size;
    guint32 completed_in_frame;

    guint32 size;
    guint32 red_offset;
    guint32 red_length;
    guint32 green_offset;
    guint32 green_length;
    guint32 blue_offset;
    guint32 blue_length;
    guint32 alpha_offset;
    guint32 alpha_length;
} framebuffer_data_t;

typedef struct _fragment_t {
    gint64    reassembled_in_frame;
    gint      length;
    guint8   *data;
} fragment_t;

typedef struct _continuation_data_t {
    guint32   length_in_frame;
    guint32   completed_in_frame;
    gint      length;
} continuation_data_t;

void proto_register_adb_service(void);
void proto_reg_handoff_adb_service(void);

gint
dissect_ascii_uint32(proto_tree *tree, gint hf_hex_ascii, gint ett_hex_ascii,
        gint hf_value, tvbuff_t *tvb, gint offset, guint32 *value)
{
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    guint8       hex_ascii[5];

    DISSECTOR_ASSERT(value);

    tvb_memcpy(tvb, hex_ascii, offset, 4);
    hex_ascii[4]='\0';

    sub_item = proto_tree_add_item(tree, hf_hex_ascii, tvb, offset, 4, ENC_NA | ENC_ASCII);
    sub_tree = proto_item_add_subtree(sub_item, ett_hex_ascii);

    *value = (guint32) g_ascii_strtoull(hex_ascii, NULL, 16);

    proto_tree_add_uint(sub_tree, hf_value, tvb, offset, 4, *value);
    offset += 4;

    return offset;
}

static gint
dissect_adb_service(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *main_item;
    proto_tree          *main_tree;
    proto_item          *sub_item;
    proto_tree          *sub_tree;
    gint                 offset = 0;
    adb_service_data_t  *adb_service_data = (adb_service_data_t *) data;
    const guint8        *service;
    wmem_tree_key_t      key[5];
    wmem_tree_t         *subtree;
    guint32              i_key;

    main_item = proto_tree_add_item(tree, proto_adb_service, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_adb_service);

    DISSECTOR_ASSERT(adb_service_data);

    service = adb_service_data->service;

    sub_item = proto_tree_add_string(main_tree, hf_service, tvb, offset, 0, service);
    PROTO_ITEM_SET_GENERATED(sub_item);

        if (g_strcmp0(service, "host:version") == 0) {
            guint32               version;
            guint32               data_length;
            continuation_data_t  *continuation_data;

            DISSECTOR_ASSERT_HINT(adb_service_data->session_key_length + 1 <= sizeof(key) / sizeof(key[0]), "Tree session key is too small");
            for (i_key = 0; i_key < adb_service_data->session_key_length; i_key += 1) {
                key[i_key].length = 1;
                key[i_key].key = &adb_service_data->session_key[i_key];
            }
            key[i_key].length = 0;
            key[i_key].key = NULL;

            subtree = (wmem_tree_t *) wmem_tree_lookup32_array(continuation_infos, key);
            continuation_data = (subtree) ? (continuation_data_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
            if (continuation_data && continuation_data->completed_in_frame < pinfo->num)
                continuation_data = NULL;

            if (!continuation_data || (continuation_data && continuation_data->length_in_frame == pinfo->num))
                offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_length, ett_length, hf_length, tvb, offset, &data_length);

            if (!pinfo->fd->flags.visited && !continuation_data && tvb_reported_length_remaining(tvb, offset) < 4) {
                key[i_key].length = 1;
                key[i_key++].key = &pinfo->num;
                key[i_key].length = 0;
                key[i_key].key = NULL;

                continuation_data = wmem_new(wmem_file_scope(), continuation_data_t);
                continuation_data->length_in_frame = pinfo->num;
                continuation_data->completed_in_frame = G_MAXUINT32;
                continuation_data->length = data_length;

                wmem_tree_insert32_array(continuation_infos, key, continuation_data);
                continuation_data = NULL;
            }

            if (tvb_reported_length_remaining(tvb, offset) >= 4 ||
                        (continuation_data && continuation_data->completed_in_frame == pinfo->num)) {
                if (!pinfo->fd->flags.visited && continuation_data) {
                    continuation_data->completed_in_frame = pinfo->num;
                }
                offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_version, ett_version, hf_version, tvb, offset, &version);

                col_append_fstr(pinfo->cinfo, COL_INFO, " Version=%u", version);
            }

        } else if (g_strcmp0(service, "host:devices") == 0 ||
                g_strcmp0(service, "host:devices-l") == 0 ||
                g_strcmp0(service, "host:track-devices") == 0) {
            guint32  data_length;

            offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_length, ett_length, hf_length, tvb, offset, &data_length);

            sub_item = proto_tree_add_item(main_tree, hf_devices, tvb, offset, -1, ENC_NA | ENC_ASCII);
            if ((gint64) data_length < tvb_reported_length_remaining(tvb, offset)) {
                expert_add_info(pinfo, sub_item, &ei_incomplete_message);
            }
        } else if (g_strcmp0(service, "host:get-state") == 0 ||
                g_strcmp0(service, "host:get-serialno") == 0 ||
                g_strcmp0(service, "host:get-devpath") == 0 ||
                g_str_has_prefix(service, "connect:") ||
                g_str_has_prefix(service, "disconnect:")) {
            guint32  data_length;

            offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_length, ett_length, hf_length, tvb, offset, &data_length);

            sub_item = proto_tree_add_item(main_tree, hf_result, tvb, offset, -1, ENC_NA | ENC_ASCII);
            if ((gint64) data_length < tvb_reported_length_remaining(tvb, offset)) {
                expert_add_info(pinfo, sub_item, &ei_incomplete_message);
            }
        } else if (g_str_has_prefix(service, "framebuffer:")) {
            framebuffer_data_t  *framebuffer_data = NULL;

            DISSECTOR_ASSERT_HINT(adb_service_data->session_key_length + 1 <= sizeof(key) / sizeof(key[0]), "Tree session key is too small");
            for (i_key = 0; i_key < adb_service_data->session_key_length; i_key += 1) {
                key[i_key].length = 1;
                key[i_key].key = &adb_service_data->session_key[i_key];
            }
            key[i_key].length = 0;
            key[i_key].key = NULL;

            subtree = (wmem_tree_t *) wmem_tree_lookup32_array(framebuffer_infos, key);
            framebuffer_data = (subtree) ? (framebuffer_data_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
            if (framebuffer_data && framebuffer_data->completed_in_frame < pinfo->num)
                framebuffer_data = NULL;

            if (!pinfo->fd->flags.visited && !framebuffer_data) {
                key[i_key].length = 1;
                key[i_key++].key = &pinfo->num;
                key[i_key].length = 0;
                key[i_key].key = NULL;

                framebuffer_data = wmem_new(wmem_file_scope(), framebuffer_data_t);
                framebuffer_data->data_in      = pinfo->num;
                framebuffer_data->current_size = 0;
                framebuffer_data->completed_in_frame = G_MAXUINT32;
                framebuffer_data->size         = tvb_get_letohl(tvb, offset + 4 * 2);
                framebuffer_data->red_offset   = tvb_get_letohl(tvb, offset + 4 * 5);
                framebuffer_data->red_length   = tvb_get_letohl(tvb, offset + 4 * 6);
                framebuffer_data->green_offset = tvb_get_letohl(tvb, offset + 4 * 7);
                framebuffer_data->green_length = tvb_get_letohl(tvb, offset + 4 * 8);
                framebuffer_data->blue_offset  = tvb_get_letohl(tvb, offset + 4 * 9);
                framebuffer_data->blue_length  = tvb_get_letohl(tvb, offset + 4 * 10);
                framebuffer_data->alpha_offset = tvb_get_letohl(tvb, offset + 4 * 11);
                framebuffer_data->alpha_length = tvb_get_letohl(tvb, offset + 4 * 12);

                wmem_tree_insert32_array(framebuffer_infos, key, framebuffer_data);
            }

            if (framebuffer_data && framebuffer_data->data_in == pinfo->num) {
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
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_red_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_blue_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_blue_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_green_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_green_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_alpha_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_framebuffer_alpha_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
                sub_tree = proto_item_add_subtree(sub_item, ett_data);

                if (!pinfo->fd->flags.visited && framebuffer_data) {
                    framebuffer_data->current_size += tvb_captured_length_remaining(tvb, offset);
                    if (framebuffer_data->current_size >= framebuffer_data->size)
                        framebuffer_data->completed_in_frame = pinfo->num;
                }

                if (pref_dissect_more_detail_framebuffer) {
                    proto_item  *pixel_item;
                    proto_tree  *pixel_tree;

                    if (framebuffer_data &&
                        framebuffer_data->red_length == 5 &&
                        framebuffer_data->green_length == 6 &&
                        framebuffer_data->blue_length == 5 &&
                        framebuffer_data->red_offset == 11 &&
                        framebuffer_data->green_offset == 5 &&
                        framebuffer_data->blue_offset == 0) {
                        while (tvb_reported_length_remaining(tvb, offset) > 0) {
                            if (tvb_reported_length_remaining(tvb, offset) < 2) {
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
                    } else if (framebuffer_data &&
                            framebuffer_data->red_length == 8 &&
                            framebuffer_data->green_length == 8 &&
                            framebuffer_data->blue_length == 8 &&
                            (framebuffer_data->alpha_length == 0 ||
                            framebuffer_data->alpha_length == 8)) {
                        while (tvb_reported_length_remaining(tvb, offset) > 0) {
                            if (tvb_reported_length_remaining(tvb, offset) < 3 || (tvb_reported_length_remaining(tvb, offset) < 4 && framebuffer_data->alpha_offset > 0)) {
                                proto_tree_add_item(main_tree, hf_fragment, tvb, offset, -1, ENC_NA);
                                offset = tvb_captured_length(tvb);
                                break;
                            }

                            pixel_item = proto_tree_add_item(sub_tree, hf_framebuffer_pixel, tvb, offset, 3, ENC_NA);
                            pixel_tree = proto_item_add_subtree(pixel_item, ett_pixel);

                            proto_tree_add_item(pixel_tree, hf_framebuffer_red, tvb, offset + framebuffer_data->red_offset / 8, 1, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(pixel_tree, hf_framebuffer_green, tvb, offset + framebuffer_data->green_offset / 8, 1, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(pixel_tree, hf_framebuffer_blue, tvb, offset + framebuffer_data->blue_offset / 8, 1, ENC_LITTLE_ENDIAN);

                            if (framebuffer_data->alpha_offset > 0) {
                                if (framebuffer_data->alpha_length == 0)
                                    proto_tree_add_item(pixel_tree, hf_framebuffer_unused, tvb, offset + framebuffer_data->alpha_offset / 8, 1, ENC_LITTLE_ENDIAN);
                                else
                                    proto_tree_add_item(pixel_tree, hf_framebuffer_alpha, tvb, offset + framebuffer_data->alpha_offset / 8, 1, ENC_LITTLE_ENDIAN);
                                offset += 1;
                                proto_item_set_len(pixel_item, 4);
                            }
                            offset += 3;
                        }
                    } else {
                        offset = tvb_captured_length(tvb);
                    }
                } else {
                    offset = tvb_captured_length(tvb);
                }
            }
        } else if (g_strcmp0(service, "track-jdwp") == 0) {
            guint32  data_length;

            offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_length, ett_length, hf_length, tvb, offset, &data_length);

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_pids, tvb, offset, -1, ENC_NA | ENC_ASCII);
                if ((gint64) data_length < tvb_reported_length_remaining(tvb, offset)) {
                    expert_add_info(pinfo, sub_item, &ei_incomplete_message);
                }
            }
            offset = tvb_captured_length(tvb);
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

            DISSECTOR_ASSERT_HINT(adb_service_data->session_key_length + 1 <= sizeof(key) / sizeof(key[0]), "Tree session key is too small");
            for (i_key = 0; i_key < adb_service_data->session_key_length; i_key += 1) {
                key[i_key].length = 1;
                key[i_key].key = &adb_service_data->session_key[i_key];
            }
            key[i_key].length = 0;
            key[i_key].key = NULL;

            subtree = (wmem_tree_t *) wmem_tree_lookup32_array(fragments, key);
            fragment = (subtree) ? (fragment_t *) wmem_tree_lookup32_le(subtree, pinfo->num - 1) : NULL;
            if (fragment) {
                if (!pinfo->fd->flags.visited && fragment->reassembled_in_frame == -1)
                    fragment->reassembled_in_frame = pinfo->num;

                if (fragment->reassembled_in_frame == pinfo->num) {
                    size += fragment->length;
                    i_char += fragment->length;
                }
            }

            size += tvb_reported_length_remaining(tvb, i_offset);
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

                while (tvb_reported_length_remaining(tvb, i_offset) > 0) {
                    c2 = tvb_get_guint8(tvb, i_offset);

                    if (c1 == '\r' && c2 == '\n') {
                        buffer[i_char] = c2;
                        if (tvb_reported_length_remaining(tvb, i_offset) > 1) {
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

                if (tvb_reported_length_remaining(tvb, old_offset) == 0) {
                    buffer[i_char] = c1;
                    i_char += 1;
                } else if (tvb_reported_length_remaining(tvb, old_offset) > 0) {
                    buffer[i_char] = c2;
                    i_char += 1;
                }

                next_tvb = tvb_new_child_real_data(tvb, buffer, i_char, i_char);
                add_new_data_source(pinfo, next_tvb, "Logcat");

                i_offset = 0;
                while (tvb_reported_length_remaining(next_tvb, i_offset) > 0) {
                    if (tvb_reported_length_remaining(next_tvb, i_offset) >= 4) {
                        payload_length = tvb_get_letohs(next_tvb, i_offset);
                        try_header_size = tvb_get_letohs(next_tvb, i_offset + 2);

                        if (try_header_size != 24)
                            logcat_length = payload_length + 20;
                        else
                            logcat_length = payload_length + 24;
                    }

                    if (tvb_reported_length_remaining(next_tvb, i_offset) >= 4 && tvb_reported_length_remaining(next_tvb, i_offset) >= logcat_length) {
                        new_tvb = tvb_new_subset_length(next_tvb, i_offset, logcat_length);

                        call_dissector(logcat_handle, new_tvb, pinfo, main_tree);
                        i_offset += logcat_length;
                    } else {

                        if (!pinfo->fd->flags.visited) {
                            DISSECTOR_ASSERT_HINT(adb_service_data->session_key_length + 2 <= sizeof(key) / sizeof(key[0]), "Tree session key is too small");
                            for (i_key = 0; i_key < adb_service_data->session_key_length; i_key += 1) {
                                key[i_key].length = 1;
                                key[i_key].key = &adb_service_data->session_key[i_key];
                            }
                            key[i_key].length = 1;
                            key[i_key++].key = &pinfo->num;
                            key[i_key].length = 0;
                            key[i_key].key = NULL;

                            fragment = wmem_new(wmem_file_scope(), fragment_t);

                            fragment->length = tvb_captured_length_remaining(next_tvb, i_offset);
                            fragment->data = (guint8 *) wmem_alloc(wmem_file_scope(), fragment->length);
                            tvb_memcpy(next_tvb, fragment->data, i_offset, fragment->length);
                            fragment->reassembled_in_frame = -1;

                            wmem_tree_insert32_array(fragments, key, fragment);
                        }

                        proto_tree_add_item(main_tree, hf_fragment, next_tvb, i_offset, -1, ENC_NA);
                        i_offset = tvb_captured_length(next_tvb);
                    }
                }
            }

            offset = tvb_captured_length(tvb);
        } else if (g_str_has_prefix(service, "shell:")) {
            if (adb_service_data->direction == P2P_DIR_SENT) {
                proto_tree_add_item(main_tree, hf_stdin, tvb, offset, -1, ENC_NA | ENC_ASCII);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Stdin=<%s>", tvb_format_text_wsp(tvb, offset, tvb_captured_length_remaining(tvb, offset)));

            } else {
                proto_tree_add_item(main_tree, hf_stdout, tvb, offset, -1, ENC_NA | ENC_ASCII);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Stdout=<%s>", tvb_format_text_wsp(tvb, offset, tvb_captured_length_remaining(tvb, offset)));
            }
            offset = tvb_captured_length(tvb);
        } else if (g_str_has_prefix(service, "jdwp:")) {
/* TODO */
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        } else if (g_str_has_prefix(service, "sync:")) {
/* TODO */
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        } else if (g_strcmp0(service, "host:list-forward") == 0 ||
                g_str_has_prefix(service, "root:") ||
                g_str_has_prefix(service, "remount:")  ||
                g_str_has_prefix(service, "tcpip:")  ||
                g_str_has_prefix(service, "usb:")) {
            if (tvb_reported_length_remaining(tvb, offset)) {
                proto_tree_add_item(main_tree, hf_result, tvb, offset, -1, ENC_NA | ENC_ASCII);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Result=<%s>", tvb_format_text_wsp(tvb, offset, tvb_captured_length_remaining(tvb, offset)));

                offset = tvb_captured_length(tvb);
            }
        } else {
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        }

    return offset;
}


void
proto_register_adb_service(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_service,
            { "Service",                         "adb_service.service",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_fragment,
            { "Fragment",                        "adb_service.fragment",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data,
            { "Data",                            "adb_service.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hex_ascii_length,
            { "Hex ASCII String Length",         "adb_service.hex_ascii_length",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_length,
            { "Length",                          "adb_service.length",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_version,
            { "Version",                         "adb_service.framebuffer.version",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hex_ascii_version,
            { "Hex ASCII String Version",        "adb_service.hex_ascii_version",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_version,
            { "Version",                         "adb_service.version",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_depth,
            { "Depth",                           "adb_service.framebuffer.depth",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_size,
            { "Size",                           "adb_service.framebuffer.size",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_width,
            { "Width",                           "adb_service.framebuffer.width",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_height,
            { "Height",                          "adb_service.framebuffer.height",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_red_offset,
            { "Red Offset",                      "adb_service.framebuffer.red_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_red_length,
            { "Red Length",                      "adb_service.framebuffer.red_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_blue_offset,
            { "Blue Offset",                     "adb_service.framebuffer.blue_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_blue_length,
            { "Blue Length",                     "adb_service.framebuffer.blue_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_green_offset,
            { "Green Offset",                    "adb_service.framebuffer.green_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_green_length,
            { "Green Length",                    "adb_service.framebuffer.green_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_alpha_offset,
            { "Alpha Offset",                    "adb_service.framebuffer.alpha_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_alpha_length,
            { "Alpha Length",                    "adb_service.framebuffer.alpha_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_pixel,
            { "Pixel",                           "adb_service.framebuffer.pixel",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_blue_5,
            { "Blue",                            "adb_service.framebuffer.pixel.blue",
            FT_UINT16, BASE_DEC, NULL, 0xF800,
            NULL, HFILL }
        },
        { &hf_framebuffer_green_6,
            { "Green",                           "adb_service.framebuffer.pixel.green",
            FT_UINT16, BASE_DEC, NULL, 0x07E0,
            NULL, HFILL }
        },
        { &hf_framebuffer_red_5,
            { "Red",                             "adb_service.framebuffer.pixel.red",
            FT_UINT16, BASE_DEC, NULL, 0x001F,
            NULL, HFILL }
        },
        { &hf_framebuffer_blue,
            { "Blue",                            "adb_service.framebuffer.pixel.blue",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_green,
            { "Green",                           "adb_service.framebuffer.pixel.green",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_red,
            { "Red",                             "adb_service.framebuffer.pixel.red",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_alpha,
            { "Alpha",                           "adb_service.framebuffer.pixel.alpha",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_framebuffer_unused,
            { "Unused",                          "adb_service.framebuffer.pixel.unused",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_devices,
            { "Devices",                         "adb_service.devices",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_stdin,
            { "Stdin",                           "adb_service.stdin",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_stdout,
            { "Stdout",                          "adb_service.stdout",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_result,
            { "Result",                          "adb_service.result",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_pids,
            { "PIDs",                            "adb_service.pids",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_sync_id,
            { "Id",                              "adb_service.sync.id",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_sync_length,
            { "Length",                          "adb_service.sync.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_sync_mode,
            { "Mode",                            "adb_service.sync.mode",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_sync_size,
            { "Size",                            "adb_service.sync.size",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_sync_time,
            { "Last Modification Time",          "adb_service.sync.time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_sync_unused,
            { "Unused",                          "adb_service.sync.unused",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_sync_data,
            { "Sync Data",                       "adb_service.sync.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_adb_service,
        &ett_length,
        &ett_version,
        &ett_pixel,
        &ett_data
    };

    static ei_register_info ei[] = {
        { &ei_incomplete_message,         { "adb_service.expert.incomplete_message", PI_PROTOCOL, PI_WARN, "Incomplete message", EXPFILL }},
    };

    fragments          = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    framebuffer_infos  = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    continuation_infos = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_adb_service = proto_register_protocol("Android Debug Bridge Service", "ADB Service", "adb_service");
    adb_service_handle = register_dissector("adb_service", dissect_adb_service, proto_adb_service);

    proto_register_field_array(proto_adb_service, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module = expert_register_protocol(proto_adb_service);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_adb_service, NULL);
    prefs_register_static_text_preference(module, "version",
            "ADB Service protocol version is compatible prior to: adb 1.0.31",
            "Version of protocol supported by this dissector.");

    prefs_register_bool_preference(module, "framebuffer_more_details",
            "Dissect more detail for framebuffer service",
            "Dissect more detail for framebuffer service",
            &pref_dissect_more_detail_framebuffer);
}


void
proto_reg_handoff_adb_service(void)
{
    logcat_handle = find_dissector_add_dependency("logcat", proto_adb_service);
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
