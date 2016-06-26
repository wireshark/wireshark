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
#include <wiretap/wtap.h>

#include "packet-adb_service.h"

static int proto_adb_cs                                                    = -1;

static int hf_role                                                         = -1;
static int hf_hex_ascii_length                                             = -1;
static int hf_length                                                       = -1;
static int hf_service                                                      = -1;
static int hf_status                                                       = -1;
static int hf_data                                                         = -1;
static int hf_fail_reason                                                  = -1;

static gint ett_adb_cs                                                     = -1;
static gint ett_length                                                     = -1;

static expert_field ei_incomplete_message                             = EI_INIT;

static dissector_handle_t  adb_cs_handle;
static dissector_handle_t  adb_service_handle;

static wmem_tree_t *client_requests = NULL;

static guint server_port = 5037;

typedef struct _client_request_t {
    gint64    service_length;
    guint8   *service;
    guint32   first_in;
    gint64    service_in;
    gint64    response_frame;

    guint8    status;
    gint64    data_length;
} client_request_t;

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
dissect_adb_cs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *main_item;
    proto_tree  *main_tree;
    proto_item  *sub_item;
    proto_item  *p_item;
    gint         offset = 0;
    gint64       length = -1;
    gint         direction;
    gboolean     client_request_service = FALSE;
    tvbuff_t           *next_tvb;
    adb_service_data_t  adb_service_data;
    guint32             wireshark_interface_id = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADB CS");
    col_clear(pinfo->cinfo, COL_INFO);

    main_item = proto_tree_add_item(tree, proto_adb_cs, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_adb_cs);

    if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
        wireshark_interface_id = pinfo->phdr->interface_id;

    if (pinfo->destport == server_port) { /* Client sent to Server */
        client_request_t  *client_request;
        guint8            *service = SERVICE_NONE;
        wmem_tree_t       *subtree;
        wmem_tree_key_t    key[5];

        direction = P2P_DIR_SENT;

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
        client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
        if (client_request && client_request->service_in > -1 && client_request->service_in < pinfo->num) {
            p_item = proto_tree_add_string(main_tree, hf_service, tvb, offset, 0, client_request->service);
            PROTO_ITEM_SET_GENERATED(p_item);
            service = client_request->service;
            client_request_service = TRUE;
        } else {
            if (client_request && client_request->service_in > -1 && client_request->service_in <= pinfo->num)
               client_request_service = TRUE;
            client_request = NULL;
        }

        /* heuristic to recognize type of (partial) packet */
        if (tvb_reported_length_remaining(tvb, offset) >= 4) {
            guint8  hex_ascii_length[5];
            guint32 ulength;

            hex_ascii_length[4] = 0;

            tvb_memcpy(tvb, hex_ascii_length, offset, 4);
            if (g_ascii_xdigit_value(hex_ascii_length[0]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[1]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[2]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[3]) >= 0) {
                /* probably 4 bytes ascii hex length field */
                offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_length, ett_length, hf_length, tvb, offset, &ulength);
                length = (gint64) ulength;
                col_append_fstr(pinfo->cinfo, COL_INFO, " Length=%u", ulength);
            }
        }


        if (length == -1 && service) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);

            /* Decode services */
            adb_service_data.service = service;
            adb_service_data.direction = direction;

            adb_service_data.session_key_length = 3;
            adb_service_data.session_key = (guint32 *) wmem_alloc(wmem_packet_scope(), adb_service_data.session_key_length * sizeof(guint32));
            adb_service_data.session_key[0] = wireshark_interface_id;
            adb_service_data.session_key[1] = pinfo->destport;
            adb_service_data.session_key[2] = pinfo->srcport;

            next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset), tvb_captured_length_remaining(tvb, offset));
            call_dissector_with_data(adb_service_handle, next_tvb, pinfo, tree, &adb_service_data);

            return tvb_captured_length(tvb);
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
            key[3].key = &pinfo->num;
            key[4].length = 0;
            key[4].key = NULL;

            client_request = wmem_new(wmem_file_scope(), client_request_t);

            client_request->service_length = length;
            client_request->service = SERVICE_NONE;
            client_request->response_frame = -1;
            client_request->first_in = pinfo->num;
            client_request->service_in = -1;
            client_request->data_length = -1;
            wmem_tree_insert32_array(client_requests, key, client_request);
        }

        if (!pinfo->fd->flags.visited && (length == -1 || (client_request && client_request->service_in == -1 && tvb_reported_length_remaining(tvb, offset) > 0))) { /* save Service to client_requests */
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
                client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->num - 1) : NULL;
            }

            if (client_request) {
                client_request->service = (guint8 *) wmem_alloc(wmem_file_scope(), (const size_t)(client_request->service_length + 1));
                tvb_memcpy(tvb, client_request->service, offset, (size_t) client_request->service_length);
                client_request->service[client_request->service_length] = '\0';
                client_request->service_in = pinfo->num;
            }
        }

        if (!client_request_service && tvb_reported_length_remaining(tvb, offset) > 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Unknown service");
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
        } else if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(main_tree, hf_service, tvb, offset, -1, ENC_NA | ENC_ASCII);

            service = (guint8 *) wmem_alloc(wmem_packet_scope(), tvb_reported_length_remaining(tvb, offset) + 1);
            tvb_memcpy(tvb, service, offset, tvb_reported_length_remaining(tvb, offset));
            service[tvb_reported_length_remaining(tvb, offset)] = '\0';
            col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);
        }

        offset = tvb_captured_length(tvb);

    } else if (pinfo->srcport == server_port) { /* Server sent to Client */
        guint8             *service = SERVICE_NONE;
        wmem_tree_t        *subtree;
        wmem_tree_key_t     key[5];
        client_request_t   *client_request;
        gint64              response_frame = -1;
        guint8              status = STATUS_UNKNOWN;

        direction = P2P_DIR_RECV;

        key[0].length = 1;
        key[0].key = &wireshark_interface_id;
        key[1].length = 1;
        key[1].key = &pinfo->destport;
        key[2].length = 1;
        key[2].key = &pinfo->srcport;
        key[3].length = 0;
        key[3].key = NULL;

        subtree = (wmem_tree_t *) wmem_tree_lookup32_array(client_requests, key);
        client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->num - 1) : NULL;
        if (client_request) {
            service = client_request->service;
            status = client_request->status;
            length = client_request->data_length;
            response_frame = client_request->response_frame;
        }

        p_item = proto_tree_add_uint(main_tree, hf_role, tvb, offset, 0, 0x01);
        PROTO_ITEM_SET_GENERATED(p_item);

        p_item = proto_tree_add_string(main_tree, hf_service, tvb, offset, 0, service);
        PROTO_ITEM_SET_GENERATED(p_item);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Server");

        if (!service) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Unknown service");
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);

            return tvb_captured_length(tvb);
        }

        if (response_frame == -1 || response_frame == (gint64) pinfo->num) {
            proto_tree_add_item(main_tree, hf_status, tvb, offset, 4, ENC_NA | ENC_ASCII);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Status=%c%c%c%c", tvb_get_guint8(tvb, offset),
            tvb_get_guint8(tvb, offset + 1), tvb_get_guint8(tvb, offset + 2), tvb_get_guint8(tvb, offset + 3));
            offset += 4;

            if (tvb_memeql(tvb, offset - 4, "FAIL", 4) == 0) {
                guint32 ulength;

                offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_length, ett_length, hf_length, tvb, offset, &ulength);
                length = (gint64) ulength;

                status = STATUS_FAIL;
            } else if (tvb_memeql(tvb, offset - 4, "OKAY", 4) == 0) {
                status = STATUS_OKAY;
                length = -1;
            }

            if (!pinfo->fd->flags.visited && client_request) {
                client_request->response_frame = pinfo->num;
                client_request->status = status;
                client_request->data_length = length;
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);

        if (tvb_reported_length_remaining(tvb, offset) <= 0) return offset;

        if (status == STATUS_FAIL) {
            const guint8* str;
            sub_item = proto_tree_add_item_ret_string(main_tree, hf_fail_reason, tvb, offset,
                            tvb_reported_length_remaining(tvb, offset), ENC_NA | ENC_ASCII, wmem_packet_scope(), &str);
            if (length < tvb_reported_length_remaining(tvb, offset)) {
                expert_add_info(pinfo, sub_item, &ei_incomplete_message);
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " Fail=<%s>", str);
            return tvb_captured_length(tvb);
        }

        /* Decode services */
        adb_service_data.service = service;
        adb_service_data.direction = direction;

        adb_service_data.session_key_length = 3;
        adb_service_data.session_key = (guint32 *) wmem_alloc(wmem_packet_scope(), adb_service_data.session_key_length * sizeof(guint32));
        adb_service_data.session_key[0] = wireshark_interface_id;
        adb_service_data.session_key[1] = pinfo->destport;
        adb_service_data.session_key[2] = pinfo->srcport;

        next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset), tvb_captured_length_remaining(tvb, offset));
        call_dissector_with_data(adb_service_handle, next_tvb, pinfo, tree, &adb_service_data);
        offset = tvb_captured_length(tvb);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown role");

        p_item = proto_tree_add_uint(main_tree, hf_role, tvb, offset, 0, 0x00);
        PROTO_ITEM_SET_GENERATED(p_item);

        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, main_tree);
        offset += tvb_captured_length_remaining(tvb, offset);
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
        { &hf_data,
            { "Data",                            "adb_cs.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_adb_cs,
        &ett_length
    };

    static ei_register_info ei[] = {
        { &ei_incomplete_message,         { "adb_cs.expert.incomplete_message", PI_PROTOCOL, PI_WARN, "Incomplete message", EXPFILL }},
    };

    client_requests = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_adb_cs = proto_register_protocol("Android Debug Bridge Client-Server", "ADB CS", "adb_cs");
    adb_cs_handle = register_dissector("adb_cs", dissect_adb_cs, proto_adb_cs);

    proto_register_field_array(proto_adb_cs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module = expert_register_protocol(proto_adb_cs);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_adb_cs, NULL);
    prefs_register_static_text_preference(module, "version",
            "ADB CS protocol version is compatible prior to: adb 1.0.31",
            "Version of protocol supported by this dissector.");

    prefs_register_uint_preference(module, "server_port",
            "Server Port",
            "Server Port",
            10, &server_port);
}

void
proto_reg_handoff_adb_cs(void)
{
    adb_service_handle = find_dissector_add_dependency("adb_service", proto_adb_cs);

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
