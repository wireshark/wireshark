/* file-btsnoop.c
 * Routines for BTSNOOP File Format
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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

static dissector_handle_t btsnoop_handle;
static dissector_handle_t hci_h1_handle;
static dissector_handle_t hci_h4_handle;
static dissector_handle_t hci_mon_handle;

static int proto_btsnoop = -1;

static int hf_btsnoop_header = -1;
static int hf_btsnoop_magic_bytes = -1;
static int hf_btsnoop_version = -1;
static int hf_btsnoop_datalink = -1;
static int hf_btsnoop_frame = -1;
static int hf_btsnoop_origin_length = -1;
static int hf_btsnoop_included_length = -1;
static int hf_btsnoop_flags = -1;
static int hf_btsnoop_cumulative_dropped_packets = -1;
static int hf_btsnoop_timestamp_microseconds = -1;
static int hf_btsnoop_payload = -1;
static int hf_btsnoop_flags_h1_reserved = -1;
static int hf_btsnoop_flags_h1_channel_type = -1;
static int hf_btsnoop_flags_h1_direction = -1;
static int hf_btsnoop_flags_h4_reserved = -1;
static int hf_btsnoop_flags_h4_direction = -1;
static int hf_btsnoop_flags_linux_monitor_opcode = -1;
static int hf_btsnoop_flags_linux_monitor_adapter_id = -1;

static expert_field ei_malformed_frame = EI_INIT;
static expert_field ei_not_implemented_yet = EI_INIT;
static expert_field ei_unknown_data = EI_INIT;

static gint ett_btsnoop = -1;
static gint ett_btsnoop_header = -1;
static gint ett_btsnoop_frame = -1;
static gint ett_btsnoop_payload = -1;
static gint ett_btsnoop_flags = -1;

static gboolean pref_dissect_next_layer = FALSE;

extern value_string_ext hci_mon_opcode_vals_ext;

static const value_string datalink_vals[] = {
    { 1001,  "H1" },
    { 1002,  "H4 (UART)" },
    { 1003,  "BCSP" },
    { 1004,  "H5 (3 Wire)" },
    { 2001,  "Linux Monitor" },
    { 2002,  "Simulator" },
    { 0, NULL }
};

static const value_string flags_direction_vals[] = {
    { 0x00,  "Received" },
    { 0x01,  "Sent" },
    { 0, NULL }
};

static const value_string flags_h1_channel_type_vals[] = {
    { 0x00,  "ACL" },
    { 0x01,  "HCI" },
    { 0, NULL }
};

void proto_register_btsnoop(void);
void proto_reg_handoff_btsnoop(void);

static int
dissect_btsnoop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static const guint8 magic[] = { 'b', 't', 's', 'n', 'o', 'o', 'p', 0};
    gint             offset = 0;
    guint32          datalink;
    guint32          flags;
    guint32          length;
    proto_tree      *main_tree;
    proto_item      *main_item;
    proto_tree      *header_tree;
    proto_item      *header_item;
    proto_tree      *frame_tree;
    proto_item      *frame_item;
    proto_tree      *flags_tree;
    proto_item      *flags_item;
    proto_tree      *payload_tree;
    proto_item      *payload_item;
    static guint32   frame_number = 1;
    tvbuff_t        *next_tvb;
    nstime_t         timestamp;
    guint64          ts;

    if (tvb_memeql(tvb, 0, magic, sizeof(magic)) != 0)
        return 0;

    if (offset == 0) frame_number = 1;

    main_item = proto_tree_add_item(tree, proto_btsnoop, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btsnoop);

    header_item = proto_tree_add_item(main_tree, hf_btsnoop_header, tvb, offset, sizeof(magic) + 4 + 4, ENC_NA);
    header_tree = proto_item_add_subtree(header_item, ett_btsnoop_header);

    proto_tree_add_item(header_tree, hf_btsnoop_magic_bytes, tvb, offset, sizeof(magic), ENC_ASCII | ENC_NA);
    offset += (gint)sizeof(magic);

    proto_tree_add_item(header_tree, hf_btsnoop_version, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(header_tree, hf_btsnoop_datalink, tvb, offset, 4, ENC_BIG_ENDIAN);
    datalink = tvb_get_ntohl(tvb, offset);
    offset += 4;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        frame_item = proto_tree_add_item(main_tree, hf_btsnoop_frame, tvb, offset, 0, ENC_NA);
        frame_tree = proto_item_add_subtree(frame_item, ett_btsnoop_frame);

        if (tvb_reported_length_remaining(tvb, offset) < 4 * 4 + 8) {
            expert_add_info(pinfo, frame_item, &ei_malformed_frame);
        }

        proto_item_append_text(frame_item, " %u", frame_number);

        proto_tree_add_item(frame_tree, hf_btsnoop_origin_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(frame_tree, hf_btsnoop_included_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        length = tvb_get_ntohl(tvb, offset);
        offset += 4;

        flags_item = proto_tree_add_item(frame_tree, hf_btsnoop_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        flags_tree = proto_item_add_subtree(flags_item, ett_btsnoop_flags);
        flags = tvb_get_ntohl(tvb, offset);
        switch (datalink) {
        case 1001: /* H1 */
            proto_tree_add_item(flags_tree, hf_btsnoop_flags_h1_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(flags_tree, hf_btsnoop_flags_h1_channel_type, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(flags_tree, hf_btsnoop_flags_h1_direction, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        case 1002: /* H4 */
            proto_tree_add_item(flags_tree, hf_btsnoop_flags_h4_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(flags_tree, hf_btsnoop_flags_h4_direction, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        case 2001: /* Linux Monitor */
            proto_tree_add_item(flags_tree, hf_btsnoop_flags_linux_monitor_adapter_id, tvb, offset , 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(flags_tree, hf_btsnoop_flags_linux_monitor_opcode, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            break;
        }
        offset += 4;

        proto_tree_add_item(frame_tree, hf_btsnoop_cumulative_dropped_packets, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        ts =  tvb_get_ntoh64(tvb, offset) - G_GINT64_CONSTANT(0x00dcddb30f2f8000);
        timestamp.secs = (guint)(ts / 1000000);
        timestamp.nsecs =(guint)((ts % 1000000) * 1000);

        proto_tree_add_time(frame_tree, hf_btsnoop_timestamp_microseconds, tvb, offset, 8, &timestamp);
        offset += 8;

        payload_item = proto_tree_add_item(frame_tree, hf_btsnoop_payload, tvb, offset, length, ENC_NA);
        payload_tree = proto_item_add_subtree(payload_item, ett_btsnoop_payload);

        if (pref_dissect_next_layer) switch (datalink) {\
            case 1001: /* H1 */
                pinfo->num = frame_number;
                pinfo->abs_ts = timestamp;

                pinfo->pseudo_header->bthci.sent = (flags & 0x01) ? FALSE : TRUE;
                if (flags & 0x02) {
                    if(pinfo->pseudo_header->bthci.sent)
                        pinfo->pseudo_header->bthci.channel = BTHCI_CHANNEL_COMMAND;
                    else
                        pinfo->pseudo_header->bthci.channel = BTHCI_CHANNEL_EVENT;
                } else {
                    pinfo->pseudo_header->bthci.channel = BTHCI_CHANNEL_ACL;
                }

                next_tvb = tvb_new_subset(tvb, offset, length, length);
                call_dissector(hci_h1_handle, next_tvb, pinfo, payload_tree);
                break;
            case 1002: /* H4 */
                pinfo->num = frame_number;
                pinfo->abs_ts = timestamp;
                pinfo->p2p_dir = (flags & 0x01) ? P2P_DIR_RECV : P2P_DIR_SENT;

                next_tvb = tvb_new_subset(tvb, offset, length, length);
                call_dissector(hci_h4_handle, next_tvb, pinfo, payload_tree);
                break;
            case 2001: /* Linux Monitor */
                pinfo->num = frame_number;
                pinfo->abs_ts = timestamp;

                pinfo->pseudo_header->btmon.opcode = flags & 0xFFFF;
                pinfo->pseudo_header->btmon.adapter_id = flags >> 16;

                next_tvb = tvb_new_subset(tvb, offset, length, length);
                call_dissector(hci_mon_handle, next_tvb, pinfo, payload_tree);
                break;

            case 1003: /* BCSP */
            case 1004: /* H5 (3 Wire) */
            case 2002: /* Simulator */
                /* Not implemented yet */
                proto_tree_add_expert(payload_tree, pinfo, &ei_not_implemented_yet, tvb, offset, length);
                break;
            default:
                /* Unknown */
                proto_tree_add_expert(payload_tree, pinfo, &ei_unknown_data, tvb, offset, length);
        }
        offset += length;

        proto_item_set_len(frame_item, 4 * 4 + 8 + length);
        frame_number += 1;
    }

    return offset;
}

static gboolean
dissect_btsnoop_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_btsnoop(tvb, pinfo, tree, NULL) > 0;
}

void
proto_register_btsnoop(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_btsnoop_header,
            { "Header",                                    "btsnoop.header",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_magic_bytes,
            { "Magic Bytes",                               "btsnoop.header.magic_bytes",
            FT_STRINGZ, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_version,
            { "Version",                                   "btsnoop.header.version",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_datalink,
            { "Datalink",                                  "btsnoop.header.datalink",
            FT_UINT32, BASE_DEC_HEX, VALS(datalink_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_frame,
            { "Frame",                                     "btsnoop.frame",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_origin_length,
            { "Origin Length",                             "btsnoop.frame.origin_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_included_length,
            { "Included Length",                           "btsnoop.frame.included_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_flags,
            { "Flags",                                     "btsnoop.frame.flags",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_cumulative_dropped_packets,
            { "Cumulative Dropped Packets",                "btsnoop.frame.cumulative_dropped_packets",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_timestamp_microseconds,
            { "Timestamp Microseconds",                    "btsnoop.frame.timestamp_microseconds",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_payload,
            { "Payload",                                   "btsnoop.frame.payload",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_flags_h1_reserved,
            { "Reserved",                                  "btsnoop.frame.flags.h1.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFC,
            NULL, HFILL }
        },
        { &hf_btsnoop_flags_h1_channel_type,
            { "Channel Type",                              "btsnoop.frame.flags.h1.channel_type",
            FT_UINT32, BASE_DEC, VALS(flags_h1_channel_type_vals), 0x02,
            NULL, HFILL }
        },
        { &hf_btsnoop_flags_h1_direction,
            { "Direction",                                 "btsnoop.frame.flags.h1.direction",
            FT_UINT32, BASE_DEC, VALS(flags_direction_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_btsnoop_flags_h4_reserved,
            { "Reserved",                                  "btsnoop.frame.flags.h4.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFE,
            NULL, HFILL }
        },
        { &hf_btsnoop_flags_h4_direction,
            { "Direction",                                 "btsnoop.frame.flags.h4.direction",
            FT_UINT32, BASE_DEC, VALS(flags_direction_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_btsnoop_flags_linux_monitor_opcode,
            { "Opcode",                                    "btsnoop.frame.flags.linux_monitor.opcode",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &hci_mon_opcode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_btsnoop_flags_linux_monitor_adapter_id,
            { "Adapter ID",                                "btsnoop.frame.flags.linux_monitor.adapter_id",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_malformed_frame,       { "btsnoop.malformed_frame", PI_PROTOCOL, PI_WARN, "Malformed Frame", EXPFILL }},
        { &ei_not_implemented_yet,   { "btsnoop.not_implemented_yet", PI_PROTOCOL, PI_UNDECODED, "Not implemented yet", EXPFILL }},
        { &ei_unknown_data,          { "btsnoop.unknown_data", PI_PROTOCOL, PI_WARN, "Unknown data", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_btsnoop,
        &ett_btsnoop_header,
        &ett_btsnoop_frame,
        &ett_btsnoop_payload,
        &ett_btsnoop_flags,
    };

    proto_btsnoop = proto_register_protocol("Symbian OS BTSNOOP File Format", "BTSNOOP", "btsnoop");
    proto_register_field_array(proto_btsnoop, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    btsnoop_handle = register_dissector("btsnoop", dissect_btsnoop, proto_btsnoop);

    module = prefs_register_protocol(proto_btsnoop, NULL);
    prefs_register_static_text_preference(module, "version",
            "BTSNOOP version: 1",
            "Version of file-format supported by this dissector.");

    prefs_register_bool_preference(module, "dissect_next_layer",
            "Dissect next layer",
            "Dissect next layer",
            &pref_dissect_next_layer);

    expert_module = expert_register_protocol(proto_btsnoop);
    expert_register_field_array(expert_module, ei, array_length(ei));
}

void
proto_reg_handoff_btsnoop(void)
{
    hci_h1_handle = find_dissector_add_dependency("hci_h1", proto_btsnoop);
    hci_h4_handle = find_dissector_add_dependency("hci_h4", proto_btsnoop);
    hci_mon_handle = find_dissector_add_dependency("hci_mon", proto_btsnoop);

    heur_dissector_add("wtap_file", dissect_btsnoop_heur, "BTSNOOP file", "btsnoop_wtap", proto_btsnoop, HEURISTIC_ENABLE);
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
