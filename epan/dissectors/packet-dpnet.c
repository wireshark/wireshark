/* packet-dpnet.c
 * This is a dissector for the DirectPlay 8 protocol.
 *
 * Copyright 2017 - Alistair Leslie-Hughes
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_dpnet(void);
void proto_reg_handoff_dpnet(void);

#define DPNET_PORT 6073

static int proto_dpnet = -1;

static int hf_dpnet_lead = -1;
static int hf_dpnet_command = -1;
static int hf_dpnet_payload = -1;
static int hf_dpnet_type = -1;
static int hf_dpnet_application = -1;
static int hf_dpnet_data = -1;
static int hf_dpnet_reply_offset = -1;
static int hf_dpnet_response_size = -1;

static int hf_dpnet_desc_size = -1;
static int hf_dpnet_desc_flags = -1;
static int hf_dpnet_max_players = -1;
static int hf_dpnet_current_players = -1;
static int hf_dpnet_session_offset = -1;
static int hf_dpnet_session_size = -1;
static int hf_dpnet_session_name = -1;
static int hf_dpnet_password_offset = -1;
static int hf_dpnet_password_size = -1;
static int hf_dpnet_reserved_offset = -1;
static int hf_dpnet_reserved_size = -1;
static int hf_dpnet_application_offset = -1;
static int hf_dpnet_application_size = -1;
static int hf_dpnet_application_data = -1;
static int hf_dpnet_instance = -1;

static gint ett_dpnet = -1;

#define DPNET_QUERY_GUID     0x01

#define DPNET_ENUM_QUERY     0x02
#define DPNET_ENUM_RESPONSE  0x03

static const value_string packetenumttypes[] = {
    { 1, "Application GUID" },
    { 2, "All Applications" },
    { 0, NULL }
};

static const value_string packetquerytype[] = {
    { 2, "Enumeration Query" },
    { 3, "Enumeration Response" },
    { 0, NULL }
};

static void process_dpnet_query(proto_tree *dpnet_tree, tvbuff_t *tvb, packet_info *pinfo)
{
    gint offset = 0, data_tvb_len;
    guint8  has_guid;
    guint8  is_query;

    proto_tree_add_item(dpnet_tree, hf_dpnet_lead, tvb, 0, 1, ENC_BIG_ENDIAN); offset += 1;
    is_query = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(dpnet_tree, hf_dpnet_command, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(dpnet_tree, hf_dpnet_payload, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;

    if(is_query == DPNET_ENUM_QUERY)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "DPNET Enum Query");

        has_guid = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(dpnet_tree, hf_dpnet_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;

        if (has_guid & DPNET_QUERY_GUID) {
            proto_tree_add_item(dpnet_tree, hf_dpnet_application, tvb, offset, 16, ENC_BIG_ENDIAN);
            offset += 16;
        }

        data_tvb_len = tvb_reported_length_remaining(tvb, offset);
        if(data_tvb_len)
            proto_tree_add_item(dpnet_tree, hf_dpnet_data, tvb, offset, data_tvb_len, ENC_NA);

    }
    else if(is_query == DPNET_ENUM_RESPONSE)
    {
        guint32 session_offset, session_size;
        guint32 application_offset, application_size;

        col_set_str(pinfo->cinfo, COL_INFO, "DPNET Enum Response");

        proto_tree_add_item(dpnet_tree, hf_dpnet_reply_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_response_size, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_desc_size, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_desc_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_max_players, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_current_players, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item_ret_uint(dpnet_tree, hf_dpnet_session_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &session_offset); offset += 4;
        proto_tree_add_item_ret_uint(dpnet_tree, hf_dpnet_session_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &session_size); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_password_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_password_size, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_reserved_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_reserved_size, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item_ret_uint(dpnet_tree, hf_dpnet_application_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &application_offset); offset += 4;
        proto_tree_add_item_ret_uint(dpnet_tree, hf_dpnet_application_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &application_size); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_instance, tvb, offset, 16, ENC_LITTLE_ENDIAN); offset += 16;
        proto_tree_add_item(dpnet_tree, hf_dpnet_application, tvb, offset, 16, ENC_LITTLE_ENDIAN);

        if(session_offset)
        {
            /* session_offset starts from the hf_dpnet_payload */
            proto_tree_add_item(dpnet_tree, hf_dpnet_session_name, tvb, session_offset + 4, session_size, ENC_UTF_16|ENC_LITTLE_ENDIAN);
        }

        if(application_offset)
        {
            /* application_offset starts from the hf_dpnet_payload */
            proto_tree_add_item(dpnet_tree, hf_dpnet_application_data, tvb, application_offset + 4, application_size, ENC_NA);
        }
    }
}

static int
dissect_dpnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    guint8  lead;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPNET");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_dpnet, tvb, 0, -1, ENC_NA);
    proto_tree *dpnet_tree = proto_item_add_subtree(ti, ett_dpnet);

    lead = tvb_get_guint8(tvb, 0);
    if(lead == 0)
    {
        process_dpnet_query(dpnet_tree, tvb, pinfo);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_dpnet(void)
{
    static hf_register_info hf[] = {
        { &hf_dpnet_lead,
            { "Lead", "dpnet.lead",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_command,
            { "Command", "dpnet.command",
            FT_UINT8, BASE_HEX,
            VALS(packetquerytype), 0,
            NULL, HFILL }
        },
        { &hf_dpnet_payload,
            { "Payload", "dpnet.payload",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_type,
            { "Type", "dpnet.type",
            FT_UINT8, BASE_DEC,
            VALS(packetenumttypes), 0,
            NULL, HFILL }
        },
        { &hf_dpnet_application,
            { "Application GUID", "dpnet.application",
            FT_GUID, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data,
            { "Data", "dpnet.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_reply_offset,
            { "Reply Offset", "dpnet.reply_offset",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_response_size,
            { "Response Size", "dpnet.response_size",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_desc_size,
            { "Description Size", "dpnet.desc_size",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_desc_flags,
            { "Description Flags", "dpnet.desc_flags",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_max_players,
            { "Max Players", "dpnet.max_players",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_current_players,
            { "Current Players", "dpnet.current_players",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_session_offset,
            { "Session Offset", "dpnet.session_offset",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_session_size,
            { "Session Size", "dpnet.session_size",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_session_name,
            { "Session name", "dpnet.session_name",
            FT_STRING, STR_UNICODE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_password_offset,
            { "Password Offset", "dpnet.password_offset",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_password_size,
            { "Password Size", "dpnet.password_size",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_reserved_offset,
            { "Reserved Offset", "dpnet.reserved_offset",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_reserved_size,
            { "Reserved Size", "dpnet.reserved_size",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_application_offset,
            { "Application Offset", "dpnet.application_offset",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_application_size,
            { "Application Size", "dpnet.application_size",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_application_data,
            { "Application data", "dpnet.application_data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_instance,
            { "Instance GUID", "dpnet.instance",
            FT_GUID, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_dpnet
    };


    proto_dpnet = proto_register_protocol ("DirectPlay 8 protocol", "DPNET", "dpnet");

    proto_register_field_array(proto_dpnet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dpnet(void)
{
    static dissector_handle_t dpnet_handle;

    dpnet_handle = create_dissector_handle(dissect_dpnet, proto_dpnet);
    dissector_add_uint("udp.port", DPNET_PORT, dpnet_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
