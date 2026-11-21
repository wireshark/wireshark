/* packet-fortinet-sso.c
 * Routines for Fortinet Single Sign-On
 * Copyright 2020, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * No spec/doc is available based on reverse/analysis of protocol...
 *
 * The message carries no type field: what it is follows from the client IP
 * (255.255.255.255 for a keepalive) and from what comes after the string.
 *
 * The TS Agent fields are named from what the TS Agent and the Collector Agent
 * (5.0.0335) do with them. The Collector Agent logs "Received event from
 * TSAgent, type: %08x, session id: %u.", handles type 0x80 as a logon and 0x81
 * as a logoff, and keeps a "tsagent syncid" for each TS Agent to detect a
 * restart.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#define UDP_FSSO        8002

void proto_register_fortinet_sso(void);
void proto_reg_handoff_fortinet_sso(void);

static int proto_fortinet_sso;
static int ett_fortinet_sso;

static int hf_fsso_length;
static int hf_fsso_timestamp;
static int hf_fsso_client_ip;
static int hf_fsso_payload_length;
static int hf_fsso_string;
static int hf_fsso_domain;
static int hf_fsso_user;
static int hf_fsso_host;
static int hf_fsso_version;
static int hf_fsso_message_kind;
static int hf_fsso_additional_ip;
static int hf_fsso_tsagent_sync_id;
static int hf_fsso_tsagent_event_type;
static int hf_fsso_tsagent_length;
static int hf_fsso_tsagent_session_id;
static int hf_fsso_tsagent_number_port_range;
static int hf_fsso_tsagent_port_range_min;
static int hf_fsso_tsagent_port_range_max;
static int hf_fsso_unknown;
static int hf_fsso_unknown_ipv4;

static dissector_handle_t fortinet_sso_handle;

#define FSSO_KIND_DC_LOGON          1
#define FSSO_KIND_DC_KEEPALIVE      2
#define FSSO_KIND_TS_KEEPALIVE      3
#define FSSO_KIND_TS_LOGON          4
#define FSSO_KIND_TS_LOGOFF         5
#define FSSO_KIND_TS_EVENT          6
#define FSSO_KIND_LOGON_EXTENDED    7

static const value_string fsso_message_kind_vals[] = {
    { FSSO_KIND_DC_LOGON,       "DC Agent logon" },
    { FSSO_KIND_DC_KEEPALIVE,   "DC Agent keepalive" },
    { FSSO_KIND_TS_KEEPALIVE,   "TS Agent keepalive" },
    { FSSO_KIND_TS_LOGON,       "TS Agent logon" },
    { FSSO_KIND_TS_LOGOFF,      "TS Agent logoff" },
    { FSSO_KIND_TS_EVENT,       "TS Agent event" },
    { FSSO_KIND_LOGON_EXTENDED, "Logon with extra data" },
    { 0, NULL }
};

#define FSSO_TSAGENT_LOGON  0x80
#define FSSO_TSAGENT_LOGOFF 0x81

static const value_string fsso_tsagent_event_type_vals[] = {
    { FSSO_TSAGENT_LOGON,  "Logon" },
    { FSSO_TSAGENT_LOGOFF, "Logoff" },
    { 0, NULL }
};

/* Add the '/' delimited field at offset (limited to *remaining bytes) and
 * advance past it. If there is no delimiter the field takes all that is left. */
static void
fsso_add_field(proto_tree *tree, int hf, tvbuff_t *tvb, unsigned *offset, unsigned *remaining)
{
    unsigned found_offset;
    unsigned len;
    bool found = false;

    if (*remaining > 0)
        found = tvb_find_uint8_length(tvb, *offset, *remaining, '/', &found_offset);
    if (found) {
        len = found_offset - *offset;
        proto_tree_add_item(tree, hf, tvb, *offset, len, ENC_ASCII);
        *offset += len + 1;
        *remaining -= len + 1;
    } else {
        proto_tree_add_item(tree, hf, tvb, *offset, *remaining, ENC_ASCII);
        *offset += *remaining;
        *remaining = 0;
    }
}

static int
dissect_fortinet_sso(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ti;
    proto_item *kind_item;
    proto_tree *fsso_tree;
    uint32_t payload_length, client_ip;
    uint32_t event_type, session_id;
    unsigned kind, i;
    unsigned string_length;
    const char *string;
    unsigned offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FSSO");
    col_set_str(pinfo->cinfo, COL_INFO, "Fortinet Single Sign-On");

    ti = proto_tree_add_item(tree, proto_fortinet_sso, tvb, 0, -1, ENC_NA);
    fsso_tree = proto_item_add_subtree(ti, ett_fortinet_sso);

    proto_tree_add_item(fsso_tree, hf_fsso_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(fsso_tree, hf_fsso_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(fsso_tree, hf_fsso_client_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    client_ip = tvb_get_ipv4(tvb, offset);
    offset += 4;

    proto_tree_add_item_ret_uint(fsso_tree, hf_fsso_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &payload_length);
    offset += 2;

    proto_tree_add_item_ret_string_and_length(fsso_tree, hf_fsso_string, tvb, offset, -1, ENC_ASCII, pinfo->pool, (const uint8_t**)&string, &string_length);
    col_add_str(pinfo->cinfo, COL_INFO, string);

    if(client_ip == 0xFFFFFFFF) { //if client_ip equal 255.255.255.255 (0xFFFFFFFF) is KeepAlive packet
        /* Host / "KEEPALIVE" / Version. The host is the name of the Domain
         * Controller (DC Agent) or the address of the terminal server (TS Agent),
         * whose version starts with "tsagent_". The word in the middle is the
         * same in every keepalive: it is skipped here and left to the String. */
        fsso_add_field(fsso_tree, hf_fsso_host, tvb, &offset, &string_length);
        fsso_add_field(NULL, hf_fsso_host, tvb, &offset, &string_length);
        fsso_add_field(fsso_tree, hf_fsso_version, tvb, &offset, &string_length);
        kind = strstr(string, "/tsagent_") ? FSSO_KIND_TS_KEEPALIVE : FSSO_KIND_DC_KEEPALIVE;
    } else {
        kind = FSSO_KIND_DC_LOGON;

        /* Host / Domain / User */
        fsso_add_field(fsso_tree, hf_fsso_host, tvb, &offset, &string_length);
        fsso_add_field(fsso_tree, hf_fsso_domain, tvb, &offset, &string_length);
        fsso_add_field(fsso_tree, hf_fsso_user, tvb, &offset, &string_length);
    }

    if(tvb_reported_length_remaining(tvb, offset) == 4) {

        /* There is some packet with extra IPv4 address... */
        if(kind == FSSO_KIND_DC_LOGON) {
            kind = FSSO_KIND_LOGON_EXTENDED;
        }
        proto_tree_add_item(fsso_tree, hf_fsso_unknown_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

    } else {

        if(tvb_reported_length_remaining(tvb, offset)) {
            uint16_t value;
            uint32_t number_port_range;
            value = tvb_get_ntohs(tvb, offset);

            if(value == 0x2002) { /* Not a TS Agent additional Data */
                if(kind == FSSO_KIND_DC_LOGON) {
                    kind = FSSO_KIND_LOGON_EXTENDED;
                }
                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 2, ENC_NA);
                offset += 2;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 6, ENC_NA);
                offset += 6;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 1, ENC_NA);
                offset += 1;
            } else {
                /* Room for three more IPv4 addresses of the client, here the
                 * terminal server. The Collector Agent stops at the first one
                 * that is zero. */
                for (i = 0; i < 3; i++) {
                    proto_tree_add_item(fsso_tree, hf_fsso_additional_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                }

                /* Kept by the Collector Agent for each TS Agent. When it changes
                 * the TS Agent has restarted and its old sessions are dropped. */
                proto_tree_add_item(fsso_tree, hf_fsso_tsagent_sync_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_tree_add_item_ret_uint(fsso_tree, hf_fsso_tsagent_event_type, tvb, offset, 1, ENC_BIG_ENDIAN, &event_type);
                offset += 1;
                if(event_type == FSSO_TSAGENT_LOGON) {
                    kind = FSSO_KIND_TS_LOGON;
                } else if(event_type == FSSO_TSAGENT_LOGOFF) {
                    kind = FSSO_KIND_TS_LOGOFF;
                } else {
                    kind = FSSO_KIND_TS_EVENT;
                }

                /* Not set by the TS Agent: zero in a logon, any value in a logoff */
                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 1, ENC_NA);
                offset += 1;

                /* Set by the TS Agent to 16 + 4 for each port range: the length
                 * from the Sync ID to the last port range. The Collector Agent
                 * does not read it. */
                proto_tree_add_item(fsso_tree, hf_fsso_tsagent_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Windows session of the user on the terminal server */
                proto_tree_add_item_ret_uint(fsso_tree, hf_fsso_tsagent_session_id, tvb, offset, 4, ENC_BIG_ENDIAN, &session_id);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", session %u", session_id);
                offset += 4;

                /* Set to zero by the TS Agent, not read by the Collector Agent */
                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 2, ENC_NA);
                offset += 2;

                /* Port Range assigned to user for TS Agent (RDP/Citrix) */
                proto_tree_add_item_ret_uint(fsso_tree, hf_fsso_tsagent_number_port_range, tvb, offset, 2, ENC_BIG_ENDIAN, &number_port_range);
                offset += 2;

                while (number_port_range) {

                    proto_tree_add_item(fsso_tree, hf_fsso_tsagent_port_range_min, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(fsso_tree, hf_fsso_tsagent_port_range_max, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    number_port_range --;
                }
            }
        }

    }

    kind_item = proto_tree_add_uint(fsso_tree, hf_fsso_message_kind, tvb, 0, 0, kind);
    proto_item_set_generated(kind_item);

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s: ", val_to_str_const(kind, fsso_message_kind_vals, "Unknown"));

    return offset;
}

static bool
dissect_fortinet_fsso_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint32_t length_remaining, length;

    if (tvb_captured_length(tvb) < 2) {
        return false;
    }

    length_remaining = tvb_reported_length_remaining(tvb, 0);
    //first bytes is the length of payload
    length = tvb_get_ntohs(tvb, 0);
    if(length_remaining != length)
    {
        return false;
    }

    //always send with UDP Destination Port 80002
    if(pinfo->destport != UDP_FSSO)
    {
        return false;
    }

    dissect_fortinet_sso(tvb, pinfo, tree, data);
    return true;
}

void
proto_register_fortinet_sso(void)
{
    static hf_register_info hf[] = {
        { &hf_fsso_length,
        { "Length", "fortinet_sso.length", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_timestamp,
        { "Timestamp", "fortinet_sso.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_client_ip,
        { "Client IP", "fortinet_sso.client_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_payload_length,
        { "Payload Length", "fortinet_sso.payload_length", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_string,
        { "String", "fortinet_sso.string", FT_STRINGZ, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_user,
        { "User", "fortinet_sso.user", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_domain,
        { "Domain", "fortinet_sso.domain", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_host,
        { "Host", "fortinet_sso.host", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_version,
        { "Version", "fortinet_sso.version", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_message_kind,
        { "Message Kind", "fortinet_sso.message_kind", FT_UINT8, BASE_DEC, VALS(fsso_message_kind_vals), 0x0,
        "Worked out from the layout, the message has no type field", HFILL}},

        { &hf_fsso_additional_ip,
        { "Additional IP", "fortinet_sso.additional_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
        "Another IPv4 address of the client, 0.0.0.0 when unused", HFILL}},

        { &hf_fsso_tsagent_sync_id,
        { "Sync ID", "fortinet_sso.tsagent.sync_id", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Changes when the TS Agent restarts", HFILL}},

        { &hf_fsso_tsagent_event_type,
        { "Event Type", "fortinet_sso.tsagent.event_type", FT_UINT8, BASE_HEX, VALS(fsso_tsagent_event_type_vals), 0x0,
        NULL, HFILL}},

        { &hf_fsso_tsagent_length,
        { "TS Agent Data Length", "fortinet_sso.tsagent.length", FT_UINT16, BASE_DEC, NULL, 0x0,
        "From the Sync ID to the last port range", HFILL}},

        { &hf_fsso_tsagent_session_id,
        { "Session ID", "fortinet_sso.tsagent.session_id", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Session of the user on the terminal server", HFILL}},

        { &hf_fsso_tsagent_number_port_range,
        { "Number of Port Range", "fortinet_sso.tsagent.port_range.number", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_tsagent_port_range_min,
        { "Port Range (Min)", "fortinet_sso.tsagent.port_range.min", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_tsagent_port_range_max,
        { "Port Range (Max)", "fortinet_sso.tsagent.port_range.max", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

        { &hf_fsso_unknown,
        { "Unknown", "fortinet_sso.unknown", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown Data...", HFILL}},

        { &hf_fsso_unknown_ipv4,
        { "Unknown IPv4", "fortinet_sso.unknown.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        "Unknown Data...", HFILL}},

    };

    static int *ett[] = {
        &ett_fortinet_sso,
    };

    proto_fortinet_sso = proto_register_protocol("Fortinet Single Sign On", "fortinet_sso", "fortinet_sso");
    fortinet_sso_handle = register_dissector("fortinet_sso", dissect_fortinet_sso, proto_fortinet_sso);

    proto_register_field_array(proto_fortinet_sso, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_fortinet_sso(void)
{
    dissector_add_uint_with_preference("udp.port", 0, fortinet_sso_handle);
    heur_dissector_add("udp", dissect_fortinet_fsso_heur, "Fortinet SSO over UDP", "fortinet_sso", proto_fortinet_sso, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
