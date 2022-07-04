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
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#define UDP_FSSO        8002

void proto_register_fortinet_sso(void);
void proto_reg_handoff_fortinet_sso(void);

static int proto_fortinet_sso = -1;
static gint ett_fortinet_sso  = -1;

static int hf_fsso_length = -1;
static int hf_fsso_timestamp = -1;
static int hf_fsso_client_ip = -1;
static int hf_fsso_payload_length = -1;
static int hf_fsso_string = -1;
static int hf_fsso_domain = -1;
static int hf_fsso_user = -1;
static int hf_fsso_host = -1;
static int hf_fsso_version = -1;
static int hf_fsso_tsagent_number_port_range = -1;
static int hf_fsso_tsagent_port_range_min = -1;
static int hf_fsso_tsagent_port_range_max = -1;
static int hf_fsso_unknown = -1;
static int hf_fsso_unknown_ipv4 = -1;

static dissector_handle_t fortinet_sso_handle;

static int
dissect_fortinet_sso(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *ti;
    proto_tree *fsso_tree;
    guint32 payload_length, client_ip;
    gint string_length = -1;
    const gchar *string;
    gint32 len;
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FSSO");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Fortinet Single Sign-On");

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

    string = tvb_get_stringz_enc(pinfo->pool, tvb, offset, &string_length, ENC_ASCII);
    proto_tree_add_item(fsso_tree, hf_fsso_string, tvb, offset, string_length, ENC_ASCII);
    col_set_str(pinfo->cinfo, COL_INFO, string);

    if(client_ip == 0xFFFFFFFF) { //if client_ip equal 255.255.255.255 (0xFFFFFFFF) is KeepAlive packet
        /* Domain / KeepAlive (User) / Version */
        len = tvb_find_guint8(tvb, offset, string_length, '/') - offset;
        proto_tree_add_item(fsso_tree, hf_fsso_domain, tvb, offset, len, ENC_ASCII);
        offset += (len + 1);
        string_length -= (len + 1);

        len = tvb_find_guint8(tvb, offset, string_length, '/') - offset;
        proto_tree_add_item(fsso_tree, hf_fsso_user, tvb, offset, len, ENC_ASCII);
        offset += (len + 1);
        string_length -= (len + 1);

        proto_tree_add_item(fsso_tree, hf_fsso_version, tvb, offset, string_length, ENC_ASCII);
        offset += (string_length);

    } else {
        /* Host / Domain / User */
        len = tvb_find_guint8(tvb, offset, string_length, '/') - offset;
        proto_tree_add_item(fsso_tree, hf_fsso_host, tvb, offset, len, ENC_ASCII);
        offset += (len + 1);
        string_length -= (len + 1);

        len = tvb_find_guint8(tvb, offset, string_length, '/') - offset;
        proto_tree_add_item(fsso_tree, hf_fsso_domain, tvb, offset, len, ENC_ASCII);
        offset += (len + 1);
        string_length -= (len + 1);

        proto_tree_add_item(fsso_tree, hf_fsso_user, tvb, offset, string_length, ENC_ASCII);
        offset += (string_length);
    }

    if(tvb_reported_length_remaining(tvb, offset) == 4) {

        /* There is some packet with extra IPv4 address... */
        proto_tree_add_item(fsso_tree, hf_fsso_unknown_ipv4, tvb, offset, 4, ENC_NA);
        offset += 4;

    } else {

        if(tvb_reported_length_remaining(tvb, offset)) {
            guint16 value;
            guint32 number_port_range;
            value = tvb_get_ntohs(tvb, offset);

            if(value == 0x2002) { /* Not a TS Agent additionnal Data */
                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 2, ENC_NA);
                offset += 2;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown_ipv4, tvb, offset, 4, ENC_NA);
                offset += 4;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 6, ENC_NA);
                offset += 6;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown_ipv4, tvb, offset, 4, ENC_NA);
                offset += 4;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 1, ENC_NA);
                offset += 1;
            } else {
                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 15, ENC_NA);
                offset += 15;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 5, ENC_NA);
                offset += 5;

                proto_tree_add_item(fsso_tree, hf_fsso_unknown, tvb, offset, 6, ENC_NA);
                offset += 6;

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

    return offset;
}

static gboolean
dissect_fortinet_fsso_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint32 length_remaining, length;

    if (tvb_captured_length(tvb) < 2) {
        return FALSE;
    }

    length_remaining = tvb_reported_length_remaining(tvb, 0);
    //first bytes is the length of payload
    length = tvb_get_ntohs(tvb, 0);
    if(length_remaining != length)
    {
        return FALSE;
    }

    //always send with UDP Destination Port 80002
    if(pinfo->destport != UDP_FSSO)
    {
        return FALSE;
    }

    dissect_fortinet_sso(tvb, pinfo, tree, data);
    return TRUE;
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
        { "String", "fortinet_sso.string", FT_STRING, BASE_NONE, NULL, 0x0,
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

    static gint *ett[] = {
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
