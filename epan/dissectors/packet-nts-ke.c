/* packet-nts-ke.c
 * Dissector for Network Time Security Key Establishment Protocol (RFC 8915)
 *
 * Copyright (c) 2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "packet-tcp.h"
#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/str_util.h>
#include <epan/expert.h>

#define TLS_PORT              4460
#define CRIT_TYPE_BODY_LEN       4
#define TYPE_MASK           0x7FFF
#define CRITICAL_MASK       0x8000

void proto_register_nts_ke(void);
void proto_reg_handoff_nts_ke(void);

static dissector_handle_t nts_ke_handle;

static int proto_nts_ke;

/* Fields */
static int hf_nts_ke_record;
static int hf_nts_ke_critical_bit;
static int hf_nts_ke_record_type;
static int hf_nts_ke_body_length;
static int hf_nts_ke_next_proto;
static int hf_nts_ke_error;
static int hf_nts_ke_warning;
static int hf_nts_ke_aead_algo;
static int hf_nts_ke_cookie;
static int hf_nts_ke_server;
static int hf_nts_ke_port;

/* Expert fields */
static expert_field ei_nts_ke_critical_bit_missing;
static expert_field ei_nts_ke_record_after_end;
static expert_field ei_nts_ke_end_missing;
static expert_field ei_nts_ke_next_proto_illegal_count;
static expert_field ei_nts_ke_body_illegal;
static expert_field ei_nts_ke_body_length_illegal;

/* Trees */
static int ett_nts_ke;
static int ett_nts_ke_record;

#define RECORD_TYPE_END         0x0000
#define RECORD_TYPE_NEXT        0x0001
#define RECORD_TYPE_ERR         0x0002
#define RECORD_TYPE_WARN        0x0003
#define RECORD_TYPE_AEAD        0x0004
#define RECORD_TYPE_COOKIE      0x0005
#define RECORD_TYPE_NEG_SRV     0x0006
#define RECORD_TYPE_NEG_PORT    0x0007

static const value_string nts_ke_record_types[] = {
    { RECORD_TYPE_END,      "End of Message" },
    { RECORD_TYPE_NEXT,     "NTS Next Protocol Negotiation" },
    { RECORD_TYPE_ERR,      "Error" },
    { RECORD_TYPE_WARN,     "Warning" },
    { RECORD_TYPE_AEAD,     "AEAD Algorithm Negotiation" },
    { RECORD_TYPE_COOKIE,   "New Cookie for NTPv4" },
    { RECORD_TYPE_NEG_SRV,  "NTPv4 Server Negotiation" },
    { RECORD_TYPE_NEG_PORT, "NTPv4 Port Negotiation" },
    { 0,                    NULL }
};

static const value_string nts_ke_error_codes[] = {
    { 0x0000, "Unrecognized Critical Record" },
    { 0x0001, "Bad Request" },
    { 0x0002, "Internal Server Error" },
    { 0,      NULL }
};

/* https://www.iana.org/assignments/nts/nts.xhtml#nts-next-protocols */
static const range_string nts_ke_next_proto_rvals[] = {
    {     0,     0, "NTPv4" },
    {     1, 32767, "Unassigned" },
    { 32768, 65535, "Reserved" },
    {     0,     0, NULL }
};

/* https://www.iana.org/assignments/aead-parameters/ */
static const range_string nts_ke_aead_rvals[] = {
    {     1,     1, "AEAD_AES_128_GCM" },
    {     2,     2, "AEAD_AES_256_GCM" },
    {     3,     3, "AEAD_AES_128_CCM" },
    {     4,     4, "AEAD_AES_256_CCM" },
    {     5,     5, "AEAD_AES_128_GCM_8" },
    {     6,     6, "AEAD_AES_256_GCM_8" },
    {     7,     7, "AEAD_AES_128_GCM_12" },
    {     8,     8, "AEAD_AES_256_GCM_12" },
    {     9,     9, "AEAD_AES_128_CCM_SHORT" },
    {    10,    10, "AEAD_AES_256_CCM_SHORT" },
    {    11,    11, "AEAD_AES_128_CCM_SHORT_8" },
    {    12,    12, "AEAD_AES_256_CCM_SHORT_8" },
    {    13,    13, "AEAD_AES_128_CCM_SHORT_12" },
    {    14,    14, "AEAD_AES_256_CCM_SHORT_12" },
    {    15,    15, "AEAD_AES_SIV_CMAC_256" },
    {    16,    16, "AEAD_AES_SIV_CMAC_384" },
    {    17,    17, "AEAD_AES_SIV_CMAC_512" },
    {    18,    18, "AEAD_AES_128_CCM_8" },
    {    19,    19, "AEAD_AES_256_CCM_8" },
    {    20,    20, "AEAD_AES_128_OCB_TAGLEN128" },
    {    21,    21, "AEAD_AES_128_OCB_TAGLEN96" },
    {    22,    22, "AEAD_AES_128_OCB_TAGLEN64" },
    {    23,    23, "AEAD_AES_192_OCB_TAGLEN128" },
    {    24,    24, "AEAD_AES_192_OCB_TAGLEN96" },
    {    25,    25, "AEAD_AES_192_OCB_TAGLEN64" },
    {    26,    26, "AEAD_AES_256_OCB_TAGLEN128" },
    {    27,    27, "AEAD_AES_256_OCB_TAGLEN96" },
    {    28,    28, "AEAD_AES_256_OCB_TAGLEN64" },
    {    29,    29, "AEAD_CHACHA20_POLY1305" },
    {    30,    30, "AEAD_AES_128_GCM_SIV" },
    {    31,    31, "AEAD_AES_256_GCM_SIV" },
    {    32,    32, "AEAD_AEGIS128L" },
    {    33,    33, "AEAD_AEGIS256" },
    {    34, 32767, "Unassigned" },
    { 32768, 65535, "Reserved for Private Use" },
    {     0,     0, NULL }
};

static int
dissect_nts_ke(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset;
    uint16_t critical, type;
    uint32_t body_length, body_counter, next_proto;
    uint32_t counter_next_proto_recs = 0, counter_aead = 0, counter_cookies = 0;
    proto_item *ti, *ti_record;
    proto_tree *nts_ke_tree, *record_tree;
    bool critical_bool, end_record = false;

    offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NTS-KE");
    col_clear(pinfo->cinfo,COL_INFO);

    ti = proto_tree_add_item(tree, proto_nts_ke, tvb, 0, 0, ENC_NA);
    nts_ke_tree = proto_item_add_subtree(ti, ett_nts_ke);

    while(tvb_reported_length_remaining(tvb, offset) >= CRIT_TYPE_BODY_LEN) {

        ti_record = proto_tree_add_item(nts_ke_tree, hf_nts_ke_record, tvb, offset, 0, ENC_NA);
        record_tree = proto_item_add_subtree(ti_record, ett_nts_ke_record);

        critical = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & CRITICAL_MASK;
        critical_bool = (bool)(critical >> 15);
        proto_tree_add_boolean(record_tree, hf_nts_ke_critical_bit, tvb, offset, 2, critical);

        type = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & TYPE_MASK;
        proto_tree_add_uint(record_tree, hf_nts_ke_record_type, tvb, offset, 2, type);
        proto_item_append_text(ti_record, " (%s)", val_to_str_const(type, nts_ke_record_types, "Unknown Record Type"));
        offset += 2;

        proto_tree_add_item_ret_uint(record_tree, hf_nts_ke_body_length, tvb, offset, 2, ENC_BIG_ENDIAN, &body_length);
        offset += 2;

        if(end_record)
            expert_add_info(pinfo, record_tree, &ei_nts_ke_record_after_end);

        body_counter = 0;

        switch (type) {
            case RECORD_TYPE_END:

                /* No body allowed */
                if(body_length > 0) {
                    call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_body_illegal);
                    offset += body_length;
                }

                /* Critical bit is mandatory for this type */
                if(!critical_bool)
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_critical_bit_missing);

                /* Mark end record as seen */
                end_record = true;

                break;

            case RECORD_TYPE_NEXT:

                while(body_counter < body_length) {
                    proto_tree_add_item_ret_uint(record_tree, hf_nts_ke_next_proto, tvb, offset, 2, ENC_BIG_ENDIAN, &next_proto);
                    offset += 2;
                    body_counter += 2;

                    col_append_str(pinfo->cinfo, COL_INFO, rval_to_str_const(next_proto, nts_ke_next_proto_rvals, "Unknown Proto"));
                }

                /* Critical bit is mandatory for this type */
                if(!critical_bool)
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_critical_bit_missing);

                counter_next_proto_recs++;

                break;

            case RECORD_TYPE_ERR:

                /* Fixed body length */
                if(body_length == 2) {
                    proto_tree_add_item(record_tree, hf_nts_ke_error, tvb, offset, body_length, ENC_BIG_ENDIAN);
                } else {
                    call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_body_length_illegal);
                }
                offset += body_length;

                /* Critical bit is mandatory for this type */
                if(!critical_bool)
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_critical_bit_missing);

                break;

            case RECORD_TYPE_WARN:

                /* Fixed body length */
                if(body_length == 2) {
                    proto_tree_add_item(record_tree, hf_nts_ke_warning, tvb, offset, body_length, ENC_BIG_ENDIAN);
                } else {
                    call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_body_length_illegal);
                }
                offset += body_length;

                /* Critical bit is mandatory for this type */
                if(!critical_bool)
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_critical_bit_missing);

                break;

            case RECORD_TYPE_AEAD:

                while(body_counter < body_length) {
                    proto_tree_add_item(record_tree, hf_nts_ke_aead_algo, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    body_counter += 2;
                    counter_aead++;
                }

                break;

            case RECORD_TYPE_COOKIE:

                /* Arbitrary body data */
                proto_tree_add_item(record_tree, hf_nts_ke_cookie, tvb, offset, body_length, ENC_NA);
                offset += body_length;
                counter_cookies++;

                break;

            case RECORD_TYPE_NEG_SRV:

                /* Arbitrary string */
                proto_tree_add_item(record_tree, hf_nts_ke_server, tvb, offset, body_length, ENC_ASCII);
                offset += body_length;

                break;

            case RECORD_TYPE_NEG_PORT:

                /* Fixed body length */
                if(body_length == 2) {
                    proto_tree_add_item(record_tree, hf_nts_ke_port, tvb, offset, body_length, ENC_BIG_ENDIAN);
                } else {
                    call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_body_length_illegal);
                }
                offset += body_length;

                break;

            default:

                call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                offset += body_length;

                break;
        }

        proto_item_set_end(ti_record, tvb, offset);
    }

    /* Info columns text */
    if(counter_aead > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%u AEAD Algorithm%s", counter_aead, plurality(counter_aead, "", "s"));

    if(counter_cookies > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%u Cookie%s", counter_cookies, plurality(counter_cookies, "", "s"));

    /* No end record found */
    if(!end_record)
        expert_add_info(pinfo, nts_ke_tree, &ei_nts_ke_end_missing);

    /* Illegal AEAD record count */
    if(counter_next_proto_recs != 1)
        expert_add_info(pinfo, nts_ke_tree, &ei_nts_ke_next_proto_illegal_count);

    proto_item_set_end(ti, tvb, offset);
    return offset;
}

static unsigned
get_nts_ke_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{

    bool another_record = true;
    unsigned size = 0;

    /* Concat multiple records into one protocol tree */
    while(another_record) {

        /* Size is body length + 4 byte (CRIT_TYPE_BODY_LEN) */
        unsigned pdu_size = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN) + CRIT_TYPE_BODY_LEN;
        size += pdu_size;

        if (tvb_captured_length_remaining(tvb, offset + pdu_size) < CRIT_TYPE_BODY_LEN)
            another_record = false;

        offset += pdu_size;
    }

    return size;

}

static int
dissect_nts_ke_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!tvb_bytes_exist(tvb, 0, CRIT_TYPE_BODY_LEN))
        return 0;

    tcp_dissect_pdus(tvb, pinfo, tree, true, CRIT_TYPE_BODY_LEN, get_nts_ke_message_len, dissect_nts_ke, data);
    return tvb_reported_length(tvb);
}

void
proto_register_nts_ke(void)
{
    static hf_register_info hf[] = {
        { &hf_nts_ke_record,
            { "NTS-KE Record", "nts-ke.record",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_critical_bit,
            { "Critical Bit", "nts-ke.critical_bit",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), CRITICAL_MASK,
            NULL, HFILL }
        },
        { &hf_nts_ke_record_type,
            { "Record Type", "nts-ke.type",
            FT_UINT16, BASE_DEC,
            VALS(nts_ke_record_types), TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_nts_ke_body_length,
            { "Body Length", "nts-ke.body_length",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_byte_bytes), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_next_proto,
            { "Next Protocol ID", "nts-ke.next_proto",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING,
            RVALS(nts_ke_next_proto_rvals), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_error,
            { "Error Code", "nts-ke.error",
            FT_UINT16, BASE_HEX,
            VALS(nts_ke_error_codes), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_warning,
            { "Warning Code", "nts-ke.warning",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_aead_algo,
            { "AEAD Algorithm", "nts-ke.aead_algo",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING,
            RVALS(nts_ke_aead_rvals), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_cookie,
            { "Cookie Data", "nts-ke.cookie",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_server,
            { "Server", "nts-ke.server",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_port,
            { "Port", "nts-ke.port",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_nts_ke_critical_bit_missing,
            { "nts-ke.critical_bit.missing", PI_MALFORMED, PI_ERROR,
                "Critical bit must be set for this record type", EXPFILL }
        },
        { &ei_nts_ke_record_after_end,
            { "nts-ke.record.after_end", PI_MALFORMED, PI_ERROR,
                "Illegal record after end of message", EXPFILL }
        },
        { &ei_nts_ke_end_missing,
            { "nts-ke.end.missing", PI_MALFORMED, PI_ERROR,
                "No end of message present", EXPFILL }
        },
        { &ei_nts_ke_body_illegal,
            { "nts-ke.body.illegal", PI_MALFORMED, PI_ERROR,
                "Illegal body data present", EXPFILL }
        },
        { &ei_nts_ke_body_length_illegal,
            { "nts-ke.body_length.illegal", PI_MALFORMED, PI_ERROR,
                "Illegal body length", EXPFILL }
        },
        { &ei_nts_ke_next_proto_illegal_count,
            { "nts-ke.next_proto.illegal_count", PI_MALFORMED, PI_ERROR,
                "Illegal Next Protocol record count", EXPFILL }
        }
    };

    static int *ett[] = {
        &ett_nts_ke,
        &ett_nts_ke_record
    };

    expert_module_t* expert_nts_ke;

    proto_nts_ke = proto_register_protocol ("NTS Key Establishment Protocol", "NTS-KE", "nts-ke");

    proto_register_field_array(proto_nts_ke, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nts_ke = expert_register_protocol(proto_nts_ke);
    expert_register_field_array(expert_nts_ke, ei, array_length(ei));

    nts_ke_handle = register_dissector("nts-ke", dissect_nts_ke_tcp, proto_nts_ke);
}

void
proto_reg_handoff_nts_ke(void)
{
    dissector_add_uint_with_preference("tls.port", TLS_PORT, nts_ke_handle);
    dissector_add_string("tls.alpn", "ntske/1", nts_ke_handle);
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
