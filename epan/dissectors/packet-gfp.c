/* packet-gfp.c
 * Routines for Generic Framing Procedure dissection
 * Copyright 2015, John Thacker <johnthacker@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Generic Framing Procedure (GFP) is used to map octet-aligned variable
 * length payloads (e.g. Ethernet, MPLS, octet-aligned PPP, IP) into
 * octet-synchronous signals such as SONET/SDH (ITU-T G.707) and OTN
 * (ITU-T G.709). GFP is a telecommunications industry standard defined in
 * ITU-T G.7041/Y.1303.
 *
 * Reference:
 * https://www.itu.int/rec/T-REC-G.7041/
 */

#include <config.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/crc16-tvb.h>
#include <epan/crc32-tvb.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

#include <wiretap/wtap.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_gfp(void);
void proto_register_gfp(void);

/* Dissector handle */
static dissector_handle_t gfp_handle;

/* Initialize the protocol and registered fields */
static int proto_gfp = -1;
static int hf_gfp_pli = -1;
static int hf_gfp_chec = -1;
static int hf_gfp_chec_status = -1;
static int hf_gfp_type = -1;
static int hf_gfp_pti = -1;
static int hf_gfp_pfi = -1;
static int hf_gfp_exi = -1;
static int hf_gfp_upi_data = -1;
static int hf_gfp_upi_management = -1;
static int hf_gfp_thec = -1;
static int hf_gfp_thec_status = -1;
static int hf_gfp_cid = -1;
static int hf_gfp_ehec = -1;
static int hf_gfp_ehec_status = -1;
static int hf_gfp_fcs = -1;
static int hf_gfp_fcs_good = -1;
static int hf_gfp_fcs_bad = -1;

static expert_field ei_gfp_pli_idle_nonempty = EI_INIT;
static expert_field ei_gfp_pli_unknown = EI_INIT;
static expert_field ei_gfp_pli_invalid = EI_INIT;
static expert_field ei_gfp_chec_bad = EI_INIT;
static expert_field ei_gfp_thec_bad = EI_INIT;
static expert_field ei_gfp_ehec_bad = EI_INIT;
static expert_field ei_gfp_exi_short = EI_INIT;
static expert_field ei_gfp_pfi_short = EI_INIT;
static expert_field ei_gfp_payload_undecoded = EI_INIT;
static expert_field ei_gfp_fcs_bad = EI_INIT;

#define GFP_USER_DATA 0
#define GFP_CLIENT_MANAGEMENT 4
#define GFP_MANAGEMENT_COMMUNICATIONS 5

#define GFP_EXT_NULL 0
#define GFP_EXT_LINEAR 1
#define GFP_EXT_RING 2

/* Initialize the subtree pointers */
static gint ett_gfp = -1;
static gint ett_gfp_type = -1;
static gint ett_gfp_fcs = -1;

static dissector_table_t gfp_dissector_table;

/* ITU-T G.7041 6.1.1, 6.2 */
static const range_string gfp_pli_rvals[] = {
    {0, 0, "Idle Frame"},
    {1, 3, "Control Frame (Reserved)"},
    {4, G_MAXUINT16, "Client Frame"},
    {0, 0, NULL}
};

static int * const gfp_type_data_fields[] = {
    &hf_gfp_pti,
    &hf_gfp_pfi,
    &hf_gfp_exi,
    &hf_gfp_upi_data,
    NULL
};

static int * const gfp_type_management_fields[] = {
    &hf_gfp_pti,
    &hf_gfp_pfi,
    &hf_gfp_exi,
    &hf_gfp_upi_management,
    NULL
};

static const value_string gfp_pti_vals[] = {
    {GFP_USER_DATA, "User Data"},
    {GFP_CLIENT_MANAGEMENT, "Client Management"},
    {GFP_MANAGEMENT_COMMUNICATIONS, "Management Communications"},
    {0, NULL}
};

static const value_string gfp_exi_vals[] = {
    {GFP_EXT_NULL, "Null Extension Header"},
    {GFP_EXT_LINEAR, "Linear Frame"},
    {GFP_EXT_RING, "Ring Frame"},
    {0, NULL}
};

static const range_string gfp_upi_data_rvals[] = {
    {0, 0, "Reserved and not available"},
    {1, 1, "Frame-Mapped Ethernet"},
    {2, 2, "Frame-Mapped PPP"},
    {3, 3, "Transparent Fibre Channel"},
    {4, 4, "Transparent FICON"},
    {5, 5, "Transparent ESCON"},
    {6, 6, "Transparent Gbit Ethernet"},
    {7, 7, "Reserved"},
    {8, 8, "Frame-Mapped Multiple Access Protocol over SDH (MAPOS)"},
    {9, 9, "Transparent DVB ASI"},
    {10, 10, "Frame-Mapped IEEE 802.17 Resilient Packet Ring"},
    {11, 11, "Frame-Mapped Fibre Channel FC-BBW"},
    {12, 12, "Asynchronous Transparent Fibre Channel"},
    {13, 13, "Frame-Mapped MPLS"},
    {14, 14, "Frame-Mapped MPLS (Multicast) [Deprecated]"},
    {15, 15, "Frame-Mapped OSI network layer protocols (IS-IS, ES-IS, CLNP)"},
    {16, 16, "Frame-Mapped IPv4"},
    {17, 17, "Frame-Mapped IPv6"},
    {18, 18, "Frame-Mapped DVB-ASI"},
    {19, 19, "Frame-Mapped 64B/66B encoded Ethernet, including frame preamble"},
    {20, 20, "Frame-Mapped 64B/66B encoded Ethernet ordered set information"},
    {21, 21, "Transparent transcoded FC-1200"},
    /*UPI value 22 & 23 from Amendment 3 (01/2015)*/
    {22, 22, "Precision Time Protocol message"},
    {23, 23, "Synchronization status message"},
    {24, 239, "Reserved for future standardization"},
    {240, 252, "Reserved for proprietary use"},
    {253, 253, "Reserved for proprietary use, formerly Frame-Mapped 64B/66B encoded Ethernet, including frame preamble"},
    {254, 254, "Reserved for proprietary use, formerly Frame-Mapped 64B/66B encoded Ethernet ordered set information"},
    {255, 255, "Reserved and not available"},
    {0, 0, NULL }
};

static const range_string gfp_upi_management_rvals[] = {
    {0, 0, "Reserved and not available"},
    {1, 1, "Client Signal Fail (Loss of Client Signal)"},
    {2, 2, "Client Signal Fail (Loss of Character Synchronisation)"},
    {3, 3, "Defect Clear Indication (DCI)"},
    {4, 4, "Forward Defect Indication (FDI)"},
    {5, 5, "Reverse Defect Indication (RDI)"},
    {6, 223, "Reserved for future use"},
    {224, 254, "Reserved for proprietary use"},
    {255, 255, "Reserved and not available"},
    {0, 0, NULL}
};


/* Even GFP idle frames must have 4 bytes for the core header.
 * If data is received with fewer than this it is rejected. */
#define GFP_MIN_LENGTH 4

static void gfp_prompt(packet_info *pinfo, gchar* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "UPI %u as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_gfp, 0)));
}

static gpointer gfp_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_gfp, 0);
}

/* GFP has several identical 16 bit CRCs in its header (HECs). Note that
 * this function increases the offset. */
static void
gfp_add_hec_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset, const guint len, const int field, const int field_status, expert_field *ei_bad)
{

    guint hec_calc;

    hec_calc = crc16_r3_ccitt_tvb(tvb, *offset, len);
    *offset += len;

    proto_tree_add_checksum(tree, tvb, *offset, field, field_status, ei_bad, pinfo, hec_calc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    *offset += 2;
}

/* G.7041 6.1.2 GFP payload area */
static void
dissect_gfp_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *gfp_tree, guint *offset, guint payload_len)
{
    tvbuff_t *payload_tvb;
    proto_item *type_ti = NULL;
    proto_item *fcs_ti;
    proto_tree *fcs_tree = NULL;
    guint pti, pfi, exi, upi;
    guint fcs, fcs_calc;
    guint fcs_len = 0;

    /* G.7041 6.1.2.3 Payload area scrambling
     * Note that payload when sent on the wire is scrambled as per ATM
     * with a 1 + x^43 multiplicative scrambler. Likely already removed by
     * the time we get a capture file (as with ATM). Could have a pref,
     * but if it's present we have to save state over subsequent frames,
     * always would fail to decode the first 43 payload bytes of a capture. */

    /* G.7041 6.1.2.1 Payload Header - at least 4 bytes */
    tvb_ensure_bytes_exist(tvb, *offset, 4);
    payload_len -= 4;

    /* G.7041 6.1.2.1.1 GFP type field - mandatory 2 bytes */
    pti = tvb_get_bits8(tvb, 8*(*offset), 3);
    pfi = tvb_get_bits8(tvb, 8*(*offset)+3, 1);
    exi = tvb_get_bits8(tvb, 8*(*offset)+4, 4);
    upi = tvb_get_guint8(tvb, *offset+1);
    p_add_proto_data(pinfo->pool, pinfo, proto_gfp, 0, GUINT_TO_POINTER(upi));

    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(pti, gfp_pti_vals, "Reserved PTI (%d)"));
    if (pti == GFP_USER_DATA ||
        pti == GFP_MANAGEMENT_COMMUNICATIONS) {
        /* G.7041 Table 6-3 - GFP_MANAGEMENT_COMMUNICATIONS
         * uses the same UPI table as USER_DATA, though
         * "not all of these UPI types are applicable" in that case. */
        type_ti = proto_tree_add_bitmask_with_flags(gfp_tree, tvb, *offset, hf_gfp_type,
            ett_gfp_type, gfp_type_data_fields, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
        col_append_sep_str(pinfo->cinfo, COL_INFO, ": ", rval_to_str(upi, gfp_upi_data_rvals, "Unknown 0x%02x"));
    } else if (pti == GFP_CLIENT_MANAGEMENT) {
        /* G.7041 Table 6-4 */
        type_ti = proto_tree_add_bitmask_with_flags(gfp_tree, tvb, *offset, hf_gfp_type,
            ett_gfp_type, gfp_type_management_fields, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
        col_append_sep_str(pinfo->cinfo, COL_INFO, ": ", rval_to_str(upi, gfp_upi_management_rvals, "Unknown 0x%02x"));
    }

    /* G.7041 6.1.2.1.2 Type HEC (tHEC) - mandatory 2 bytes */
    gfp_add_hec_tree(tvb, pinfo, gfp_tree, offset, 2, hf_gfp_thec, hf_gfp_thec_status, &ei_gfp_thec_bad);

    switch (exi) {
        case GFP_EXT_NULL:
            /* G.7041 6.1.2.1.3.1 Null extension header */
            break;

        case GFP_EXT_LINEAR:
            /* G.7041 6.1.2.1.3.2 Extension header for a linear frame */
            if (payload_len < 4) {
                expert_add_info(pinfo, type_ti, &ei_gfp_exi_short);
                payload_len = 0;
            }
            else {
                payload_len -= 4;
            }
            proto_tree_add_item(gfp_tree, hf_gfp_cid, tvb, *offset, 1, ENC_BIG_ENDIAN);
            /* Next byte spare field, reserved */

            /* 6.1.2.1.4 Extension HEC field */
            gfp_add_hec_tree(tvb, pinfo, gfp_tree, offset, 2, hf_gfp_ehec, hf_gfp_ehec_status, &ei_gfp_ehec_bad);
            break;
        case GFP_EXT_RING:
            /* 6.1.2.1.3.3 Extension header for a ring frame */
            /* "For further study." Undefined so fall through */
        default:
            /* Reserved */
            /* TODO: Mark as error / unhandled? */
            break;
    }

    proto_item_set_end(gfp_tree, tvb, *offset);

    if (pfi == 1) { /* 6.1.2.2.1 Payload FCS field present */
        if (payload_len < 4) {
            expert_add_info(pinfo, type_ti, &ei_gfp_pfi_short);
            fcs_len = payload_len;
            payload_len = 0;
        } else {
            fcs_len = 4;
            payload_len -= 4;
        }

        proto_tree_set_appendix(gfp_tree, tvb, *offset + payload_len, fcs_len);
        fcs = tvb_get_ntohl(tvb, *offset + payload_len);
        /* Same CRC32 as ATM */
        /* As with ATM, we can either compute the CRC as it would be
         * calculated and compare (last step involves taking the complement),
         * or we can include the passed CRC in the input and check to see
         * if the remainder is a known value. I like the first method
         * only because it lets us display what we should have received. */
        /* Method 1: */
        fcs_calc = crc32_mpeg2_tvb_offset(tvb, *offset, payload_len);
        if (fcs == ~fcs_calc) {
            fcs_ti = proto_tree_add_uint_format_value(gfp_tree, hf_gfp_fcs, tvb, *offset+payload_len, 4, fcs, "0x%08x [correct]", fcs);
            fcs_tree = proto_item_add_subtree(fcs_ti, ett_gfp_fcs);
            fcs_ti = proto_tree_add_boolean(fcs_tree, hf_gfp_fcs_good, tvb, *offset+payload_len, 4, TRUE);
            proto_item_set_generated(fcs_ti);
            fcs_ti = proto_tree_add_boolean(fcs_tree, hf_gfp_fcs_bad, tvb, *offset+payload_len, 4, FALSE);
            proto_item_set_generated(fcs_ti);
        } else {
            fcs_ti = proto_tree_add_uint_format_value(gfp_tree, hf_gfp_fcs, tvb, *offset+payload_len, 4, fcs, "0x%08x [incorrect, should be 0x%08x]", fcs, fcs_calc);
            fcs_tree = proto_item_add_subtree(fcs_ti, ett_gfp_fcs);
            fcs_ti = proto_tree_add_boolean(fcs_tree, hf_gfp_fcs_good, tvb, *offset+payload_len, 4, FALSE);
            proto_item_set_generated(fcs_ti);
            fcs_ti = proto_tree_add_boolean(fcs_tree, hf_gfp_fcs_bad, tvb, *offset+payload_len, 4, TRUE);
            proto_item_set_generated(fcs_ti);
            expert_add_info(pinfo, fcs_ti, &ei_gfp_fcs_bad);
        }
        /* Method 2: */
        /* fcs_calc = crc32_mpeg2_tvb_offset(tvb, *offset, payload_len+4);
        fcs_ti = proto_tree_add_uint(gfp_tree, hf_gfp_fcs, tvb, *offset+payload_len, 4, fcs);
        proto_item_append_text(fcs_ti, (fcs_calc == 0xC704DD7B) ? " [correct]" : " [incorrect]"); */
    }

    /* Some client frames we can do. Others are not implemented yet.
     * Transparent mode types are much trickier than frame-mapped,
     * since they requires reassembling streams across multiple GFP packets. */
    payload_tvb = tvb_new_subset_length(tvb, *offset, payload_len);
    switch (pti) {
        case GFP_USER_DATA:
        case GFP_MANAGEMENT_COMMUNICATIONS:
            if (!dissector_try_uint(gfp_dissector_table, upi, payload_tvb, pinfo, tree)) {
                expert_add_info_format(pinfo, type_ti, &ei_gfp_payload_undecoded, "Payload type 0x%02x (%s) unsupported", upi, rval_to_str_const(upi, gfp_upi_data_rvals, "UNKNOWN"));
                call_data_dissector(payload_tvb, pinfo, tree);
            }
            break;

        case GFP_CLIENT_MANAGEMENT:
            call_data_dissector(payload_tvb, pinfo, tree);
            break;

        default:
            break;
    }
    *offset += payload_len;
    *offset += fcs_len;
}

static int
dissect_gfp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *pli_ti;
    proto_tree *gfp_tree;
    guint       offset = 0;
    int         len    = 0;
    guint       pli;

    /*** HEURISTICS ***/

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < GFP_MIN_LENGTH)
        return 0;

    /*** COLUMN DATA ***/

    /* Set the Protocol column to the constant string of GFP */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GFP");

    col_clear(pinfo->cinfo, COL_INFO);
    /* Avoid asserts for leaving these blank. */
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");

    /*** PROTOCOL TREE ***/

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_gfp, tvb, 0, GFP_MIN_LENGTH, ENC_NA);

    gfp_tree = proto_item_add_subtree(ti, ett_gfp);

    /* ITU-T G.7041 6.1.1 GFP core header */
    /* The core header could be scrambled (see G.7041 6.1.1.3) but isn't on
     * the GFP level capture files I've seen as it's removed before then.
     * If using this as a subdissector to a SDH or OTN dissector, that could
     * be an issue. TODO: Maybe add a pref for scrambling? */
    len = 2;
    pli_ti = proto_tree_add_item_ret_uint(gfp_tree, hf_gfp_pli, tvb,
        offset, len, ENC_BIG_ENDIAN, &pli);
    if (pli < 4) { /* Don't interpret as payload length */
        proto_item_append_text(pli_ti, " (%s)", rval_to_str_const(pli, gfp_pli_rvals, "Unknown"));
    }
    col_set_str(pinfo->cinfo, COL_INFO, rval_to_str_const(pli, gfp_pli_rvals, "Unknown"));

    /* 6.1.1.2 Core HEC field */
    gfp_add_hec_tree(tvb, pinfo, gfp_tree, &offset, len, hf_gfp_chec, hf_gfp_chec_status, &ei_gfp_chec_bad);

    if (pli == 0) { /* 6.2.1 GFP idle frames */
        if (tvb_reported_length_remaining(tvb, offset)) {
            expert_add_info(pinfo, pli_ti, &ei_gfp_pli_idle_nonempty);
        }
    } else if (pli < 4) { /* 6.2.2 Other control frames (reserved) */
        expert_add_info(pinfo, pli_ti, &ei_gfp_pli_unknown);
    } else {
        /* G.7041 6.1.2 GFP payload area */
        if (tvb_reported_length(tvb) < pli + offset) {
        /* avoid signed / unsigned comparison */
            proto_item_append_text(pli_ti, " (invalid, reported length is %u)", tvb_reported_length_remaining(tvb, offset));
            expert_add_info(pinfo, pli_ti, &ei_gfp_pli_invalid);
        }
        dissect_gfp_payload(tvb, pinfo, tree, gfp_tree, &offset, pli);
    }

    /* Return the amount of data this dissector was able to dissect */
    return offset;
}

void
proto_register_gfp(void)
{
    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_gfp_pli,
          { "Payload Length Indicator", "gfp.pli", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_gfp_chec,
          { "Core HEC", "gfp.chec", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_gfp_chec_status,
          { "cHEC Status", "gfp.chec.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gfp_type,
          { "Type Field", "gfp.type", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gfp_pti,
          { "PTI", "gfp.pti", FT_UINT16, BASE_HEX, VALS(gfp_pti_vals),
            0xE000, "Payload Type Identifier", HFILL }
        },
        { &hf_gfp_pfi,
          { "PFI", "gfp.pfi", FT_BOOLEAN, 16, TFS(&tfs_present_absent),
            0x1000, "Payload FCS Indicator", HFILL }
        },
        { &hf_gfp_exi,
          { "EXI", "gfp.exi", FT_UINT16, BASE_HEX, VALS(gfp_exi_vals),
            0x0F00, "Extension Header Identifier", HFILL }
        },
        { &hf_gfp_upi_data,
          { "UPI", "gfp.upi", FT_UINT16, BASE_HEX|BASE_RANGE_STRING,
            RVALS(gfp_upi_data_rvals),
            0xFF, "User Payload Identifier for Client Data Frame (or Management Communications Frame)", HFILL }
        },
        { &hf_gfp_upi_management,
          { "UPI", "gfp.upi", FT_UINT16, BASE_HEX|BASE_RANGE_STRING,
            RVALS(gfp_upi_management_rvals),
            0xFF, "User Payload Identifier for Client Management Frame", HFILL }
        },
        { &hf_gfp_thec,
          { "Type HEC", "gfp.thec", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gfp_thec_status,
          { "tHEC Status", "gfp.thec.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gfp_cid,
          { "Channel ID", "gfp.cid", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gfp_ehec,
          { "Extension HEC", "gfp.ehec", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gfp_ehec_status,
          { "eHEC Status", "gfp.ehec.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gfp_fcs,
          { "Payload FCS", "gfp.fcs", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gfp_fcs_good,
          { "Good FCS", "gfp.fcs_good", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: FCS matches payload; False: doesn't match", HFILL }
        },
        { &hf_gfp_fcs_bad,
          { "Bad eHEC", "gfp.fcs_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: FCS doesn't match payload; False: matches", HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_gfp,
        &ett_gfp_type,
        &ett_gfp_fcs
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_gfp_pli_idle_nonempty,
          { "gfp.pli.idle.nonempty", PI_MALFORMED, PI_ERROR,
            "Payload present on idle frame", EXPFILL }
        },
        { &ei_gfp_pli_unknown,
          { "gfp.pli.unknown", PI_UNDECODED, PI_WARN,
            "Unknown control frame type", EXPFILL }
        },
        { &ei_gfp_pli_invalid,
          { "gfp.pli.invalid", PI_MALFORMED, PI_WARN,
            "Bogus PLI does not match reported length", EXPFILL }
        },
        { &ei_gfp_chec_bad,
          { "gfp.chec.bad", PI_CHECKSUM, PI_WARN,
            "Bad cHEC", EXPFILL }
        },
        { &ei_gfp_thec_bad,
          { "gfp.thec.bad", PI_CHECKSUM, PI_WARN,
            "Bad tHEC", EXPFILL }
        },
        { &ei_gfp_ehec_bad,
          { "gfp.ehec.bad", PI_CHECKSUM, PI_WARN,
            "Bad eHEC", EXPFILL }
        },
        { &ei_gfp_exi_short,
          { "gfp.exi.missing", PI_MALFORMED, PI_ERROR,
            "EXI bit set but PLI too short for extension header", EXPFILL}
        },
        { &ei_gfp_pfi_short,
          { "gfp.pfi.missing", PI_MALFORMED, PI_ERROR,
            "PFI bit set but PLI too short for payload FCS", EXPFILL}
        },
        { &ei_gfp_payload_undecoded,
          { "gfp.payload.undecoded", PI_UNDECODED, PI_WARN,
            "Payload type not supported yet by the dissector", EXPFILL}
        },
        { &ei_gfp_fcs_bad,
          { "gfp.fcs.bad", PI_CHECKSUM, PI_WARN,
            "Bad FCS", EXPFILL }
        }
    };

    /* Decode As handling */
    static build_valid_func gfp_da_build_value[1] = {gfp_value};
    static decode_as_value_t gfp_da_values = {gfp_prompt, 1, gfp_da_build_value};
    static decode_as_t gfp_da = {"gfp", "gfp.upi", 1, 0, &gfp_da_values, NULL, NULL,
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    /* module_t        *gfp_module; */
    expert_module_t *expert_gfp;

    /* Register the protocol name and description */
    proto_gfp = proto_register_protocol("Generic Framing Procedure",
            "GFP", "gfp");
    gfp_handle = register_dissector("gfp", dissect_gfp,
            proto_gfp);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_gfp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_gfp = expert_register_protocol(proto_gfp);
    expert_register_field_array(expert_gfp, ei, array_length(ei));

    /* Subdissectors for payload */
    gfp_dissector_table = register_dissector_table("gfp.upi", "GFP UPI (for Client Data frames)",
                                                   proto_gfp, FT_UINT8, BASE_DEC);

    /* Don't register a preferences module yet since there are no prefs in
     * order to avoid a warning. (See section 2.6 of README.dissector
     * for more details on preferences). */
    /*gfp_module = prefs_register_protocol(proto_gfp, NULL);*/

    register_decode_as(&gfp_da);
}

void
proto_reg_handoff_gfp(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_GFP_T, gfp_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_GFP_F, gfp_handle);

    /* Add a few of the easiest UPIs to decode. There's more that probably
     * would work, but are untested (frame mapped DVB, frame mapped Fibre
     * Channel). The transparent mode ones are trickier, since without a
     * one-to-one mapping of frames, we would have to reassemble payload
     * packets across multiple GFP packets.
     *
     * Section 7.1.1 "Ethernet MAC encapsulation" of G.7041 says
     * "The Ethernet MAC octets from destination address through
     * "frame check sequence, inclusive, are placed in the GFP payload
     * "information field.", so we want the dissector for Ethernet
     * frames including the FCS. */
    dissector_add_uint("gfp.upi", 1, find_dissector("eth_withfcs"));
    dissector_add_uint("gfp.upi", 2, find_dissector("ppp_hdlc"));
    dissector_add_uint("gfp.upi", 9, find_dissector("mp2t"));
    dissector_add_uint("gfp.upi", 12, find_dissector("mpls"));
    dissector_add_uint("gfp.upi", 13, find_dissector("mpls"));
    dissector_add_uint("gfp.upi", 16, find_dissector("ip"));
    dissector_add_uint("gfp.upi", 17, find_dissector("ipv6"));
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
