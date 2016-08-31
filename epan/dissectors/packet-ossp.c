/* packet-ossp.c
 * Routines for Organization Specific Slow Protocol dissection
 * IEEE Std 802.3, Annex 57B
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
 * Copyright 2009 Artem Tamazov <artem.tamazov@telllabs.com>
 * Copyright 2010 Roberto Morro <roberto.morro[AT]tilab.com>
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

#include <epan/slow_protocol_subtypes.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>

#include <wsutil/str_util.h>

/* General declarations */
void proto_register_ossp(void);
void proto_reg_handoff_ossp(void);

/*
 * ESMC
 */
#define ITU_OUI_0                   0x00
#define ITU_OUI_1                   0x19
#define ITU_OUI_2                   0xa7
#define OUI_SIZE                       3
#define ESMC_ITU_SUBTYPE          0x0001
#define ESMC_VERSION_1              0x01
#define ESMC_QL_TLV_TYPE            0x01
#define ESMC_QL_TLV_LENGTH          0x04
#define ESMC_TIMESTAMP_TLV_TYPE     0x02
#define ESMC_TIMESTAMP_TLV_LENGTH   0x08

static const value_string esmc_event_flag_vals[] = {
    { 0, "Information ESMC PDU" },
    { 1, "Time-critical Event ESMC PDU" },
    { 0, NULL }
};

static const value_string esmc_tlv_type_vals[] = {
    { 1, "Quality Level" },
    { 2, "Timestamp" },
    { 0, NULL }
};

static const value_string esmc_timestamp_valid_flag_vals[] = {
    { 0, "Not set. Do not use Timestamp value even if Timestamp TLV present" },
    { 1, "Set. Timestamp TLV Present" },
    { 0, NULL }
};

/* G.781 5.5.1.1 Option I SDH (same in G.707) */
static const value_string esmc_quality_level_opt_1_vals[] = {
    {  2,   "QL-PRC, Primary reference clock (G.811)" },
    {  4,   "QL-SSU-A, Type I or V SSU clock (G.812), 'transit node clock'" },
    {  8,   "QL-SSU-B, Type VI SSU clock (G.812), 'local node clock'" },
    { 11,   "QL-SEC, SEC clock (G.813, Option I) or QL-EEC1 (G.8262)" },
    { 15,   "QL-DNU, 'Do Not Use'" },
    { 0, NULL }
};

static const value_string esmc_quality_level_opt_1_vals_short[] = {
    {  2,   "QL-PRC" },
    {  4,   "QL-SSU-A" },
    {  8,   "QL-SSU-B" },
    { 11,   "QL-SEC" },
    { 15,   "QL-DNU" },
    { 0, NULL }
};

#if 0 /*not used yet*/
/* G.781 5.5.1.2 Option II SDH synchronization networking */
static const value_string esmc_quality_level_opt_2_vals[] = {
    {  0,   "QL-STU, unknown - signal does not carry the QL message of the source" },
    {  1,   "QL-PRS, PRS clock (G.811) / ST1, Stratum 1 Traceable" },
    {  4,   "QL-TNC, Transit Node Clock (G.812, Type V)" },
    {  7,   "QL-ST2, Stratum 2 clock (G.812, Type II)" },
    { 10,   "QL-ST3, Stratum 3 clock (G.812, Type IV) or QL-EEC2 (G.8262)" },
    { 12,   "QL-SMC, SONET self timed clock (G.813, Option II) / SMC 20 ppm Clock Traceable" },
    { 13,   "QL-ST3E, Stratum 3E clock (G.812, Type III)" },
    { 14,   "QL-PROV, provisionable by the network operator / Reserved for Network Synchronization" },
    { 15,   "QL-DUS, shall not be used for synchronization" },
    { 0, NULL }
};

static const value_string esmc_quality_level_opt_2_short[] = {
    {  0,   "QL-STU" },
    {  1,   "QL-PRS" },
    {  4,   "QL-TNC" },
    {  7,   "QL-ST2" },
    { 10,   "QL-ST3" },
    { 12,   "QL-SMC" },
    { 13,   "QL-ST3E" },
    { 14,   "QL-PROV" },
    { 15,   "QL-DUS" },
    { 0, NULL }
};
#endif

static const value_string esmc_quality_level_invalid_vals[] = {
    {  0,   "QL-INV0" },
    {  1,   "QL-INV1" },
    {  2,   "QL-INV2" },
    {  3,   "QL-INV3" },
    {  4,   "QL-INV4" },
    {  5,   "QL-INV5" },
    {  6,   "QL-INV6" },
    {  7,   "QL-INV7" },
    {  8,   "QL-INV8" },
    {  9,   "QL-INV9" },
    { 10,   "QL-INV10" },
    { 11,   "QL-INV11" },
    { 12,   "QL-INV12" },
    { 13,   "QL-INV13" },
    { 14,   "QL-INV14" },
    { 15,   "QL-INV15" },
    { 0, NULL }
};

/* Initialise the protocol and registered fields */
static int proto_ossp = -1;

static int hf_ossp_oui = -1;
static int hf_itu_subtype = -1;
static int hf_esmc_version = -1;
static int hf_esmc_event_flag = -1;
static int hf_esmc_timestamp_valid_flag = -1;
static int hf_esmc_reserved_32 = -1;
static int hf_esmc_tlv = -1;
static int hf_esmc_tlv_type = -1;
static int hf_esmc_tlv_length = -1;
static int hf_esmc_tlv_ql_unused = -1;
static int hf_esmc_tlv_ts_reserved = -1;
static int hf_esmc_quality_level_opt_1 = -1;
#if 0 /*not used yet*/
static int hf_esmc_quality_level_opt_2 = -1;
#endif
static int hf_esmc_quality_level_invalid = -1;
static int hf_esmc_timestamp = -1;
static int hf_esmc_padding = -1;

/*
 * The Timestamp TLV and Timestamp Valid Flag fields
 * are proposed in WD56 document for G.8264.
 * WD56 is not accepted at this moment (June 2009).
 *
 * The following variable controls dissection of Timestamp fields.
 * Implementation is not fully complete yet -- in this version
 * Timestamp dissection is always enabled.
 *
 * I expect that when WD56 proposal for G.8264 will be accepted,
 * ESMC Version would be used to control Timestamp dissection.
 * In this case this variable will be eliminated (replaced).
 *
 * Until that, a preference which controls Timestamp
 * dissection may be added, if such need arise.
 * At the moment this is not practical as nobody needs this.
 */
static gboolean pref_decode_esmc_timestamp = TRUE;

/* Initialise the subtree pointers */

static gint ett_ossppdu = -1;
static gint ett_itu_ossp = -1;

static gint ett_esmc = -1;

static expert_field ei_esmc_tlv_type_ql_type_not_first = EI_INIT;
static expert_field ei_esmc_tlv_type_not_timestamp = EI_INIT;
static expert_field ei_esmc_quality_level_invalid = EI_INIT;
static expert_field ei_esmc_tlv_ql_unused_not_zero = EI_INIT;
static expert_field ei_esmc_tlv_type_decoded_as_timestamp = EI_INIT;
static expert_field ei_esmc_tlv_type_decoded_as_ql_type = EI_INIT;
static expert_field ei_esmc_version_compliance = EI_INIT;
static expert_field ei_esmc_tlv_length_bad = EI_INIT;
static expert_field ei_esmc_reserved_not_zero = EI_INIT;

static void
dissect_esmc_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *treex);

static void
dissect_itu_ossp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*
 * Name: dissect_ossp_pdu
 *
 * Description:
 *    This function is used to dissect the Organization Specific Slow
 *    Protocol defined in IEEE 802.3 Annex 57B. Currently only the ESMC
 *    slow protocol as defined in ITU-T G.8264 is implemented
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Roberto Morro (roberto.morro[AT]tilab.com)
 */
static int
dissect_ossp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint          offset = 0;
    const gchar  *str;
    proto_item   *oui_item, *ossp_item;
    proto_tree   *ossp_tree;
    tvbuff_t     *ossp_tvb;
    const guint8  itu_oui[] = {ITU_OUI_0, ITU_OUI_1, ITU_OUI_2};

    /* OUI of the organization defining the protocol */
    str = tvb_get_manuf_name(tvb, offset);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OSSP");
    col_add_fstr(pinfo->cinfo, COL_INFO, "OUI: %s", str);

    ossp_item = proto_tree_add_protocol_format(tree, proto_ossp, tvb, 0, -1,
                                               "Organization Specific Slow Protocol");
    ossp_tree = proto_item_add_subtree(ossp_item, ett_ossppdu);

    oui_item = proto_tree_add_item(ossp_tree, hf_ossp_oui,
                                    tvb, offset, OUI_SIZE, ENC_NA);
    proto_item_append_text(oui_item, " (%s)", str);
    offset += 3;

    /*
     * XXX - should have a dissector table here, but we don't yet
     * support OUIs as keys in dissector tables.
     */
    ossp_tvb = tvb_new_subset_remaining(tvb, offset);
    if (tvb_memeql(tvb, 0, itu_oui, OUI_SIZE) == 0)
    {
       dissect_itu_ossp(ossp_tvb, pinfo, ossp_tree);
    }
/*    new Organization Specific Slow Protocols go hereafter */
#if 0
    else if (tvb_memeql(tvb, 0, xxx_oui, OUI_SIZE) == 0)
    {
        dissect_xxx_ossp(ossp_tvb, pinfo, ossp_tree);
    }
    else if (tvb_memeql(tvb, 0, yyy_oui, OUI_SIZE) == 0)
    {
        dissect_yyy_ossp(ossp_tvb, pinfo, ossp_tree);
    }
#endif
    else
    {
        proto_item_append_text(oui_item, " (Unknown OSSP organization)");
    }
    return tvb_captured_length(tvb);
}

/*
 * Name: dissect_itu_ossp
 *
 * Description:
 *    This function is used to dissect the ITU-T OSSP (Organization Specific
 *    Slow Protocol). Currently only the Ethernet Synchronization
 *    Messaging Channel (ESMC) slow protocol as defined in ITU-T G.8264
 *    is implemented
 *
 * Input Arguments:
 *    tvb:     buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo:   structure associated with the rcv packet (see packet_info.h).
 *    tree:    the protocol tree associated with the rcv packet (see proto.h).
 *    subtype: the protocol subtype (according to IEEE802.3 annex 57B)
 *
 * Return Values: None
 *
 * Notes:
 *    Roberto Morro (roberto.morro[AT]tilab.com)
 */

static void
dissect_itu_ossp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16     subtype;
    proto_tree *itu_ossp_tree, *ti;

    /* ITU-T OSSP Subtype */
    subtype = tvb_get_ntohs(tvb, 0);
    ti = proto_tree_add_item(tree, hf_itu_subtype, tvb, 0, 2, ENC_BIG_ENDIAN);

    itu_ossp_tree = proto_item_add_subtree(ti, ett_itu_ossp);

    switch (subtype)
    {
        case ESMC_ITU_SUBTYPE:
            dissect_esmc_pdu(tvb, pinfo, itu_ossp_tree);
            break;

/*  Other ITU-T defined slow protocols go hereafter */
#if 0
        case XXXX_ITU_SUBTYPE:
            dissect_xxxx_pdu(tvb, pinfo, itu_ossp_tree);
            break;
#endif
        default:
            proto_item_append_text(itu_ossp_tree, " (Unknown)");
    }
}
/*
 * Description:
 *    This function is used to dissect ESMC PDU defined G.8264/Y.1364
 *    clause 11.3.1.1.
 *
 *    Added: TimeStamp TLV as per WD56 proposal for G.8264,
 *    "TLVs for ESMC and Querying Capability".
 */
static void
dissect_esmc_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *treex)
{
    gint     offset    = 2; /*starting from ESMC Version */
    gboolean event_flag;
    gboolean malformed = FALSE;
    gint     ql        = -1; /*negative means unknown:*/
    gboolean timestamp_valid_flag = FALSE; /*set if timestamp valid*/
    gint32   timestamp = -1; /*nanoseconds*/

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESMC");

    proto_item_append_text(treex, ": ESMC");
    {
        proto_tree *tree_a;
        tree_a = proto_item_add_subtree(treex, ett_esmc);

        { /* version */
            proto_item *item_b;
            item_b = proto_tree_add_item(tree_a, hf_esmc_version, tvb, offset, 1, ENC_BIG_ENDIAN);
            if ((tvb_get_guint8(tvb, offset) >> 4) != ESMC_VERSION_1)
            {
                malformed = TRUE;
                expert_add_info_format(pinfo, item_b, &ei_esmc_version_compliance, "Version must be 0x%.1x claim compliance with Version 1 of this protocol", ESMC_VERSION_1);
            }
            /*stay at the same octet in tvb*/
        }
        { /* event flag */
            event_flag = ((tvb_get_guint8(tvb, offset) & 0x08) != 0);
            proto_tree_add_item(tree_a, hf_esmc_event_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            /*stay at the same octet in tvb*/
        }
        if (pref_decode_esmc_timestamp)
        { /* timestamp valid flag */
            timestamp_valid_flag = ((tvb_get_guint8(tvb, offset) & 0x04) != 0);
            proto_tree_add_item(tree_a, hf_esmc_timestamp_valid_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            /*stay at the same octet in tvb*/
        }
        { /* reserved bits */
            proto_item *item_b;
            guint32 reserved;
            reserved = tvb_get_ntohl(tvb, offset)
                        & (pref_decode_esmc_timestamp ? 0x3ffffff : 0x7ffffff);
            item_b = proto_tree_add_uint_format_value(tree_a, hf_esmc_reserved_32, tvb, offset, 4
                                                    , reserved, "0x%.7x", reserved);
            if (reserved != 0x0)
            {
                malformed = TRUE;
                expert_add_info_format(pinfo, item_b, &ei_esmc_reserved_not_zero, "Reserved bits must be set to all zero on transmitter");
            }
            offset += 4;
        }
        proto_item_append_text(treex, ", Event:%s", event_flag ?
                               "Time-critical" : "Information");

        /*
         * Quality Level TLV is mandatory at fixed location.
         */
        {
            proto_item *item_b;
            guint8 type;
            item_b = proto_tree_add_item(tree_a, hf_esmc_tlv, tvb, offset, 4, ENC_NA);
            {
                proto_tree *tree_b;
                tree_b = proto_item_add_subtree(item_b, ett_esmc);
                {
                    proto_item *item_c;
                    guint16 length;
                    guint8 unused;

                    /* type */
                    type = tvb_get_guint8(tvb, offset);
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    if (type != ESMC_QL_TLV_TYPE)
                    {
                        malformed = TRUE;
                        expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_type_ql_type_not_first, "TLV Type must be == 0x%.2x (QL) because QL TLV must be first in the ESMC PDU", ESMC_QL_TLV_TYPE);
                        expert_add_info(pinfo, item_c, &ei_esmc_tlv_type_decoded_as_ql_type);
                    }
                    offset += 1;

                    /* length */
                    length = tvb_get_ntohs(tvb, offset);
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    if (length != ESMC_QL_TLV_LENGTH)
                    {
                        malformed = TRUE;
                        expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_length_bad, "QL TLV Length must be == 0x%.4x", ESMC_QL_TLV_LENGTH);
                        expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_type_decoded_as_ql_type, "Let's decode this TLV as if Length has valid value");
                    }
                    offset += 2;

                    /* value */
                    unused = tvb_get_guint8(tvb, offset); /*as temp var*/
                    ql = unused & 0x0f;
                    unused &= 0xf0;
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_ql_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
                    if (unused != 0x00)
                    {
                        malformed = TRUE;
                        expert_add_info(pinfo, item_c, &ei_esmc_tlv_ql_unused_not_zero);
                    }
                    if (NULL != try_val_to_str(ql, esmc_quality_level_opt_1_vals))
                    {
                        proto_tree_add_item(tree_b, hf_esmc_quality_level_opt_1, tvb, offset, 1, ENC_BIG_ENDIAN);
                    }
                    else
                    {
                        item_c = proto_tree_add_item(tree_b, hf_esmc_quality_level_invalid, tvb, offset, 1, ENC_BIG_ENDIAN);
                        expert_add_info(pinfo, item_c, &ei_esmc_quality_level_invalid);
                    }
                    offset += 1;
                }
            }
            proto_item_append_text(item_b, ", %s"
                , val_to_str(ql, esmc_quality_level_opt_1_vals_short, "QL-INV%d"));
        }
        proto_item_append_text(treex, ", %s"
            , val_to_str(ql, esmc_quality_level_opt_1_vals_short, "QL-INV%d"));

        if (pref_decode_esmc_timestamp)
        {
            /*
             * Timestamp TLV is optional at fixed location.
             * Decode it if Timestamp Valid flag is set,
             * or if type of next TLV is 0x02.
             */
            guint8 type;
            type = tvb_get_guint8(tvb, offset);

            if (timestamp_valid_flag || type == ESMC_TIMESTAMP_TLV_TYPE)
            {
                proto_item *item_b;
                item_b = proto_tree_add_item(tree_a, hf_esmc_tlv, tvb, offset, 8, ENC_NA);
                {
                    proto_tree *tree_b;
                    tree_b = proto_item_add_subtree(item_b, ett_esmc);
                    {
                        proto_item *item_c;
                        guint16 length;
                        guint8 reserved;

                        /* type */
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        if (type != ESMC_TIMESTAMP_TLV_TYPE)
                        {
                            malformed = TRUE;
                            expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_type_not_timestamp, "TLV Type must be == 0x%.2x (Timestamp) because Timestamp Valid Flag is set", ESMC_TIMESTAMP_TLV_TYPE);
                            expert_add_info(pinfo, item_c, &ei_esmc_tlv_type_decoded_as_timestamp);
                        }
                        offset += 1;

                        /* length */
                        length = tvb_get_ntohs(tvb, offset);
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                        if (length != ESMC_TIMESTAMP_TLV_LENGTH)
                        {
                            malformed = TRUE;
                            expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_length_bad, "Timestamp TLV Length must be == 0x%.4x", ESMC_TIMESTAMP_TLV_LENGTH);
                            expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_type_decoded_as_timestamp, "Let's decode this TLV as if Length has valid value");
                        }
                        offset += 2;

                        /* value */
                        timestamp = (gint32)tvb_get_ntohl(tvb, offset);
                        item_c = proto_tree_add_item(tree_b, hf_esmc_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
                        if (!timestamp_valid_flag) proto_item_append_text(item_c, " [invalid]");
                        offset += 4;

                        /* reserved */
                        reserved = tvb_get_guint8(tvb, offset);
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_ts_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                        if (reserved != 0x0)
                        {
                            expert_add_info(pinfo, item_c, &ei_esmc_reserved_not_zero);
                        }
                        offset += 1;
                    }
                }
                proto_item_append_text(item_b, ", Timestamp: %d ns", timestamp);
                if (!timestamp_valid_flag) proto_item_append_text(item_b, " [invalid]");
            }
        }
        if (timestamp_valid_flag)
        {
            proto_item_append_text(treex, ", Timestamp:%d", timestamp);
        }
    }

    { /* padding */
        gint padding_size;
        padding_size = tvb_captured_length_remaining(tvb, offset);
        if (0 != padding_size)
        {
            proto_tree* tree_a;
            tree_a = proto_item_add_subtree(treex, ett_esmc);
            {
                proto_item* item_b;
                tvbuff_t* tvb_next;
                tvb_next = tvb_new_subset_remaining(tvb, offset);
                item_b = proto_tree_add_item(tree_a, hf_esmc_padding, tvb_next, 0, -1, ENC_NA);
                proto_item_append_text(item_b, ", %d %s%s", padding_size
                , "octet", plurality(padding_size,"","s"));
                {
                    proto_tree* tree_b;
                    tree_b = proto_item_add_subtree(item_b, ett_esmc);
                    call_data_dissector(tvb_next, pinfo, tree_b);
                }
            }
        }
    }

    /* append summary info */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Event:%s", event_flag ?
                    "Time-critical" : "Information");
    if (ql >= 0)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s"
        , val_to_str(ql, esmc_quality_level_opt_1_vals_short, "QL-INVALID-%d"));
    }
    if (timestamp_valid_flag)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", TS:%d", timestamp);
    }
    if (malformed)
    {
        col_append_str(pinfo->cinfo, COL_INFO, ", Malformed PDU");
    }
}

/* Register the protocol with Wireshark */
void
proto_register_ossp(void)
{
/* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_ossp_oui,
          { "OUI",    "ossp.oui",
            FT_BYTES,     BASE_NONE,    NULL,    0,
            "IEEE assigned Organizationally Unique Identifier", HFILL }},

        { &hf_itu_subtype,
          { "ITU-T OSSP Subtype",    "ossp.itu.subtype",
            FT_UINT16,    BASE_HEX,    NULL,    0,
            "Subtype assigned by the ITU-T", HFILL }},

        { &hf_esmc_version,
          { "Version",    "ossp.esmc.version",
            FT_UINT8,     BASE_HEX,    NULL,    0xf0,
            "This field indicates the version of ITU-T SG15 Q13 OSSP frame format", HFILL }},

        { &hf_esmc_event_flag,
          { "Event Flag",    "ossp.esmc.event_flag",
            FT_UINT8,    BASE_HEX,    VALS(esmc_event_flag_vals),    0x08,
            "This bit distinguishes the critical, time sensitive behaviour of the"
            " ESMC Event PDU from the ESMC Information PDU", HFILL }},

        { &hf_esmc_timestamp_valid_flag,
          { "Timestamp Valid Flag",    "ossp.esmc.timestamp_valid_flag",
            FT_UINT8,    BASE_HEX,    VALS(esmc_timestamp_valid_flag_vals),    0x04,
            "Indicates validity (i.e. presence) of the Timestamp TLV", HFILL }},

        { &hf_esmc_reserved_32,
          { "Reserved",    "ossp.esmc.reserved",
            FT_UINT32,    BASE_HEX,    NULL,    0,
            "Reserved. Set to all zero at the transmitter and ignored by the receiver", HFILL }},

        { &hf_esmc_tlv,
          { "ESMC TLV",    "ossp.esmc.tlv",
            FT_NONE,     BASE_NONE,    NULL,    0,
            NULL, HFILL }},

        { &hf_esmc_tlv_type,
          { "TLV Type",    "ossp.esmc.tlv_type",
            FT_UINT8,    BASE_HEX,    VALS(esmc_tlv_type_vals),    0,
            NULL, HFILL }},

        { &hf_esmc_tlv_length,
          { "TLV Length",    "ossp.esmc.tlv_length",
            FT_UINT16,    BASE_HEX,    NULL,    0,
            NULL, HFILL }},

        { &hf_esmc_tlv_ql_unused,
          { "Unused",    "ossp.esmc.tlv_ql_unused",
            FT_UINT8,     BASE_HEX,    NULL,    0xf0,
            "This field is not used in QL TLV", HFILL }},

        { &hf_esmc_quality_level_opt_1,
          { "SSM Code",    "ossp.esmc.ql",
            FT_UINT8,    BASE_HEX,    VALS(esmc_quality_level_opt_1_vals),    0x0f,
            "Quality Level information", HFILL }},

#if 0 /*not used yet*/
        { &hf_esmc_quality_level_opt_2,
          { "SSM Code",    "ossp.esmc.ql",
            FT_UINT8,    BASE_HEX,    VALS(esmc_quality_level_opt_2_vals),    0x0f,
            "Quality Level information", HFILL }},
#endif

        { &hf_esmc_quality_level_invalid,
          { "SSM Code",    "ossp.esmc.ql",
            FT_UINT8,    BASE_HEX,    VALS(esmc_quality_level_invalid_vals),    0x0f,
            "Quality Level information", HFILL }},

        { &hf_esmc_timestamp,
          { "Timestamp (ns)",    "ossp.esmc.timestamp",
            FT_INT32,    BASE_DEC,    NULL,    0,
            "Timestamp according to the \"whole nanoseconds\" part of the IEEE 1588 originTimestamp", HFILL }},

        { &hf_esmc_tlv_ts_reserved,
          { "Reserved",    "ossp.esmc.tlv_ts_reserved",
            FT_UINT8,     BASE_HEX,    NULL,    0,
            "Reserved. Set to all zero at the transmitter and ignored by the receiver", HFILL }},

        { &hf_esmc_padding,
          { "Padding",    "ossp.esmc.padding",
            FT_BYTES,     BASE_NONE,    NULL,    0x0,
            "This field contains necessary padding to achieve the minimum frame size of 64 bytes at least", HFILL }},
    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_esmc,
        &ett_ossppdu,
        &ett_itu_ossp
    };

    static ei_register_info ei[] = {
        { &ei_esmc_version_compliance, { "ossp.esmc.version.compliance", PI_MALFORMED, PI_ERROR, "Version must claim compliance with Version 1 of this protocol", EXPFILL }},
        { &ei_esmc_tlv_type_ql_type_not_first, { "ossp.esmc.tlv_type.ql_type_not_first", PI_MALFORMED, PI_ERROR, "TLV Type must be QL because QL TLV must be first in the ESMC PDU", EXPFILL }},
        { &ei_esmc_tlv_type_decoded_as_ql_type, { "ossp.esmc.tlv_type.decoded_as_ql_type", PI_UNDECODED, PI_NOTE, "Let's decode as if this is QL TLV", EXPFILL }},
        { &ei_esmc_tlv_length_bad, { "ossp.esmc.tlv_length.bad", PI_MALFORMED, PI_ERROR, "QL TLV Length must be X", EXPFILL }},
        { &ei_esmc_tlv_ql_unused_not_zero, { "ossp.esmc.tlv_ql_unused.not_zero", PI_MALFORMED, PI_WARN, "Unused bits of TLV must be all zeroes", EXPFILL }},
        { &ei_esmc_quality_level_invalid, { "ossp.esmc.ql.invalid", PI_UNDECODED, PI_WARN, "Invalid SSM message, unknown QL code", EXPFILL }},
        { &ei_esmc_tlv_type_not_timestamp, { "ossp.esmc.tlv_type.not_timestamp", PI_MALFORMED, PI_ERROR, "TLV Type must be == Timestamp because Timestamp Valid Flag is set", EXPFILL }},
        { &ei_esmc_tlv_type_decoded_as_timestamp, { "ossp.esmc.tlv_type.decoded_as_timestamp", PI_UNDECODED, PI_NOTE, "Let's decode as if this is Timestamp TLV", EXPFILL }},
        { &ei_esmc_reserved_not_zero, { "ossp.esmc.reserved_bits_must_be_set_to_all_zero", PI_PROTOCOL, PI_WARN, "Reserved bits must be set to all zero", EXPFILL }},
    };

    expert_module_t* expert_ossp;

    /* Register the protocol name and description */

    proto_ossp = proto_register_protocol("OSSP", "Organization Specific Slow Protocol", "ossp");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_ossp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ossp = expert_register_protocol(proto_ossp);
    expert_register_field_array(expert_ossp, ei, array_length(ei));
}

void
proto_reg_handoff_ossp(void)
{
    dissector_handle_t ossp_handle;

    ossp_handle = create_dissector_handle(dissect_ossp_pdu, proto_ossp);
    dissector_add_uint("slow.subtype", OSSP_SUBTYPE, ossp_handle);
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
