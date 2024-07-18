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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/slow_protocol_subtypes.h>
#include <epan/addr_resolv.h>
#include <epan/oui.h>
#include <epan/expert.h>

#include <wsutil/str_util.h>

/* General declarations */
void proto_register_ossp(void);
void proto_reg_handoff_ossp(void);

static dissector_handle_t ossp_handle;

/*
 * ESMC
 */
#define OUI_SIZE                       3
#define ESMC_ITU_SUBTYPE          0x0001
#define ESMC_VERSION_1              0x01
#define ESMC_QL_TLV_TYPE            0x01
#define ESMC_QL_TLV_LENGTH          0x04
#define ESMC_EXTENDED_QL_TLV_TYPE   0x02
#define ESMC_EXTENDED_QL_TLV_LENGTH 0x14

static const true_false_string esmc_event_flag_tfs =
    { "Time-critical Event ESMC PDU", "Information ESMC PDU" };

static const value_string esmc_tlv_type_vals[] = {
    { 1, "Quality Level" },
    { 2, "Extended Quality Level" },
    { 0, NULL }
};

/* G.781 5.5.1.1 Option I SDH (same in G.707) */
static const value_string esmc_quality_level_opt_1_vals[] = {
// SSM only codes
    {              2,   "QL-PRC, Primary reference clock (G.811)" },
    {              4,   "QL-SSU-A, Type I or V SSU clock (G.812), 'transit node clock'" },
    {              8,   "QL-SSU-B, Type VI SSU clock (G.812), 'local node clock'" },
    {             11,   "QL-EEC1, EEC (G.8262, Option I) or SEC clock (G.813, Option I)" },
    {             15,   "QL-DNU, 'Do Not Use'" },
// SSM+eSSM codes
    { (0xFF<<8) |  2,   "QL-PRC, Primary reference clock (G.811)" },
    { (0xFF<<8) |  4,   "QL-SSU-A, Type I or V SSU clock (G.812), 'transit node clock'" },
    { (0xFF<<8) |  8,   "QL-SSU-B, Type VI SSU clock (G.812), 'local node clock'" },
    { (0xFF<<8) | 11,   "QL-EEC1, EEC (G.8262, Option I) or SEC clock (G.813, Option I)" },
    { (0xFF<<8) | 15,   "QL-DNU, 'Do Not Use'" },
    { (0x20<<8) |  2,   "QL-PRTC, Primary Reference Time Clock" },
    { (0x21<<8) |  2,   "QL-ePRTC, Enhanced Primary Reference Time Clock"},
    { (0x22<<8) | 11,   "QL-eEEC, Enhanced Ethernet Equipment Clock" },
    { (0x23<<8) |  2,   "QL-ePRC, Enhanced Primary Reference Clock" },
    { 0, NULL }
};

static const value_string esmc_quality_level_opt_1_vals_short[] = {
// SSM codes
    {              2,   "QL-PRC" },
    {              4,   "QL-SSU-A" },
    {              8,   "QL-SSU-B" },
    {             11,   "QL-EEC1" },
    {             15,   "QL-DNU" },
// SSM+eSSM codes
    { (0xFF<<8) |  2,   "QL-PRC" },
    { (0xFF<<8) |  4,   "QL-SSU-A" },
    { (0xFF<<8) |  8,   "QL-SSU-B" },
    { (0xFF<<8) | 11,   "QL-EEC1" },
    { (0xFF<<8) | 15,   "QL-DNU" },
    { (0x20<<8) |  2,   "QL-PRTC" },
    { (0x21<<8) |  2,   "QL-ePRTC"},
    { (0x22<<8) | 11,   "QL-eEEC" },
    { (0x23<<8) |  2,   "QL-ePRC" },
    { 0, NULL }
};

/* G.781 5.5.1.2 Option II SDH synchronization networking */
static const value_string esmc_quality_level_opt_2_vals[] = {
// SSM codes
    {              0,   "QL-STU, unknown - signal does not carry the QL message of the source" },
    {              1,   "QL-PRS, PRS clock (G.811) / ST1, Stratum 1 Traceable" },
    {              4,   "QL-TNC, Transit Node Clock (G.812, Type V)" },
    {              7,   "QL-ST2, Stratum 2 clock (G.812, Type II)" },
    {             10,   "QL-ST3, Stratum 3 clock (G.812, Type IV) or QL-EEC2 (G.8262)" },
    {             13,   "QL-ST3E, Stratum 3E clock (G.812, Type III)" },
    {             14,   "QL-PROV, provisionable by the network operator / Reserved for Network Synchronization" },
    {             15,   "QL-DUS, shall not be used for synchronization" },
// SSM+eSSM codes
    { (0xFF<<8) |  0,   "QL-STU, unknown - signal does not carry the QL message of the source" },
    { (0xFF<<8) |  1,   "QL-PRS, PRS clock (G.811) / ST1, Stratum 1 Traceable" },
    { (0xFF<<8) |  4,   "QL-TNC, Transit Node Clock (G.812, Type V)" },
    { (0xFF<<8) |  7,   "QL-ST2, Stratum 2 clock (G.812, Type II)" },
    { (0xFF<<8) | 10,   "QL-ST3, Stratum 3 clock (G.812, Type IV) or QL-EEC2 (G.8262)" },
    { (0xFF<<8) | 13,   "QL-ST3E, Stratum 3E clock (G.812, Type III)" },
    { (0xFF<<8) | 14,   "QL-PROV, provisionable by the network operator / Reserved for Network Synchronization" },
    { (0xFF<<8) | 15,   "QL-DUS, shall not be used for synchronization" },
    { (0x20<<8) |  1,   "QL-PRTC, Primary Reference Time Clock" },
    { (0x21<<8) |  1,   "QL-ePRTC, Enhanced Primary Reference Time Clock" },
    { (0x22<<8) | 10,   "QL-eEEC, Enhanced Ethernet Equipment Clock" },
    { (0x23<<8) |  1,   "QL-ePRC, Enhanced Primary Reference Clock" },
    { 0, NULL }
};

static const value_string esmc_quality_level_opt_2_vals_short[] = {
// SSM codes
    {              0,   "QL-STU" },
    {              1,   "QL-PRS" },
    {              4,   "QL-TNC" },
    {              7,   "QL-ST2" },
    {             10,   "QL-ST3" },
    {             13,   "QL-ST3E" },
    {             14,   "QL-PROV" },
    {             15,   "QL-DUS" },
// SSM+eSSM codes
    { (0xFF<<8) |  0,   "QL-STU" },
    { (0xFF<<8) |  1,   "QL-PRS" },
    { (0xFF<<8) |  4,   "QL-TNC" },
    { (0xFF<<8) |  7,   "QL-ST2" },
    { (0xFF<<8) | 10,   "QL-ST3" },
    { (0xFF<<8) | 13,   "QL-ST3E" },
    { (0xFF<<8) | 14,   "QL-PROV" },
    { (0xFF<<8) | 15,   "QL-DUS" },
    { (0x20<<8) |  1,   "QL-PRTC" },
    { (0x21<<8) |  1,   "QL-ePRTC" },
    { (0x22<<8) | 10,   "QL-eEEC" },
    { (0x23<<8) |  1,   "QL-ePRC" },
    { 0, NULL }
};

/* G.781 5.5.1.3 Option III SDH synchronization networking */
static const value_string esmc_quality_level_opt_3_vals[] = {
// SSM
    {              0,   "QL-UNK, Unknown" },
    {             11,   "QL-EEC1, EEC (G.8262, Option I) or SEC clock (G.813, Option I)" },
// SSM+eSSM codes
    { (0xFF<<8) |  0,   "QL-UNK, Unknown" },
    { (0xFF<<8) | 11,   "QL-EEC1, EEC (G.8262, Option I) or SEC clock (G.813, Option I)" },
    { 0, NULL }
};

static const value_string esmc_quality_level_opt_3_vals_short[] = {
// SSM
    {              0,   "QL-UNK" },
    {             11,   "QL-EEC1" },
// SSM+eSSM codes
    { (0xFF<<8) |  0,   "QL-UNK" },
    { (0xFF<<8) | 11,   "QL-EEC1" },
    { 0, NULL }
};


static const value_string *esmc_quality_level_vals[] = {
    NULL,
    esmc_quality_level_opt_1_vals,
    esmc_quality_level_opt_2_vals,
    esmc_quality_level_opt_3_vals
};

static const value_string *esmc_quality_level_vals_short[] = {
    NULL,
    esmc_quality_level_opt_1_vals_short,
    esmc_quality_level_opt_2_vals_short,
    esmc_quality_level_opt_3_vals_short
};

/* Initialise the protocol and registered fields */
static int proto_ossp;

static int hf_ossp_oui;
static int hf_itu_subtype;
static int hf_esmc_version;
static int hf_esmc_event_flag;
static int hf_esmc_reserved_bits;
static int hf_esmc_reserved_octets;
static int hf_esmc_tlv;
static int hf_esmc_tlv_type;
static int hf_esmc_tlv_length;
static int hf_esmc_tlv_ql_unused;
static int hf_esmc_tlv_ql_ssm;
static int hf_esmc_tlv_ext_ql_essm;
static int hf_esmc_tlv_ext_ql_clockid;
static int hf_esmc_tlv_ext_ql_flag_reserved;
static int hf_esmc_tlv_ext_ql_flag_chain;
static int hf_esmc_tlv_ext_ql_flag_mixed;
static int hf_esmc_tlv_ext_ql_eeec;
static int hf_esmc_tlv_ext_ql_eec;
static int hf_esmc_tlv_ext_ql_reserved;
static int hf_esmc_quality_level;
static int hf_esmc_padding;

/* Initialise the subtree pointers */

static int ett_ossppdu;
static int ett_itu_ossp;

static int ett_esmc;

static expert_field ei_esmc_tlv_type_ql_type_not_first;
static expert_field ei_esmc_tlv_type_not_ext_ql;
static expert_field ei_esmc_quality_level_invalid;
static expert_field ei_esmc_tlv_ql_unused_not_zero;
static expert_field ei_esmc_tlv_type_decoded_as_ext_ql;
static expert_field ei_esmc_tlv_type_decoded_as_ql_type;
static expert_field ei_esmc_version_compliance;
static expert_field ei_esmc_tlv_length_bad;
static expert_field ei_esmc_reserved_not_zero;

static int pref_option_network = 1;
static const enum_val_t pref_option_network_vals[] =
{
    { "1", "Option I network", 1 }, /* G.781 5.5.1.1 Option I SDH (same in G.707) */
    { "2", "Option II network", 2 }, /* G.781 5.5.1.2 Option II SDH synchronization networking */
    //{ "3", "Option III network", 3 }, /* G.781 5.5.1.3 Option III SDH synchronization networking */
    { NULL, NULL, 0 }
};

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
    int           offset = 0;
    const char   *str;
    proto_item   *ossp_item;
    proto_tree   *ossp_tree;
    tvbuff_t     *ossp_tvb;
    uint32_t     oui;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OSSP");

    ossp_item = proto_tree_add_protocol_format(tree, proto_ossp, tvb, 0, -1,
                                               "Organization Specific Slow Protocol");
    ossp_tree = proto_item_add_subtree(ossp_item, ett_ossppdu);

    proto_tree_add_item_ret_uint(ossp_tree, hf_ossp_oui, tvb, offset, OUI_SIZE, ENC_BIG_ENDIAN, &oui);
    str = uint_get_manuf_name_if_known(oui);
    col_add_fstr(pinfo->cinfo, COL_INFO, "OUI: %s", (str != NULL) ? str : "(Unknown OSSP organization)");
    offset += 3;

    /*
     * XXX - should have a dissector table here, but we don't yet
     * support OUIs as keys in dissector tables.
     */
    ossp_tvb = tvb_new_subset_remaining(tvb, offset);
    if (OUI_ITU_T == oui)
    {
       dissect_itu_ossp(ossp_tvb, pinfo, ossp_tree);
    }
/*    new Organization Specific Slow Protocols go hereafter */
#if 0
    else if (OUI_XXX == oui)
    {
        dissect_xxx_ossp(ossp_tvb, pinfo, ossp_tree);
    }
    else if (OUI_YYY == oui)
    {
        dissect_yyy_ossp(ossp_tvb, pinfo, ossp_tree);
    }
#endif

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
    uint16_t    subtype;
    proto_item *ti;
    proto_tree *itu_ossp_tree;
    tvbuff_t   *ossp_subtype_tvb;

    /* ITU-T OSSP Subtype */
    subtype = tvb_get_ntohs(tvb, 0);
    ti = proto_tree_add_item(tree, hf_itu_subtype, tvb, 0, 2, ENC_BIG_ENDIAN);

    itu_ossp_tree = proto_item_add_subtree(ti, ett_itu_ossp);

    ossp_subtype_tvb = tvb_new_subset_remaining(tvb, 2);

    switch (subtype)
    {
        case ESMC_ITU_SUBTYPE:
            dissect_esmc_pdu(ossp_subtype_tvb, pinfo, itu_ossp_tree);
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
 *    clause 11.3.1.
 */
static void
dissect_esmc_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *treex)
{
    int      offset    = 0;
    bool event_flag;
    int      ssm       = 0;
    int      essm      = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESMC");

    proto_item_append_text(treex, ": ESMC");
    {
        proto_tree *tree_a;
        tree_a = proto_item_add_subtree(treex, ett_esmc);

        { /* version */
            proto_item *item_b;
            item_b = proto_tree_add_item(tree_a, hf_esmc_version, tvb, offset, 1, ENC_BIG_ENDIAN);
            if ((tvb_get_uint8(tvb, offset) >> 4) != ESMC_VERSION_1)
            {
                expert_add_info_format(pinfo, item_b, &ei_esmc_version_compliance, "Version must be 0x%.1x claim compliance with Version 1 of this protocol", ESMC_VERSION_1);
            }
            /*stay at the same octet in tvb*/
        }
        { /* event flag */
            event_flag = ((tvb_get_uint8(tvb, offset) & 0x08) != 0);
            proto_tree_add_item(tree_a, hf_esmc_event_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            /*stay at the same octet in tvb*/
        }
        { /* reserved bits */
            proto_item *item_b;
            uint8_t reserved;
            reserved = tvb_get_uint8(tvb, offset) & 0x07;
            item_b = proto_tree_add_uint_format_value(tree_a, hf_esmc_reserved_bits, tvb, offset, 1, reserved, "0x%.2x", reserved);
            if (reserved != 0x0)
            {
                expert_add_info_format(pinfo, item_b, &ei_esmc_reserved_not_zero, "Reserved bits must be set to all zero on transmitter");
            }
            offset += 1;
        }
        { /* reserved octets */
            proto_item *item_b;
            uint32_t reserved;
            reserved = tvb_get_ntoh24(tvb, offset);
            item_b = proto_tree_add_uint_format_value(tree_a, hf_esmc_reserved_octets, tvb, offset, 3, reserved, "0x%.6x", reserved);
            if (reserved != 0x0)
            {
                expert_add_info_format(pinfo, item_b, &ei_esmc_reserved_not_zero, "Reserved octets must be set to all zero on transmitter");
            }
            offset += 3;
        }
        proto_item_append_text(treex, ", Event:%s", event_flag ?
                               "Time-critical" : "Information");

        col_add_fstr(pinfo->cinfo, COL_INFO, "Event:%s", event_flag ?
                     "Time-critical" : "Information");

        /*
         * Quality Level TLV is mandatory at fixed location.
         */
        {
            proto_item *item_b;
            uint8_t type;
            item_b = proto_tree_add_item(tree_a, hf_esmc_tlv, tvb, offset, ESMC_QL_TLV_LENGTH, ENC_NA);
            {
                proto_tree *tree_b;
                tree_b = proto_item_add_subtree(item_b, ett_esmc);
                {
                    proto_item *item_c;
                    uint16_t length;
                    uint8_t unused;

                    /* type */
                    type = tvb_get_uint8(tvb, offset);
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                    if (type != ESMC_QL_TLV_TYPE)
                    {
                        expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_type_ql_type_not_first, "TLV Type must be == 0x%.2x (QL) because QL TLV must be first in the ESMC PDU", ESMC_QL_TLV_TYPE);
                        expert_add_info(pinfo, item_c, &ei_esmc_tlv_type_decoded_as_ql_type);
                    }
                    proto_item_append_text(item_b, ", %s", val_to_str_const(type, esmc_tlv_type_vals, "Unknown"));
                    offset += 1;

                    /* length */
                    length = tvb_get_ntohs(tvb, offset);
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    if (length != ESMC_QL_TLV_LENGTH)
                    {
                        expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_length_bad, "QL TLV Length must be == 0x%.4x", ESMC_QL_TLV_LENGTH);
                        expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_type_decoded_as_ql_type, "Let's decode this TLV as if Length has valid value");
                    }
                    offset += 2;

                    /* value */
                    ssm = tvb_get_uint8(tvb, offset);
                    unused = ssm & 0xf0;
                    ssm &= 0x0f;
                    item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_ql_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
                    if (unused != 0x00)
                    {
                        expert_add_info(pinfo, item_c, &ei_esmc_tlv_ql_unused_not_zero);
                    }
                    proto_tree_add_item(tree_b, hf_esmc_tlv_ql_ssm, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                }
            }
        }

        /*
         * Extended Quality Level TLV is optional at fixed location.
         */
        if (tvb_captured_length_remaining(tvb, offset) >= ESMC_EXTENDED_QL_TLV_LENGTH)
        {
            uint8_t type;
            type = tvb_get_uint8(tvb, offset);

            if (type == ESMC_EXTENDED_QL_TLV_TYPE)
            {
                proto_item *item_b;
                item_b = proto_tree_add_item(tree_a, hf_esmc_tlv, tvb, offset, ESMC_EXTENDED_QL_TLV_LENGTH, ENC_NA);
                {
                    proto_tree *tree_b;
                    tree_b = proto_item_add_subtree(item_b, ett_esmc);
                    {
                        proto_item *item_c;
                        uint16_t length;
                        uint64_t reserved;

                        /* type */
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        if (type != ESMC_EXTENDED_QL_TLV_TYPE)
                        {
                            expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_type_not_ext_ql, "TLV Type must be == 0x%.2x (Extended QL)", ESMC_EXTENDED_QL_TLV_TYPE);
                            expert_add_info(pinfo, item_c, &ei_esmc_tlv_type_decoded_as_ext_ql);
                        }
                        proto_item_append_text(item_b, ", %s", val_to_str_const(type, esmc_tlv_type_vals, "Unknown"));
                        offset += 1;

                        /* length */
                        length = tvb_get_ntohs(tvb, offset);
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                        if (length != ESMC_EXTENDED_QL_TLV_LENGTH)
                        {
                            expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_length_bad, "Extended QL TLV Length must be == 0x%.4x", ESMC_EXTENDED_QL_TLV_LENGTH);
                            expert_add_info_format(pinfo, item_c, &ei_esmc_tlv_type_decoded_as_ext_ql, "Let's decode this TLV as if Length has valid value");
                        }
                        offset += 2;

                        /* Enhanced SSM code */
                        essm = tvb_get_uint8(tvb, offset);
                        proto_tree_add_item(tree_b, hf_esmc_tlv_ext_ql_essm, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* SyncE clockIdentity */
                        proto_tree_add_item(tree_b, hf_esmc_tlv_ext_ql_clockid, tvb, offset, 8, ENC_BIG_ENDIAN);
                        offset += 8;

                        /* Flag */
                        reserved = tvb_get_uint8(tvb, offset) & 0xfc;
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_ext_ql_flag_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                        if (reserved != 0x0)
                        {
                            expert_add_info(pinfo, item_c, &ei_esmc_reserved_not_zero);
                        }
                        proto_tree_add_item(tree_b, hf_esmc_tlv_ext_ql_flag_chain, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tree_b, hf_esmc_tlv_ext_ql_flag_mixed, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* Cascaded eEECs */
                        proto_tree_add_item(tree_b, hf_esmc_tlv_ext_ql_eeec, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* Cascaded EECs */
                        proto_tree_add_item(tree_b, hf_esmc_tlv_ext_ql_eec, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        /* Reserved */
                        reserved = tvb_get_uint40(tvb, offset, ENC_BIG_ENDIAN);
                        item_c = proto_tree_add_item(tree_b, hf_esmc_tlv_ext_ql_reserved, tvb, offset, 5, ENC_BIG_ENDIAN);
                        if (reserved != 0x0)
                        {
                            expert_add_info(pinfo, item_c, &ei_esmc_reserved_not_zero);
                        }
                        offset += 5;
                    }
                }
            }
        }
    }

    /* Derive Quality Level from SSM/eSSM based on
     * ITU-T G.8264/Y.1364 (2017)/Amd.1 (03.2018)
     * Table 11-7 and Table 11-8.
     */
    {
        const value_string *ql_vals;
        const value_string *ql_vals_short;
        const char *ql_str;
        proto_item *item_b;

        ql_vals = esmc_quality_level_vals[pref_option_network];
        ql_vals_short = esmc_quality_level_vals_short[pref_option_network];
        ql_str = try_val_to_str((essm<<8) | ssm, ql_vals);
        item_b = proto_tree_add_uint_format_value(treex, hf_esmc_quality_level, tvb, 6, offset-6,
            (essm<<8) | ssm, "%s", (NULL != ql_str) ? ql_str : "Unknown Quality Level");
        proto_item_set_generated(item_b);
        if (NULL == ql_str)
        {
            expert_add_info(pinfo, item_b, &ei_esmc_quality_level_invalid);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
            val_to_str_const((essm<<8) | ssm, ql_vals_short, "Unknown Quality Level"));
    }

    { /* padding */
        int padding_size;
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
                proto_item_append_text(item_b, ", %d %s%s", padding_size,
                    "octet", plurality(padding_size,"","s"));
                {
                    proto_tree* tree_b;
                    tree_b = proto_item_add_subtree(item_b, ett_esmc);
                    call_data_dissector(tvb_next, pinfo, tree_b);
                }
            }
        }
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
            FT_UINT24,    BASE_OUI,    NULL,    0,
            "IEEE assigned Organizational Unique Identifier", HFILL }},

        { &hf_itu_subtype,
          { "ITU-T OSSP Subtype",    "ossp.itu.subtype",
            FT_UINT16,    BASE_HEX,    NULL,    0,
            "Subtype assigned by the ITU-T", HFILL }},

        { &hf_esmc_version,
          { "Version",    "ossp.esmc.version",
            FT_UINT8,    BASE_HEX,    NULL,    0xf0,
            "Version of ITU-T OSSP frame format", HFILL }},

        { &hf_esmc_event_flag,
          { "Event Flag",    "ossp.esmc.event_flag",
            FT_BOOLEAN,    8,    TFS(&esmc_event_flag_tfs),    0x08,
            "This bit distinguishes the critical, time sensitive behaviour of the "
            "ESMC Event PDU from the ESMC Information PDU", HFILL }},

        { &hf_esmc_reserved_bits,
          { "Reserved",    "ossp.esmc.reserved_bits",
            FT_UINT8,    BASE_HEX,    NULL,    0x07,
            "Reserved. Set to all zero at the transmitter and ignored by the receiver", HFILL }},

        { &hf_esmc_reserved_octets,
          { "Reserved",    "ossp.esmc.reserved",
            FT_UINT24,    BASE_HEX,    NULL,    0,
            "Reserved. Set to all zero at the transmitter and ignored by the receiver", HFILL }},

        { &hf_esmc_tlv,
          { "ESMC TLV",    "ossp.esmc.tlv",
            FT_NONE,    BASE_NONE,    NULL,    0,
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

        { &hf_esmc_tlv_ql_ssm,
          { "SSM Code",    "ossp.esmc.tlv_ql_ssm",
            FT_UINT8,    BASE_HEX,    NULL,    0x0f,
            NULL, HFILL }},

        { &hf_esmc_tlv_ext_ql_essm,
          { "Enhanced SSM Code",    "ossp.esmc.tlv_ext_ql_essm",
            FT_UINT8,    BASE_HEX,    NULL,    0,
            NULL, HFILL }},

        { &hf_esmc_tlv_ext_ql_clockid,
          { "SyncE clockID",    "ossp.esmc.tlv_ext_ql_clockid",
            FT_UINT64,    BASE_HEX,    NULL,    0,
            NULL, HFILL }},

        { &hf_esmc_tlv_ext_ql_flag_reserved,
          { "Reserved",    "ossp.esmc.tlv_ext_ql_flag_reserved",
            FT_UINT8,    BASE_HEX,    NULL,    0xfc,
            "Reserved. Set to all zero at the transmitter and ignored by the receiver", HFILL }},

        { &hf_esmc_tlv_ext_ql_flag_chain,
          { "Partial chain",    "ossp.esmc.tlv_ext_ql_flag_chain",
            FT_BOOLEAN,    8,    TFS(&tfs_yes_no),    0x02,
            "Whether or not the TLV has been generated in the middle of the chain", HFILL }},

        { &hf_esmc_tlv_ext_ql_flag_mixed,
          { "Mixed EEC/eEEC clocks",    "ossp.esmc.tlv_ext_ql_flag_mixed",
            FT_BOOLEAN,    8,    TFS(&tfs_yes_no),    0x01,
            "Whether of not there is at least one non-eEEC clock in the chain", HFILL }},

        { &hf_esmc_tlv_ext_ql_eeec,
          { "Cascaded eEECs",    "ossp.esmc.tlv_ext_ql_eeec",
            FT_UINT8,    BASE_DEC,    NULL,    0,
            "Number of cascaded eEECs from nearest SSU/PRC", HFILL }},

        { &hf_esmc_tlv_ext_ql_eec,
          { "Cascaded EECs",    "ossp.esmc.tlv_ext_ql_eec",
            FT_UINT8,    BASE_DEC,    NULL,    0,
            "Number of cascaded EECs from nearest SSU/PRC", HFILL }},

        { &hf_esmc_tlv_ext_ql_reserved,
          { "Reserved",    "ossp.esmc.tlv_ext_ql_reserved",
            FT_UINT40,     BASE_HEX,    NULL,    0,
            "Reserved. Set to all zero at the transmitter and ignored by the receiver", HFILL }},

        { &hf_esmc_quality_level,
          { "Quality Level",    "ossp.esmc.ql",
            FT_UINT16,    BASE_HEX,    NULL,    0,
            NULL, HFILL }},

        { &hf_esmc_padding,
          { "Padding",    "ossp.esmc.padding",
            FT_BYTES,     BASE_NONE,    NULL,    0x0,
            "This field contains necessary padding to achieve the minimum frame size of 64 bytes at least", HFILL }},
    };

    /* Setup protocol subtree array */

    static int *ett[] = {
        &ett_esmc,
        &ett_ossppdu,
        &ett_itu_ossp
    };

    /* Setup expert info array */

    static ei_register_info ei[] = {
        { &ei_esmc_version_compliance, { "ossp.esmc.version.compliance", PI_MALFORMED, PI_ERROR, "Version must claim compliance with Version 1 of this protocol", EXPFILL }},
        { &ei_esmc_tlv_type_ql_type_not_first, { "ossp.esmc.tlv_type.ql_type_not_first", PI_MALFORMED, PI_ERROR, "TLV Type must be QL because QL TLV must be first in the ESMC PDU", EXPFILL }},
        { &ei_esmc_tlv_type_decoded_as_ql_type, { "ossp.esmc.tlv_type.decoded_as_ql_type", PI_UNDECODED, PI_NOTE, "Let's decode as if this is QL TLV", EXPFILL }},
        { &ei_esmc_tlv_length_bad, { "ossp.esmc.tlv_length.bad", PI_MALFORMED, PI_ERROR, "QL TLV Length must be X", EXPFILL }},
        { &ei_esmc_tlv_ql_unused_not_zero, { "ossp.esmc.tlv_ql_unused.not_zero", PI_MALFORMED, PI_WARN, "Unused bits of TLV must be all zeroes", EXPFILL }},
        { &ei_esmc_quality_level_invalid, { "ossp.esmc.ql.invalid", PI_UNDECODED, PI_WARN, "Invalid SSM message, unknown QL code", EXPFILL }},
        { &ei_esmc_tlv_type_not_ext_ql, { "ossp.esmc.tlv_type.not_ext_ql", PI_MALFORMED, PI_ERROR, "TLV Type must be == Extended QL", EXPFILL }},
        { &ei_esmc_tlv_type_decoded_as_ext_ql, { "ossp.esmc.tlv_type.decoded_as_ext_ql", PI_UNDECODED, PI_NOTE, "Let's decode as if this is Extended QL TLV", EXPFILL }},
        { &ei_esmc_reserved_not_zero, { "ossp.esmc.reserved_bits_must_be_set_to_all_zero", PI_PROTOCOL, PI_WARN, "Reserved bits must be set to all zero", EXPFILL }},
    };

    expert_module_t *expert_ossp;

    module_t *prefs_ossp;

    /* Register the protocol name and description */

    proto_ossp = proto_register_protocol("OSSP", "Organization Specific Slow Protocol", "ossp");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_ossp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the exert items */

    expert_ossp = expert_register_protocol(proto_ossp);
    expert_register_field_array(expert_ossp, ei, array_length(ei));

    /* Register the preferences */

    prefs_ossp = prefs_register_protocol(proto_ossp, NULL);
    prefs_register_enum_preference(prefs_ossp, "option_network",
        "Regional option", "Select the option of the network to interpret the Quality Level for",
        &pref_option_network, pref_option_network_vals, true);

    /* Register the dissector */

    ossp_handle = register_dissector("ossp", dissect_ossp_pdu, proto_ossp);
}

void
proto_reg_handoff_ossp(void)
{
    dissector_add_uint("slow.subtype", OSSP_SUBTYPE, ossp_handle);
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
