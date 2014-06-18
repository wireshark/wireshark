/* packet-mpls.c
 * Routines for MPLS data packet disassembly
 * RFC 3032
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * (c) Copyright 2006, _FF_ Francesco Fondelli <francesco.fondelli@gmail.com>
 *     - added MPLS OAM support, ITU-T Y.1711
 *     - PW Associated Channel Header dissection as per RFC 4385
 *     - PW MPLS Control Word dissection as per RFC 4385
 *     - mpls subdissector table indexed by label value
 *     - enhanced "what's past last mpls label?" heuristic
 *
 * (c) Copyright 2011, Shobhank Sharma <ssharma5@ncsu.edu>
 *     - Removed some mpls preferences which are no longer relevant/needed like
 *       decode PWAC payloads as PPP traffic and assume all channel types except
 *       0x21 are raw BFD.
 *     - MPLS extension from PW-ACH to MPLS Generic Associated Channel as per RFC 5586
 *     - Updated Pseudowire Associated Channel Types as per http://www.iana.org/assignments/pwe3-parameters
 *
 * (c) Copyright 2011, Jaihari Kalijanakiraman <jaiharik@ipinfusion.com>
 *                     Krishnamurthy Mayya <krishnamurthy.mayya@ipinfusion.com>
 *                     Nikitha Malgi       <malgi.nikitha@ipinfusion.com>
 *     - Identification of BFD CC, BFD CV and ON-Demand CV ACH types as per RFC 6428, RFC 6426
 *       respectively and the corresponding decoding of messages
 *     - Decoding support for MPLS-TP Lock Instruct as per RFC 6435
 *     - Decoding support for MPLS-TP Fault-Management as per RFC 6427
 *
 * (c) Copyright 2012, Aditya Ambadkar and Diana Chris <arambadk,dvchris@ncsu.edu>
 *   -  Added preference to select BOS label as flowlabel as per RFC 6391
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

#include <epan/ppptypes.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/decode_as.h>

#include "packet-ppp.h"
#include "packet-mpls.h"
#include "packet-pw-common.h"
#include "packet-bfd.h"

void proto_register_mpls(void);
void proto_reg_handoff_mpls(void);

/* As per RFC 6428 http://tools.ietf.org/html/rfc6428, Section: 3.3 */
#define ACH_TYPE_BFD_CC               0x0022
#define ACH_TYPE_BFD_CV               0x0023
/* As RFC 6426:http://tools.ietf.org/html/rfc6426, Section: 7.4 */
#define ACH_TYPE_ONDEMAND_CV          0x0025

static gint proto_mpls = -1;
static gint proto_pw_ach = -1;
static gint proto_pw_mcw = -1;

static gint ett_mpls = -1;
static gint ett_mpls_pw_ach = -1;
static gint ett_mpls_pw_mcw = -1;
static char PW_ACH[50] = "PW Associated Channel Header";

const value_string special_labels[] = {
    {MPLS_LABEL_IP4_EXPLICIT_NULL,   "IPv4 Explicit-Null"},
    {MPLS_LABEL_ROUTER_ALERT,        "Router Alert"},
    {MPLS_LABEL_IP6_EXPLICIT_NULL,   "IPv6 Explicit-Null"},
    {MPLS_LABEL_IMPLICIT_NULL,       "Implicit-Null"},
    {MPLS_LABEL_OAM_ALERT,           "OAM Alert"},
    {MPLS_LABEL_GACH,                "Generic Associated Channel Label (GAL)"},
    {0, NULL }
};

static dissector_handle_t dissector_data;
static dissector_handle_t dissector_ipv6;
static dissector_handle_t dissector_ip;
static dissector_handle_t dissector_bfd;
static dissector_handle_t dissector_mpls_pm_dlm;
static dissector_handle_t dissector_mpls_pm_ilm;
static dissector_handle_t dissector_mpls_pm_dm;
static dissector_handle_t dissector_mpls_pm_dlm_dm;
static dissector_handle_t dissector_mpls_pm_ilm_dm;
static dissector_handle_t dissector_mpls_psc;
static dissector_handle_t dissector_mplstp_lock;
static dissector_handle_t dissector_mplstp_fm;
static dissector_handle_t dissector_pw_oam;
static dissector_handle_t dissector_pw_eth_heuristic;
static dissector_handle_t dissector_pw_fr;
static dissector_handle_t dissector_pw_hdlc_nocw_fr;
static dissector_handle_t dissector_pw_hdlc_nocw_hdlc_ppp;
static dissector_handle_t dissector_pw_eth_cw;
static dissector_handle_t dissector_pw_eth_nocw;
static dissector_handle_t dissector_pw_satop;
static dissector_handle_t dissector_itdm;
static dissector_handle_t dissector_mpls_pw_atm_n1_cw;
static dissector_handle_t dissector_mpls_pw_atm_n1_nocw;
static dissector_handle_t dissector_mpls_pw_atm_11_aal5pdu;
static dissector_handle_t dissector_mpls_pw_atm_aal5_sdu;
static dissector_handle_t dissector_pw_cesopsn;

enum mpls_default_dissector_t {
    MDD_PW_ETH_HEUR = 0
    ,MDD_MPLS_PW_ETH_CW
    ,MDD_MPLS_PW_ETH_NOCW
    ,MDD_PW_SATOP
    ,MDD_PW_CESOPSN
    ,MDD_MPLS_PW_FR_DLCI
    ,MDD_MPLS_PW_HDLC_NOCW_FRPORT
    ,MDD_MPLS_PW_HDLC_NOCW_HDLC_PPP
    ,MDD_MPLS_PW_GENERIC
    ,MDD_ITDM
    ,MDD_MPLS_PW_ATM_N1_CW
    ,MDD_MPLS_PW_ATM_N1_NOCW
    ,MDD_MPLS_PW_ATM_11_OR_AAL5_PDU
    ,MDD_MPLS_PW_ATM_AAL5_SDU
};

/* TODO the content of mpls_default_payload menu
 * should be automatically built like mpls "decode as..." menu;
 * this way, mpls_default_payload will be automatically filled up when
 * new mpls-specific dissector added.
 */
static const enum_val_t mpls_default_payload_defs[] = {
    {
        "pw satop"
        ,pwc_longname_pw_satop
        ,MDD_PW_SATOP
    },
    {
        "pw cesopsn"
        ,pwc_longname_pw_cesopsn
        ,MDD_PW_CESOPSN
    },
    {
        "mpls pw ethernet heuristic"
        ,"Ethernet MPLS PW (CW is heuristically detected)"
        ,MDD_PW_ETH_HEUR
    },
    {
        "mpls pw ethernet cw"
        ,"Ethernet MPLS PW (with CW)"
        ,MDD_MPLS_PW_ETH_CW
    },
    {
        "mpls pw ethernet no_cw"
        ,"Ethernet MPLS PW (no CW, early implementations)"
        ,MDD_MPLS_PW_ETH_NOCW
    },
    {
        "mpls pw generic cw"
        ,"Generic MPLS PW (with Generic/Preferred MPLS CW)"
        ,MDD_MPLS_PW_GENERIC
    },
    {
        "mpls pw fr dlci"
        ,"Frame relay DLCI MPLS PW"
        ,MDD_MPLS_PW_FR_DLCI
    },
    {
        "mpls pw hdlc no_cw fr_port"
        ,"HDLC MPLS PW (no CW), FR Port mode"
        ,MDD_MPLS_PW_HDLC_NOCW_FRPORT
    },
    {
        "mpls pw hdlc no_cw hdlc payload_ppp"
        ,"HDLC MPLS PW (no CW), HDLC mode, PPP payload"
        ,MDD_MPLS_PW_HDLC_NOCW_HDLC_PPP
    },
    {
        "itdm"
        ,"Internal TDM"
        ,MDD_ITDM
    },
    {
        "mpls pw atm n_to_one cw"
        ,pwc_longname_pw_atm_n1_cw
        ,MDD_MPLS_PW_ATM_N1_CW
    },
    {
        "mpls pw atm n_to_one no_cw"
        ,pwc_longname_pw_atm_n1_nocw
        ,MDD_MPLS_PW_ATM_N1_NOCW
    },
    {
        "mpls pw atm one_to_one or aal5_pdu"
        ,pwc_longname_pw_atm_11_or_aal5_pdu
        ,MDD_MPLS_PW_ATM_11_OR_AAL5_PDU
    },
    {
        "mpls pw atm aal5_sdu"
        ,pwc_longname_pw_atm_aal5_sdu
        ,MDD_MPLS_PW_ATM_AAL5_SDU
    },
    {
        NULL
        ,NULL
        ,-1
    }
};

/* For RFC6391 - Flow aware transport of pseudowire over a mpls PSN*/
static gboolean mpls_bos_flowlabel = FALSE;

static int hf_mpls_label = -1;
static int hf_mpls_label_special = -1;
static int hf_mpls_exp = -1;
static int hf_mpls_bos = -1;
static int hf_mpls_ttl = -1;

static gint mpls_default_payload = MDD_PW_ETH_HEUR;

static int hf_mpls_pw_ach_ver = -1;
static int hf_mpls_pw_ach_res = -1;
static int hf_mpls_pw_ach_channel_type = -1;

static int hf_mpls_pw_mcw_flags = -1;
static int hf_mpls_pw_mcw_length = -1;
static int hf_mpls_pw_mcw_sequence_number = -1;

#if 0 /*not used yet*/
/*
 * MPLS PW types
 * http://www.iana.org/assignments/pwe3-parameters
 */
static const value_string mpls_pw_types[] = {
    { 0x0001, "Frame Relay DLCI ( Martini Mode )"              },
    { 0x0002, "ATM AAL5 SDU VCC transport"                     },
    { 0x0003, "ATM transparent cell transport"                 },
    { 0x0004, "Ethernet Tagged Mode"                           },
    { 0x0005, "Ethernet"                                       },
    { 0x0006, "HDLC"                                           },
    { 0x0007, "PPP"                                            },
    { 0x0008, "SONET/SDH Circuit Emulation Service Over MPLS"  },
    { 0x0009, "ATM n-to-one VCC cell transport"                },
    { 0x000A, "ATM n-to-one VPC cell transport"                },
    { 0x000B, "IP Layer2 Transport"                            },
    { 0x000C, "ATM one-to-one VCC Cell Mode"                   },
    { 0x000D, "ATM one-to-one VPC Cell Mode"                   },
    { 0x000E, "ATM AAL5 PDU VCC transport"                     },
    { 0x000F, "Frame-Relay Port mode"                          },
    { 0x0010, "SONET/SDH Circuit Emulation over Packet"        },
    { 0x0011, "Structure-agnostic E1 over Packet"              },
    { 0x0012, "Structure-agnostic T1 (DS1) over Packet"        },
    { 0x0013, "Structure-agnostic E3 over Packet"              },
    { 0x0014, "Structure-agnostic T3 (DS3) over Packet"        },
    { 0x0015, "CESoPSN basic mode"                             },
    { 0x0016, "TDMoIP AAL1 Mode"                               },
    { 0x0017, "CESoPSN TDM with CAS"                           },
    { 0x0018, "TDMoIP AAL2 Mode"                               },
    { 0x0019, "Frame Relay DLCI"                               },
    { 0x001A, "ROHC Transport Header-compressed Packets"       },/*[RFC4995][RFC4901]*/
    { 0x001B, "ECRTP Transport Header-compressed Packets"      },/*[RFC3545][RFC4901]*/
    { 0x001C, "IPHC Transport Header-compressed Packets"       },/*[RFC2507][RFC4901]*/
    { 0x001D, "cRTP Transport Header-compressed Packets"       },/*[RFC2508][RFC4901]*/
    { 0x001E, "ATM VP Virtual Trunk"                           },/*[MFA9]*/
    { 0x001F, "Reserved"                                       },/*[Bryant]  2008-04-17*/
    { 0, NULL }
};
static value_string_ext mpls_pw_types_ext = VALUE_STRING_EXT_INIT(mpls_pw_types);
#endif

/*
 * MPLS PW Associated Channel Types
 * as per http://www.iana.org/assignments/pwe3-parameters
 * and http://tools.ietf.org/html/draft-ietf-pwe3-vccv-bfd-05 clause 3.2
 */
static const value_string mpls_pwac_types[] = {
    { 0x0000, "Reserved"},
    { 0x0001, "Management Communication Channel (MCC)"},
    { 0x0002, "Signaling Communication Channel (SCC)"},
    { 0x0007, "BFD Control, PW-ACH-encapsulated (BFD Without IP/UDP Headers)" },
    { 0x000A, "MPLS Direct Loss Measurement (DLM)"},
    { 0x000B, "MPLS Inferred Loss Measurement (ILM)"},
    { 0x000C, "MPLS Delay Measurement (DM)"},
    { 0x000D, "MPLS Direct Loss and Delay Measurement (DLM+DM)"},
    { 0x000E, "MPLS Inferred Loss and Delay Measurement (ILM+DM)"},
    { 0x0021, "IPv4 packet" },
    { 0x0022, "MPLS-TP CC message"},
    { 0x0023, "MPLS-TP CV message"},
    { 0x0024, "Protection State Coordination Protocol (PSC)"},
    { 0x0025, "On-Demand CV"},
    { 0x0026, "LI"},
    { 0x0027, "Pseudo-Wire OAM"},
    { 0x0057, "IPv6 packet" },
    { 0x0058, "Fault OAM"},
    { 0x7FF8, "Reserved for Experimental Use"},
    { 0x7FF9, "Reserved for Experimental Use"},
    { 0x7FFA, "Reserved for Experimental Use"},
    { 0x7FFB, "Reserved for Experimental Use"},
    { 0x7FFC, "Reserved for Experimental Use"},
    { 0x7FFD, "Reserved for Experimental Use"},
    { 0x7FFE, "Reserved for Experimental Use"},
    { 0x7FFF, "Reserved for Experimental Use"},
    { 0, NULL }
};
static value_string_ext mpls_pwac_types_ext = VALUE_STRING_EXT_INIT(mpls_pwac_types);

static dissector_table_t mpls_subdissector_table;

static void mpls_prompt(packet_info *pinfo, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Data after label %u as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_mpls, 0)));
}

static gpointer mpls_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_mpls, 0);
}

/*
 * Given a 4-byte MPLS label starting at offset "offset", in tvbuff "tvb",
 * decode it.
 * Return the label in "label", EXP bits in "exp",
 * bottom_of_stack in "bos", and TTL in "ttl"
 */
void
decode_mpls_label(tvbuff_t *tvb, int offset,
                       guint32  *label, guint8 *exp,
                       guint8   *bos, guint8 *ttl)
{
    guint8 octet0 = tvb_get_guint8(tvb, offset+0);
    guint8 octet1 = tvb_get_guint8(tvb, offset+1);
    guint8 octet2 = tvb_get_guint8(tvb, offset+2);

    *label = (octet0 << 12) + (octet1 << 4) + ((octet2 >> 4) & 0xff);
    *exp = (octet2 >> 1) & 0x7;
    *bos = (octet2 & 0x1);
    *ttl = tvb_get_guint8(tvb, offset+3);
}

/*
 * FF: PW Associated Channel Header dissection as per RFC 4385.
 */
static void
dissect_pw_ach(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t   *next_tvb;
    guint16     channel_type;

    if (tvb_reported_length_remaining(tvb, 0) < 4) {
        proto_tree_add_text(tree, tvb, 0, -1, "Error processing Message");
        return;
    }

    channel_type = tvb_get_ntohs(tvb, 2);

    if (tree) {
        proto_tree *mpls_pw_ach_tree;
        proto_item *ti;
        guint16     res;

        ti = proto_tree_add_item(tree, proto_pw_ach, tvb, 0, 4, ENC_NA);
        mpls_pw_ach_tree = proto_item_add_subtree(ti, ett_mpls_pw_ach);

        proto_tree_add_item(mpls_pw_ach_tree, hf_mpls_pw_ach_ver,
                            tvb, 0, 1, ENC_BIG_ENDIAN);

        res = tvb_get_guint8(tvb, 1);
        ti = proto_tree_add_uint(mpls_pw_ach_tree, hf_mpls_pw_ach_res,
                                        tvb, 1, 1, res);
        if (res != 0)
            proto_tree_add_text(mpls_pw_ach_tree, tvb, 1, 1,
                "Error: this byte is reserved and must be 0");
        else
            PROTO_ITEM_SET_HIDDEN(ti);

        proto_tree_add_uint_format_value(mpls_pw_ach_tree, hf_mpls_pw_ach_channel_type,
                                         tvb, 2, 2, channel_type,
                                         "%s (0x%04x)",
                                         val_to_str_ext_const(channel_type, &mpls_pwac_types_ext, "Unknown"),
                                         channel_type);

    } /* if (tree) */

    next_tvb     = tvb_new_subset_remaining(tvb, 4);

    switch (channel_type) {
        case ACH_TYPE_BFD_CC:
            call_dissector(dissector_bfd, next_tvb, pinfo, tree);  /* bfd_control() */
            break;

        case ACH_TYPE_BFD_CV:
            call_dissector(dissector_bfd, next_tvb, pinfo, tree);  /* bfd_control() */
            dissect_bfd_mep(next_tvb, tree, 0);
            break;

        case ACH_TYPE_ONDEMAND_CV:
            dissect_mpls_echo(next_tvb, pinfo, tree, NULL);
            break;

        case 0x21:   /* IPv4, RFC4385 clause 6. */
            call_dissector(dissector_ip, next_tvb, pinfo, tree);
            break;

        case 0x7:    /* PWACH-encapsulated BFD, RFC 5885 */
            call_dissector(dissector_bfd, next_tvb, pinfo, tree);
            break;

        case 0x57:   /* IPv6, RFC4385 clause 6. */
            call_dissector(dissector_ipv6, next_tvb, pinfo, tree);
            break;

        case 0x000A: /* FF: MPLS PM, RFC 6374, DLM */
            call_dissector(dissector_mpls_pm_dlm, next_tvb, pinfo, tree);
            break;

        case 0x000B: /* FF: MPLS PM, RFC 6374, ILM */
            call_dissector(dissector_mpls_pm_ilm, next_tvb, pinfo, tree);
            break;

        case 0x000C: /* FF: MPLS PM, RFC 6374, DM */
            call_dissector(dissector_mpls_pm_dm, next_tvb, pinfo, tree);
            break;

        case 0x000D: /* FF: MPLS PM, RFC 6374, DLM+DM */
            call_dissector(dissector_mpls_pm_dlm_dm, next_tvb, pinfo, tree);
            break;

        case 0x000E: /* FF: MPLS PM, RFC 6374, ILM+DM */
            call_dissector(dissector_mpls_pm_ilm_dm, next_tvb, pinfo, tree);
            break;

        case 0x0024: /* FF: PSC, RFC 6378 */
            call_dissector(dissector_mpls_psc, next_tvb, pinfo, tree);
            break;

        case 0x0026: /* KM: MPLSTP LOCK, RFC 6435 */
            call_dissector(dissector_mplstp_lock, next_tvb, pinfo, tree);
            break;

        case 0x0027: /* KM: MPLSTP PW-OAM, RFC 6478 */
            call_dissector(dissector_pw_oam, next_tvb, pinfo, tree);
            break;

        case 0x0058: /* KM: MPLSTP FM, RFC 6427 */
            call_dissector(dissector_mplstp_fm, next_tvb, pinfo, tree);
            break;

        default:
            call_dissector(dissector_data, next_tvb, pinfo, tree);
            break;
    }
}

gboolean
dissect_try_cw_first_nibble( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
    guint8 nibble;

    nibble = (tvb_get_guint8(tvb, 0 ) >> 4) & 0x0F;
    switch ( nibble )
    {
        case 6:
            call_dissector(dissector_ipv6, tvb, pinfo, tree);
            return TRUE;
        case 4:
            call_dissector(dissector_ip, tvb, pinfo, tree);
            return TRUE;
        case 1:
            dissect_pw_ach(tvb, pinfo, tree );
            return TRUE;
        default:
            break;
    }
    return FALSE;
}

/*
 * FF: Generic/Preferred PW MPLS Control Word dissection as per RFC 4385.
 */
static void
dissect_pw_mcw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *next_tvb;

    if (tvb_reported_length_remaining(tvb, 0) < 4) {
        proto_tree_add_text(tree, tvb, 0, -1, "Error processing Message");
        return;
    }

    if ( dissect_try_cw_first_nibble( tvb, pinfo, tree ))
       return;

    if (tree) {
        proto_tree  *mpls_pw_mcw_tree;
        proto_item  *ti;

        ti = proto_tree_add_item(tree, proto_pw_mcw, tvb, 0, 4, ENC_NA);
        mpls_pw_mcw_tree = proto_item_add_subtree(ti, ett_mpls_pw_mcw);

        proto_tree_add_item(mpls_pw_mcw_tree, hf_mpls_pw_mcw_flags,
                            tvb, 0, 2, ENC_BIG_ENDIAN);
        /* bits 4 to 7 and FRG bits are displayed together */
        proto_tree_add_item(mpls_pw_mcw_tree, hf_mpls_pw_mcw_length,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mpls_pw_mcw_tree, hf_mpls_pw_mcw_sequence_number,
                            tvb, 2, 2, ENC_BIG_ENDIAN);
    }
    next_tvb = tvb_new_subset_remaining(tvb, 4);
    call_dissector(dissector_data, next_tvb, pinfo, tree);
}

static void
dissect_mpls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int       offset = 0;
    guint32   label  = MPLS_LABEL_INVALID;
    guint8    exp;
    guint8    bos;
    guint8    ttl;
    tvbuff_t *next_tvb;
    gboolean  found;
    guint8    first_nibble;
    struct mplsinfo mplsinfo;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPLS");
    col_set_str(pinfo->cinfo, COL_INFO, "MPLS Label Switched Packet");

    /* Ensure structure is initialized */
    memset(&mplsinfo, 0, sizeof(struct mplsinfo));

    /* Start Decoding Here. */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {

        decode_mpls_label(tvb, offset, &label, &exp, &bos, &ttl);

        /*
         * FF: export (last shim in stack) info to subdissectors and
         * update pinfo
         */
        mplsinfo.label = label;
        p_add_proto_data(pinfo->pool, pinfo, proto_mpls, 0, GUINT_TO_POINTER(label));
        mplsinfo.exp   = exp;
        mplsinfo.bos   = bos;
        mplsinfo.ttl   = ttl;

        if (tree) {
            proto_item *ti;
            proto_tree *mpls_tree;

            ti = proto_tree_add_item(tree, proto_mpls, tvb, offset, 4, ENC_NA);
            mpls_tree = proto_item_add_subtree(ti, ett_mpls);

            if (mpls_bos_flowlabel) {
                proto_item_append_text(ti, ", Label: %u (Flow Label)", label);
            } else {
                proto_item_append_text(ti, ", Label: %u", label);
            }
            if (label <= MPLS_LABEL_MAX_RESERVED){
                proto_tree_add_item(mpls_tree, hf_mpls_label_special, tvb,
                                    offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(ti, " (%s)",
                                       val_to_str_const(label, special_labels, "Reserved - Unknown"));
            } else {
                proto_tree_add_item(mpls_tree, hf_mpls_label, tvb, offset, 4,
                                    ENC_BIG_ENDIAN);
            }

            proto_tree_add_item(mpls_tree, hf_mpls_exp, tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", Exp: %u", exp);

            proto_tree_add_item(mpls_tree, hf_mpls_bos , tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", S: %u", bos);

            proto_tree_add_item(mpls_tree, hf_mpls_ttl, tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", TTL: %u", ttl);
        }

        offset += 4;

        if ((label == MPLS_LABEL_GACH) && !bos) {
            proto_tree_add_text(tree, tvb, 0, -1, "Invalid Label");
        }

        if ((label == MPLS_LABEL_GACH) && bos) {
            g_strlcpy(PW_ACH, "Generic Associated Channel Header",50);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            dissect_pw_ach( next_tvb, pinfo, tree );
            return;
        }
        else
            g_strlcpy(PW_ACH, "PW Associated Channel Header",50);

        if (bos)
            break;
    }

    first_nibble = (tvb_get_guint8(tvb, offset) >> 4) & 0x0F;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    /* 1) explicit label-to-dissector binding ? */
    found = dissector_try_uint_new(mpls_subdissector_table, label,
                               next_tvb, pinfo, tree, FALSE, &mplsinfo);
    if (found)
        return;

    /* 2) use the 1st nibble logic (see BCP 4928, RFC 4385 and 5586) */
    if (first_nibble == 4) {
        call_dissector(dissector_ip, next_tvb, pinfo, tree);
        /* IP dissector may reduce the length of the tvb.
           We need to do the same, so that ethernet trailer is detected. */
        set_actual_length(tvb, offset+tvb_reported_length(next_tvb));
        return;
    } else if (first_nibble == 6) {
        call_dissector(dissector_ipv6, next_tvb, pinfo, tree);
        /* IPv6 dissector may reduce the length of the tvb.
           We need to do the same, so that ethernet trailer is detected. */
        set_actual_length(tvb, offset+tvb_reported_length(next_tvb));
        return;
    } else if (first_nibble == 1) {
        dissect_pw_ach(next_tvb, pinfo, tree);
        return;
    } else if (first_nibble == 0) {
        /*
         * FF: it should be a PW with a CW but... it's not
         * guaranteed (e.g. an Ethernet PW w/o CW and a DA MAC
         * address like 00:xx:xx:xx:xx:xx).  So, let the user and
         * eventually any further PW heuristics decide.
         */
    }

    /* 3) use the mpls_default_payload info from user */
    switch (mpls_default_payload) {
        case MDD_PW_SATOP:
            call_dissector(dissector_pw_satop, next_tvb, pinfo, tree);
            break;
        case MDD_PW_CESOPSN:
            call_dissector(dissector_pw_cesopsn, next_tvb, pinfo, tree);
            break;
        case MDD_PW_ETH_HEUR:
            call_dissector(dissector_pw_eth_heuristic, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_ETH_CW:
            call_dissector(dissector_pw_eth_cw, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_ETH_NOCW:
            call_dissector(dissector_pw_eth_nocw, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_FR_DLCI:
            call_dissector(dissector_pw_fr, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_HDLC_NOCW_FRPORT:
            call_dissector(dissector_pw_hdlc_nocw_fr, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_HDLC_NOCW_HDLC_PPP:
            call_dissector(dissector_pw_hdlc_nocw_hdlc_ppp,next_tvb, pinfo, tree);
            break;
        case MDD_ITDM:
            call_dissector(dissector_itdm, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_ATM_N1_CW:
            call_dissector(dissector_mpls_pw_atm_n1_cw, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_ATM_N1_NOCW:
            call_dissector(dissector_mpls_pw_atm_n1_nocw, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_ATM_11_OR_AAL5_PDU:
            call_dissector(dissector_mpls_pw_atm_11_aal5pdu, next_tvb, pinfo, tree);
            break;
        case MDD_MPLS_PW_ATM_AAL5_SDU:
            call_dissector(dissector_mpls_pw_atm_aal5_sdu, next_tvb, pinfo, tree);
            break;
        default: /* fallthrough */
        case MDD_MPLS_PW_GENERIC:
            dissect_pw_mcw(next_tvb, pinfo, tree);
            break;
    }
}

void
proto_register_mpls(void)
{
    static hf_register_info mplsf_info[] = {

        /* MPLS header fields */
        {&hf_mpls_label,
         {"MPLS Label", "mpls.label",
          FT_UINT32, BASE_DEC, NULL, 0xFFFFF000,
          NULL, HFILL }
        },

        {&hf_mpls_label_special,
         {"MPLS Label", "mpls.label",
          FT_UINT32, BASE_DEC, VALS(special_labels), 0xFFFFF000,
          NULL, HFILL }
        },

        {&hf_mpls_exp,
         {"MPLS Experimental Bits", "mpls.exp",
          FT_UINT32, BASE_DEC, NULL, 0x00000E00,
          NULL, HFILL }
        },

        {&hf_mpls_bos,
         {"MPLS Bottom Of Label Stack", "mpls.bottom",
          FT_UINT32, BASE_DEC, NULL, 0x00000100,
          NULL, HFILL }
        },

        {&hf_mpls_ttl,
         {"MPLS TTL", "mpls.ttl",
          FT_UINT32, BASE_DEC, NULL, 0x0000000FF,
          NULL, HFILL }
        },

        /* PW Associated Channel Header fields */
        {&hf_mpls_pw_ach_ver,
         {"Channel Version", "pwach.ver",
          FT_UINT8, BASE_DEC, NULL, 0x0F,
          "PW Associated Channel Version", HFILL }
        },

        {&hf_mpls_pw_ach_res,
         {"Reserved", "pwach.res",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
        },

        {&hf_mpls_pw_ach_channel_type,
         {"Channel Type", "pwach.channel_type",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          "PW Associated Channel Type", HFILL }
        },

        /* Generic/Preferred PW MPLS Control Word fields */
        {&hf_mpls_pw_mcw_flags,
         {"Flags", "pwmcw.flags",
          FT_UINT8, BASE_HEX, NULL, 0x0FC0,
          "Generic/Preferred PW MPLS Control Word Flags", HFILL }
        },

        {&hf_mpls_pw_mcw_length,
         {"Length", "pwmcw.length",
          FT_UINT8, BASE_DEC, NULL, 0x3F,
          "Generic/Preferred PW MPLS Control Word Length", HFILL }
        },

        {&hf_mpls_pw_mcw_sequence_number,
         {"Sequence Number", "pwmcw.sequence_number",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Generic/Preferred PW MPLS Control Word Sequence Number", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_mpls,
        &ett_mpls_pw_ach,
        &ett_mpls_pw_mcw,
    };

    /* Decode As handling */
    static build_valid_func mpls_da_build_value[1] = {mpls_value};
    static decode_as_value_t mpls_da_values = {mpls_prompt, 1, mpls_da_build_value};
    static decode_as_t mpls_da = {"mpls", "MPLS", "mpls.label", 1, 0, &mpls_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    module_t * module_mpls;

    /* FF: mpls subdissector table is indexed by label */
    mpls_subdissector_table = register_dissector_table("mpls.label",
                                                       "MPLS protocol",
                                                       FT_UINT32, BASE_DEC);
    proto_mpls = proto_register_protocol("MultiProtocol Label Switching Header",
                                         "MPLS", "mpls");
    proto_pw_ach = proto_register_protocol(PW_ACH,
                                           "PW Associated Channel", "pwach");
    proto_pw_mcw = proto_register_protocol("PW MPLS Control Word (generic/preferred)",
                                           "Generic PW (with CW)", "pwmcw");

    proto_register_field_array(proto_mpls, mplsf_info, array_length(mplsf_info));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("mpls", dissect_mpls, proto_mpls);
    register_dissector("mplspwcw", dissect_pw_mcw, proto_pw_mcw );

    module_mpls = prefs_register_protocol( proto_mpls, NULL );

    prefs_register_enum_preference(module_mpls,
                                   "mplspref.payload",
                                   "Default decoder for MPLS payload",
                                   "Default decoder for MPLS payload",
                                   &mpls_default_payload,
                                   mpls_default_payload_defs,
                                   FALSE );

    /* RFC6391: Flow aware transport of pseudowire*/
    prefs_register_bool_preference(module_mpls,
                                    "flowlabel_in_mpls_header",
                                    "Assume bottom of stack label as Flow label",
                                    "Lowest label is used to segregate flows inside a pseudowire",
                                    &mpls_bos_flowlabel);

    register_decode_as(&mpls_da);
}

void
proto_reg_handoff_mpls(void)
{
    dissector_handle_t mpls_handle;

    mpls_handle = find_dissector("mpls");
    dissector_add_uint("ethertype", ETHERTYPE_MPLS, mpls_handle);
    dissector_add_uint("ethertype", ETHERTYPE_MPLS_MULTI, mpls_handle);
    dissector_add_uint("ppp.protocol", PPP_MPLS_UNI, mpls_handle);
    dissector_add_uint("ppp.protocol", PPP_MPLS_MULTI, mpls_handle);
    dissector_add_uint("chdlc.protocol", ETHERTYPE_MPLS, mpls_handle);
    dissector_add_uint("chdlc.protocol", ETHERTYPE_MPLS_MULTI, mpls_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_MPLS, mpls_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_MPLS_MULTI, mpls_handle);
    dissector_add_uint("ip.proto", IP_PROTO_MPLS_IN_IP, mpls_handle);

    mpls_handle = find_dissector("mplspwcw");
    dissector_add_uint( "mpls.label", MPLS_LABEL_INVALID, mpls_handle );

    dissector_data                  = find_dissector("data");
    dissector_ipv6                  = find_dissector("ipv6");
    dissector_ip                    = find_dissector("ip");
    dissector_bfd                   = find_dissector("bfd");
    dissector_mpls_pm_dlm           = find_dissector("mpls_pm_dlm");
    dissector_mpls_pm_ilm           = find_dissector("mpls_pm_ilm");
    dissector_mpls_pm_dm            = find_dissector("mpls_pm_dm");
    dissector_mpls_pm_dlm_dm        = find_dissector("mpls_pm_dlm_dm");
    dissector_mpls_pm_ilm_dm        = find_dissector("mpls_pm_ilm_dm");
    dissector_mpls_psc              = find_dissector("mpls_psc");
    dissector_mplstp_lock           = find_dissector("mplstp_lock");
    dissector_mplstp_fm             = find_dissector("mplstp_fm");
    dissector_pw_oam                = find_dissector("pw_oam");
    dissector_pw_eth_heuristic      = find_dissector("pw_eth_heuristic");
    dissector_pw_fr                 = find_dissector("pw_fr");
    dissector_pw_hdlc_nocw_fr       = find_dissector("pw_hdlc_nocw_fr");
    dissector_pw_hdlc_nocw_hdlc_ppp = find_dissector("pw_hdlc_nocw_hdlc_ppp");
    dissector_pw_eth_cw             = find_dissector("pw_eth_cw");
    dissector_pw_eth_nocw           = find_dissector("pw_eth_nocw");
    dissector_pw_satop              = find_dissector("pw_satop_mpls");
    dissector_itdm                  = find_dissector("itdm");
    dissector_mpls_pw_atm_n1_cw     = find_dissector("mpls_pw_atm_n1_cw");
    dissector_mpls_pw_atm_n1_nocw   = find_dissector("mpls_pw_atm_n1_nocw");
    dissector_mpls_pw_atm_11_aal5pdu= find_dissector("mpls_pw_atm_11_or_aal5_pdu");
    dissector_mpls_pw_atm_aal5_sdu  = find_dissector("mpls_pw_atm_aal5_sdu");
    dissector_pw_cesopsn            = find_dissector("pw_cesopsn_mpls");

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
