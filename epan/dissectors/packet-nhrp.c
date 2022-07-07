/* packet-nhrp.c
 * Routines for NBMA Next Hop Resolution Protocol
 * RFC 2332 plus Cisco extensions (documented where?), plus extensions from:
 *     RFC 2520: NHRP with Mobile NHCs
 *     RFC 2735: NHRP Support for Virtual Private Networks
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CIE decoding for extensions and Cisco 12.4T extensions
 * added by Timo Teras <timo.teras@iki.fi>
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/nlpid.h>
#include <epan/afn.h>
#include <epan/in_cksum.h>
#include "packet-iana-oui.h"
#include "packet-llc.h"
#include "packet-gre.h"

void proto_register_nhrp(void);
void proto_reg_handoff_nhrp(void);

/* forward reference */
static void _dissect_nhrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean nested, gboolean codeinfo);

static int proto_nhrp = -1;
static int hf_nhrp_hdr_afn = -1;
static int hf_nhrp_hdr_pro_type = -1;
static int hf_nhrp_hdr_pro_snap_oui = -1;
static int hf_nhrp_hdr_pro_snap_pid = -1;
static int hf_nhrp_hdr_hopcnt = -1;
static int hf_nhrp_hdr_pktsz = -1;
static int hf_nhrp_hdr_chksum = -1;
static int hf_nhrp_hdr_chksum_status = -1;
static int hf_nhrp_hdr_extoff = -1;
static int hf_nhrp_hdr_version = -1;
static int hf_nhrp_hdr_op_type = -1;
static int hf_nhrp_hdr_shtl = -1;
static int hf_nhrp_hdr_shtl_type = -1;
static int hf_nhrp_hdr_shtl_len = -1;
static int hf_nhrp_hdr_sstl = -1;
static int hf_nhrp_hdr_sstl_type = -1;
static int hf_nhrp_hdr_sstl_len = -1;

static int hf_nhrp_src_proto_len = -1;
static int hf_nhrp_dst_proto_len = -1;
static int hf_nhrp_flags = -1;
static int hf_nhrp_flag_Q = -1;
static int hf_nhrp_flag_N = -1;
static int hf_nhrp_flag_A = -1;
static int hf_nhrp_flag_D = -1;
static int hf_nhrp_flag_U1 = -1;
static int hf_nhrp_flag_U2 = -1;
static int hf_nhrp_flag_S = -1;
static int hf_nhrp_flag_NAT = -1;
static int hf_nhrp_src_nbma_addr = -1;
static int hf_nhrp_src_nbma_saddr = -1;
static int hf_nhrp_src_prot_addr = -1;
static int hf_nhrp_dst_prot_addr = -1;
static int hf_nhrp_request_id = -1;

static int hf_nhrp_code = -1;
static int hf_nhrp_prefix_len = -1;
static int hf_nhrp_unused = -1;
static int hf_nhrp_mtu = -1;
static int hf_nhrp_holding_time = -1;
static int hf_nhrp_cli_addr_tl = -1;
static int hf_nhrp_cli_addr_tl_type = -1;
static int hf_nhrp_cli_addr_tl_len = -1;
static int hf_nhrp_cli_saddr_tl = -1;
static int hf_nhrp_cli_saddr_tl_type = -1;
static int hf_nhrp_cli_saddr_tl_len = -1;
static int hf_nhrp_cli_prot_len = -1;
static int hf_nhrp_pref = -1;
static int hf_nhrp_client_nbma_addr = -1;
static int hf_nhrp_client_nbma_saddr = -1;
static int hf_nhrp_client_prot_addr = -1;
static int hf_nhrp_ext_C = -1;
static int hf_nhrp_ext_type = -1;
static int hf_nhrp_ext_len = -1;
/* static int hf_nhrp_ext_value = -1; */          /* TBD: Not used */
static int hf_nhrp_error_code = -1;
static int hf_nhrp_error_offset = -1;
/* static int hf_nhrp_error_packet = -1; */       /* TBD: Not used */

static int hf_nhrp_auth_ext_reserved = -1;
static int hf_nhrp_auth_ext_spi = -1;
static int hf_nhrp_auth_ext_src_addr = -1;
static int hf_nhrp_vendor_ext_id = -1;
static int hf_nhrp_devcap_ext_srccap = -1;
static int hf_nhrp_devcap_ext_srccap_V = -1;
static int hf_nhrp_devcap_ext_dstcap = -1;
static int hf_nhrp_devcap_ext_dstcap_V = -1;
static int hf_nhrp_unknown_ext_value = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_nhrp_dst_prot_addr_bytes = -1;
static int hf_nhrp_auth_ext_src_addr_bytes = -1;
static int hf_nhrp_vendor_ext_data = -1;
static int hf_nhrp_protocol_type = -1;
static int hf_nhrp_src_nbma_addr_bytes = -1;
static int hf_nhrp_client_nbma_address_bytes = -1;
static int hf_nhrp_client_prot_addr_bytes = -1;
static int hf_nhrp_auth_data = -1;
static int hf_nhrp_src_prot_addr_bytes = -1;

static gint ett_nhrp = -1;
static gint ett_nhrp_hdr = -1;
static gint ett_nhrp_hdr_shtl = -1;
static gint ett_nhrp_hdr_sstl = -1;
static gint ett_nhrp_mand = -1;
static gint ett_nhrp_ext = -1;
static gint ett_nhrp_mand_flag = -1;
static gint ett_nhrp_cie = -1;
static gint ett_nhrp_cie_cli_addr_tl = -1;
static gint ett_nhrp_cie_cli_saddr_tl = -1;
static gint ett_nhrp_indication = -1;
static gint ett_nhrp_auth_ext = -1;
static gint ett_nhrp_vendor_ext = -1;
static gint ett_nhrp_devcap_ext = -1;
static gint ett_nhrp_devcap_ext_srccap = -1;
static gint ett_nhrp_devcap_ext_dstcap = -1;

static expert_field ei_nhrp_hdr_pktsz = EI_INIT;
static expert_field ei_nhrp_hdr_extoff = EI_INIT;
static expert_field ei_nhrp_hdr_chksum = EI_INIT;
static expert_field ei_nhrp_ext_not_allowed = EI_INIT;
static expert_field ei_nhrp_ext_malformed = EI_INIT;
static expert_field ei_nhrp_ext_extra = EI_INIT;

static gboolean pref_auth_ext_has_addr = TRUE;

/* NHRP Packet Types */
#define NHRP_RESOLUTION_REQ     1
#define NHRP_RESOLUTION_REPLY   2
#define NHRP_REGISTRATION_REQ   3
#define NHRP_REGISTRATION_REPLY 4
#define NHRP_PURGE_REQ          5
#define NHRP_PURGE_REPLY        6
#define NHRP_ERROR_INDICATION   7
#define NHRP_TRAFFIC_INDICATION 8

/* NHRP Extension Types */
#define NHRP_EXT_NULL              0   /* End of Extension */
#define NHRP_EXT_RESP_ADDR         3   /* Responder Address Extension */
#define NHRP_EXT_FWD_RECORD        4   /* NHRP Forward Transit NHS Record Extension */
#define NHRP_EXT_REV_RECORD        5   /* NHRP Reverse Transit NHS Record Extension */
#define NHRP_EXT_AUTH              7   /* NHRP Authentication Extension */
#define NHRP_EXT_VENDOR_PRIV       8   /* NHRP Vendor Private Extension */
#define NHRP_EXT_NAT_ADDRESS       9   /* Cisco NAT Address Extension */
#define NHRP_EXT_DEV_CAPABILITIES  9   /* RFC 2735: Device Capabilities Extension */
#define NHRP_EXT_MOBILE_AUTH      10   /* RFC 2520: NHRP Mobile NHC Authentication Extension */

/* NHRP Error Codes */
#define NHRP_ERR_UNRECOGNIZED_EXT       0x0001
#define NHRP_ERR_NHRP_LOOP_DETECT       0x0003
#define NHRP_ERR_PROT_ADDR_UNREACHABLE  0x0006
#define NHRP_ERR_PROT_ERROR             0x0007
#define NHRP_ERR_SDU_SIZE_EXCEEDED      0x0008
#define NHRP_ERR_INV_EXT                0x0009
#define NHRP_ERR_INV_RESOLUTION_REPLY   0x000a
#define NHRP_ERR_AUTH_FAILURE           0x000b
#define NHRP_ERR_HOP_COUNT_EXCEEDED     0x000f
#define NHRP_ERR_VPN_MISMATCH           0x0010  /* RFC 2735 */
#define NHRP_ERR_VPN_UNSUPPORTED        0x0011  /* RFC 2735 */

/* NHRP CIE codes */
#define NHRP_CODE_SUCCESS                   0x00
#define NHRP_CODE_ADMIN_PROHIBITED          0x04
#define NHRP_CODE_INSUFFICIENT_RESOURCES    0x05
#define NHRP_CODE_NO_BINDING_EXISTS         0x0c
#define NHRP_CODE_NON_UNIQUE_BINDING        0x0d
#define NHRP_CODE_ALREADY_REGISTERED        0x0e

/* NHRP Subnetwork layer address type/length */
#define NHRP_SHTL_TYPE_MASK 0x40
#define NHRP_SHTL_LEN_MASK  0x3F
#define NHRP_SHTL_TYPE(val) (((val) & (NHRP_SHTL_TYPE_MASK)) >> 6)
#define NHRP_SHTL_LEN(val)  ((val) & (NHRP_SHTL_LEN_MASK))

#define NHRP_SHTL_TYPE_NSAP 0
#define NHRP_SHTL_TYPE_E164 1

static const value_string nhrp_shtl_type_vals[] = {
    { NHRP_SHTL_TYPE_NSAP, "NSAP format" },
    { NHRP_SHTL_TYPE_E164, "Native E.164 format" },
    { 0, NULL }
};

static const value_string nhrp_op_type_vals[] = {
    { NHRP_RESOLUTION_REQ,      "NHRP Resolution Request" },
    { NHRP_RESOLUTION_REPLY,    "NHRP Resolution Reply" },
    { NHRP_REGISTRATION_REQ,    "NHRP Registration Request" },
    { NHRP_REGISTRATION_REPLY,  "NHRP Registration Reply" },
    { NHRP_PURGE_REQ,           "NHRP Purge Request" },
    { NHRP_PURGE_REPLY,         "NHRP Purge Reply" },
    { NHRP_ERROR_INDICATION,    "NHRP Error Indication" },
    { NHRP_TRAFFIC_INDICATION,  "NHRP Traffic Indication" },
    { 0,                        NULL }
};

static const value_string ext_type_vals[] = {
    { NHRP_EXT_NULL,            "End of Extension" },
    { NHRP_EXT_RESP_ADDR,       "Responder Address Extension" },
    { NHRP_EXT_FWD_RECORD,      "Forward Transit NHS Record Extension" },
    { NHRP_EXT_REV_RECORD,      "Reverse Transit NHS Record Extension" },
    { NHRP_EXT_AUTH,            "NHRP Authentication Extension" },
    { NHRP_EXT_VENDOR_PRIV,     "NHRP Vendor Private Extension" },
    { NHRP_EXT_NAT_ADDRESS,     "Cisco NAT Address Extension" },
#if 0 /* Dup (which is handled in the code) */
    { NHRP_EXT_DEV_CAPABILITIES,"Device Capabilities Extension" },
#endif
    { NHRP_EXT_MOBILE_AUTH,     "Mobile NHC Authentication Extension" },
    { 0,                        NULL }
};

static const value_string nhrp_error_code_vals[] = {
    { NHRP_ERR_UNRECOGNIZED_EXT,        "Unrecognized Extension" },
    { NHRP_ERR_NHRP_LOOP_DETECT,        "NHRP Loop Detected" },
    { NHRP_ERR_PROT_ADDR_UNREACHABLE,   "Protocol Address Unreachable" },
    { NHRP_ERR_PROT_ERROR,              "Protocol Error" },
    { NHRP_ERR_SDU_SIZE_EXCEEDED,       "NHRP SDU Size Exceeded" },
    { NHRP_ERR_INV_EXT,                 "Invalid Extension" },
    { NHRP_ERR_INV_RESOLUTION_REPLY,    "Invalid NHRP Resolution Reply Received" },
    { NHRP_ERR_AUTH_FAILURE,            "Authentication Failure" },
    { NHRP_ERR_HOP_COUNT_EXCEEDED,      "Hop Count Exceeded" },
    { NHRP_ERR_VPN_MISMATCH,            "VPN Mismatch" },
    { NHRP_ERR_VPN_UNSUPPORTED,         "VPN Unsupported" },
    { 0,                                NULL }
};

static const value_string nhrp_cie_code_vals[] = {
    { NHRP_CODE_SUCCESS,                "Success" },
    { NHRP_CODE_ADMIN_PROHIBITED,       "Administratively Prohibited" },
    { NHRP_CODE_INSUFFICIENT_RESOURCES, "Insufficient Resources" },
    { NHRP_CODE_NO_BINDING_EXISTS,      "No Interworking Layer Address to NBMA Address Binding Exists" },
    { NHRP_CODE_NON_UNIQUE_BINDING,     "Binding Exists But Is Not Unique" },
    { NHRP_CODE_ALREADY_REGISTERED,     "Unique Internetworking Layer Address Already Registered" },
    { 0,                                NULL }
};

static dissector_table_t osinl_incl_subdissector_table;
static dissector_table_t osinl_excl_subdissector_table;
static dissector_table_t ethertype_subdissector_table;

/*
 * The header fields needed outside of dissect_nhrp_hdr().
 * This is not all of the fields.
 */
typedef struct _e_nhrp {
    guint16 ar_afn;
    guint16 ar_pro_type;
    guint32 ar_pro_type_oui;
    guint16 ar_pro_type_pid;
    guint8  ar_op_type;
    guint8  ar_shtl;
    guint8  ar_sstl;
} e_nhrp_hdr;

static gboolean dissect_nhrp_hdr(tvbuff_t     *tvb,
                      packet_info  *pinfo,
                      proto_tree   *tree,
                      gint         *pOffset,
                      gint         *pMandLen,
                      gint         *pExtLen,
                      oui_info_t  **pOuiInfo,
                      e_nhrp_hdr   *hdr)
{
    gint         offset    = *pOffset;
    const gchar *pro_type_str;

    proto_tree *nhrp_tree;
    proto_item *nhrp_item;
    proto_item *shtl_tree_item;
    proto_tree *shtl_tree;
    proto_item *sstl_tree_item;
    proto_tree *sstl_tree;
    proto_item *ti;
    guint32     afn;
    guint32     oui;
    guint32     pid;
    guint32     pktsz;
    guint32     extoff;
    guint8      version;

    nhrp_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nhrp_hdr, &nhrp_item, "NHRP Fixed Header");

    proto_tree_add_item_ret_uint(nhrp_tree, hf_nhrp_hdr_afn, tvb, offset, 2, ENC_BIG_ENDIAN, &afn);
    hdr->ar_afn = (guint16)afn;
    offset += 2;

    /* XXX - range_string? */
    hdr->ar_pro_type = tvb_get_ntohs(tvb, offset);
    if (hdr->ar_pro_type <= 0xFF) {
        /* It's an NLPID */
        pro_type_str = val_to_str_const(hdr->ar_pro_type, nlpid_vals,
            "Unknown NLPID");
    } else if (hdr->ar_pro_type <= 0x3FF) {
        /* Reserved for future use by the IETF */
        pro_type_str = "Reserved for future use by the IETF";
    } else if (hdr->ar_pro_type <= 0x04FF) {
        /* Allocated for use by the ATM Forum */
        pro_type_str = "Allocated for use by the ATM Forum";
    } else if (hdr->ar_pro_type <= 0x05FF) {
        /* Experimental/Local use */
        pro_type_str = "Experimental/Local use";
    } else {
        pro_type_str = val_to_str_const(hdr->ar_pro_type, etype_vals,
            "Unknown Ethertype");
    }
    proto_tree_add_uint_format_value(nhrp_tree, hf_nhrp_hdr_pro_type, tvb, offset, 2,
        hdr->ar_pro_type, "%s (0x%04x)",
        pro_type_str, hdr->ar_pro_type);
    offset += 2;

    if (hdr->ar_pro_type == NLPID_SNAP) {
        /*
         * The long form protocol type is a SNAP OUI and PID.
         */
        proto_tree_add_item_ret_uint(nhrp_tree, hf_nhrp_hdr_pro_snap_oui,
            tvb, offset, 3, hdr->ar_pro_type_oui, &oui);
        offset += 3;
        hdr->ar_pro_type_oui = oui;

        *pOuiInfo = get_snap_oui_info(hdr->ar_pro_type_oui);
        if (*pOuiInfo != NULL) {
            proto_tree_add_item_ret_uint(nhrp_tree,
                *(*pOuiInfo)->field_info->p_id,
                tvb, offset, 2, ENC_BIG_ENDIAN, &pid);
        } else {
            proto_tree_add_item_ret_uint(nhrp_tree, hf_nhrp_hdr_pro_snap_pid,
                tvb, offset, 2, ENC_BIG_ENDIAN, &pid);
        }
        hdr->ar_pro_type_pid = (guint16)pid;
    } else {
        /*
         * XXX - we should check that this is zero, as RFC 2332
         * says it should be zero.
         */
        proto_tree_add_item(nhrp_tree, hf_nhrp_protocol_type, tvb, offset, 5, ENC_NA);
        offset += 5;
    }

    proto_tree_add_item(nhrp_tree, hf_nhrp_hdr_hopcnt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    ti = proto_tree_add_item_ret_uint(nhrp_tree, hf_nhrp_hdr_pktsz, tvb, offset, 2, ENC_BIG_ENDIAN, &pktsz);
    if (pktsz < 20) {
        /*
         * The total packet size isn't large enough for a full header.
         */
        expert_add_info(pinfo, ti, &ei_nhrp_hdr_pktsz);
        proto_item_set_end(nhrp_item, tvb, offset + 2);
        return FALSE;
    }
    offset += 2;

    if (tvb_bytes_exist(tvb, 0, pktsz)) {
        vec_t cksum_vec[1];
        SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, 0, pktsz);

        proto_tree_add_checksum(nhrp_tree, tvb, offset, hf_nhrp_hdr_chksum, hf_nhrp_hdr_chksum_status, &ei_nhrp_hdr_chksum,
                                pinfo, in_cksum(&cksum_vec[0], 1), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
    } else {
        proto_tree_add_checksum(nhrp_tree, tvb, offset, hf_nhrp_hdr_chksum, hf_nhrp_hdr_chksum_status, &ei_nhrp_hdr_chksum,
                                pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }
    offset += 2;

    ti = proto_tree_add_item_ret_uint(nhrp_tree, hf_nhrp_hdr_extoff, tvb, offset, 2, ENC_BIG_ENDIAN, &extoff);
    if (extoff != 0 && (extoff < 20 || extoff > pktsz)) {
        /* Bogus value; keep dissecting the header */
        expert_add_info(pinfo, ti, &ei_nhrp_hdr_extoff);
    }
    offset += 2;

    version = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format_value(nhrp_tree, hf_nhrp_hdr_version, tvb, offset, 1,
        version, "%u (%s)", version,
        (version == 1) ? "NHRP - rfc2332" : "Unknown");
    offset += 1;
    proto_tree_add_item(nhrp_tree, hf_nhrp_hdr_op_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    hdr->ar_shtl = tvb_get_guint8(tvb, offset);
    shtl_tree_item = proto_tree_add_uint_format_value(nhrp_tree, hf_nhrp_hdr_shtl,
        tvb, offset, 1, hdr->ar_shtl, "%s/%u",
        val_to_str_const(NHRP_SHTL_TYPE(hdr->ar_shtl), nhrp_shtl_type_vals, "Unknown Type"),
        NHRP_SHTL_LEN(hdr->ar_shtl));
    shtl_tree = proto_item_add_subtree(shtl_tree_item, ett_nhrp_hdr_shtl);
    proto_tree_add_item(shtl_tree, hf_nhrp_hdr_shtl_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(shtl_tree, hf_nhrp_hdr_shtl_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    hdr->ar_sstl = tvb_get_guint8(tvb, offset);
    sstl_tree_item = proto_tree_add_uint_format_value(nhrp_tree, hf_nhrp_hdr_sstl,
        tvb, offset, 1, hdr->ar_sstl, "%s/%u",
        val_to_str_const(NHRP_SHTL_TYPE(hdr->ar_sstl), nhrp_shtl_type_vals, "Unknown Type"),
        NHRP_SHTL_LEN(hdr->ar_sstl));
    sstl_tree = proto_item_add_subtree(sstl_tree_item, ett_nhrp_hdr_sstl);
    proto_tree_add_item(sstl_tree, hf_nhrp_hdr_sstl_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sstl_tree, hf_nhrp_hdr_sstl_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_item_set_end(nhrp_item, tvb, offset);
    *pOffset = offset;
    if (extoff != 0) {
        if (extoff < 20 || extoff > pktsz) {
            /* Bogus value */
            return FALSE;
        }
        *pMandLen = extoff - 20;
        *pExtLen = pktsz - extoff;
    }
    else {
        *pMandLen = pktsz - 20;
        *pExtLen = 0;
    }
    return TRUE;
}

static void dissect_cie_list(tvbuff_t    *tvb,
                      packet_info *pinfo,
                      proto_tree  *tree,
                      gint         offset,
                      gint         cieEnd,
                      e_nhrp_hdr  *hdr,
                      gint         isReq,
                      gboolean     codeinfo)
{
    proto_item *cli_addr_tree_item;
    proto_tree *cli_addr_tree;
    proto_item *cli_saddr_tree_item;
    proto_tree *cli_saddr_tree;
    guint8      val;

    while ((offset + 12)          <= cieEnd) {
        guint       cli_addr_len   = tvb_get_guint8(tvb, offset + 8);
        guint       cli_saddr_len  = tvb_get_guint8(tvb, offset + 9);
        guint       cli_prot_len   = tvb_get_guint8(tvb, offset + 10);
        guint       cie_len        = 12 + cli_addr_len + cli_saddr_len + cli_prot_len;
        proto_tree *cie_tree       = proto_tree_add_subtree(tree, tvb, offset, cie_len, ett_nhrp_cie, NULL, "Client Information Entry");

        if (isReq) {
            proto_tree_add_item(cie_tree, hf_nhrp_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else {
            guint8 code = tvb_get_guint8(tvb, offset);
            if ( codeinfo ) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Code=%s",
                    val_to_str(code, nhrp_cie_code_vals, "Unknown (%u)"));
            }
            proto_tree_add_item(cie_tree, hf_nhrp_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        offset += 1;

        proto_tree_add_item(cie_tree, hf_nhrp_prefix_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(cie_tree, hf_nhrp_unused, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(cie_tree, hf_nhrp_mtu, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(cie_tree, hf_nhrp_holding_time, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        val = tvb_get_guint8(tvb, offset);
        cli_addr_tree_item = proto_tree_add_uint_format_value(cie_tree,
            hf_nhrp_cli_addr_tl, tvb, offset, 1, val, "%s/%u",
            val_to_str_const(NHRP_SHTL_TYPE(val), nhrp_shtl_type_vals, "Unknown Type"),
            NHRP_SHTL_LEN(val));
        cli_addr_tree = proto_item_add_subtree(cli_addr_tree_item, ett_nhrp_cie_cli_addr_tl);
        proto_tree_add_item(cli_addr_tree, hf_nhrp_cli_addr_tl_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(cli_addr_tree, hf_nhrp_cli_addr_tl_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        val = tvb_get_guint8(tvb, offset);
        cli_saddr_tree_item = proto_tree_add_uint_format_value(cie_tree,
            hf_nhrp_cli_saddr_tl, tvb, offset, 1, val, "%s/%u",
            val_to_str_const(NHRP_SHTL_TYPE(val), nhrp_shtl_type_vals, "Unknown Type"),
            NHRP_SHTL_LEN(val));
        cli_saddr_tree = proto_item_add_subtree(cli_saddr_tree_item, ett_nhrp_cie_cli_saddr_tl);
        proto_tree_add_item(cli_saddr_tree, hf_nhrp_cli_saddr_tl_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(cli_saddr_tree, hf_nhrp_cli_saddr_tl_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(cie_tree, hf_nhrp_cli_prot_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(cie_tree, hf_nhrp_pref, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (cli_addr_len) {
            switch (hdr->ar_afn) {

            case AFNUM_INET:
                if (cli_addr_len == 4)
                    proto_tree_add_item(cie_tree, hf_nhrp_client_nbma_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                else {
                    proto_tree_add_item(cie_tree, hf_nhrp_client_nbma_address_bytes, tvb, offset, cli_addr_len, ENC_NA);
                }
                break;

            default:
                proto_tree_add_item(cie_tree, hf_nhrp_client_nbma_address_bytes, tvb, offset, cli_addr_len, ENC_NA);
                break;
            }
            offset += cli_addr_len;
        }

        if (cli_saddr_len) {
            proto_tree_add_item(cie_tree, hf_nhrp_client_nbma_saddr, tvb, offset, cli_saddr_len, ENC_NA);
        }

        if (cli_prot_len) {
            if (cli_prot_len == 4)
                proto_tree_add_item(cie_tree, hf_nhrp_client_prot_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
            else {
                proto_tree_add_item(cie_tree, hf_nhrp_client_prot_addr_bytes, tvb, offset, cli_prot_len, ENC_NA);
            }
            offset += cli_prot_len;
        }
    }
}

static void dissect_nhrp_mand(tvbuff_t    *tvb,
                       packet_info *pinfo,
                       proto_tree  *tree,
                       gint        *pOffset,
                       gint         mandLen,
                       oui_info_t  *oui_info,
                       e_nhrp_hdr  *hdr,
                       guint       *srcLen,
                       gboolean     codeinfo)
{
    gint     offset  = *pOffset;
    gint     mandEnd = offset + mandLen;
    guint8   ssl, shl;
    guint    dstLen;
    gboolean isReq   = FALSE;
    gboolean isErr   = FALSE;
    gboolean isInd   = FALSE;

    proto_tree *nhrp_tree;
    proto_item *nhrp_item;

    switch (hdr->ar_op_type)
    {
    case NHRP_RESOLUTION_REPLY:
    case NHRP_REGISTRATION_REPLY:
    case NHRP_PURGE_REPLY:
        break;
    case NHRP_RESOLUTION_REQ:
    case NHRP_REGISTRATION_REQ:
    case NHRP_PURGE_REQ:
        isReq = TRUE;
        break;
    case NHRP_ERROR_INDICATION: /* This needs special treatment */
        isErr = TRUE;
        isInd = TRUE;
        break;
    case NHRP_TRAFFIC_INDICATION:
        isInd = TRUE;
        break;
    }
    nhrp_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nhrp_mand, &nhrp_item, "NHRP Mandatory Part");

    *srcLen = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(nhrp_tree, hf_nhrp_src_proto_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    dstLen = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(nhrp_tree, hf_nhrp_dst_proto_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (!isInd) {
        switch (hdr->ar_op_type)
        {
        case NHRP_RESOLUTION_REQ:
        case NHRP_RESOLUTION_REPLY:
            {
            static int * const flags[] = {
                &hf_nhrp_flag_Q,
                &hf_nhrp_flag_A,
                &hf_nhrp_flag_D,
                &hf_nhrp_flag_U1,
                &hf_nhrp_flag_S,
                &hf_nhrp_flag_NAT,
                NULL
            };
            proto_tree_add_bitmask(nhrp_tree, tvb, offset, hf_nhrp_flags, ett_nhrp_mand_flag, flags, ENC_BIG_ENDIAN);
            }
            break;
        case NHRP_REGISTRATION_REQ:
        case NHRP_REGISTRATION_REPLY:
            {
            static int * const flags[] = {
                &hf_nhrp_flag_U2,
                &hf_nhrp_flag_NAT,
                NULL
            };
            proto_tree_add_bitmask(nhrp_tree, tvb, offset, hf_nhrp_flags, ett_nhrp_mand_flag, flags, ENC_BIG_ENDIAN);
            }
            break;

        case NHRP_PURGE_REQ:
        case NHRP_PURGE_REPLY:
            {
            static int * const flags[] = {
                &hf_nhrp_flag_N,
                &hf_nhrp_flag_NAT,
                NULL
            };
            proto_tree_add_bitmask(nhrp_tree, tvb, offset, hf_nhrp_flags, ett_nhrp_mand_flag, flags, ENC_BIG_ENDIAN);
            }
            break;
        default:
            {
            static int * const flags[] = {
                &hf_nhrp_flag_NAT,
                NULL
            };
            proto_tree_add_bitmask(nhrp_tree, tvb, offset, hf_nhrp_flags, ett_nhrp_mand_flag, flags, ENC_BIG_ENDIAN);
            }
            break;
        }
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, ", ID=%u", tvb_get_ntohl(tvb, offset));
        proto_tree_add_item(nhrp_tree, hf_nhrp_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    else if (isErr) {
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
            val_to_str(tvb_get_ntohs(tvb, offset), nhrp_error_code_vals, "Unknown Error (%u)"));
        proto_tree_add_item(nhrp_tree, hf_nhrp_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(nhrp_tree, hf_nhrp_error_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    else {
        offset += 6;
    }

    shl = NHRP_SHTL_LEN(hdr->ar_shtl);
    if (shl) {
        switch (hdr->ar_afn) {

        case AFNUM_INET:
            if (shl == 4)
                proto_tree_add_item(nhrp_tree, hf_nhrp_src_nbma_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
            else {
                proto_tree_add_item(nhrp_tree, hf_nhrp_src_nbma_addr_bytes, tvb, offset, shl, ENC_NA);
            }
            break;

        default:
            proto_tree_add_item(nhrp_tree, hf_nhrp_src_nbma_addr_bytes, tvb, offset, shl, ENC_NA);
            break;
        }
        offset += shl;
    }

    ssl = NHRP_SHTL_LEN(hdr->ar_sstl);
    if (ssl) {
        proto_tree_add_item(nhrp_tree, hf_nhrp_src_nbma_saddr, tvb, offset, ssl, ENC_NA);
        offset += ssl;
    }

    if (*srcLen == 4) {
        proto_tree_add_item(nhrp_tree, hf_nhrp_src_prot_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    else if (*srcLen) {
        proto_tree_add_item(nhrp_tree, hf_nhrp_src_prot_addr_bytes, tvb, offset, *srcLen, ENC_NA);
        offset += *srcLen;
    }

    if (dstLen == 4) {
        proto_tree_add_item(nhrp_tree, hf_nhrp_dst_prot_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    else if (dstLen) {
        proto_tree_add_item(nhrp_tree, hf_nhrp_dst_prot_addr_bytes, tvb, offset, dstLen, ENC_NA);
        offset += dstLen;
    }

    if (isInd) {
        gboolean    save_in_error_pkt;
        proto_tree *ind_tree;
        proto_item *ind_item;
        int         dissected;
        tvbuff_t   *sub_tvb;

        ind_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nhrp_indication, &ind_item, "Packet Causing Indication");
        save_in_error_pkt = pinfo->flags.in_error_pkt;
        pinfo->flags.in_error_pkt = TRUE;
        sub_tvb = tvb_new_subset_remaining(tvb, offset);
        if (isErr) {
            _dissect_nhrp(sub_tvb, pinfo, ind_tree, TRUE, FALSE);
        }
        else {
            if (hdr->ar_pro_type <= 0xFF) {
                /* It's an NLPID */
                if (hdr->ar_pro_type == NLPID_SNAP) {
                    /*
                     * Dissect based on the SNAP OUI
                     * and PID.
                     */
                    if (hdr->ar_pro_type_oui == 0x000000) {
                        /*
                         * "Should not happen", as
                         * the protocol type should
                         * be the Ethertype, but....
                         */
                        dissected = dissector_try_uint(
                            ethertype_subdissector_table,
                            hdr->ar_pro_type_pid,
                            sub_tvb, pinfo, ind_tree);
                    } else {
                        /*
                         * If we have a dissector
                         * table, use it, otherwise
                         * just dissect as data.
                         */
                        if (oui_info != NULL) {
                            dissected = dissector_try_uint(
                                oui_info->table,
                                hdr->ar_pro_type_pid,
                                sub_tvb, pinfo,
                                ind_tree);
                        } else
                            dissected = 0;
                    }
                } else {
                    /*
                     * Dissect based on the NLPID.
                     */
                    dissected = dissector_try_uint(
                        osinl_incl_subdissector_table,
                        hdr->ar_pro_type, sub_tvb, pinfo,
                        ind_tree) ||
                                dissector_try_uint(
                        osinl_excl_subdissector_table,
                        hdr->ar_pro_type, sub_tvb, pinfo,
                        ind_tree);
                }
            } else if (hdr->ar_pro_type <= 0x3FF) {
                /* Reserved for future use by the IETF */
                dissected = 0;
            } else if (hdr->ar_pro_type <= 0x04FF) {
                /* Allocated for use by the ATM Forum */
                dissected = 0;
            } else if (hdr->ar_pro_type <= 0x05FF) {
                /* Experimental/Local use */
                dissected = 0;
            } else {
                dissected = dissector_try_uint(
                    ethertype_subdissector_table,
                    hdr->ar_pro_type, sub_tvb, pinfo, ind_tree);
            }
            if (!dissected) {
                call_data_dissector(sub_tvb, pinfo, ind_tree);
            }
        }
        pinfo->flags.in_error_pkt = save_in_error_pkt;
        proto_item_set_end(ind_item, tvb, offset);
        offset = mandEnd;
    }
    proto_item_set_len(nhrp_item, mandLen);

    /* According to RFC 2332, section 5.2.7, there shouldn't be any extensions
     * in the Error Indication packet. */
    if (isErr && tvb_reported_length_remaining(tvb, offset)) {
        expert_add_info(pinfo, tree, &ei_nhrp_ext_not_allowed);
    }

    dissect_cie_list(tvb, pinfo, nhrp_tree, offset, mandEnd, hdr, isReq, codeinfo);

    *pOffset = mandEnd;
}

static void dissect_nhrp_ext(tvbuff_t    *tvb,
                      packet_info *pinfo,
                      proto_tree  *tree,
                      gint        *pOffset,
                      gint         extLen,
                      e_nhrp_hdr  *hdr,
                      guint        srcLen,
                      gboolean     nested)
{
    gint offset = *pOffset;
    gint extEnd = offset + extLen;

    while ((offset + 4) <= extEnd)
    {
        proto_tree *nhrp_tree;
        proto_item *nhrp_item;
        gint        extTypeC = tvb_get_ntohs(tvb, offset);
        gint        extType  = extTypeC & 0x3FFF;
        guint       len      = tvb_get_ntohs(tvb, offset+2);

        if ((extType == NHRP_EXT_NAT_ADDRESS) && (len == 8)) {
            /* Assume it's not really a Cisco NAT extension, but a device
             * capabilities extension instead (see RFC 2735). */
            nhrp_tree =  proto_tree_add_subtree(tree, tvb, offset,
                -1, ett_nhrp_ext, &nhrp_item, "Device Capabilities Extension");
        }
        else {
            nhrp_tree =  proto_tree_add_subtree(tree, tvb, offset,
                -1, ett_nhrp_ext, &nhrp_item,
                val_to_str(extType, ext_type_vals, "Unknown (%u)"));
        }
        proto_tree_add_boolean(nhrp_tree, hf_nhrp_ext_C, tvb, offset, 2, extTypeC);
        proto_tree_add_item(nhrp_tree, hf_nhrp_ext_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(nhrp_tree, hf_nhrp_ext_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (len && (extType != NHRP_EXT_NULL)) {
            if ((extType == NHRP_EXT_NAT_ADDRESS) && (len == 8)) {
                /* Assume it's not really a Cisco NAT extension, but a device
                 * capabilities extension instead (see RFC 2735). */
                proto_tree *devcap_tree;
                proto_item *cap_item;
                proto_tree *cap_tree;

                devcap_tree = proto_tree_add_subtree_format(nhrp_tree, tvb, offset, len,
                    ett_nhrp_devcap_ext, NULL, "Extension Data: Src is %sVPN-aware; Dst is %sVPN-aware",
                    tvb_get_ntohl(tvb, offset) & 1 ? "" : "non-",
                    tvb_get_ntohl(tvb, offset + 4) & 1 ? "" : "non-");
                cap_item = proto_tree_add_item(devcap_tree, hf_nhrp_devcap_ext_srccap, tvb, offset, 4, ENC_BIG_ENDIAN);
                cap_tree = proto_item_add_subtree(cap_item, ett_nhrp_devcap_ext_srccap);
                proto_tree_add_item(cap_tree, hf_nhrp_devcap_ext_srccap_V, tvb, offset, 4, ENC_BIG_ENDIAN);

                cap_item = proto_tree_add_item(devcap_tree, hf_nhrp_devcap_ext_dstcap, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                cap_tree = proto_item_add_subtree(cap_item, ett_nhrp_devcap_ext_dstcap);
                proto_tree_add_item(cap_tree, hf_nhrp_devcap_ext_dstcap_V, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                goto skip_switch;
            }

            switch (extType) {
            case NHRP_EXT_RESP_ADDR:
            case NHRP_EXT_FWD_RECORD:
            case NHRP_EXT_REV_RECORD:
            case NHRP_EXT_NAT_ADDRESS:
                dissect_cie_list(tvb, pinfo, nhrp_tree,
                    offset, offset + len, hdr, 0, FALSE);
                break;

            case NHRP_EXT_AUTH:
                /* This is ugly, but this is the only place srcLen is actually
                 * used so we manipulate it here.
                 */
                if (!pref_auth_ext_has_addr)
                    srcLen = 0;
                /* fallthrough */
            case NHRP_EXT_MOBILE_AUTH:
                if (len < (4 + srcLen)) {
                    proto_tree_add_expert_format(nhrp_tree, pinfo, &ei_nhrp_ext_malformed, tvb, offset, len,
                        "Incomplete Authentication Extension");
                }
                else {
                    proto_tree *auth_tree;
                    proto_item *auth_item;
                    guint32 spi;

                    auth_tree = proto_tree_add_subtree_format(nhrp_tree, tvb, offset, -1,
                        ett_nhrp_auth_ext, &auth_item, "Extension Data");
                    proto_tree_add_item(auth_tree, hf_nhrp_auth_ext_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item_ret_uint(auth_tree, hf_nhrp_auth_ext_spi, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &spi);
                    proto_item_append_text(auth_item, ": SPI=%u", spi);
                    if (srcLen == 4)
                        proto_tree_add_item(auth_tree, hf_nhrp_auth_ext_src_addr, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                    else if (srcLen) {
                        proto_tree_add_item(auth_tree, hf_nhrp_auth_ext_src_addr_bytes, tvb, offset + 4, srcLen, ENC_NA);
                    }
                    if (len > (4 + srcLen)) {
                        proto_tree_add_item(auth_tree, hf_nhrp_auth_data, tvb, offset + 4 + srcLen, len - (4 + srcLen), ENC_NA);
                        proto_item_append_text(auth_item, ": Data=%s",
                            tvb_bytes_to_str(pinfo->pool, tvb, offset + 4 + srcLen, len - (4 + srcLen)));
                    }
                    proto_item_set_len(auth_item, len);
                }
                break;

            case NHRP_EXT_VENDOR_PRIV:
                if (len < 3) {
                    proto_tree_add_expert_format(nhrp_tree, pinfo, &ei_nhrp_ext_malformed, tvb, offset, len,
                        "Incomplete Vendor-Private Extension");
                }
                else {
                    proto_tree *vendor_tree;
                    proto_item *vendor_item;
                    guint32 manuf;
                    const gchar* oui;

                    vendor_tree = proto_tree_add_subtree(nhrp_tree, tvb, offset, len,
                        ett_nhrp_vendor_ext, &vendor_item, "Extension Data:");
                    proto_tree_add_item_ret_uint(vendor_tree, hf_nhrp_vendor_ext_id, tvb, offset, 3, ENC_BIG_ENDIAN, &manuf);
                    oui = uint_get_manuf_name_if_known(manuf);
                    if (oui != NULL) {
                        proto_item_append_text(vendor_item, " Vendor ID=%s", oui);
                    } else {
                        proto_item_append_text(vendor_item, " Vendor ID=Unknown");
                    }
                    if (len > 3) {
                        proto_tree_add_item(vendor_tree, hf_nhrp_vendor_ext_data, tvb, offset + 3, len - 3, ENC_NA);
                        proto_item_append_text(vendor_item, ", Data=%s", tvb_bytes_to_str(pinfo->pool, tvb, offset + 3, len - 3));
                    } else {
                        proto_item_append_text(vendor_item, ", Data=<none>");
                    }
                }
                break;

            default:
                proto_tree_add_item(nhrp_tree, hf_nhrp_unknown_ext_value, tvb,
                    offset, len, ENC_NA);
                break;
            }
skip_switch:
            offset += len;
        }
        proto_item_set_end(nhrp_item, tvb, offset);

        if (!nested) {
            len = tvb_reported_length_remaining(tvb, offset);
            if ((extType == NHRP_EXT_NULL) && len) {
                proto_tree_add_expert_format(tree, pinfo, &ei_nhrp_ext_extra, tvb, offset, len,
                    "Unknown Data (%d bytes)", len);
                break;
            }
        }
    }

    *pOffset = extEnd;
}

static int dissect_nhrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    _dissect_nhrp(tvb, pinfo, tree, FALSE, TRUE);
    return tvb_captured_length(tvb);
}

static void _dissect_nhrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean nested, gboolean codeinfo)
{
    e_nhrp_hdr  hdr;
    gint        mandLen  = 0;
    gint        extLen   = 0;
    gint        offset   = 0;
    proto_item *ti;
    proto_tree *nhrp_tree;
    oui_info_t *oui_info = NULL;
    guint       srcLen   = 0;

    if (!nested) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "NHRP");
        col_clear(pinfo->cinfo, COL_INFO);
    }

    memset(&hdr, 0, sizeof(e_nhrp_hdr));
    hdr.ar_op_type = tvb_get_guint8(tvb, 17);

    if (!nested) {
        col_add_str(pinfo->cinfo, COL_INFO,
            val_to_str(hdr.ar_op_type, nhrp_op_type_vals,
                "0x%02X - unknown"));
    }

    ti = proto_tree_add_protocol_format(tree, proto_nhrp, tvb, 0, -1,
        "Next Hop Resolution Protocol (%s)",
        val_to_str(hdr.ar_op_type, nhrp_op_type_vals, "0x%02X - unknown"));
    nhrp_tree = proto_item_add_subtree(ti, ett_nhrp);

    if (!dissect_nhrp_hdr(tvb, pinfo, nhrp_tree, &offset, &mandLen, &extLen,
        &oui_info, &hdr)) {
        /*
         * Header is bogus in a way that we can't dissect any further.
         */
        return;
    }
    if (mandLen) {
        dissect_nhrp_mand(tvb, pinfo, nhrp_tree, &offset, mandLen,
            oui_info, &hdr, &srcLen, codeinfo);
    }

    if (extLen) {
        dissect_nhrp_ext(tvb, pinfo, nhrp_tree, &offset, extLen, &hdr, srcLen, nested);
    }
}

void
proto_register_nhrp(void)
{
    static hf_register_info hf[] = {

        { &hf_nhrp_hdr_afn,
          { "Address Family Number", "nhrp.hdr.afn",
            FT_UINT16, BASE_HEX_DEC, VALS(afn_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_pro_type,
          { "Protocol Type (short form)", "nhrp.hdr.pro.type",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_pro_snap_oui,
          { "Protocol Type (long form) - OUI", "nhrp.hdr.pro.snap.oui",
            FT_UINT24, BASE_OUI, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_pro_snap_pid,
          { "Protocol Type (long form) - PID", "nhrp.hdr.pro.snap.pid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_hopcnt,
          { "Hop Count", "nhrp.hdr.hopcnt",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_pktsz,
          { "Packet Length", "nhrp.hdr.pktsz",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_chksum,
          { "NHRP Packet Checksum", "nhrp.hdr.chksum",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_chksum_status,
          { "NHRP Packet Checksum Status", "nhrp.hdr.chksum.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_extoff,
          { "Extension Offset", "nhrp.hdr.extoff",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_version,
          { "Version", "nhrp.hdr.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_op_type,
          { "NHRP Packet Type", "nhrp.hdr.op.type",
            FT_UINT8, BASE_DEC, VALS(nhrp_op_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_shtl,
          { "Source Address Type/Len", "nhrp.hdr.shtl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_shtl_type,
          { "Type", "nhrp.hdr.shtl.type",
            FT_UINT8, BASE_DEC, VALS(nhrp_shtl_type_vals), NHRP_SHTL_TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_shtl_len,
          { "Length", "nhrp.hdr.shtl.len",
            FT_UINT8, BASE_DEC, NULL, NHRP_SHTL_LEN_MASK,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_sstl,
          { "Source SubAddress Type/Len", "nhrp.hdr.sstl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_sstl_type,
          { "Type", "nhrp.hdr.sstl.type",
            FT_UINT8, BASE_DEC, VALS(nhrp_shtl_type_vals), NHRP_SHTL_TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_nhrp_hdr_sstl_len,
          { "Length", "nhrp.hdr.sstl.len",
            FT_UINT8, BASE_DEC, NULL, NHRP_SHTL_LEN_MASK,
            NULL, HFILL }
        },

        { &hf_nhrp_src_proto_len,
          { "Source Protocol Len", "nhrp.src.prot.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_dst_proto_len,
          { "Destination Protocol Len", "nhrp.dst.prot.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_flags,
          { "Flags", "nhrp.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_flag_Q,
          { "Is Router", "nhrp.flag.q",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_nhrp_flag_N,
          { "Expected Purge Reply", "nhrp.flag.n",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_nhrp_flag_A,
          { "Authoritative", "nhrp.flag.a",
            FT_BOOLEAN, 16, NULL, 0x4000,
            "A bit", HFILL }
        },
        { &hf_nhrp_flag_D,
          { "Stable Association", "nhrp.flag.d",
            FT_BOOLEAN, 16, NULL, 0x2000,
            "D bit", HFILL }
        },
        { &hf_nhrp_flag_U1,
          { "Uniqueness Bit", "nhrp.flag.u",
            FT_BOOLEAN, 16, NULL, 0x1000,
            "U bit", HFILL }
        },
        { &hf_nhrp_flag_U2,
          { "Uniqueness Bit", "nhrp.flag.u",
            FT_BOOLEAN, 16, NULL, 0x8000,
            "U bit", HFILL }
        },
        { &hf_nhrp_flag_S,
          { "Stable Binding", "nhrp.flag.s",
            FT_BOOLEAN, 16, NULL, 0x0800,
            "S bit", HFILL }
        },
        { &hf_nhrp_flag_NAT,
          { "Cisco NAT Supported", "nhrp.flag.nat",
            FT_BOOLEAN, 16, NULL, 0x0002,
            "NAT bit", HFILL }
        },
        { &hf_nhrp_request_id,
          { "Request ID", "nhrp.reqid",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_src_nbma_addr,
          { "Source NBMA Address", "nhrp.src.nbma.addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_src_nbma_saddr,
          { "Source NBMA Sub Address", "nhrp.src.nbma.saddr",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_src_prot_addr,
          { "Source Protocol Address", "nhrp.src.prot.addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_dst_prot_addr,
          { "Destination Protocol Address", "nhrp.dst.prot.addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_nhrp_code,
          { "Code", "nhrp.code",
            FT_UINT8, BASE_DEC, VALS(nhrp_cie_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_prefix_len,
          { "Prefix Length", "nhrp.prefix",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_unused,
          { "Unused", "nhrp.unused",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_mtu,
          { "Max Transmission Unit", "nhrp.mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_holding_time,
          { "Holding Time (s)", "nhrp.htime",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_cli_addr_tl,
          { "Client Address Type/Len", "nhrp.cli.addr_tl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_cli_addr_tl_type,
          { "Type", "nhrp.cli.addr_tl.type",
            FT_UINT8, BASE_DEC, VALS(nhrp_shtl_type_vals), NHRP_SHTL_TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_nhrp_cli_addr_tl_len,
          { "Length", "nhrp.cli.addr_tl.len",
            FT_UINT8, BASE_DEC, NULL, NHRP_SHTL_LEN_MASK,
            NULL, HFILL }
        },
        { &hf_nhrp_cli_saddr_tl,
          { "Client Sub Address Type/Len", "nhrp.cli.saddr_tl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_cli_saddr_tl_type,
          { "Type", "nhrp.cli.saddr_tl.type",
            FT_UINT8, BASE_DEC, VALS(nhrp_shtl_type_vals), NHRP_SHTL_TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_nhrp_cli_saddr_tl_len,
          { "Length", "nhrp.cli.saddr_tl.len",
            FT_UINT8, BASE_DEC, NULL, NHRP_SHTL_LEN_MASK,
            NULL, HFILL }
        },
        { &hf_nhrp_cli_prot_len,
          { "Client Protocol Length", "nhrp.prot.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_pref,
          { "CIE Preference Value", "nhrp.pref",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_client_nbma_addr,
          { "Client NBMA Address", "nhrp.client.nbma.addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_client_nbma_saddr,
          { "Client NBMA Sub Address", "nhrp.client.nbma.saddr",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_client_prot_addr,
          { "Client Protocol Address", "nhrp.client.prot.addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_nhrp_ext_C,
          { "Compulsory Flag", "nhrp.ext.c",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_nhrp_ext_type,
          { "Extension Type", "nhrp.ext.type",
            FT_UINT16, BASE_HEX, NULL, 0x3FFF,
            NULL, HFILL }
        },
        { &hf_nhrp_ext_len,
          { "Extension length", "nhrp.ext.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
#if 0
        { &hf_nhrp_ext_value,
          { "Extension Value", "nhrp.ext.val",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
#endif

        { &hf_nhrp_error_code,
          { "Error Code", "nhrp.err.code",
            FT_UINT16, BASE_DEC, VALS(nhrp_error_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_error_offset,
          { "Error Offset", "nhrp.err.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
#if 0
        { &hf_nhrp_error_packet,
          { "Errored Packet", "nhrp.err.pkt",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
#endif
        { &hf_nhrp_auth_ext_reserved,
          { "Reserved", "nhrp.auth_ext.reserved",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_auth_ext_spi,
          { "SPI", "nhrp.auth_ext.spi",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Security Parameter Index", HFILL }
        },
        { &hf_nhrp_auth_ext_src_addr,
          { "Source Address", "nhrp.auth_ext.src_addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_vendor_ext_id      ,
          { "Vendor ID", "nhrp.vendor_ext.id",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_devcap_ext_srccap,
          { "Source Capabilities", "nhrp.devcap_ext.srccap",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_devcap_ext_srccap_V,
          { "VPN-aware", "nhrp.devcap_ext.srccap.V",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_nhrp_devcap_ext_dstcap,
          { "Destination Capabilities", "nhrp.devcap_ext.dstcap",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nhrp_devcap_ext_dstcap_V,
          { "VPN-aware", "nhrp.devcap_ext.dstcap.V",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_nhrp_unknown_ext_value,
          { "Extension Value", "nhrp.unknown_ext.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_nhrp_protocol_type, { "Protocol Type (long form)", "nhrp.protocol_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nhrp_client_nbma_address_bytes, { "Client NBMA Address", "nhrp.client.nbma.addr_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nhrp_client_prot_addr_bytes, { "Client Protocol Address", "nhrp.client.prot.addr_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nhrp_src_nbma_addr_bytes, { "Source NBMA Address", "nhrp.src.nbma.addr_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nhrp_src_prot_addr_bytes, { "Source Protocol Address", "nhrp.src.prot.addr_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nhrp_dst_prot_addr_bytes, { "Destination Protocol Address", "nhrp.dst.prot.addr_byets", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nhrp_auth_ext_src_addr_bytes, { "Source Address", "nhrp.auth_ext.src_addr_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nhrp_auth_data, { "Data", "nhrp.auth_ext.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_nhrp_vendor_ext_data, { "Data", "nhrp.vendor_ext.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_nhrp,
        &ett_nhrp_hdr,
        &ett_nhrp_hdr_shtl,
        &ett_nhrp_hdr_sstl,
        &ett_nhrp_mand,
        &ett_nhrp_ext,
        &ett_nhrp_mand_flag,
        &ett_nhrp_cie,
        &ett_nhrp_cie_cli_addr_tl,
        &ett_nhrp_cie_cli_saddr_tl,
        &ett_nhrp_indication,
        &ett_nhrp_auth_ext,
        &ett_nhrp_vendor_ext,
        &ett_nhrp_devcap_ext,
        &ett_nhrp_devcap_ext_srccap,
        &ett_nhrp_devcap_ext_dstcap
    };

    static ei_register_info ei[] = {
        { &ei_nhrp_hdr_pktsz, { "nhrp.hdr.pktsz.invalid", PI_MALFORMED, PI_ERROR, "Packet length is less than the fixed header length", EXPFILL }},
        { &ei_nhrp_hdr_extoff, { "nhrp.hdr.extoff.invalid", PI_MALFORMED, PI_ERROR, "Extension offset is less than the fixed header length or larger than the packet size", EXPFILL }},
        { &ei_nhrp_hdr_chksum, { "nhrp.hdr.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_nhrp_ext_not_allowed, { "nhrp.ext.not_allowed", PI_MALFORMED, PI_ERROR, "Extensions not allowed per RFC2332 section 5.2.7", EXPFILL }},
        { &ei_nhrp_ext_malformed, { "nhrp.ext.malformed", PI_MALFORMED, PI_ERROR, "Incomplete Authentication Extension", EXPFILL }},
        { &ei_nhrp_ext_extra, { "nhrp.ext.extra", PI_MALFORMED, PI_ERROR, "Superfluous data follows End Extension", EXPFILL }},
    };

    module_t *nhrp_module;
    expert_module_t* expert_nhrp;

    proto_nhrp = proto_register_protocol("NBMA Next Hop Resolution Protocol", "NHRP", "nhrp");
    proto_register_field_array(proto_nhrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    nhrp_module = prefs_register_protocol(proto_nhrp, NULL);
    prefs_register_bool_preference(nhrp_module, "auth_ext_has_addr",
                                   "Authentication Extension data contains the source address",
                                   "Whether the Authentication Extension data contains the source address. "
                                   "Some Cisco IOS implementations forgo this part of RFC2332.",
                                   &pref_auth_ext_has_addr);
    expert_nhrp = expert_register_protocol(proto_nhrp);
    expert_register_field_array(expert_nhrp, ei, array_length(ei));
}

void
proto_reg_handoff_nhrp(void)
{
    dissector_handle_t nhrp_handle;

    osinl_incl_subdissector_table = find_dissector_table("osinl.incl");
    osinl_excl_subdissector_table = find_dissector_table("osinl.excl");
    ethertype_subdissector_table  = find_dissector_table("ethertype");

    nhrp_handle = create_dissector_handle(dissect_nhrp, proto_nhrp);
    dissector_add_uint("ip.proto", IP_PROTO_NARP, nhrp_handle);
    dissector_add_uint("gre.proto", GRE_NHRP, nhrp_handle);
    dissector_add_uint("llc.iana_pid", IANA_PID_MARS_NHRP_CONTROL, nhrp_handle);
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
