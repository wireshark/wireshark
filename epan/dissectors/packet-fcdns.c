/* packet-fcdns.c
 * Routines for FC distributed Name Server (dNS)
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include "packet-fc.h"
#include "packet-fcct.h"
#include "packet-fcswils.h"

void proto_register_fcdns(void);
void proto_reg_handoff_fcdns(void);

/*
 * See FC-GS-2.
 */

static dissector_handle_t dns_handle;

/* protocol and registered fields */

/* Opcode definitions */
#define FCDNS_GA_NXT   0x0100
#define FCDNS_GID_A    0x0101
#define FCDNS_GPN_ID   0x0112
#define FCDNS_GNN_ID   0x0113
#define FCDNS_GCS_ID   0x0114
#define FCDNS_GFT_ID   0x0117
#define FCDNS_GSPN_ID  0x0118
#define FCDNS_GPT_ID   0x011A
#define FCDNS_GIPP_ID  0x011B
#define FCDNS_GFPN_ID  0x011C
#define FCDNS_GHA_ID   0x011D
#define FCDNS_GFD_ID   0x011E
#define FCDNS_GFF_ID   0x011F
#define FCDNS_GID_PN   0x0121
#define FCDNS_GIPP_PN  0x012B
#define FCDNS_GID_NN   0x0131
#define FCDNS_GPN_NN   0x0132
#define FCDNS_GIP_NN   0x0135
#define FCDNS_GIPA_NN  0x0136
#define FCDNS_GSNN_NN  0x0139
#define FCDNS_GNN_IP   0x0153
#define FCDNS_GIPA_IP  0x0156
#define FCDNS_GID_FT   0x0171
#define FCDNS_GPN_FT   0x0172
#define FCDNS_GNN_FT   0x0173
#define FCDNS_GID_PT   0x01A1
#define FCDNS_GID_IPP  0x01B1
#define FCDNS_GPN_IPP  0x01B2
#define FCDNS_GID_FF   0x01F1
#define FCDNS_RPN_ID   0x0212
#define FCDNS_RNN_ID   0x0213
#define FCDNS_RCS_ID   0x0214
#define FCDNS_RFT_ID   0x0217
#define FCDNS_RSPN_ID  0x0218
#define FCDNS_RPT_ID   0x021A
#define FCDNS_RIPP_ID  0x021B
#define FCDNS_RHA_ID   0x021D
#define FCDNS_RFD_ID   0x021E
#define FCDNS_RFF_ID   0x021F
#define FCDNS_RIP_NN   0x0235
#define FCDNS_RSNN_NN  0x0239
#define FCDNS_DA_ID    0x0300
/* dNS messages defined by FC-SW2 */
#define FCDNS_RA       0x0
#define FCDNS_GE_ID    0x0410
#define FCDNS_GE_PN    0x0420
#define FCDNS_GE_NN    0x0430
#define FCDNS_GE_IP    0x0450
#define FCDNS_GE_FT    0x0470
#define FCDNS_GE_PT    0x04A0
#define FCDNS_GE_ZM    0x04B0
#define FCDNS_GE_ZN    0x04C0
#define FCDNS_GE_IPP   0x04D0
#define FCDNS_GE_FF    0x04E0

static const value_string fc_dns_opcode_val[] = {
    {FCDNS_GA_NXT, "GA_NXT"  },
    {FCDNS_GID_A,  "GID_A"   },
    {FCDNS_GPN_ID, "GPN_ID"  },
    {FCDNS_GNN_ID, "GNN_ID"  },
    {FCDNS_GCS_ID, "GCS_ID"  },
    {FCDNS_GFT_ID, "GFT_ID"  },
    {FCDNS_GSPN_ID, "GSPN_ID" },
    {FCDNS_GPT_ID, "GPT_ID"  },
    {FCDNS_GIPP_ID, "GIPP_ID" },
    {FCDNS_GFPN_ID, "GFPN_ID" },
    {FCDNS_GHA_ID, "GHA_ID"  },
    {FCDNS_GFD_ID, "GFD_ID"  },
    {FCDNS_GFF_ID, "GFF_ID"  },
    {FCDNS_GID_PN, "GID_PN"  },
    {FCDNS_GIPP_PN, "GIPP_PN" },
    {FCDNS_GID_NN, "GID_NN"  },
    {FCDNS_GPN_NN, "GPN_NN"  },
    {FCDNS_GIP_NN, "GIP_NN"  },
    {FCDNS_GIPA_NN, "GIPA_NN" },
    {FCDNS_GSNN_NN, "GSNN_NN" },
    {FCDNS_GNN_IP, "GNN_IP"  },
    {FCDNS_GIPA_IP, "GIPA_IP" },
    {FCDNS_GID_FT, "GID_FT"  },
    {FCDNS_GPN_FT, "GPN_FT"  },
    {FCDNS_GNN_FT, "GNN_FT"  },
    {FCDNS_GID_PT, "GID_PT"  },
    {FCDNS_GID_IPP, "GID_IPP" },
    {FCDNS_GPN_IPP, "GPN_IPP" },
    {FCDNS_GID_FF, "GID_FF"  },
    {FCDNS_RPN_ID, "RPN_ID"  },
    {FCDNS_RNN_ID, "RNN_ID"  },
    {FCDNS_RCS_ID, "RCS_ID"  },
    {FCDNS_RFT_ID, "RFT_ID"  },
    {FCDNS_RSPN_ID, "RSPN_ID" },
    {FCDNS_RPT_ID, "RPT_ID"  },
    {FCDNS_RIPP_ID, "RIPP_ID" },
    {FCDNS_RHA_ID, "RHA_ID"  },
    {FCDNS_RFD_ID, "RFD_ID"  },
    {FCDNS_RFF_ID, "RFF_ID"  },
    {FCDNS_RIP_NN, "RIP_NN"  },
    {FCDNS_RSNN_NN, "RSNN_NN"},
    {FCDNS_DA_ID, "DA_ID"},
    {FCDNS_GE_ID, "GE_ID"},
    {FCDNS_GE_PN, "GE_PN"},
    {FCDNS_GE_NN, "GE_NN"},
    {FCDNS_GE_IP, "GE_IP"},
    {FCDNS_GE_FT, "GE_FT"},
    {FCDNS_GE_PT, "GE_PT"},
    {FCDNS_GE_ZM, "GE_ZM"},
    {FCDNS_GE_ZN, "GE_ZN"},
    {FCDNS_GE_IPP, "GE_IPP"},
    {FCDNS_GE_FF, "GE_FF"},
    {FCCT_MSG_ACC, "MSG_ACC"},
    {FCCT_MSG_RJT, "MSG_RJT"},
    {0, NULL},
};

/* Port type definitions */
#define FCDNS_PTYPE_UNDEF    0x00
#define FCDNS_PTYPE_NPORT    0x01
#define FCDNS_PTYPE_NLPORT   0x02
#define FCDNS_PTYPE_FNLPORT  0x03
#define FCDNS_PTYPE_NXPORT   0x7F
#define FCDNS_PTYPE_FPORT    0x81
#define FCDNS_PTYPE_FLPORT   0x82
#define FCDNS_PTYPE_EPORT    0x84
#define FCDNS_PTYPE_BPORT    0x85

static const value_string fc_dns_port_type_val [] = {
    {FCDNS_PTYPE_UNDEF   , "Undefined Port Type"},
    {FCDNS_PTYPE_NPORT   , "N_Port"},
    {FCDNS_PTYPE_NLPORT  , "NL_Port"},
    {FCDNS_PTYPE_FNLPORT , "F/NL_Port"},
    {FCDNS_PTYPE_NXPORT  , "Nx_Port"},
    {FCDNS_PTYPE_FPORT   , "F_Port"},
    {FCDNS_PTYPE_FLPORT  , "FL_Port"},
    {FCDNS_PTYPE_EPORT   , "E_Port"},
    {FCDNS_PTYPE_BPORT   , "B_Port"},
    {0, NULL},
};

/* Reject Detailed Reason code definitions for dNS */
#define FCDNS_RJT_NOREASON          0x00
#define FCDNS_RJT_PIDNOTREG         0x01
#define FCDNS_RJT_PNAMENOTREG       0x02
#define FCDNS_RJT_NNAMENOTREG       0x03
#define FCDNS_RJT_CLASSNOTREG       0x04
#define FCDNS_RJT_IPNNOTREG         0x05
#define FCDNS_RJT_IPANOTREG         0x06
#define FCDNS_RJT_FC4NOTREG         0x07
#define FCDNS_RJT_SPNAMENOTREG      0x08
#define FCDNS_RJT_SNNAMENOTREG      0x09
#define FCDNS_RJT_PTYPENOTREG       0x0A
#define FCDNS_RJT_IPPNOTREG         0x0B
#define FCDNS_RJT_FPNAMENOTREG      0x0C
#define FCDNS_RJT_HRDADDNOTREG      0x0D
#define FCDNS_RJT_FC4DESNOTREG      0x0E
#define FCDNS_RJT_FC4FEANOTREG      0x0F
#define FCDNS_RJT_ACCRJT            0x10
#define FCDNS_RJT_PTYPEFMT          0x11
#define FCDNS_RJT_DBEMPTY           0x12
#define FCDNS_RJT_NOOBJSCOPE        0x13
#define FCDNS_RJT_AUTHRZN_EXCEPTION 0xF0
#define FCDNS_RJT_AUTH_EXCEPTION    0xF1
#define FCDNS_RJT_DB_FULL           0xF2
#define FCDNS_RJT_DB_EMPTY          0xF3

static const value_string fc_dns_rjt_det_code_val [] = {
    {FCDNS_RJT_NOREASON    , "No Additional Info"},
    {FCDNS_RJT_PIDNOTREG   , "PortID Not Regd."},
    {FCDNS_RJT_PNAMENOTREG , "PortName Not Regd."},
    {FCDNS_RJT_NNAMENOTREG , "NodeName Not Regd."},
    {FCDNS_RJT_CLASSNOTREG , "Class Not Regd."},
    {FCDNS_RJT_IPNNOTREG   , "IP Addr (Node) Not Regd."},
    {FCDNS_RJT_IPANOTREG   , "IPA Not Regd."},
    {FCDNS_RJT_FC4NOTREG   , "FC4 TYPEs Not Regd."},
    {FCDNS_RJT_SPNAMENOTREG, "Symbolic PortName Not Regd."},
    {FCDNS_RJT_SNNAMENOTREG, "Symbolic NodeName Not Regd."},
    {FCDNS_RJT_PTYPENOTREG , "PortType Not Regd."},
    {FCDNS_RJT_IPPNOTREG   , "IP Addr (Port) Not Regd."},
    {FCDNS_RJT_FPNAMENOTREG, "Fabric Port Name Not Regd."},
    {FCDNS_RJT_HRDADDNOTREG, "Hard Addr Not Regd."},
    {FCDNS_RJT_FC4DESNOTREG, "FC4 Descriptors Not Regd."},
    {FCDNS_RJT_FC4FEANOTREG, "FC4 Features Not Regd."},
    {FCDNS_RJT_ACCRJT      , "Access Denied"},
    {FCDNS_RJT_PTYPEFMT    , "Unacceptable PortId"},
    {FCDNS_RJT_DBEMPTY     , "Database Empty"},
    {FCDNS_RJT_NOOBJSCOPE  , "No Objects Regd. in Scope"},
    {FCDNS_RJT_AUTHRZN_EXCEPTION, "Authorization Exception"},
    {FCDNS_RJT_AUTH_EXCEPTION, "Authentication Exception"},
    {FCDNS_RJT_DB_FULL, "Database Full"},
    {FCDNS_RJT_DB_EMPTY, "Database Empty"},
    {0, NULL},
};

/* Actual servers serving the directory service type identified by subtype */
#define FCDNS_GSSUBTYPE_DNS  0x02
#define FCDNS_GSSUBTYPE_IP   0x03

static int proto_fcdns = -1;

static int hf_fcdns_cos_1 = -1;
static int hf_fcdns_cos_2 = -1;
static int hf_fcdns_cos_3 = -1;
static int hf_fcdns_cos_4 = -1;
static int hf_fcdns_cos_6 = -1;
static int hf_fcdns_cos_f = -1;
static int hf_fcdns_fc4features = -1;
static int hf_fcdns_fc4features_i = -1;
static int hf_fcdns_fc4features_t = -1;
static int hf_fcdns_fc4type = -1;
static int hf_fcdns_fc4type_fcp = -1;
static int hf_fcdns_fc4type_gs3 = -1;
static int hf_fcdns_fc4type_ip = -1;
static int hf_fcdns_fc4type_llcsnap = -1;
static int hf_fcdns_fc4type_snmp = -1;
static int hf_fcdns_fc4type_swils = -1;
static int hf_fcdns_fc4type_vi = -1;
static int hf_fcdns_id_length = -1;
static int hf_fcdns_maxres_size = -1;
static int hf_fcdns_num_entries = -1;
static int hf_fcdns_num_fc4desc = -1;
static int hf_fcdns_opcode = -1;
static int hf_fcdns_portip = -1;
static int hf_fcdns_reason = -1;
static int hf_fcdns_reply_cos = -1;
static int hf_fcdns_req_areascope = -1;
static int hf_fcdns_req_cos = -1;
static int hf_fcdns_req_domainscope = -1;
static int hf_fcdns_req_fc4type = -1;
static int hf_fcdns_req_fc4types = -1;
static int hf_fcdns_req_fdesc = -1;
static int hf_fcdns_req_fdesclen = -1;
static int hf_fcdns_req_ip = -1;
static int hf_fcdns_req_nname = -1;
static int hf_fcdns_req_pname = -1;
static int hf_fcdns_req_portid = -1;
static int hf_fcdns_req_ptype = -1;
static int hf_fcdns_req_sname = -1;
static int hf_fcdns_req_snamelen = -1;
static int hf_fcdns_req_spname = -1;
static int hf_fcdns_req_spnamelen = -1;
static int hf_fcdns_rjtdetail = -1;
static int hf_fcdns_rply_fc4desc = -1;
static int hf_fcdns_rply_fc4desclen = -1;
static int hf_fcdns_rply_fc4type = -1;
static int hf_fcdns_rply_fpname = -1;
static int hf_fcdns_rply_gft = -1;
static int hf_fcdns_rply_hrdaddr = -1;
static int hf_fcdns_rply_ipa = -1;
static int hf_fcdns_rply_ipnode = -1;
static int hf_fcdns_rply_ipport = -1;
static int hf_fcdns_rply_nname = -1;
static int hf_fcdns_rply_ownerid = -1;
static int hf_fcdns_rply_pname = -1;
static int hf_fcdns_rply_portid = -1;
static int hf_fcdns_rply_ptype = -1;
static int hf_fcdns_rply_sname = -1;
static int hf_fcdns_rply_snamelen = -1;
static int hf_fcdns_rply_spname = -1;
static int hf_fcdns_rply_spnamelen = -1;
static int hf_fcdns_sw2_objfmt = -1;
static int hf_fcdns_vendor = -1;
static int hf_fcdns_zone_flags = -1;
static int hf_fcdns_zone_mbrid = -1;
static int hf_fcdns_zone_mbrid_fc = -1;
static int hf_fcdns_zone_mbrid_uint = -1;
static int hf_fcdns_zone_mbrid_wwn = -1;
static int hf_fcdns_zone_mbrtype = -1;
static int hf_fcdns_zonelen = -1;
static int hf_fcdns_zonenm = -1;

/* Initialize the subtree pointers */
static gint ett_fcdns = -1;
static gint ett_cos_flags = -1;
static gint ett_fc4flags = -1;
static gint ett_fc4features = -1;

static expert_field ei_fcdns_no_record_of_exchange = EI_INIT;
static expert_field ei_fcdns_zone_mbrid = EI_INIT;

typedef struct _fcdns_conv_key {
    guint32 conv_idx;
} fcdns_conv_key_t;

typedef struct _fcdns_conv_data {
    guint32 opcode;
} fcdns_conv_data_t;

static wmem_map_t *fcdns_req_hash = NULL;

/*
 * Hash Functions
 */
static gint
fcdns_equal(gconstpointer v, gconstpointer w)
{
  const fcdns_conv_key_t *v1 = (const fcdns_conv_key_t *)v;
  const fcdns_conv_key_t *v2 = (const fcdns_conv_key_t *)w;

  return (v1->conv_idx == v2->conv_idx);
}

static guint
fcdns_hash (gconstpointer v)
{
    const fcdns_conv_key_t *key = (const fcdns_conv_key_t *)v;
    guint val;

    val = key->conv_idx;

    return val;
}

static void
dissect_cos_flags (proto_tree *parent_tree, tvbuff_t *tvb, int offset, int hfindex)
{
    static int * const flags[] = {
        &hf_fcdns_cos_f,
        &hf_fcdns_cos_1,
        &hf_fcdns_cos_2,
        &hf_fcdns_cos_3,
        &hf_fcdns_cos_4,
        &hf_fcdns_cos_6,
        NULL
    };

    proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hfindex,
                                ett_cos_flags, flags, ENC_BIG_ENDIAN, BMT_NO_FALSE|BMT_NO_TFS);
}



/* The feature routines just decode FCP's FC-4 features field
 * based on the flahs in offset and the type in offset+1
 */
static void
dissect_fc4features_and_type (proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
    guint8 type;
    static int * const flags[] = {
        &hf_fcdns_fc4features_i,
        &hf_fcdns_fc4features_t,
        NULL
    };

    type = tvb_get_guint8(tvb, offset+1);

    if(type==FC_TYPE_SCSI){
        proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hf_fcdns_fc4features,
                                ett_fc4features, flags, ENC_NA, BMT_NO_FALSE|BMT_NO_TFS);
    } else {
        proto_tree_add_item(parent_tree, hf_fcdns_fc4features, tvb, offset, 1, ENC_NA);
    }

    proto_tree_add_item (parent_tree, hf_fcdns_req_fc4type, tvb, offset+1, 1, ENC_BIG_ENDIAN);
}

/* The feature routines just decode FCP's FC-4 features field
 */
static void
dissect_fc4features (proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
    static int * const flags[] = {
        &hf_fcdns_fc4features_i,
        &hf_fcdns_fc4features_t,
        NULL
    };

    proto_tree_add_bitmask(parent_tree, tvb, offset, hf_fcdns_fc4features,
                           ett_fc4features, flags, ENC_NA);
}



/* Decodes LLC/SNAP, IP, FCP, VI, GS, SW_ILS types only */
static void
dissect_fc4type (proto_tree *parent_tree, tvbuff_t *tvb, int offset, int hfindex)
{
    proto_item *item;
    proto_tree *tree;
    guint32 flags;

    item=proto_tree_add_item(parent_tree, hfindex, tvb, offset,
                                32, ENC_NA);
    tree=proto_item_add_subtree(item, ett_fc4flags);

    flags = tvb_get_ntohl (tvb, offset);

    proto_tree_add_boolean(tree, hf_fcdns_fc4type_fcp, tvb, offset, 4, flags);
    if (flags&0x0100){
        proto_item_append_text(item, "  FCP");
    }
    flags&=(~( 0x0100 ));

    proto_tree_add_boolean(tree, hf_fcdns_fc4type_ip, tvb, offset, 4, flags);
    if (flags&0x0020){
        proto_item_append_text(item, "  IP");
    }
    flags&=(~( 0x0020 ));

    proto_tree_add_boolean(tree, hf_fcdns_fc4type_llcsnap, tvb, offset, 4, flags);
    if (flags&0x0010){
        proto_item_append_text(item, "  LLC/SNAP");
    }
    /*flags&=(~( 0x0010 ));*/


    flags = tvb_get_ntohl (tvb, offset+4);

    proto_tree_add_boolean(tree, hf_fcdns_fc4type_swils, tvb, offset+4, 4, flags);
    if (flags&0x0010){
        proto_item_append_text(item, "  SW_ILS");
    }
    flags&=(~( 0x0010 ));

    proto_tree_add_boolean(tree, hf_fcdns_fc4type_snmp, tvb, offset+4, 4, flags);
    if (flags&0x0004){
        proto_item_append_text(item, "  SNMP");
    }
    flags&=(~( 0x0004 ));

    proto_tree_add_boolean(tree, hf_fcdns_fc4type_gs3, tvb, offset+4, 4, flags);
    if (flags&0x0001){
        proto_item_append_text(item, "  GS3");
    }
    /*flags&=(~( 0x0001 ));*/


    flags = tvb_get_ntohl (tvb, offset+8);

    proto_tree_add_boolean(tree, hf_fcdns_fc4type_vi, tvb, offset+8, 4, flags);
    if (flags&0x0001){
        proto_item_append_text(item, "  VI");
    }
    /*flags&=(~( 0x0001 ));*/
}

/* Code to actually dissect the packets */

/* A bunch of get routines have a similar req packet format. The first few
 * routines deal with this decoding. All assume that tree is valid */
static void
dissect_fcdns_req_portid (tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree_add_item (tree, hf_fcdns_req_portid, tvb, offset, 3, ENC_NA);
}

static void
dissect_fcdns_ganxt (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_ptype, tvb, offset,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_rply_portid, tvb,
                                   offset+1, 3, ENC_NA);
            proto_tree_add_item (req_tree, hf_fcdns_rply_pname, tvb,
                                   offset+4, 8, ENC_NA);
            len = tvb_get_guint8 (tvb, offset+12);
            proto_tree_add_item (req_tree, hf_fcdns_rply_spnamelen, tvb,
                                 offset+12, 1, ENC_BIG_ENDIAN);
            if (!tvb_offset_exists (tvb, 29+len))
                return;

            if (len) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_spname, tvb,
                                     offset+13, len, ENC_ASCII);
            }

            if (tvb_offset_exists (tvb, 292)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_nname, tvb,
                                       offset+268, 8, ENC_NA);
            }
            if (tvb_offset_exists (tvb, 548)) {
                len = tvb_get_guint8 (tvb, offset+276);
                proto_tree_add_item (req_tree, hf_fcdns_rply_snamelen, tvb,
                                     offset+276, 1, ENC_BIG_ENDIAN);
                if (len) {
                    proto_tree_add_item (req_tree, hf_fcdns_rply_sname, tvb,
                                         offset+277, len, ENC_ASCII);
                }
            }
            if (tvb_offset_exists (tvb, 556)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_ipa, tvb,
                                     offset+532, 8, ENC_NA);
            }
            if (tvb_offset_exists (tvb, 572)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_ipnode, tvb,
                                     offset+540, 16, ENC_NA);
            }
            if (tvb_offset_exists (tvb, 576)) {
                dissect_cos_flags(req_tree, tvb, offset+556, hf_fcdns_reply_cos);
            }
            if (tvb_offset_exists (tvb, 608)) {
                dissect_fc4type(req_tree, tvb, offset+560, hf_fcdns_rply_gft);
            }
            if (tvb_offset_exists (tvb, 624)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_ipport, tvb,
                                     offset+592, 16, ENC_NA);
            }
            if (tvb_offset_exists (tvb, 632)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_fpname, tvb,
                                       offset+608, 8, ENC_NA);
            }
            if (tvb_offset_exists (tvb, 635)) {
                proto_tree_add_item (req_tree, hf_fcdns_rply_hrdaddr, tvb,
                                       offset+617, 3, ENC_NA);
            }
        }
    }
}

static void
dissect_fcdns_gpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_pname, tvb, offset,
                                   8, ENC_NA);
        }
    }
}

static void
dissect_fcdns_gnnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_nname, tvb,
                                   offset, 8, ENC_NA);
        }
    }
}

static void
dissect_fcdns_gcsid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset);
        }
        else {
            dissect_cos_flags(req_tree, tvb, offset, hf_fcdns_reply_cos);
        }
    }
}

static void
dissect_fcdns_gftid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            dissect_fc4type(req_tree, tvb, offset, hf_fcdns_rply_gft);
        }
    }
}

static void
dissect_fcdns_gspnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item (req_tree, hf_fcdns_rply_spnamelen,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_rply_spname, tvb,
                                 offset+1, len, ENC_ASCII);
        }
    }
}

static void
dissect_fcdns_gptid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_ptype, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
        }
    }
}

static void
dissect_fcdns_gfpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_fpname, tvb,
                                   offset, 8, ENC_NA);
        }
    }

}

static void
dissect_fcdns_gfdid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int tot_len, desclen;

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
            dissect_fc4type(req_tree, tvb, offset+4, hf_fcdns_fc4type);
        }
        else {
            tot_len = tvb_reported_length_remaining (tvb, offset); /* excluding CT header */
            while (tot_len > 0) {
                /* The count of the descriptors is not returned and so we have
                 * to track the display by the length field */
                desclen = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_fc4desc, tvb,
                                     offset, desclen, ENC_NA);
                tot_len -= 255; /* descriptors are aligned to 255 bytes */
                offset += 256;
            }
        }
    }
}

static void
dissect_fcdns_gffid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            dissect_fcdns_req_portid (tvb, req_tree, offset+1);
        }
        else {
            dissect_fc4features(req_tree, tvb, offset);
        }
    }
}

static void
dissect_fcdns_gidpn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_pname, tvb,
                                   offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_portid, tvb,
                                   offset+1, 3, ENC_NA);
        }
    }
}

static void
dissect_fcdns_gipppn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_pname, tvb,
                                   offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_ipport, tvb, offset,
                                 16, ENC_NA);
        }
    }
}

static void
dissect_fcdns_gidnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_nname, tvb,
                                   offset, 8, ENC_NA);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3, ENC_NA);
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gipnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_nname, tvb,
                                   offset, 8, ENC_NA);
        }
        else {
            proto_tree_add_item (req_tree, hf_fcdns_rply_ipnode, tvb, offset,
                                 16, ENC_NA);
        }
    }
}

static void
dissect_fcdns_gpnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_nname, tvb,
                                   offset, 8, ENC_NA);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3, ENC_NA);
                proto_tree_add_item (req_tree, hf_fcdns_rply_pname,
                                       tvb, offset+8, 8, ENC_NA);
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gsnnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_nname, tvb,
                                   offset, 8, ENC_NA);
        }
        else {
            len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_item (req_tree, hf_fcdns_rply_snamelen, tvb,
                                 offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_rply_sname, tvb,
                                 offset+1, len, ENC_ASCII);
        }
    }
}

static void
dissect_fcdns_gidft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope,
                                 tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope,
                                 tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_fc4type,
                                 tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3, ENC_NA);
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gpnft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope,
                                 tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope,
                                 tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_fc4type,
                                 tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3, ENC_NA);
                proto_tree_add_item (req_tree, hf_fcdns_rply_pname,
                                       tvb, offset+4, 8, ENC_NA);
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gnnft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope,
                                 tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope,
                                 tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_fc4type,
                                 tvb, offset+3, 1, ENC_BIG_ENDIAN);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3, ENC_NA);
                proto_tree_add_item (req_tree, hf_fcdns_rply_nname,
                                       tvb, offset+4, 8, ENC_NA);
                offset += 16;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidpt (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast = 0;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_ptype,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope,
                                 tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope,
                                 tvb, offset+2, 1, ENC_BIG_ENDIAN);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3, ENC_NA);
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidipp (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_ip, tvb, offset,
                                 16, ENC_NA);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3, ENC_NA);
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_gidff (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 islast;

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_domainscope, tvb,
                                 offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_areascope, tvb,
                                 offset+2, 1, ENC_BIG_ENDIAN);
            dissect_fc4features_and_type(req_tree, tvb, offset+6);
        }
        else {
            do {
                islast = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (req_tree, hf_fcdns_rply_portid,
                                       tvb, offset+1, 3, ENC_NA);
                offset += 4;
            } while (!(islast & 0x80));
        }
    }
}

static void
dissect_fcdns_rpnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_portid,
                                   tvb, offset+1, 3, ENC_NA);
            proto_tree_add_item (req_tree, hf_fcdns_req_pname, tvb,
                                   offset+4, 8, ENC_NA);
        }
    }
}

static void
dissect_fcdns_rnnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree) {
        if (isreq) {
            proto_tree_add_item (req_tree, hf_fcdns_req_portid,
                                   tvb, offset+1, 3, ENC_NA);
            proto_tree_add_item (req_tree, hf_fcdns_req_nname, tvb,
                                   offset+4, 8, ENC_NA);
        }
    }
}

static void
dissect_fcdns_rcsid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (req_tree && isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3, ENC_NA);
        dissect_cos_flags(req_tree, tvb, offset+4, hf_fcdns_req_cos);
    }
}

static void
dissect_fcdns_rptid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3, ENC_NA);
        proto_tree_add_item (req_tree, hf_fcdns_req_ptype, tvb,
                             offset+4, 1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcdns_rftid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3, ENC_NA);
        dissect_fc4type(req_tree, tvb, offset+4, hf_fcdns_req_fc4types);
    }
}

static void
dissect_fcdns_rspnid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (req_tree && isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3, ENC_NA);
        proto_tree_add_item (req_tree, hf_fcdns_req_spnamelen, tvb,
                             offset+4, 1, ENC_BIG_ENDIAN);
        len = tvb_get_guint8 (tvb, offset+4);

        proto_tree_add_item (req_tree, hf_fcdns_req_spname, tvb, offset+5,
                             len, ENC_ASCII);
    }
}

static void
dissect_fcdns_rippid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3, ENC_NA);
        proto_tree_add_item (req_tree, hf_fcdns_req_ip, tvb,
                             offset+4, 16, ENC_NA);
    }
}

static void
dissect_fcdns_rfdid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int len;

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb,
                               offset+1, 3, ENC_NA);
        dissect_fc4type(req_tree, tvb, offset+4, hf_fcdns_req_fc4types);

        offset += 36;
        len = tvb_reported_length_remaining (tvb, offset);

        while (len > 0) {
            proto_tree_add_item (req_tree, hf_fcdns_req_fdesclen, tvb, offset,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (req_tree, hf_fcdns_req_fdesc, tvb, offset+1,
                                 len, ENC_ASCII);
            offset += 256;
            len -= 256;
        }
    }
}

static void
dissect_fcdns_rffid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb, offset+1, 3, ENC_NA);
        dissect_fc4features_and_type(req_tree, tvb, offset+6);
    }
}

static void
dissect_fcdns_ripnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_nname, tvb, offset, 8, ENC_NA);
        proto_tree_add_item (req_tree, hf_fcdns_req_ip, tvb, offset+8, 16, ENC_NA);
    }
}

static void
dissect_fcdns_rsnnnn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    guint8 len;

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_nname, tvb, offset, 8, ENC_NA);
        len = tvb_get_guint8 (tvb, offset+8);

        proto_tree_add_item (req_tree, hf_fcdns_req_snamelen, tvb, offset+8,
                             1, ENC_BIG_ENDIAN);
        proto_tree_add_item (req_tree, hf_fcdns_req_sname, tvb, offset+9,
                             len, ENC_ASCII);
    }
}

static void
dissect_fcdns_daid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb, offset+1, 3, ENC_NA);
    }
}

static guint8 *
zonenm_to_str (tvbuff_t *tvb, gint offset)
{
    int len = tvb_get_guint8 (tvb, offset);
    return tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, len, ENC_ASCII);
}

static void
dissect_fcdns_zone_mbr (tvbuff_t *tvb, packet_info* pinfo, proto_tree *zmbr_tree, int offset)
{
    guint8 mbrtype;
    int idlen;
    proto_item* ti;

    mbrtype = tvb_get_guint8 (tvb, offset);
    ti = proto_tree_add_uint (zmbr_tree, hf_fcdns_zone_mbrtype, tvb,
                         offset, 1, mbrtype);
    proto_tree_add_item(zmbr_tree, hf_fcdns_zone_flags, tvb, offset+2, 1, ENC_NA);
    idlen = tvb_get_guint8 (tvb, offset+3);
    proto_tree_add_item(zmbr_tree, hf_fcdns_id_length, tvb, offset+3, 1, ENC_NA);
    switch (mbrtype) {
    case FC_SWILS_ZONEMBR_WWN:
        proto_tree_add_item (zmbr_tree, hf_fcdns_zone_mbrid_wwn, tvb,
                               offset+4, 8, ENC_NA);
        break;
    case FC_SWILS_ZONEMBR_DP:
        proto_tree_add_item (zmbr_tree, hf_fcdns_zone_mbrid_uint, tvb,
                               offset+4, 4, ENC_BIG_ENDIAN);
        break;
    case FC_SWILS_ZONEMBR_FCID:
        proto_tree_add_item (zmbr_tree, hf_fcdns_zone_mbrid_fc, tvb,
                               offset+4, 3, ENC_NA);
        break;
    case FC_SWILS_ZONEMBR_ALIAS:
        proto_tree_add_string (zmbr_tree, hf_fcdns_zone_mbrid, tvb,
                               offset+4, idlen, zonenm_to_str (tvb, offset+4));
        break;
    default:
        expert_add_info(pinfo, ti, &ei_fcdns_zone_mbrid);

    }
}

static void
dissect_fcdns_swils_entries (tvbuff_t *tvb, proto_tree *tree, int offset)
{
    int numrec, i, len;
    guint8 objfmt;

    if (tree) {
        numrec = tvb_get_ntohl (tvb, offset);
        proto_tree_add_uint(tree, hf_fcdns_num_entries, tvb, offset, 4, numrec);
        offset += 4;

        for (i = 0; i < numrec; i++) {
            objfmt = tvb_get_guint8 (tvb, offset);

            proto_tree_add_item (tree, hf_fcdns_sw2_objfmt, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_fcdns_rply_ownerid, tvb, offset+1, 3, ENC_NA);
            proto_tree_add_item (tree, hf_fcdns_rply_ptype, tvb, offset+4,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_fcdns_rply_portid, tvb, offset+5, 3, ENC_NA);
            proto_tree_add_item (tree, hf_fcdns_rply_pname, tvb, offset+8, 8, ENC_NA);
            offset += 16;
            if (!(objfmt & 0x1)) {
                len = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (tree, hf_fcdns_rply_spnamelen, tvb,
                                     offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_fcdns_rply_spname, tvb,
                                     offset+1, len, ENC_ASCII);
                offset += 256;
            }
            proto_tree_add_item (tree, hf_fcdns_rply_nname, tvb, offset, 8, ENC_NA);
            offset += 8;
            if (!(objfmt & 0x1)) {
                len = tvb_get_guint8 (tvb, offset);
                proto_tree_add_item (tree, hf_fcdns_rply_snamelen, tvb,
                                     offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_fcdns_rply_sname, tvb,
                                     offset+1, len, ENC_ASCII);
                offset += 256;
            }
            proto_tree_add_item (tree, hf_fcdns_rply_ipa, tvb, offset, 8, ENC_NA);
            proto_tree_add_item (tree, hf_fcdns_rply_ipnode, tvb, offset+8, 16,
                                 ENC_NA);
            dissect_cos_flags(tree, tvb, offset+24, hf_fcdns_reply_cos);
            dissect_fc4type(tree, tvb, offset+28, hf_fcdns_rply_gft);
            proto_tree_add_item (tree, hf_fcdns_rply_ipport, tvb, offset+60,
                                 16, ENC_NA);
            proto_tree_add_item (tree, hf_fcdns_rply_fpname, tvb, offset+76,
                                   8, ENC_NA);
            proto_tree_add_item (tree, hf_fcdns_rply_hrdaddr, tvb, offset+85,
                                   3, ENC_NA);
            offset += 88;
            if (objfmt & 0x2) {
                dissect_fc4features(tree, tvb, offset);
                if (tvb_get_guint8 (tvb, offset+129)) {
                    proto_tree_add_item (tree, hf_fcdns_rply_fc4type, tvb,
                                         offset+128, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item (tree, hf_fcdns_num_fc4desc, tvb,
                                         offset+129, 1, ENC_BIG_ENDIAN);
                    len = tvb_get_guint8 (tvb, offset+132);
                    proto_tree_add_item (tree, hf_fcdns_rply_fc4desclen, tvb,
                                         offset+132, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item (tree, hf_fcdns_rply_fc4desc, tvb,
                                         offset+133, len, ENC_NA);
                }
                else {
                    proto_tree_add_item (tree, hf_fcdns_num_fc4desc, tvb,
                                         offset+129, 1, ENC_BIG_ENDIAN);
                }
                offset += 388;  /* FC4 desc is 260 bytes, maybe padded */
            }
        }
    }
}

static void
dissect_fcdns_geid (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_portid, tvb, offset+1, 3, ENC_NA);
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gepn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    if (isreq) {
        proto_tree_add_item(req_tree, hf_fcdns_req_pname, tvb, offset, 8, ENC_NA);
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_genn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        proto_tree_add_item (req_tree, hf_fcdns_req_nname, tvb, offset, 8, ENC_NA);
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geip (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, hf_fcdns_req_ip, tvb, offset, 16, ENC_NA);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geft (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            dissect_fc4type(req_tree, tvb, offset, hf_fcdns_fc4type);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gept (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, hf_fcdns_req_ptype, tvb, offset+3,
                                 1, ENC_BIG_ENDIAN);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gezm (tvbuff_t *tvb, packet_info* pinfo, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        dissect_fcdns_zone_mbr (tvb, pinfo, req_tree, offset);
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_gezn (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */
    int str_len;

    if (isreq) {
        if (req_tree) {
            str_len = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint(req_tree, hf_fcdns_zonelen, tvb, offset, 1, str_len);
            proto_tree_add_item (req_tree, hf_fcdns_zonenm, tvb, offset+3,
                                 str_len, ENC_ASCII);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geipp (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            proto_tree_add_item (req_tree, hf_fcdns_portip, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_geff (tvbuff_t *tvb, proto_tree *req_tree, gboolean isreq)
{
    int offset = 16;            /* past the fc_ct header */

    if (isreq) {
        if (req_tree) {
            dissect_fc4features(req_tree, tvb, offset);
        }
    }
    else {
        dissect_fcdns_swils_entries (tvb, req_tree, offset);
    }
}

static void
dissect_fcdns_rjt (tvbuff_t *tvb, proto_tree *req_tree)
{
    int offset = 0;

    if (req_tree) {
        proto_tree_add_item (req_tree, hf_fcdns_reason, tvb, offset+13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (req_tree, hf_fcdns_rjtdetail, tvb, offset+14, 1,
                             ENC_BIG_ENDIAN);
        proto_tree_add_item (req_tree, hf_fcdns_vendor, tvb, offset+15, 1, ENC_BIG_ENDIAN);
    }
}

static int
dissect_fcdns (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti = NULL;
    proto_tree *fcdns_tree = NULL;
    int offset = 0;
    int opcode,
        failed_opcode = 0;
    int isreq = 1;
    fc_ct_preamble cthdr;
    conversation_t *conversation;
    fcdns_conv_data_t *cdata;
    fcdns_conv_key_t ckey, *req_key;
    fc_hdr *fchdr;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    fchdr = (fc_hdr *)data;

    tvb_memcpy (tvb, (guint8 *)&cthdr, offset, FCCT_PRMBL_SIZE);
    cthdr.revision = tvb_get_guint8 (tvb, offset);
    cthdr.in_id = tvb_get_ntoh24 (tvb, offset+1);
    cthdr.opcode = g_ntohs (cthdr.opcode);
    opcode = cthdr.opcode;
    cthdr.maxres_size = g_ntohs (cthdr.maxres_size);

    /* Determine the type of server the request/response is for */
    if (cthdr.gstype == FCCT_GSTYPE_DIRSVC)
        col_set_str (pinfo->cinfo, COL_PROTOCOL, "dNS");
    else
        col_set_str (pinfo->cinfo, COL_PROTOCOL, "Unzoned NS");

    if (tree) {
        if (cthdr.gstype == FCCT_GSTYPE_DIRSVC) {
            ti = proto_tree_add_protocol_format (tree, proto_fcdns, tvb, 0,
                                                 -1,
                                                 "dNS");
            fcdns_tree = proto_item_add_subtree (ti, ett_fcdns);
        }
        else {
            ti = proto_tree_add_protocol_format (tree, proto_fcdns, tvb, 0,
                                                 -1,
                                                 "Unzoned NS");
            fcdns_tree = proto_item_add_subtree (ti, ett_fcdns);
        }
    }

    if ((opcode != FCCT_MSG_ACC) && (opcode != FCCT_MSG_RJT)) {
        conversation = find_conversation (pinfo->num, &pinfo->src, &pinfo->dst,
                                          conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                          fchdr->rxid, NO_PORT_B);
        if (!conversation) {
            conversation = conversation_new (pinfo->num, &pinfo->src, &pinfo->dst,
                                             conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                             fchdr->rxid, NO_PORT2);
        }

        ckey.conv_idx = conversation->conv_index;

        cdata = (fcdns_conv_data_t *)wmem_map_lookup (fcdns_req_hash,
                                                            &ckey);
        if (cdata) {
            /* Since we never free the memory used by an exchange, this maybe a
             * case of another request using the same exchange as a previous
             * req.
             */
            cdata->opcode = opcode;
        }
        else {
            req_key = wmem_new(wmem_file_scope(), fcdns_conv_key_t);
            req_key->conv_idx = conversation->conv_index;

            cdata = wmem_new(wmem_file_scope(), fcdns_conv_data_t);
            cdata->opcode = opcode;

            wmem_map_insert (fcdns_req_hash, req_key, cdata);
        }
        col_add_str (pinfo->cinfo, COL_INFO, val_to_str (opcode, fc_dns_opcode_val,
                                                          "0x%x"));
    }
    else {
        /* Opcode is ACC or RJT */
        conversation = find_conversation (pinfo->num, &pinfo->src, &pinfo->dst,
                                          conversation_pt_to_conversation_type(pinfo->ptype), fchdr->oxid,
                                          fchdr->rxid, NO_PORT_B);
        isreq = 0;
        if (!conversation) {
            if (opcode == FCCT_MSG_ACC) {
                col_add_str (pinfo->cinfo, COL_INFO,
                                 val_to_str (opcode, fc_dns_opcode_val,
                                             "0x%x"));
                /* No record of what this accept is for. Can't decode */
                proto_tree_add_expert(fcdns_tree, pinfo, &ei_fcdns_no_record_of_exchange, tvb, 0, -1);
                return 0;
            }
        }
        else {
            ckey.conv_idx = conversation->conv_index;

            cdata = (fcdns_conv_data_t *)wmem_map_lookup (fcdns_req_hash, &ckey);

            if (cdata != NULL) {
                if (opcode == FCCT_MSG_ACC) {
                    opcode = cdata->opcode;
                }
                else
                    failed_opcode = cdata->opcode;
            }

            if (opcode != FCCT_MSG_RJT) {
                col_add_fstr (pinfo->cinfo, COL_INFO, "ACC (%s)",
                                val_to_str (opcode, fc_dns_opcode_val,
                                            "0x%x"));
            }
            else {
                col_add_fstr (pinfo->cinfo, COL_INFO, "RJT (%s)",
                                val_to_str (failed_opcode,
                                            fc_dns_opcode_val,
                                            "0x%x"));
            }

            if (tree) {
                if ((cdata == NULL) && (opcode != FCCT_MSG_RJT)) {
                    /* No record of what this accept is for. Can't decode */
                    proto_tree_add_expert(fcdns_tree, pinfo, &ei_fcdns_no_record_of_exchange, tvb, 0, -1);
                    return 0;
                }
            }
        }
    }

     if (tree) {
        proto_tree_add_item (fcdns_tree, hf_fcdns_opcode, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (fcdns_tree, hf_fcdns_maxres_size, tvb, offset+10,
                             2, ENC_BIG_ENDIAN);
    }

    switch (opcode) {
    case FCCT_MSG_RJT:
        dissect_fcdns_rjt (tvb, fcdns_tree);
        break;
    case FCDNS_GA_NXT:
        dissect_fcdns_ganxt (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_ID:
        dissect_fcdns_gpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GNN_ID:
        dissect_fcdns_gnnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GCS_ID:
        dissect_fcdns_gcsid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFT_ID:
        dissect_fcdns_gftid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GSPN_ID:
        dissect_fcdns_gspnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPT_ID:
        dissect_fcdns_gptid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFPN_ID:
        dissect_fcdns_gfpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFD_ID:
        dissect_fcdns_gfdid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GFF_ID:
        dissect_fcdns_gffid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_PN:
        dissect_fcdns_gidpn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GIPP_PN:
        dissect_fcdns_gipppn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_NN:
        dissect_fcdns_gidnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_NN:
        dissect_fcdns_gpnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GIP_NN:
        dissect_fcdns_gipnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GSNN_NN:
        dissect_fcdns_gsnnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_FT:
        dissect_fcdns_gidft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GPN_FT:
        dissect_fcdns_gpnft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GNN_FT:
        dissect_fcdns_gnnft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_PT:
        dissect_fcdns_gidpt (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_IPP:
        dissect_fcdns_gidipp (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GID_FF:
        dissect_fcdns_gidff (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RPN_ID:
        dissect_fcdns_rpnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RNN_ID:
        dissect_fcdns_rnnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RCS_ID:
        dissect_fcdns_rcsid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RPT_ID:
        dissect_fcdns_rptid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFT_ID:
        dissect_fcdns_rftid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RSPN_ID:
        dissect_fcdns_rspnid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RIPP_ID:
        dissect_fcdns_rippid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFD_ID:
        dissect_fcdns_rfdid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RFF_ID:
        dissect_fcdns_rffid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RIP_NN:
        dissect_fcdns_ripnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_RSNN_NN:
        dissect_fcdns_rsnnnn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_DA_ID:
        dissect_fcdns_daid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ID:
        dissect_fcdns_geid (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_PN:
        dissect_fcdns_gepn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_NN:
        dissect_fcdns_genn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_IP:
        dissect_fcdns_geip (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_FT:
        dissect_fcdns_geft (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_PT:
        dissect_fcdns_gept (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ZM:
        dissect_fcdns_gezm (tvb, pinfo, fcdns_tree, isreq);
        break;
    case FCDNS_GE_ZN:
        dissect_fcdns_gezn (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_IPP:
        dissect_fcdns_geipp (tvb, fcdns_tree, isreq);
        break;
    case FCDNS_GE_FF:
        dissect_fcdns_geff (tvb, fcdns_tree, isreq);
        break;
    default:
        break;
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */

void
proto_register_fcdns (void)
{
    static hf_register_info hf[] = {
        { &hf_fcdns_opcode,
            { "Opcode", "fcdns.opcode",
              FT_UINT16, BASE_HEX, VALS (fc_dns_opcode_val), 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_reason,
            { "Reason Code", "fcdns.rply.reason",
              FT_UINT8, BASE_HEX, VALS (fc_ct_rjt_code_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_vendor,
            { "Vendor Unique Reject Code", "fcdns.rply.vendor",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_portid,
            { "Port Identifier", "fcdns.req.portid",
              FT_BYTES, SEP_DOT, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_pname,
            { "Port Name", "fcdns.rply.pname",
              FT_FCWWN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_nname,
            { "Node Name", "fcdns.rply.nname",
              FT_FCWWN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_gft,
            { "FC-4 Types Supported", "fcdns.rply.gft",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_snamelen,
            { "Symbolic Node Name Length", "fcdns.rply.snamelen",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_sname,
            { "Symbolic Node Name", "fcdns.rply.sname",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_ptype,
            { "Port Type", "fcdns.rply.porttype",
              FT_UINT8, BASE_HEX, VALS (fc_dns_port_type_val), 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_fpname,
            { "Fabric Port Name", "fcdns.rply.fpname",
              FT_FCWWN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4type,
            { "FC-4 Types", "fcdns.req.fc4types",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_fc4type,
            { "FC-4 Descriptor Type", "fcdns.rply.fc4type",
              FT_UINT8, BASE_HEX, VALS (fc_fc4_val), 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_fc4desc,
            { "FC-4 Descriptor", "fcdns.rply.fc4desc",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_pname,
            { "Port Name", "fcdns.req.portname",
              FT_FCWWN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_portid,
            { "Port Identifier", "fcdns.rply.portid",
              FT_BYTES, SEP_DOT, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_nname,
            { "Node Name", "fcdns.req.nname",
              FT_FCWWN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_domainscope,
            { "Domain ID Scope", "fcdns.req.domainid",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_areascope,
            { "Area ID Scope", "fcdns.req.areaid",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_ptype,
            { "Port Type", "fcdns.req.porttype",
              FT_UINT8, BASE_HEX, VALS (fc_dns_port_type_val), 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_cos,
            { "Requested Class of Service", "fcdns.req.class",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_fc4types,
            { "FC-4 Types Supported", "fcdns.req.fc4types",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_snamelen,
            { "Symbolic Name Length", "fcdns.req.snamelen",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_sname,
            { "Symbolic Port Name", "fcdns.req.sname",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_spnamelen,
            { "Symbolic Port Name Length", "fcdns.rply.spnamelen",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_spname,
            { "Symbolic Port Name", "fcdns.rply.spname",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_spnamelen,
            { "Symbolic Port Name Length", "fcdns.req.spnamelen",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_spname,
            { "Symbolic Port Name", "fcdns.req.spname",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_ipa,
            { "Initial Process Associator", "fcdns.rply.ipa",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_ipnode,
            { "Node IP Address", "fcdns.rply.ipnode",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_ipport,
            { "Port IP Address", "fcdns.rply.ipport",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_fc4desclen,
            { "FC-4 Descriptor Length", "fcdns.rply.fc4desclen",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_hrdaddr,
            { "Hard Address", "fcdns.rply.hrdaddr",
              FT_BYTES, SEP_DOT, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_fdesclen,
            { "FC-4 Descriptor Length", "fcdns.req.fc4desclen",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_fdesc,
            { "FC-4 Descriptor", "fcdns.req.fc4desc",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_req_ip,
            { "IP Address", "fcdns.req.ip",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rjtdetail,
            { "Reason Code Explanation", "fcdns.rply.reasondet",
              FT_UINT8, BASE_HEX, VALS (fc_dns_rjt_det_code_val), 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_zone_mbrtype,
            { "Zone Member Type", "fcdns.zone.mbrtype",
              FT_UINT8, BASE_HEX, VALS (fc_swils_zonembr_type_val), 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_zone_mbrid,
            { "Member Identifier", "fcdns.zone.mbrid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_zone_mbrid_wwn,
            { "Member Identifier", "fcdns.zone.mbrid.wwn",
              FT_FCWWN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_zone_mbrid_uint,
            { "Member Identifier", "fcdns.zone.mbrid.uint",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_zone_mbrid_fc,
            { "Member Identifier", "fcdns.zone.mbrid.fc",
              FT_BYTES, SEP_DOT, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_id_length,
            { "Identifier Length", "fcdns.id_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_zone_flags,
            { "Flags", "fcdns.zone_flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_zonelen,
            { "Name Length", "fcdns.zone_len",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_zonenm,
            { "Zone Name", "fcdns.zonename",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_portip,
            { "Port IP Address", "fcdns.portip",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_num_entries,
            { "Number of Entries", "fcdns.num_entries",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_sw2_objfmt,
            { "Name Entry Object Format", "fcdns.entry.objfmt",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_num_fc4desc,
            { "Number of FC4 Descriptors Registered", "fcdns.entry.numfc4desc",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_rply_ownerid,
            { "Owner Id", "fcdns.rply.ownerid",
              FT_BYTES, SEP_DOT, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_maxres_size,
            { "Maximum/Residual Size", "fcdns.maxres_size",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_reply_cos,
            { "Class of Service Supported", "fcdns.reply.cos",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_cos_f,
            { "F", "fcdns.cos.f",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x01,
              NULL, HFILL }
        },
        { &hf_fcdns_cos_1,
            { "1", "fcdns.cos.1",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x02,
              NULL, HFILL }
        },
        { &hf_fcdns_cos_2,
            { "2", "fcdns.cos.2",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x04,
              NULL, HFILL }
        },
        { &hf_fcdns_cos_3,
            { "3", "fcdns.cos.3",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x08,
              NULL, HFILL }
        },
        { &hf_fcdns_cos_4,
            { "4", "fcdns.cos.4",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x10,
              NULL, HFILL }
        },
        { &hf_fcdns_cos_6,
            { "6", "fcdns.cos.6",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x40,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4type_llcsnap,
            { "LLC/SNAP", "fcdns.fc4types.llc_snap",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0010,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4type_ip,
            { "IP", "fcdns.fc4types.ip",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0020,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4type_fcp,
            { "FCP", "fcdns.fc4types.fcp",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0100,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4type_swils,
            { "SW_ILS", "fcdns.fc4types.swils",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0010,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4type_snmp,
            { "SNMP", "fcdns.fc4types.snmp",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0004,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4type_gs3,
            { "GS3", "fcdns.fc4types.gs3",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0001,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4type_vi,
            { "VI", "fcdns.fc4types.vi",
              FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0001,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4features,
            { "FC-4 Feature Bits", "fcdns.fc4features",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4features_i,
            { "I", "fcdns.fc4features.i",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
              NULL, HFILL }
        },
        { &hf_fcdns_fc4features_t,
            { "T", "fcdns.fc4features.t",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
              NULL, HFILL }
        },
        { &hf_fcdns_req_fc4type,
            { "FC-4 Type", "fcdns.req.fc4type",
              FT_UINT8, BASE_HEX, VALS (fc_fc4_val), 0x0,
              NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_fcdns,
        &ett_cos_flags,
        &ett_fc4flags,
        &ett_fc4features,
    };

    static ei_register_info ei[] = {
        { &ei_fcdns_no_record_of_exchange, { "fcdns.no_record_of_exchange", PI_UNDECODED, PI_WARN, "No record of Exchg. Unable to decode MSG_ACC/RJT", EXPFILL }},
        { &ei_fcdns_zone_mbrid, { "fcdns.zone.mbrid.unknown_type", PI_PROTOCOL, PI_WARN, "Unknown member type format", EXPFILL }},
    };

    expert_module_t* expert_fcdns;

    proto_fcdns = proto_register_protocol("Fibre Channel Name Server", "FC-dNS", "fcdns");
    proto_register_field_array(proto_fcdns, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fcdns = expert_register_protocol(proto_fcdns);
    expert_register_field_array(expert_fcdns, ei, array_length(ei));

    fcdns_req_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), fcdns_hash, fcdns_equal);

    dns_handle = create_dissector_handle (dissect_fcdns, proto_fcdns);
}

void
proto_reg_handoff_fcdns (void)
{
    dissector_add_uint("fcct.server", FCCT_GSRVR_DNS, dns_handle);
    dissector_add_uint("fcct.server", FCCT_GSRVR_UNS, dns_handle);
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
