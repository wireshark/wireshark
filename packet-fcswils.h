/* packet-fcswils.h
 * Fibre Channel Switch InterLink Services Definitions
 * Copyright 2001 Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id: packet-fcswils.h,v 1.1 2002/12/08 02:32:17 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_FCSWILS_H_
#define __PACKET_FCSWILS_H_

/* Command codes */
#define FC_SWILS_SWRJT          0x01
#define FC_SWILS_SWACC          0x02
#define FC_SWILS_ELP            0x10
#define FC_SWILS_EFP            0x11
#define FC_SWILS_DIA            0x12
#define FC_SWILS_RDI            0x13
#define FC_SWILS_HLO            0x14
#define FC_SWILS_LSU            0x15
#define FC_SWILS_LSA            0x16
#define FC_SWILS_BF             0x17
#define FC_SWILS_RCF            0x18
#define FC_SWILS_RSCN           0x1B
#define FC_SWILS_DRLIR          0x1E
#define FC_SWILS_DSCN           0x20
#define FC_SWILS_LOOPD          0x21
#define FC_SWILS_MR             0x22
#define FC_SWILS_ACA            0x23
#define FC_SWILS_RCA            0x24
#define FC_SWILS_SFC            0x25
#define FC_SWILS_UFC            0x26
#define FC_SWILS_ESC            0x30

/* Used in filters */
static const value_string fc_swils_opcode_key_val[] = {
    {FC_SWILS_SWRJT  , "SW_RJT"},
    {FC_SWILS_SWACC  , "SW_ACC"},
    {FC_SWILS_ELP    , "ELP"},
    {FC_SWILS_EFP    , "EFP"},
    {FC_SWILS_DIA    , "DIA"},
    {FC_SWILS_RDI    , "RDI"},
    {FC_SWILS_HLO    , "HLO"},
    {FC_SWILS_LSU    , "LSU"},
    {FC_SWILS_LSA    , "LSA"},
    {FC_SWILS_BF     , "BF"},
    {FC_SWILS_RCF    , "RCF"},
    {FC_SWILS_RSCN   , "SW_RSCN"},
    {FC_SWILS_DRLIR  , "DRLIR"},
    {FC_SWILS_DSCN   , "DSCN"},
    {FC_SWILS_LOOPD  , "LOOPD"},
    {FC_SWILS_MR     , "MR"},
    {FC_SWILS_ACA    , "ACA"},
    {FC_SWILS_RCA    , "RCA"},
    {FC_SWILS_SFC    , "SFC"},
    {FC_SWILS_UFC    , "UFC"},
    {FC_SWILS_ESC    , "ESC"},
    {0, NULL},
};

/* Used in Info field */
static const value_string fc_swils_opcode_val[] = {
    {FC_SWILS_SWRJT  , "SW_RJT"},
    {FC_SWILS_SWACC  , "SW_ACC"},
    {FC_SWILS_ELP    , "ELP"},
    {FC_SWILS_EFP    , "EFP"},
    {FC_SWILS_DIA    , "Domain ID Assigned"},
    {FC_SWILS_RDI    , "Request Domain ID"},
    {FC_SWILS_HLO    , "Hello"},
    {FC_SWILS_LSU    , "Link State Update"},
    {FC_SWILS_LSA    , "Link State Ack"},
    {FC_SWILS_BF     , "Build Fabric"},
    {FC_SWILS_RCF    , "Reconfigure Fabric"},
    {FC_SWILS_RSCN   , "Interswitch RSCN"},
    {FC_SWILS_DRLIR  , "DRLIR"},
    {FC_SWILS_DSCN   , "SW_RSCN"},
    {FC_SWILS_LOOPD  , "LOOPD"},
    {FC_SWILS_MR     , "Merge Req"},
    {FC_SWILS_ACA    , "Acquire Change Auth"},
    {FC_SWILS_RCA    , "Release Change Auth"},
    {FC_SWILS_SFC    , "Stage Fabric Conf"},
    {FC_SWILS_UFC    , "Update Fabric Conf"},
    {FC_SWILS_ESC    , "ESC"},
    {0, NULL},
};

/* Reject reason codes */

#define FC_SWILS_RJT_INVCODE       0x01
#define FC_SWILS_RJT_INVVER        0x02
#define FC_SWILS_RJT_LOGERR        0x03
#define FC_SWILS_RJT_INVSIZE       0x04
#define FC_SWILS_RJT_LOGBSY        0x05
#define FC_SWILS_RJT_PROTERR       0x07
#define FC_SWILS_RJT_GENFAIL       0x09
#define FC_SWILS_RJT_CMDNOTSUPP    0x0B
#define FC_SWILS_RJT_VENDUNIQ      0xFF

static const value_string fc_swils_rjt_val [] = {
    {FC_SWILS_RJT_INVCODE   , "Invalid Cmd Code"},
    {FC_SWILS_RJT_INVVER    , "Invalid Revision"},
    {FC_SWILS_RJT_LOGERR    , "Logical Error"},
    {FC_SWILS_RJT_INVSIZE   , "Invalid Size"},
    {FC_SWILS_RJT_LOGBSY    , "Logical Busy"},
    {FC_SWILS_RJT_PROTERR   , "Protocol Error"},
    {FC_SWILS_RJT_GENFAIL   , "Unable to Perform"},
    {FC_SWILS_RJT_CMDNOTSUPP, "Unsupported Cmd"},
    {FC_SWILS_RJT_VENDUNIQ  , "Vendor Unique Err"},
    {0, NULL},
};

/* Detailed reason code defines */
#define FC_SWILS_RJT_NODET         0x0
#define FC_SWILS_RJT_CLSF_ERR      0x1
#define FC_SWILS_RJT_CLSN_ERR      0x3
#define FC_SWILS_RJT_INVFC_CODE    0x4
#define FC_SWILS_RJT_INVFC_PARM    0x5
#define FC_SWILS_RJT_INV_PNAME     0xD
#define FC_SWILS_RJT_INV_SNAME     0xE
#define FC_SWILS_RJT_TOV_MSMTCH    0xF
#define FC_SWILS_RJT_INV_DIDLST    0x10
#define FC_SWILS_RJT_CMD_INPROG    0x19
#define FC_SWILS_RJT_OORSRC        0x29
#define FC_SWILS_RJT_NO_DID        0x2A
#define FC_SWILS_RJT_INV_DID       0x2B
#define FC_SWILS_RJT_NO_REQ        0x2C
#define FC_SWILS_RJT_NOLNK_PARM    0x2D
#define FC_SWILS_RJT_NO_REQDID     0x2E
#define FC_SWILS_RJT_EP_ISOL       0x2F

static const value_string fc_swils_deterr_val [] = {
    {FC_SWILS_RJT_NODET ,      "No Additional Details"},
    {FC_SWILS_RJT_CLSF_ERR ,   "Class F Svc Param Err"},
    {FC_SWILS_RJT_CLSN_ERR ,   "Class N Svc Param Err"},
    {FC_SWILS_RJT_INVFC_CODE , "Unknown Flow Ctrl Code"},
    {FC_SWILS_RJT_INVFC_PARM , "Invalid Flow Ctrl Parm"},
    {FC_SWILS_RJT_INV_PNAME ,  "Invalid Port Name"},
    {FC_SWILS_RJT_INV_SNAME ,  "Invalid Switch Name"},
    {FC_SWILS_RJT_TOV_MSMTCH , "R_A_/E_D_TOV Mismatch"},
    {FC_SWILS_RJT_INV_DIDLST,  "Invalid Domain ID List"},
    {FC_SWILS_RJT_CMD_INPROG , "Cmd Already in Progress"},
    {FC_SWILS_RJT_OORSRC ,     "Insufficient Resources"},
    {FC_SWILS_RJT_NO_DID ,     "Domain ID Unavailable"},
    {FC_SWILS_RJT_INV_DID,     "Invalid Domain ID"},
    {FC_SWILS_RJT_NO_REQ ,     "Request Not Supported"},
    {FC_SWILS_RJT_NOLNK_PARM , "Link Parm Not Estd."},
    {FC_SWILS_RJT_NO_REQDID ,  "Group of Domain IDs Unavail"},
    {FC_SWILS_RJT_EP_ISOL ,    "E_Port Isolated"},
    {0, NULL}
};

typedef struct _fcswils_elp {
    guint8 revision;
    guint8 flags[2];
    guint8 rsvd1;
    guint32 r_a_tov;
    guint32 e_d_tov;
    guint8  req_epname[8];
    guint8  req_sname[8];
    guint8  clsf_svcparm[6];
    guint16 clsf_rcvsize;
    guint16 clsf_conseq;
    guint16 clsf_e2e;
    guint16 clsf_openseq;
    guint16 rsvd;
    guint8  cls1_svcparm[2];
    guint16 cls1_rcvsize;
    guint8  cls2_svcparm[2];
    guint16 cls2_rcvsize;
    guint8  cls3_svcparm[2];
    guint16 cls3_rcvsize;
    guint8  rsvd2[20];
    guint16 isl_flwctrl_mode;
    guint16 flw_ctrl_parmlen;
    guint32 b2b_credit;
    guint32 compat_p1;
    guint32 compat_p2;
    guint32 compat_p3;
    guint32 compat_p4;
} fcswils_elp;
#define FC_SWILS_ELP_SIZE 100

#define FC_SWILS_ELP_FC_VENDOR   0x1
#define FC_SWILS_ELP_FC_RRDY     0x2

static const value_string fcswils_elp_fc_val[] = {
    {FC_SWILS_ELP_FC_VENDOR, "Vendor Unique"},
    {FC_SWILS_ELP_FC_RRDY,   "R_RDY Flow Ctrl"},
    {0, NULL},
};

struct _fcswils_efp_didrec {
    guint8 rec_type;
    guint8 dom_id;
    guint16 rsvd1;
    guint32 rsvd2;
    guint8  sname[8];
};
struct _fcswils_efp_mcastrec {
    guint8 rec_type;
    guint8 mcast_grpnum;
    guint8 rsvd[14];
};

typedef union _fcswils_efp_listrec {
    struct _fcswils_efp_didrec didrec;
    struct _fcswils_efp_mcastrec mcastrec;
} fcswils_efp_listrec;

#define FC_SWILS_LRECTYPE_DOMAIN 0x1
#define FC_SWILS_LRECTYPE_MCAST  0x2

static const value_string fcswils_rectype_val[] = {
    {FC_SWILS_LRECTYPE_DOMAIN, "Domain ID List Rec"},
    {FC_SWILS_LRECTYPE_MCAST, "Multicast ID List Rec"},
    {0, NULL},
};

typedef struct _fcswils_efp {
    guint8  opcode;
    guint8  reclen;
    guint16 payload_len;
    guint8  rsvd1[3];
    guint8  pswitch_prio;
    guint8  pswitch_name[8];
    fcswils_efp_listrec *listrec;
} fcswils_efp;
#define FC_SWILS_EFP_SIZE 16    /* not including listrec */

typedef struct _fcswils_dia {
    guint8 switch_name[8];
    guint8 rsvd[4];
} fcswils_dia;

typedef struct _fcswils_rdi_req {
    guint8 rsvd[3];
    guint8 domain_id;
} fcswils_rdi_req;
#define FC_SWILS_RDIREQ_SIZE 4

static const value_string fc_swils_link_type_val[] = {
    {0x01, "P2P Link"},
    {0xF0, "Vendor Specific"},
    {0xF1, "Vendor Specific"},
    {0xF2, "Vendor Specific"},
    {0xF3, "Vendor Specific"},
    {0xF4, "Vendor Specific"},
    {0xF5, "Vendor Specific"},
    {0xF6, "Vendor Specific"},
    {0xF7, "Vendor Specific"},
    {0xF8, "Vendor Specific"},
    {0xF9, "Vendor Specific"},
    {0xFA, "Vendor Specific"},
    {0xFB, "Vendor Specific"},
    {0xFC, "Vendor Specific"},
    {0xFD, "Vendor Specific"},
    {0xFE, "Vendor Specific"},
    {0xFF, "Vendor Specific"},
    {0, NULL},
};

#define FC_SWILS_LSR_SLR    0x1 /* switch link record */
#define FC_SWILS_LSR_ARS    0x2 /* AR Summary record */

static const value_string fc_swils_fspf_linkrec_val[] = {
    {FC_SWILS_LSR_SLR, "Switch Link Record"},
    {FC_SWILS_LSR_ARS, "AR Summary Record"},
    {0, NULL},
};

static const value_string fc_swils_fspf_lsrflags_val[] = {
    {0x0, "LSR is for a Topology Update"},
    {0x1, "LSR is for Initial DB Sync | Not the last seq in DB sync"},
    {0x2, "Last Seq in DB Sync. LSU has no LSRs"},
    {0x3, "LSR is for Initial DB Sync | Last Seq in DB Sync"},
    {0, NULL},
};

#define FC_SWILS_PDESC_FSPF_BB 0x01
#define FC_SWILS_PDESC_FSPF    0x02

static const value_string fc_swils_rscn_portstate_val[] = {
    {0, "No Additional Info"},
    {1, "Port is online"},
    {2, "Port is offline"},
    {0, NULL},
};

static const value_string fc_swils_rscn_addrfmt_val[] = {
    {0, "Port Addr Format"},
    {1, "Area Addr Format"},
    {2, "Domain Addr Format"},
    {3, "Fabric Addr Format"},
};

static const value_string fc_swils_rscn_detectfn_val[] = {
    {1, "Fabric Detected"},
    {2, "N_Port Detected"},
    {0, NULL},
};

static const value_string fc_swils_esc_protocol_val[] = {
    {0, "Reserved"},
    {1, "FSPF-Backbone Protocol"},
    {2, "FSPF Protocol"},
    {0, NULL},
};

#define FC_SWILS_ZONEOBJ_ZONESET    1
#define FC_SWILS_ZONEOBJ_ZONE       2
#define FC_SWILS_ZONEOBJ_ZONEALIAS  3

static const value_string fc_swils_zoneobj_type_val[] = {
    {0, "Reserved"},
    {FC_SWILS_ZONEOBJ_ZONESET  , "Zone Set"},
    {FC_SWILS_ZONEOBJ_ZONE     , "Zone"},
    {FC_SWILS_ZONEOBJ_ZONEALIAS, "Zone Alias"},
    {0, NULL},
};

#define FC_SWILS_ZONEMBR_WWN             1
#define FC_SWILS_ZONEMBR_DP              2
#define FC_SWILS_ZONEMBR_FCID            3
#define FC_SWILS_ZONEMBR_ALIAS           4
#define FC_SWILS_ZONEMBR_WWN_LUN         0xE1
#define FC_SWILS_ZONEMBR_DP_LUN          0xE2
#define FC_SWILS_ZONEMBR_FCID_LUN        0xE3

static const value_string fc_swils_zonembr_type_val[] = {
    {0, "Reserved"},
    {FC_SWILS_ZONEMBR_WWN, "WWN"},
    {FC_SWILS_ZONEMBR_DP, "Domain/Physical Port (0x00ddpppp)"},
    {FC_SWILS_ZONEMBR_FCID, "FC Address"},
    {FC_SWILS_ZONEMBR_ALIAS, "Zone Alias"},
    {FC_SWILS_ZONEMBR_WWN_LUN, "WWN+LUN"},
    {FC_SWILS_ZONEMBR_DP_LUN, "Domain/Physical Port+LUN"},
    {FC_SWILS_ZONEMBR_FCID_LUN, "FCID+LUN"},
    {0, NULL},
};

static const value_string fc_swils_mr_rsp_val[] = {
    {0, "Successful"},
    {1, "Fabric Busy"},
    {2, "Failed"},
    {0, NULL},
};

static const value_string fc_swils_mr_reason_val[] = {
    {0x0, "No Reason"},
    {0x1, "Invalid Data Length"},
    {0x2, "Unsupported Command"},
    {0x3, "Reserved"},
    {0x4, "Not Authorized"},
    {0x5, "Invalid Request"},
    {0x6, "Fabric Changing"},
    {0x7, "Update Not Staged"},
    {0x8, "Invalid Zone Set Format"},
    {0x9, "Invalid Data"},
    {0xA, "Cannot Merge"},
    {0, NULL},
};

static const value_string fc_swils_sfc_op_val[] = {
    {0, "Reserved"},
    {1, "Reserved"},
    {2, "Reserved"},
    {3, "Activate Zone Set"},
    {4, "Deactivate Zone Set"},
    {0, NULL},
};

#endif
