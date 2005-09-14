/* packet-fcswils.h
 * Fibre Channel Switch InterLink Services Definitions
 * Copyright 2001 Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id$
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
#define FC_SWILS_ESS            0x31
#define FC_SWILS_MRRA           0x34
#define FC_SWILS_AUTH_ILS       0x40
#define FC_SWILS_MAXCODE        0x35 /* the dissector jump table is sized to
                                        this table */

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

typedef struct _fcswils_efp {
    guint8  opcode;
    guint8  reclen;
    guint16 payload_len;
    guint8  rsvd1[3];
    guint8  pswitch_prio;
    guint8  pswitch_name[8];
} fcswils_efp;
#define FC_SWILS_EFP_SIZE 16

typedef struct _fcswils_dia {
    guint8 switch_name[8];
    guint8 rsvd[4];
} fcswils_dia;

typedef struct _fcswils_rdi_req {
    guint8 rsvd[3];
    guint8 domain_id;
} fcswils_rdi_req;
#define FC_SWILS_RDIREQ_SIZE 4

#define FC_SWILS_LSR_SLR    0x1 /* switch link record */
#define FC_SWILS_LSR_ARS    0x2 /* AR Summary record */

#define FC_SWILS_PDESC_FSPF_BB 0x01
#define FC_SWILS_PDESC_FSPF    0x02

#define FC_SWILS_ZONEOBJ_ZONESET    1
#define FC_SWILS_ZONEOBJ_ZONE       2
#define FC_SWILS_ZONEOBJ_ZONEALIAS  3

#define FC_SWILS_ZONEMBR_WWN             1
#define FC_SWILS_ZONEMBR_DP              2
#define FC_SWILS_ZONEMBR_FCID            3
#define FC_SWILS_ZONEMBR_ALIAS           4
#define FC_SWILS_ZONEMBR_WWN_LUN         0xE1
#define FC_SWILS_ZONEMBR_DP_LUN          0xE2
#define FC_SWILS_ZONEMBR_FCID_LUN        0xE3

extern const value_string fc_swils_zonembr_type_val[];

#endif
