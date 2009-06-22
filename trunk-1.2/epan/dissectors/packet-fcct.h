/* packet-fcct.h
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_FCCT_H_
#define __PACKET_FCCT_H_

/* Well-known GSTYPEs */
#define FCCT_GSTYPE_KEYSVC   0xF7
#define FCCT_GSTYPE_ALIASSVC 0xF8
#define FCCT_GSTYPE_MGMTSVC  0xFA
#define FCCT_GSTYPE_TIMESVC  0xFB
#define FCCT_GSTYPE_DIRSVC   0xFC
#define FCCT_GSTYPE_FCTLR    0xFD
#define FCCT_GSTYPE_VENDOR   0xE0

/* Well-known GSSUBTYPES */
/* Actual servers serving the directory service type identified by subtype */
#define FCCT_GSSUBTYPE_FCTLR 0x0
#define FCCT_GSSUBTYPE_DNS  0x02
#define FCCT_GSSUBTYPE_IP   0x03
#define FCCT_GSSUBTYPE_FCS  0x01
#define FCCT_GSSUBTYPE_UNS  0x02
#define FCCT_GSSUBTYPE_FZS  0x03
#define FCCT_GSSUBTYPE_AS   0x01
#define FCCT_GSSUBTYPE_TS   0x01

/* Derived field: Server servicing the request */
#define FCCT_GSRVR_DNS       0x1
#define FCCT_GSRVR_IP        0x2
#define FCCT_GSRVR_FCS       0x3
#define FCCT_GSRVR_UNS       0x4
#define FCCT_GSRVR_FZS       0x5
#define FCCT_GSRVR_AS        0x6
#define FCCT_GSRVR_TS        0x7
#define FCCT_GSRVR_KS        0x8
#define FCCT_GSRVR_FCTLR     0x9
#define FCCT_GSRVR_UNKNOWN   0xFF

/* Reject code definitions */
#define FCCT_RJT_INVCMDCODE    0x1
#define FCCT_RJT_INVVERSION    0x2
#define FCCT_RJT_LOGICALERR    0x3
#define FCCT_RJT_INVSIZE       0x4
#define FCCT_RJT_LOGICALBSY    0x5
#define FCCT_RJT_PROTOERR      0x7
#define FCCT_RJT_GENFAIL       0x9
#define FCCT_RJT_CMDNOTSUPP    0xB

#define FCCT_MSG_REQ_MAX       0x8000 /* All opcodes below this are requests */
#define FCCT_MSG_RJT           0x8001 /* Reject CT message */
#define FCCT_MSG_ACC           0x8002 /* Accept CT message */

#define FCCT_PRMBL_SIZE        16
#define FCCT_EXTPRMBL_SIZE     88

extern const value_string fc_ct_gstype_vals [];
extern const value_string fc_ct_gsserver_vals [];
extern const value_string fc_ct_rjt_code_vals [];
extern guint8 get_gs_server (guint8 type, guint8 subtype);

typedef struct _fc_ct_preamble {
    guint32 in_id:24,
            revision:8;
    guint8  gstype;
    guint8  gssubtype;
    guint8  options;
    guint8  rsvd1;
    guint16 opcode;
    guint16 maxres_size;
    guint8  rsvd2;
    guint8  rjt_code;
    guint8  rjt_code_det;
    guint8  rjt_code_vendor;
} fc_ct_preamble;

typedef struct _fc_ct_ext_hdr {
    guint32 auth_said;
    guint32 tid;
    guint32 req_pname[2];
    guint32 timestamp[2];
    guint32 auth_hashblk[15];
} fc_ct_ext_hdr;

#endif
