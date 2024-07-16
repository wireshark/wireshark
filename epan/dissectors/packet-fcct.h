/* packet-fcct.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
extern uint8_t get_gs_server (uint8_t type, uint8_t subtype);

typedef struct _fc_ct_preamble {
    uint32_t in_id:24,
            revision:8;
    uint8_t gstype;
    uint8_t gssubtype;
    uint8_t options;
    uint8_t rsvd1;
    uint16_t opcode;
    uint16_t maxres_size;
    uint8_t rsvd2;
    uint8_t rjt_code;
    uint8_t rjt_code_det;
    uint8_t rjt_code_vendor;
} fc_ct_preamble;

typedef struct _fc_ct_ext_hdr {
    uint32_t auth_said;
    uint32_t tid;
    uint32_t req_pname[2];
    uint32_t timestamp[2];
    uint32_t auth_hashblk[15];
} fc_ct_ext_hdr;

#endif
