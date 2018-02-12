/* packet-fcbls.h
 * Fibre Channel Basic Link Services header
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_FCBLS_H_
#define __PACKET_FCBLS_H_

#define FC_BLS_NOP          0x00
#define FC_BLS_ABTS         0x01
#define FC_BLS_RMC          0x02
#define FC_BLS_BAACC        0x04
#define FC_BLS_BARJT        0x05
#define FC_BLS_PRMT         0x06

#define FC_BLS_BARJT_INVCMDCODE     0x01
#define FC_BLS_BARJT_LOGERR         0x03
#define FC_BLS_BARJT_LOGBSY         0x05
#define FC_BLS_BARJT_PROTERR        0x07
#define FC_BLS_BARJT_GENFAIL        0x09
#define FC_BLS_BARJT_VENDOR         0xFF

static const value_string fc_bls_barjt_val[] = {
    {FC_BLS_BARJT_INVCMDCODE, "Invalid Cmd Code"},
    {FC_BLS_BARJT_LOGERR    , "Logical Error"},
    {FC_BLS_BARJT_LOGBSY    , "Logical Busy"},
    {FC_BLS_BARJT_PROTERR   , "Protocol Error"},
    {FC_BLS_BARJT_GENFAIL   , "Unable to Perform Cmd"},
    {FC_BLS_BARJT_VENDOR    , "Vendor Unique Error"},
    {0, NULL},
};

#define FC_BLS_BARJT_DET_NODET      0x01
#define FC_BLS_BARJT_DET_INVEXCHG   0x03
#define FC_BLS_BARJT_DET_SEQABT     0x05

static const value_string fc_bls_barjt_det_val[] = {
    {FC_BLS_BARJT_DET_NODET   , "No Details"},
    {FC_BLS_BARJT_DET_INVEXCHG, "Invalid OXID-RXID Combo"},
    {FC_BLS_BARJT_DET_SEQABT  , "Sequence Aborted"},
    {0, NULL},
};

static const value_string fc_bls_seqid_val[] = {
    {0x80, "Yes"},
    {0x0,  "No"},
    {0, NULL},
};

typedef struct _fc_bls_ba_rjt {
    guint8 rsvd;
    guint8 reason_code;
    guint8 rjt_detail;
    guint8 vendor_uniq;
} fc_bls_ba_rjt;

#endif
