/* packet-lnet.h
 * Copyright (c) 2017 Intel Corporation.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_LNET_H__
#define __PACKET_LNET_H__

#include <epan/packet.h>

#define portal_index_VALUE_STRING_LIST(XXX) \
    XXX(LNET_RESERVED_PORTAL, 0) \
    XXX(CONNMGR_REQUEST_PORTAL, 1) \
    XXX(CONNMGR_REPLY_PORTAL, 2) \
    XXX(OSC_REQUEST_PORTAL, 3) \
    XXX(OSC_REPLY_PORTAL, 4) \
    XXX(OSC_BULK_PORTAL, 5) \
    XXX(OST_IO_PORTAL, 6) \
    XXX(OST_CREATE_PORTAL, 7) \
    XXX(OST_BULK_PORTAL, 8) \
    XXX(MDC_REQUEST_PORTAL, 9) \
    XXX(MDC_REPLY_PORTAL, 10) \
    XXX(MDC_BULK_PORTAL, 11) \
    XXX(MDS_REQUEST_PORTAL, 12) \
    XXX(MDS_REPLY_PORTAL, 13) \
    XXX(MDS_BULK_PORTAL, 14) \
    XXX(LDLM_CB_REQUEST_PORTAL, 15) \
    XXX(LDLM_CB_REPLY_PORTAL, 16) \
    XXX(LDLM_CANCEL_REQUEST_PORTAL, 17) \
    XXX(LDLM_CANCEL_REPLY_PORTAL, 18) \
    XXX(PTLBD_REQUEST_PORTAL, 19) \
    XXX(PTLBD_REPLY_PORTAL, 20) \
    XXX(PTLBD_BULK_PORTAL, 21) \
    XXX(MDS_SETATTR_PORTAL, 22) \
    XXX(MDS_READPAGE_PORTAL, 23) \
    XXX(MDS_MDS_PORTAL, 24) \
    XXX(MGC_REPLY_PORTAL, 25) \
    XXX(MGS_REQUEST_PORTAL, 26) \
    XXX(MGS_REPLY_PORTAL, 27) \
    XXX(OST_REQUEST_PORTAL, 28) \
    XXX(FLD_REQUEST_PORTAL, 29) \
    XXX(SEQ_METADATA_PORTAL, 30) \
    XXX(SEQ_DATA_PORTAL, 31) \
    XXX(SEQ_CONTROLLER_PORTAL, 32) \
    XXX(MGS_BULK_PORTAL, 33)
VALUE_STRING_ENUM2(portal_index);
//VALUE_STRING_ARRAY2(portal_index);

struct lnet_trans_info {
    uint64_t match_bits;
};

int lnet_dissect_struct_nid(tvbuff_t *tvb, proto_tree *parent_tree, int offset, int hf_index);

#endif
