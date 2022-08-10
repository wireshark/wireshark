/* packet-lpp.h
 * Routines for 3GPP LTE Positioning Protocol (LPP) packet dissection
 * Copyright 2011-2022 Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef PACKET_LPP_H
#define PACKET_LPP_H

typedef enum {
    LPP_POS_SIB_TYPE_UNKNOWN,
    LPP_POS_SIB_TYPE_1_1,
    LPP_POS_SIB_TYPE_1_2,
    LPP_POS_SIB_TYPE_1_3,
    LPP_POS_SIB_TYPE_1_4,
    LPP_POS_SIB_TYPE_1_5,
    LPP_POS_SIB_TYPE_1_6,
    LPP_POS_SIB_TYPE_1_7,
    LPP_POS_SIB_TYPE_1_8,
    LPP_POS_SIB_TYPE_1_9,
    LPP_POS_SIB_TYPE_1_10,
    LPP_POS_SIB_TYPE_2_1,
    LPP_POS_SIB_TYPE_2_2,
    LPP_POS_SIB_TYPE_2_3,
    LPP_POS_SIB_TYPE_2_4,
    LPP_POS_SIB_TYPE_2_5,
    LPP_POS_SIB_TYPE_2_6,
    LPP_POS_SIB_TYPE_2_7,
    LPP_POS_SIB_TYPE_2_8,
    LPP_POS_SIB_TYPE_2_9,
    LPP_POS_SIB_TYPE_2_10,
    LPP_POS_SIB_TYPE_2_11,
    LPP_POS_SIB_TYPE_2_12,
    LPP_POS_SIB_TYPE_2_13,
    LPP_POS_SIB_TYPE_2_14,
    LPP_POS_SIB_TYPE_2_15,
    LPP_POS_SIB_TYPE_2_16,
    LPP_POS_SIB_TYPE_2_17,
    LPP_POS_SIB_TYPE_2_18,
    LPP_POS_SIB_TYPE_2_19,
    LPP_POS_SIB_TYPE_2_20,
    LPP_POS_SIB_TYPE_2_21,
    LPP_POS_SIB_TYPE_2_22,
    LPP_POS_SIB_TYPE_2_23,
    LPP_POS_SIB_TYPE_2_24,
    LPP_POS_SIB_TYPE_2_25,
    LPP_POS_SIB_TYPE_3_1,
    LPP_POS_SIB_TYPE_4_1,
    LPP_POS_SIB_TYPE_5_1,
    LPP_POS_SIB_TYPE_6_1,
    LPP_POS_SIB_TYPE_6_2,
    LPP_POS_SIB_TYPE_6_3,
    LPP_POS_SIB_TYPE_6_4,
    LPP_POS_SIB_TYPE_6_5,
    LPP_POS_SIB_TYPE_6_6,
} lpp_pos_sib_type_t;

int dissect_lpp_AssistanceDataSIBelement_r15_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, lpp_pos_sib_type_t pos_sib_type);

#include "packet-lpp-exp.h"

#endif  /* PACKET_LPP_H */
