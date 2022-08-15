/* packet-nr-rrc-template.h
 * Copyright 2018-2022, Pascal Quantin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_NR_RRC_H
#define PACKET_NR_RRC_H

#include "packet-nr-rrc-exp.h"
int dissect_nr_rrc_nr_RLF_Report_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_subCarrierSpacingCommon_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_rach_ConfigCommonIAB_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
#endif  /* PACKET_NR_RRC_H */
