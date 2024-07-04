/* packet-s1ap.h
 * Routines for E-UTRAN S1 Application Protocol (S1AP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_S1AP_H
#define PACKET_S1AP_H

typedef struct _s1ap_ctx_t {
  uint32_t message_type;
  uint32_t ProcedureCode;
  uint32_t ProtocolIE_ID;
  uint32_t ProtocolExtensionID;
} s1ap_ctx_t;

extern const value_string s1ap_warningType_vals[];
extern const value_string s1ap_serialNumber_gs_vals[];

void dissect_s1ap_warningMessageContents(tvbuff_t *warning_msg_tvb, proto_tree *tree, packet_info *pinfo, uint8_t dcs, int hf_nb_pages, int hf_decoded_page);

#include "packet-s1ap-exp.h"

#endif  /* PACKET_S1AP_H */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
