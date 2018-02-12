/* packet-sscop.h
 * definitions for SSCOP (Q.2110, Q.SAAL) frame disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

typedef struct _sscop_info_t {
	guint8 type;
	guint32 payload_len;
} sscop_info_t;

typedef struct _sscop_payload_info {
	dissector_handle_t subdissector;
} sscop_payload_info;

typedef enum {
  DATA_DISSECTOR = 1,
  Q2931_DISSECTOR = 2,
  SSCF_NNI_DISSECTOR = 3,
  ALCAP_DISSECTOR = 4,
  NBAP_DISSECTOR = 5
} Dissector_Option;

extern gboolean sscop_allowed_subdissector(dissector_handle_t handle);
extern void dissect_sscop_and_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dissector_handle_t handle);
