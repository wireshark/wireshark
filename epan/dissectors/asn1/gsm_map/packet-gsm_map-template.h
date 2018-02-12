/* packet-gsm_map-template.h
 * Routines for GSM MAP packet dissection
 * Copyright 2004 - 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_GSM_MAP_H
#define PACKET_GSM_MAP_H

#include "ws_symbol_export.h"

/* Defines for the GSM MAP taps */
#define	GSM_MAP_MAX_NUM_OPR_CODES	256

typedef struct _gsm_map_tap_rec_t {
  gboolean invoke;
  guint32  opcode;
  guint16  size;
} gsm_map_tap_rec_t;


#define SMS_ENCODING_NOT_SET	0
#define SMS_ENCODING_7BIT		1
#define SMS_ENCODING_8BIT		2
#define SMS_ENCODING_UCS2		3
#define SMS_ENCODING_7BIT_LANG	4
#define SMS_ENCODING_UCS2_LANG	5

WS_DLL_PUBLIC const value_string gsm_map_opr_code_strings[];

extern const value_string ssCode_vals[];
extern const value_string gsm_map_PDP_Type_Organisation_vals[];
extern const value_string gsm_map_ietf_defined_pdp_vals[];
extern const value_string gsm_map_etsi_defined_pdp_vals[];

guint8 dissect_cbs_data_coding_scheme(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 offset);
void dissect_gsm_map_msisdn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree);

typedef enum {
  GSM_MAP_SM_RP_OA_NO_ID = 0,
  GSM_MAP_SM_RP_OA_MSISDN,
  GSM_MAP_SM_RP_OA_SERVICE_CENTER_ADDRESS
} gsm_map_sm_rp_oa_id;

typedef enum {
  GSM_MAP_SM_RP_DA_NO_ID = 0,
  GSM_MAP_SM_RP_DA_IMSI,
  GSM_MAP_SM_RP_DA_LMSI,
  GSM_MAP_SM_RP_DA_SERVICE_CENTER_ADDRESS
} gsm_map_sm_rp_da_id;

/* structure accessible via p_get_proto_data(wmem_file_scope(), pinfo, proto_gsm_map, 0) */
typedef struct {
  gsm_map_sm_rp_oa_id sm_rp_oa_id;
  const gchar *sm_rp_oa_str;
  gsm_map_sm_rp_da_id sm_rp_da_id;
  const gchar *sm_rp_da_str;
  guint32 tcap_src_tid;
} gsm_map_packet_info_t;

#include "packet-gsm_map-exp.h"


#endif  /* PACKET_GSM_MAP_H */
