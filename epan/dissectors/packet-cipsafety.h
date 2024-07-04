/* packet-cipsafety.h
 * Routines for CIP (Common Industrial Protocol) Safety dissection
 * CIP Safety Home: www.odva.org
 *
 * Copyright 2011
 * Michael Mann <mmann@pyramidsolutions.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PACKET_CIPSAFETY_H
#define PACKET_CIPSAFETY_H

#include "packet-enip.h"

/* Classes that have class-specific dissectors */
#define CI_CLS_SAFETY_SUPERVISOR   0x39    /* Safety Supervisor */
#define CI_CLS_SAFETY_VALIDATOR    0x3A    /* Safety Validator */

/* Class specific services */
/* Safety Supervisor */
#define SC_SSUPER_RECOVER                 0x4C
#define SC_SSUPER_PERFORM_DIAGNOSTICS     0x4E
#define SC_SSUPER_CONFIGURE_REQUEST       0x4F
#define SC_SSUPER_VALIDATE_CONFIGURATION  0x50
#define SC_SSUPER_SET_PASSWORD            0x51
#define SC_SSUPER_CONFIGURATION_LOCK      0x52
#define SC_SSUPER_MODE_CHANGE             0x53
#define SC_SSUPER_SAFETY_RESET            0x54
#define SC_SSUPER_RESET_PASSWORD          0x55
#define SC_SSUPER_PROPOSE_TUNID           0x56
#define SC_SSUPER_APPLY_TUNID             0x57
#define SC_SSUPER_PROPOSE_TUNID_LIST      0x58
#define SC_SSUPER_APPLY_TUNID_LIST        0x59

typedef struct cip_safety_info {
   enum enip_connid_type conn_type;
   cip_conn_info_t* eip_conn_info;
   bool compute_crc;
} cip_safety_info_t;


/*
** Exported functions
*/
extern void dissect_unid(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_item *pi, const char* snn_name, int hf_snn_timestamp,
             int hf_snn_date, int hf_snn_time, int hf_macid, int ett, int ett_snn);
extern void dissect_cipsafety_snn(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int hf_real_datetime, int hf_date, int hf_time);
extern void cip_safety_128us_fmt(char *s, uint32_t value);
extern void add_safety_data_type_to_info_column(packet_info *pinfo, enum enip_connid_type conn_type, const cip_safety_epath_info_t* safety);

/*
** Exported variables
*/
extern const value_string cipsafety_snn_date_vals[8];
extern const attribute_info_t cip_safety_attribute_vals[51];
extern const range_string safety_max_consumer_numbers[];

#endif /* PACKET_CIPSAFETY_H */
