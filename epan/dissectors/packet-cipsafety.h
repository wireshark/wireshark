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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef PACKET_CIPSAFETY_H
#define PACKET_CIPSAFETY_H

#include "packet-enip.h"

/* Classes that have class-specfic dissectors */
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

typedef struct cip_safety_info {
   enum enip_connid_type conn_type;
   enum cip_safety_format_type format;
   gboolean server_dir;
} cip_safety_info_t;


/*
** Exported functions
*/
extern void dissect_unid(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_item *pi, const char* ssn_name, int hf_ssn_timestamp,
             int hf_ssn_date, int hf_ssn_time, int hf_macid, gint ett, gint ett_ssn);
extern void dissect_cipsafety_ssn(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int hf_real_datetime, int hf_date, int hf_time);

/*
** Exported variables
*/
extern const value_string cipsafety_ssn_date_vals[8];
extern attribute_info_t cip_safety_attribute_vals[52];

#endif /* PACKET_CIPSAFETY_H */
