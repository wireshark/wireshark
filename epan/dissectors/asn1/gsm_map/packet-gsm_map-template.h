/* packet-gsm_map-template.h
 * Routines for GSM MAP packet dissection
 * Copyright 2004 - 2006, Anders Broman <anders.broman@ericsson.com>
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

#ifndef PACKET_GSM_MAP_H
#define PACKET_GSM_MAP_H

#include "ws_symbol_export.h"

/* Defines for the GSM MAP taps */
#define	GSM_MAP_MAX_NUM_OPR_CODES	256

typedef struct _gsm_map_tap_rec_t {
    gboolean		invoke;
    guint32		opcode;
    guint16		size;
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

#include "packet-gsm_map-exp.h"


#endif  /* PACKET_GSM_MAP_H */
