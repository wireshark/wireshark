/* packet-gsm_ss.h
 *
 * $Id$
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

typedef enum
{
    GSM_SS_ETT_SEQUENCE,
    GSM_SS_ETT_PARAM
}
gsm_ss_ett_e;
#define	NUM_GSM_SS_ETT	sizeof(gsm_ss_ett_e)
extern gint gsm_ss_ett[];

extern const value_string gsm_ss_opr_code_strings[];
extern const value_string gsm_ss_err_code_strings[];

extern void param_AddressString(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field);
extern void gsm_ss_dissect(ASN1_SCK *asn1, proto_tree *tree, guint exp_len, guint opr_code, guint comp_type_tag);
