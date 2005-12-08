/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-dap.h                                                             */
/* ../../tools/asn2eth.py -X -b -e -p dap -c dap.cnf -s packet-dap-template dap.asn */

/* Input file: packet-dap-template.h */

#line 1 "packet-dap-template.h"
/* packet-dap.h
 * Routines for X.511 (X.500 Directory Access Protocol) packet dissection
 * Graeme Lunt 2005
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_DAP_H
#define PACKET_DAP_H


/*--- Included file: packet-dap-exp.h ---*/
#line 1 "packet-dap-exp.h"
extern const value_string dap_ContextSelection_vals[];
extern const value_string dap_DirectoryBindError_vals[];
extern const value_string dap_ReadArgument_vals[];
extern const value_string dap_ReadResult_vals[];
extern const value_string dap_CompareArgument_vals[];
extern const value_string dap_CompareResult_vals[];
extern const value_string dap_AbandonArgument_vals[];
extern const value_string dap_AbandonResult_vals[];
extern const value_string dap_ListArgument_vals[];
extern const value_string dap_ListResult_vals[];
extern const value_string dap_SearchArgument_vals[];
extern const value_string dap_SearchResult_vals[];
extern const value_string dap_AddEntryArgument_vals[];
extern const value_string dap_AddEntryResult_vals[];
extern const value_string dap_RemoveEntryArgument_vals[];
extern const value_string dap_RemoveEntryResult_vals[];
extern const value_string dap_ModifyEntryArgument_vals[];
extern const value_string dap_ModifyEntryResult_vals[];
extern const value_string dap_EntryModification_vals[];
extern const value_string dap_ModifyDNResult_vals[];
extern const value_string dap_Abandoned_vals[];
extern const value_string dap_AbandonFailedError_vals[];
extern const value_string dap_AttributeError_vals[];
extern const value_string dap_NameError_vals[];
extern const value_string dap_Referral_vals[];
extern const value_string dap_SecurityError_vals[];
extern const value_string dap_ServiceError_vals[];
extern const value_string dap_UpdateError_vals[];
int dissect_dap_CommonResults(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ContextSelection(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_SecurityParameters(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_DirectoryBindArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_DirectoryBindError(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ReadArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ReadResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_CompareArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_CompareResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_AbandonArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_AbandonResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ListArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ListResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_SearchArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_SearchResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_AddEntryArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_AddEntryResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_RemoveEntryArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_RemoveEntryResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ModifyEntryArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ModifyEntryResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_EntryModification(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ModifyDNArgument(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ModifyDNResult(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_Abandoned(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_AbandonFailedError(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_AttributeError(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_NameError(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_Referral(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_SecurityError(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_ServiceError(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_UpdateError(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_dap_OperationalBindingID(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-dap-exp.h ---*/
#line 30 "packet-dap-template.h"

#endif  /* PACKET_DAP_H */
