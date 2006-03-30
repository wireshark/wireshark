/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-gsm_map.h                                                         */
/* ../../tools/asn2eth.py -X -b -e -p gsm_map -c gsmmap.cnf -s packet-gsm_map-template GSMMAP.asn */

/* Input file: packet-gsm_map-template.h */

#line 1 "packet-gsm_map-template.h"
/* packet-gsm_map-template.h
 * Routines for GSM MAP packet dissection
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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

#ifndef PACKET_GSM_MAP_H
#define PACKET_GSM_MAP_H

/* Defines for the GSM MAP taps */
#define	GSM_MAP_MAX_NUM_OPR_CODES	256

typedef struct _gsm_map_tap_rec_t {
    gboolean		invoke;
    guint8		opr_code_idx;
    guint16		size;
} gsm_map_tap_rec_t;

ETH_VAR_IMPORT const value_string gsm_map_opr_code_strings[];
char* unpack_digits(tvbuff_t *tvb, int offset);

extern const value_string ssCode_vals[];
extern const value_string gsm_map_PDP_Type_Organisation_vals[];
extern const value_string gsm_map_ietf_defined_pdp_vals[];
extern const value_string gsm_map_etsi_defined_pdp_vals[];

/*--- Included file: packet-gsm_map-exp.h ---*/
#line 1 "packet-gsm_map-exp.h"
extern const value_string gsm_map_NotificationToMSUser_vals[];
extern const value_string gsm_map_SubscriberState_vals[];
extern const value_string gsm_map_SS_Info_vals[];
extern const value_string gsm_map_InterrogateSS_Res_vals[];
extern const value_string gsm_map_GetPasswordArg_vals[];
extern const value_string gsm_map_Ext_BasicServiceCode_vals[];
int dissect_gsm_map_SupportedCamelPhases(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_ISDN_AddressString(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_QoS_Subscribed(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_Ext_QoS_Subscribed(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_Ext2_QoS_Subscribed(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LSAIdentity(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_SS_Status(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_CUG_Info(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_CUG_Index(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_CUG_Interlock(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_NotificationToMSUser(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_AlertingPattern(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_IMSI(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_IMEI(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LCSClientExternalID(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LCSServiceTypeID(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LAIFixedLength(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LocationInformation(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_RAIdentity(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_GeographicalInformation(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_SubscriberState(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_GPRSChargingID(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_UU_Data(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_RegisterSS_Arg(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_SS_Info(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_InterrogateSS_Res(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_Ussd_Arg(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_Ussd_Res(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_USSD_DataCodingScheme(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_USSD_String(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_SS_Code(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_NewPassword(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_GetPasswordArg(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_CurrentPassword(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_RegisterCC_EntryRes(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_EraseCC_EntryArg(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_EraseCC_EntryRes(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_MS_Classmark2(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_OfferedCamel4Functionalities(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_SS_ForBS_Code(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_CCBS_Feature(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_AgeOfLocationInformation(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_Ext_BasicServiceCode(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_AddressString(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_ISDN_SubaddressString(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_GSN_Address(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LocationType(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_DeferredLocationEventType(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LCSClientName(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LCSRequestorID(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LCS_QoS(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_SupportedGADShapes(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LCS_ReferenceNumber(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_LCSCodeword(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_AreaEventInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_Ext_GeographicalInformation(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_Add_GeographicalInformation(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_SecurityHeader(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_ProtectedPayload(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);
int dissect_gsm_map_ExtensionContainer(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-gsm_map-exp.h ---*/
#line 46 "packet-gsm_map-template.h"

#endif  /* PACKET_GSM_MAP_H */
