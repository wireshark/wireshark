/* packet-dcom-dispatch.h
 * Routines for DCOM IDispatch
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* see packet-dcom.c for details about DCOM */

#ifndef __PACKET_DCERPC_DCOM_DISPATCH_H
#define __PACKET_DCERPC_DCOM_DISPATCH_H

WS_DLL_PUBLIC int
dissect_IDispatch_GetTypeInfoCount_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

WS_DLL_PUBLIC int
dissect_IDispatch_GetTypeInfo_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

WS_DLL_PUBLIC int
dissect_IDispatch_GetTypeInfo_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

WS_DLL_PUBLIC int
dissect_IDispatch_GetIDsOfNames_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

WS_DLL_PUBLIC int
dissect_IDispatch_GetIDsOfNames_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

WS_DLL_PUBLIC int
dissect_IDispatch_Invoke_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

WS_DLL_PUBLIC int
dissect_IDispatch_Invoke_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

#endif /* __PACKET_DCERPC_DCOM_DISPATCH_H */
