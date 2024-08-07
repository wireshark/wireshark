/* packet-dcom.h
 * Routines for DCOM generics
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DCOM_H
#define __PACKET_DCOM_H

#include "ws_symbol_export.h"

WS_DLL_PUBLIC const value_string dcom_hresult_vals[];
WS_DLL_PUBLIC const value_string dcom_variant_type_vals[];
extern const value_string dcom_protseq_vals[];

extern int hf_dcom_iid;
extern int hf_dcom_clsid;
extern int hf_dcom_oxid;
extern int hf_dcom_oid;
extern int hf_dcom_ipid;

extern GHashTable *dcom_uuids;

/* preferences */
WS_DLL_PUBLIC bool dcom_prefs_display_unmarshalling_details;


typedef struct dcom_machine_s {
    GList           *objects;
    int             first_packet;

    address         ip;
} dcom_machine_t;

typedef struct dcom_object_s {
    dcom_machine_t  *parent;
    GList           *interfaces;
    void            *private_data;
    int             first_packet;

    uint64_t        oid;
    uint64_t        oxid;
} dcom_object_t;

typedef struct dcom_interface_s {
    dcom_object_t   *parent;
    void            *private_data;
    int             first_packet;

    e_guid_t        iid;
    e_guid_t        ipid;   /* the DCE/RPC Object UUID */
} dcom_interface_t;

typedef int (*dcom_dissect_fn_t) (tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int size);

typedef struct dcom_marshaler_s {
    dcom_object_t   *parent;
    void            *private_data;

    e_guid_t        uuid;
    dcom_dissect_fn_t routine;
} dcom_marshaler_t;

WS_DLL_PUBLIC dcom_interface_t *dcom_interface_new(packet_info *pinfo, const address *addr, e_guid_t *iid, uint64_t oxid, uint64_t oid, e_guid_t *ipid);
WS_DLL_PUBLIC dcom_interface_t *dcom_interface_find(packet_info *pinfo, const address *addr, e_guid_t *ipid);
#ifdef DEBUG
extern void dcom_interface_dump(void);
#endif
extern int dcom_register_routine(dcom_dissect_fn_t routine, e_guid_t* uuid);
extern void dcom_register_common_routines_(void);

extern dcom_dissect_fn_t dcom_get_routine_by_uuid(const e_guid_t* uuid);

/* the essential DCOM this and that, starting every call */
WS_DLL_PUBLIC int
dissect_dcom_this(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);
WS_DLL_PUBLIC int
dissect_dcom_that(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);


/* dissection of somewhat more simple data types */
#define dissect_dcom_BOOLEAN		dissect_ndr_uint8
#define dissect_dcom_BYTE			dissect_ndr_uint8
#define dissect_dcom_WORD			dissect_ndr_uint16
#define dissect_dcom_DWORD			dissect_ndr_uint32
#define dissect_dcom_I8			dissect_ndr_uint64
#define dissect_dcom_ID				dissect_ndr_duint32
#define dissect_dcom_FILETIME		dissect_ndr_duint32 /* ToBeDone */
#define dissect_dcom_VARIANT_BOOL	dissect_ndr_uint16
#define dissect_dcom_FLOAT			dissect_ndr_float
#define dissect_dcom_DOUBLE			dissect_ndr_double
#define dissect_dcom_DATE			dissect_ndr_double

WS_DLL_PUBLIC int
dissect_dcom_UUID(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep,
	int hfindex, e_guid_t *uuid);

WS_DLL_PUBLIC int
dissect_dcom_append_UUID(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep,
	int hfindex, int field_index, e_guid_t *uuid);

extern int
dissect_dcom_indexed_WORD(tvbuff_t *tvb, int offset,	packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, uint8_t *drep,
					 int hfindex, uint16_t * pu16WORD, int field_index);

WS_DLL_PUBLIC int
dissect_dcom_indexed_DWORD(tvbuff_t *tvb, int offset,	packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, uint8_t *drep,
					 int hfindex, uint32_t * pu32DWORD, int field_index);

WS_DLL_PUBLIC int
dissect_dcom_HRESULT(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep, uint32_t * pu32hresult);

WS_DLL_PUBLIC int
dissect_dcom_HRESULT_item(tvbuff_t *tvb, int offset,	packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, uint8_t *drep,
					 uint32_t * pu32HResult, int field_index, proto_item **item);

WS_DLL_PUBLIC int
dissect_dcom_indexed_HRESULT(tvbuff_t *tvb, int offset,	packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, uint8_t *drep,
					 uint32_t * pu32hresult, int field_index);

extern int
dissect_dcom_COMVERSION(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep,
	uint16_t	* pu16version_major, uint16_t * pu16version_minor);

typedef void (*sa_callback_t) (tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep,
                       uint32_t u32VarType, uint32_t u32ArraySize);

WS_DLL_PUBLIC int
dissect_dcom_SAFEARRAY(tvbuff_t *tvb, int offset, packet_info *pinfo,
						proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex _U_, sa_callback_t sacb);

WS_DLL_PUBLIC int
dissect_dcom_LPWSTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex,
					   char *psz_buffer, uint32_t u32max_buffer);

WS_DLL_PUBLIC int
dissect_dcom_indexed_LPWSTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex,
					   char *pszStr, uint32_t u32MaxStr, int field_index);

WS_DLL_PUBLIC int
dissect_dcom_BSTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex,
					   char *psz_buffer, uint32_t u32max_buffer);

extern int
dissect_dcom_DUALSTRINGARRAY(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, char *ip);

extern int
dissect_dcom_STDOBJREF(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex,
                       uint64_t *oxid, uint64_t *oid, e_guid_t *ipid);
extern int
dissect_dcom_OBJREF(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, dcom_interface_t **interf);

WS_DLL_PUBLIC int
dissect_dcom_MInterfacePointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, dcom_interface_t **interf);
WS_DLL_PUBLIC int
dissect_dcom_PMInterfacePointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex, dcom_interface_t **interf);

WS_DLL_PUBLIC int
dissect_dcom_VARTYPE(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep,
	uint16_t *pu16Vartype);

WS_DLL_PUBLIC int
dissect_dcom_VARIANT(tvbuff_t *tvb, int offset, packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex);

/* dcom "dcerpc internal" unmarshalling */
WS_DLL_PUBLIC int
dissect_dcom_dcerpc_array_size(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, uint32_t *pu32array_size);

WS_DLL_PUBLIC int
dissect_dcom_dcerpc_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, uint8_t *drep, uint32_t *pu32pointer);

/* mark things as "to be done" */
extern int
dissect_dcom_tobedone_data(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, uint8_t *drep, int length);

/* mark things "no specification available" */
extern int
dissect_dcom_nospec_data(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, uint8_t *drep, int length);

/* very simple parameter-profiles dissectors (for very simple requests ;-) */
/* request: no parameters */
WS_DLL_PUBLIC int
dissect_dcom_simple_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);
/* response: only HRESULT */
WS_DLL_PUBLIC int
dissect_dcom_simple_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep);

#endif /* packet-dcom.h */
