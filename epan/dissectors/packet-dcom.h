/* packet-dcom.h
 * Routines for DCOM generics
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

#ifndef __PACKET_DCERPC_DCOM_H
#define __PACKET_DCERPC_DCOM_H

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
WS_DLL_PUBLIC gboolean dcom_prefs_display_unmarshalling_details;


typedef struct dcom_machine_s {
    GList           *objects;
    gint            first_packet;

    guint8          ip[4];
} dcom_machine_t;

typedef struct dcom_object_s {
    dcom_machine_t  *parent;
    GList           *interfaces;
    void            *private_data;
    gint            first_packet;

    guint64         oid;
    guint64         oxid;
} dcom_object_t;

typedef struct dcom_interface_s {
    dcom_object_t   *parent;
    void            *private_data;
    gint            first_packet;

    e_uuid_t        iid;
    e_uuid_t        ipid;   /* the DCE/RPC Object UUID */
} dcom_interface_t;

typedef int (*dcom_dissect_fn_t) (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, gint size);

typedef struct dcom_marshaler_s {
    dcom_object_t   *parent;
    void            *private_data;

    e_uuid_t        uuid;
    dcom_dissect_fn_t routine;
} dcom_marshaler_t;

WS_DLL_PUBLIC dcom_interface_t *dcom_interface_new(packet_info *pinfo, const guint8 *ip, e_uuid_t *iid, guint64 oxid, guint64 oid, e_uuid_t *ipid);
WS_DLL_PUBLIC dcom_interface_t *dcom_interface_find(packet_info *pinfo, const guint8 *ip, e_uuid_t *ipid);
extern void dcom_interface_dump(void);

extern int dcom_register_rountine(dcom_dissect_fn_t routine, e_uuid_t* uuid);
extern void dcom_register_common_routines_(void);

extern dcom_dissect_fn_t dcom_get_rountine_by_uuid(const e_uuid_t* uuid);

/* the essential DCOM this and that, starting every call */
WS_DLL_PUBLIC int
dissect_dcom_this(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
WS_DLL_PUBLIC int
dissect_dcom_that(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);


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

extern int
dissect_dcom_UUID(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep,
	int hfindex, e_uuid_t *uuid);

extern int
dissect_dcom_append_UUID(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep,
	int hfindex, int field_index, e_uuid_t *uuid);

extern int
dissect_dcom_indexed_WORD(tvbuff_t *tvb, int offset,	packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, guint8 *drep,
					 int hfindex, guint16 * pu16WORD, int field_index);

WS_DLL_PUBLIC int
dissect_dcom_indexed_DWORD(tvbuff_t *tvb, int offset,	packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, guint8 *drep,
					 int hfindex, guint32 * pu32DWORD, int field_index);

WS_DLL_PUBLIC int
dissect_dcom_HRESULT(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, guint32 * pu32hresult);

WS_DLL_PUBLIC int
dissect_dcom_HRESULT_item(tvbuff_t *tvb, int offset,	packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, guint8 *drep,
					 guint32 * pu32HResult, int field_index, proto_item **item);

WS_DLL_PUBLIC int
dissect_dcom_indexed_HRESULT(tvbuff_t *tvb, int offset,	packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, guint8 *drep,
					 guint32 * pu32hresult, int field_index);

extern int
dissect_dcom_COMVERSION(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep,
	guint16	* pu16version_major, guint16 * pu16version_minor);

typedef void (*sa_callback_t) (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep,
                       guint32 u32VarType, guint32 u32ArraySize);

WS_DLL_PUBLIC int
dissect_dcom_SAFEARRAY(tvbuff_t *tvb, int offset, packet_info *pinfo,
						proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex _U_, sa_callback_t sacb);

WS_DLL_PUBLIC int
dissect_dcom_LPWSTR(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex,
					   gchar *psz_buffer, guint32 u32max_buffer);

WS_DLL_PUBLIC int
dissect_dcom_indexed_LPWSTR(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex,
					   gchar *pszStr, guint32 u32MaxStr, int field_index);

WS_DLL_PUBLIC int
dissect_dcom_BSTR(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex,
					   gchar *psz_buffer, guint32 u32max_buffer);

extern int
dissect_dcom_DUALSTRINGARRAY(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex, gchar *ip);

extern int
dissect_dcom_STDOBJREF(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex,
                       guint64 *oxid, guint64 *oid, e_uuid_t *ipid);
extern int
dissect_dcom_OBJREF(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex, dcom_interface_t **interf);

WS_DLL_PUBLIC int
dissect_dcom_MInterfacePointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex, dcom_interface_t **interf);
WS_DLL_PUBLIC int
dissect_dcom_PMInterfacePointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex, dcom_interface_t **interf);

WS_DLL_PUBLIC int
dissect_dcom_VARTYPE(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep,
	guint16 *pu16Vartype);

WS_DLL_PUBLIC int
dissect_dcom_VARIANT(tvbuff_t *tvb, int offset, packet_info *pinfo,
					 proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex);

/* dcom "dcerpc internal" unmarshalling */
WS_DLL_PUBLIC int
dissect_dcom_dcerpc_array_size(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, guint32 *pu32array_size);

WS_DLL_PUBLIC int
dissect_dcom_dcerpc_pointer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, dcerpc_info *di, guint8 *drep, guint32 *pu32pointer);

/* mark things as "to be done" */
extern int
dissect_dcom_tobedone_data(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, int length);

/* mark things "no specification available" */
extern int
dissect_dcom_nospec_data(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, int length);

/* very simple parameter-profiles dissectors (for very simple requests ;-) */
/* request: no parameters */
WS_DLL_PUBLIC int
dissect_dcom_simple_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
/* response: only HRESULT */
WS_DLL_PUBLIC int
dissect_dcom_simple_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);

#endif /* packet-dcerpc-dcom.h */
