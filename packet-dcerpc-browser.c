/* packet-dcerpc-browser.c
 * Routines for DCERPC Browser packet disassembly
 * Copyright 2001, Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-browser.c,v 1.12 2003/08/04 02:49:03 tpot Exp $
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

/* The IDL file for this interface can be extracted by grepping for idl
 * in capitals.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-browser.h"
#include "packet-dcerpc-nt.h"
#include "smb.h"

static int proto_dcerpc_browser = -1;
static int hf_browser_opnum = -1;
static int hf_browser_rc = -1;
static int hf_browser_unknown_long = -1;
static int hf_browser_unknown_hyper = -1;
static int hf_browser_unknown_bytes = -1;
static int hf_browser_unknown_string = -1;


static gint ett_dcerpc_browser = -1;


static int
dissect_browser_long_pointer(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     di->hf_index, NULL);
	return offset;
}



/*
 IDL [ uuid(6bffd098-a112-3610-9833-012892020162),
 IDL   version(0.0),
 IDL   implicit_handle(handle_t rpc_binding)
 IDL ] interface browser
 IDL {
*/

static e_uuid_t uuid_dcerpc_browser = {
        0x6bffd098, 0xa112, 0x3610,
        { 0x98, 0x33, 0x01, 0x28, 0x92, 0x02, 0x01, 0x62 }
};

static guint16 ver_dcerpc_browser = 0;


/*
  IDL typedef struct {
  IDL   long element_7;
  IDL   [size_is(element_7)] [unique] byte *element_8;
  IDL } TYPE_4;
*/
static int
dissect_browser_TYPE_4_data(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, &len);

	proto_tree_add_item(tree, hf_browser_unknown_bytes, tvb, offset, len,
		FALSE);
	offset += len;

	return len;
}
static int
dissect_browser_TYPE_4(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_browser_TYPE_4_data, NDR_POINTER_UNIQUE,
		"unknown TYPE_4", -1);

	return offset;
}


/*
  IDL typedef struct {
  IDL   long element_5;
  IDL   [size_is(element_5)] [unique] byte *element_6;
  IDL } TYPE_3;
*/
static int
dissect_browser_TYPE_3_data(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}

	/* this is really the length of the encoded data */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, &len);
	proto_tree_add_item(tree, hf_browser_unknown_bytes, tvb, offset, len,
		FALSE);
	offset += len;

	return len;
}
static int
dissect_browser_TYPE_3(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_browser_TYPE_3_data, NDR_POINTER_UNIQUE,
		"unknown TYPE_3", -1);

	return offset;
}



/*
  IDL typedef [switch_type(long)] union {
  IDL   [case(100)] [unique] TYPE_3 *element_3;
  IDL   [case(101)] [unique] TYPE_4 *element_4;
  IDL } TYPE_2;
*/
static int
dissect_browser_TYPE_2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 level;

	/* this is really the union switch arm */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, &level);

	ALIGN_TO_4_BYTES;

	switch(level){
	case 100:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_3, NDR_POINTER_UNIQUE,
			"unknown TYPE_3", -1);
		break;
	case 101:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_4, NDR_POINTER_UNIQUE,
			"unknown TYPE_4", -1);
		break;
	}

	return offset;
}


/*
  IDL typedef struct {
  IDL   long element_1;
  IDL   TYPE_2 element_2;
  IDL } TYPE_1;
*/
static int
dissect_browser_TYPE_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_browser_TYPE_2(tvb, offset, pinfo, tree, drep);

	return offset;
}



/*
 IDL  long Function_00(
 IDL        [in] [unique] [string] wchar_t *element_9,
 IDL        [in] [unique] [string] wchar_t *element_10,
 IDL        [in] [unique] [string] wchar_t *element_11,
 IDL        [in,out] [ref] TYPE_1 *element_12,
 IDL        [in] long element_13,
 IDL        [out] long element_14,
 IDL        [in] long element_15,
 IDL        [in] [unique] [string] wchar_t *element_16,
 IDL        [in,out] [unique] long *element_17
 IDL  );
*/
static int
dissect_browser_UNKNOWN_00_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
                        hf_browser_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_1, NDR_POINTER_REF,
			"unknown TYPE_1", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_long_pointer, NDR_POINTER_UNIQUE, 
			"unknown long", hf_browser_unknown_long);

	return offset;
}
static int
dissect_browser_UNKNOWN_00_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_1, NDR_POINTER_REF,
			"unknown TYPE_1", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_long_pointer, NDR_POINTER_UNIQUE,
			"unknown long", hf_browser_unknown_long);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}

/*
  IDL long Function_01(
  IDL       [in] [unique] [string] wchar_t *element_18,
  IDL       [in] long element_19,
  IDL       [in] long element_20
  IDL );
*/
static int
dissect_browser_UNKNOWN_01_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	return offset;
}
static int
dissect_browser_UNKNOWN_01_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}


/*
  IDL long Function_02(
  IDL       [in] [unique] [string] wchar_t *element_21,
  IDL       [in,out] [ref] TYPE_1 *element_22,
  IDL       [out] long element_23
  IDL );
*/
static int
dissect_browser_UNKNOWN_02_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_1, NDR_POINTER_REF,
			"unknown TYPE_1", -1);

	return offset;
}
static int
dissect_browser_UNKNOWN_02_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}


/*
  IDL long Function_03(
  IDL       [in] [unique] [string] wchar_t *element_24
  IDL );
*/
static int
dissect_browser_UNKNOWN_03_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	return offset;
}
static int
dissect_browser_UNKNOWN_03_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}


/*
  IDL long Function_04(
  IDL       [in] [unique] [string] wchar_t *element_25,
  IDL       [in] [string] char element_26
  IDL );
*/
static int
dissect_browser_UNKNOWN_04_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "unknown string", 
			hf_browser_unknown_string, 0);

	return offset;
}
static int
dissect_browser_UNKNOWN_04_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}



/*
  IDL typedef struct {
  IDL   TYPE_6 element_27;
  IDL   TYPE_6 element_28;
  IDL   TYPE_6 element_29;
  IDL   long element_30;
  IDL   long element_31;
  IDL   long element_32;
  IDL   long element_33;
  IDL   long element_34;
  IDL   long element_35;
  IDL   long element_36;
  IDL   long element_37;
  IDL   long element_38;
  IDL   long element_39;
  IDL   long element_40;
  IDL   long element_41;
  IDL   long element_42;
  IDL   long element_43;
  IDL   long element_44;
  IDL   TYPE_6 element_45;
  IDL } TYPE_5;
  IDL
  IDL typedef struct {
  IDL   hyper element_46;
  IDL } TYPE_6;
*/
static int
dissect_browser_TYPE_5(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_hyper, NULL);

	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_hyper, NULL);

	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_hyper, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_hyper, NULL);

	return offset;
}


/*
  IDL long Function_05(
  IDL       [in] [unique] [string] wchar_t *element_47,
  IDL       [out] [ref] TYPE_5 **element_48
  IDL );
*/
static int
dissect_browser_UNKNOWN_05_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	return offset;
}
static int
dissect_browser_UNKNOWN_05_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_5, NDR_POINTER_UNIQUE,
			"unknown TYPE_5", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}


/*
  IDL long Function_06(
  IDL       [in] [unique] [string] wchar_t *element_49
  IDL );
*/
static int
dissect_browser_UNKNOWN_06_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	return offset;
}
static int
dissect_browser_UNKNOWN_06_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}


/*
  IDL long Function_07(
  IDL       [in] [unique] [string] wchar_t *element_49
  IDL );
*/
static int
dissect_browser_UNKNOWN_07_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	return offset;
}
static int
dissect_browser_UNKNOWN_07_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}


/*
  IDL typedef struct {
  IDL   TYPE_6 element_59;
  IDL   TYPE_6 element_60;
  IDL   TYPE_6 element_61;
  IDL   long element_62;
  IDL   long element_63;
  IDL   long element_64;
  IDL   TYPE_6 element_65;
  IDL   long element_66;
  IDL   long element_67;
  IDL   long element_68;
  IDL   long element_69;
  IDL   long element_70;
  IDL   long element_71;
  IDL   long element_72;
  IDL   long element_73;
  IDL   long element_74;
  IDL } TYPE_11;
*/
static int
dissect_browser_TYPE_11(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_hyper, NULL);

	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_hyper, NULL);

	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_hyper, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_hyper, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	return offset;
}

/*
  IDL typedef struct {
  IDL   long element_57;
  IDL   [size_is(element_57)] [unique] TYPE_11 *element_58;
  IDL } TYPE_10;
*/
static int
dissect_browser_TYPE_11_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		dissect_browser_TYPE_11);

	return offset;
}

static int
dissect_browser_TYPE_10(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_browser_TYPE_11_array, NDR_POINTER_UNIQUE,
		"unknown TYPE_11_ARRAY", -1);

	return offset;
}


/*
  IDL typedef struct {
  IDL   long element_55;
  IDL   [size_is(element_55)] [unique] byte *element_56;
  IDL } TYPE_9;
*/
static int
dissect_browser_TYPE_9_data(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}

	/* this is really the length of the encoded data */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, &len);

	proto_tree_add_item(tree, hf_browser_unknown_bytes, tvb, offset, len,
		FALSE);
	offset += len;

	return len;
}
static int
dissect_browser_TYPE_9(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_browser_TYPE_9_data, NDR_POINTER_UNIQUE,
		"unknown TYPE_9", -1);

	return offset;
}


/*
  IDL typedef [switch_type(long)] union {
  IDL   [case(100)] [unique] TYPE_9 *element_53;
  IDL   [case(101)] [unique] TYPE_10 *element_54;
  IDL } TYPE_8;
*/
static int
dissect_browser_TYPE_8(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 level;

	/* this is really the union switch arm */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, &level);

	ALIGN_TO_4_BYTES;

	switch(level){
	case 100:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_9, NDR_POINTER_UNIQUE,
			"unknown TYPE_9", -1);
		break;
	case 101:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_10, NDR_POINTER_UNIQUE,
			"unknown TYPE_10", -1);
		break;
	}

	return offset;
}


/*
  IDL typedef struct {
  IDL   long element_51;
  IDL   TYPE_8 element_52;
  IDL } TYPE_7;
*/
static int
dissect_browser_TYPE_7(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_browser_TYPE_8(tvb, offset, pinfo, tree, drep);

	return offset;
}


/*
  IDL long Function_08(
  IDL       [in] [unique] [string] wchar_t *element_75,
  IDL       [in] long element_76,
  IDL   [in,out] [ref] TYPE_7 *element_77
  IDL );
*/
static int
dissect_browser_UNKNOWN_08_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_7, NDR_POINTER_REF,
			"unknown TYPE_7", -1);

	return offset;
}
static int
dissect_browser_UNKNOWN_08_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_7, NDR_POINTER_REF,
			"unknown TYPE_7", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}


/*
  IDL long Function_09(
  IDL       [in] [unique] [string] wchar_t *element_78,
  IDL       [in] [ref] [string] wchar_t *element_79,
  IDL       [in] [unique] [string] wchar_t *element_80,
  IDL       [in] long element_81
  IDL );
*/
static int
dissect_browser_UNKNOWN_09_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "unknown string", 
                        hf_browser_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	return offset;
}
static int
dissect_browser_UNKNOWN_09_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}




/*
  IDL typedef struct {
  IDL   long element_82;
  IDL   [size_is(element_82)] [unique] byte *element_83;
  IDL } TYPE_12;
*/
static int
dissect_browser_TYPE_12_data(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}

	/* this is really the length of the encoded data */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, &len);

	proto_tree_add_item(tree, hf_browser_unknown_bytes, tvb, offset, len,
		FALSE);
	offset += len;

	return len;
}
static int
dissect_browser_TYPE_12(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_browser_TYPE_12_data, NDR_POINTER_UNIQUE,
		"unknown TYPE_12", -1);

	return offset;
}


/*
  IDL long Function_0a(
  IDL       [in] [unique] [string] wchar_t *element_84,
  IDL       [in,out] [ref] TYPE_12 *element_85
  );
*/
static int
dissect_browser_UNKNOWN_0a_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_12, NDR_POINTER_REF,
			"unknown TYPE_12", -1);

	return offset;
}
static int
dissect_browser_UNKNOWN_0a_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_12, NDR_POINTER_REF,
			"unknown TYPE_12", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}


/*
  IDL long Function_0b(
  IDL       [in] [unique] [string] wchar_t *element_86,
  IDL       [in] [unique] [string] wchar_t *element_87,
  IDL       [in] [unique] [string] wchar_t *element_88,
  IDL       [in,out] [ref] TYPE_1 *element_89,
  IDL       [in] long element_90,
  IDL       [out] long element_91,
  IDL       [in] long element_92,
  IDL       [in] [unique] [string] wchar_t *element_93,
  IDL       [in] [unique] [string] wchar_t *element_94
  IDL );
*/
static int
dissect_browser_UNKNOWN_0b_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_1, NDR_POINTER_REF,
			"unknown TYPE_1", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "unknown string", 
			hf_browser_unknown_string, 0);

	return offset;
}
static int
dissect_browser_UNKNOWN_0b_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_browser_TYPE_1, NDR_POINTER_REF,
			"unknown TYPE_1", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_browser_rc, NULL);

	return offset;
}



/*
  IDL }
*/
static dcerpc_sub_dissector dcerpc_browser_dissectors[] = {
        { BROWSER_UNKNOWN_00, "BROWSER_UNKNOWN_00",
		dissect_browser_UNKNOWN_00_rqst,
		dissect_browser_UNKNOWN_00_reply },
        { BROWSER_UNKNOWN_01, "BROWSER_UNKNOWN_01",
		dissect_browser_UNKNOWN_01_rqst,
		dissect_browser_UNKNOWN_01_reply },
        { BROWSER_UNKNOWN_02, "BROWSER_UNKNOWN_02",
		dissect_browser_UNKNOWN_02_rqst,
		dissect_browser_UNKNOWN_02_reply },
        { BROWSER_UNKNOWN_03, "BROWSER_UNKNOWN_03",
		dissect_browser_UNKNOWN_03_rqst,
		dissect_browser_UNKNOWN_03_reply },
        { BROWSER_UNKNOWN_04, "BROWSER_UNKNOWN_04",
		dissect_browser_UNKNOWN_04_rqst,
		dissect_browser_UNKNOWN_04_reply },
        { BROWSER_UNKNOWN_05, "BROWSER_UNKNOWN_05",
		dissect_browser_UNKNOWN_05_rqst,
		dissect_browser_UNKNOWN_05_reply },
        { BROWSER_UNKNOWN_06, "BROWSER_UNKNOWN_06",
		dissect_browser_UNKNOWN_06_rqst,
		dissect_browser_UNKNOWN_06_reply },
        { BROWSER_UNKNOWN_07, "BROWSER_UNKNOWN_07",
		dissect_browser_UNKNOWN_07_rqst,
		dissect_browser_UNKNOWN_07_reply },
        { BROWSER_UNKNOWN_08, "BROWSER_UNKNOWN_08",
		dissect_browser_UNKNOWN_08_rqst,
		dissect_browser_UNKNOWN_08_reply },
        { BROWSER_UNKNOWN_09, "BROWSER_UNKNOWN_09",
		dissect_browser_UNKNOWN_09_rqst,
		dissect_browser_UNKNOWN_09_reply },
        { BROWSER_UNKNOWN_0a, "BROWSER_UNKNOWN_0a",
		dissect_browser_UNKNOWN_0a_rqst,
		dissect_browser_UNKNOWN_0a_reply },
        { BROWSER_UNKNOWN_0b, "BROWSER_UNKNOWN_0b",
		dissect_browser_UNKNOWN_0b_rqst,
		dissect_browser_UNKNOWN_0b_reply },

        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_browser(void)
{
static hf_register_info hf[] = {

	{ &hf_browser_opnum, { 
		"Operation", "rpc_browser.opnum", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Operation", HFILL }},

	{ &hf_browser_rc, {
		"Return code", "rpc_browser.rc", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0x0, "Browser return code", HFILL }},

	{ &hf_browser_unknown_long, {
		"Unknown long", "rpc_browser.unknown.long", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Unknown long. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_browser_unknown_hyper, {
		"Unknown hyper", "rpc_browser.unknown.hyper", FT_UINT64, BASE_HEX,
		NULL, 0x0, "Unknown hyper. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_browser_unknown_bytes, {
		"Unknown bytes", "rpc_browser.unknown.bytes", FT_BYTES, BASE_HEX,
		NULL, 0x0, "Unknown bytes. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_browser_unknown_string, {
		"Unknown string", "rpc_browser.unknown.string", FT_STRING, BASE_HEX,
		NULL, 0x0, "Unknown string. If you know what this is, contact ethereal developers.", HFILL }}

	};
        static gint *ett[] = {
                &ett_dcerpc_browser
        };

        proto_dcerpc_browser = proto_register_protocol(
                "RPC Browser", "RPC_BROWSER", "rpc_browser");

        proto_register_field_array(proto_dcerpc_browser, hf,
				   array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_browser(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_browser, ett_dcerpc_browser,
                         &uuid_dcerpc_browser, ver_dcerpc_browser,
                         dcerpc_browser_dissectors, hf_browser_opnum);
}
