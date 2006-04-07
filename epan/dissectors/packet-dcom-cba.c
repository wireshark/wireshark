/* packet-dcom-cba.c
 * Routines for DCOM CBA
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif


#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcom.h"
#include "packet-dcom-dispatch.h"


static int hf_cba_opnum = -1;

static int hf_cba_revision_major = -1;
static int hf_cba_revision_minor = -1;
static int hf_cba_revision_service_pack = -1;
static int hf_cba_revision_build = -1;

static int hf_cba_time = -1;

static int hf_cba_name = -1;
static int hf_cba_producer = -1;
static int hf_cba_product = -1;
static int hf_cba_production_date = -1;
static int hf_cba_serial_no = -1;
static int hf_cba_multi_app = -1;
static int hf_cba_profinet_dcom_stack = -1;
static int hf_cba_pdev_stamp = -1;

static int hf_cba_browse_count = -1;
static int hf_cba_browse_offset = -1;
static int hf_cba_browse_max_return = -1;
static int hf_cba_browse_item = -1;
static int hf_cba_browse_data_type = -1;
static int hf_cba_browse_access_right = -1;
static int hf_cba_browse_selector = -1;
static int hf_cba_browse_info1 = -1;
static int hf_cba_browse_info2 = -1;

static int hf_cba_cookie = -1;
static int hf_cba_state = -1;
static int hf_cba_new_state = -1;
static int hf_cba_old_state = -1;
static int hf_cba_grouperror = -1;
static int hf_cba_new_grouperror = -1;
static int hf_cba_old_grouperror = -1;

static int hf_cba_component_id = -1;
static int hf_cba_component_version = -1;

static int hf_cba_save_ldev_name = -1;
static int hf_cba_save_result = -1;


/* fake protocols (these are simply classes) */
static int proto_coclass_CBAPhysicalDevice = -1;
static gint ett_coclass_CBAPhysicalDevice = -1;
static e_uuid_t uuid_coclass_CBAPhysicalDevice = { 0xcba00000, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_coclass_CBAPhysicalDevice = 0;


/* CBA interfaces */
static int proto_ICBAPhysicalDevice = -1;
static gint ett_ICBAPhysicalDevice = -1;
static e_uuid_t uuid_ICBAPhysicalDevice = { 0xcba00001, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAPhysicalDevice = 0;

static int proto_ICBAPhysicalDevice2 = -1;
static e_uuid_t uuid_ICBAPhysicalDevice2 = { 0xcba00006, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAPhysicalDevice2 = 0;

static int proto_ICBABrowse = -1;
static gint ett_ICBABrowse = -1;
static e_uuid_t uuid_ICBABrowse = { 0xcba00002, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBABrowse = 0;

static int proto_ICBABrowse2 = -1;
static e_uuid_t uuid_ICBABrowse2 = { 0xcba00007, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBABrowse2 = 0;

static int proto_ICBAPhysicalDevicePC = -1;
static gint ett_ICBAPhysicalDevicePC = -1;
static e_uuid_t uuid_ICBAPhysicalDevicePC = { 0xcba00003, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAPhysicalDevicePC = 0;

static int proto_ICBAPhysicalDevicePCEvent = -1;
static gint ett_ICBAPhysicalDevicePCEvent = -1;
static e_uuid_t uuid_ICBAPhysicalDevicePCEvent = { 0xcba00004, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAPhysicalDevicePCEvent = 0;

static int proto_ICBAPersist = -1;
static gint ett_ICBAPersist = -1;
static e_uuid_t uuid_ICBAPersist = { 0xcba00005, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAPersist = 0;

static int proto_ICBAPersist2 = -1;
static e_uuid_t uuid_ICBAPersist2 = { 0xcba00008, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAPersist2 = 0;

static int proto_ICBALogicalDevice = -1;
static gint ett_ICBALogicalDevice = -1;
static e_uuid_t uuid_ICBALogicalDevice = { 0xcba00011, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBALogicalDevice = 0;

static int proto_ICBALogicalDevice2 = -1;
static e_uuid_t uuid_ICBALogicalDevice2 = { 0xcba00017, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBALogicalDevice2 = 0;

static int proto_ICBAState = -1;
static gint ett_ICBAState = -1;
static e_uuid_t uuid_ICBAState = { 0xcba00012, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAState = 0;

static int proto_ICBAStateEvent = -1;
static gint ett_ICBAStateEvent = -1;
static e_uuid_t uuid_ICBAStateEvent = { 0xcba00013, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAStateEvent = 0;

static int proto_ICBATime = -1;
static gint ett_ICBATime = -1;
static e_uuid_t uuid_ICBATime = { 0xcba00014, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBATime = 0;

static int proto_ICBAGroupError = -1;
static gint ett_ICBAGroupError = -1;
static e_uuid_t uuid_ICBAGroupError = { 0xcba00015, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAGroupError = 0;

static int proto_ICBAGroupErrorEvent = -1;
static gint ett_ICBAGroupErrorEvent = -1;
static e_uuid_t uuid_ICBAGroupErrorEvent = { 0xcba00016, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBAGroupErrorEvent = 0;

static int proto_ICBARTAuto = -1;
static gint ett_ICBARTAuto = -1;
static e_uuid_t uuid_ICBARTAuto = { 0xcba00051, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBARTAuto = 0;

static int proto_ICBARTAuto2 = -1;
static e_uuid_t uuid_ICBARTAuto2 = { 0xcba00052, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBARTAuto2 = 0;

static int proto_ICBASystemProperties = -1;
static gint ett_ICBASystemProperties = -1;
static e_uuid_t uuid_ICBASystemProperties = { 0xcba00062, 0x6c97, 0x11d1, { 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d } };
static guint16  ver_ICBASystemProperties = 0;


static const value_string cba_state_vals[] = {
	{ 0x00, "NonExistent" },
	{ 0x01, "Initializing" },
	{ 0x02, "Ready" },
	{ 0x03, "Operating" },
	{ 0x04, "Defect" },
    { 0, NULL }
};


static const value_string cba_grouperror_vals[] = {
	{ 0x00, "NonAccessible" },
	{ 0x01, "Okay" },
	{ 0x02, "Problem" },
	{ 0x03, "Unknown" },
    { 0, NULL }
};


static const value_string dcom_boolean_vals[] = {
	{ 0x00, "FALSE" },
	{ 0x01, "TRUE" },
	{ 0xffff, "TRUE" },
    { 0, NULL }
};




static int
dissect_ICBABrowse_get_Count_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Count;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_browse_count, &u32Count);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, 
                        &u32HResult);

	if (u32HResult) {	/* !S_OK */
	    if (check_col(pinfo->cinfo, COL_INFO))
	      col_append_fstr(pinfo->cinfo, COL_INFO, "-> %s", 
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
    } else {
	    if (check_col(pinfo->cinfo, COL_INFO))
	      col_append_fstr(pinfo->cinfo, COL_INFO, " Cnt=%u -> S_OK", u32Count);
    }
	    

	return offset;
}


static int
dissect_ICBABrowse_BrowseItems_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Offset;
	guint32 u32MaxReturn;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_browse_offset, &u32Offset);
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_browse_max_return, &u32MaxReturn);

    if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, " Offset=%u MaxReturn=%u", 
			u32Offset, u32MaxReturn);

	return offset;
}


static int
dissect_ICBABrowse_BrowseItems_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Pointer;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_cba_browse_item);
	}
	
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_cba_browse_data_type);
	}

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_cba_browse_access_right);
	}

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", 
		val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

	return offset;
}


static int
dissect_ICBABrowse2_get_Count2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Selector;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_browse_selector, &u32Selector);

    if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, " Selector=%u", 
			u32Selector);

	return offset;
}



static int
dissect_ICBABrowse2_BrowseItems2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Selector;
	guint32 u32Offset;
	guint32 u32MaxReturn;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_browse_selector, &u32Selector);
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_browse_offset, &u32Offset);
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_browse_max_return, &u32MaxReturn);

    if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, " Sel=%u Offset=%u MaxReturn=%u", 
			u32Selector, u32Offset, u32MaxReturn);

	return offset;
}


static int
dissect_ICBABrowse2_BrowseItems2_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Pointer;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_cba_browse_item);
	}
	
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_cba_browse_info1);
	}

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_cba_browse_info2);
	}

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", 
		val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

	return offset;
}


static int
dissect_ICBAPersist2_Save2_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Pointer;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_cba_save_ldev_name);
	}
	
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_cba_save_result);
	}

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", 
		val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

	return offset;
}



static int
dissect_get_BSTR_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep, int hfindex)
{
	gchar 	szStr[1000];
	guint32 u32MaxStr = sizeof(szStr);
	guint32 u32Pointer;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_BSTR(tvb, offset, pinfo, tree, drep, 
			hfindex, szStr, u32MaxStr);
	}
	
	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

    if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": \"%s\" -> %s", szStr,
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_get_ProductionDate_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32HResult;
	gdouble r8Date;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DATE(tvb, offset, pinfo, tree, drep, 
				hf_cba_production_date, &r8Date);
	
	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

    if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Date: %g -> %s",
			r8Date,
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_get_SerialNo_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32HResult;
	guint32 u32Pointer;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, 
					hf_cba_serial_no);
	}
	
	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

    if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", 
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_ICBATime_get_Time_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32HResult;
	gdouble r8Date;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DATE(tvb, offset, pinfo, tree, drep, 
				hf_cba_time, &r8Date);
	
	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

    if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Time: %g -> %s", 
			r8Date,
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_ICBATime_put_Time_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	gdouble r8Date;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DATE(tvb, offset, pinfo, tree, drep, 
				hf_cba_time, &r8Date);
	
	return offset;
}


static int
dissect_get_Producer_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	return dissect_get_BSTR_resp(tvb, offset, pinfo, tree, drep, hf_cba_producer);
}


static int
dissect_get_Product_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	return dissect_get_BSTR_resp(tvb, offset, pinfo, tree, drep, hf_cba_product);
}


static int
dissect_ICBAPhysicalDevice_get_LogicalDevice_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Pointer;
	gchar 	szStr[1000];
	guint32 u32MaxStr = sizeof(szStr);


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_BSTR(tvb, offset, pinfo, tree, drep, 
			hf_cba_name, szStr, u32MaxStr);
	}
	
    if (check_col(pinfo->cinfo, COL_INFO)) {
	      col_append_fstr(pinfo->cinfo, COL_INFO, ": \"%s\"", szStr);
	}

	return offset;
}


static int
dissect_ICBAPhysicalDevice_get_LogicalDevice_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 0);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO))
		  col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", 
		  val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

	return offset;
}


static int
dissect_ICBAPhysicalDevice2_Type_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint16 u16MultiApp;
	guint16 u16PROFInetDCOMStack;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_VARIANT_BOOL(tvb, offset, pinfo, tree, drep, 
                        hf_cba_multi_app, &u16MultiApp);

	offset = dissect_dcom_VARIANT_BOOL(tvb, offset, pinfo, tree, drep, 
                        hf_cba_profinet_dcom_stack, &u16PROFInetDCOMStack);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO))
		  col_append_fstr(pinfo->cinfo, COL_INFO, " App=%s Stack=%s -> %s", 
		  (u16MultiApp) ? "Multi" : "Single",
		  (u16PROFInetDCOMStack) ? "PN-DCOM" : "MS-DCOM",
		  val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

	return offset;
}


static int
dissect_PROFInetRevision_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint16 u16Major;
	guint16 u16Minor;
	guint16 u16ServicePack;
	guint16 u16Build;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_revision_major, &u16Major);
	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_revision_minor, &u16Minor);
	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_revision_service_pack, &u16ServicePack);
	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_revision_build, &u16Build);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO))
		  col_append_fstr(pinfo->cinfo, COL_INFO, " Revision=%u.%u.%u.%u -> %s", 
		  u16Major, u16Minor, u16ServicePack, u16Build,
		  val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

	return offset;
}


static int
dissect_ICBAPhysicalDevice2_get_PDevStamp_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32PDevStamp;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_pdev_stamp, &u32PDevStamp);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO))
		  col_append_fstr(pinfo->cinfo, COL_INFO, " PDevStamp=0x%x -> %s", 
		  u32PDevStamp,
		  val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

	return offset;
}


static int
dissect_Revision_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint16 u16Major;
	guint16 u16Minor;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_revision_major, &u16Major);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_revision_minor, &u16Minor);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
				&u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %u.%u -> %s", 
			u16Major, u16Minor,
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_get_Name_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	return dissect_get_BSTR_resp(tvb, offset, pinfo, tree, drep, hf_cba_name);
}


static int
dissect_ICBALogicalDevice_get_ACCO_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 0);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, &u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", 
		val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_ICBALogicalDevice_get_RTAuto_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 0);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, &u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", 
		val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_ICBALogicalDevice_Get_RTAuto_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	gchar 	szStr[1000];
	guint32 u32MaxStr = sizeof(szStr);
	guint32 u32Pointer;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_BSTR(tvb, offset, pinfo, tree, drep, 
			hf_cba_name, szStr, u32MaxStr);
	}
	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": \"%s\"", szStr);
	}

	return offset;
}



static int
dissect_ComponentInfo_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	gchar 	szStr[1000];
	guint32 u32MaxStr = sizeof(szStr);
	gchar 	szStr2[1000];
	guint32 u32MaxStr2 = sizeof(szStr2);
	guint32 u32HResult;
	guint32 u32Pointer;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_BSTR(tvb, offset, pinfo, tree, drep, 
			hf_cba_component_id, szStr, u32MaxStr);
	}
	
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_BSTR(tvb, offset, pinfo, tree, drep, 
			hf_cba_component_version, szStr2, u32MaxStr2);
	}
	
	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, &u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": ID=\"%s\" Version=\"%s\" -> %s", 
			szStr, szStr2,
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_Advise_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 0);

	return offset;
}


static int
dissect_Advise_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Cookie;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_cookie, &u32Cookie);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, 
                        &u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Cookie=0x%x -> %s", 
			u32Cookie, 
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_Unadvise_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Cookie;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_cookie, &u32Cookie);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Cookie=0x%x", 
			u32Cookie);
	}

	return offset;
}


static int
dissect_ICBAState_get_State_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint16 u16State;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_state, &u16State);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, 
                        &u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": State=%s -> %s", 
			val_to_str(u16State, cba_state_vals, "Unknown (0x%08x)"),
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_ICBAStateEvent_OnStateChanged_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint16 u16NewState;
	guint16 u16OldState;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_new_state, &u16NewState);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_old_state, &u16OldState);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": NewState=%s OldState=%s", 
			val_to_str(u16NewState, cba_state_vals, "Unknown (0x%04x)"),
			val_to_str(u16OldState, cba_state_vals, "Unknown (0x%04x)") );
	}

	return offset;
}


static int
dissect_ICBAGroupError_OnGroupErrorChanged_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint16 u16NewGroupError;
	guint16 u16OldGroupError;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_new_grouperror, &u16NewGroupError);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_old_grouperror, &u16OldGroupError);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": NewGE=%s OldGE=%s", 
			val_to_str(u16NewGroupError, cba_grouperror_vals, "Unknown (0x%04x)"),
			val_to_str(u16OldGroupError, cba_grouperror_vals, "Unknown (0x%04x)") );
	}

	return offset;
}


static int
dissect_ICBAPhysicalDevicePCEvent_OnLogicalDeviceAdded_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Cookie;
	guint32 u32HResult;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_cookie, &u32Cookie);

	offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 0);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, 
                        &u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": Cookie=0x%x %s", 
			u32Cookie,
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


static int
dissect_ICBAGroupError_GroupError_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint16 u16GroupError;
	guint32 u32Cookie;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_grouperror, &u16GroupError);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_cba_cookie, &u32Cookie);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, 
                        &u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ": GroupError=%s Cookie=0x%x -> %s", 
			val_to_str(u16GroupError, cba_grouperror_vals, "Unknown (0x%08x)"),
			u32Cookie,
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}


/* sub dissector table of ICBAPhysicalDevice class (fake only) */
static dcerpc_sub_dissector coclass_ICBAPhysicalDevice_dissectors[] = {
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAPhysicalDevice / ICBAPhysicalDevice2 interface */
static dcerpc_sub_dissector ICBAPhysicalDevice_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "get_Producer", dissect_dcom_simple_rqst, dissect_get_Producer_resp },
    { 8, "get_Product", dissect_dcom_simple_rqst, dissect_get_Product_resp },
    { 9, "get_SerialNo", dissect_dcom_simple_rqst, dissect_get_SerialNo_resp },
    {10, "get_ProductionDate", dissect_dcom_simple_rqst, dissect_get_ProductionDate_resp },
    {11, "Revision", dissect_dcom_simple_rqst, dissect_Revision_resp },
    {12, "get_LogicalDevice", dissect_ICBAPhysicalDevice_get_LogicalDevice_rqst, dissect_ICBAPhysicalDevice_get_LogicalDevice_resp },
	/* stage 2 */
    {13, "Type", dissect_dcom_simple_rqst, dissect_ICBAPhysicalDevice2_Type_resp },
    {14, "PROFInetRevision", dissect_dcom_simple_rqst, dissect_PROFInetRevision_resp },
    {15, "PDevStamp", dissect_dcom_simple_rqst, dissect_ICBAPhysicalDevice2_get_PDevStamp_resp },
	{ 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBABrowse / ICBABrowse2 interface */
static dcerpc_sub_dissector ICBABrowse_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "get_Count", dissect_dcom_simple_rqst, dissect_ICBABrowse_get_Count_resp },
    { 8, "BrowseItems", dissect_ICBABrowse_BrowseItems_rqst, dissect_ICBABrowse_BrowseItems_resp },
	/* stage 2 */
    { 9, "get_Count2", dissect_ICBABrowse2_get_Count2_rqst, dissect_ICBABrowse_get_Count_resp },
    {10, "BrowseItems2", dissect_ICBABrowse2_BrowseItems2_rqst, dissect_ICBABrowse2_BrowseItems2_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAPersist / ICBAPersist2 interface */
static dcerpc_sub_dissector ICBAPersist_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "Save", dissect_dcom_simple_rqst, dissect_dcom_simple_resp },
	/* stage 2 */
    { 8, "Save2", dissect_dcom_simple_rqst, dissect_ICBAPersist2_Save2_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAPhysicalDevicePC interface */
/* (local COM interface, not to be called over network) */
static dcerpc_sub_dissector ICBAPhysicalDevicePC_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "AddLogicalDevice", dissect_Advise_rqst, dissect_Advise_resp },
    { 4, "RemoveLogicalDevice", dissect_Unadvise_rqst, dissect_dcom_simple_resp  },
    { 5, "AdvisePDevPC", dissect_Advise_rqst, dissect_Advise_resp },
    { 6, "UnadvisePDevPC", dissect_Unadvise_rqst, dissect_dcom_simple_resp },
	/* stage 2 */
    { 7, "RegisterApplication", NULL, NULL },
    { 8, "UnRegisterApplication", NULL, NULL },
    { 9, "AddLogicalDevice2", NULL, NULL },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAPhysicalDevicePCEvent interface */
static dcerpc_sub_dissector ICBAPhysicalDevicePCEvent_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "OnLogicalDeviceAdded", dissect_ICBAPhysicalDevicePCEvent_OnLogicalDeviceAdded_rqst, dissect_dcom_simple_resp  },
    { 4, "OnLogicalDeviceRemoved", dissect_Unadvise_rqst, dissect_dcom_simple_resp  },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBALogicalDevice / ICBALogicalDevice2 interface */
static dcerpc_sub_dissector ICBALogicalDevice_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "get_Name", dissect_dcom_simple_rqst, dissect_get_Name_resp },
    { 8, "get_Producer", dissect_dcom_simple_rqst, dissect_get_Producer_resp },
    { 9, "get_Product", dissect_dcom_simple_rqst, dissect_get_Product_resp },
    {10, "get_SerialNo", dissect_dcom_simple_rqst, dissect_get_SerialNo_resp },
    {11, "get_ProductionDate", dissect_dcom_simple_rqst, dissect_get_ProductionDate_resp },
    {12, "Revision", dissect_dcom_simple_rqst, dissect_Revision_resp },
    {13, "get_ACCO", dissect_dcom_simple_rqst, dissect_ICBALogicalDevice_get_ACCO_resp },
    {14, "get_RTAuto", dissect_ICBALogicalDevice_Get_RTAuto_rqst, dissect_ICBALogicalDevice_get_RTAuto_resp },
	/* stage 2 */
    {15, "PROFInetRevision", dissect_dcom_simple_rqst, dissect_PROFInetRevision_resp },
    {16, "ComponentInfo", dissect_dcom_simple_rqst, dissect_ComponentInfo_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAState interface */
static dcerpc_sub_dissector ICBAState_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "get_State", dissect_dcom_simple_rqst, dissect_ICBAState_get_State_resp },
    { 8, "Activate", dissect_dcom_simple_rqst, dissect_dcom_simple_resp },
    { 9, "Deactivate", dissect_dcom_simple_rqst, dissect_dcom_simple_resp },
    {10, "Reset", dissect_dcom_simple_rqst, dissect_dcom_simple_resp },
    {11, "AdviseState", dissect_Advise_rqst, dissect_Advise_resp },
    {12, "UnadviseState", dissect_Unadvise_rqst, dissect_dcom_simple_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAStateEvent interface */
static dcerpc_sub_dissector ICBAStateEvent_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "OnStateChanged", dissect_ICBAStateEvent_OnStateChanged_rqst, dissect_dcom_simple_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBATime interface */
static dcerpc_sub_dissector ICBATime_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "get_Time", dissect_dcom_simple_rqst, dissect_ICBATime_get_Time_resp },
    { 8, "put_Time", dissect_ICBATime_put_Time_rqst, dissect_dcom_simple_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAGroupError interface */
static dcerpc_sub_dissector ICBAGroupError_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "GroupError", dissect_dcom_simple_rqst, dissect_ICBAGroupError_GroupError_resp },
    { 8, "AdviseGroupError", dissect_Advise_rqst, dissect_Advise_resp },
    { 9, "UnadviseGroupError", dissect_Unadvise_rqst, dissect_dcom_simple_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBAGroupErrorEvent interface */
static dcerpc_sub_dissector ICBAGroupErrorEvent_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "OnGroupErrorChanged", dissect_ICBAGroupError_OnGroupErrorChanged_rqst, dissect_dcom_simple_resp },
    { 0, NULL, NULL, NULL },
};


/* sub dissector table of ICBARTAuto interface */
static dcerpc_sub_dissector ICBARTAuto_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "get_Name", dissect_dcom_simple_rqst, dissect_get_Name_resp },
    { 8, "Revision", dissect_dcom_simple_rqst, dissect_Revision_resp },

	/* stage 2 */
    { 9, "ComponentInfo", dissect_dcom_simple_rqst, dissect_ComponentInfo_resp },
    { 0, NULL, NULL, NULL },
};


/* the interface ICBASystemProperties will NOT be seen on the ethernet */
/* sub dissector table of ICBASystemProperties interface (stage 2 only) */
/* (usually not called over network, no dissecting needed) */
static dcerpc_sub_dissector ICBASystemProperties_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },

    { 7, "StateCollection", dissect_dcom_simple_rqst, NULL },
    { 8, "StampCollection", dissect_dcom_simple_rqst, NULL },
    { 0, NULL, NULL, NULL },
};


/* register protocol */
void
proto_register_dcom_cba (void)
{
	static gint *ett[1];

	static hf_register_info hf_cba_browse_array[] = {
		{ &hf_cba_browse_count,
		{ "Count",   "cba.browse.count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_cba_browse_offset,
		{ "Offset",   "cba.browse.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_cba_browse_max_return,
		{ "MaxReturn",   "cba.browse.max_return", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_cba_browse_item,
		{ "ItemNames", "cba.browse.item", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_browse_data_type,
		{ "DataTypes", "cba.browse.data_type", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_browse_access_right,
		{ "AccessRights", "cba.browse.access_right", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_browse_selector,
		{ "Selector",   "cba.browse.selector", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_cba_browse_info1,
		{ "Info1", "cba.browse.info1", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_browse_info2,
		{ "Info2", "cba.browse.info2", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	};


	static hf_register_info hf_cba_pdev_array[] = {
		{ &hf_cba_revision_major,
		{ "Major", "cba.revision_major", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_cba_revision_minor,
		{ "Minor", "cba.revision_minor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_cba_revision_service_pack,
		{ "ServicePack", "cba.revision_service_pack", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_cba_revision_build,
		{ "Build", "cba_revision_build", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_cba_producer,
		{ "Producer", "cba.producer", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_product,
		{ "Product", "cba.product", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_multi_app,
		{ "MultiApp", "cba.multi_app", FT_UINT16, BASE_HEX, VALS(dcom_boolean_vals), 0x0, "", HFILL }},
		{ &hf_cba_profinet_dcom_stack,
		{ "PROFInetDCOMStack", "cba.profinet_dcom_stack", FT_UINT16, BASE_HEX, VALS(dcom_boolean_vals), 0x0, "", HFILL }},
		{ &hf_cba_pdev_stamp,
		{ "PDevStamp", "cba.pdev_stamp", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_cba_save_ldev_name,
		{ "LDevName", "cba.save_ldev_name", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_save_result,
		{ "PatialResult", "cba.save_result", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	};

	static hf_register_info hf_cba_ldev_array[] = {
		{ &hf_cba_name,
		{ "Name", "cba.name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_component_id,
		{ "ComponentID", "cba.component_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_component_version,
		{ "Version", "cba.component_version", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
	};

	static hf_register_info hf_cba_array[] = {
        { &hf_cba_opnum,
	    { "Operation", "cba.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }},
		{ &hf_cba_production_date,
		{ "ProductionDate", "cba.production_date", FT_DOUBLE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_time,
		{ "Time", "cba.time", FT_DOUBLE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_serial_no,
		{ "SerialNo", "cba.serial_no", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_cba_state,
		{ "State",  "cba.state", FT_UINT16, BASE_HEX, VALS(cba_state_vals), 0x0, "", HFILL }},
		{ &hf_cba_new_state,
		{ "NewState",  "cba.state_new", FT_UINT16, BASE_HEX, VALS(cba_state_vals), 0x0, "", HFILL }},
		{ &hf_cba_old_state,
		{ "OldState",  "cba.state_old", FT_UINT16, BASE_HEX, VALS(cba_state_vals), 0x0, "", HFILL }},
		{ &hf_cba_cookie,
		{ "Cookie", "cba.cookie", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_cba_grouperror,
		{ "GroupError", "cba.grouperror", FT_UINT16, BASE_HEX, VALS(cba_grouperror_vals), 0x0, "", HFILL }},
		{ &hf_cba_new_grouperror,
		{ "NewGroupError", "cba.grouperror_new", FT_UINT16, BASE_HEX, VALS(cba_grouperror_vals), 0x0, "", HFILL }},
		{ &hf_cba_old_grouperror,
		{ "OldGroupError", "cba.grouperror_old", FT_UINT16, BASE_HEX, VALS(cba_grouperror_vals), 0x0, "", HFILL }},
	};


	ett[0] = &ett_coclass_CBAPhysicalDevice;
	proto_coclass_CBAPhysicalDevice = proto_register_protocol ("CBAPhysicalDevice", "CBAPDev", "cba_pdev_class");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBAPhysicalDevice;
	proto_ICBAPhysicalDevice = proto_register_protocol ("ICBAPhysicalDevice", "ICBAPDev", "cba_pdev");
    proto_register_field_array(proto_ICBAPhysicalDevice, hf_cba_pdev_array, array_length(hf_cba_pdev_array));
	proto_register_subtree_array (ett, array_length (ett));

	proto_ICBAPhysicalDevice2 = proto_register_protocol ("ICBAPhysicalDevice2", "ICBAPDev2", "cba_pdev2");

	ett[0] = &ett_ICBABrowse;
	proto_ICBABrowse = proto_register_protocol ("ICBABrowse", "ICBABrowse", "cba_browse");
    proto_register_field_array(proto_ICBABrowse, hf_cba_array, array_length(hf_cba_array));
    proto_register_field_array(proto_ICBABrowse, hf_cba_browse_array, array_length(hf_cba_browse_array));
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBABrowse;
	proto_ICBABrowse2 = proto_register_protocol ("ICBABrowse2", "ICBABrowse2", "cba_browse2");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBAPhysicalDevicePC;
	proto_ICBAPhysicalDevicePC = proto_register_protocol ("ICBAPhysicalDevicePC", "ICBAPDevPC", "cba_pdev_pc");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBAPhysicalDevicePCEvent;
	proto_ICBAPhysicalDevicePCEvent = proto_register_protocol ("ICBAPhysicalDevicePCEvent", "ICBAPDevPCEvent", "cba_pdev_pc_event");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBAPersist;
	proto_ICBAPersist = proto_register_protocol ("ICBAPersist", "ICBAPersist", "cba_persist");
	proto_register_subtree_array (ett, array_length (ett));

	proto_ICBAPersist2 = proto_register_protocol ("ICBAPersist2", "ICBAPersist2", "cba_persist2");

	ett[0] = &ett_ICBALogicalDevice;
	proto_ICBALogicalDevice = proto_register_protocol ("ICBALogicalDevice", "ICBALDev", "cba_ldev");
    proto_register_field_array(proto_ICBAPhysicalDevice, hf_cba_ldev_array, array_length(hf_cba_ldev_array));
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBALogicalDevice;
	proto_ICBALogicalDevice2 = proto_register_protocol ("ICBALogicalDevice2", "ICBALDev2", "cba_ldev2");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBAState;
	proto_ICBAState = proto_register_protocol ("ICBAState", "ICBAState", "cba_state");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBAStateEvent;
	proto_ICBAStateEvent = proto_register_protocol ("ICBAStateEvent", "ICBAStateEvent", "cba_state_event");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBATime;
	proto_ICBATime = proto_register_protocol ("ICBATime", "ICBATime", "cba_time");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBAGroupError;
	proto_ICBAGroupError = proto_register_protocol ("ICBAGroupError", "ICBAGErr", "cba_grouperror");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBAGroupErrorEvent;
	proto_ICBAGroupErrorEvent = proto_register_protocol ("ICBAGroupErrorEvent", "ICBAGErrEvent", "cba_grouperror_event");
	proto_register_subtree_array (ett, array_length (ett));

	ett[0] = &ett_ICBARTAuto;
	proto_ICBARTAuto = proto_register_protocol ("ICBARTAuto", "ICBARTAuto", "cba_rtauto");
	proto_register_subtree_array (ett, array_length (ett));

	proto_ICBARTAuto2 = proto_register_protocol ("ICBARTAuto2", "ICBARTAuto2", "cba_rtauto2");

	ett[0] = &ett_ICBASystemProperties;
	proto_ICBASystemProperties = proto_register_protocol ("ICBASystemProperties", "ICBASysProp", "cba_sysprop");
	proto_register_subtree_array (ett, array_length (ett));
}


/* handoff protocol */
void
proto_reg_handoff_dcom_cba (void)
{
	/* Register the DCOM coclass */
	dcom_register_server_coclass(proto_coclass_CBAPhysicalDevice, ett_coclass_CBAPhysicalDevice,
		&uuid_coclass_CBAPhysicalDevice, ver_coclass_CBAPhysicalDevice,
		coclass_ICBAPhysicalDevice_dissectors, hf_cba_opnum);

	/* Register the interfaces */
	dcerpc_init_uuid(proto_ICBAPhysicalDevice, ett_ICBAPhysicalDevice,
		&uuid_ICBAPhysicalDevice, ver_ICBAPhysicalDevice,
		ICBAPhysicalDevice_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAPhysicalDevice2, ett_ICBAPhysicalDevice,
		&uuid_ICBAPhysicalDevice2, ver_ICBAPhysicalDevice2,
		ICBAPhysicalDevice_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBABrowse, ett_ICBABrowse,
		&uuid_ICBABrowse, ver_ICBABrowse,
		ICBABrowse_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBABrowse2, ett_ICBABrowse,
		&uuid_ICBABrowse2, ver_ICBABrowse2,
		ICBABrowse_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAPhysicalDevicePC, ett_ICBAPhysicalDevicePC,
		&uuid_ICBAPhysicalDevicePC, ver_ICBAPhysicalDevicePC,
		ICBAPhysicalDevicePC_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAPhysicalDevicePCEvent, ett_ICBAPhysicalDevicePCEvent,
		&uuid_ICBAPhysicalDevicePCEvent, ver_ICBAPhysicalDevicePCEvent,
		ICBAPhysicalDevicePCEvent_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAPersist, ett_ICBAPersist,
		&uuid_ICBAPersist, ver_ICBAPersist,
		ICBAPersist_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAPersist2, ett_ICBAPersist,
		&uuid_ICBAPersist2, ver_ICBAPersist2,
		ICBAPersist_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBALogicalDevice, ett_ICBALogicalDevice,
		&uuid_ICBALogicalDevice, ver_ICBALogicalDevice,
		ICBALogicalDevice_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBALogicalDevice2, ett_ICBALogicalDevice,
		&uuid_ICBALogicalDevice2, ver_ICBALogicalDevice2,
		ICBALogicalDevice_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAState, ett_ICBAState,
		&uuid_ICBAState, ver_ICBAState,
		ICBAState_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAStateEvent, ett_ICBAStateEvent,
		&uuid_ICBAStateEvent, ver_ICBAStateEvent,
		ICBAStateEvent_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBATime, ett_ICBATime,
		&uuid_ICBATime, ver_ICBATime,
		ICBATime_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAGroupError, ett_ICBAGroupError,
		&uuid_ICBAGroupError, ver_ICBAGroupError, 
		ICBAGroupError_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBAGroupErrorEvent, ett_ICBAGroupErrorEvent,
		&uuid_ICBAGroupErrorEvent, ver_ICBAGroupErrorEvent,
		ICBAGroupErrorEvent_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBARTAuto, ett_ICBARTAuto,
		&uuid_ICBARTAuto, ver_ICBARTAuto, 
		ICBARTAuto_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBARTAuto2, ett_ICBARTAuto,
		&uuid_ICBARTAuto2, ver_ICBARTAuto2, 
		ICBARTAuto_dissectors, hf_cba_opnum);

	dcerpc_init_uuid(proto_ICBASystemProperties, ett_ICBASystemProperties,
		&uuid_ICBASystemProperties, ver_ICBASystemProperties, 
		ICBASystemProperties_dissectors, hf_cba_opnum);
}
