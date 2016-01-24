/* packet-dcerpc-spoolss.c
 * Routines for SMB \PIPE\spoolss packet disassembly
 * Copyright 2001-2003, Tim Potter <tpot@samba.org>
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

/* TODO list:

 - audit of item lengths

*/

#include "config.h"


#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-spoolss.h"
#include "packet-windows-common.h"

void proto_register_dcerpc_spoolss(void);
void proto_reg_handoff_dcerpc_spoolss(void);

/* GetPrinterDriver2 */

static int hf_clientmajorversion = -1;
static int hf_clientminorversion = -1;
static int hf_servermajorversion = -1;
static int hf_serverminorversion = -1;
static int hf_driverpath = -1;
static int hf_datafile = -1;
static int hf_configfile = -1;
static int hf_helpfile = -1;
static int hf_monitorname = -1;
static int hf_defaultdatatype = -1;
static int hf_driverinfo_cversion = -1;
static int hf_dependentfiles = -1;
static int hf_previousdrivernames = -1;
static int hf_driverdate = -1;
static int hf_padding = -1;
static int hf_driver_version_low = -1;
static int hf_driver_version_high = -1;
static int hf_mfgname = -1;
static int hf_oemurl = -1;
static int hf_hardwareid= -1;
static int hf_provider = -1;

/* GetPrinter */

/* Times */

static int hf_start_time = -1;
static int hf_end_time = -1;
static int hf_elapsed_time = -1;

/****************************************************************************/

/*
 * New hf index values - I'm in the process of doing a bit of a cleanup -tpot
 */

static int hf_opnum = -1;
static int hf_hnd = -1;
static int hf_rc = -1;
static int hf_offered = -1;
static int hf_needed = -1;
static int hf_returned = -1;
static int hf_buffer_size = -1;
static int hf_buffer_data = -1;
static int hf_string_parm_size = -1;
static int hf_string_parm_data= -1;
static int hf_offset = -1;
static int hf_level = -1;
static int hf_access_required = -1;

static int hf_printername = -1;
static int hf_machinename = -1;
static int hf_notifyname = -1;
static int hf_printerdesc = -1;
static int hf_printercomment = -1;
static int hf_servername = -1;
static int hf_sharename = -1;
static int hf_portname = -1;
static int hf_printerlocation = -1;
static int hf_drivername = -1;
static int hf_environment = -1;
static int hf_username = -1;
static int hf_documentname = -1;
static int hf_outputfile = -1;
static int hf_datatype = -1;
static int hf_textstatus = -1;
static int hf_sepfile = -1;
static int hf_printprocessor = -1;
static int hf_parameters = -1;

/* Printer information */

static int hf_printer_cjobs = -1;
static int hf_printer_total_jobs = -1;
static int hf_printer_total_bytes = -1;
static int hf_printer_global_counter = -1;
static int hf_printer_total_pages = -1;
static int hf_printer_major_version = -1;
static int hf_printer_build_version = -1;
static int hf_printer_unk7 = -1;
static int hf_printer_unk8 = -1;
static int hf_printer_unk9 = -1;
static int hf_printer_session_ctr = -1;
static int hf_printer_unk11 = -1;
static int hf_printer_printer_errors = -1;
static int hf_printer_unk13 = -1;
static int hf_printer_unk14 = -1;
static int hf_printer_unk15 = -1;
static int hf_printer_unk16 = -1;
static int hf_printer_changeid = -1;
static int hf_printer_unk18 = -1;
static int hf_printer_unk20 = -1;
static int hf_printer_c_setprinter = -1;
static int hf_printer_unk22 = -1;
static int hf_printer_unk23 = -1;
static int hf_printer_unk24 = -1;
static int hf_printer_unk25 = -1;
static int hf_printer_unk26 = -1;
static int hf_printer_unk27 = -1;
static int hf_printer_unk28 = -1;
static int hf_printer_unk29 = -1;
static int hf_printer_flags = -1;
static int hf_printer_priority = -1;
static int hf_printer_default_priority = -1;
static int hf_printer_jobs = -1;
static int hf_printer_averageppm = -1;
static int hf_printer_guid = -1;
static int hf_printer_action = -1;

/* Printer data */

static int hf_printerdata = -1;
static int hf_printerdata_key = -1;
static int hf_printerdata_value = -1;
static int hf_printerdata_type = -1;
static int hf_printerdata_size = -1; /* Length of printer data */
static int hf_printerdata_data = -1;
static int hf_printerdata_data_sz = -1;
static int hf_printerdata_data_dword = -1;

/* Devicemode */

static int hf_devmodectr_size = -1;

static int hf_devmode = -1;
static int hf_devmode_size = -1;
static int hf_devmode_spec_version = -1;
static int hf_devmode_driver_version = -1;
static int hf_devmode_size2 = -1;
static int hf_devmode_driver_extra_len = -1;
static int hf_devmode_fields = -1;
static int hf_devmode_orientation = -1;
static int hf_devmode_paper_size = -1;
static int hf_devmode_paper_width = -1;
static int hf_devmode_paper_length = -1;
static int hf_devmode_scale = -1;
static int hf_devmode_copies = -1;
static int hf_devmode_default_source = -1;
static int hf_devmode_print_quality = -1;
static int hf_devmode_color = -1;
static int hf_devmode_duplex = -1;
static int hf_devmode_y_resolution = -1;
static int hf_devmode_tt_option = -1;
static int hf_devmode_collate = -1;
static int hf_devmode_log_pixels = -1;
static int hf_devmode_bits_per_pel = -1;
static int hf_devmode_pels_width = -1;
static int hf_devmode_pels_height = -1;
static int hf_devmode_display_flags = -1;
static int hf_devmode_display_freq = -1;
static int hf_devmode_icm_method = -1;
static int hf_devmode_icm_intent = -1;
static int hf_devmode_media_type = -1;
static int hf_devmode_dither_type = -1;
static int hf_devmode_reserved1 = -1;
static int hf_devmode_reserved2 = -1;
static int hf_devmode_panning_width = -1;
static int hf_devmode_panning_height = -1;
static int hf_devmode_driver_extra = -1;

static int hf_devmode_fields_orientation = -1;
static int hf_devmode_fields_papersize = -1;
static int hf_devmode_fields_paperlength = -1;
static int hf_devmode_fields_paperwidth = -1;
static int hf_devmode_fields_scale = -1;
static int hf_devmode_fields_position = -1;
static int hf_devmode_fields_nup = -1;
static int hf_devmode_fields_copies = -1;
static int hf_devmode_fields_defaultsource = -1;
static int hf_devmode_fields_printquality = -1;
static int hf_devmode_fields_color = -1;
static int hf_devmode_fields_duplex = -1;
static int hf_devmode_fields_yresolution = -1;
static int hf_devmode_fields_ttoption = -1;
static int hf_devmode_fields_collate = -1;
static int hf_devmode_fields_formname = -1;
static int hf_devmode_fields_logpixels = -1;
static int hf_devmode_fields_bitsperpel = -1;
static int hf_devmode_fields_pelswidth = -1;
static int hf_devmode_fields_pelsheight = -1;
static int hf_devmode_fields_displayflags = -1;
static int hf_devmode_fields_displayfrequency = -1;
static int hf_devmode_fields_icmmethod = -1;
static int hf_devmode_fields_icmintent = -1;
static int hf_devmode_fields_mediatype = -1;
static int hf_devmode_fields_dithertype = -1;
static int hf_devmode_fields_panningwidth = -1;
static int hf_devmode_fields_panningheight = -1;

/* Print job */

static int hf_job_id = -1;
static int hf_job_priority = -1;
static int hf_job_position = -1;
static int hf_job_totalpages = -1;
static int hf_job_totalbytes = -1;
static int hf_job_pagesprinted = -1;
static int hf_job_bytesprinted = -1;
static int hf_job_size = -1;

static int hf_job_status = -1;
static int hf_job_status_paused = -1;
static int hf_job_status_error = -1;
static int hf_job_status_deleting = -1;
static int hf_job_status_spooling = -1;
static int hf_job_status_printing = -1;
static int hf_job_status_offline = -1;
static int hf_job_status_paperout = -1;
static int hf_job_status_printed = -1;
static int hf_job_status_deleted = -1;
static int hf_job_status_blocked = -1;
static int hf_job_status_user_intervention = -1;

/* Forms */

static int hf_form = -1;
static int hf_form_level = -1;
static int hf_form_name = -1;
static int hf_form_flags = -1;
static int hf_form_unknown = -1;
static int hf_form_width = -1;
static int hf_form_height = -1;
static int hf_form_left_margin = -1;
static int hf_form_top_margin = -1;
static int hf_form_horiz_len = -1;
static int hf_form_vert_len = -1;

static int hf_enumforms_num = -1;

/* Print notify */

static int hf_notify_options_version = -1;
static int hf_notify_options_flags = -1;
static int hf_notify_options_flags_refresh = -1;
static int hf_notify_options_count = -1;
static int hf_notify_option_type = -1;
static int hf_notify_option_reserved1 = -1;
static int hf_notify_option_reserved2 = -1;
static int hf_notify_option_reserved3 = -1;
static int hf_notify_option_count = -1;
static int hf_notify_option_data_count = -1;
static int hf_notify_info_count = -1;
static int hf_notify_info_version = -1;
static int hf_notify_info_flags = -1;
static int hf_notify_info_data_type = -1;
static int hf_notify_info_data_count = -1;
static int hf_notify_info_data_id = -1;
static int hf_notify_info_data_value1 = -1;
static int hf_notify_info_data_value2 = -1;
static int hf_notify_info_data_bufsize = -1;
static int hf_notify_info_data_buffer = -1;
static int hf_notify_info_data_buffer_len = -1;
static int hf_notify_info_data_buffer_data = -1;

static int hf_notify_field = -1;

static int hf_printerlocal = -1;

static int hf_rrpcn_changelow = -1;
static int hf_rrpcn_changehigh = -1;
static int hf_rrpcn_unk0 = -1;
static int hf_rrpcn_unk1 = -1;

static int hf_replyopenprinter_unk0 = -1;
static int hf_replyopenprinter_unk1 = -1;

static int hf_devmode_devicename = -1;
static int hf_devmode_form_name = -1;
static int hf_relative_string = -1;
static int hf_value_name = -1;
static int hf_keybuffer = -1;
static int hf_value_string = -1;

static expert_field ei_unimplemented_dissector = EI_INIT;
static expert_field ei_unknown_data = EI_INIT;
static expert_field ei_spool_printer_info_level = EI_INIT;
static expert_field ei_printer_info_level = EI_INIT;
static expert_field ei_form_level = EI_INIT;
static expert_field ei_job_info_level = EI_INIT;
static expert_field ei_driver_info_level = EI_INIT;
static expert_field ei_level = EI_INIT;
static expert_field ei_notify_info_data_type = EI_INIT;
static expert_field ei_enumprinterdataex_value = EI_INIT;

/* Registry data types */

#define DCERPC_REG_NONE                        0
#define DCERPC_REG_SZ                          1
#define DCERPC_REG_EXPAND_SZ                   2
#define DCERPC_REG_BINARY                      3
#define DCERPC_REG_DWORD                       4
#define DCERPC_REG_DWORD_LE                    4        /* DWORD, little endian
*/
#define DCERPC_REG_DWORD_BE                    5        /* DWORD, big endian */
#define DCERPC_REG_LINK                        6
#define DCERPC_REG_MULTI_SZ                    7
#define DCERPC_REG_RESOURCE_LIST               8
#define DCERPC_REG_FULL_RESOURCE_DESCRIPTOR    9
#define DCERPC_REG_RESOURCE_REQUIREMENTS_LIST 10

static const value_string reg_datatypes[] = {
	{ DCERPC_REG_NONE, "REG_NONE" },
	{ DCERPC_REG_SZ, "REG_SZ" },
	{ DCERPC_REG_EXPAND_SZ, "REG_EXPAND_SZ" },
	{ DCERPC_REG_BINARY, "REG_BINARY" },
	{ DCERPC_REG_DWORD, "REG_DWORD" },
/*	  { DCERPC_REG_DWORD_LE, "REG_DWORD_LE" }, */
	{ DCERPC_REG_DWORD_BE, "REG_DWORD_BE" },
	{ DCERPC_REG_LINK, "REG_LINK" },
	{ DCERPC_REG_MULTI_SZ, "REG_MULTI_SZ" },
	{ DCERPC_REG_RESOURCE_LIST, "REG_RESOURCE_LIST" },
	{ DCERPC_REG_FULL_RESOURCE_DESCRIPTOR, "REG_FULL_RESOURCE_DESCRIPTOR" },
	{ DCERPC_REG_RESOURCE_REQUIREMENTS_LIST, "REG_RESOURCE_REQUIREMENTS_LIST" },
	{0, NULL }
};
static value_string_ext reg_datatypes_ext = VALUE_STRING_EXT_INIT(reg_datatypes);

/****************************************************************************/

/*
 * Dissect SPOOLSS specific access rights
 */

static int hf_server_access_admin = -1;
static int hf_server_access_enum = -1;
static int hf_printer_access_admin = -1;
static int hf_printer_access_use = -1;
static int hf_job_access_admin = -1;

static void
spoolss_printer_specific_rights(tvbuff_t *tvb, gint offset, proto_tree *tree,
				guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_printer_access_use, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_printer_access_admin, tvb, offset, 4, access);
}

struct access_mask_info spoolss_printer_access_mask_info = {
	"SPOOLSS printer",
	spoolss_printer_specific_rights,
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

static void
spoolss_printserver_specific_rights(tvbuff_t *tvb, gint offset,
				    proto_tree *tree, guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_server_access_enum, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_server_access_admin, tvb, offset, 4, access);
}

struct access_mask_info spoolss_printserver_access_mask_info = {
	"SPOOLSS print server",
	spoolss_printserver_specific_rights,
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

static void
spoolss_job_specific_rights(tvbuff_t *tvb, gint offset,
			    proto_tree *tree, guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_job_access_admin, tvb, offset, 4, access);
}

struct access_mask_info spoolss_job_access_mask_info = {
	"SPOOLSS job",
	spoolss_job_specific_rights,
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

/*
 * Routines to dissect a spoolss BUFFER
 */

typedef struct {
	tvbuff_t *tvb;
	proto_item *tree;	/* Proto tree buffer located in */
	proto_item *item;
} BUFFER;

static gint ett_BUFFER = -1;

static int
dissect_spoolss_buffer_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	BUFFER *b = (BUFFER *)di->private_data;
	proto_item *item;
	guint32 size;
	const guint8 *data;

	if (di->conformant_run)
		return offset;

	/* Dissect size and data */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_buffer_size, &size);

	offset = dissect_ndr_uint8s(tvb, offset, pinfo, NULL, di, drep,
				    hf_buffer_data, size, &data);

	item = proto_tree_add_item(
		tree, hf_buffer_data, tvb, offset - size,
		size, ENC_NA);

	/* Return buffer info */

	if (b) {

		/* I'm not sure about this.  Putting the buffer into
		   its own tvb makes sense and the dissection code is
		   much clearer, but the data is a proper subset of
		   the actual tvb.  Not adding the new data source
		   makes the hex display confusing as it switches
		   between the 'DCERPC over SMB' tvb and the buffer
		   tvb with no visual cues as to what is going on. */

		b->tvb = tvb_new_child_real_data(tvb, data, size, size);
		add_new_data_source(pinfo, b->tvb, "SPOOLSS buffer");

		b->item = item;
		b->tree = proto_item_add_subtree(item, ett_BUFFER);
	}

	return offset;
}

/* Dissect a spoolss buffer and return buffer data */

static int
dissect_spoolss_buffer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		       proto_tree *tree, dcerpc_info *di, guint8 *drep, BUFFER *b)
{
	if (b)
		memset(b, 0, sizeof(BUFFER));

	di->private_data = b;

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_spoolss_buffer_data, NDR_POINTER_UNIQUE,
		"Buffer", -1);

	return offset;
}

static int
dissect_spoolss_string_parm_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 buffer_len, len;
	gchar *s;
	proto_item *item = NULL;

	if (di->conformant_run)
		return offset;

	/* Dissect size and data */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				hf_string_parm_size, &buffer_len);

	s = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len, ENC_UTF_16|ENC_LITTLE_ENDIAN);

	if (tree && buffer_len) {
		tvb_ensure_bytes_exist(tvb, offset, buffer_len);

		item = proto_tree_add_string(
			tree, hf_string_parm_data, tvb, offset, len, s);
	}
	offset += buffer_len;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", s);

	/* Append string to upper level item */
	if (tree && item) {
		item = item->parent != NULL ? item->parent : item;
		proto_item_append_text(item, ": %s", s);
	}

	return offset;
}

/* Dissect a spoolss string parameter */

static int
dissect_spoolss_string_parm(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		       proto_tree *tree, dcerpc_info *di, guint8 *drep, const char *text)
{
	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_spoolss_string_parm_data, NDR_POINTER_UNIQUE,
		text, -1);

	return offset;
}

/*
 * SYSTEM_TIME
 */

static gint ett_SYSTEM_TIME = -1;

static int hf_time_year = -1;
static int hf_time_month = -1;
static int hf_time_dow = -1;
static int hf_time_day = -1;
static int hf_time_hour = -1;
static int hf_time_minute = -1;
static int hf_time_second = -1;
static int hf_time_msec = -1;

static int
dissect_SYSTEM_TIME(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, dcerpc_info *di, guint8 *drep, const char *name,
		    gboolean add_subtree, char **data)
{
	proto_item *item = NULL;
	proto_tree *subtree = tree;
	guint16 year, month, day, hour, minute, second, millisecond;
	char *str;

	if (add_subtree) {
		subtree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_SYSTEM_TIME, &item, name);
	}

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep, hf_time_year, &year);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep, hf_time_month, &month);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep, hf_time_dow, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep, hf_time_day, &day);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep, hf_time_hour, &hour);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep, hf_time_minute, &minute);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep, hf_time_second, &second);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep, hf_time_msec, &millisecond);

	str = wmem_strdup_printf(wmem_packet_scope(),
			      "%d/%02d/%02d %02d:%02d:%02d.%03d",
			      year, month, day, hour, minute, second,
			      millisecond);

	if (add_subtree)
		proto_item_append_text(item, ": %s", str);

	if (data)
		*data = str;

	return offset;
}

static int
dissect_SYSTEM_TIME_ptr(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *str;


	offset =  dissect_SYSTEM_TIME(
		tvb, offset, pinfo, tree, di, drep, NULL, FALSE, &str);
	dcv->private_data = str;

	return offset;
}

/*
 * SpoolssClosePrinter
 */

static int
SpoolssClosePrinter_q(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, guint8 *drep _U_)
{
	e_ctx_hnd policy_hnd;
	char *pol_name;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, NULL,
		FALSE, TRUE);

	dcerpc_fetch_polhnd_data(&policy_hnd, &pol_name, NULL, NULL, NULL,
			     pinfo->num);

	if (pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	return offset;
}

static int
SpoolssClosePrinter_r(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, guint8 *drep _U_)
{
	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);


	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/* Dissect some printer data.  The get/set/enum printerdata routines all
   store value/data in a uint8 array.  We could use the ndr routines for
   this but that would result in one item for each byte in the printer
   data. */

static gint ett_printerdata_data = -1;
static gint ett_printerdata_value = -1;

static int
dissect_printerdata_data(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    dcerpc_info *di, guint8 *drep _U_, guint32 type)
{
	proto_item *item, *hidden_item;
	proto_tree *subtree;
	guint32 size;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_printerdata_data, &item, "Data");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_printerdata_size, &size);

	if (size) {

		offset = dissect_ndr_uint8s(
			tvb, offset, pinfo, subtree, di, drep,
			hf_printerdata_data, size, NULL);

		switch(type) {
		case DCERPC_REG_SZ: {
			char *data = tvb_get_string_enc(NULL, tvb, offset - size, size, ENC_UTF_16|ENC_LITTLE_ENDIAN);

			proto_item_append_text(item, ": %s", data);

			col_append_fstr(
					pinfo->cinfo, COL_INFO, " = %s", data);

			hidden_item = proto_tree_add_string(
				tree, hf_printerdata_data_sz, tvb,
				offset - size, size, data);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			g_free(data);

			break;
		}
		case DCERPC_REG_DWORD: {
			guint32 data = tvb_get_letohl(tvb, offset - size);

			proto_item_append_text(item, ": 0x%08x", data);

			col_append_fstr(
					pinfo->cinfo, COL_INFO, " = 0x%08x",
					data);

			hidden_item = proto_tree_add_uint(
				tree, hf_printerdata_data_dword, tvb,
				offset - size, 4, data);
			PROTO_ITEM_SET_HIDDEN(hidden_item);

			break;
		}
		case DCERPC_REG_BINARY:
			col_append_str(
					pinfo->cinfo, COL_INFO,
					" = <binary data>");
			break;

		default:
			break;
		}
	}

	proto_item_set_len(item, size + 4);

	return offset;
}

/*
 * SpoolssGetPrinterData
 */

static int
SpoolssGetPrinterData_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *value_name;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);


	value_name=NULL;
 	offset = dissect_ndr_cvstring(
 		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
 		hf_printerdata_value, TRUE, value_name ? NULL : &value_name);
	/* GetPrinterData() stores the printerdata in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			if(value_name){
				dcv->se_data = wmem_strdup(wmem_file_scope(), value_name);
			}
		}
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value_name);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssGetPrinterData_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 type;
	proto_item *hidden_item;
	const char *data;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_printerdata_type, &type);

	data = (const char *)(dcv->se_data ? dcv->se_data : "????");

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", data);

	offset = dissect_printerdata_data(
		tvb, offset, pinfo, tree, di, drep, type);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SpoolssGetPrinterDataEx
 */

static int
SpoolssGetPrinterDataEx_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *key_name, *value_name;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	key_name=NULL;
	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_printerdata_key, TRUE, &key_name);

	value_name=NULL;
	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_printerdata_value, TRUE, &value_name);

	/* GetPrinterDataEx() stores the key/value in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = wmem_strdup_printf(wmem_file_scope(),
				"%s==%s",
				key_name?key_name:"",
				value_name?value_name:"");
		}
	}

	if (dcv->se_data)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				(char *)dcv->se_data);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	return offset;
}

static int
SpoolssGetPrinterDataEx_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 size, type;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printerdata_type, &type);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_returned, &size);

	if (dcv->se_data) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", (char *)dcv->se_data);
	}

	if (size)
		dissect_printerdata_data(tvb, offset, pinfo, tree, di, drep, type);

	offset += size;

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SpoolssSetPrinterData
 */

static int
SpoolssSetPrinterData_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *value_name;
	guint32 type;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	value_name=NULL;
	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_printerdata_value, TRUE, &value_name);

	/* GetPrinterDataEx() stores the key/value in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = wmem_strdup_printf(wmem_file_scope(),
				"%s", value_name?value_name:"");
		}
	}


	if (dcv->se_data){
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", (char *)dcv->se_data);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_printerdata_type, &type);

	offset = dissect_printerdata_data(
		tvb, offset, pinfo, tree, di, drep, type);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssSetPrinterData_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep _U_)
{
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SpoolssSetPrinterDataEx
 */

static int hf_setprinterdataex_max_len = -1;
static int hf_setprinterdataex_real_len = -1;
static int hf_setprinterdataex_data = -1;

static int
SpoolssSetPrinterDataEx_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep _U_)
{
	char *key_name, *value_name;
	guint32 max_len;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_printerdata_key, TRUE, &key_name);

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_printerdata_value, TRUE, &value_name);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s/%s",
				key_name, value_name);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_printerdata_type, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_setprinterdataex_max_len, &max_len);

	offset = dissect_ndr_uint8s(
		tvb, offset, pinfo, tree, di, drep,
		hf_setprinterdataex_data, max_len, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_setprinterdataex_real_len, NULL);

	return offset;
}

static int
SpoolssSetPrinterDataEx_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep _U_)
{
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/* XXX - "name" should be an hf_ value for an FT_STRING. */
static int
dissect_spoolss_uint16uni(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, guint8 *drep _U_, char **data,
			  int hf_name)
{
	gint len, remaining;
	char *text;

	if (offset % 2)
		offset += 2 - (offset % 2);

	/* Get remaining data in buffer as a string */

	remaining = tvb_captured_length_remaining(tvb, offset);
	if (remaining <= 0) {
		if (data)
			*data = g_strdup("");
		return offset;
	}

	text = tvb_get_string_enc(NULL, tvb, offset, remaining, ENC_UTF_16|ENC_LITTLE_ENDIAN);
	len = (int)strlen(text);

	proto_tree_add_string(tree, hf_name, tvb, offset, len * 2, text);

	if (data)
		*data = text;
	else
		g_free(text);

	return offset + (len + 1) * 2;
}

/*
 * DEVMODE
 */

/* Devicemode orientation values */

static const value_string devmode_orientation_vals[] =
{
	{ DEVMODE_ORIENTATION_PORTRAIT, "Portrait" },
	{ DEVMODE_ORIENTATION_LANDSCAPE, "Landscape" },
	{ 0, NULL }
};

/* Paper size values.  International paper sizes is a fascinating
   topic.  No seriously!  (-: */

static const value_string devmode_papersize_vals[] =
{
	{ DEVMODE_PAPERSIZE_LETTER, "Letter" },
	{ DEVMODE_PAPERSIZE_LETTERSMALL, "Letter (small)" },
	{ DEVMODE_PAPERSIZE_TABLOID, "Tabloid" },
	{ DEVMODE_PAPERSIZE_LEDGER, "Ledger" },
	{ DEVMODE_PAPERSIZE_LEGAL, "Legal" },
	{ DEVMODE_PAPERSIZE_STATEMENT, "Statement" },
	{ DEVMODE_PAPERSIZE_EXECUTIVE, "Executive" },
	{ DEVMODE_PAPERSIZE_A3, "A3" },
	{ DEVMODE_PAPERSIZE_A4, "A4" },
	{ DEVMODE_PAPERSIZE_A4SMALL, "A4 (small)" },
	{ DEVMODE_PAPERSIZE_A5, "A5" },
	{ DEVMODE_PAPERSIZE_B4, "B4" },
	{ DEVMODE_PAPERSIZE_B5, "B5" },
	{ DEVMODE_PAPERSIZE_FOLIO, "Folio" },
	{ DEVMODE_PAPERSIZE_QUARTO, "Quarto" },
	{ DEVMODE_PAPERSIZE_10X14, "10x14" },
	{ DEVMODE_PAPERSIZE_11X17, "11x17" },
	{ DEVMODE_PAPERSIZE_NOTE, "Note" },
	{ DEVMODE_PAPERSIZE_ENV9, "Envelope #9" },
	{ DEVMODE_PAPERSIZE_ENV10, "Envelope #10" },
	{ DEVMODE_PAPERSIZE_ENV11, "Envelope #11" },
	{ DEVMODE_PAPERSIZE_ENV12, "Envelope #12" },
	{ DEVMODE_PAPERSIZE_ENV14, "Envelope #14" },
	{ DEVMODE_PAPERSIZE_CSHEET, "C sheet" },
	{ DEVMODE_PAPERSIZE_DSHEET, "D sheet" },
	{ DEVMODE_PAPERSIZE_ESHEET, "E sheet" },
	{ DEVMODE_PAPERSIZE_ENVDL, "Envelope DL" },
	{ DEVMODE_PAPERSIZE_ENVC5, "Envelope C5" },
	{ DEVMODE_PAPERSIZE_ENVC3, "Envelope C3" },
	{ DEVMODE_PAPERSIZE_ENVC4, "Envelope C4" },
	{ DEVMODE_PAPERSIZE_ENVC6, "Envelope C6" },
	{ DEVMODE_PAPERSIZE_ENVC65, "Envelope C65" },
	{ DEVMODE_PAPERSIZE_ENVB4, "Envelope B4" },
	{ DEVMODE_PAPERSIZE_ENVB5, "Envelope B5" },
	{ DEVMODE_PAPERSIZE_ENVB6, "Envelope B6" },
	{ DEVMODE_PAPERSIZE_ENVITALY, "Envelope (Italy)" },
	{ DEVMODE_PAPERSIZE_ENVMONARCH, "Envelope (Monarch)" },
	{ DEVMODE_PAPERSIZE_ENVPERSONAL, "Envelope (Personal)" },
	{ DEVMODE_PAPERSIZE_FANFOLDUS, "Fanfold (US)" },
	{ DEVMODE_PAPERSIZE_FANFOLDSTDGERMAN, "Fanfold (Std German)" },
	{ DEVMODE_PAPERSIZE_FANFOLDLGLGERMAN, "Fanfold (Legal German)" },
	{ DEVMODE_PAPERSIZE_ISOB4, "B4 (ISO)" },
	{ DEVMODE_PAPERSIZE_JAPANESEPOSTCARD, "Japanese postcard" },
	{ DEVMODE_PAPERSIZE_9X11, "9x11" },
	{ DEVMODE_PAPERSIZE_10X11, "10x11" },
	{ DEVMODE_PAPERSIZE_15X11, "15x11" },
	{ DEVMODE_PAPERSIZE_ENVINVITE, "Envelope (Invite)" },
	{ DEVMODE_PAPERSIZE_RESERVED48, "Reserved (48)" },
	{ DEVMODE_PAPERSIZE_RESERVED49, "Reserved (49)" },
	{ DEVMODE_PAPERSIZE_LETTEREXTRA, "Letter (Extra)" },
	{ DEVMODE_PAPERSIZE_LEGALEXTRA, "Legal (Extra)" },
	{ DEVMODE_PAPERSIZE_TABLOIDEXTRA, "Tabloid (Extra)" },
	{ DEVMODE_PAPERSIZE_A4EXTRA, "A4 (Extra)" },
	{ DEVMODE_PAPERSIZE_LETTERTRANS, "Letter (Transverse)" },
	{ DEVMODE_PAPERSIZE_A4TRANS, "A4 (Transverse)" },
	{ DEVMODE_PAPERSIZE_LETTEREXTRATRANS, "Letter (Extra, Transverse)" },
	{ DEVMODE_PAPERSIZE_APLUS, "A+" },
	{ DEVMODE_PAPERSIZE_BPLUS, "B+" },
	{ DEVMODE_PAPERSIZE_LETTERPLUS, "Letter+" },
	{ DEVMODE_PAPERSIZE_A4PLUS, "A4+" },
	{ DEVMODE_PAPERSIZE_A5TRANS, "A5 (Transverse)" },
	{ DEVMODE_PAPERSIZE_B5TRANS, "B5 (Transverse)" },
	{ DEVMODE_PAPERSIZE_A3EXTRA, "A3 (Extra)" },
	{ DEVMODE_PAPERSIZE_A5EXTRA, "A5 (Extra)" },
	{ DEVMODE_PAPERSIZE_B5EXTRA, "B5 (Extra)" },
	{ DEVMODE_PAPERSIZE_A2, "A2" },
	{ DEVMODE_PAPERSIZE_A3TRANS, "A3 (Transverse)" },
	{ DEVMODE_PAPERSIZE_A3EXTRATRANS, "A3 (Extra, Transverse" },
	{ DEVMODE_PAPERSIZE_DBLJAPANESEPOSTCARD, "Double Japanese Postcard" },
	{ DEVMODE_PAPERSIZE_A6, "A6" },
	{ DEVMODE_PAPERSIZE_JENVKAKU2, "Japanese Envelope (Kaku #2)" },
	{ DEVMODE_PAPERSIZE_JENVKAKU3, "Japanese Envelope (Kaku #3)" },
	{ DEVMODE_PAPERSIZE_JENVCHOU3, "Japanese Envelope (Chou #3)" },
	{ DEVMODE_PAPERSIZE_JENVCHOU4, "Japaneve Envelope (Chou #4)" },
	{ DEVMODE_PAPERSIZE_LETTERROT, "Letter (Rotated)" },
	{ DEVMODE_PAPERSIZE_A3ROT, "A3 (Rotated)" },
	{ DEVMODE_PAPERSIZE_A4ROT, "A4 (Rotated)" },
	{ DEVMODE_PAPERSIZE_A5ROT, "A5 (Rotated)" },
	{ DEVMODE_PAPERSIZE_B4JISROT, "B4 (JIS, Rotated)" },
	{ DEVMODE_PAPERSIZE_B5JISROT, "B5 (JIS, Rotated)"},
	{ DEVMODE_PAPERSIZE_JAPANESEPOSTCARDROT,
	  "Japanese Postcard (Rotated)" },
	{ DEVMODE_PAPERSIZE_DBLJAPANESEPOSTCARDROT82,
	  "Double Japanese Postcard (Rotated)" },
	{ DEVMODE_PAPERSIZE_A6ROT, "A6 (Rotated)" },
	{ DEVMODE_PAPERSIZE_JENVKAKU2ROT,
	  "Japanese Envelope (Kaku #2, Rotated)" },
	{ DEVMODE_PAPERSIZE_JENVKAKU3ROT,
	  "Japanese Envelope (Kaku #3, Rotated)" },
	{ DEVMODE_PAPERSIZE_JENVCHOU3ROT,
	  "Japanese Envelope (Chou #3, Rotated)" },
	{ DEVMODE_PAPERSIZE_JENVCHOU4ROT,
	  "Japanese Envelope (Chou #4, Rotated)" },
	{ DEVMODE_PAPERSIZE_B6JIS, "B6 (JIS)" },
	{ DEVMODE_PAPERSIZE_B6JISROT, "B6 (JIS, Rotated)" },
	{ DEVMODE_PAPERSIZE_12X11, "12x11" },
	{ DEVMODE_PAPERSIZE_JENVYOU4, "Japanese Envelope (You #4)" },
	{ DEVMODE_PAPERSIZE_JENVYOU4ROT,
	  "Japanese Envelope (You #4, Rotated" },
	{ DEVMODE_PAPERSIZE_P16K, "PRC 16K" },
	{ DEVMODE_PAPERSIZE_P32K, "PRC 32K" },
	{ DEVMODE_PAPERSIZE_P32KBIG, "P32K (Big)" },
	{ DEVMODE_PAPERSIZE_PENV1, "PRC Envelope #1" },
	{ DEVMODE_PAPERSIZE_PENV2, "PRC Envelope #2" },
	{ DEVMODE_PAPERSIZE_PENV3, "PRC Envelope #3" },
	{ DEVMODE_PAPERSIZE_PENV4, "PRC Envelope #4" },
	{ DEVMODE_PAPERSIZE_PENV5, "PRC Envelope #5" },
	{ DEVMODE_PAPERSIZE_PENV6, "PRC Envelope #6" },
	{ DEVMODE_PAPERSIZE_PENV7, "PRC Envelope #7" },
	{ DEVMODE_PAPERSIZE_PENV8, "PRC Envelope #8" },
	{ DEVMODE_PAPERSIZE_PENV9, "PRC Envelope #9" },
	{ DEVMODE_PAPERSIZE_PENV10, "PRC Envelope #10" },
	{ DEVMODE_PAPERSIZE_P16KROT, "PRC 16K (Rotated)" },
	{ DEVMODE_PAPERSIZE_P32KROT, "PRC 32K (Rotated)" },
	{ DEVMODE_PAPERSIZE_P32KBIGROT, "PRC 32K (Big, Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV1ROT, "PRC Envelope #1 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV2ROT, "PRC Envelope #2 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV3ROT, "PRC Envelope #3 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV4ROT, "PRC Envelope #4 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV5ROT, "PRC Envelope #5 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV6ROT, "PRC Envelope #6 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV7ROT, "PRC Envelope #7 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV8ROT, "PRC Envelope #8 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV9ROT, "PRC Envelope #9 (Rotated)" },
	{ DEVMODE_PAPERSIZE_PENV10ROT, "PRC Envelope #10 (Rotated)" },
	{ 0, NULL }
};
static value_string_ext devmode_papersize_vals_ext = VALUE_STRING_EXT_INIT(devmode_papersize_vals);

/* List of observed specversions */

static const value_string devmode_specversion_vals[] =
{
	{ 0x0320, "Observed" },
	{ 0x0400, "Observed" },
	{ 0x0401, "Observed" },
	{ 0x040d, "Observed" },
	{ 0, NULL }
};

/* Paper sources */

static const value_string devmode_papersource_vals[] =
{
	{ DEVMODE_PAPERSOURCE_UPPER, "Upper" },
	{ DEVMODE_PAPERSOURCE_LOWER, "Lower" },
	{ DEVMODE_PAPERSOURCE_MIDDLE, "Middle" },
	{ DEVMODE_PAPERSOURCE_MANUAL, "Manual" },
	{ DEVMODE_PAPERSOURCE_ENV, "Envelope" },
	{ DEVMODE_PAPERSOURCE_ENVMANUAL, "Envelope Manual" },
	{ DEVMODE_PAPERSOURCE_AUTO, "Auto" },
	{ DEVMODE_PAPERSOURCE_TRACTOR, "Tractor" },
	{ DEVMODE_PAPERSOURCE_SMALLFMT, "Small Format" },
	{ DEVMODE_PAPERSOURCE_LARGEFMAT, "Large Format" },
	{ DEVMODE_PAPERSOURCE_LARGECAP, "Large Capacity" },
	{ DEVMODE_PAPERSOURCE_CASSETTE, "Cassette" },
	{ DEVMODE_PAPERSOURCE_FORMSRC, "Form Source" },
	{ 0, NULL }
};
static value_string_ext devmode_papersource_vals_ext = VALUE_STRING_EXT_INIT(devmode_papersource_vals);

/* Print quality */

static const value_string devmode_printquality_vals[] =
{
	{ DEVMODE_PRINTQUALITY_HIGH, "High" },
	{ DEVMODE_PRINTQUALITY_MEDIUM, "Medium" },
	{ DEVMODE_PRINTQUALITY_LOW, "Low" },
	{ DEVMODE_PRINTQUALITY_DRAFT, "Draft" },
	{ 0, NULL }
};

/* Color */

static const value_string devmode_colour_vals[] =
{
	{ DEVMODE_COLOUR_COLOUR, "Colour" },
	{ DEVMODE_COLOUR_MONO, "Monochrome" },
	{ 0, NULL }
};

/* TrueType options */

static const value_string devmode_ttoption_vals[] =
{
	{ 0, "Not set" },
	{ DEVMODE_TTOPTION_BITMAP, "Bitmap" },
	{ DEVMODE_TTOPTION_DOWNLOAD, "Download" },
	{ DEVMODE_TTOPTION_DOWNLOAD_OUTLINE, "Download outline" },
	{ DEVMODE_TTOPTION_SUBDEV, "Substitute device fonts" },
	{ 0, NULL }
};

/* Collate info */

static const value_string devmode_collate_vals[] =
{
	{ DEVMODE_COLLATE_FALSE, "False" },
	{ DEVMODE_COLLATE_TRUE, "True" },
	{ 0, NULL }
};

/* Duplex info */

static const value_string devmode_duplex_vals[] =
{
	{ DEVMODE_DUPLEX_SIMPLEX, "Simplex" },
	{ DEVMODE_DUPLEX_VERT, "Vertical" },
	{ DEVMODE_DUPLEX_HORIZ, "Horizontal" },
	{ 0, NULL }
};

static const value_string devmode_displayflags_vals[] =
{
	{ 0, "Colour" },
	{ DEVMODE_DISPLAYFLAGS_GRAYSCALE, "Grayscale" },
	{ DEVMODE_DISPLAYFLAGS_INTERLACED, "Interlaced" },
	{ 0, NULL }
};

static const value_string devmode_icmmethod_vals[] =
{
	{ DEVMODE_ICMMETHOD_NONE, "None" },
	{ DEVMODE_ICMMETHOD_SYSTEM, "System" },
	{ DEVMODE_ICMMETHOD_DRIVER, "Driver" },
	{ DEVMODE_ICMMETHOD_DEVICE, "Device" },
	{ 0, NULL }
};

static const value_string devmode_icmintent_vals[] =
{
	{ 0, "Not set" },
	{ DEVMODE_ICMINTENT_SATURATE, "Saturate" },
	{ DEVMODE_ICMINTENT_CONTRAST, "Contrast" },
	{ DEVMODE_ICMINTENT_COLORIMETRIC, "Colorimetric" },
	{ DEVMODE_ICMINTENT_ABS_COLORIMETRIC, "Absolute colorimetric" },
	{ 0, NULL }
};

static const value_string devmode_mediatype_vals[] =
{
	{ 0, "Not set" },
	{ DEVMODE_MEDIATYPE_STANDARD, "Standard" },
	{ DEVMODE_MEDIATYPE_TRANSPARENCY, "Transparency" },
	{ DEVMODE_MEDIATYPE_GLOSSY, "Glossy" },
	{ 0, NULL }
};

static const value_string devmode_dithertype_vals[] =
{
	{ 0, "Not set" },
	{ DEVMODE_DITHERTYPE_NONE, "None" },
	{ DEVMODE_DITHERTYPE_COARSE, "Coarse" },
	{ DEVMODE_DITHERTYPE_LINE, "Line" },
	{ DEVMODE_DITHERTYPE_LINEART, "Line art" },
	{ DEVMODE_DITHERTYPE_ERRORDIFFUSION, "Error diffusion" },
	{ DEVMODE_DITHERTYPE_RESERVED6, "Reserved 6" },
	{ DEVMODE_DITHERTYPE_RESERVED7, "Reserved 7" },
	{ DEVMODE_DITHERTYPE_GRAYSCALE, "Grayscale" },
	{ 0, NULL }
};

static gint ett_DEVMODE_fields = -1;

static int
dissect_DEVMODE_fields(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		       proto_tree *tree, dcerpc_info *di, guint8 *drep _U_, guint32 *pdata)
{
	guint32 fields;
	proto_item *hidden_item;

	static const int * hf_fields[] = {
		&hf_devmode_fields_orientation,
		&hf_devmode_fields_papersize,
		&hf_devmode_fields_paperlength,
		&hf_devmode_fields_paperwidth,
		&hf_devmode_fields_scale,
		&hf_devmode_fields_position,
		&hf_devmode_fields_nup,
		&hf_devmode_fields_copies,
		&hf_devmode_fields_defaultsource,
		&hf_devmode_fields_printquality,
		&hf_devmode_fields_color,
		&hf_devmode_fields_duplex,
		&hf_devmode_fields_yresolution,
		&hf_devmode_fields_ttoption,
		&hf_devmode_fields_collate,
		&hf_devmode_fields_formname,
		&hf_devmode_fields_logpixels,
		&hf_devmode_fields_bitsperpel,
		&hf_devmode_fields_pelswidth,
		&hf_devmode_fields_pelsheight,
		&hf_devmode_fields_displayflags,
		&hf_devmode_fields_displayfrequency,
		&hf_devmode_fields_icmmethod,
		&hf_devmode_fields_icmintent,
		&hf_devmode_fields_mediatype,
		&hf_devmode_fields_dithertype,
		&hf_devmode_fields_panningwidth,
		&hf_devmode_fields_panningheight,
		NULL
	};

	hidden_item = proto_tree_add_uint(
		tree, hf_devmode, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &fields);

	proto_tree_add_bitmask_value_with_flags(tree, tvb, offset - 4, hf_devmode_fields,
					ett_DEVMODE_fields, hf_fields, fields, BMT_NO_APPEND);

	if (pdata)
		*pdata = fields;

	return offset;
}

static gint ett_DEVMODE = -1;

static int
dissect_DEVMODE(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint16 driver_extra;
	gint16 print_quality;
	guint32 fields;
	int struct_start = offset;

	if (di->conformant_run)
		return offset;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_DEVMODE, &item, "Devicemode");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_devmode_size,
		NULL);

	/* The device name is stored in a 32-wchar buffer */

	dissect_spoolss_uint16uni(tvb, offset, pinfo, subtree, drep, NULL, hf_devmode_devicename);
	offset += 64;

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_spec_version, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_driver_version, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_size2, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_driver_extra_len, &driver_extra);

	offset = dissect_DEVMODE_fields(
		tvb, offset, pinfo, subtree, di, drep, &fields);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_orientation, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_paper_size, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_paper_length, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_paper_width, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_scale, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_copies, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_default_source, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, NULL, di, drep,
		hf_devmode_print_quality, &print_quality);

	if (print_quality < 0)
		proto_tree_add_item(
			subtree, hf_devmode_print_quality, tvb,
			offset - 2, 2, DREP_ENC_INTEGER(drep));
	else
		proto_tree_add_uint_format_value(
			subtree, hf_devmode_print_quality, tvb, offset - 4, 4,
			print_quality, "%d dpi", print_quality);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_color, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_duplex, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_y_resolution, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_tt_option, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_collate, NULL);

	dissect_spoolss_uint16uni(tvb, offset, pinfo, subtree, drep, NULL, hf_devmode_form_name);
	offset += 64;

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_log_pixels, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_bits_per_pel, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_pels_width, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_pels_height, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_display_flags, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_display_freq, NULL);

	/* TODO: Some of the remaining fields are optional.  See
	   rpc_parse/parse_spoolss.c in the Samba source for details. */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_icm_method, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_icm_intent, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_media_type, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_dither_type, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_reserved1, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_reserved2, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_panning_width, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_devmode_panning_height, NULL);

	if (driver_extra)
		offset = dissect_ndr_uint8s(
			tvb, offset, pinfo, subtree, di, drep,
			hf_devmode_driver_extra, driver_extra, NULL);

	proto_item_set_len(item, offset - struct_start);

	return offset;
}

/*
 * DEVMODE_CTR
 */

static gint ett_DEVMODE_CTR = -1;

static int
dissect_DEVMODE_CTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	guint32 size;

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_DEVMODE_CTR, NULL, "Devicemode container");

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_devmodectr_size, &size);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, di, drep,
		dissect_DEVMODE, NDR_POINTER_UNIQUE, "Devicemode", -1);

	return offset;
}

/*
 * Relative string given by offset into the current buffer.  Note that
 * the offset for subsequent relstrs are against the structure start, not
 * the point where the offset is parsed from.
 */

static gint ett_RELSTR = -1;

static int
dissect_spoolss_relstr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index,
		       int struct_start, char **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 relstr_offset, relstr_start, relstr_end;
	char *text;

	/* Peek ahead to read the string.  We need this for the
	   proto_tree_add_string() call so filtering will work. */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_offset, &relstr_offset);

	relstr_start = relstr_offset + struct_start;

	if (relstr_offset) {
		relstr_end = dissect_spoolss_uint16uni(
			tvb, relstr_start, pinfo, NULL, drep, &text, hf_relative_string);
	} else { 			/* relstr_offset == 0 is a NULL string */
		text = g_strdup("");
		relstr_end = relstr_start;
	}

	/* OK now add the proto item with the string value */

	item = proto_tree_add_string(tree, hf_index, tvb, relstr_start, relstr_end - relstr_start, text);
	subtree = proto_item_add_subtree(item, ett_RELSTR);

	dissect_ndr_uint32(
		tvb, offset - 4, pinfo, subtree, di, drep, hf_offset, NULL);

	if (relstr_offset)
		dissect_spoolss_uint16uni(
			tvb, relstr_start, pinfo, subtree, drep, NULL, hf_relative_string);

	if (data)
		*data = text;
	else
		g_free(text);

	return offset;
}

/* An array of relative strings.  This is currently just a copy of the
   dissect_spoolss_relstr() function as I can't find an example driver that
   has more than one dependent file. */

static gint ett_RELSTR_ARRAY = -1;

static int
dissect_spoolss_relstrarray(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index,
			    int struct_start, char **data)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 relstr_offset, relstr_start/*, relstr_end, relstr_len*/;
	char *text;

	item = proto_tree_add_string(tree, hf_index, tvb, offset, 4, "");

	subtree = proto_item_add_subtree(item, ett_RELSTR_ARRAY);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_offset, &relstr_offset);

	/* A relative offset of zero is a NULL string */

	relstr_start = relstr_offset + struct_start;

	if (relstr_offset)
		/*relstr_end = */dissect_spoolss_uint16uni(
			tvb, relstr_start, pinfo, subtree, drep, &text, hf_relative_string);
	else {
		text = g_strdup("NULL");
		/*relstr_end = offset;*/
	}

	/*relstr_len = relstr_end - relstr_start;*/

	proto_item_append_text(item, "%s", text);

	if (data)
		*data = text;
	else
		g_free(text);

	return offset;
}

/*
 * PRINTER_INFO_0
 */

static int hf_printer_status = -1;

static const value_string printer_status_vals[] =
{
	{ PRINTER_STATUS_OK, "OK" },
	{ PRINTER_STATUS_PAUSED, "Paused" },
	{ PRINTER_STATUS_ERROR, "Error" },
	{ PRINTER_STATUS_PENDING_DELETION, "Pending deletion" },
	{ PRINTER_STATUS_PAPER_JAM, "Paper jam" },
	{ PRINTER_STATUS_PAPER_OUT, "Paper out" },
	{ PRINTER_STATUS_MANUAL_FEED, "Manual feed" },
	{ PRINTER_STATUS_PAPER_PROBLEM, "Paper problem" },
	{ PRINTER_STATUS_OFFLINE, "Offline" },
	{ PRINTER_STATUS_IO_ACTIVE, "IO active" },
	{ PRINTER_STATUS_BUSY, "Busy" },
	{ PRINTER_STATUS_PRINTING, "Printing" },
	{ PRINTER_STATUS_OUTPUT_BIN_FULL, "Output bin full" },
	{ PRINTER_STATUS_NOT_AVAILABLE, "Not available" },
	{ PRINTER_STATUS_WAITING, "Waiting" },
	{ PRINTER_STATUS_PROCESSING, "Processing" },
	{ PRINTER_STATUS_INITIALIZING, "Initialising" },
	{ PRINTER_STATUS_WARMING_UP, "Warming up" },
	{ PRINTER_STATUS_TONER_LOW, "Toner low" },
	{ PRINTER_STATUS_NO_TONER, "No toner" },
	{ PRINTER_STATUS_PAGE_PUNT, "Page punt" },
	{ PRINTER_STATUS_USER_INTERVENTION, "User intervention" },
	{ PRINTER_STATUS_OUT_OF_MEMORY, "Out of memory" },
	{ PRINTER_STATUS_DOOR_OPEN, "Door open" },
	{ PRINTER_STATUS_SERVER_UNKNOWN, "Server unknown" },
	{ PRINTER_STATUS_POWER_SAVE, "Power save" },
	{ 0, NULL }
};
static value_string_ext printer_status_vals_ext = VALUE_STRING_EXT_INIT(printer_status_vals);

static gint ett_PRINTER_INFO_0 = -1;

static int
dissect_PRINTER_INFO_0(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printername,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_servername,
		0, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_cjobs, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_total_jobs,
		NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_total_bytes,
		NULL);

	offset = dissect_SYSTEM_TIME(
		tvb, offset, pinfo, tree, di, drep, "Unknown time", TRUE, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_global_counter,
		NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_total_pages,
		NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_major_version,
		NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_build_version,
		NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk7, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk8, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk9, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_session_ctr,
		NULL);

	offset = dissect_ndr_uint32( tvb, offset, pinfo, tree, di, drep,
		hf_printer_unk11, NULL);

	offset = dissect_ndr_uint32( tvb, offset, pinfo, tree, di, drep,
		hf_printer_printer_errors, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk13, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk14, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk15, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk16, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_changeid, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk18, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_status, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk20, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printer_c_setprinter,
		NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk22, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk23, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk24, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk25, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk26, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk27, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk28, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, di, drep, hf_printer_unk29, NULL);

	return offset;
}

/*
 * PRINTER_INFO_1
 */

static gint ett_PRINTER_INFO_1 = -1;

static int
dissect_PRINTER_INFO_1(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_printer_flags, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printerdesc,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printername,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printercomment,
		0, NULL);

	return offset;
}

/* Job status */

static const true_false_string tfs_job_status_paused = {
	"Job is paused",
	"Job is not paused"
};

static const true_false_string tfs_job_status_error = {
	"Job has an error",
	"Job is OK"
};

static const true_false_string tfs_job_status_deleting = {
	"Job is being deleted",
	"Job is not being deleted"
};

static const true_false_string tfs_job_status_spooling = {
	"Job is being spooled",
	"Job is not being spooled"
};

static const true_false_string tfs_job_status_printing = {
	"Job is being printed",
	"Job is not being printed"
};

static const true_false_string tfs_job_status_offline = {
	"Job is offline",
	"Job is not offline"
};

static const true_false_string tfs_job_status_paperout = {
	"Job is out of paper",
	"Job is not out of paper"
};

static const true_false_string tfs_job_status_printed = {
	"Job has completed printing",
	"Job has not completed printing"
};

static const true_false_string tfs_job_status_deleted = {
	"Job has been deleted",
	"Job has not been deleted"
};

static const true_false_string tfs_job_status_blocked = {
	"Job has been blocked",
	"Job has not been blocked"
};

static const true_false_string tfs_job_status_user_intervention = {
	"User intervention required",
	"User intervention not required"
};

static gint ett_job_status = -1;

static int
dissect_job_status(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 status;
	static const int * hf_status[] = {
		&hf_job_status_user_intervention,
		&hf_job_status_blocked,
		&hf_job_status_deleted,
		&hf_job_status_printed,
		&hf_job_status_paperout,
		&hf_job_status_offline,
		&hf_job_status_printing,
		&hf_job_status_spooling,
		&hf_job_status_deleting,
		&hf_job_status_error,
		&hf_job_status_paused,
		NULL
	};

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &status);

	proto_tree_add_bitmask_value_with_flags(tree, tvb, offset - 4, hf_job_status,
					ett_job_status, hf_status, status, BMT_NO_APPEND);

	return offset;
}

/* Printer attributes */

static gint ett_printer_attributes = -1;

static int hf_printer_attributes = -1;
static int hf_printer_attributes_queued = -1;
static int hf_printer_attributes_direct = -1;
static int hf_printer_attributes_default = -1;
static int hf_printer_attributes_shared = -1;
static int hf_printer_attributes_network = -1;
static int hf_printer_attributes_hidden = -1;
static int hf_printer_attributes_local = -1;
static int hf_printer_attributes_enable_devq = -1;
static int hf_printer_attributes_keep_printed_jobs = -1;
static int hf_printer_attributes_do_complete_first = -1;
static int hf_printer_attributes_work_offline = -1;
static int hf_printer_attributes_enable_bidi = -1;
static int hf_printer_attributes_raw_only = -1;
static int hf_printer_attributes_published = -1;

static const true_false_string tfs_printer_attributes_queued = {
	"Printer starts printing after last page spooled",
	"Printer starts printing while spooling"
};

static const true_false_string tfs_printer_attributes_direct = {
	"Jobs sent directly to printer",
	"Jobs are spooled to printer before printing"
};

static const true_false_string tfs_printer_attributes_default = {
	"Printer is the default printer",
	"Printer is not the default printer"
};

static const true_false_string tfs_printer_attributes_shared = {
	"Printer is shared",
	"Printer is not shared"
};

static const true_false_string tfs_printer_attributes_network = {
	"Printer is a network printer connection",
	"Printer is not a network printer connection"
};

static const true_false_string tfs_printer_attributes_hidden = {
	"Reserved",
	"Reserved"
};

static const true_false_string tfs_printer_attributes_local = {
	"Printer is a local printer",
	"Printer is not a local printer"
};

static const true_false_string tfs_printer_attributes_enable_devq = {
	"Call DevQueryPrint",
	"Do not call DevQueryPrint"
};

static const true_false_string tfs_printer_attributes_keep_printed_jobs = {
	"Jobs are kept after they are printed",
	"Jobs are deleted after printing"
};

static const true_false_string tfs_printer_attributes_do_complete_first = {
	"Jobs that have completed spooling are scheduled before still spooling jobs",
	"Jobs are scheduled in the order they start spooling"
};

static const true_false_string tfs_printer_attributes_work_offline = {
	"The printer is currently connected",
	"The printer is currently not connected"
};

static const true_false_string tfs_printer_attributes_enable_bidi = {
	"Bidirectional communications are supported",
	"Bidirectional communications are not supported"
};

static const true_false_string tfs_printer_attributes_raw_only = {
	"Only raw data type print jobs can be spooled",
	"All data type print jobs can be spooled"
};

static const true_false_string tfs_printer_attributes_published = {
	"Printer is published in the directory",
	"Printer is not published in the directory"
};

static int
dissect_printer_attributes(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 attributes;
	static const int * hf_attributes[] = {
		&hf_printer_attributes_published,
		&hf_printer_attributes_raw_only,
		&hf_printer_attributes_enable_bidi,
		&hf_printer_attributes_work_offline,
		&hf_printer_attributes_do_complete_first,
		&hf_printer_attributes_keep_printed_jobs,
		&hf_printer_attributes_enable_devq,
		&hf_printer_attributes_local,
		&hf_printer_attributes_hidden,
		&hf_printer_attributes_network,
		&hf_printer_attributes_shared,
		&hf_printer_attributes_default,
		&hf_printer_attributes_direct,
		&hf_printer_attributes_queued,
		NULL
	};

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &attributes);

	proto_tree_add_bitmask_value_with_flags(tree, tvb, offset - 4, hf_printer_attributes,
					ett_printer_attributes, hf_attributes, attributes, BMT_NO_APPEND);

	return offset;
}

/*
 * PRINTER_INFO_2
 */

static gint ett_PRINTER_INFO_2 = -1;

static int
dissect_PRINTER_INFO_2(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	guint32 devmode_offset, secdesc_offset;

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_servername,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printername,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_sharename,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_portname,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_drivername,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printercomment,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printerlocation,
		0, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_offset,
		&devmode_offset);

	dissect_DEVMODE(tvb, devmode_offset - 4, pinfo, tree, di, drep);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_sepfile,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printprocessor,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_datatype,
		0, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_parameters,
		0, NULL);

	/*
	 * XXX - what *is* the length of this security descriptor?
	 * "prs_PRINTER_INFO_2()" is passed to "defer_ptr()", but
	 * "defer_ptr" takes, as an argument, a function with a
	 * different calling sequence from "prs_PRINTER_INFO_2()",
	 * lacking the "len" argument, so that won't work.
	 */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_offset,
		&secdesc_offset);

	dissect_nt_sec_desc(
		tvb, secdesc_offset, pinfo, tree, drep,
		FALSE, -1,
		&spoolss_printer_access_mask_info);

	offset = dissect_printer_attributes(tvb, offset, pinfo, tree, di, drep);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_printer_priority,
		NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep,
		hf_printer_default_priority, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_start_time, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_end_time, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_printer_status, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_printer_jobs,
		NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep,
		hf_printer_averageppm, NULL);

	return offset;
}

/*
 * PRINTER_INFO_3
 */

static gint ett_PRINTER_INFO_3 = -1;

static int
dissect_PRINTER_INFO_3(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_printer_flags, NULL);

	offset = dissect_nt_sec_desc(
		tvb, offset, pinfo, tree, drep,
		FALSE, -1,
		&spoolss_printer_access_mask_info);

	return offset;
}

/*
 * PRINTER_INFO_7
 */

static gint ett_PRINTER_INFO_7 = -1;

static const value_string getprinter_action_vals[] = {
	{ DS_PUBLISH, "Publish" },
	{ DS_UNPUBLISH, "Unpublish" },
	{ DS_UPDATE, "Update" },

	/* Not sure what the constant values are here */

/*	{ DS_PENDING, "Pending" }, */
/*	{ DS_REPUBLISH, "Republish" }, */

	{ 0, NULL }
};

static int
dissect_PRINTER_INFO_7(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, tree, di, drep, hf_printer_guid,
		0, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_printer_action, NULL);

	return offset;
}

/*
 * PRINTER_DATATYPE structure
 */

static gint ett_PRINTER_DATATYPE = -1;

static int
dissect_PRINTER_DATATYPE(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    dcerpc_info *di, guint8 *drep _U_)
{
	if (di->conformant_run)
		return offset;

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_datatype, TRUE, NULL);

	return offset;
}

/*
 * USER_LEVEL_1 structure
 */

static gint ett_USER_LEVEL_1 = -1;

static int hf_userlevel_size = -1;
static int hf_userlevel_client = -1;
static int hf_userlevel_user = -1;
static int hf_userlevel_build = -1;
static int hf_userlevel_major = -1;
static int hf_userlevel_minor = -1;
static int hf_userlevel_processor = -1;

static int
dissect_USER_LEVEL_1(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree,
				dcerpc_info *di, guint8 *drep)
{
	guint32 level;

	/* Guy has pointed out that this dissection looks wrong.  In
	   the wireshark output for a USER_LEVEL_1 it looks like the
	   info level and container pointer are transposed.  I'm not
	   even sure this structure is a container. */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_userlevel_size, NULL);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep, NDR_POINTER_UNIQUE,
		"Client", hf_userlevel_client, 0);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep, NDR_POINTER_UNIQUE,
		"User", hf_userlevel_user, 0);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_userlevel_build, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_userlevel_major, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_userlevel_minor, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_userlevel_processor, NULL);

	return offset;
}

/*
 * USER_LEVEL_CTR structure
 */

static gint ett_USER_LEVEL_CTR = -1;

static int
dissect_USER_LEVEL_CTR(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	proto_item *item;
	guint32 level;

	if (di->conformant_run)
		return offset;

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_USER_LEVEL_CTR, &item, "User level container");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_level, &level);

	switch(level) {
	case 1:
		offset = dissect_ndr_pointer(
			tvb, offset, pinfo, subtree, di, drep,
			dissect_USER_LEVEL_1, NDR_POINTER_UNIQUE,
			"User level 1", -1);
		break;
	default:
		expert_add_info_format(pinfo, item, &ei_level, "Info level %d not decoded", level);
		break;
	}

	return offset;
}

/*
 * SpoolssOpenPrinterEx
 */

static int
SpoolssOpenPrinterEx_q(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *name;

	/* Parse packet */

	dcv->private_data=NULL;
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Printer name", hf_printername, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | CB_STR_SAVE | 1));
	name = (char *)dcv->private_data;

	/* OpenPrinterEx() stores the key/value in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = wmem_strdup_printf(wmem_file_scope(),
				"%s", name?name:"");
		}
	}

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_PRINTER_DATATYPE, NDR_POINTER_UNIQUE,
		"Printer datatype", -1);

	offset = dissect_DEVMODE_CTR(tvb, offset, pinfo, tree, di, drep);

	name=(char *)dcv->se_data;
	if (name) {
		if (name[0] == '\\' && name[1] == '\\')
			name += 2;

		/* Determine if we are opening a printer or a print server */

		if (strchr(name, '\\'))
			offset = dissect_nt_access_mask(
				tvb, offset, pinfo, tree, di, drep,
				hf_access_required,
				&spoolss_printer_access_mask_info, NULL);
		else
			offset = dissect_nt_access_mask(
				tvb, offset, pinfo, tree, di, drep,
				hf_access_required,
				&spoolss_printserver_access_mask_info, NULL);
	} else {

		/* We can't decide what type of object being opened */

		offset = dissect_nt_access_mask(
			tvb, offset, pinfo, tree, di, drep, hf_access_required,
			NULL, NULL);
	}

	offset = dissect_USER_LEVEL_CTR(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int
SpoolssOpenPrinterEx_r(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, &hnd_item,
		TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, &status);

	if( status == 0 ){
		const char *pol_name;

		if (dcv->se_data){
			pol_name = wmem_strdup_printf(wmem_packet_scope(),
				"OpenPrinterEx(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown OpenPrinterEx() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_store_polhnd_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static const value_string printer_notify_option_data_vals[] = {
	{ PRINTER_NOTIFY_SERVER_NAME, "Server name" },
	{ PRINTER_NOTIFY_PRINTER_NAME, "Printer name" },
	{ PRINTER_NOTIFY_SHARE_NAME, "Share name" },
	{ PRINTER_NOTIFY_PORT_NAME, "Port name" },
	{ PRINTER_NOTIFY_DRIVER_NAME, "Driver name" },
	{ PRINTER_NOTIFY_COMMENT, "Comment" },
	{ PRINTER_NOTIFY_LOCATION, "Location" },
	{ PRINTER_NOTIFY_DEVMODE, "Devmode" },
	{ PRINTER_NOTIFY_SEPFILE, "Sepfile" },
	{ PRINTER_NOTIFY_PRINT_PROCESSOR, "Print processor" },
	{ PRINTER_NOTIFY_PARAMETERS, "Parameters" },
	{ PRINTER_NOTIFY_DATATYPE, "Datatype" },
	{ PRINTER_NOTIFY_SECURITY_DESCRIPTOR, "Security descriptor" },
	{ PRINTER_NOTIFY_ATTRIBUTES, "Attributes" },
	{ PRINTER_NOTIFY_PRIORITY, "Priority" },
	{ PRINTER_NOTIFY_DEFAULT_PRIORITY, "Default priority" },
	{ PRINTER_NOTIFY_START_TIME, "Start time" },
	{ PRINTER_NOTIFY_UNTIL_TIME, "Until time" },
	{ PRINTER_NOTIFY_STATUS, "Status" },
	{ PRINTER_NOTIFY_STATUS_STRING, "Status string" },
	{ PRINTER_NOTIFY_CJOBS, "Cjobs" },
	{ PRINTER_NOTIFY_AVERAGE_PPM, "Average PPM" },
	{ PRINTER_NOTIFY_TOTAL_PAGES, "Total pages" },
	{ PRINTER_NOTIFY_PAGES_PRINTED, "Pages printed" },
	{ PRINTER_NOTIFY_TOTAL_BYTES, "Total bytes" },
	{ PRINTER_NOTIFY_BYTES_PRINTED, "Bytes printed" },
	{ 0, NULL}
};
static value_string_ext printer_notify_option_data_vals_ext = VALUE_STRING_EXT_INIT(printer_notify_option_data_vals);

static const value_string job_notify_option_data_vals[] = {
	{ JOB_NOTIFY_PRINTER_NAME, "Printer name" },
	{ JOB_NOTIFY_MACHINE_NAME, "Machine name" },
	{ JOB_NOTIFY_PORT_NAME, "Port name" },
	{ JOB_NOTIFY_USER_NAME, "User name" },
	{ JOB_NOTIFY_NOTIFY_NAME, "Notify name" },
	{ JOB_NOTIFY_DATATYPE, "Data type" },
	{ JOB_NOTIFY_PRINT_PROCESSOR, "Print processor" },
	{ JOB_NOTIFY_PARAMETERS, "Parameters" },
	{ JOB_NOTIFY_DRIVER_NAME, "Driver name" },
	{ JOB_NOTIFY_DEVMODE, "Devmode" },
	{ JOB_NOTIFY_STATUS, "Status" },
	{ JOB_NOTIFY_STATUS_STRING, "Status string" },
	{ JOB_NOTIFY_SECURITY_DESCRIPTOR, "Security descriptor" },
	{ JOB_NOTIFY_DOCUMENT, "Document" },
	{ JOB_NOTIFY_PRIORITY, "Priority" },
	{ JOB_NOTIFY_POSITION, "Position" },
	{ JOB_NOTIFY_SUBMITTED, "Submitted" },
	{ JOB_NOTIFY_START_TIME, "Start time" },
	{ JOB_NOTIFY_UNTIL_TIME, "Until time" },
	{ JOB_NOTIFY_TIME, "Time" },
	{ JOB_NOTIFY_TOTAL_PAGES, "Total pages" },
	{ JOB_NOTIFY_PAGES_PRINTED, "Pages printed" },
	{ JOB_NOTIFY_TOTAL_BYTES, "Total bytes" },
	{ JOB_NOTIFY_BYTES_PRINTED, "Bytes printed" },
	{ 0, NULL}
};
static value_string_ext job_notify_option_data_vals_ext = VALUE_STRING_EXT_INIT(job_notify_option_data_vals);

static int
dissect_notify_field(tvbuff_t *tvb, int offset, packet_info *pinfo,
		     proto_tree *tree, dcerpc_info *di, guint8 *drep, guint16 type,
		     guint16 *data)
{
	guint16 field;
	const char *str;

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, NULL, di, drep,
		hf_notify_field, &field);

	switch(type) {
	case PRINTER_NOTIFY_TYPE:
		str = val_to_str_ext_const(field, &printer_notify_option_data_vals_ext,
				 "Unknown");
		break;
	case JOB_NOTIFY_TYPE:
		str = val_to_str_ext_const(field, &job_notify_option_data_vals_ext,
				 "Unknown");
		break;
	default:
		str = "Unknown notify type";
		break;
	}

	proto_tree_add_uint_format_value(tree, hf_notify_field, tvb, offset - 2, 2, field, "%s (%d)", str, field);

	if (data)
		*data = field;

	return offset;
}

static int
dissect_NOTIFY_OPTION_DATA(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 count, i;
	guint16 type;

	if (di->conformant_run)
		return offset;

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_notify_option_data_count, &count);

	type = GPOINTER_TO_INT(dcv->private_data);

	for (i = 0; i < count; i++)
		offset = dissect_notify_field(
			tvb, offset, pinfo, tree, di, drep, type, NULL);

	return offset;
}

static const value_string printer_notify_types[] =
{
	{ PRINTER_NOTIFY_TYPE, "Printer notify" },
	{ JOB_NOTIFY_TYPE, "Job notify" },
	{ 0, NULL }
};

static const
char *notify_plural(int count)
{
	if (count == 1)
		return "notification";

	return "notifies";
}

static gint ett_NOTIFY_OPTION = -1;

static int
dissect_NOTIFY_OPTION(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	proto_item *item;
	proto_tree *subtree;
	guint16 type;
	guint32 count;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_NOTIFY_OPTION, &item, "Notify Option");

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, di, drep,
				    hf_notify_option_type, &type);

	proto_item_append_text(
		item, ": %s", val_to_str(type, printer_notify_types,
					 "Unknown (%d)"));

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, di, drep,
				    hf_notify_option_reserved1, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_notify_option_reserved2, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_notify_option_reserved3, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_notify_option_count, &count);

	proto_item_append_text(
		item, ", %d %s", count, notify_plural(count));

	dcv->private_data = GINT_TO_POINTER((int)type);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, di, drep,
		dissect_NOTIFY_OPTION_DATA, NDR_POINTER_UNIQUE,
		"Notify Option Data", -1);

	return offset;
}

static int
dissect_NOTIFY_OPTIONS_ARRAY(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     dcerpc_info *di, guint8 *drep)
{
	/* Why is a check for di->conformant_run not required here? */

	offset = dissect_ndr_ucarray(
		tvb, offset, pinfo, tree, di, drep, dissect_NOTIFY_OPTION);

	return offset;
}

static gint ett_notify_options_flags = -1;

static const true_false_string tfs_notify_options_flags_refresh = {
	"Data for all monitored fields is present",
	"Data for all monitored fields not present"
};

static int
dissect_notify_options_flags(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 flags;
	static const int * hf_flags[] = {
		&hf_notify_options_flags_refresh,
		NULL
	};

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);

	proto_tree_add_bitmask_value_with_flags(tree, tvb, offset - 4, hf_notify_options_flags,
					ett_notify_options_flags, hf_flags, flags, BMT_NO_APPEND);

	return offset;
}

static int
dissect_NOTIFY_OPTIONS_ARRAY_CTR(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, guint8 *drep)
{
	if (di->conformant_run)
		return offset;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_notify_options_version, NULL);

	offset = dissect_notify_options_flags(tvb, offset, pinfo, tree, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_notify_options_count, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_NOTIFY_OPTIONS_ARRAY, NDR_POINTER_UNIQUE,
		"Notify Options Array", -1);

	return offset;
}

/*
 * SpoolssRFFPCNEX
 */

static gint ett_rffpcnex_flags = -1;

static int hf_rffpcnex_flags = -1;
static int hf_rffpcnex_options = -1;

static int hf_rffpcnex_flags_add_printer = -1;
static int hf_rffpcnex_flags_set_printer = -1;
static int hf_rffpcnex_flags_delete_printer = -1;
static int hf_rffpcnex_flags_failed_printer_connection = -1;

static const true_false_string tfs_rffpcnex_flags_add_printer = {
	"Notify on add printer",
	"Don't notify on add printer"
};

static const true_false_string tfs_rffpcnex_flags_set_printer = {
	"Notify on set printer",
	"Don't notify on set printer"
};

static const true_false_string tfs_rffpcnex_flags_delete_printer = {
	"Notify on delete printer",
	"Don't notify on delete printer"
};

static const true_false_string tfs_rffpcnex_flags_failed_connection_printer = {
	"Notify on failed printer connection",
	"Don't notify on failed printer connection"
};

static int hf_rffpcnex_flags_add_job = -1;
static int hf_rffpcnex_flags_set_job = -1;
static int hf_rffpcnex_flags_delete_job = -1;
static int hf_rffpcnex_flags_write_job = -1;

static const true_false_string tfs_rffpcnex_flags_add_job = {
	"Notify on add job",
	"Don't notify on add job"
};

static const true_false_string tfs_rffpcnex_flags_set_job = {
	"Notify on set job",
	"Don't notify on set job"
};

static const true_false_string tfs_rffpcnex_flags_delete_job = {
	"Notify on delete job",
	"Don't notify on delete job"
};

static const true_false_string tfs_rffpcnex_flags_write_job = {
	"Notify on writejob",
	"Don't notify on write job"
};

static int hf_rffpcnex_flags_add_form = -1;
static int hf_rffpcnex_flags_set_form = -1;
static int hf_rffpcnex_flags_delete_form = -1;

static const true_false_string tfs_rffpcnex_flags_add_form = {
	"Notify on add form",
	"Don't notify on add form"
};

static const true_false_string tfs_rffpcnex_flags_set_form = {
	"Notify on set form",
	"Don't notify on set form"
};

static const true_false_string tfs_rffpcnex_flags_delete_form = {
	"Notify on delete form",
	"Don't notify on delete form"
};

static int hf_rffpcnex_flags_add_port = -1;
static int hf_rffpcnex_flags_configure_port = -1;
static int hf_rffpcnex_flags_delete_port = -1;

static const true_false_string tfs_rffpcnex_flags_add_port = {
	"Notify on add port",
	"Don't notify on add port"
};

static const true_false_string tfs_rffpcnex_flags_configure_port = {
	"Notify on configure port",
	"Don't notify on configure port"
};

static const true_false_string tfs_rffpcnex_flags_delete_port = {
	"Notify on delete port",
	"Don't notify on delete port"
};

static int hf_rffpcnex_flags_add_print_processor = -1;
static int hf_rffpcnex_flags_delete_print_processor = -1;

static const true_false_string tfs_rffpcnex_flags_add_print_processor = {
	"Notify on add driver",
	"Don't notify on add driver"
};

static const true_false_string tfs_rffpcnex_flags_delete_print_processor = {
	"Notify on add driver",
	"Don't notify on add driver"
};

static int hf_rffpcnex_flags_add_driver = -1;
static int hf_rffpcnex_flags_set_driver = -1;
static int hf_rffpcnex_flags_delete_driver = -1;

static const true_false_string tfs_rffpcnex_flags_add_driver = {
	"Notify on add driver",
	"Don't notify on add driver"
};

static const true_false_string tfs_rffpcnex_flags_set_driver = {
	"Notify on set driver",
	"Don't notify on set driver"
};

static const true_false_string tfs_rffpcnex_flags_delete_driver = {
	"Notify on delete driver",
	"Don't notify on delete driver"
};

static int hf_rffpcnex_flags_timeout = -1;

static const true_false_string tfs_rffpcnex_flags_timeout = {
	"Notify on timeout",
	"Don't notify on timeout"
};

static int
SpoolssRFFPCNEX_q(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     dcerpc_info *di, guint8 *drep _U_)
{
	guint32 flags;
	static const int * hf_flags[] = {
		&hf_rffpcnex_flags_timeout,
		&hf_rffpcnex_flags_delete_driver,
		&hf_rffpcnex_flags_set_driver,
		&hf_rffpcnex_flags_add_driver,
		&hf_rffpcnex_flags_delete_print_processor,
		&hf_rffpcnex_flags_add_print_processor,
		&hf_rffpcnex_flags_delete_port,
		&hf_rffpcnex_flags_configure_port,
		&hf_rffpcnex_flags_add_port,
		&hf_rffpcnex_flags_delete_form,
		&hf_rffpcnex_flags_set_form,
		&hf_rffpcnex_flags_add_form,
		&hf_rffpcnex_flags_write_job,
		&hf_rffpcnex_flags_delete_job,
		&hf_rffpcnex_flags_set_job,
		&hf_rffpcnex_flags_add_job,
		&hf_rffpcnex_flags_failed_printer_connection,
		&hf_rffpcnex_flags_delete_printer,
		&hf_rffpcnex_flags_set_printer,
		&hf_rffpcnex_flags_add_printer,
		NULL
	};

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);

	proto_tree_add_bitmask_value(tree, tvb, offset - 4, hf_rffpcnex_flags,
					ett_rffpcnex_flags, hf_flags, flags);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_rffpcnex_options, NULL);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep, NDR_POINTER_UNIQUE,
		"Server", hf_servername, 0);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printerlocal, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_NOTIFY_OPTIONS_ARRAY_CTR, NDR_POINTER_UNIQUE,
		"Notify Options Container", -1);

	return offset;
}

static int
SpoolssRFFPCNEX_r(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     dcerpc_info *di, guint8 *drep _U_)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SpoolssReplyOpenPrinter
 */

static int
SpoolssReplyOpenPrinter_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 printerlocal;
	char *name;

	/* Parse packet */
	name=NULL;
	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_servername, TRUE, &name);
	/* ReplyOpenPrinter() stores the printername in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			if(name){
				dcv->se_data = wmem_strdup(wmem_file_scope(), name);
			}
		}
	}

	if (name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", name);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printerlocal,
		&printerlocal);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_printerdata_type, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_replyopenprinter_unk0,
		NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_replyopenprinter_unk1,
		NULL);

	return offset;
}

static int
SpoolssReplyOpenPrinter_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, &hnd_item,
		TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, &status);

	if( status == 0 ){
		const char *pol_name;

		if (dcv->se_data){
			pol_name = wmem_strdup_printf(wmem_packet_scope(),
				"ReplyOpenPrinter(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown ReplyOpenPrinter() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_store_polhnd_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

/*
 * SpoolssGetPrinter
 */


static int
SpoolssGetPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
 		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	/* GetPrinter() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
			dcv->se_data = GINT_TO_POINTER((int)level);
	}


	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static gint ett_PRINTER_INFO = -1;

static int
SpoolssGetPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	BUFFER buffer;
	gint16 level = GPOINTER_TO_INT(dcv->se_data);
	proto_item *item = NULL;
	proto_tree *subtree = NULL;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	/* Parse packet */

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, &buffer);

	if (buffer.tvb) {
		subtree = proto_tree_add_subtree_format( buffer.tree, buffer.tvb, 0, -1, ett_PRINTER_INFO, &item, "Print info level %d", level);

		switch(level) {
		case 0:
			dissect_PRINTER_INFO_0(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		case 1:
			dissect_PRINTER_INFO_1(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		case 2:
			dissect_PRINTER_INFO_2(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		case 3:
			dissect_PRINTER_INFO_3(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		case 7:
			dissect_PRINTER_INFO_7(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		default:
			expert_add_info(pinfo, item, &ei_printer_info_level);
			break;
		}
	}

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SEC_DESC_BUF
 */

static gint ett_SEC_DESC_BUF = -1;

static int hf_secdescbuf_maxlen = -1;
static int hf_secdescbuf_undoc = -1;
static int hf_secdescbuf_len = -1;

static int
dissect_SEC_DESC_BUF(tvbuff_t *tvb, int offset, packet_info *pinfo,
		     proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	guint32 len;

	/* XXX: I think this is really a array of bytes which can be
	   dissected using dissect_ndr_cvstring().  The dissected data
	   can be passed to dissect_nt_sec_desc().  The problem is that
	   dissect_nt_cvstring() passes back a char * where it really
	   should pass back a tvb. */

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_SEC_DESC_BUF, NULL, "Security descriptor buffer");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_secdescbuf_maxlen, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_secdescbuf_undoc, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_secdescbuf_len, &len);

	dissect_nt_sec_desc(
		tvb, offset, pinfo, subtree, drep, TRUE, len,
		&spoolss_printer_access_mask_info);

	offset += len;

	return offset;
}

/*
 * SPOOL_PRINTER_INFO_LEVEL
 */

static gint ett_SPOOL_PRINTER_INFO_LEVEL = -1;

/* spool printer info */

static int hf_spool_printer_info_devmode_ptr = -1;
static int hf_spool_printer_info_secdesc_ptr = -1;

static int
dissect_SPOOL_PRINTER_INFO(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	guint32 level;
	proto_tree *item;

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_SPOOL_PRINTER_INFO_LEVEL, &item, "Spool printer info level");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_level, &level);

	switch(level) {
	case 3: {
		guint32 devmode_ptr, secdesc_ptr;

		/* I can't seem to get this working with the correct
		   dissect_ndr_pointer() function so let's cheat and
		   dissect the pointers by hand. )-: */

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, subtree, di, drep,
			hf_spool_printer_info_devmode_ptr,
			&devmode_ptr);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, subtree, di, drep,
			hf_spool_printer_info_secdesc_ptr,
			&secdesc_ptr);

		if (devmode_ptr)
			offset = dissect_DEVMODE_CTR(
				tvb, offset, pinfo, subtree, di, drep);

		if (secdesc_ptr)
			offset = dissect_SEC_DESC_BUF(
				tvb, offset, pinfo, subtree, di, drep);

	break;
	}
	case 2:
	default:
		expert_add_info_format(pinfo, item, &ei_spool_printer_info_level, "Unknown spool printer info level %d", level);
		break;
	}

	return offset;
}

/*
 * SpoolssSetPrinter
 */

static int hf_setprinter_cmd = -1;

static const value_string setprinter_cmd_vals[] = {
	{ SPOOLSS_PRINTER_CONTROL_UNPAUSE, "Unpause" },
	{ SPOOLSS_PRINTER_CONTROL_PAUSE, "Pause" },
	{ SPOOLSS_PRINTER_CONTROL_RESUME, "Resume" },
	{ SPOOLSS_PRINTER_CONTROL_PURGE, "Purge" },
	{ SPOOLSS_PRINTER_CONTROL_SET_STATUS, "Set status" },
	{ 0, NULL }
};

static int
SpoolssSetPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	guint32 level;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_SPOOL_PRINTER_INFO(
		tvb, offset, pinfo, tree, di, drep);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_setprinter_cmd, NULL);

	return offset;
}

static int
SpoolssSetPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * FORM_REL
 */

static const value_string form_type_vals[] =
{
	{ SPOOLSS_FORM_USER, "User" },
	{ SPOOLSS_FORM_BUILTIN, "Builtin" },
	{ SPOOLSS_FORM_PRINTER, "Printer" },
	{ 0, NULL }
};

static gint ett_FORM_REL = -1;

static int
dissect_FORM_REL(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep, int struct_start)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 flags;
	int item_start = offset;
	char *name = NULL;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_FORM_REL, &item, "Form");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_form_flags, &flags);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_form_name,
		struct_start, &name);

	if (name) {
		proto_item_append_text(item, ": %s", name);
		g_free(name);
	}

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_width, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_height, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_left_margin, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_top_margin, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_horiz_len, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_vert_len, NULL);

	proto_item_set_len(item, offset - item_start);

	return offset;
}

/*
 * SpoolssEnumForms
 */

static int
SpoolssEnumForms_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	/* EnumForms() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
			dcv->se_data = GINT_TO_POINTER((int)level);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssEnumForms_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	BUFFER buffer;
	guint32 level = GPOINTER_TO_UINT(dcv->se_data), i, count;
	int buffer_offset;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, &buffer);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_enumforms_num, &count);

	/* Unfortunately this array isn't in NDR format so we can't
	   use prs_array().  The other weird thing is the
	   struct_start being inside the loop rather than outside.
	   Very strange. */

	buffer_offset = 0;

	for (i = 0; i < count; i++) {
		int struct_start = buffer_offset;

		buffer_offset = dissect_FORM_REL(
			buffer.tvb, buffer_offset, pinfo, buffer.tree, di, drep,
			struct_start);
	}

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SpoolssDeletePrinter
 */

static int
SpoolssDeletePrinter_q(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep _U_)
{
	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	return offset;
}

static int
SpoolssDeletePrinter_r(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep _U_)
{
	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

static int
SpoolssAddPrinterEx_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, &hnd_item,
		TRUE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, &status);

	if( status == 0 ){
		const char *pol_name;

		if (dcv->se_data){
			pol_name = wmem_strdup_printf(wmem_packet_scope(),
				"AddPrinterEx(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown AddPrinterEx() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_store_polhnd_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

/*
 * SpoolssEnumPrinterData
 */

static int hf_enumprinterdata_enumindex = -1;
static int hf_enumprinterdata_value_offered = -1;
static int hf_enumprinterdata_data_offered = -1;
static int hf_enumprinterdata_value_len = -1;
static int hf_enumprinterdata_value_needed = -1;
static int hf_enumprinterdata_data_needed = -1;

static int
SpoolssEnumPrinterData_q(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    dcerpc_info *di, guint8 *drep _U_)
{
	guint32 ndx;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_enumprinterdata_enumindex, &ndx);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", index %d", ndx);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_enumprinterdata_value_offered, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_enumprinterdata_data_offered, NULL);

	return offset;
}

static int
SpoolssEnumPrinterData_r(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    dcerpc_info *di, guint8 *drep _U_)
{
	guint32 value_len, type;
	char *value;
	proto_item *value_item;
	proto_tree *value_subtree;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	value_subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_printerdata_value, &value_item, "Value");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, value_subtree, di, drep,
		hf_enumprinterdata_value_len, &value_len);

	if (value_len) {
		dissect_spoolss_uint16uni(
			tvb, offset, pinfo, value_subtree, drep, &value, hf_value_name);

		offset += value_len * 2;

		if (value && value[0])
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value);

		proto_item_append_text(value_item, ": %s", value);

		hidden_item = proto_tree_add_string(
			tree, hf_printerdata_value, tvb, offset, 0, value);
		PROTO_ITEM_SET_HIDDEN(hidden_item);

		g_free(value);
	}

	proto_item_set_len(value_item, value_len * 2 + 4);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, value_subtree, di, drep,
		hf_enumprinterdata_value_needed, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_printerdata_type, &type);

	offset = dissect_printerdata_data(
		tvb, offset, pinfo, tree, di, drep, type);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_enumprinterdata_data_needed, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SpoolssEnumPrinters
 */

static gint ett_enumprinters_flags = -1;

static int hf_enumprinters_flags = -1;
static int hf_enumprinters_flags_local = -1;
static int hf_enumprinters_flags_name = -1;
static int hf_enumprinters_flags_shared = -1;
static int hf_enumprinters_flags_default = -1;
static int hf_enumprinters_flags_connections = -1;
static int hf_enumprinters_flags_network = -1;
static int hf_enumprinters_flags_remote = -1;

static int
SpoolssEnumPrinters_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	guint32 level, flags;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	static const int * hf_flags[] = {
		&hf_enumprinters_flags_network,
		&hf_enumprinters_flags_shared,
		&hf_enumprinters_flags_remote,
		&hf_enumprinters_flags_name,
		&hf_enumprinters_flags_connections,
		&hf_enumprinters_flags_local,
		&hf_enumprinters_flags_default,
		NULL
	};

	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);

	proto_tree_add_bitmask_value(tree, tvb, offset - 4, hf_enumprinters_flags,
					ett_enumprinters_flags, hf_flags, flags);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep,
		NDR_POINTER_UNIQUE, "Server name", hf_servername, 0);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	/* GetPrinter() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
		dcv->se_data = GINT_TO_POINTER((int)level);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssEnumPrinters_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	guint32 num_drivers;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	gint16 level = GPOINTER_TO_INT(dcv->se_data);
	BUFFER buffer;
	proto_item *item;
	proto_tree *subtree = NULL;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	/* Parse packet */

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, &buffer);

	if (buffer.tvb) {
		subtree = proto_tree_add_subtree_format( buffer.tree, buffer.tvb, 0, -1, ett_PRINTER_INFO, &item, "Print info level %d", level);

		switch(level) {
		case 0:
			dissect_PRINTER_INFO_0(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		case 1:
			dissect_PRINTER_INFO_1(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		case 2:
			dissect_PRINTER_INFO_2(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		case 3:
			dissect_PRINTER_INFO_3(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		case 7:
			dissect_PRINTER_INFO_7(
				buffer.tvb, 0, pinfo, subtree, di, drep);
			break;
		default:
			expert_add_info(pinfo, item, &ei_printer_info_level);
			break;
		}
	}

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_returned,
		&num_drivers);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * AddPrinterDriver
 */
static int
SpoolssAddPrinterDriver_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep _U_)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * FORM_1
 */

static gint ett_FORM_1 = -1;

static int
dissect_FORM_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	guint32 flags;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_FORM_1, NULL, "Form level 1");

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, subtree, di, drep, NDR_POINTER_UNIQUE,
		"Name", hf_form_name, 0);

	/* Eek - we need to know whether this pointer was NULL or not.
	   Currently there is not any way to do this. */

	if (tvb_reported_length_remaining(tvb, offset) <= 0)
		goto done;

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_form_flags, &flags);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_unknown, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_width, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_height, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_left_margin, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_top_margin, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_horiz_len, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_form_vert_len, NULL);

 done:
	return offset;
}

/*
 * FORM_CTR
 */

static gint ett_FORM_CTR = -1;

static int
dissect_FORM_CTR(tvbuff_t *tvb, int offset,
			    packet_info *pinfo, proto_tree *tree,
			    dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	proto_item *item;
	guint32 level;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_FORM_CTR, &item, "Form container");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_form_level, &level);

	switch(level) {
	case 1:
		offset = dissect_FORM_1(tvb, offset, pinfo, subtree, di, drep);
		break;

	default:
		expert_add_info_format(pinfo, item, &ei_form_level, "Unknown form info level %d", level);
		break;
	}

	return offset;
}

/*
 * AddForm
 */

static int
SpoolssAddForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_form_level, &level);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	/* AddForm() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
			dcv->se_data = GUINT_TO_POINTER((int)level);
	}

	offset = dissect_FORM_CTR(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int
SpoolssAddForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * DeleteForm
 */

static int
SpoolssDeleteForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	proto_item *hidden_item;
	char *name = NULL;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep,
		sizeof(guint16), hf_form_name, TRUE, &name);

	if (name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", name);

	return offset;
}

static int
SpoolssDeleteForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SetForm
 */

static int
SpoolssSetForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	char *name = NULL;
	guint32 level;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep,
		sizeof(guint16), hf_form_name, TRUE, &name);

	if (name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", name);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_form_level, &level);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_FORM_CTR(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int
SpoolssSetForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * GetForm
 */

static int
SpoolssGetForm_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	proto_item *hidden_item;
	guint32 level;
	char *name;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep,
		sizeof(guint16), hf_form_name, TRUE, &name);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", name);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_form_level, &level);

	/* GetForm() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
			dcv->se_data = GUINT_TO_POINTER((int)level);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d",
				level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssGetForm_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	BUFFER buffer;
	guint32 level = GPOINTER_TO_UINT(dcv->se_data);
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_form, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, &buffer);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	if (buffer.tvb) {
		int buffer_offset = 0;

		switch(level) {
		case 1: {
			int struct_start = buffer_offset;

			/*buffer_offset = */dissect_FORM_REL(
				buffer.tvb, buffer_offset, pinfo, tree, di, drep,
				struct_start);
			break;
		}

		default:
			proto_tree_add_expert_format(buffer.tree, pinfo, &ei_form_level, buffer.tvb, buffer_offset, -1, "Unknown form info level %d", level);
			break;
		}
	}

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}


/* A generic reply function that just parses the status code.  Useful for
   unimplemented dissectors so the status code can be inserted into the
   INFO column. */

static int
SpoolssGeneric_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	int len = tvb_reported_length(tvb);

	proto_tree_add_expert(tree, pinfo, &ei_unimplemented_dissector, tvb, offset, 0);

	offset = dissect_doserror(
		tvb, len - 4, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * JOB_INFO_1
 */

static gint ett_JOB_INFO_1 = -1;

static int
dissect_spoolss_JOB_INFO_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_item *item;
	proto_tree *subtree;
	int struct_start = offset;
	char *document_name;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_JOB_INFO_1, &item, "Job info level 1");

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_job_id, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_printername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_servername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_username,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_documentname,
		struct_start, &document_name);

	proto_item_append_text(item, ": %s", document_name);
	g_free(document_name);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_datatype,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_textstatus,
		struct_start, NULL);

	offset = dissect_job_status(tvb, offset, pinfo, subtree, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_job_priority, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_job_position, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_job_totalpages, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_job_pagesprinted, NULL);

	offset = dissect_SYSTEM_TIME(
		tvb, offset, pinfo, subtree, di, drep, "Job Submission Time",
		TRUE, NULL);

	proto_item_set_len(item, offset - struct_start);

	return offset;
}

/*
 * JOB_INFO_2
 */

static gint ett_JOB_INFO_2 = -1;

static int
dissect_spoolss_JOB_INFO_2(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_item *item;
	proto_tree *subtree;
	int struct_start = offset;
	char *document_name;
	guint32 devmode_offset, secdesc_offset;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_JOB_INFO_2, &item, "Job info level 2");

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_job_id, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_printername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_machinename,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_username,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_documentname,
		struct_start, &document_name);

	proto_item_append_text(item, ": %s", document_name);
	g_free(document_name);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_notifyname,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_datatype,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_printprocessor,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_parameters,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_drivername,
		struct_start, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_offset,
		&devmode_offset);

	dissect_DEVMODE(
		tvb, devmode_offset - 4 + struct_start, pinfo, subtree, di, drep);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_textstatus,
		struct_start, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_offset,
		&secdesc_offset);

	dissect_nt_sec_desc(
		tvb, secdesc_offset, pinfo, subtree, drep,
		FALSE, -1,
		&spoolss_job_access_mask_info);

	offset = dissect_job_status(tvb, offset, pinfo, subtree, di, drep);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_job_priority, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_job_position, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_start_time, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_end_time, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_job_totalpages, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_job_size, NULL);

	offset = dissect_SYSTEM_TIME(
		tvb, offset, pinfo, subtree, di, drep, "Job Submission Time",
		TRUE, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep, hf_elapsed_time, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_job_pagesprinted, NULL);

	proto_item_set_len(item, offset - struct_start);

	return offset;
}

/*
 * EnumJobs
 */

static int hf_enumjobs_firstjob = -1;
static int hf_enumjobs_numjobs = -1;

static int
SpoolssEnumJobs_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep,
		hf_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_enumjobs_firstjob, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_enumjobs_numjobs, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	/* EnumJobs() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
			dcv->se_data = GUINT_TO_POINTER((int)level);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssEnumJobs_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, dcerpc_info *di, guint8 *drep _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	gint16 level = GPOINTER_TO_UINT(dcv->se_data);
	BUFFER buffer;
	guint32 num_jobs, i;
	int buffer_offset;

	/* Parse packet */

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, &buffer);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_enumjobs_numjobs,
		&num_jobs);

	buffer_offset = 0;

	for (i = 0; i < num_jobs; i++) {
		switch(level) {
		case 1:
			buffer_offset = dissect_spoolss_JOB_INFO_1(
				buffer.tvb, buffer_offset, pinfo,
				buffer.tree, di, drep);
			break;
		case 2:
			buffer_offset = dissect_spoolss_JOB_INFO_2(
				buffer.tvb, buffer_offset, pinfo,
				buffer.tree, di, drep);
			break;
		default:
			proto_tree_add_expert_format( buffer.tree, pinfo, &ei_job_info_level, buffer.tvb, 0, -1, "Unknown job info level %d", level);
			break;
		}

	}

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * SetJob
 */

static const value_string setjob_commands[] = {
	{ JOB_CONTROL_PAUSE, "Pause" },
	{ JOB_CONTROL_RESUME, "Resume" },
	{ JOB_CONTROL_CANCEL, "Cancel" },
	{ JOB_CONTROL_RESTART, "Restart" },
	{ JOB_CONTROL_DELETE, "Delete" },
	{ 0, NULL }
};

static int hf_setjob_cmd = -1;

static int
SpoolssSetJob_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 jobid, cmd;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_job_id, &jobid);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_setjob_cmd, &cmd);

	col_append_fstr(
			pinfo->cinfo, COL_INFO, ", %s jobid %d",
			val_to_str(cmd, setjob_commands, "Unknown (%d)"),
			jobid);

	return offset;
}

static int
SpoolssSetJob_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * GetJob
 */

static int
SpoolssGetJob_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level, jobid;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_job_id, &jobid);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	/* GetJob() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
			dcv->se_data = GUINT_TO_POINTER((int)level);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d, jobid %d",
				level, jobid);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssGetJob_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	gint32 level = GPOINTER_TO_UINT(dcv->se_data);
	BUFFER buffer;

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, di, drep,
					&buffer);

	if (buffer.tvb) {
		int buffer_offset = 0;

		switch(level) {
		case 1:
			/*buffer_offset = */dissect_spoolss_JOB_INFO_1(
				buffer.tvb, buffer_offset, pinfo,
				buffer.tree, di, drep);
			break;
		case 2:
		default:
			proto_tree_add_expert_format( buffer.tree, pinfo, &ei_job_info_level, buffer.tvb, buffer_offset, -1, "Unknown job info level %d", level);
			break;
		}
	}

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * StartPagePrinter
 */

static int
SpoolssStartPagePrinter_q(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	char *pol_name;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, NULL,
		FALSE, FALSE);

	dcerpc_fetch_polhnd_data(&policy_hnd, &pol_name, NULL, NULL, NULL,
			     pinfo->num);

	if (pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	return offset;
}

static int
SpoolssStartPagePrinter_r(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * EndPagePrinter
 */

static int
SpoolssEndPagePrinter_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	char *pol_name;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, NULL,
		FALSE, FALSE);

	dcerpc_fetch_polhnd_data(&policy_hnd, &pol_name, NULL, NULL, NULL,
			     pinfo->num);

	if (pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	return offset;
}

static int
SpoolssEndPagePrinter_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * DOC_INFO_1
 */

static gint ett_DOC_INFO_1 = -1;

static int
dissect_spoolss_doc_info_1(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_DOC_INFO_1, NULL, "Document info level 1");

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, subtree, di, drep, NDR_POINTER_UNIQUE,
		"Document name", hf_documentname, 0);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, subtree, di, drep, NDR_POINTER_UNIQUE,
		"Output file", hf_outputfile, 0);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, subtree, di, drep, NDR_POINTER_UNIQUE,
		"Data type", hf_datatype, 0);

	return offset;
}

static int
dissect_spoolss_doc_info_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	if (di->conformant_run)
		return offset;

	return dissect_spoolss_doc_info_1(tvb, offset, pinfo, tree, di, drep);
}

/*
 * DOC_INFO
 */

static gint ett_DOC_INFO = -1;

static int
dissect_spoolss_doc_info(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	guint32 level;

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_DOC_INFO, NULL, "Document info");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_level, &level);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, subtree, di, drep,
		dissect_spoolss_doc_info_data,
		NDR_POINTER_UNIQUE, "Document info", -1);

	return offset;
}

/*
 * DOC_INFO_CTR
 */

static gint ett_DOC_INFO_CTR = -1;

static int
dissect_spoolss_doc_info_ctr(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_DOC_INFO_CTR, NULL, "Document info container");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_level, NULL);

	offset = dissect_spoolss_doc_info(
		tvb, offset, pinfo, subtree, di, drep);

	return offset;
}

/*
 * StartDocPrinter
 */

static int
SpoolssStartDocPrinter_q(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    dcerpc_info *di, guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	char *pol_name;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, NULL,
		FALSE, FALSE);

	dcerpc_fetch_polhnd_data(&policy_hnd, &pol_name, NULL, NULL, NULL,
			     pinfo->num);

	if (pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	offset = dissect_spoolss_doc_info_ctr(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int
SpoolssStartDocPrinter_r(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_job_id, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * EndDocPrinter
 */

static int
SpoolssEndDocPrinter_q(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	char *pol_name;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, NULL,
		FALSE, FALSE);

	dcerpc_fetch_polhnd_data(&policy_hnd, &pol_name, NULL, NULL, NULL,
			     pinfo->num);

	if (pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);


	return offset;
}

static int
SpoolssEndDocPrinter_r(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * WritePrinter
 */

static gint ett_writeprinter_buffer = -1;

static int hf_writeprinter_numwritten = -1;

static int
SpoolssWritePrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	char *pol_name;
	guint32 size;
	proto_item *item;
	proto_tree *subtree;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, NULL,
		FALSE, FALSE);

	dcerpc_fetch_polhnd_data(&policy_hnd, &pol_name, NULL, NULL, NULL,
			     pinfo->num);

	if (pol_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_buffer_size, &size);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %d bytes", size);

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_writeprinter_buffer, &item, "Buffer");

	offset = dissect_ndr_uint8s(tvb, offset, pinfo, subtree, di, drep,
				    hf_buffer_data, size, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_buffer_size, NULL);

	proto_item_set_len(item, size + 4);

	return offset;
}

static int
SpoolssWritePrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 size;

	/* Parse packet */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_writeprinter_numwritten,
		&size);

	col_append_fstr(
			pinfo->cinfo, COL_INFO, ", %d bytes written", size);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * DeletePrinterData
 */

static int
SpoolssDeletePrinterData_q(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	char *value_name;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_printerdata_value, TRUE, &value_name);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", value_name);

	return offset;
}

static int
SpoolssDeletePrinterData_r(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * DRIVER_INFO_1
 */

static gint ett_DRIVER_INFO_1 = -1;

static int
dissect_DRIVER_INFO_1(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	int struct_start = offset;

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_DRIVER_INFO_1, NULL, "Driver info level 1");

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_drivername,
		struct_start, NULL);

	return offset;
}

/*
 * DRIVER_INFO_2
 */

static const value_string driverinfo_cversion_vals[] =
{
	{ 0, "Windows 95/98/Me" },
	{ 2, "Windows NT 4.0" },
	{ 3, "Windows 2000/XP" },
	{ 0, NULL }
};

static gint ett_DRIVER_INFO_2 = -1;

static int
dissect_DRIVER_INFO_2(tvbuff_t *tvb, int offset,
	 packet_info *pinfo, proto_tree *tree,
	 dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	int struct_start = offset;

	subtree = proto_tree_add_subtree(
			tree, tvb, offset, 0, ett_DRIVER_INFO_2, NULL, "Driver info level 2");

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
			hf_driverinfo_cversion, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_drivername,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_environment,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_driverpath,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_datafile,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_configfile,
			struct_start, NULL);

	return offset;
}

/*
 * DRIVER_INFO_3
 */

static gint ett_DRIVER_INFO_3 = -1;

static int
dissect_DRIVER_INFO_3(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	int struct_start = offset;

	subtree = proto_tree_add_subtree(
		tree, tvb, offset, 0, ett_DRIVER_INFO_3, NULL, "Driver info level 3");

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
				    hf_driverinfo_cversion, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_drivername,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_environment,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_driverpath,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_datafile,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_configfile,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_helpfile,
		struct_start, NULL);

	offset = dissect_spoolss_relstrarray(
		tvb, offset, pinfo, subtree, di, drep, hf_dependentfiles,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_monitorname,
		struct_start, NULL);

	offset = dissect_spoolss_relstr(
		tvb, offset, pinfo, subtree, di, drep, hf_defaultdatatype,
		struct_start, NULL);

	return offset;
}


/*
	DRIVER_INFO_6
*/

static gint ett_DRIVER_INFO_6 = -1;

static int
dissect_DRIVER_INFO_6(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	int struct_start = offset;

	subtree = proto_tree_add_subtree(
			tree, tvb, offset, 0, ett_DRIVER_INFO_6, NULL, "Driver info level 6");

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
			hf_driverinfo_cversion, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_drivername,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_environment,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_driverpath,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_datafile,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_configfile,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_helpfile,
			struct_start, NULL);

	offset = dissect_spoolss_relstrarray(
			tvb, offset, pinfo, subtree, di, drep, hf_dependentfiles,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_monitorname,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_defaultdatatype,
			struct_start, NULL);

	offset = dissect_spoolss_relstrarray(
			tvb, offset, pinfo, subtree, di, drep, hf_previousdrivernames,
			struct_start, NULL);

	offset = dissect_ndr_nt_NTTIME (
			tvb, offset, pinfo, subtree, di, drep,hf_driverdate);

	offset = dissect_ndr_uint32(
			tvb, offset, pinfo, subtree, di, drep, hf_padding,
			NULL);

	offset = dissect_ndr_uint32(
			tvb, offset, pinfo, subtree, di, drep, hf_driver_version_low,
			NULL);

	offset = dissect_ndr_uint32(
			tvb, offset, pinfo, subtree, di, drep, hf_driver_version_high,
			NULL);


	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_mfgname,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_oemurl,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_hardwareid,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_provider,
			struct_start, NULL);

	return offset;
}


static gint ett_DRIVER_INFO_101 = -1;

static int
dissect_DRIVER_INFO_101(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, guint8 *drep)
{
	proto_tree *subtree;
	int struct_start = offset;

	subtree = proto_tree_add_subtree(
			tree, tvb, offset, 0, ett_DRIVER_INFO_101, NULL, "Driver info level 101");

	offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, di, drep,
			hf_driverinfo_cversion, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_drivername,
			struct_start, NULL);

	offset = dissect_spoolss_relstr(
			tvb, offset, pinfo, subtree, di, drep, hf_environment,
			struct_start, NULL);

	proto_tree_add_expert(subtree, pinfo, &ei_unknown_data, tvb, offset, 0);

	return offset;
}
/*
 * EnumPrinterDrivers
 */

static int
SpoolssEnumPrinterDrivers_q(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level;

	/* Parse packet */

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep, NDR_POINTER_UNIQUE,
		"Name", hf_servername, 0);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep, NDR_POINTER_UNIQUE,
		"Environment", hf_environment, 0);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	/* EnumPrinterDrivers() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
			dcv->se_data = GUINT_TO_POINTER((int)level);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssEnumPrinterDrivers_r(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level = GPOINTER_TO_UINT(dcv->se_data), num_drivers, i;
	int buffer_offset;
	BUFFER buffer;

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, di, drep,
					&buffer);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_returned,
		&num_drivers);

	buffer_offset = 0;

	for (i = 0; i < num_drivers; i++) {
		switch(level) {
		case 1:
			buffer_offset = dissect_DRIVER_INFO_1(
				buffer.tvb, buffer_offset, pinfo,
				buffer.tree, di, drep);
			break;
		case 2:
			buffer_offset = dissect_DRIVER_INFO_2(
				buffer.tvb, buffer_offset, pinfo,
				buffer.tree, di, drep);
			break;
		case 3:
			buffer_offset = dissect_DRIVER_INFO_3(
				buffer.tvb, buffer_offset, pinfo,
				buffer.tree, di, drep);
			break;
		case 6:
			buffer_offset = dissect_DRIVER_INFO_6(
				buffer.tvb, buffer_offset, pinfo,
				buffer.tree, di, drep);
			break;
		case 101:
			/*buffer_offset =*/ dissect_DRIVER_INFO_101(
				buffer.tvb, buffer_offset, pinfo,
				buffer.tree, di, drep);
			/*break;*/
			goto done; /*Not entirely imeplemented*/
		default:
			proto_tree_add_expert_format( buffer.tree, pinfo, &ei_driver_info_level, buffer.tvb, buffer_offset, -1, "Unknown driver info level %d", level);
			goto done;
		}
	}

done:
	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * GetPrinterDriver2
 */

static int
SpoolssGetPrinterDriver2_q(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	char *pol_name;
	guint32 level;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, &policy_hnd, NULL,
		FALSE, FALSE);

	dcerpc_fetch_polhnd_data(&policy_hnd, &pol_name, NULL, NULL, NULL,
			     pinfo->num);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				pol_name);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep, NDR_POINTER_UNIQUE,
		"Environment", hf_environment, 0);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	/* GetPrinterDriver2() stores the level in se_data */
	if(!pinfo->fd->flags.visited){
			dcv->se_data = GUINT_TO_POINTER((int)level);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_clientmajorversion, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_clientminorversion, NULL);

	return offset;
}

static int
SpoolssGetPrinterDriver2_r(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 level = GPOINTER_TO_UINT(dcv->se_data);
	BUFFER buffer;

	/* Parse packet */

	offset = dissect_spoolss_buffer(tvb, offset, pinfo, tree, di, drep,
					&buffer);

	if (buffer.tvb) {
		switch(level) {
		case 1:
			dissect_DRIVER_INFO_1(
				buffer.tvb, 0, pinfo, buffer.tree, di, drep);
			break;
		case 2:
			dissect_DRIVER_INFO_2(
				buffer.tvb, 0, pinfo, buffer.tree, di, drep);
			break;
		case 3:
			dissect_DRIVER_INFO_3(
				buffer.tvb, 0, pinfo, buffer.tree, di, drep);
			break;
		case 6:
			dissect_DRIVER_INFO_6(
				buffer.tvb, 0, pinfo, buffer.tree, di, drep);
			break;
		case 101:
			dissect_DRIVER_INFO_101(
				buffer.tvb, 0, pinfo, buffer.tree, di, drep);
			break;
		default:
			proto_tree_add_expert_format( buffer.tree, pinfo, &ei_driver_info_level, buffer.tvb, 0, -1, "Unknown driver info level %d", level);
			break;
		}
	}

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_servermajorversion, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_serverminorversion, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

static int
dissect_notify_info_data_buffer(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 len;

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_notify_info_data_buffer_len, &len);

	offset = dissect_ndr_uint16s(
		tvb, offset, pinfo, tree, di, drep,
		hf_notify_info_data_buffer_data, len);

	return offset;
}

static void
cb_notify_str_postprocess(packet_info *pinfo _U_,
				      proto_tree *tree _U_,
				      proto_item *item, dcerpc_info *di _U_, tvbuff_t *tvb,
				      int start_offset, int end_offset,
				      void *callback_args)
{
	gint levels, hf_index = GPOINTER_TO_INT(callback_args);
	guint32 len;
	char *s;
	proto_item *hidden_item;

	/* Align start_offset on 4-byte boundary. */

	if (start_offset % 4)
		start_offset += 4 - (start_offset % 4);

	/* Get string length */

	len = tvb_get_letohl(tvb, start_offset);

	s = tvb_get_string_enc(NULL,
		tvb, start_offset + 4, (end_offset - start_offset - 4), ENC_UTF_16|ENC_LITTLE_ENDIAN);

	/* Append string to upper-level proto_items */

	levels = 2;

	if (levels > 0 && item && s && s[0]) {
		proto_item_append_text(item, ": %s", s);
		item = item->parent;
		levels--;
		if (levels > 0) {
			proto_item_append_text(item, ": %s", s);
			item = item->parent;
			levels--;
			while (levels > 0) {
				proto_item_append_text(item, " %s", s);
				item = item->parent;
				levels--;
			}
		}
	}

	/* Add hidden field so filter brings up any notify data */

	if (hf_index != -1) {
		hidden_item = proto_tree_add_string(
			tree, hf_index, tvb, start_offset, len, s);
		PROTO_ITEM_SET_HIDDEN(hidden_item);
	}

	g_free(s);
}

/* Return the hf_index for a printer notify field.  This is used to
   add a hidden string to the display so that filtering will bring
   up relevant notify data. */

static int
printer_notify_hf_index(int field)
{
	int result = -1;

	switch(field) {
	case PRINTER_NOTIFY_SERVER_NAME:
		result = hf_servername;
		break;
	case PRINTER_NOTIFY_PRINTER_NAME:
		result = hf_printername;
		break;
	case PRINTER_NOTIFY_SHARE_NAME:
		result = hf_sharename;
		break;
	case PRINTER_NOTIFY_PORT_NAME:
		result = hf_portname;
		break;
	case PRINTER_NOTIFY_DRIVER_NAME:
		result = hf_drivername;
		break;
	case PRINTER_NOTIFY_COMMENT:
		result = hf_printercomment;
		break;
	case PRINTER_NOTIFY_LOCATION:
		result = hf_printerlocation;
		break;
	case PRINTER_NOTIFY_SEPFILE:
		result = hf_sepfile;
		break;
	case PRINTER_NOTIFY_PRINT_PROCESSOR:
		result = hf_printprocessor;
		break;
	case PRINTER_NOTIFY_PARAMETERS:
		result = hf_parameters;
		break;
	case PRINTER_NOTIFY_DATATYPE:
		result = hf_parameters;
		break;
	}

	return result;
}

static int
job_notify_hf_index(int field)
{
	int result = -1;

	switch(field) {
	case JOB_NOTIFY_PRINTER_NAME:
		result = hf_printername;
		break;
	case JOB_NOTIFY_MACHINE_NAME:
		result = hf_machinename;
		break;
	case JOB_NOTIFY_PORT_NAME:
		result = hf_portname;
		break;
	case JOB_NOTIFY_USER_NAME:
		result = hf_username;
		break;
	case JOB_NOTIFY_NOTIFY_NAME:
		result = hf_notifyname;
		break;
	case JOB_NOTIFY_DATATYPE:
		result = hf_datatype;
		break;
	case JOB_NOTIFY_PRINT_PROCESSOR:
		result = hf_printprocessor;
		break;
	case JOB_NOTIFY_DRIVER_NAME:
		result = hf_drivername;
		break;
	case JOB_NOTIFY_DOCUMENT:
		result = hf_documentname;
		break;
	case JOB_NOTIFY_PRIORITY:
		result = hf_job_priority;
		break;
	case JOB_NOTIFY_POSITION:
		result = hf_job_position;
		break;
	case JOB_NOTIFY_TOTAL_PAGES:
		result = hf_job_totalpages;
		break;
	case JOB_NOTIFY_PAGES_PRINTED:
		result = hf_job_pagesprinted;
		break;
	case JOB_NOTIFY_TOTAL_BYTES:
		result = hf_job_totalbytes;
		break;
	case JOB_NOTIFY_BYTES_PRINTED:
		result = hf_job_bytesprinted;
		break;
	}

	return result;
}

static int
dissect_NOTIFY_INFO_DATA_printer(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, proto_item *item,
				 dcerpc_info *di, guint8 *drep, guint16 field)
{
	guint32 value1;

	switch (field) {

		/* String notify data */

	case PRINTER_NOTIFY_SERVER_NAME:
	case PRINTER_NOTIFY_PRINTER_NAME:
	case PRINTER_NOTIFY_SHARE_NAME:
	case PRINTER_NOTIFY_DRIVER_NAME:
	case PRINTER_NOTIFY_COMMENT:
	case PRINTER_NOTIFY_LOCATION:
	case PRINTER_NOTIFY_SEPFILE:
	case PRINTER_NOTIFY_PRINT_PROCESSOR:
	case PRINTER_NOTIFY_PARAMETERS:
	case PRINTER_NOTIFY_DATATYPE:
	case PRINTER_NOTIFY_PORT_NAME:

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_bufsize, &value1);

		offset = dissect_ndr_pointer_cb(
			tvb, offset, pinfo, tree, di, drep,
			dissect_notify_info_data_buffer,
			NDR_POINTER_UNIQUE, "String",
			hf_notify_info_data_buffer,
			cb_notify_str_postprocess,
			GINT_TO_POINTER(printer_notify_hf_index(field)));

		break;

	case PRINTER_NOTIFY_ATTRIBUTES:

		/* Value 1 is the printer attributes */

		offset = dissect_printer_attributes(
			tvb, offset, pinfo, tree, di, drep);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, NULL, di, drep,
			hf_notify_info_data_value2, NULL);

		break;

	case PRINTER_NOTIFY_STATUS: {
		guint32 status;

		/* Value 1 is the printer status */

 		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_printer_status, &status);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, NULL, di, drep,
			hf_notify_info_data_value2, NULL);

		proto_item_append_text(
			item, ": %s",
			val_to_str_ext_const(status, &printer_status_vals_ext, "Unknown"));

		break;
	}

		/* Unknown notify data */

	case PRINTER_NOTIFY_SECURITY_DESCRIPTOR: /* Secdesc */
	case PRINTER_NOTIFY_DEVMODE: /* Devicemode */

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_bufsize, &value1);

		offset = dissect_ndr_pointer(
			tvb, offset, pinfo, tree, di, drep,
			dissect_notify_info_data_buffer,
			NDR_POINTER_UNIQUE, "Buffer",
			hf_notify_info_data_buffer);

		break;

	default:
		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_value1, NULL);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_value2, NULL);

		break;
	}
	return offset;
}

static void
notify_job_time_cb(packet_info *pinfo _U_, proto_tree *tree _U_,
			       proto_item *item, dcerpc_info *di, tvbuff_t *tvb _U_,
			       int start_offset _U_, int end_offset _U_,
			       void *callback_args _U_)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *str = (char *)dcv->private_data;

	/* Append job string stored in dcv->private_data by
	   dissect_SYSTEM_TIME_ptr() in the current item as well
	   as the parent. */

	proto_item_append_text(item, ": %s", str);

	if (item)
		proto_item_append_text(item->parent, ": %s", str);
}

static int
dissect_NOTIFY_INFO_DATA_job(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, proto_item *item, dcerpc_info *di, guint8 *drep,
			     guint16 field)
{
	guint32 value1;
	proto_item *hidden_item;

	switch (field) {

		/* String notify data */

	case JOB_NOTIFY_PRINTER_NAME:
	case JOB_NOTIFY_MACHINE_NAME:
	case JOB_NOTIFY_PORT_NAME:
	case JOB_NOTIFY_USER_NAME:
	case JOB_NOTIFY_NOTIFY_NAME:
	case JOB_NOTIFY_DATATYPE:
	case JOB_NOTIFY_PRINT_PROCESSOR:
	case JOB_NOTIFY_PARAMETERS:
	case JOB_NOTIFY_DRIVER_NAME:
	case JOB_NOTIFY_STATUS_STRING:
	case JOB_NOTIFY_DOCUMENT:

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_bufsize, &value1);

		offset = dissect_ndr_pointer_cb(
			tvb, offset, pinfo, tree, di, drep,
			dissect_notify_info_data_buffer,
			NDR_POINTER_UNIQUE, "String",
			hf_notify_info_data_buffer,
			cb_notify_str_postprocess,
			GINT_TO_POINTER(job_notify_hf_index(field)));

		break;

	case JOB_NOTIFY_STATUS:
		offset = dissect_job_status(
			tvb, offset, pinfo, tree, di, drep);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, NULL, di, drep,
			hf_notify_info_data_value2, NULL);

		break;

	case JOB_NOTIFY_SUBMITTED:

		/* SYSTEM_TIME */

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_buffer_len, NULL);

		offset = dissect_ndr_pointer_cb(
			tvb, offset, pinfo, tree, di, drep,
			dissect_SYSTEM_TIME_ptr, NDR_POINTER_UNIQUE,
			"Time submitted", -1, notify_job_time_cb, NULL);

		break;

	case JOB_NOTIFY_PRIORITY:
	case JOB_NOTIFY_POSITION:
	case JOB_NOTIFY_TOTAL_PAGES:
	case JOB_NOTIFY_PAGES_PRINTED:
	case JOB_NOTIFY_TOTAL_BYTES:
	case JOB_NOTIFY_BYTES_PRINTED: {
		guint32 value;

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_value1, &value);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_value2, NULL);

		proto_item_append_text(item, ": %d", value);

		hidden_item = proto_tree_add_uint(
			tree, job_notify_hf_index(field), tvb,
			offset, 4, value);
		PROTO_ITEM_SET_HIDDEN(hidden_item);

		break;
	}

		/* Unknown notify data */

	case JOB_NOTIFY_DEVMODE:

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_bufsize, &value1);

		offset = dissect_ndr_pointer(
			tvb, offset, pinfo, tree, di, drep,
			dissect_notify_info_data_buffer,
			NDR_POINTER_UNIQUE, "Buffer",
			hf_notify_info_data_buffer);

		break;

	default:
		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_value1, NULL);

		offset = dissect_ndr_uint32(
			tvb, offset, pinfo, tree, di, drep,
			hf_notify_info_data_value2, NULL);
	}
	return offset;
}

static gint ett_NOTIFY_INFO_DATA = -1;

static int
dissect_NOTIFY_INFO_DATA(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	proto_item *item;
	proto_tree *subtree;
	guint32 count;
	guint16 type, field;
	const char *field_string;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_NOTIFY_INFO_DATA, &item, "");

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, subtree, di, drep,
		hf_notify_info_data_type, &type);

	offset = dissect_notify_field(
		tvb, offset, pinfo, subtree, di, drep, type, &field);

	switch(type) {
	case PRINTER_NOTIFY_TYPE:
		field_string = val_to_str_ext(
			field, &printer_notify_option_data_vals_ext,
			"Unknown (%d)");
		break;
	case JOB_NOTIFY_TYPE:
		field_string = val_to_str_ext(
			field, &job_notify_option_data_vals_ext,
			"Unknown (%d)");
		break;
	default:
		field_string = "Unknown field";
		break;
	}

	proto_item_append_text(
		item, "%s, %s",
		val_to_str(type, printer_notify_types, "Unknown (%d)"),
		field_string);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_notify_info_data_count, &count);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_notify_info_data_id, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_notify_info_data_count, NULL);

	/* The value here depends on (type, field) */

	switch (type) {
	case PRINTER_NOTIFY_TYPE:
		offset = dissect_NOTIFY_INFO_DATA_printer(
			tvb, offset, pinfo, subtree, item, di, drep, field);
		break;
	case JOB_NOTIFY_TYPE:
		offset = dissect_NOTIFY_INFO_DATA_job(
			tvb, offset, pinfo, subtree, item, di, drep, field);
		break;
	default:
		expert_add_info(pinfo, item, &ei_notify_info_data_type);
		break;
	}

	return offset;
}

static int
dissect_NOTIFY_INFO(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 count;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_notify_info_version, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_notify_info_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_notify_info_count, &count);

	if (!di->conformant_run)
		col_append_fstr(
			pinfo->cinfo, COL_INFO, ", %d %s", count,
			notify_plural(count));

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep,
				     dissect_NOTIFY_INFO_DATA);

	return offset;
}

/*
 * RFNPCNEX
 */

static int
SpoolssRFNPCNEX_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 changeid;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_rrpcn_changelow, &changeid);

	col_append_fstr(
			pinfo->cinfo, COL_INFO, ", changeid %d", changeid);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_NOTIFY_OPTIONS_ARRAY_CTR, NDR_POINTER_UNIQUE,
		"Notify Options Array Container", -1);

	return offset;
}

static int
SpoolssRFNPCNEX_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_NOTIFY_INFO, NDR_POINTER_UNIQUE,
		"Notify Info", -1);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * RRPCN
 */

static int
SpoolssRRPCN_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 changeid;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_rrpcn_changelow, &changeid);

	col_append_fstr(
			pinfo->cinfo, COL_INFO, ", changeid %d", changeid);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_rrpcn_changehigh, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_rrpcn_unk0, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_rrpcn_unk1, NULL);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, di, drep,
		dissect_NOTIFY_INFO, NDR_POINTER_UNIQUE,
		"Notify Info", -1);

	/* Notify info */

	return offset;
}

static int
SpoolssRRPCN_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_rrpcn_unk0, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * ReplyClosePrinter
 */

static int
SpoolssReplyClosePrinter_q(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, TRUE);

	return offset;
}

static int
SpoolssReplyClosePrinter_r(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * FCPN
 */

static int
SpoolssFCPN_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	return offset;
}

static int
SpoolssFCPN_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * RouterReplyPrinter
 */

static int hf_routerreplyprinter_condition = -1;
static int hf_routerreplyprinter_unknown1 = -1;
static int hf_routerreplyprinter_changeid = -1;

static int
SpoolssRouterReplyPrinter_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
				       proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_routerreplyprinter_condition, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_routerreplyprinter_unknown1, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_routerreplyprinter_changeid, NULL);

	return offset;
}

static int
SpoolssRouterReplyPrinter_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
				       proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

static int hf_keybuffer_size = -1;

static int
dissect_spoolss_keybuffer(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
	guint32 size;
	int end_offset;

	if (di->conformant_run)
		return offset;

	/* Dissect size and data */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hf_keybuffer_size, &size);

	end_offset = offset + (size*2);
	if (end_offset < offset) {
		/*
		 * Overflow - make the end offset one past the end of
		 * the packet data, so we throw an exception (as the
		 * size is almost certainly too big).
		 */
		end_offset = tvb_reported_length_remaining(tvb, offset) + 1;
	}

	while (offset < end_offset)
		offset = dissect_spoolss_uint16uni(
			tvb, offset, pinfo, tree, drep, NULL, hf_keybuffer);

	return offset;
}


static int
SpoolssEnumPrinterKey_q(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep)
{
	char *key_name;

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_printerdata_key, TRUE, &key_name);

	if (!key_name[0])
		key_name = "\"\"";

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", key_name);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	return offset;
}

static int
SpoolssEnumPrinterKey_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_spoolss_keybuffer(tvb, offset, pinfo, tree, di, drep);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

static int hf_enumprinterdataex_name_offset = -1;
static int hf_enumprinterdataex_name_len = -1;
static int hf_enumprinterdataex_name = -1;
static int hf_enumprinterdataex_val_offset = -1;
static int hf_enumprinterdataex_val_len = -1;
static int hf_enumprinterdataex_val_dword_low = -1;
static int hf_enumprinterdataex_val_dword_high = -1;
static int hf_enumprinterdataex_value_null = -1;
static int hf_enumprinterdataex_value_uint = -1;
static int hf_enumprinterdataex_value_binary = -1;
static int hf_enumprinterdataex_value_multi_sz = -1;

static int
SpoolssEnumPrinterDataEx_q(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	char *key_name;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, di, drep, hf_hnd, NULL, NULL,
		FALSE, FALSE);

	offset = dissect_ndr_cvstring(
		tvb, offset, pinfo, tree, di, drep, sizeof(guint16),
		hf_printerdata_key, TRUE, &key_name);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", key_name);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static gint ett_printer_enumdataex_value = -1;

static int
dissect_spoolss_printer_enum_values(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    dcerpc_info *di, guint8 *drep)
{
	guint32 start_offset = offset;
	guint32 name_offset, name_len, val_offset, val_len, val_type;
	char *name;
	proto_item *item;
	proto_tree *subtree;

	/* Get offset of value name */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep,
		hf_enumprinterdataex_name_offset, &name_offset);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, NULL, di, drep,
		hf_enumprinterdataex_name_len, &name_len);

	dissect_spoolss_uint16uni(
		tvb, start_offset + name_offset, pinfo, NULL, drep,
		&name, hf_enumprinterdataex_name);

	subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_printer_enumdataex_value, &item, "Name: %s", name);

	proto_tree_add_uint(subtree, hf_enumprinterdataex_name_offset, tvb, offset - 8, 4, name_offset);

	proto_tree_add_uint(subtree, hf_enumprinterdataex_name_len, tvb, offset - 4, 4, name_len);

	proto_tree_add_string( subtree, hf_enumprinterdataex_name, tvb, start_offset + name_offset, ((int)strlen(name) + 1) * 2, name);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep, hf_printerdata_type,
		&val_type);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_enumprinterdataex_val_offset, &val_offset);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, subtree, di, drep,
		hf_enumprinterdataex_val_len, &val_len);

	if (val_len == 0) {
		proto_tree_add_uint_format_value(subtree, hf_enumprinterdataex_value_null, tvb, start_offset + val_offset, 4, 0, "(null)");
		goto done;
	}

	switch(val_type) {
	case DCERPC_REG_DWORD: {
		guint32 value;
		guint16 low, high;
		int offset2 = start_offset + val_offset;

		/* Needs to be broken into two 16-byte ints because it may
		   not be aligned. */

		offset2 = dissect_ndr_uint16(
			tvb, offset2, pinfo, subtree, di, drep,
			hf_enumprinterdataex_val_dword_low, &low);

		/*offset2 = */dissect_ndr_uint16(
			tvb, offset2, pinfo, subtree, di, drep,
			hf_enumprinterdataex_val_dword_high, &high);

		value = (high << 16) | low;

		proto_tree_add_uint(subtree, hf_enumprinterdataex_value_uint, tvb, start_offset + val_offset, 4, value);

		proto_item_append_text(item, ", Value: %d", value);

		break;
	}
	case DCERPC_REG_SZ: {
		char *value;

		dissect_spoolss_uint16uni(
			tvb, start_offset + val_offset, pinfo, subtree, drep,
			&value, hf_value_string);

		proto_item_append_text(item, ", Value: %s", value);

		g_free(value);

		break;
	}
	case DCERPC_REG_BINARY:

		/* FIXME: nicer way to display this */

		proto_tree_add_bytes_format_value( subtree, hf_enumprinterdataex_value_binary, tvb, start_offset + val_offset, val_len, NULL, "<binary data>");
		break;

	case DCERPC_REG_MULTI_SZ:

		/* FIXME: implement REG_MULTI_SZ support */

		proto_tree_add_bytes_format_value(subtree, hf_enumprinterdataex_value_multi_sz, tvb, start_offset + val_offset, val_len, NULL, "<REG_MULTI_SZ not implemented>");
		break;

	default:
		proto_tree_add_expert_format( subtree, pinfo, &ei_enumprinterdataex_value, tvb, start_offset + val_offset, val_len, "%s: unknown type %d", name, val_type);
	}

 done:
	g_free(name);

	return offset;
}

static gint ett_PRINTER_DATA_CTR = -1;

static int
SpoolssEnumPrinterDataEx_r(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   dcerpc_info *di, guint8 *drep)
{
	guint32 size, num_values;
	proto_item *hidden_item;

	hidden_item = proto_tree_add_uint(
		tree, hf_printerdata, tvb, offset, 0, 1);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* Parse packet */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep,
		hf_buffer_size, &size);

	dissect_ndr_uint32(
		tvb, offset + size + 4, pinfo, NULL, di, drep, hf_returned,
		&num_values);

	if (size) {
		proto_tree *subtree;
		int offset2 = offset;
		guint32 i;

		subtree = proto_tree_add_subtree(
			tree, tvb, offset, 0, ett_PRINTER_DATA_CTR, NULL, "Printer data");

		for (i=0; i < num_values; i++)
			offset2 = dissect_spoolss_printer_enum_values(
				tvb, offset2, pinfo, subtree, di, drep);
	}

	offset += size;

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_returned, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

static int
SpoolssGetPrinterDriverDirectory_q(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	guint32 level;

	/* Parse packet */

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep, NDR_POINTER_UNIQUE,
		"Name", hf_servername, 0);

	offset = dissect_ndr_str_pointer_item(
		tvb, offset, pinfo, tree, di, drep, NDR_POINTER_UNIQUE,
		"Environment", hf_environment, 0);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_level, &level);

	offset = dissect_spoolss_buffer(
		tvb, offset, pinfo, tree, di, drep, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_offered, NULL);

	return offset;
}

static int
SpoolssGetPrinterDriverDirectory_r(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      dcerpc_info *di, guint8 *drep)
{
	/* Parse packet */

	offset = dissect_spoolss_string_parm(
		tvb, offset, pinfo, tree, di, drep, "Directory");

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, di, drep, hf_needed, NULL);

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/*
 * List of subdissectors for this pipe.
 */

static dcerpc_sub_dissector dcerpc_spoolss_dissectors[] = {
	{ SPOOLSS_ENUMPRINTERS, "EnumPrinters",
	  SpoolssEnumPrinters_q, SpoolssEnumPrinters_r },
	{ SPOOLSS_OPENPRINTER, "OpenPrinter",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_SETJOB, "SetJob",
	  SpoolssSetJob_q, SpoolssSetJob_r },
	{ SPOOLSS_GETJOB, "GetJob",
	  SpoolssGetJob_q, SpoolssGetJob_r },
	{ SPOOLSS_ENUMJOBS, "EnumJobs",
	  SpoolssEnumJobs_q, SpoolssEnumJobs_r },
	{ SPOOLSS_ADDPRINTER, "AddPrinter",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTER, "DeletePrinter",
	  SpoolssDeletePrinter_q, SpoolssDeletePrinter_r },
	{ SPOOLSS_SETPRINTER, "SetPrinter",
	  SpoolssSetPrinter_q, SpoolssSetPrinter_r },
	{ SPOOLSS_GETPRINTER, "GetPrinter",
	  SpoolssGetPrinter_q, SpoolssGetPrinter_r },
	{ SPOOLSS_ADDPRINTERDRIVER, "AddPrinterDriver",
	  NULL, SpoolssAddPrinterDriver_r },
	{ SPOOLSS_ENUMPRINTERDRIVERS, "EnumPrinterDrivers",
	  SpoolssEnumPrinterDrivers_q, SpoolssEnumPrinterDrivers_r },
	{ SPOOLSS_GETPRINTERDRIVER, "GetPrinterDriver",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_GETPRINTERDRIVERDIRECTORY, "GetPrinterDriverDirectory",
	  SpoolssGetPrinterDriverDirectory_q, SpoolssGetPrinterDriverDirectory_r },
	{ SPOOLSS_DELETEPRINTERDRIVER, "DeletePrinterDriver",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTPROCESSOR, "AddPrintProcessor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ENUMPRINTPROCESSORS, "EnumPrintProcessor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_GETPRINTPROCESSORDIRECTORY, "GetPrintProcessorDirectory",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_STARTDOCPRINTER, "StartDocPrinter",
	  SpoolssStartDocPrinter_q, SpoolssStartDocPrinter_r },
	{ SPOOLSS_STARTPAGEPRINTER, "StartPagePrinter",
	  SpoolssStartPagePrinter_q, SpoolssStartPagePrinter_r },
	{ SPOOLSS_WRITEPRINTER, "WritePrinter",
	  SpoolssWritePrinter_q, SpoolssWritePrinter_r },
	{ SPOOLSS_ENDPAGEPRINTER, "EndPagePrinter",
	  SpoolssEndPagePrinter_q, SpoolssEndPagePrinter_r },
	{ SPOOLSS_ABORTPRINTER, "AbortPrinter",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_READPRINTER, "ReadPrinter",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ENDDOCPRINTER, "EndDocPrinter",
	  SpoolssEndDocPrinter_q, SpoolssEndDocPrinter_r },
	{ SPOOLSS_ADDJOB, "AddJob",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_SCHEDULEJOB, "ScheduleJob",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_GETPRINTERDATA, "GetPrinterData",
	  SpoolssGetPrinterData_q, SpoolssGetPrinterData_r },
	{ SPOOLSS_SETPRINTERDATA, "SetPrinterData",
	  SpoolssSetPrinterData_q, SpoolssSetPrinterData_r },
	{ SPOOLSS_WAITFORPRINTERCHANGE, "WaitForPrinterChange",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_CLOSEPRINTER, "ClosePrinter",
	  SpoolssClosePrinter_q, SpoolssClosePrinter_r },
	{ SPOOLSS_ADDFORM, "AddForm",
	  SpoolssAddForm_q, SpoolssAddForm_r },
	{ SPOOLSS_DELETEFORM, "DeleteForm",
	  SpoolssDeleteForm_q, SpoolssDeleteForm_r },
	{ SPOOLSS_GETFORM, "GetForm",
	  SpoolssGetForm_q, SpoolssGetForm_r },
	{ SPOOLSS_SETFORM, "SetForm",
	  SpoolssSetForm_q, SpoolssSetForm_r },
	{ SPOOLSS_ENUMFORMS, "EnumForms",
	  SpoolssEnumForms_q, SpoolssEnumForms_r },
	{ SPOOLSS_ENUMPORTS, "EnumPorts",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ENUMMONITORS, "EnumMonitors",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPORT, "AddPort",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_CONFIGUREPORT, "ConfigurePort",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPORT, "DeletePort",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_CREATEPRINTERIC, "CreatePrinterIC",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_PLAYGDISCRIPTONPRINTERIC, "PlayDiscriptOnPrinterIC",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERIC, "DeletePrinterIC",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTERCONNECTION, "AddPrinterConnection",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERCONNECTION, "DeletePrinterConnection",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_PRINTERMESSAGEBOX, "PrinterMessageBox",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDMONITOR, "AddMonitor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEMONITOR, "DeleteMonitor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTPROCESSOR, "DeletePrintProcessor",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTPROVIDER, "AddPrintProvider",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTPROVIDER, "DeletePrintProvider",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ENUMPRINTPROCDATATYPES, "EnumPrintProcDataTypes",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_RESETPRINTER, "ResetPrinter",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_GETPRINTERDRIVER2, "GetPrinterDriver2",
	  SpoolssGetPrinterDriver2_q, SpoolssGetPrinterDriver2_r },
	{ SPOOLSS_FINDFIRSTPRINTERCHANGENOTIFICATION,
	  "FindFirstPrinterChangeNotification",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_FINDNEXTPRINTERCHANGENOTIFICATION,
	  "FindNextPrinterChangeNotification",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_FCPN, "FCPN",
	  SpoolssFCPN_q, SpoolssFCPN_r },
	{ SPOOLSS_ROUTERFINDFIRSTPRINTERNOTIFICATIONOLD,
	  "RouterFindFirstPrinterNotificationOld",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_REPLYOPENPRINTER, "ReplyOpenPrinter",
	  SpoolssReplyOpenPrinter_q, SpoolssReplyOpenPrinter_r },
	{ SPOOLSS_ROUTERREPLYPRINTER, "RouterReplyPrinter",
	  SpoolssRouterReplyPrinter_q, SpoolssRouterReplyPrinter_r },
	{ SPOOLSS_REPLYCLOSEPRINTER, "ReplyClosePrinter",
	  SpoolssReplyClosePrinter_q, SpoolssReplyClosePrinter_r },
	{ SPOOLSS_ADDPORTEX, "AddPortEx",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_REMOTEFINDFIRSTPRINTERCHANGENOTIFICATION,
	  "RemoteFindFirstPrinterChangeNotification",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_SPOOLERINIT, "SpoolerInit",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_RESETPRINTEREX, "ResetPrinterEx",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_RFFPCNEX, "RFFPCNEX",
	  SpoolssRFFPCNEX_q, SpoolssRFFPCNEX_r },
	{ SPOOLSS_RRPCN, "RRPCN",
	  SpoolssRRPCN_q, SpoolssRRPCN_r },
	{ SPOOLSS_RFNPCNEX, "RFNPCNEX",
	  SpoolssRFNPCNEX_q, SpoolssRFNPCNEX_r },
	{ SPOOLSS_OPENPRINTEREX, "OpenPrinterEx",
	  SpoolssOpenPrinterEx_q, SpoolssOpenPrinterEx_r },
	{ SPOOLSS_ADDPRINTEREX, "AddPrinterEx",
	  NULL, SpoolssAddPrinterEx_r },
	{ SPOOLSS_ENUMPRINTERDATA, "EnumPrinterData",
	  SpoolssEnumPrinterData_q, SpoolssEnumPrinterData_r },
	{ SPOOLSS_DELETEPRINTERDATA, "DeletePrinterData",
	  SpoolssDeletePrinterData_q, SpoolssDeletePrinterData_r },
	{ SPOOLSS_GETPRINTERDATAEX, "GetPrinterDataEx",
	  SpoolssGetPrinterDataEx_q, SpoolssGetPrinterDataEx_r },
	{ SPOOLSS_SETPRINTERDATAEX, "SetPrinterDataEx",
	  SpoolssSetPrinterDataEx_q, SpoolssSetPrinterDataEx_r },
	{ SPOOLSS_ENUMPRINTERDATAEX, "EnumPrinterDataEx",
	  SpoolssEnumPrinterDataEx_q, SpoolssEnumPrinterDataEx_r },
	{ SPOOLSS_ENUMPRINTERKEY, "EnumPrinterKey",
	  SpoolssEnumPrinterKey_q, SpoolssEnumPrinterKey_r },
	{ SPOOLSS_DELETEPRINTERDATAEX, "DeletePrinterDataEx",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_DELETEPRINTERDRIVEREX, "DeletePrinterDriverEx",
	  NULL, SpoolssGeneric_r },
	{ SPOOLSS_ADDPRINTERDRIVEREX, "AddPrinterDriverEx",
	  NULL, SpoolssGeneric_r },

	{ 0, NULL, NULL, NULL },
};

/*
 * Dissector initialisation function
 */

/* Protocol registration */

static int proto_dcerpc_spoolss = -1;
static gint ett_dcerpc_spoolss = -1;

void
proto_register_dcerpc_spoolss(void)
{
	static hf_register_info hf[] = {

		/* GetPrinterDriver2 */

		{ &hf_clientmajorversion,
		  { "Client major version", "spoolss.clientmajorversion", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Client printer driver major version", HFILL }},
		{ &hf_clientminorversion,
		  { "Client minor version", "spoolss.clientminorversion", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Client printer driver minor version", HFILL }},
		{ &hf_servermajorversion,
		  { "Server major version", "spoolss.servermajorversion", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Server printer driver major version", HFILL }},
		{ &hf_serverminorversion,
		  { "Server minor version", "spoolss.serverminorversion", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Server printer driver minor version", HFILL }},
		{ &hf_driverpath,
		  { "Driver path", "spoolss.driverpath", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_datafile,
		  { "Data file", "spoolss.datafile", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_configfile,
		  { "Config file", "spoolss.configfile", FT_STRING, BASE_NONE,
		    NULL, 0, "Printer name", HFILL }},
		{ &hf_helpfile,
		  { "Help file", "spoolss.helpfile", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_monitorname,
		  { "Monitor name", "spoolss.monitorname", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_defaultdatatype,
		  { "Default data type", "spoolss.defaultdatatype", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_driverinfo_cversion,
		  { "Driver version", "spoolss.driverversion", FT_UINT32, BASE_DEC,
		    VALS(driverinfo_cversion_vals), 0, "Printer name", HFILL }},
		{ &hf_dependentfiles,
		  { "Dependent files", "spoolss.dependentfiles", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_printer_status,
		  { "Status", "spoolss.printer_status", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		    &printer_status_vals_ext, 0, NULL, HFILL }},

		{ &hf_previousdrivernames,
		  { "Previous Driver Names", "spoolss.previousdrivernames", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_driverdate,
		  { "Driver Date", "spoolss.driverdate", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		    NULL, 0, "Date of driver creation", HFILL }},

		{ &hf_padding,
		  { "Padding", "spoolss.padding", FT_UINT32, BASE_HEX,
		    NULL, 0, "Some padding - conveys no semantic information", HFILL }},

		{ &hf_driver_version_low,
		  { "Minor Driver Version", "spoolss.minordriverversion", FT_UINT32, BASE_DEC,
		    NULL, 0, "Driver Version Low", HFILL }},

		{ &hf_driver_version_high,
		  { "Major Driver Version", "spoolss.majordriverversion", FT_UINT32, BASE_DEC,
		    NULL, 0, "Driver Version High", HFILL }},

		{ &hf_mfgname,
		  { "Mfgname", "spoolss.mfgname", FT_STRING, BASE_NONE,
		    NULL, 0, "Manufacturer Name", HFILL }},

		{ &hf_oemurl,
		  { "OEM URL", "spoolss.oemrul", FT_STRING, BASE_NONE,
		    NULL, 0, "OEM URL - Website of Vendor", HFILL }},

		{ &hf_hardwareid,
		  { "Hardware ID", "spoolss.hardwareid", FT_STRING, BASE_NONE,
		    NULL, 0, "Hardware Identification Information", HFILL }},

	   	{ &hf_provider,
	   	  { "Provider", "spoolss.provider", FT_STRING, BASE_NONE,
		    NULL, 0, "Provider of Driver", HFILL }},

		/* Setprinter RPC */

		{ &hf_setprinter_cmd,
		  { "Command", "spoolss.setprinter_cmd", FT_UINT32, BASE_DEC,
		   VALS(setprinter_cmd_vals), 0, NULL, HFILL }},

		/* Enumprinters */

		{ &hf_enumprinters_flags,
		  { "Flags", "spoolss.enumprinters.flags",
		    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_enumprinters_flags_local,
		  { "Enum local", "spoolss.enumprinters.flags.enum_local",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ENUM_LOCAL, NULL, HFILL }},

		{ &hf_enumprinters_flags_name,
		  { "Enum name", "spoolss.enumprinters.flags.enum_name",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ENUM_NAME, NULL, HFILL }},

		{ &hf_enumprinters_flags_shared,
		  { "Enum shared", "spoolss.enumprinters.flags.enum_shared",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ENUM_SHARED, NULL, HFILL }},

		{ &hf_enumprinters_flags_default,
		  { "Enum default", "spoolss.enumprinters.flags.enum_default",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ENUM_DEFAULT, NULL, HFILL }},

		{ &hf_enumprinters_flags_connections,
		  { "Enum connections", "spoolss.enumprinters.flags.enum_connections",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ENUM_CONNECTIONS, NULL, HFILL }},

		{ &hf_enumprinters_flags_network,
		  { "Enum network", "spoolss.enumprinters.flags.enum_network",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ENUM_NETWORK, NULL, HFILL }},

		{ &hf_enumprinters_flags_remote,
		  { "Enum remote", "spoolss.enumprinters.flags.enum_remote",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ENUM_REMOTE, NULL, HFILL }},

		/* GetPrinter */

		{ &hf_start_time,
		  { "Start time", "spoolss.start_time",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_end_time,
		  { "End time", "spoolss.end_time",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_elapsed_time,
		  { "Elapsed time", "spoolss.elapsed_time",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		/*
		 * New hf index values
		 */

		{ &hf_opnum,
		  { "Operation", "spoolss.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_hnd,
		  { "Context handle", "spoolss.hnd", FT_BYTES, BASE_NONE,
		    NULL, 0x0, "SPOOLSS policy handle", HFILL }},

		{ &hf_rc,
		  { "Return code", "spoolss.rc", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
		    &DOS_errors_ext, 0x0, "SPOOLSS return code", HFILL }},

		{ &hf_offered,
		  { "Offered", "spoolss.offered", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Size of buffer offered in this request",
		    HFILL }},

		{ &hf_needed,
		  { "Needed", "spoolss.needed", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Size of buffer required for request", HFILL }},

		{ &hf_returned,
		  { "Returned", "spoolss.returned", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Number of items returned", HFILL }},

		{ &hf_buffer_size,
		  { "Buffer size", "spoolss.buffer.size", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Size of buffer", HFILL }},

		{ &hf_buffer_data,
		  { "Buffer data", "spoolss.buffer.data", FT_BYTES, BASE_NONE,
		    NULL, 0x0, "Contents of buffer", HFILL }},

		{ &hf_string_parm_size,
		  { "String buffer size", "spoolss.string.buffersize", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Size of string buffer", HFILL }},

		{ &hf_string_parm_data,
		  { "String data", "spoolss.string.data", FT_STRINGZ, BASE_NONE,
		    NULL, 0x0, "Contents of string", HFILL }},

		{ &hf_offset,
		  { "Offset", "spoolss.offset", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Offset of data", HFILL }},

		{ &hf_level,
		  { "Info level", "spoolss.enumjobs.level", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }},


		{ &hf_printername,
		  { "Printer name", "spoolss.printername", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_machinename,
		  { "Machine name", "spoolss.machinename", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_notifyname,
		  { "Notify name", "spoolss.notifyname", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_printerdesc,
		  { "Printer description", "spoolss.printerdesc", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_printercomment,
		  { "Printer comment", "spoolss.printercomment", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_servername,
		  { "Server name", "spoolss.servername", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_sharename,
		  { "Share name", "spoolss.sharename", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_portname,
		  { "Port name", "spoolss.portname", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_printerlocation,
		  { "Printer location", "spoolss.printerlocation", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_environment,
		  { "Environment name", "spoolss.environment", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_drivername,
		  { "Driver name", "spoolss.drivername", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_username,
		  { "User name", "spoolss.username", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_documentname,
		  { "Document name", "spoolss.document", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_outputfile,
		  { "Output file", "spoolss.outputfile", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_datatype,
		  { "Datatype", "spoolss.datatype", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_textstatus,
		  { "Text status", "spoolss.textstatus", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

 		{ &hf_sepfile,
		  { "Separator file", "spoolss.setpfile", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

 		{ &hf_parameters,
		  { "Parameters", "spoolss.parameters", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_printprocessor,
		  { "Print processor", "spoolss.printprocessor", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		/* Printer data */

		{ &hf_printerdata,
		  { "Data", "spoolss.printerdata", FT_UINT32,
		    BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_printerdata_key,
		  { "Key", "spoolss.printerdata.key", FT_STRING,
		    BASE_NONE, NULL, 0, "Printer data key", HFILL }},

		{ &hf_printerdata_value,
		  { "Value", "spoolss.printerdata.value",
		    FT_STRING, BASE_NONE, NULL, 0, "Printer data value",
		    HFILL }},

		{ &hf_printerdata_type,
		  { "Type", "spoolss.printerdata.type",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &reg_datatypes_ext, 0,
		    "Printer data type", HFILL }},

		{ &hf_printerdata_size,
		  { "Size", "spoolss.printerdata.size",
		    FT_UINT32, BASE_DEC, NULL, 0, "Printer data size",
		    HFILL }},

		{ &hf_printerdata_data,
		  { "Data", "spoolss.printerdata.data", FT_BYTES, BASE_NONE,
		    NULL, 0x0, "Printer data", HFILL }},

		{ &hf_printerdata_data_dword,
		  { "DWORD data", "spoolss.printerdata.data.dword",
		    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_printerdata_data_sz,
		  { "String data", "spoolss.printerdata.data.sz",
		    FT_STRING, BASE_NONE, NULL, 0, NULL,
		    HFILL }},

		/* Devicemode */

		{ &hf_devmodectr_size,
		  { "Devicemode ctr size", "spoolss.devicemodectr.size",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL,
		    HFILL }},

		{ &hf_devmode,
		  { "Devicemode", "spoolss.devmode", FT_UINT32,
		    BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_size,
		  { "Size", "spoolss.devmode.size",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_spec_version,
		  { "Spec version", "spoolss.devmode.spec_version",
		    FT_UINT16, BASE_DEC, VALS(devmode_specversion_vals),
		    0, NULL, HFILL }},

		{ &hf_devmode_driver_version,
		  { "Driver version", "spoolss.devmode.driver_version",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_size2,
		  { "Size2", "spoolss.devmode.size2",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_fields,
		  { "Fields", "spoolss.devmode.fields",
		    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_orientation,
		  { "Orientation", "spoolss.devmode.orientation",
		    FT_UINT16, BASE_DEC, VALS(devmode_orientation_vals),
		    0, NULL, HFILL }},

		{ &hf_devmode_paper_size,
		  { "Paper size", "spoolss.devmode.paper_size",
		    FT_UINT16, BASE_DEC|BASE_EXT_STRING, &devmode_papersize_vals_ext,
		    0, NULL, HFILL }},

		{ &hf_devmode_paper_width,
		  { "Paper width", "spoolss.devmode.paper_width",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_paper_length,
		  { "Paper length", "spoolss.devmode.paper_length",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_scale,
		  { "Scale", "spoolss.devmode.scale",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_copies,
		  { "Copies", "spoolss.devmode.copies",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_default_source,
		  { "Default source", "spoolss.devmode.default_source",
		    FT_UINT16, BASE_DEC|BASE_EXT_STRING, &devmode_papersource_vals_ext,
		    0, NULL, HFILL }},

		{ &hf_devmode_print_quality,
		  { "Print quality", "spoolss.devmode.print_quality",
		    FT_UINT16, BASE_DEC, VALS(devmode_printquality_vals),
		    0, NULL, HFILL }},

		{ &hf_devmode_color,
		  { "Color", "spoolss.devmode.color",
		    FT_UINT16, BASE_DEC, VALS(devmode_colour_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_duplex,
		  { "Duplex", "spoolss.devmode.duplex",
		    FT_UINT16, BASE_DEC, VALS(devmode_duplex_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_y_resolution,
		  { "Y resolution", "spoolss.devmode.y_resolution",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_tt_option,
		  { "TT option", "spoolss.devmode.tt_option",
		    FT_UINT16, BASE_DEC, VALS(devmode_ttoption_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_collate,
		  { "Collate", "spoolss.devmode.collate",
		    FT_UINT16, BASE_DEC, VALS(devmode_collate_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_log_pixels,
		  { "Log pixels", "spoolss.devmode.log_pixels",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_bits_per_pel,
		  { "Bits per pel", "spoolss.devmode.bits_per_pel",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_pels_width,
		  { "Pels width", "spoolss.devmode.pels_width",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_pels_height,
		  { "Pels height", "spoolss.devmode.pels_height",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_display_flags,
		  { "Display flags", "spoolss.devmode.display_flags",
		    FT_UINT32, BASE_DEC, VALS(devmode_displayflags_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_display_freq,
		  { "Display frequency", "spoolss.devmode.display_freq",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL,
		    HFILL }},

		{ &hf_devmode_icm_method,
		  { "ICM method", "spoolss.devmode.icm_method",
		    FT_UINT32, BASE_DEC, VALS(devmode_icmmethod_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_icm_intent,
		  { "ICM intent", "spoolss.devmode.icm_intent",
		    FT_UINT32, BASE_DEC, VALS(devmode_icmintent_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_media_type,
		  { "Media type", "spoolss.devmode.media_type",
		    FT_UINT32, BASE_DEC, VALS(devmode_mediatype_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_dither_type,
		  { "Dither type", "spoolss.devmode.dither_type",
		    FT_UINT32, BASE_DEC, VALS(devmode_dithertype_vals), 0,
		    NULL, HFILL }},

		{ &hf_devmode_reserved1,
		  { "Reserved1", "spoolss.devmode.reserved1",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_reserved2,
		  { "Reserved2", "spoolss.devmode.reserved2",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_panning_width,
		  { "Panning width", "spoolss.devmode.panning_width",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_panning_height,
		  { "Panning height", "spoolss.devmode.panning_height",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_driver_extra_len,
		  { "Driver extra length",
		    "spoolss.devmode.driver_extra_len",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL,
		    HFILL }},

		{ &hf_devmode_driver_extra,
		  { "Driver extra", "spoolss.devmode.driver_extra",
		    FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		/* Devicemode fields */

		{ &hf_devmode_fields_orientation,
		  { "Orientation", "spoolss.devmode.fields.orientation",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_ORIENTATION, NULL, HFILL }},

		{ &hf_devmode_fields_papersize,
		  { "Paper size", "spoolss.devmode.fields.paper_size",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_PAPERSIZE, NULL, HFILL }},

		{ &hf_devmode_fields_paperlength,
		  { "Paper length", "spoolss.devmode.fields.paper_length",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_PAPERLENGTH, NULL, HFILL }},

		{ &hf_devmode_fields_paperwidth,
		  { "Paper width", "spoolss.devmode.fields.paper_width",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_PAPERWIDTH, NULL, HFILL }},

		{ &hf_devmode_fields_scale,
		  { "Scale", "spoolss.devmode.fields.scale",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_SCALE, NULL, HFILL }},

		{ &hf_devmode_fields_position,
		  { "Position", "spoolss.devmode.fields.position",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_POSITION, NULL, HFILL }},

		{ &hf_devmode_fields_nup,
		  { "N-up", "spoolss.devmode.fields.nup",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_NUP, NULL, HFILL }},

		{ &hf_devmode_fields_copies,
		  { "Copies", "spoolss.devmode.fields.copies",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_COPIES, NULL, HFILL }},

		{ &hf_devmode_fields_defaultsource,
		  { "Default source", "spoolss.devmode.fields.default_source",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_DEFAULTSOURCE, NULL, HFILL }},

		{ &hf_devmode_fields_printquality,
		  { "Print quality", "spoolss.devmode.fields.print_quality",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_PRINTQUALITY, NULL, HFILL }},

		{ &hf_devmode_fields_color,
		  { "Color", "spoolss.devmode.fields.color",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_COLOR, NULL, HFILL }},

		{ &hf_devmode_fields_duplex,
		  { "Duplex", "spoolss.devmode.fields.duplex",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_DUPLEX, NULL, HFILL }},

		{ &hf_devmode_fields_yresolution,
		  { "Y resolution", "spoolss.devmode.fields.y_resolution",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_YRESOLUTION, NULL, HFILL }},

		{ &hf_devmode_fields_ttoption,
		  { "TT option", "spoolss.devmode.fields.tt_option",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_TTOPTION, NULL, HFILL }},

		{ &hf_devmode_fields_collate,
		  { "Collate", "spoolss.devmode.fields.collate",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_COLLATE, NULL, HFILL }},

		{ &hf_devmode_fields_formname,
		  { "Form name", "spoolss.devmode.fields.form_name",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_FORMNAME, NULL, HFILL }},

		{ &hf_devmode_fields_logpixels,
		  { "Log pixels", "spoolss.devmode.fields.log_pixels",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_LOGPIXELS, NULL, HFILL }},

		{ &hf_devmode_fields_bitsperpel,
		  { "Bits per pel", "spoolss.devmode.fields.bits_per_pel",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_BITSPERPEL, NULL, HFILL }},

		{ &hf_devmode_fields_pelswidth,
		  { "Pels width", "spoolss.devmode.fields.pels_width",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_PELSWIDTH, NULL, HFILL }},

		{ &hf_devmode_fields_pelsheight,
		  { "Pels height", "spoolss.devmode.fields.pels_height",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_PELSHEIGHT, NULL, HFILL }},

		{ &hf_devmode_fields_displayflags,
		  { "Display flags", "spoolss.devmode.fields.display_flags",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_DISPLAYFLAGS, NULL, HFILL }},

		{ &hf_devmode_fields_displayfrequency,
		  { "Display frequency",
		    "spoolss.devmode.fields.display_frequency",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_DISPLAYFREQUENCY, NULL, HFILL }},

		{ &hf_devmode_fields_icmmethod,
		  { "ICM method", "spoolss.devmode.fields.icm_method",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_ICMMETHOD, NULL, HFILL }},

		{ &hf_devmode_fields_icmintent,
		  { "ICM intent", "spoolss.devmode.fields.icm_intent",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_ICMINTENT, NULL, HFILL }},

		{ &hf_devmode_fields_mediatype,
		  { "Media type", "spoolss.devmode.fields.media_type",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_MEDIATYPE, NULL, HFILL }},

		{ &hf_devmode_fields_dithertype,
		  { "Dither type", "spoolss.devmode.fields.dither_type",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_DITHERTYPE, NULL, HFILL }},

		{ &hf_devmode_fields_panningwidth,
		  { "Panning width", "spoolss.devmode.fields.panning_width",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_PANNINGWIDTH, NULL, HFILL }},

		{ &hf_devmode_fields_panningheight,
		  { "Panning height", "spoolss.devmode.fields.panning_height",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    DEVMODE_PANNINGHEIGHT, NULL, HFILL }},

		/* EnumPrinterData RPC */

		{ &hf_enumprinterdata_enumindex,
		  { "Enum index", "spoolss.enumprinterdata.enumindex",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Index for start of enumeration", HFILL }},

		{ &hf_enumprinterdata_value_offered,
		  { "Value size offered",
		    "spoolss.enumprinterdata.value_offered", FT_UINT32,
		    BASE_DEC, NULL, 0x0,
		    "Buffer size offered for printerdata value", HFILL }},

		{ &hf_enumprinterdata_data_offered,
		  { "Data size offered",
		    "spoolss.enumprinterdata.data_offered", FT_UINT32,
		    BASE_DEC, NULL, 0x0,
		    "Buffer size offered for printerdata data", HFILL }},

		{ &hf_enumprinterdata_value_len,
		  { "Value length",
		    "spoolss.enumprinterdata.value_len", FT_UINT32,
		    BASE_DEC, NULL, 0x0,
		    "Size of printerdata value", HFILL }},

		{ &hf_enumprinterdata_value_needed,
		  { "Value size needed",
		    "spoolss.enumprinterdata.value_needed", FT_UINT32,
		    BASE_DEC, NULL, 0x0,
		    "Buffer size needed for printerdata value", HFILL }},

		{ &hf_enumprinterdata_data_needed,
		  { "Data size needed",
		    "spoolss.enumprinterdata.data_needed", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Buffer size needed for printerdata data",
		    HFILL }},

		/* Print jobs */

		{ &hf_job_id,
		  { "Job ID", "spoolss.job.id", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Job identification number", HFILL }},

		{ &hf_job_status,
		  { "Job status", "spoolss.job.status", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_job_status_paused,
		  { "Paused", "spoolss.job.status.paused", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_paused), JOB_STATUS_PAUSED,
		    NULL, HFILL }},

		{ &hf_job_status_error,
		  { "Error", "spoolss.job.status.error", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_error), JOB_STATUS_ERROR,
		    NULL, HFILL }},

		{ &hf_job_status_deleting,
		  { "Deleting", "spoolss.job.status.deleting", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_deleting), JOB_STATUS_DELETING,
		    NULL, HFILL }},

		{ &hf_job_status_spooling,
		  { "Spooling", "spoolss.job.status.spooling", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_spooling), JOB_STATUS_SPOOLING,
		    NULL, HFILL }},

		{ &hf_job_status_printing,
		  { "Printing", "spoolss.job.status.printing", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_printing), JOB_STATUS_PRINTING,
		    NULL, HFILL }},

		{ &hf_job_status_offline,
		  { "Offline", "spoolss.job.status.offline", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_offline), JOB_STATUS_OFFLINE,
		    NULL, HFILL }},

		{ &hf_job_status_paperout,
		  { "Paperout", "spoolss.job.status.paperout", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_paperout), JOB_STATUS_PAPEROUT,
		    NULL, HFILL }},

		{ &hf_job_status_printed,
		  { "Printed", "spoolss.job.status.printed", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_printed), JOB_STATUS_PRINTED,
		    NULL, HFILL }},

		{ &hf_job_status_deleted,
		  { "Deleted", "spoolss.job.status.deleted", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_deleted), JOB_STATUS_DELETED,
		    NULL, HFILL }},

		{ &hf_job_status_blocked,
		  { "Blocked", "spoolss.job.status.blocked", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_blocked), JOB_STATUS_BLOCKED,
		    NULL, HFILL }},

		{ &hf_job_status_user_intervention,
		  { "User intervention",
		    "spoolss.job.status.user_intervention", FT_BOOLEAN, 32,
		    TFS(&tfs_job_status_user_intervention),
		    JOB_STATUS_USER_INTERVENTION, NULL,
		    HFILL }},

		{ &hf_job_priority,
		  { "Job priority", "spoolss.job.priority", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_job_position,
		  { "Job position", "spoolss.job.position", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_job_totalpages,
		  { "Job total pages", "spoolss.job.totalpages", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_job_totalbytes,
		  { "Job total bytes", "spoolss.job.totalbytes", FT_UINT32,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_job_bytesprinted,
		  { "Job bytes printed", "spoolss.job.bytesprinted",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
		    HFILL }},

		{ &hf_job_pagesprinted,
		  { "Job pages printed", "spoolss.job.pagesprinted",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
		    HFILL }},

		{ &hf_job_size,
		  { "Job size", "spoolss.job.size", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		/* Forms */

		{ &hf_form,
		  { "Data", "spoolss.form", FT_UINT32,
		    BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_form_level,
		  { "Level", "spoolss.form.level", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_form_name,
		  { "Name", "spoolss.form.name", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_form_flags,
		  { "Flags", "spoolss.form.flags", FT_UINT32,
		    BASE_DEC, VALS(form_type_vals), 0, NULL, HFILL }},

		{ &hf_form_unknown,
		  { "Unknown", "spoolss.form.unknown", FT_UINT32,
		    BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_form_width,
		  { "Width", "spoolss.form.width", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_form_height,
		  { "Height", "spoolss.form.height", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_form_left_margin,
		  { "Left margin", "spoolss.form.left", FT_UINT32,
		    BASE_DEC, NULL, 0, "Left", HFILL }},

		{ &hf_form_top_margin,
		  { "Top", "spoolss.form.top", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_form_horiz_len,
		  { "Horizontal", "spoolss.form.horiz", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_form_vert_len,
		  { "Vertical", "spoolss.form.vert", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_enumforms_num,
		  { "Num", "spoolss.enumforms.num", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		/* Print notify */

		{ &hf_notify_options_version,
		  { "Version", "spoolss.notify_options.version", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_options_flags,
		  { "Flags", "spoolss.notify_options.flags", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_options_count,
		  { "Count", "spoolss.notify_options.count", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_option_type,
		  { "Type", "spoolss.notify_option.type", FT_UINT16, BASE_DEC,
		    VALS(printer_notify_types), 0, NULL, HFILL }},

		{ &hf_notify_option_reserved1,
		  { "Reserved1", "spoolss.notify_option.reserved1", FT_UINT16,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_option_reserved2,
		  { "Reserved2", "spoolss.notify_option.reserved2", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_option_reserved3,
		  { "Reserved3", "spoolss.notify_option.reserved3", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_option_count,
		  { "Count", "spoolss.notify_option.count", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_option_data_count,
		  { "Count", "spoolss.notify_option_data.count", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_options_flags_refresh,
		  { "Refresh", "spoolss.notify_options.flags.refresh", FT_BOOLEAN, 32,
		    TFS(&tfs_notify_options_flags_refresh),
		    PRINTER_NOTIFY_OPTIONS_REFRESH, NULL, HFILL }},

		{ &hf_notify_info_count,
		  { "Count", "spoolss.notify_info.count", FT_UINT32, BASE_DEC,
		    NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_version,
		  { "Version", "spoolss.notify_info.version", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_flags,
		  { "Flags", "spoolss.notify_info.flags", FT_UINT32, BASE_HEX,
		    NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_type,
		  { "Type", "spoolss.notify_info_data.type", FT_UINT16,
		    BASE_DEC, VALS(printer_notify_types), 0, NULL, HFILL }},

		{ &hf_notify_field,
		  { "Field", "spoolss.notify_field", FT_UINT16, BASE_DEC,
		    NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_count,
		  { "Count", "spoolss.notify_info_data.count", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_id,
		  { "Job Id", "spoolss.notify_info_data.jobid", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_value1,
		  { "Value1", "spoolss.notify_info_data.value1", FT_UINT32,
		    BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_value2,
		  { "Value2", "spoolss.notify_info_data.value2", FT_UINT32,
		    BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_bufsize,
		  { "Buffer size", "spoolss.notify_info_data.bufsize",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_buffer,
		  { "Buffer", "spoolss.notify_info_data.buffer", FT_UINT32,
		    BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_buffer_len,
		  { "Buffer length", "spoolss.notify_info_data.buffer.len",
		    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_notify_info_data_buffer_data,
		  { "Buffer data", "spoolss.notify_info_data.buffer.data",
		    FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		/* RffpCNex RPC */

		{ &hf_rffpcnex_options,
		  { "Options", "spoolss.rffpcnex.options", FT_UINT32, BASE_DEC,
		    NULL, 0, "RFFPCNEX options", HFILL }},

		{ &hf_printerlocal, /* XXX: move me */
		  { "Printer local", "spoolss.printer_local", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_rffpcnex_flags,
		  { "RFFPCNEX flags", "spoolss.rffpcnex.flags", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_rffpcnex_flags_add_printer,
		  { "Add printer", "spoolss.rffpcnex.flags.add_printer",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_printer),
		    SPOOLSS_PRINTER_CHANGE_ADD_PRINTER, NULL,
		    HFILL }},

		{ &hf_rffpcnex_flags_set_printer,
		  { "Set printer", "spoolss.rffpcnex.flags.set_printer",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_set_printer),
		    SPOOLSS_PRINTER_CHANGE_SET_PRINTER, NULL,
		    HFILL }},

		{ &hf_rffpcnex_flags_delete_printer,
		  { "Delete printer", "spoolss.rffpcnex.flags.delete_printer",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_printer),
		    SPOOLSS_PRINTER_CHANGE_DELETE_PRINTER, NULL,
		    HFILL }},

		{ &hf_rffpcnex_flags_add_job,
		  { "Add job", "spoolss.rffpcnex.flags.add_job",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_job),
		    SPOOLSS_PRINTER_CHANGE_ADD_JOB, NULL, HFILL }},

		{ &hf_rffpcnex_flags_set_job,
		  { "Set job", "spoolss.rffpcnex.flags.set_job",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_set_job),
		    SPOOLSS_PRINTER_CHANGE_SET_JOB, NULL, HFILL }},

		{ &hf_rffpcnex_flags_delete_job,
		  { "Delete job", "spoolss.rffpcnex.flags.delete_job",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_job),
		    SPOOLSS_PRINTER_CHANGE_DELETE_JOB, NULL, HFILL }},

		{ &hf_rffpcnex_flags_write_job,
		  { "Write job", "spoolss.rffpcnex.flags.write_job",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_write_job),
		    SPOOLSS_PRINTER_CHANGE_WRITE_JOB, NULL, HFILL }},

		{ &hf_rffpcnex_flags_add_form,
		  { "Add form", "spoolss.rffpcnex.flags.add_form",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_form),
		    SPOOLSS_PRINTER_CHANGE_ADD_FORM, NULL, HFILL }},

		{ &hf_rffpcnex_flags_set_form,
		  { "Set form", "spoolss.rffpcnex.flags.set_form",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_set_form),
		    SPOOLSS_PRINTER_CHANGE_SET_FORM, NULL, HFILL }},

		{ &hf_rffpcnex_flags_delete_form,
		  { "Delete form", "spoolss.rffpcnex.flags.delete_form",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_form),
		    SPOOLSS_PRINTER_CHANGE_DELETE_FORM, NULL,
		    HFILL }},

		{ &hf_rffpcnex_flags_add_port,
		  { "Add port", "spoolss.rffpcnex.flags.add_port",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_port),
		    SPOOLSS_PRINTER_CHANGE_ADD_PORT, NULL, HFILL }},

		{ &hf_rffpcnex_flags_configure_port,
		  { "Configure port", "spoolss.rffpcnex.flags.configure_port",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_configure_port),
		    SPOOLSS_PRINTER_CHANGE_CONFIGURE_PORT, NULL,
		    HFILL }},

		{ &hf_rffpcnex_flags_delete_port,
		  { "Delete port", "spoolss.rffpcnex.flags.delete_port",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_port),
		    SPOOLSS_PRINTER_CHANGE_DELETE_PORT, NULL,
		    HFILL }},

		{ &hf_rffpcnex_flags_add_print_processor,
		  { "Add processor", "spoolss.rffpcnex.flags.add_processor",
		    FT_BOOLEAN, 32,
		    TFS(&tfs_rffpcnex_flags_add_print_processor),
		    SPOOLSS_PRINTER_CHANGE_ADD_PRINT_PROCESSOR,
		    NULL, HFILL }},

		{ &hf_rffpcnex_flags_delete_print_processor,
		  { "Delete processor",
		    "spoolss.rffpcnex.flags.delete_processor", FT_BOOLEAN, 32,
		    TFS(&tfs_rffpcnex_flags_delete_print_processor),
		    SPOOLSS_PRINTER_CHANGE_DELETE_PRINT_PROCESSOR,
		    NULL, HFILL }},

		{ &hf_rffpcnex_flags_add_driver,
		  { "Add driver", "spoolss.rffpcnex.flags.add_driver",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_add_driver),
		    SPOOLSS_PRINTER_CHANGE_ADD_PRINTER_DRIVER, NULL,
		    HFILL }},

		{ &hf_rffpcnex_flags_set_driver,
		  { "Set driver", "spoolss.rffpcnex.flags.set_driver",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_set_driver),
		    SPOOLSS_PRINTER_CHANGE_SET_PRINTER_DRIVER, NULL,
		    HFILL }},

		{ &hf_rffpcnex_flags_delete_driver,
		  { "Delete driver", "spoolss.rffpcnex.flags.delete_driver",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_delete_driver),
		    SPOOLSS_PRINTER_CHANGE_DELETE_PRINTER_DRIVER,
		    NULL, HFILL }},

		{ &hf_rffpcnex_flags_timeout,
		  { "Timeout", "spoolss.rffpcnex.flags.timeout",
		    FT_BOOLEAN, 32, TFS(&tfs_rffpcnex_flags_timeout),
		    SPOOLSS_PRINTER_CHANGE_TIMEOUT, NULL, HFILL }},

		{ &hf_rffpcnex_flags_failed_printer_connection,
		  { "Failed printer connection",
		    "spoolss.rffpcnex.flags.failed_connection_printer",
		    FT_BOOLEAN, 32,
		    TFS(&tfs_rffpcnex_flags_failed_connection_printer),
		    SPOOLSS_PRINTER_CHANGE_FAILED_CONNECTION_PRINTER,
		    NULL, HFILL }},

		/* RRPCN RPC */

		{ &hf_rrpcn_changelow,
		  { "Change low", "spoolss.rrpcn.changelow", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_rrpcn_changehigh,
		  { "Change high", "spoolss.rrpcn.changehigh", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_rrpcn_unk0,
		  { "Unknown 0", "spoolss.rrpcn.unk0", FT_UINT32, BASE_DEC,
		    NULL, 0, NULL, HFILL }},

		{ &hf_rrpcn_unk1,
		  { "Unknown 1", "spoolss.rrpcn.unk1", FT_UINT32, BASE_DEC,
		    NULL, 0, NULL, HFILL }},

		/* ReplyOpenPrinter RPC */

		{ &hf_replyopenprinter_unk0,
		  { "Unknown 0", "spoolss.replyopenprinter.unk0", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_replyopenprinter_unk1,
		  { "Unknown 1", "spoolss.replyopenprinter.unk1", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_devicename,
		  { "DeviceName", "spoolss.devmode.devicename", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_devmode_form_name,
		  { "FormName", "spoolss.devmode.form_name", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_relative_string,
		  { "String", "spoolss.relative_string", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_value_name,
		  { "Value Name", "spoolss.value_name", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_keybuffer,
		  { "Key", "spoolss.hf_keybuffer", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_value_string,
		  { "Value", "spoolss.value_string", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		/* Printer attributes */

		{ &hf_printer_attributes,
		  { "Attributes", "spoolss.printer_attributes", FT_UINT32,
		    BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_printer_attributes_queued,
		  { "Queued", "spoolss.printer_attributes.queued", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_queued),
		    PRINTER_ATTRIBUTE_QUEUED, NULL, HFILL }},

		{ &hf_printer_attributes_direct,
		  { "Direct", "spoolss.printer_attributes.direct", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_direct),
		    PRINTER_ATTRIBUTE_DIRECT, NULL, HFILL }},

		{ &hf_printer_attributes_default,
		  { "Default (9x/ME only)",
		    "spoolss.printer_attributes.default",FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_default),
		    PRINTER_ATTRIBUTE_DEFAULT, "Default", HFILL }},

		{ &hf_printer_attributes_shared,
		  { "Shared", "spoolss.printer_attributes.shared", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_shared),
		    PRINTER_ATTRIBUTE_SHARED, NULL, HFILL }},

		{ &hf_printer_attributes_network,
		  { "Network", "spoolss.printer_attributes.network",
		    FT_BOOLEAN, 32, TFS(&tfs_printer_attributes_network),
		    PRINTER_ATTRIBUTE_NETWORK, NULL, HFILL }},

		{ &hf_printer_attributes_hidden,
		  { "Hidden", "spoolss.printer_attributes.hidden", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_hidden),
		    PRINTER_ATTRIBUTE_HIDDEN, NULL, HFILL }},

		{ &hf_printer_attributes_local,
		  { "Local", "spoolss.printer_attributes.local", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_local),
		    PRINTER_ATTRIBUTE_LOCAL, NULL, HFILL }},

		{ &hf_printer_attributes_enable_devq,
		  { "Enable devq", "spoolss.printer_attributes.enable_devq",
		    FT_BOOLEAN, 32, TFS(&tfs_printer_attributes_enable_devq),
		    PRINTER_ATTRIBUTE_ENABLE_DEVQ, "Enable evq", HFILL }},

		{ &hf_printer_attributes_keep_printed_jobs,
		  { "Keep printed jobs",
		    "spoolss.printer_attributes.keep_printed_jobs", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_keep_printed_jobs),
		    PRINTER_ATTRIBUTE_KEEPPRINTEDJOBS, NULL,
		    HFILL }},

		{ &hf_printer_attributes_do_complete_first,
		  { "Do complete first",
		    "spoolss.printer_attributes.do_complete_first", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_do_complete_first),
		    PRINTER_ATTRIBUTE_DO_COMPLETE_FIRST, NULL,
		    HFILL }},

		{ &hf_printer_attributes_work_offline,
		  { "Work offline (9x/ME only)",
		    "spoolss.printer_attributes.work_offline", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_work_offline),
		    PRINTER_ATTRIBUTE_WORK_OFFLINE, "Work offline", HFILL }},

		{ &hf_printer_attributes_enable_bidi,
		  { "Enable bidi (9x/ME only)",
		    "spoolss.printer_attributes.enable_bidi", FT_BOOLEAN,
		    32, TFS(&tfs_printer_attributes_enable_bidi),
		    PRINTER_ATTRIBUTE_ENABLE_BIDI, "Enable bidi", HFILL }},

		{ &hf_printer_attributes_raw_only,
		  { "Raw only", "spoolss.printer_attributes.raw_only",
		    FT_BOOLEAN, 32, TFS(&tfs_printer_attributes_raw_only),
		    PRINTER_ATTRIBUTE_RAW_ONLY, NULL, HFILL }},

		{ &hf_printer_attributes_published,
		  { "Published", "spoolss.printer_attributes.published",
		    FT_BOOLEAN, 32, TFS(&tfs_printer_attributes_published),
		    PRINTER_ATTRIBUTE_PUBLISHED, NULL, HFILL }},

		/* Timestamps */

		{ &hf_time_year,
		  { "Year", "spoolss.time.year", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_time_month,
		  { "Month", "spoolss.time.month", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_time_dow,
		  { "Day of week", "spoolss.time.dow", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_time_day,
		  { "Day", "spoolss.time.day", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_time_hour,
		  { "Hour", "spoolss.time.hour", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_time_minute,
		  { "Minute", "spoolss.time.minute", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_time_second,
		  { "Second", "spoolss.time.second", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_time_msec,
		  { "Millisecond", "spoolss.time.msec", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		/* Userlevel */

		{ &hf_userlevel_size,
		  { "Size", "spoolss.userlevel.size",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_userlevel_client,
		  { "Client", "spoolss.userlevel.client", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_userlevel_user,
		  { "User", "spoolss.userlevel.user", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_userlevel_build,
		  { "Build", "spoolss.userlevel.build",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_userlevel_major,
		  { "Major", "spoolss.userlevel.major",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_userlevel_minor,
		  { "Minor", "spoolss.userlevel.minor",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_userlevel_processor,
		  { "Processor", "spoolss.userlevel.processor",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		/* EnumprinterdataEx RPC */

		{ &hf_enumprinterdataex_name_offset,
		  { "Name offset", "spoolss.enumprinterdataex.name_offset",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_name_len,
		  { "Name len", "spoolss.enumprinterdataex.name_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_name,
		  { "Name", "spoolss.enumprinterdataex.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_val_offset,
		  { "Value offset", "spoolss.enumprinterdataex.value_offset",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_val_len,
		  { "Value len", "spoolss.enumprinterdataex.value_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_val_dword_high,
		  { "DWORD value (high)",
		    "spoolss.enumprinterdataex.val_dword.high",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_value_null,
		  { "Value",
		    "spoolss.enumprinterdataex.val_null",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_value_uint,
		  { "Value",
		    "spoolss.enumprinterdataex.val_uint",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_value_binary,
		  { "Value",
		    "spoolss.enumprinterdataex.val_binary",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_value_multi_sz,
		  { "Value",
		    "spoolss.enumprinterdataex.val_multi_sz",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_enumprinterdataex_val_dword_low,
		  { "DWORD value (low)",
		    "spoolss.enumprinterdataex.val_dword.low",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		/* RouterReplyPrinter RPC */

		{ &hf_routerreplyprinter_condition,
		  { "Condition", "spoolss.routerreplyprinter.condition",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_routerreplyprinter_unknown1,
		  { "Unknown1", "spoolss.routerreplyprinter.unknown1",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_routerreplyprinter_changeid,
		  { "Change id", "spoolss.routerreplyprinter.changeid",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		/* EnumPrinterKey RPC */

		{ &hf_keybuffer_size,
		  { "Key Buffer size", "spoolss.keybuffer.size", FT_UINT32,
		    BASE_DEC, NULL, 0x0, "Size of buffer", HFILL }},

		/* SetJob RPC */

		{ &hf_setjob_cmd,
		  { "Set job command", "spoolss.setjob.cmd", FT_UINT32,
		    BASE_DEC, VALS(setjob_commands), 0x0, "Printer data name",
		    HFILL }},

		/* EnumJobs RPC */

		{ &hf_enumjobs_firstjob,
		  { "First job", "spoolss.enumjobs.firstjob", FT_UINT32,
		    BASE_DEC, NULL, 0x0, "Index of first job to return",
		    HFILL }},

		{ &hf_enumjobs_numjobs,
		  { "Num jobs", "spoolss.enumjobs.numjobs", FT_UINT32,
		    BASE_DEC, NULL, 0x0, "Number of jobs to return", HFILL }},

		/* Security descriptor buffer */

		{ &hf_secdescbuf_maxlen,
		  { "Max len", "spoolss.secdescbuf.max_len",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_secdescbuf_undoc,
		  { "Undocumented", "spoolss.secdescbuf.undoc",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_secdescbuf_len,
		  { "Length", "spoolss.secdescbuf.len",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		/* Spool printer info */

		{ &hf_spool_printer_info_devmode_ptr,
		  { "Devmode pointer", "spoolss.spoolprinterinfo.devmode_ptr",
		    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_spool_printer_info_secdesc_ptr,
		  { "Secdesc pointer", "spoolss.spoolprinterinfo.secdesc_ptr",
		    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		/* WritePrinter RPC */

		{ &hf_writeprinter_numwritten,
		  { "Num written", "spoolss.writeprinter.numwritten",
		    FT_UINT32, BASE_DEC, NULL, 0x0, "Number of bytes written",
		    HFILL }},

		/* Setprinterdataex RPC */

		{ &hf_setprinterdataex_max_len,
		  { "Max len", "spoolss.setprinterdataex.max_len",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_setprinterdataex_real_len,
		  { "Real len", "spoolss.setprinterdataex.real_len",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_setprinterdataex_data,
		  { "Data", "spoolss.setprinterdataex.data",
		    FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		/* Specific access rights */

		{ &hf_access_required,
		  { "Access required", "spoolss.access_required",
		    FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
		    HFILL }},

		{ &hf_server_access_admin,
		  { "Server admin", "spoolss.access_mask.server_admin",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    SERVER_ACCESS_ADMINISTER, NULL, HFILL }},

		{ &hf_server_access_enum,
		  { "Server enum", "spoolss.access_mask.server_enum",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    SERVER_ACCESS_ENUMERATE, NULL, HFILL }},

		{ &hf_printer_access_admin,
		  { "Printer admin", "spoolss.access_mask.printer_admin",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ACCESS_ADMINISTER, NULL, HFILL }},

		{ &hf_printer_access_use,
		  { "Printer use", "spoolss.access_mask.printer_use",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    PRINTER_ACCESS_USE, NULL, HFILL }},

		{ &hf_job_access_admin,
		  { "Job admin", "spoolss.access_mask.job_admin",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset),
		    JOB_ACCESS_ADMINISTER, NULL, HFILL }},

		/* Printer information */

		{ &hf_printer_cjobs,
		  { "CJobs", "spoolss.printer.cjobs", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_total_jobs,
		  { "Total jobs", "spoolss.printer.total_jobs", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_total_bytes,
		  { "Total bytes", "spoolss.printer.total_bytes", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_global_counter,
		  { "Global counter", "spoolss.printer.global_counter",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_total_pages,
		  { "Total pages", "spoolss.printer.total_pages", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_major_version,
		  { "Major version", "spoolss.printer.major_version",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_build_version,
		  { "Build version", "spoolss.printer.build_version",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk7,
		  { "Unknown 7", "spoolss.printer.unknown7", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk8,
		  { "Unknown 8", "spoolss.printer.unknown8", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk9,
		  { "Unknown 9", "spoolss.printer.unknown9", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_session_ctr,
		  { "Session counter", "spoolss.printer.session_ctr",
		    FT_UINT32, BASE_DEC, NULL, 0, "Sessopm counter", HFILL }},

		{ &hf_printer_unk11,
		  { "Unknown 11", "spoolss.printer.unknown11", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_printer_errors,
		  { "Printer errors", "spoolss.printer.printer_errors",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk13,
		  { "Unknown 13", "spoolss.printer.unknown13", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk14,
		  { "Unknown 14", "spoolss.printer.unknown14", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk15,
		  { "Unknown 15", "spoolss.printer.unknown15", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk16,
		  { "Unknown 16", "spoolss.printer.unknown16", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_changeid,
		  { "Change id", "spoolss.printer.changeid", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk18,
		  { "Unknown 18", "spoolss.printer.unknown18", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk20,
		  { "Unknown 20", "spoolss.printer.unknown20", FT_UINT32,
		    BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_c_setprinter,
		  { "Csetprinter", "spoolss.printer.c_setprinter",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk22,
		  { "Unknown 22", "spoolss.printer.unknown22",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk23,
		  { "Unknown 23", "spoolss.printer.unknown23",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk24,
		  { "Unknown 24", "spoolss.printer.unknown24",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk25,
		  { "Unknown 25", "spoolss.printer.unknown25",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk26,
		  { "Unknown 26", "spoolss.printer.unknown26",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk27,
		  { "Unknown 27", "spoolss.printer.unknown27",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk28,
		  { "Unknown 28", "spoolss.printer.unknown28",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_unk29,
		  { "Unknown 29", "spoolss.printer.unknown29",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_flags,
		  { "Flags", "spoolss.printer.flags",
		    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_printer_priority,
		  { "Priority", "spoolss.printer.priority",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_default_priority,
		  { "Default Priority", "spoolss.printer.default_priority",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_averageppm,
		  { "Average PPM", "spoolss.printer.averageppm",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_jobs,
		  { "Jobs", "spoolss.printer.jobs",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_printer_guid,
		  { "GUID", "spoolss.printer.guid", FT_STRING,
		    BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_printer_action,
		  { "Action", "spoolss.printer.action", FT_UINT32, BASE_DEC,
		   VALS(getprinter_action_vals), 0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_dcerpc_spoolss,
		&ett_PRINTER_DATATYPE,
		&ett_DEVMODE_CTR,
		&ett_DEVMODE,
		&ett_DEVMODE_fields,
		&ett_USER_LEVEL_CTR,
		&ett_USER_LEVEL_1,
		&ett_BUFFER,
		&ett_PRINTER_INFO,
		&ett_SPOOL_PRINTER_INFO_LEVEL,
		&ett_PRINTER_INFO_0,
		&ett_PRINTER_INFO_1,
		&ett_PRINTER_INFO_2,
		&ett_PRINTER_INFO_3,
		&ett_PRINTER_INFO_7,
		&ett_RELSTR,
		&ett_RELSTR_ARRAY,
		&ett_FORM_REL,
		&ett_FORM_CTR,
		&ett_FORM_1,
		&ett_JOB_INFO_1,
		&ett_JOB_INFO_2,
		&ett_SEC_DESC_BUF,
		&ett_SYSTEM_TIME,
		&ett_DOC_INFO_1,
		&ett_DOC_INFO,
		&ett_DOC_INFO_CTR,
		&ett_printerdata_value,
		&ett_printerdata_data,
		&ett_writeprinter_buffer,
		&ett_DRIVER_INFO_1,
		&ett_DRIVER_INFO_2,
		&ett_DRIVER_INFO_3,
		&ett_DRIVER_INFO_6,
		&ett_DRIVER_INFO_101,
		&ett_rffpcnex_flags,
		&ett_notify_options_flags,
		&ett_NOTIFY_INFO_DATA,
		&ett_NOTIFY_OPTION,
		&ett_printer_attributes,
		&ett_job_status,
		&ett_enumprinters_flags,
		&ett_PRINTER_DATA_CTR,
		&ett_printer_enumdataex_value,
	};

	static ei_register_info ei[] = {
		{ &ei_unimplemented_dissector, { "spoolss.unimplemented_dissector", PI_UNDECODED, PI_WARN, "Unimplemented dissector: SPOOLSS", EXPFILL }},
		{ &ei_unknown_data, { "spoolss.unknown_data", PI_UNDECODED, PI_WARN, "Unknown data follows", EXPFILL }},
		{ &ei_printer_info_level, { "spoolss.printer.unknown", PI_PROTOCOL, PI_WARN, "Unknown printer info level", EXPFILL }},
		{ &ei_spool_printer_info_level, { "spoolss.spool_printer.unknown", PI_PROTOCOL, PI_WARN, "Unknown spool printer info level", EXPFILL }},
		{ &ei_form_level, { "spoolss.form.level.unknown", PI_PROTOCOL, PI_WARN, "Unknown form info level", EXPFILL }},
		{ &ei_job_info_level, { "spoolss.job_info.level.unknown", PI_PROTOCOL, PI_WARN, "Unknown job info level", EXPFILL }},
		{ &ei_driver_info_level, { "spoolss.driver_info.level.unknown", PI_PROTOCOL, PI_WARN, "Unknown driver info level", EXPFILL }},
		{ &ei_level, { "spoolss.level.unknown", PI_PROTOCOL, PI_WARN, "Info level unknown", EXPFILL }},
		{ &ei_notify_info_data_type, { "spoolss.notify_info_data.type.unknown", PI_PROTOCOL, PI_WARN, "Unknown notify type", EXPFILL }},
		{ &ei_enumprinterdataex_value, { "spoolss.enumprinterdataex.val_unknown", PI_PROTOCOL, PI_WARN, "Unknown value type", EXPFILL }},
	};

	expert_module_t* expert_dcerpc_spoolss;

	proto_dcerpc_spoolss = proto_register_protocol(
		"Microsoft Spool Subsystem", "SPOOLSS", "spoolss");

	proto_register_field_array(proto_dcerpc_spoolss, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_dcerpc_spoolss = expert_register_protocol(proto_dcerpc_spoolss);
	expert_register_field_array(expert_dcerpc_spoolss, ei, array_length(ei));
}

/* Protocol handoff */

static e_guid_t uuid_dcerpc_spoolss = {
	0x12345678, 0x1234, 0xabcd,
	{ 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab }
};

static guint16 ver_dcerpc_spoolss = 1;

void
proto_reg_handoff_dcerpc_spoolss(void)
{

	/* Register protocol as dcerpc */

	dcerpc_init_uuid(proto_dcerpc_spoolss, ett_dcerpc_spoolss,
			 &uuid_dcerpc_spoolss, ver_dcerpc_spoolss,
			 dcerpc_spoolss_dissectors, hf_opnum);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
