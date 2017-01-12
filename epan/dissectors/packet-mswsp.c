/* packet-mswsp.c
 * Routines for Windows Search Protocol dissection
 * Copyright 2012, Gregor Beck <gregor.beck@sernet.de>
 * Copyright 2015, Noel Power <noel.power@suse.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

# include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/exceptions.h>

#include "packet-smb.h"
#include "packet-smb2.h"
#include "packet-dcom.h" /* HRESULT */
#include "to_str.h"
#include "packet-dcerpc-nt.h"

void proto_register_mswsp(void);

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

enum vType {
	VT_EMPTY       = 0x00,
	VT_NULL        = 0x01,
	VT_I2          = 0x02,
	VT_I4          = 0x03,
	VT_R4          = 0x04,
	VT_R8          = 0x05,
	VT_CY          = 0x06,
	VT_DATE        = 0x07,
	VT_BSTR        = 0x08,
	VT_ERROR       = 0x0a,
	VT_BOOL        = 0x0b,
	VT_VARIANT     = 0x0c,
	VT_DECIMAL     = 0x0e,
	VT_I1          = 0x10,
	VT_UI1         = 0x11,
	VT_UI2         = 0x12,
	VT_UI4         = 0x13,
	VT_I8          = 0x14,
	VT_UI8         = 0x15,
	VT_INT         = 0x16,
	VT_UINT        = 0x17,
	VT_LPSTR       = 0x1e,
	VT_LPWSTR      = 0x1f,
	VT_COMPRESSED_LPWSTR = 0x23,
	VT_FILETIME    = 0x40,
	VT_BLOB        = 0x41,
	VT_BLOB_OBJECT = 0x46,
	VT_CLSID       = 0x48,
	VT_VECTOR      = 0x1000,
	VT_ARRAY       = 0x2000
};

struct data_blob {
	guint8 *data;
	guint32 size;
};

struct data_str {
	const char *str;
	guint32 len;
};

struct vt_decimal {
	guint32 hi, lo, mid;
};


struct vt_vector {
	guint32 len;
	union  {
		gint8 *vt_i1;
		guint8 *vt_ui1;
		gint16 *vt_i2;
		guint16 *vt_ui2, *vt_bool;
		gint32 *vt_i4;
		guint32 *vt_ui4, *vt_error;
		gint64 *vt_i8, *vt_cy, *vt_filetime;
		guint64 *vt_ui8;
		float *vt_r4;
		double *vt_r8, *vt_date;
		e_guid_t *vt_clsid;
		struct data_blob *vt_blob, *vt_blob_object;
		struct data_str *vt_lpstr, *vt_lpwstr, *vt_compressed_lpwstr, *vt_bstr;
	} u;
};

struct SAFEARRAYBOUNDS {
	guint32 cElements, lLbound;
};

struct vt_array {
	struct vt_vector vData;
	guint16 cDims, fFeature;
	guint32 cbElements;

	struct SAFEARRAYBOUNDS *Rgsabound;
};

union vt_single
{
	gint8 vt_i1;
	guint8 vt_ui1;
	gint16 vt_i2;
	guint16 vt_ui2, vt_bool;
	gint32 vt_i4, vt_int;
	guint32 vt_ui4, vt_uint, vt_error;
	gint64 vt_i8, vt_cy, vt_filetime;
	guint64 vt_ui8;
	double vt_r8, vt_date;
	e_guid_t vt_clsid;
	float vt_r4;
	struct vt_decimal vt_decimal;
	struct data_blob vt_blob, vt_blob_object;
	struct data_str vt_lpstr, vt_lpwstr, vt_compressed_lpwstr, vt_bstr;
};

union vValue {
	union vt_single vt_single;
	struct vt_vector vt_vector;
	struct vt_array vt_array;
};

struct vtype_data {
	enum vType tag; /* base type, high bits cleared */
	const char *str;  /* string rep of base type */
	int size;        /* -1 for variable length */
	int (*tvb_get)(tvbuff_t*, int, void*);/* read StorageVariant */
	int (*tvb_get_value_only)(tvbuff_t*, int, int, void*);/*read StorageVariant value*/
	void (*strbuf_append)(wmem_strbuf_t*, void*);
};

/* 2.2.1.1 */
struct CBaseStorageVariant {
	guint16 vType; /* value enum vType */
	guint16 vData1;
	guint16 vData2;
	union vValue vValue;

	struct vtype_data *type;
};

/*****************************************************/


enum rType {
	RTNone = 0,
	RTAnd,
	RTOr,
	RTNot,
	RTContent,
	RTProperty,
	RTProximity,
	RTVector,
	RTNatLanguage,
	RTScope,
	RTCoerce_Add,
	RTCoerce_Multiply,
	RTCoerce_Absolute,
	RTProb,
	RTFeedback,
	RTReldoc,
	RTReuseWhere = 0x11,
	RTInternalProp = 0x00fffffa,
	RTPhrase = 0x00fffffd
};


struct CRestriction;

enum relop {
	PRLT = 0,
	PRLE,
	PRGT,
	PRGE,
	PREQ,
	PRNE,
	PRRE,
	PRAllBits,
	PRSomeBits,
	PRAll = 0x100,
	PRAny = 0x200
};

enum PRSPEC_Kind {
	PRSPEC_LPWSTR = 0,
	PRSPEC_PROPID
};

/* 2.2.1.2 */
struct CFullPropSpec {
	e_guid_t guid;
	enum PRSPEC_Kind kind;
	union {
		guint32 propid;
		const guint8 *name;
	} u;
};

/* 2.2.1.7 */
struct CPropertyRestriction {
	guint32 relop; /*with value enum relop*/
	struct CFullPropSpec property;
	struct CBaseStorageVariant prval;
	guint32 lcid;
};

/* 2.2.1.6 */
struct CNodeRestriction {
	guint32 cNode;
	struct CRestriction *paNode;
};

/* 2.2.1.17 */
struct CRestriction {
	enum rType ulType;
	guint32 Weight;
	union {
		struct CNodeRestriction *RTAnd, *RTOr, *RTProximity, *RTPhrase;
		struct CRestriction *RTNot;
		struct CContentRestriction *RTContent;
		struct CPropertyRestriction *RTProperty;
		struct CVectorRestriction *RTVector;
		struct CNatLanguageRestriction *RTNatLanguage;
		struct CScopeRestriction *RTScope;
		struct CReuseWhere *RTReuseWhere;
		struct CInternalPropertyRestriction *RTInternalProp;
		struct CCoercionRestriction *RTCoerce_Add, *RTCoerce_Multiply, *RTCoerce_Absolute;
	} u;
};


/* 2.2.1.12 */
struct CCoercionRestriction {
	float value;
	struct CRestriction child;
};

/* 2.2.1.3 */
struct CContentRestriction {
	struct CFullPropSpec property;
	const guint8 *phrase;
	guint32 lcid;
	guint32 method;
};

/* 2.2.1.8 */
struct CReuseWhere /*Restriction*/ {
	guint32 whereId;
};

/* 2.2.1.5 */
struct CNatLanguageRestriction {
	struct CFullPropSpec property;
	const guint8 *phrase;
	guint32 lcid;
};

#define PROP_LENGTH 255

/* 2.2.1.44 */
struct CTableColumn {
	/*struct CFullPropSpec propspec;*/
	guint32 vtype;
	guint8  aggregateused;
	guint8  aggregatetype;
	guint8  valueused;
	guint16 valueoffset;
	guint16 valuesize;
	guint8  statusused;
	guint16 statusoffset;
	guint8  lengthused;
	guint16 lengthoffset;
	char name[PROP_LENGTH];
};
/* minimum size in bytes on the wire CTableColumn can be */
#define MIN_CTABLECOL_SIZE 32

/* 2.2.3.10 */

struct CPMSetBindingsIn {
	guint32 hcursor;
	guint32 brow;
	guint32 bbindingdesc;
	guint32 dummy;
	guint32 ccolumns;
	struct CTableColumn *acolumns;
};

struct vector_or_array_64 {
	guint64 count;
	guint64 array_address;
};

struct vector_or_array_32 {
	guint32 count;
	guint32 array_address;
};

/* 2.2.1.42 */
struct CRowVariant {
	guint16 vtype;
	guint16 reserved1;
	guint32 reserved2;
	union {
		guint8  byte;
		guint16 shortw;
		guint32 longw;
		guint64 hyperw;
		union {
		    struct vector_or_array_64 i64;
		    struct vector_or_array_32 i32;
		} array_vector;
	} content;
};

static int SMB1 = 1;
static int SMB2 = 2;

void proto_reg_handoff_mswsp(void);

static expert_field ei_missing_msg_context = EI_INIT;
static expert_field ei_mswsp_msg_cpmsetbinding_ccolumns = EI_INIT;

static int proto_mswsp = -1;
static int hf_mswsp_msg = -1;
static int hf_mswsp_hdr = -1;
static int hf_mswsp_hdr_msg = -1;
static int hf_mswsp_hdr_status = -1;
static int hf_mswsp_hdr_checksum = -1;
static int hf_mswsp_hdr_reserved = -1;
static int hf_mswsp_msg_Connect_Version = -1;
static int hf_mswsp_msg_ConnectIn_ClientIsRemote = -1;
static int hf_mswsp_msg_ConnectIn_Blob1 = -1;
static int hf_mswsp_msg_ConnectIn_MachineName = -1;
static int hf_mswsp_msg_ConnectIn_UserName = -1;
static int hf_mswsp_msg_ConnectIn_PropSets_num = -1;
static int hf_mswsp_bool_options = -1;
static int hf_mswsp_bool_options_cursor = -1;
static int hf_mswsp_bool_options_async = -1;
static int hf_mswsp_bool_options_firstrows = -1;
static int hf_mswsp_bool_options_holdrows = -1;
static int hf_mswsp_bool_options_chaptered = -1;
static int hf_mswsp_bool_options_useci = -1;
static int hf_mswsp_bool_options_defertrim = -1;
static int hf_mswsp_bool_options_rowsetevents = -1;
static int hf_mswsp_bool_options_dontcomputeexpensive = -1;
static int hf_mswsp_guid_time_low = -1;
static int hf_mswsp_guid_time_mid = -1;
static int hf_mswsp_guid_time_high = -1;
static int hf_mswsp_guid_time_clock_hi = -1;
static int hf_mswsp_guid_time_clock_low = -1;
static int hf_mswsp_guid_node = -1;
static int hf_mswsp_lcid = -1;
static int hf_mswsp_lcid_sortid = -1;
static int hf_mswsp_lcid_langid = -1;
static int hf_mswsp_cscort_column = -1;
static int hf_mswsp_cscort_order = -1;
static int hf_mswsp_cscort_individual = -1;
static int hf_mswsp_cscortset_count = -1;
static int hf_mswsp_ctablecolumn_vtype = -1;
static int hf_mswsp_ctablecolumn_aggused = -1;
static int hf_mswsp_ctablecolumn_aggtype = -1;
static int hf_mswsp_ctablecolumn_valused = -1;
static int hf_mswsp_ctablecolumn_valoffset = -1;
static int hf_mswsp_ctablecolumn_valsize = -1;
static int hf_mswsp_ctablecolumn_statused = -1;
static int hf_mswsp_ctablecolumn_statoffset = -1;
static int hf_mswsp_ctablecolumn_lenused = -1;
static int hf_mswsp_ctablecolumn_lenoffset = -1;
static int hf_mswsp_cfullpropspec_kind = -1;
static int hf_mswsp_cfullpropspec_propid = -1;
static int hf_mswsp_cfullpropspec_propname = -1;
static int hf_mswsp_cproprestrict_relop = -1;
static int hf_mswsp_ccoercerestrict_value = -1;
static int hf_mswsp_ccontentrestrict_cc = -1;
static int hf_mswsp_ccontentrestrict_phrase = -1;
static int hf_mswsp_ccontentrestrict_method = -1;
static int hf_mswsp_natlangrestrict_cc = -1;
static int hf_mswsp_natlangrestrict_phrase = -1;
static int hf_mswsp_crestrict_ultype = -1;
static int hf_mswsp_crestrict_weight = -1;
static int hf_mswsp_crestrictarray_count = -1;
static int hf_mswsp_crestrictarray_present = -1;
static int hf_mswsp_cnoderestrict_cnode = -1;
static int hf_mswsp_cbasestorvariant_vtype = -1;
static int hf_mswsp_cbasestorvariant_vvalue = -1;
static int hf_mswsp_cbasestorvariant_vdata1 = -1;
static int hf_mswsp_cbasestorvariant_vdata2 = -1;
static int hf_mswsp_cbasestorvariant_num = -1;
static int hf_mswsp_cbasestorvariant_cdims = -1;
static int hf_mswsp_cbasestorvariant_ffeatures = -1;
static int hf_mswsp_cbasestorvariant_cbelements = -1;
static int hf_mswsp_cbasestorvariant_rgsabound = -1;
static int hf_mswsp_cdbcolid_ekind = -1;
static int hf_mswsp_cdbcolid_ulid = -1;
static int hf_mswsp_cdbcolid_vstring = -1;
static int hf_mswsp_cdbprop_id = -1;
static int hf_mswsp_cdbprop_options = -1;
static int hf_mswsp_cdbprop_status = -1;
static int hf_mswsp_cdbpropset_cprops = -1;
static int hf_mswsp_rangeboundry_ultype = -1;
static int hf_mswsp_rangeboundry_labelpresent = -1;
static int hf_mswsp_rangeboundry_cclabel = -1;
static int hf_mswsp_rangeboundry_label = -1;
static int hf_mswsp_crangecategspec_crange = -1;
static int hf_mswsp_ccategspec_type = -1;
static int hf_mswsp_caggregspec_type = -1;
static int hf_mswsp_caggregspec_ccalias = -1;
static int hf_mswsp_caggregspec_alias = -1;
static int hf_mswsp_caggregspec_idcolumn = -1;
static int hf_mswsp_caggregset_count = -1;
static int hf_mswsp_caggregsortkey_order = -1;
static int hf_mswsp_csortaggregset_count = -1;
static int hf_mswsp_cingroupsortaggregset_type = -1;
static int hf_mswsp_cingroupsortaggregsets_count = -1;
static int hf_mswsp_categorizationspec_cmaxres= -1;
static int hf_mswsp_crowsetprops_ulmaxopenrows = -1;
static int hf_mswsp_crowsetprops_ulmemusage = -1;
static int hf_mswsp_crowsetprops_cmaxresults = -1;
static int hf_mswsp_crowsetprops_ccmdtimeout = -1;
static int hf_mswsp_cpidmapper_count = -1;
static int hf_mswsp_ccolumngroup_count = -1;
static int hf_mswsp_ccolumngroup_grouppid = -1;
static int hf_mswsp_ccolumngroup_pid = -1;
static int hf_mswsp_ccolumngrouparray_count = -1;
static int hf_mswsp_int32array_value = -1;
static int hf_mswsp_crowseeknext_cskip = -1;
static int hf_mswsp_crowseekat_bmkoffset = -1;
static int hf_mswsp_crowseekat_skip = -1;
static int hf_mswsp_crowseekat_hregion = -1;
static int hf_mswsp_crowseekatratio_ulnumerator = -1;
static int hf_mswsp_crowseekatratio_uldenominator = -1;
static int hf_mswsp_crowseekatratio_hregion = -1;
static int hf_mswsp_crowseekbybookmark_cbookmarks = -1;
static int hf_mswsp_crowseekbybookmark_maxret = -1;
static int hf_mswsp_crowvariantinfo_count64 = -1;
static int hf_mswsp_arrayvector_address64 = -1;
static int hf_mswsp_crowvariantinfo_count32 = -1;
static int hf_mswsp_arrayvector_address32 = -1;
static int hf_mswsp_rowvariant_item_address64 = -1;
static int hf_mswsp_rowvariant_item_address32 = -1;
static int hf_mswsp_rowvariant_item_value = -1;
static int hf_mswsp_rowvariant_vtype = -1;
static int hf_mswsp_rowvariant_reserved1 = -1;
static int hf_mswsp_rowvariant_reserved2 = -1;
static int hf_mswsp_ctablecolumn_status = -1;
static int hf_mswsp_ctablecolumn_length = -1;
static int hf_mswsp_msg_cpmcreatequery_size = -1;
static int hf_mswsp_msg_cpmcreatequery_ccolumnsetpresent = -1;
static int hf_mswsp_msg_cpmcreatequery_crestrictionpresent = -1;
static int hf_mswsp_msg_cpmcreatequery_csortpresent = -1;
static int hf_mswsp_msg_cpmcreatequery_ccategpresent = -1;
static int hf_mswsp_msg_cpmcreatequery_ccateg_count = -1;
static int hf_mswsp_msg_cpmcreatequery_trueseq = -1;
static int hf_mswsp_msg_cpmcreatequery_workid = -1;
static int hf_mswsp_msg_cpmcreatequery_cursors = -1;
static int hf_mswsp_msg_cpmgetrows_hcursor = -1;
static int hf_mswsp_msg_cpmgetrows_rowstotransfer = -1;
static int hf_mswsp_msg_cpmgetrows_rowwidth = -1;
static int hf_mswsp_msg_cpmgetrows_cbseek = -1;
static int hf_mswsp_msg_cpmgetrows_cbreserved = -1;
static int hf_mswsp_msg_cpmgetrows_cbreadbuffer = -1;
static int hf_mswsp_msg_cpmgetrows_ulclientbase = -1;
static int hf_mswsp_msg_cpmgetrows_fbwdfetch = -1;
static int hf_mswsp_msg_cpmgetrows_etype = -1;
static int hf_mswsp_msg_cpmgetrows_chapt = -1;
static int hf_mswsp_msg_cpmgetrows_crowsreturned = -1;
static int hf_mswsp_msg_cpmratiofinished_hcursor = -1;
static int hf_mswsp_msg_cpmratiofinished_fquick = -1;
static int hf_mswsp_msg_cpmratiofinished_ulnumerator = -1;
static int hf_mswsp_msg_cpmratiofinished_uldenominator = -1;
static int hf_mswsp_msg_cpmratiofinished_crows = -1;
static int hf_mswsp_msg_cpmratiofinished_fnewrows = -1;
static int hf_mswsp_msg_cpmcomparebmk_hcursor = -1;
static int hf_mswsp_msg_cpmcomparebmk_chapt = -1;
static int hf_mswsp_msg_cpmcomparebmk_bmkfirst = -1;
static int hf_mswsp_msg_cpmcomparebmk_bmksecond = -1;
static int hf_mswsp_msg_cpmcomparebmk_dwcomparison = -1;
static int hf_mswsp_msg_cpmgetapproxpos_hcursor = -1;
static int hf_mswsp_msg_cpmgetapproxpos_chapt = -1;
static int hf_mswsp_msg_cpmgetapproxpos_bmk = -1;
static int hf_mswsp_msg_cpmgetapproxpos_numerator = -1;
static int hf_mswsp_msg_cpmgetapproxpos_denominator = -1;
static int hf_mswsp_msg_cpmsetbinding_hcursor = -1;
static int hf_mswsp_msg_cpmsetbinding_cbrow = -1;
static int hf_mswsp_msg_cpmsetbinding_desc = -1;
static int hf_mswsp_msg_cpmsetbinding_dummy = -1;
static int hf_mswsp_msg_cpmsetbinding_ccolumns = -1;
static int hf_mswsp_msg_cpmsetbinding_acolumns = -1;
static int hf_mswsp_msg_cpmsendnotify_watchnotify = -1;
static int hf_mswsp_msg_cpmgetquerystatus_hcursor = -1;
static int hf_mswsp_msg_cpmgetquerystatus_qstatus = -1;
static int hf_mswsp_msg_cpmcistate_cbstruct = -1;
static int hf_mswsp_msg_cpmcistate_cwordlist = -1;
static int hf_mswsp_msg_cpmcistate_cpersistindex = -1;
static int hf_mswsp_msg_cpmcistate_cqueries = -1;
static int hf_mswsp_msg_cpmcistate_cfreshtest = -1;
static int hf_mswsp_msg_cpmcistate_dwmergeprogress = -1;
static int hf_mswsp_msg_cpmcistate_estate = -1;
static int hf_mswsp_msg_cpmcistate_cfiltereddocs = -1;
static int hf_mswsp_msg_cpmcistate_ctotaldocs = -1;
static int hf_mswsp_msg_cpmcistate_cpendingscans = -1;
static int hf_mswsp_msg_cpmcistate_dwindexsize = -1;
static int hf_mswsp_msg_cpmcistate_cuniquekeys = -1;
static int hf_mswsp_msg_cpmcistate_csecqdocuments = -1;
static int hf_mswsp_msg_cpmcistate_dwpropcachesize = -1;
static int hf_mswsp_msg_cpmfetchvalue_wid = -1;
static int hf_mswsp_msg_cpmfetchvalue_cbsofar = -1;
static int hf_mswsp_msg_cpmfetchvalue_cbpropspec = -1;
static int hf_mswsp_msg_cpmfetchvalue_cbchunk = -1;
static int hf_mswsp_msg_cpmfetchvalue_cbvalue = -1;
static int hf_mswsp_msg_cpmfetchvalue_fmoreexists = -1;
static int hf_mswsp_msg_cpmfetchvalue_fvalueexists = -1;
static int hf_mswsp_msg_cpmfetchvalue_vvalue = -1;
static int hf_mswsp_msg_cpmquerystatusex_hcursor = -1;
static int hf_mswsp_msg_cpmquerystatusex_bmk = -1;
static int hf_mswsp_msg_cpmquerystatusex_qstatus = -1;
static int hf_mswsp_msg_cpmquerystatusex_cfiltereddocs = -1;
static int hf_mswsp_msg_cpmquerystatusex_cdocstofilter = -1;
static int hf_mswsp_msg_cpmquerystatusex_dwratiodenom = -1;
static int hf_mswsp_msg_cpmquerystatusex_dwrationumer = -1;
static int hf_mswsp_msg_cpmquerystatusex_irowbmk = -1;
static int hf_mswsp_msg_cpmquerystatusex_crowstotal = -1;
static int hf_mswsp_msg_cpmquerystatusex_maxrank = -1;
static int hf_mswsp_msg_cpmquerystatusex_cresultsfound = -1;
static int hf_mswsp_msg_cpmquerystatusex_whereid = -1;
static int hf_mswsp_msg_cpmrestartposition_hcursor = -1;
static int hf_mswsp_msg_cpmrestartposition_chapt = -1;
static int hf_mswsp_msg_cpmgetrowsetnotify_wid = -1;
static int hf_mswsp_msg_cpmgetrowsetnotify_moreevents = -1;
static int hf_mswsp_msg_cpmgetrowsetnotify_eventtype = -1;
static int hf_mswsp_msg_cpmgetrowsetnotify_rowsetitemstate = -1;
static int hf_mswsp_msg_cpmgetrowsetnotify_changeditemstate = -1;
static int hf_mswsp_msg_cpmgetrowsetnotify_rowsetevent = -1;
static int hf_mswsp_msg_cpmgetrowsetnotify_rowseteventdata1 = -1;
static int hf_mswsp_msg_cpmgetrowsetnotify_rowseteventdata2 = -1;
static int hf_mswsp_msg_cpmfindindices_cwids = -1;
static int hf_mswsp_msg_cpmfindindices_cdepthprev = -1;
static int hf_mswsp_msg_cpmfindindices_cdepthnext = -1;
static int hf_mswsp_msg_cpmsetscopeprioritization_priority = -1;
static int hf_mswsp_msg_cpmsetscopeprioritization_eventfreq = -1;
static int hf_mswsp_msg_cpmsetscopestatisics_dwindexitems = -1;
static int hf_mswsp_msg_cpmsetscopestatisics_dwoutstandingadds = -1;
static int hf_mswsp_msg_cpmsetscopestatisics_dwoutstandingmodifies = -1;

static gint ett_mswsp = -1;
static gint ett_mswsp_hdr = -1;
static gint ett_mswsp_msg = -1;
static gint ett_mswsp_pad = -1;

static gint ett_mswsp_property_restriction = -1;
static gint ett_CRestrictionArray = -1;
static gint ett_CBaseStorageVariant = -1;
static gint ett_CBaseStorageVariant_Vector = -1;
static gint ett_CBaseStorageVariant_Array = -1;
static gint ett_CDbColId = -1;
static gint ett_GUID = -1;
static gint ett_CDbProp = -1;
static gint ett_CDbPropSet = -1;
static gint ett_CDbPropSet_Array = -1;
static gint ett_CRestriction = -1;
static gint ett_CNodeRestriction = -1;
static gint ett_CPropertyRestriction = -1;
static gint ett_CCoercionRestriction = -1;
static gint ett_CContentRestriction = -1;
static gint ett_RANGEBOUNDARY = -1;
static gint ett_CRangeCategSpec = -1;
static gint ett_CCategSpec = -1;
static gint ett_CAggregSpec = -1;
static gint ett_CAggregSet = -1;
static gint ett_CCategorizationSpec = -1;
static gint ett_CAggregSortKey = -1;
static gint ett_CSortAggregSet = -1;
static gint ett_CInGroupSortAggregSet = -1;
static gint ett_CInGroupSortAggregSets = -1;
static gint ett_CRowsetProperties = -1;
static gint ett_CFullPropSpec = -1;
static gint ett_CPidMapper = -1;
static gint ett_CSort = -1;
static gint ett_CSortSet = -1;
static gint ett_CNatLanguageRestriction = -1;
static gint ett_CColumnGroup = -1;
static gint ett_CColumnGroupArray = -1;
static gint ett_LCID = -1;
static gint ett_CTableColumn = -1;
static gint ett_Array = -1;
static gint ett_SeekDescription = -1;
static gint ett_CRowsSeekNext = -1;
static gint ett_CRowsSeekAt = -1;
static gint ett_CRowsSeekAtRatio = -1;
static gint ett_CRowsSeekByBookmark = -1;
static gint ett_GetRowsRow = -1;
static gint ett_GetRowsColumn = -1;
static gint ett_CRowVariant = -1;
static gint ett_CRowVariant_Vector = -1;
static gint ett_mswsp_bool_options = -1;
static gint ett_mswsp_uin32_array = -1;
static gint ett_mswsp_msg_padding = -1;
static gint ett_mswsp_msg_creusewhere = -1;

static struct vtype_data *vType_get_type(guint16 t);

/* converstation related data */
struct rows_data {
	guint32 ulclientbase;
	guint32 cbreserved;
};


struct message_data {
	guint32 fid;
	guint frame;
	guint16 msg_id;
	gboolean is_request;
	int smb_level;
	union {
		struct CPMSetBindingsIn bindingsin;/* CPMBindingIn request */
		struct rows_data rowsin; /*CPMGetRowsIn request*/
		guint32 version; /*CPMConnectIn requst/respose */
	} content;
};

struct mswsp_ct {
	GSList *GSL_message_data;
};

static gint msg_data_find(struct message_data *a, struct message_data *b)
{
	if (a->fid == b->fid
		&& a->frame == b->frame
		&& a->msg_id == b->msg_id
		&& a->smb_level == b->smb_level
		&& a->is_request == b->is_request) {
		return 0;
	}
	return 1;
}
static  smb_fid_info_t *find_fid_info(smb_info_t *si)
{
	smb_fid_info_t *fid_info = NULL;
	smb_transact_info_t *tri = (smb_transact_info_t *)((si->sip && (si->sip->extra_info_type == SMB_EI_TRI)) ? si->sip->extra_info : NULL);
	GSList *iter;
	guint32 fid = 0;

	if (tri == NULL) {
		/* fallback to try search visited RWINFO (for AndX request/response) */
		if (si->sip && (si->sip->extra_info_type == SMB_EI_RWINFO)) {
			fid = si->sip->fid;
		}
	} else {
		fid = tri->fid;
	}


	if (!fid) {
		return NULL;
	}
	for (iter = si->ct->GSL_fid_info; iter; iter = iter->next) {
		smb_fid_info_t *info = (smb_fid_info_t *)iter->data;
		if ((info->tid == si->tid) && (info->fid == fid)) {
			fid_info = info;
			break;
		}
	}
	return fid_info;
}

static gboolean get_fid_and_frame(packet_info *pinfo, guint32 *fid, guint *frame,
							  void *data)
{
	gboolean result = TRUE;
	int *p_smb_level = (int*)p_get_proto_data(wmem_file_scope(), pinfo, proto_mswsp, 0);
	if (!p_smb_level) {
		return FALSE;
	}
	*frame = pinfo->num;
	if (*p_smb_level == SMB1) {
		smb_info_t *si = (smb_info_t*)data;
		smb_fid_info_t *info;
		info = find_fid_info(si);
		if (!info) {
			return FALSE;
		}
		*fid = info->fid;
	} else {
		smb2_info_t *si2 = (smb2_info_t*)data;
		guint32     open_frame = 0, close_frame = 0;
		char       *fid_name = NULL;
		if (si2->saved) {
			dcerpc_fetch_polhnd_data(&si2->saved->policy_hnd, &fid_name, NULL, &open_frame, &close_frame, pinfo->num);
			*fid = open_frame;
		} else {
			result = FALSE;
		}
	}
	return result;
}

static struct message_data *find_or_create_message_data(struct mswsp_ct *conv_data, packet_info *pinfo, guint16 msg_id, gboolean is_request, void *data)
{
	struct message_data to_find;
	struct message_data* msg_data = NULL;
	GSList *result = NULL;
	int *p_smb_level = (int*)p_get_proto_data(wmem_file_scope(), pinfo, proto_mswsp, 0);
	to_find.is_request = is_request;
	to_find.msg_id = msg_id;
	to_find.smb_level = *p_smb_level;
	if (!get_fid_and_frame(pinfo, &to_find.fid, &to_find.frame, data) || !conv_data) {
		return msg_data;
	}
	result = g_slist_find_custom(conv_data->GSL_message_data,
								 &to_find, (GCompareFunc)msg_data_find);
	if (!result) {
		msg_data = (struct message_data *)wmem_alloc(wmem_file_scope(), sizeof(struct message_data));
		*msg_data = to_find;
		conv_data->GSL_message_data = g_slist_prepend(conv_data->GSL_message_data, msg_data);
	} else {
		msg_data = (struct message_data*)result->data;
	}
	return msg_data;
}

static struct mswsp_ct *get_create_converstation_data(packet_info *pinfo)
{
	struct mswsp_ct *ct = NULL;
	conversation_t *conversation;

	conversation = find_or_create_conversation(pinfo);
	if (!conversation) {
		return NULL;
	}
	ct = (struct mswsp_ct*)conversation_get_proto_data(conversation, proto_mswsp);
	if (!ct) {
		ct = wmem_new(wmem_file_scope(), struct mswsp_ct);
		ct->GSL_message_data = NULL;
		conversation_add_proto_data(conversation, proto_mswsp, ct);
	}

	return ct;
}

static struct message_data *
find_matching_request_by_fid(struct mswsp_ct *ct, packet_info *pinfo, guint32 msg, gboolean in, void *private_data)
{
	guint32 fid = 0;
	guint frame = 0;
	GSList *iter;
	int *p_smb_level = (int*)p_get_proto_data(wmem_file_scope(), pinfo, proto_mswsp, 0);

	struct message_data *result = NULL;
	get_fid_and_frame(pinfo, &fid, &frame, private_data);
	for (iter = ct->GSL_message_data; iter; iter = iter->next) {
		struct message_data* data = (struct message_data*)iter->data;
		if (data->frame < frame && data->fid == fid && data->is_request == in
			&& data->msg_id == msg && data->smb_level == *p_smb_level) {
			result = data;
			break;
		}
	}
	return result;
}

static struct CPMSetBindingsIn *
find_binding_msg_data(struct mswsp_ct *ct, packet_info *pinfo, void *private_data)
{
	struct CPMSetBindingsIn *result = NULL;
	struct message_data *data = find_matching_request_by_fid(ct, pinfo, 0xD0, TRUE, private_data);
	if (data) {
		result = &data->content.bindingsin;
	}
	return result;
}

static struct rows_data *
find_rowsin_msg_data(struct mswsp_ct *ct, packet_info *pinfo, void *private_data)
{
	struct rows_data *result = NULL;
	struct message_data *data = find_matching_request_by_fid(ct, pinfo, 0xCC, TRUE, private_data);
	if (data) {
		result = &data->content.rowsin;
	}
	return result;
}

static gboolean is_64bit_mode(struct mswsp_ct *ct, packet_info *pinfo, gboolean *result, void *private_data)
{
	guint32 client_ver = 0;
	guint32 server_ver = 0;
	struct message_data *data = find_matching_request_by_fid(ct, pinfo, 0xC8,
								TRUE, private_data);
	if (data) {
		client_ver = data->content.version;
		data = find_matching_request_by_fid(ct, pinfo, 0xC8, FALSE, private_data);
		if (data) {
			server_ver = data->content.version;
			*result = (server_ver & 0xffff0000) && (client_ver & 0xffff0000);
			return TRUE;
		}
	}
	return FALSE;
}

#define eSequential			0x00000001
#define eLocateable			0x00000003
#define eScrollable			0x00000007
#define eAsynchronous			0x00000008
#define eFirstRows			0x00000080
#define eHoldRows			0x00000200
#define eChaptered			0x00000800
#define eUseCI				0x00001000
#define eDeferTrimming			0x00002000
#define eEnableRowsetEvents		0x00800000
#define eDoNotComputeExpensiveProps	0x00400000

static const value_string cursor_vals[] = {
	{ eSequential, "eSequential" },
	{ eLocateable, "eLocateable" },
	{ eScrollable, "eScrollable" },
	{ 0, NULL }
};



/******************************************************************************/
struct GuidPropertySet {
	e_guid_t guid;
	const char *def;
	const char *desc;
	const value_string *id_map;
};

/* 2.2.1.31.1 */
static const value_string DBPROPSET_FSCIFRMWRK_EXT_IDS[] = {
	{0x02, "DBPROP_CI_CATALOG_NAME"},
	{0x03, "DBPROP_CI_INCLUDE_SCOPES"},
	{0x04, "DBPROP_CI_SCOPE_FLAGS"},
	{0x07, "DBPROP_CI_QUERY_TYPE"},
	{0, NULL}
};

static const value_string DBPROPSET_QUERYEXT_IDS[] = {
	{0x02, "DBPROP_USECONTENTINDEX"},
	{0x03, "DBPROP_DEFERNONINDEXEDTRIMMING"},
	{0x04, "DBPROP_USEEXTENDEDDBTYPES"},
	{0x05, "DBPROP_IGNORENOISEONLYCLAUSES"},
	{0x06, "DBPROP_GENERICOPTIONS_STRING"},
	{0x07, "DBPROP_FIRSTROWS"},
	{0x08, "DBPROP_DEFERCATALOGVERIFICATION"},
	{0x0a, "DBPROP_GENERATEPARSETREE"},
	{0x0c, "DBPROP_FREETEXTANYTERM"},
	{0x0d, "DBPROP_FREETEXTUSESTEMMING"},
	{0x0e, "DBPROP_IGNORESBRI"},
	{0x10, "DBPROP_ENABLEROWSETEVENTS"},
	{0, NULL}
};

static const value_string DBPROPSET_CIFRMWRKCORE_EXT_IDS[] = {
	{0x02, "DBPROP_MACHINE"},
	{0x03, "DBPROP_CLIENT_CLSID"},
	{0, NULL}
};

static const value_string DBPROPSET_MSIDXS_ROWSETEXT_IDS[] = {
	{0x02, "MSIDXSPROP_ROWSETQUERYSTATUS"},
	{0x03, "MSIDXSPROP_COMMAND_LOCALE_STRING"},
	{0x04, "MSIDXSPROP_QUERY_RESTRICTION"},
	{0x05, "MSIDXSPROP_PARSE_TREE"},
	{0x06, "MSIDXSPROP_MAX_RANK"},
	{0x07, "MSIDXSPROP_RESULTS_FOUND"},
	{0, NULL}
};

/* 2.2.5.1 */
static const value_string QueryGuid_IDS[] = {
	{0x02, "RankVector"},
	{0x03, "System.Search.Rank"},
	{0x04, "System.Search.HitCount"},
	{0x05, "System.Search.EntryID"},
	{0x06, "All"},
	{0x8, "System.Search.ReverseFileName"},
	{0x09, "System.ItemURL"},
	{0xa, "System.ContentUrl"},
	{0, NULL}
};

/* 2.2.5.2 */
static const value_string StorageGuid_IDS[] = {
	{0x02, "System.ItemFolderNameDisplay"},
	{0x03, "ClassId"},
	{0x04, "System.ItemTypeText"},
	{0x08, "FileIndex"},
	{0x09, "USN"},
	{0x0a, "System.ItemNameDisplay"},
	{0x0b, "Path"},
	{0x0c, "System.Size"},
	{0x0d, "System.FileAttributes"},
	{0x0e, "System.DateModified"},
	{0x0f, "System.DateCreated"},
	{0x10, "System.DateAccessed"},
	{0x12, "AllocSize"},
	{0x13, "System.Search.Contents"},
	{0x14, "ShortFilename"},
	{0x15, "System.FileFRN"},
	{0x16, "Scope"},
	{0, NULL}
};

static const value_string DocPropSetGuid_IDS[] = {
	{0x02, "System.Title"},
	{0x03, "System.Subject"},
	{0x04, "System.Author"},
	{0x05, "System.Keywords"},
	{0x06, "System.Comment"},
	{0x07, "DocTemplate"},
	{0x08, "System.Document.LastAuthor"},
	{0x09, "System.Document.RevisionNumber"},
	{0x0a, "System.Document.TotalEditTime"},
	{0x0b, "System.Document.DatePrinted"},
	{0x0c, "System.Document.DateCreated"},
	{0x0d, "System.Document.DateSaved"},
	{0x0e, "System.Document.PageCount"},
	{0x0f, "System.Document.WordCount"},
	{0x10, "System.Document.CharacterCount"},
	{0x11, "DocThumbnail"},
	{0x12, "System.ApplicationName"},
	{0, NULL}
};

static const value_string ShellDetails_IDS[] = {
	{ 5, "System.ComputerName"},
	{ 8, "System.ItemPathDisplayNarrow"},
	{ 9, "PercivedType"},
	{11, "System.ItemType"},
	{12, "FileCount"},
	{14, "TotalFileSize"},
	{24, "System.ParsingName"},
	{25, "System.SFGAOFlags"},
	{0, NULL}
};

static const value_string PropSet1_IDS[] = {
	{100, "System.ThumbnailCacheId"},
	{0, NULL}
};

static const value_string PropSet2_IDS[] = {
	{3, "System.Kind"},
	{0, NULL}
};

static const value_string MusicGuid_IDS[] = {
	{0x2, "System.Music.Artist"},
	{0x4, "System.Music.AlbumTitle"},
	{0x5, "System.Media.Year"},
	{0x7, "System.Music.TrackNumber"},
	{0xb, "System.Music.Genre"},
	{0xc, "System.Music.Lyrics"},
	{0xd, "System.Music.AlbumArtist"},
	{0x21, "System.Music.ContentGroupDescription"},
	{0x22, "System.Music.InitialKey"},
	{0x23, "System.Music.BeatsPerMinute"},
	{0x24, "System.Music.Conductor"},
	{0x25, "System.Music.PartOfSet"},
	{0x26, "System.Media.SubTitle"},
	{0x27, "System.Music.Mood"},
	{0x64, "System.Music.AlbumID"},
	{0, NULL}
};

static const value_string PropSet3_IDS[] = {
	{ 2, "System.Message.BccAddress"},
	{ 3, "System.Message.BccName"},
	{ 4, "System.Message.CcAddress"},
	{ 5, "System.Message.CcName"},
	{ 6, "System.ItemFolderPathDisplay"},
	{ 7, "System.ItemPathDisplay"},
	{ 9, "System.Communication.AccountName"},
	{10, "System.IsRead"},
	{11, "System.Importance"},
	{12, "System.FlagStatus"},
	{13, "System.Message.FromAddress"},
	{14, "System.Message.FromName"},
	{15, "System.Message.Store"},
	{16, "System.Message.ToAddress"},
	{17, "System.Message.ToName"},
	{18, "System.Contact.WebPage"},
	{19, "System.Message.DateSent"},
	{20, "System.Message.DateReceived"},
	{21, "System.Message.AttachmentNames"},
	{0, NULL}
};

static const value_string PropSet4_IDS[] = {
	{100, "System.ItemFolderPathDisplayNarrow"},
	{0, NULL}
};

static const value_string PropSet5_IDS[] = {
	{100, "System.Contact.FullName"},
	{0, NULL}
};

static const value_string PropSet6_IDS[] = {
	{100, "System.ItemAuthors"},
	{0, NULL}
};

static const value_string PropSet7_IDS[] = {
	{2, "System.Shell.OmitFromView"},
	{0, NULL}
};

static const value_string PropSet8_IDS[] = {
	{2, "System.Shell.SFGAOFlagsStrings"},
	{3, "System.Link.TargetSFGAOFlagsStrings"},
	{0, NULL}
};

static const value_string PropSet9_IDS[] = {
	{100, "System.ItemDate"},
	{0, NULL}
};

static const value_string PropSet10_IDS[] = {
	{ 5, "System.MIMEType"},
	{ 8, "System.Search.GatherTime"},
	{ 9, "System.Search.AccessCount"},
	{11, "System.Search.LastIndexedTotalTime"},
	{0, NULL}
};

static const value_string PropSet11_IDS[] = {
	{5, "System.Priority"},
	{8, "System.Message.HasAttachments"},
	{0, NULL}
};

static const value_string DocCharacter_IDS[] = {
	{2, "System.Search.Autosummary"},
	{0, NULL}
};

static const value_string PropSet12_IDS[] = {
	{100, "System.IsDeleted"},
	{0, NULL}
};

static const value_string PropSet13_IDS[] = {
	{100, "System.IsAttachment"},
	{0, NULL}
};

static const value_string PropSet14_IDS[] = {
	{100, "System.Message.ConversationID"},
	{101, "System.Message.ConversationIndex"},
	{0, NULL}
};

static const value_string DocPropSetGuid2_IDS[] = {
	{0x02, "System.Category"},
	{0x03, "System.Document.PresentationFormat"},
	{0x04, "System.Document.ByteCount"},
	{0x05, "System.Document.LineCount"},
	{0x06, "System.Document.ParagraphCount"},
	{0x07, "System.Document.SlideCount"},
	{0x08, "DocNoteCount"},
	{0x09, "System.Document.HiddenSlideCount"},
	{0x0D, "DocPartTitles"},
	{0x0E, "System.Document.Manager"},
	{0x0F, "System.Company"},
	{0x1A, "System.ContentType"},
	{0x1B, "System.ContentStatus"},
	{0x1C, "System.Language"},
	{0x1D, "System.Document.Version"},
	{0, NULL}
};

static const value_string SystemContact_IDS[] = {
	{ 6, "System.Contact.JobTitle"},
	{ 7, "System.Contact.OfficeLocation"},
	{20, "System.Contact.HomeTelephone"},
	{25, "System.Contact.PrimaryTelephone"},
	{35, "System.Contact.MobileTelephone"},
	{47, "System.Contact.Birthday"},
	{48, "System.Contact.PrimaryEmailAddress"},
	{65, "System.Contact.HomeAddressCity"},
	{69, "System.Contact.PersonalTitle"},
	{71, "System.Contact.MiddleName"},
	{73, "System.Contact.Suffix"},
	{74, "System.Contact.NickName"},
	{0, NULL}
};

static const value_string PropSet15_IDS[] = {
	{0x64, "System.Calendar.IsOnline"},
	{0,NULL}
};

static const value_string PropSet16_IDS[] = {
	{0x64, "System.Contact.OtherAddressStreet"},
	{0,NULL}
};

static const value_string PropSet17_IDS[] = {
	{0x2, "System.DRM.IsProtected"},
	{0,NULL}
};

static const value_string PropSet18_IDS[] = {
	{0x64, "System.Calendar.OptionalAttendeeNames"},
	{0,NULL}
};

static const value_string PropSet19_IDS[] = {
	{0x64, "System.Calendar.ShowTimeAs"},
	{0,NULL}
};

static const value_string PropSet20_IDS[] = {
	{0x64, "System.ParentalRatingReason"},
	{0,NULL}
};

static const value_string PropSet21_IDS[] = {
	{0x64, "System.Project"},
	{0,NULL}
};

static const value_string PropSet22_IDS[] = {
	{0x64, "System.Contact.OtherAddressCountry"},
	{0,NULL}
};

static const value_string PropSet23_IDS[] = {
	{0x9, "System.Status"},
	{0,NULL}
};

static const value_string PropSet24_IDS[] = {
	{0x64, "System.DateArchived"},
	{0,NULL}
};

static const value_string PropSet25_IDS[] = {
	{0x64, "System.Contact.CarTelephone"},
	{0,NULL}
};

static const value_string PropSet26_IDS[] = {
	{0x64, "System.Calendar.ResponseStatus"},
	{0,NULL}
};

static const value_string PropSet27_IDS[] = {
	{0x64, "System.Task.BillingInformation"},
	{0,NULL}
};

static const value_string PropSet28_IDS[] = {
	{0x64, "System.Media.AverageLevel"},
	{0,NULL}
};

static const value_string PropSet29_IDS[] = {
	{0x64, "System.Contact.SpouseName"},
	{0,NULL}
};

static const value_string PropSet30_IDS[] = {
	{0x64, "System.Document.DocumentID"},
	{0,NULL}
};

static const value_string PropSet31_IDS[] = {
	{0x64, "System.RecordedTV.NetworkAffiliation"},
	{0,NULL}
};

static const value_string PropSet32_IDS[] = {
	{0x64, "System.PriorityText"},
	{0,NULL}
};

static const value_string PropSet33_IDS[] = {
	{0x64, "System.Contact.Children"},
	{0,NULL}
};

static const value_string PropSet34_IDS[] = {
	{0x64, "System.RecordedTV.RecordingTime"},
	{0,NULL}
};

static const value_string PropSet35_IDS[] = {
	{0x64, "System.FlagColorText"},
	{0,NULL}
};

static const value_string PropSet36_IDS[] = {
	{0x64, "System.Contact.OtherAddressPostalCode"},
	{0,NULL}
};

static const value_string PropSet37_IDS[] = {
	{0x64, "System.Photo.SharpnessText"},
	{0,NULL}
};

static const value_string PropSet38_IDS[] = {
	{0x64, "System.Contact.OtherAddress"},
	{0,NULL}
};

static const value_string PropSet40_IDS[] = {
	{0x64, "System.Contact.BusinessAddress"},
	{0,NULL}
};

static const value_string PropSet41_IDS[] = {
	{0x64, "System.IsIncomplete"},
	{0,NULL}
};

static const value_string PropSet42_IDS[] = {
	{0x64, "System.Contact.EmailAddress2"},
	{0,NULL}
};

static const value_string PropSet43_IDS[] = {
	{0x64, "System.Contact.BusinessTelephone"},
	{0,NULL}
};

static const value_string PropSet45_IDS[] = {
	{0x64, "System.Image.CompressionText"},
	{0,NULL}
};

static const value_string PropSet46_IDS[] = {
	{0x64, "System.Contact.HomeAddressState"},
	{0,NULL}
};

static const value_string PropSet47_IDS[] = {
	{0x64, "System.Contact.EmailAddress3"},
	{0,NULL}
};

static const value_string PropSet48_IDS[] = {
	{0x64, "System.Communication.FollowupIconIndex"},
	{0,NULL}
};

static const value_string PropSet49_IDS[] = {
	{0x64, "System.Photo.TagViewAggregate"},
	{0,NULL}
};

static const value_string PropSet50_IDS[] = {
	{0x64, "System.Search.Store"},
	{0,NULL}
};

static const value_string PropSet51_IDS[] = {
	{0x64, "System.FileName"},
	{0,NULL}
};

static const value_string PropSet52_IDS[] = {
	{0x64, "System.Contact.HomeAddressStreet"},
	{0,NULL}
};

static const value_string PropSet53_IDS[] = {
	{0x64, "System.Contact.HomeAddressPostalCode"},
	{0,NULL}
};

static const value_string PropSet54_IDS[] = {
	{0x64, "System.Contact.BusinessHomePage"},
	{0,NULL}
};

static const value_string PropSet55_IDS[] = {
	{0x64, "System.Calendar.RequiredAttendeeNames"},
	{0,NULL}
};

static const value_string PropSet56_IDS[] = {
	{0x64, "System.FlagColor"},
	{0,NULL}
};

static const value_string PropSet57_IDS[] = {
	{0x64, "System.Message.ProofInProgress"},
	{0,NULL}
};

static const value_string PropSet58_IDS[] = {
	{0x64, "System.Contact.PrimaryAddressPostOfficeBox"},
	{0,NULL}
};

static const value_string PropSet59_IDS[] = {
	{0x64, "System.Calendar.IsRecurring"},
	{0,NULL}
};

static const value_string PropSet60_IDS[] = {
	{0x64, "System.Contact.HomeAddress"},
	{0,NULL}
};

static const value_string PropSet61_IDS[] = {
	{0x64, "System.Photo.MaxAperture"},
	{0,NULL}
};

static const value_string PropSet62_IDS[] = {
	{0x64, "System.ItemParticipants"},
	{0,NULL}
};

static const value_string PropSet63_IDS[] = {
	{0x64, "System.Media.DateReleased"},
	{0,NULL}
};

static const value_string PropSet64_IDS[] = {
	{0x64, "System.Journal.Contacts"},
	{0,NULL}
};

static const value_string PropSet65_IDS[] = {
	{0x64, "System.Calendar.Resources"},
	{0,NULL}
};

static const value_string PropSet66_IDS[] = {
	{0x67, "System.Message.MessageClass"},
	{0,NULL}
};

static const value_string PropSet67_IDS[] = {
	{0x9, "System.Rating"},
	{0xb, "System.Copyright"},
	{0xd, "System.Media.ClassPrimaryID"},
	{0xe, "System.Media.ClassSecondaryID"},
	{0xf, "System.Media.DVDID"},
	{0x10, "System.Media.MCDI"},
	{0x11, "System.Media.MetadataContentProvider"},
	{0x12, "System.Media.ContentDistributor"},
	{0x13, "System.Music.Composer"},
	{0x14, "System.Video.Director"},
	{0x15, "System.ParentalRating"},
	{0x16, "System.Media.Producer"},
	{0x17, "System.Media.Writer"},
	{0x18, "System.Media.CollectionGroupID"},
	{0x19, "System.Media.CollectionID"},
	{0x1a, "System.Media.ContentID"},
	{0x1b, "System.Media.CreatorApplication"},
	{0x1c, "System.Media.CreatorApplicationVersion"},
	{0x1e, "System.Media.Publisher"},
	{0x1f, "System.Music.Period"},
	{0x22, "System.Media.UserWebUrl"},
	{0x23, "System.Media.UniqueFileIdentifier"},
	{0x24, "System.Media.EncodedBy"},
	{0x26, "System.Media.ProtectionType"},
	{0x27, "System.Media.ProviderRating"},
	{0x28, "System.Media.ProviderStyle"},
	{0x29, "System.Media.UserNoAutoInfo"},
	{0,NULL}
};

static const value_string PropSet68_IDS[] = {
	{0x64, "System.Calendar.OrganizerName"},
	{0,NULL}
};

static const value_string PropSet69_IDS[] = {
	{0x64, "System.Photo.PeopleNames"},
	{0,NULL}
};

static const value_string PropSet70_IDS[] = {
	{0x3, "System.Media.Duration"},
	{0x4, "System.Audio.EncodingBitrate"},
	{0x5, "System.Audio.SampleRate"},
	{0x6, "System.Audio.SampleSize"},
	{0x7, "System.Audio.ChannelCount"},
	{0,NULL}
};

static const value_string PropSet71_IDS[] = {
	{0x64, "System.FileExtension"},
	{0,NULL}
};

static const value_string PropSet72_IDS[] = {
	{0x103, "System.Image.Compression"},
	{0x10f, "System.Photo.CameraManufacturer"},
	{0x110, "System.Photo.CameraModel"},
	{0x112, "System.Photo.Orientation"},
	{0x131, "System.SoftwareUsed"},
	{0x4748, "System.Photo.Event"},
	{0x4752, "System.DateImported"},
	{0x829a, "System.Photo.ExposureTime"},
	{0x829d, "System.Photo.FNumber"},
	{0x8822, "System.Photo.ExposureProgram"},
	{0x8827, "System.Photo.ISOSpeed"},
	{0x9003, "System.Photo.DateTaken"},
	{0x9201, "System.Photo.ShutterSpeed"},
	{0x9202, "System.Photo.Aperture"},
	{0x9204, "System.Photo.ExposureBias"},
	{0x9206, "System.Photo.SubjectDistance"},
	{0x9207, "System.Photo.MeteringMode"},
	{0x9208, "System.Photo.LightSource"},
	{0x9209, "System.Photo.Flash"},
	{0x920a, "System.Photo.FocalLength"},
	{0,NULL}
};

static const value_string PropSet73_IDS[] = {
	{0x64, "System.Contact.TTYTDDTelephone"},
	{0,NULL}
};

static const value_string PropSet74_IDS[] = {
	{0x64, "System.Photo.PhotometricInterpretationText"},
	{0,NULL}
};

static const value_string PropSet75_IDS[] = {
	{0x64, "System.Calendar.OptionalAttendeeAddresses"},
	{0,NULL}
};

static const value_string PropSet76_IDS[] = {
	{0x64, "System.Calendar.ReminderTime"},
	{0,NULL}
};

static const value_string PropSet77_IDS[] = {
	{0x64, "System.Calendar.RequiredAttendeeAddresses"},
	{0,NULL}
};

static const value_string PropSet78_IDS[] = {
	{0x64, "System.Calendar.OrganizerAddress"},
	{0,NULL}
};

static const value_string PropSet79_IDS[] = {
	{0x2, "System.Link.TargetParsingPath"},
	{0x8, "System.Link.TargetSFGAOFlags"},
	{0,NULL}
};

static const value_string PropSet80_IDS[] = {
	{0x64, "System.Contact.Hobbies"},
	{0,NULL}
};

static const value_string PropSet81_IDS[] = {
	{0x64, "System.Contact.HomeAddressPostOfficeBox"},
	{0,NULL}
};

static const value_string PropSet82_IDS[] = {
	{0x64, "System.Contact.CompanyMainTelephone"},
	{0,NULL}
};

static const value_string PropSet83_IDS[] = {
	{0x64, "System.IsFlagged"},
	{0,NULL}
};

static const value_string PropSet84_IDS[] = {
	{0x64, "System.Contact.FirstName"},
	{0,NULL}
};

static const value_string PropSet85_IDS[] = {
	{0xa, "System.IsEncrypted"},
	{0,NULL}
};

static const value_string PropSet86_IDS[] = {
	{0x64, "System.Calendar.Duration"},
	{0,NULL}
};

static const value_string PropSet87_IDS[] = {
	{0x64, "System.Contact.PrimaryAddressCity"},
	{0,NULL}
};

static const value_string PropSet88_IDS[] = {
	{0x64, "System.Contact.OtherAddressPostOfficeBox"},
	{0,NULL}
};

static const value_string PropSet89_IDS[] = {
	{0x64, "System.ProviderItemID"},
	{0,NULL}
};

static const value_string PropSet90_IDS[] = {
	{0x64, "System.Contact.BusinessAddressCountry"},
	{0,NULL}
};

static const value_string PropSet91_IDS[] = {
	{0x64, "System.Contact.EmailName"},
	{0,NULL}
};

static const value_string PropSet92_IDS[] = {
	{0x64, "System.Photo.FocalLengthInFilm"},
	{0,NULL}
};

static const value_string PropSet93_IDS[] = {
	{0x64, "System.Contact.IMAddress"},
	{0,NULL}
};

static const value_string PropSet94_IDS[] = {
	{0x64, "System.DateAcquired"},
	{0,NULL}
};

static const value_string PropSet95_IDS[] = {
	{0x64, "System.DateCompleted"},
	{0,NULL}
};

static const value_string PropSet96_IDS[] = {
	{0x64, "System.ItemName"},
	{0,NULL}
};

static const value_string PropSet97_IDS[] = {
	{0x64, "System.Contact.PrimaryAddressPostalCode"},
	{0,NULL}
};

static const value_string PropSet99_IDS[] = {
	{0x64, "System.Document.ClientID"},
	{0,NULL}
};

static const value_string PropSet100_IDS[] = {
	{0x64, "System.Photo.ExposureProgramText"},
	{0,NULL}
};

static const value_string PropSet101_IDS[] = {
	{0x64, "System.Note.ColorText"},
	{0,NULL}
};

static const value_string PropSet102_IDS[] = {
	{0x64, "System.Photo.MeteringModeText"},
	{0,NULL}
};

static const value_string PropSet103_IDS[] = {
	{0x2, "System.Link.TargetExtension"},
	{0,NULL}
};

static const value_string PropSet104_IDS[] = {
	{0x64, "System.Contact.BusinessAddressState"},
	{0,NULL}
};

static const value_string PropSet105_IDS[] = {
	{0x64, "System.Photo.OrientationText"},
	{0,NULL}
};

static const value_string PropSet106_IDS[] = {
	{0x64, "System.Contact.Label"},
	{0,NULL}
};

static const value_string PropSet107_IDS[] = {
	{0x64, "System.Calendar.Location"},
	{0,NULL}
};

static const value_string PropSet108_IDS[] = {
	{0x64, "System.Photo.SaturationText"},
	{0,NULL}
};

static const value_string PropSet109_IDS[] = {
	{0x64, "System.Message.ToDoTitle"},
	{0,NULL}
};

static const value_string PropSet110_IDS[] = {
	{0x64, "System.Contact.Anniversary"},
	{0,NULL}
};

static const value_string PropSet111_IDS[] = {
	{0x64, "System.Contact.FileAsName"},
	{0,NULL}
};

static const value_string PropSet112_IDS[] = {
	{0x64, "System.GPS.Date"},
	{0,NULL}
};

static const value_string PropSet113_IDS[] = {
	{0x64, "System.IsFlaggedComplete"},
	{0,NULL}
};

static const value_string PropSet114_IDS[] = {
	{0x2, "System.Contact.JA.CompanyNamePhonetic"},
	{0x3, "System.Contact.JA.FirstNamePhonetic"},
	{0x4, "System.Contact.JA.LastNamePhonetic"},
	{0,NULL}
};

static const value_string PropSet115_IDS[] = {
	{0x64, "System.Communication.SecurityFlags"},
	{0,NULL}
};

static const value_string PropSet116_IDS[] = {
	{0x64, "System.Identity"},
	{0,NULL}
};

static const value_string PropSet117_IDS[] = {
	{0x64, "System.Contact.BusinessAddressPostOfficeBox"},
	{0,NULL}
};

static const value_string PropSet118_IDS[] = {
	{0x64, "System.AcquisitionID"},
	{0,NULL}
};

static const value_string PropSet119_IDS[] = {
	{0x64, "System.Contact.EmailAddresses"},
	{0,NULL}
};

static const value_string PropSet120_IDS[] = {
	{0x64, "System.Communication.TaskStatus"},
	{0,NULL}
};

static const value_string PropSet121_IDS[] = {
	{0x64, "System.Contact.LastName"},
	{0,NULL}
};

static const value_string PropSet122_IDS[] = {
	{0x64, "System.Communication.DateItemExpires"},
	{0,NULL}
};

static const value_string PropSet123_IDS[] = {
	{0x64, "System.ImportanceText"},
	{0,NULL}
};

static const value_string PropSet124_IDS[] = {
	{0x64, "System.Search.ContainerHash"},
	{0,NULL}
};

static const value_string PropSet125_IDS[] = {
	{0x64, "System.Contact.BusinessFaxNumber"},
	{0,NULL}
};

static const value_string PropSet126_IDS[] = {
	{0x2, "System.Link.TargetUrl"},
	{0x1a, "System.IconIndex"},
	{0,NULL}
};

static const value_string PropSet127_IDS[] = {
	{0x64, "System.RecordedTV.StationName"},
	{0,NULL}
};

static const value_string PropSet128_IDS[] = {
	{0x64, "System.Task.Owner"},
	{0,NULL}
};

static const value_string PropSet129_IDS[] = {
	{0x64, "System.Photo.ProgramModeText"},
	{0,NULL}
};

static const value_string PropSet130_IDS[] = {
	{0x64, "System.Contact.PrimaryAddressCountry"},
	{0,NULL}
};

static const value_string PropSet131_IDS[] = {
	{0x64, "System.Note.Color"},
	{0,NULL}
};

static const value_string PropSet132_IDS[] = {
	{0x64, "System.Contact.OtherAddressState"},
	{0,NULL}
};

static const value_string PropSet133_IDS[] = {
	{0x64, "System.Message.AttachmentContents"},
	{0,NULL}
};

static const value_string PropSet134_IDS[] = {
	{0x64, "System.Communication.TaskStatusText"},
	{0,NULL}
};

static const value_string PropSet135_IDS[] = {
	{0x64, "System.Communication.HeaderItem"},
	{0,NULL}
};

static const value_string PropSet136_IDS[] = {
	{0x64, "System.Contact.EmailAddress"},
	{0,NULL}
};

static const value_string PropSet137_IDS[] = {
	{0x64, "System.Contact.Profession"},
	{0,NULL}
};

static const value_string PropSet138_IDS[] = {
	{0x64, "System.Contact.BusinessAddressPostalCode"},
	{0,NULL}
};

static const value_string PropSet139_IDS[] = {
	{0x64, "System.ItemNamePrefix"},
	{0,NULL}
};

static const value_string PropSet140_IDS[] = {
	{0x64, "System.Photo.DigitalZoom"},
	{0,NULL}
};

static const value_string PropSet141_IDS[] = {
	{0x64, "System.SourceItem"},
	{0,NULL}
};

static const value_string PropSet142_IDS[] = {
	{0x64, "System.Photo.WhiteBalance"},
	{0,NULL}
};

static const value_string PropSet143_IDS[] = {
	{0x64, "System.SensitivityText"},
	{0,NULL}
};

static const value_string PropSet144_IDS[] = {
	{0x64, "System.Contact.Gender"},
	{0x65, "System.Contact.GenderValue"},
	{0,NULL}
};

static const value_string PropSet145_IDS[] = {
	{0x64, "System.Contact.OtherAddressCity"},
	{0,NULL}
};

static const value_string PropSet146_IDS[] = {
	{0x64, "System.Music.DisplayArtist"},
	{0,NULL}
};

static const value_string PropSet147_IDS[] = {
	{0x64, "System.Message.SenderAddress"},
	{0,NULL}
};

static const value_string PropSet148_IDS[] = {
	{0x64, "System.Contact.PrimaryAddressState"},
	{0,NULL}
};

static const value_string PropSet149_IDS[] = {
	{0x64, "System.Journal.EntryType"},
	{0,NULL}
};

static const value_string PropSet150_IDS[] = {
	{0x64, "System.Contact.BusinessAddressStreet"},
	{0,NULL}
};

static const value_string PropSet151_IDS[] = {
	{0x4, "System.FileOwner"},
	{0,NULL}
};

static const value_string PropSet152_IDS[] = {
	{0x64, "System.Contact.HomeAddressCountry"},
	{0,NULL}
};

static const value_string PropSet153_IDS[] = {
	{0x64, "System.Task.CompletionStatus"},
	{0,NULL}
};

static const value_string PropSet154_IDS[] = {
	{0x10, "System.Software.DateLastUsed"},
	{0,NULL}
};

static const value_string PropSet155_IDS[] = {
	{0x64, "System.Contact.Department"},
	{0,NULL}
};

static const value_string PropSet156_IDS[] = {
	{0x64, "System.Calendar.ShowTimeAsText"},
	{0,NULL}
};

static const value_string PropSet157_IDS[] = {
	{0x64, "System.Sensitivity"},
	{0,NULL}
};

static const value_string PropSet158_IDS[] = {
	{0x64, "System.RecordedTV.OriginalBroadcastDate"},
	{0,NULL}
};

static const value_string PropSet159_IDS[] = {
	{0x64, "System.Music.IsCompilation"},
	{0,NULL}
};

static const value_string PropSet160_IDS[] = {
	{0x64, "System.DueDate"},
	{0,NULL}
};

static const value_string PropSet161_IDS[] = {
	{0x3, "System.FileDescription"},
	{0x6, "System.OriginalFileName"},
	{0x7, "System.Software.ProductName"},
	{0x8, "System.Software.ProductVersion"},
	{0,NULL}
};

static const value_string PropSet162_IDS[] = {
	{0x64, "System.MileageInformation"},
	{0,NULL}
};

static const value_string PropSet163_IDS[] = {
	{0x2, "System.RecordedTV.EpisodeName"},
	{0x3, "System.RecordedTV.ProgramDescription"},
	{0x5, "System.RecordedTV.StationCallSign"},
	{0x7, "System.RecordedTV.ChannelNumber"},
	{0xc, "System.RecordedTV.IsClosedCaptioningAvailable"},
	{0xd, "System.RecordedTV.IsRepeatBroadcast"},
	{0xe, "System.RecordedTV.IsSAP"},
	{0xf, "System.RecordedTV.DateContentExpires"},
	{0x10, "System.RecordedTV.IsATSCContent"},
	{0x11, "System.RecordedTV.IsDTVContent"},
	{0x12, "System.RecordedTV.IsHDContent"},
	{0,NULL}
};

static const value_string PropSet164_IDS[] = {
	{0x64, "System.Audio.PeakValue"},
	{0,NULL}
};

static const value_string PropSet165_IDS[] = {
	{0x64, "System.Contact.TelexNumber"},
	{0,NULL}
};

static const value_string PropSet166_IDS[] = {
	{0x64, "System.Message.SenderName"},
	{0,NULL}
};

static const value_string PropSet167_IDS[] = {
	{0x64, "System.Message.Flags"},
	{0,NULL}
};

static const value_string PropSet168_IDS[] = {
	{0x64, "System.IsFolder"},
	{0,NULL}
};

static const value_string PropSet169_IDS[] = {
	{0x64, "System.Contact.AssistantTelephone"},
	{0,NULL}
};

static const value_string PropSet170_IDS[] = {
	{0x64, "System.KindText"},
	{0,NULL}
};

static const value_string PropSet171_IDS[] = {
	{0x64, "System.Photo.ContrastText"},
	{0,NULL}
};

static const value_string PropSet172_IDS[] = {
	{0x3, "System.Image.HorizontalSize"},
	{0x4, "System.Image.VerticalSize"},
	{0x5, "System.Image.HorizontalResolution"},
	{0x6, "System.Image.VerticalResolution"},
	{0x7, "System.Image.BitDepth"},
	{0xc, "System.Media.FrameCount"},
	{0xd, "System.Image.Dimensions"},
	{0,NULL}
};

static const value_string PropSet173_IDS[] = {
	{0x64, "System.Message.IsFwdOrReply"},
	{0,NULL}
};

static const value_string PropSet174_IDS[] = {
	{0x64, "System.Photo.WhiteBalanceText"},
	{0,NULL}
};

static const value_string PropSet175_IDS[] = {
	{0x64, "System.Photo.GainControlText"},
	{0,NULL}
};

static const value_string PropSet176_IDS[] = {
	{0x64, "System.Communication.PolicyTag"},
	{0,NULL}
};

static const value_string PropSet177_IDS[] = {
	{0x64, "System.Contact.HomeFaxNumber"},
	{0,NULL}
};

static const value_string PropSet178_IDS[] = {
	{0x64, "System.FlagStatusText"},
	{0,NULL}
};

static const value_string PropSet179_IDS[] = {
	{0x64, "System.Contact.AssistantName"},
	{0,NULL}
};

static const value_string PropSet180_IDS[] = {
	{0x64, "System.Message.ToDoFlags"},
	{0,NULL}
};

static const value_string PropSet181_IDS[] = {
	{0x64, "System.RatingText"},
	{0,NULL}
};

static const value_string PropSet182_IDS[] = {
	{0x64, "System.Document.Contributor"},
	{0,NULL}
};

static const value_string PropSet183_IDS[] = {
	{0x64, "System.Contact.CallbackTelephone"},
	{0,NULL}
};

static const value_string PropSet184_IDS[] = {
	{0x64, "System.EndDate"},
	{0,NULL}
};

static const value_string PropSet185_IDS[] = {
	{0x64, "System.Media.DateEncoded"},
	{0,NULL}
};

static const value_string PropSet186_IDS[] = {
	{0x64, "System.Photo.FlashText"},
	{0,NULL}
};

static const value_string PropSet187_IDS[] = {
	{0x64, "System.Photo.FlashFired"},
	{0,NULL}
};

static const value_string PropSet188_IDS[] = {
	{0x64, "System.Document.Division"},
	{0,NULL}
};

static const value_string PropSet189_IDS[] = {
	{0x64, "System.Contact.PagerTelephone"},
	{0,NULL}
};

static const value_string PropSet190_IDS[] = {
	{0x64, "System.Contact.BusinessAddressCity"},
	{0,NULL}
};

static const value_string PropSet191_IDS[] = {
	{0x64, "System.Media.SubscriptionContentId"},
	{0,NULL}
};

static const value_string PropSet192_IDS[] = {
	{0x64, "System.Contact.PrimaryAddressStreet"},
	{0,NULL}
};

static const value_string PropSet193_IDS[] = {
	{0x64, "System.StartDate"},
	{0,NULL}
};

static const value_string PropSet194_IDS[] = {
	{0x2, "System.Video.StreamName"},
	{0x3, "System.Video.FrameWidth"},
	{0x4, "System.Video.FrameHeight"},
	{0x6, "System.Video.FrameRate"},
	{0x8, "System.Video.EncodingBitrate"},
	{0x9, "System.Video.SampleSize"},
	{0xa, "System.Video.Compression"},
	{0x2a, "System.Video.HorizontalAspectRatio"},
	{0x2b, "System.Video.TotalBitrate"},
	{0x2c, "System.Video.FourCC"},
	{0x2d, "System.Video.VerticalAspectRatio"},
	{0,NULL}
};

static const value_string PropSet195_IDS[] = {
	{0x64, "System.Contact.MailingAddress"},
	{0,NULL}
};

static struct GuidPropertySet GuidPropertySet[] = {
	{	{0xa9bd1526, 0x6a80, 0x11d0, {0x8c, 0x9d, 0x00, 0x20, 0xaf, 0x1d, 0x74, 0x0e}},
		"DBPROPSET_FSCIFRMWRK_EXT", "File system content index framework",
		DBPROPSET_FSCIFRMWRK_EXT_IDS
	},
	{	{0xa7ac77ed, 0xf8d7, 0x11ce, {0xa7, 0x98, 0x00, 0x20, 0xf8, 0x00, 0x80, 0x25}},
		"DBPROPSET_QUERYEXT", "Query extension",
		DBPROPSET_QUERYEXT_IDS
	},
	{	{0xafafaca5, 0xb5d1, 0x11d0, {0x8c, 0x62, 0x00, 0xc0, 0x4f, 0xc2, 0xdb, 0x8d}},
		"DBPROPSET_CIFRMWRKCORE_EXT", "Content index framework core",
		DBPROPSET_CIFRMWRKCORE_EXT_IDS
	},
	{	{0xAA6EE6B0, 0xE828, 0x11D0, {0xB2, 0x3E, 0x00, 0xAA, 0x00, 0x47, 0xFC, 0x01}},
		"DBPROPSET_MSIDXS_ROWSETEXT", "???",
		DBPROPSET_MSIDXS_ROWSETEXT_IDS
	},
	{	{0xB725F130, 0x47ef, 0x101a, {0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC}},
		"Storage", "Storage Property Set",
		StorageGuid_IDS
	},
	{	{0xF29F85E0, 0x4FF9, 0x1068, {0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9}},
		"Document", "Document Property Set",
		DocPropSetGuid_IDS
	},
	{	{0x49691C90, 0x7E17, 0x101A, {0xA9, 0x1C, 0x08, 0x00, 0x2B, 0x2E, 0xCD, 0xA9}},
		"Query", "Query Property Set",
		QueryGuid_IDS
	},
	{	{0x28636AA6, 0x953D, 0x11D2, {0xB5, 0xD6, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0xD0}},
		"ShellDetails", "Shell Details Property Set",
		ShellDetails_IDS
	},
	{	{0x446D16B1, 0x8DAD, 0x4870, {0xA7, 0x48, 0x40, 0x2E, 0xA4, 0x3D, 0x78, 0x8C}},
		"???", "Unspecified Property Set",
		PropSet1_IDS
	},
	{	{0x1E3EE840, 0xBC2B, 0x476C, {0x82, 0x37, 0x2A, 0xCD, 0x1A, 0x83, 0x9B, 0x22}},
		"???", "Unspecified Property Set",
		PropSet2_IDS
	},
	{	{0x56A3372E, 0xCE9C, 0x11d2, {0x9F, 0x0E, 0x00, 0x60, 0x97, 0xC6, 0x86, 0xF6}},
		"Music", "Music Property Set",
		MusicGuid_IDS
	},
	{	{0xE3E0584C, 0xB788, 0x4A5A, {0xBB, 0x20, 0x7F, 0x5A, 0x44, 0xC9, 0xAC, 0xDD}},
		"???", "Unspecified Property Set",
		PropSet3_IDS
	},
	{	{0xDABD30ED, 0x0043, 0x4789, {0xA7, 0xF8, 0xD0, 0x13, 0xA4, 0x73, 0x66, 0x22}},
		"???", "Unspecified Property Set",
		PropSet4_IDS
	},
	{	{0x635E9051, 0x50A5, 0x4BA2, {0xB9, 0xDB, 0x4E, 0xD0, 0x56, 0xC7, 0x72, 0x96}},
		"???", "Unspecified Property Set",
		PropSet5_IDS
	},
	{	{0xD0A04F0A, 0x462A, 0x48A4, {0xBB, 0x2F, 0x37, 0x06, 0xE8, 0x8D, 0xBD, 0x7D}},
		"???", "Unspecified Property Set",
		PropSet6_IDS
	},
	{	{0xDE35258C, 0xC695, 0x4CBC, {0xB9, 0x82, 0x38, 0xB0, 0xAD, 0x24, 0xCE, 0xD0}},
		"???", "Unspecified Property Set",
		PropSet7_IDS
	},
	{	{0xD6942081, 0xD53B, 0x443D, {0xAD, 0x47, 0x5E, 0x05, 0x9D, 0x9C, 0xD2, 0x7A}},
		"???", "Unspecified Property Set",
		PropSet8_IDS
	},
	{	{0xF7DB74B4, 0x4287, 0x4103, {0xAF, 0xBA, 0xF1, 0xB1, 0x3D, 0xCD, 0x75, 0xCF}},
		"???", "Unspecified Property Set",
		PropSet9_IDS
	},
	{	{0x0B63E350, 0x9CCC, 0x11d0, {0xBC, 0xDB, 0x00, 0x80, 0x5F, 0xCC, 0xCE, 0x04}},
		"???", "Unspecified Property Set",
		PropSet10_IDS
	},
	{	{0x9C1FCF74, 0x2D97, 0x41BA, {0xB4, 0xAE, 0xCB, 0x2E, 0x36, 0x61, 0xA6, 0xE4}},
		"???", "Unspecified Property Set",
		PropSet11_IDS
	},
	{	{0x560C36C0, 0x503A, 0x11CF, {0xBA, 0xA1, 0x00, 0x00, 0x4C, 0x75, 0x2A, 0x9A}},
		"DocCharacter", "Document characterization Property Set",
		DocCharacter_IDS
	},
	{	{0x5CDA5FC8, 0x33EE, 0x4FF3, {0x90, 0x94, 0xAE, 0x7B, 0xD8, 0x86, 0x8C, 0x4D}},
		"???", "Unspecified Property Set",
		PropSet12_IDS
	},
	{	{0xF23F425C, 0x71A1, 0x4FA8, {0x92, 0x2F, 0x67, 0x8E, 0xA4, 0xA6, 0x04, 0x08}},
		"???", "Unspecified Property Set",
		PropSet13_IDS
	},
	{	{0xDC8F80BD, 0xAF1E, 0x4289, {0x85, 0xB6, 0x3D, 0xFC, 0x1B, 0x49, 0x39, 0x92}},
		"???", "Unspecified Property Set",
		PropSet14_IDS
	},
	{	{0xD5CDD502, 0x2E9C, 0x101B, {0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE}},
		"DocPropSet2", "Document Property Set 2",
		DocPropSetGuid2_IDS
	},
	{	{0x176DC63C, 0x2688, 0x4E89, {0x81, 0x43, 0xA3, 0x47, 0x80, 0x0F, 0x25, 0xE9}},
		"System.Contact", "System Contact Property Set",
		SystemContact_IDS
	},
	{	{0xBFEE9149, 0xE3E2, 0x49A7, {0xA8, 0x62, 0xC0, 0x59, 0x88, 0x14, 0x5C, 0xEC}},
		"???","Unspecified Property Set",
		PropSet15_IDS
	},
	{	{0xFF962609, 0xB7D6, 0x4999, {0x86, 0x2D, 0x95, 0x18, 0x0D, 0x52, 0x9A, 0xEA}},
		"???","Unspecified Property Set",
		PropSet16_IDS
	},
	{	{0xAEAC19E4, 0x89AE, 0x4508, {0xB9, 0xB7, 0xBB, 0x86, 0x7A, 0xBE, 0xE2, 0xED}},
		"???","Unspecified Property Set",
		PropSet17_IDS
	},
	{	{0x09429607, 0x582D, 0x437F, {0x84, 0xC3, 0xDE, 0x93, 0xA2, 0xB2, 0x4C, 0x3C}},
		"???","Unspecified Property Set",
		PropSet18_IDS
	},
	{	{0x5BF396D4, 0x5EB2, 0x466F, {0xBD, 0xE9, 0x2F, 0xB3, 0xF2, 0x36, 0x1D, 0x6E}},
		"???","Unspecified Property Set",
		PropSet19_IDS
	},
	{	{0x10984E0A, 0xF9F2, 0x4321, {0xB7, 0xEF, 0xBA, 0xF1, 0x95, 0xAF, 0x43, 0x19}},
		"???","Unspecified Property Set",
		PropSet20_IDS
	},
	{	{0x39A7F922, 0x477C, 0x48DE, {0x8B, 0xC8, 0xB2, 0x84, 0x41, 0xE3, 0x42, 0xE3}},
		"???","Unspecified Property Set",
		PropSet21_IDS
	},
	{	{0x8F167568, 0x0AAE, 0x4322, {0x8E, 0xD9, 0x60, 0x55, 0xB7, 0xB0, 0xE3, 0x98}},
		"???","Unspecified Property Set",
		PropSet22_IDS
	},
	{	{0x000214A1, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
		"???","Unspecified Property Set",
		PropSet23_IDS
	},
	{	{0x43F8D7B7, 0xA444, 0x4F87, {0x93, 0x83, 0x52, 0x27, 0x1C, 0x9B, 0x91, 0x5C}},
		"???","Unspecified Property Set",
		PropSet24_IDS
	},
	{	{0x8FDC6DEA, 0xB929, 0x412B, {0xBA, 0x90, 0x39, 0x7A, 0x25, 0x74, 0x65, 0xFE}},
		"???","Unspecified Property Set",
		PropSet25_IDS
	},
	{	{0x188C1F91, 0x3C40, 0x4132, {0x9E, 0xC5, 0xD8, 0xB0, 0x3B, 0x72, 0xA8, 0xA2}},
		"???","Unspecified Property Set",
		PropSet26_IDS
	},
	{	{0xD37D52C6, 0x261C, 0x4303, {0x82, 0xB3, 0x08, 0xB9, 0x26, 0xAC, 0x6F, 0x12}},
		"???","Unspecified Property Set",
		PropSet27_IDS
	},
	{	{0x09EDD5B6, 0xB301, 0x43C5, {0x99, 0x90, 0xD0, 0x03, 0x02, 0xEF, 0xFD, 0x46}},
		"???","Unspecified Property Set",
		PropSet28_IDS
	},
	{	{0x9D2408B6, 0x3167, 0x422B, {0x82, 0xB0, 0xF5, 0x83, 0xB7, 0xA7, 0xCF, 0xE3}},
		"???","Unspecified Property Set",
		PropSet29_IDS
	},
	{	{0xE08805C8, 0xE395, 0x40DF, {0x80, 0xD2, 0x54, 0xF0, 0xD6, 0xC4, 0x31, 0x54}},
		"???","Unspecified Property Set",
		PropSet30_IDS
	},
	{	{0x2C53C813, 0xFB63, 0x4E22, {0xA1, 0xAB, 0x0B, 0x33, 0x1C, 0xA1, 0xE2, 0x73}},
		"???","Unspecified Property Set",
		PropSet31_IDS
	},
	{	{0xD98BE98B, 0xB86B, 0x4095, {0xBF, 0x52, 0x9D, 0x23, 0xB2, 0xE0, 0xA7, 0x52}},
		"???","Unspecified Property Set",
		PropSet32_IDS
	},
	{	{0xD4729704, 0x8EF1, 0x43EF, {0x90, 0x24, 0x2B, 0xD3, 0x81, 0x18, 0x7F, 0xD5}},
		"???","Unspecified Property Set",
		PropSet33_IDS
	},
	{	{0xA5477F61, 0x7A82, 0x4ECA, {0x9D, 0xDE, 0x98, 0xB6, 0x9B, 0x24, 0x79, 0xB3}},
		"???","Unspecified Property Set",
		PropSet34_IDS
	},
	{	{0x45EAE747, 0x8E2A, 0x40AE, {0x8C, 0xBF, 0xCA, 0x52, 0xAB, 0xA6, 0x15, 0x2A}},
		"???","Unspecified Property Set",
		PropSet35_IDS
	},
	{	{0x95C656C1, 0x2ABF, 0x4148, {0x9E, 0xD3, 0x9E, 0xC6, 0x02, 0xE3, 0xB7, 0xCD}},
		"???","Unspecified Property Set",
		PropSet36_IDS
	},
	{	{0x51EC3F47, 0xDD50, 0x421D, {0x87, 0x69, 0x33, 0x4F, 0x50, 0x42, 0x4B, 0x1E}},
		"???","Unspecified Property Set",
		PropSet37_IDS
	},
	{	{0x508161FA, 0x313B, 0x43D5, {0x83, 0xA1, 0xC1, 0xAC, 0xCF, 0x68, 0x62, 0x2C}},
		"???","Unspecified Property Set",
		PropSet38_IDS
	},
	{	{0x730FB6DD, 0xCF7C, 0x426B, {0xA0, 0x3F, 0xBD, 0x16, 0x6C, 0xC9, 0xEE, 0x24}},
		"???","Unspecified Property Set",
		PropSet40_IDS
	},
	{	{0x346C8BD1, 0x2E6A, 0x4C45, {0x89, 0xA4, 0x61, 0xB7, 0x8E, 0x8E, 0x70, 0x0F}},
		"???","Unspecified Property Set",
		PropSet41_IDS
	},
	{	{0x38965063, 0xEDC8, 0x4268, {0x84, 0x91, 0xB7, 0x72, 0x31, 0x72, 0xCF, 0x29}},
		"???","Unspecified Property Set",
		PropSet42_IDS
	},
	{	{0x6A15E5A0, 0x0A1E, 0x4CD7, {0xBB, 0x8C, 0xD2, 0xF1, 0xB0, 0xC9, 0x29, 0xBC}},
		"???","Unspecified Property Set",
		PropSet43_IDS
	},
	{	{0x3F08E66F, 0x2F44, 0x4BB9, {0xA6, 0x82, 0xAC, 0x35, 0xD2, 0x56, 0x23, 0x22}},
		"???","Unspecified Property Set",
		PropSet45_IDS
	},
	{	{0xC89A23D0, 0x7D6D, 0x4EB8, {0x87, 0xD4, 0x77, 0x6A, 0x82, 0xD4, 0x93, 0xE5}},
		"???","Unspecified Property Set",
		PropSet46_IDS
	},
	{	{0x644D37B4, 0xE1B3, 0x4BAD, {0xB0, 0x99, 0x7E, 0x7C, 0x04, 0x96, 0x6A, 0xCA}},
		"???","Unspecified Property Set",
		PropSet47_IDS
	},
	{	{0x83A6347E, 0x6FE4, 0x4F40, {0xBA, 0x9C, 0xC4, 0x86, 0x52, 0x40, 0xD1, 0xF4}},
		"???","Unspecified Property Set",
		PropSet48_IDS
	},
	{	{0xB812F15D, 0xC2D8, 0x4BBF, {0xBA, 0xCD, 0x79, 0x74, 0x43, 0x46, 0x11, 0x3F}},
		"???","Unspecified Property Set",
		PropSet49_IDS
	},
	{	{0xA06992B3, 0x8CAF, 0x4ED7, {0xA5, 0x47, 0xB2, 0x59, 0xE3, 0x2A, 0xC9, 0xFC}},
		"???","Unspecified Property Set",
		PropSet50_IDS
	},
	{	{0x41CF5AE0, 0xF75A, 0x4806, {0xBD, 0x87, 0x59, 0xC7, 0xD9, 0x24, 0x8E, 0xB9}},
		"???","Unspecified Property Set",
		PropSet51_IDS
	},
	{	{0x0ADEF160, 0xDB3F, 0x4308, {0x9A, 0x21, 0x06, 0x23, 0x7B, 0x16, 0xFA, 0x2A}},
		"???","Unspecified Property Set",
		PropSet52_IDS
	},
	{	{0x8AFCC170, 0x8A46, 0x4B53, {0x9E, 0xEE, 0x90, 0xBA, 0xE7, 0x15, 0x1E, 0x62}},
		"???","Unspecified Property Set",
		PropSet53_IDS
	},
	{	{0x56310920, 0x2491, 0x4919, {0x99, 0xCE, 0xEA, 0xDB, 0x06, 0xFA, 0xFD, 0xB2}},
		"???","Unspecified Property Set",
		PropSet54_IDS
	},
	{	{0xB33AF30B, 0xF552, 0x4584, {0x93, 0x6C, 0xCB, 0x93, 0xE5, 0xCD, 0xA2, 0x9F}},
		"???","Unspecified Property Set",
		PropSet55_IDS
	},
	{	{0x67DF94DE, 0x0CA7, 0x4D6F, {0xB7, 0x92, 0x05, 0x3A, 0x3E, 0x4F, 0x03, 0xCF}},
		"???","Unspecified Property Set",
		PropSet56_IDS
	},
	{	{0x9098F33C, 0x9A7D, 0x48A8, {0x8D, 0xE5, 0x2E, 0x12, 0x27, 0xA6, 0x4E, 0x91}},
		"???","Unspecified Property Set",
		PropSet57_IDS
	},
	{	{0xDE5EF3C7, 0x46E1, 0x484E, {0x99, 0x99, 0x62, 0xC5, 0x30, 0x83, 0x94, 0xC1}},
		"???","Unspecified Property Set",
		PropSet58_IDS
	},
	{	{0x315B9C8D, 0x80A9, 0x4EF9, {0xAE, 0x16, 0x8E, 0x74, 0x6D, 0xA5, 0x1D, 0x70}},
		"???","Unspecified Property Set",
		PropSet59_IDS
	},
	{	{0x98F98354, 0x617A, 0x46B8, {0x85, 0x60, 0x5B, 0x1B, 0x64, 0xBF, 0x1F, 0x89}},
		"???","Unspecified Property Set",
		PropSet60_IDS
	},
	{	{0x08F6D7C2, 0xE3F2, 0x44FC, {0xAF, 0x1E, 0x5A, 0xA5, 0xC8, 0x1A, 0x2D, 0x3E}},
		"???","Unspecified Property Set",
		PropSet61_IDS
	},
	{	{0xD4D0AA16, 0x9948, 0x41A4, {0xAA, 0x85, 0xD9, 0x7F, 0xF9, 0x64, 0x69, 0x93}},
		"???","Unspecified Property Set",
		PropSet62_IDS
	},
	{	{0xDE41CC29, 0x6971, 0x4290, {0xB4, 0x72, 0xF5, 0x9F, 0x2E, 0x2F, 0x31, 0xE2}},
		"???","Unspecified Property Set",
		PropSet63_IDS
	},
	{	{0xDEA7C82C, 0x1D89, 0x4A66, {0x94, 0x27, 0xA4, 0xE3, 0xDE, 0xBA, 0xBC, 0xB1}},
		"???","Unspecified Property Set",
		PropSet64_IDS
	},
	{	{0x00F58A38, 0xC54B, 0x4C40, {0x86, 0x96, 0x97, 0x23, 0x59, 0x80, 0xEA, 0xE1}},
		"???","Unspecified Property Set",
		PropSet65_IDS
	},
	{	{0xCD9ED458, 0x08CE, 0x418F, {0xA7, 0x0E, 0xF9, 0x12, 0xC7, 0xBB, 0x9C, 0x5C}},
		"???","Unspecified Property Set",
		PropSet66_IDS
	},
	{	{0x64440492, 0x4C8B, 0x11D1, {0x8B, 0x70, 0x08, 0x00, 0x36, 0xB1, 0x1A, 0x03}},
		"???","Unspecified Property Set",
		PropSet67_IDS
	},
	{	{0xAAA660F9, 0x9865, 0x458E, {0xB4, 0x84, 0x01, 0xBC, 0x7F, 0xE3, 0x97, 0x3E}},
		"???","Unspecified Property Set",
		PropSet68_IDS
	},
	{	{0xE8309B6E, 0x084C, 0x49B4, {0xB1, 0xFC, 0x90, 0xA8, 0x03, 0x31, 0xB6, 0x38}},
		"???","Unspecified Property Set",
		PropSet69_IDS
	},
	{	{0x64440490, 0x4C8B, 0x11D1, {0x8B, 0x70, 0x08, 0x00, 0x36, 0xB1, 0x1A, 0x03}},
		"???","Unspecified Property Set",
		PropSet70_IDS
	},
	{	{0xE4F10A3C, 0x49E6, 0x405D, {0x82, 0x88, 0xA2, 0x3B, 0xD4, 0xEE, 0xAA, 0x6C}},
		"???","Unspecified Property Set",
		PropSet71_IDS
	},
	{	{0x14B81DA1, 0x0135, 0x4D31, {0x96, 0xD9, 0x6C, 0xBF, 0xC9, 0x67, 0x1A, 0x99}},
		"???","Unspecified Property Set",
		PropSet72_IDS
	},
	{	{0xAAF16BAC, 0x2B55, 0x45E6, {0x9F, 0x6D, 0x41, 0x5E, 0xB9, 0x49, 0x10, 0xDF}},
		"???","Unspecified Property Set",
		PropSet73_IDS
	},
	{	{0x821437D6, 0x9EAB, 0x4765, {0xA5, 0x89, 0x3B, 0x1C, 0xBB, 0xD2, 0x2A, 0x61}},
		"???","Unspecified Property Set",
		PropSet74_IDS
	},
	{	{0xD55BAE5A, 0x3892, 0x417A, {0xA6, 0x49, 0xC6, 0xAC, 0x5A, 0xAA, 0xEA, 0xB3}},
		"???","Unspecified Property Set",
		PropSet75_IDS
	},
	{	{0x72FC5BA4, 0x24F9, 0x4011, {0x9F, 0x3F, 0xAD, 0xD2, 0x7A, 0xFA, 0xD8, 0x18}},
		"???","Unspecified Property Set",
		PropSet76_IDS
	},
	{	{0x0BA7D6C3, 0x568D, 0x4159, {0xAB, 0x91, 0x78, 0x1A, 0x91, 0xFB, 0x71, 0xE5}},
		"???","Unspecified Property Set",
		PropSet77_IDS
	},
	{	{0x744C8242, 0x4DF5, 0x456C, {0xAB, 0x9E, 0x01, 0x4E, 0xFB, 0x90, 0x21, 0xE3}},
		"???","Unspecified Property Set",
		PropSet78_IDS
	},
	{	{0xB9B4B3FC, 0x2B51, 0x4A42, {0xB5, 0xD8, 0x32, 0x41, 0x46, 0xAF, 0xCF, 0x25}},
		"???","Unspecified Property Set",
		PropSet79_IDS
	},
	{	{0x5DC2253F, 0x5E11, 0x4ADF, {0x9C, 0xFE, 0x91, 0x0D, 0xD0, 0x1E, 0x3E, 0x70}},
		"???","Unspecified Property Set",
		PropSet80_IDS
	},
	{	{0x7B9F6399, 0x0A3F, 0x4B12, {0x89, 0xBD, 0x4A, 0xDC, 0x51, 0xC9, 0x18, 0xAF}},
		"???","Unspecified Property Set",
		PropSet81_IDS
	},
	{	{0x8589E481, 0x6040, 0x473D, {0xB1, 0x71, 0x7F, 0xA8, 0x9C, 0x27, 0x08, 0xED}},
		"???","Unspecified Property Set",
		PropSet82_IDS
	},
	{	{0x5DA84765, 0xE3FF, 0x4278, {0x86, 0xB0, 0xA2, 0x79, 0x67, 0xFB, 0xDD, 0x03}},
		"???","Unspecified Property Set",
		PropSet83_IDS
	},
	{	{0x14977844, 0x6B49, 0x4AAD, {0xA7, 0x14, 0xA4, 0x51, 0x3B, 0xF6, 0x04, 0x60}},
		"???","Unspecified Property Set",
		PropSet84_IDS
	},
	{	{0x90E5E14E, 0x648B, 0x4826, {0xB2, 0xAA, 0xAC, 0xAF, 0x79, 0x0E, 0x35, 0x13}},
		"???","Unspecified Property Set",
		PropSet85_IDS
	},
	{	{0x293CA35A, 0x09AA, 0x4DD2, {0xB1, 0x80, 0x1F, 0xE2, 0x45, 0x72, 0x8A, 0x52}},
		"???","Unspecified Property Set",
		PropSet86_IDS
	},
	{	{0xC8EA94F0, 0xA9E3, 0x4969, {0xA9, 0x4B, 0x9C, 0x62, 0xA9, 0x53, 0x24, 0xE0}},
		"???","Unspecified Property Set",
		PropSet87_IDS
	},
	{	{0x8B26EA41, 0x058F, 0x43F6, {0xAE, 0xCC, 0x40, 0x35, 0x68, 0x1C, 0xE9, 0x77}},
		"???","Unspecified Property Set",
		PropSet88_IDS
	},
	{	{0xF21D9941, 0x81F0, 0x471A, {0xAD, 0xEE, 0x4E, 0x74, 0xB4, 0x92, 0x17, 0xED}},
		"???","Unspecified Property Set",
		PropSet89_IDS
	},
	{	{0xB0B87314, 0xFCF6, 0x4FEB, {0x8D, 0xFF, 0xA5, 0x0D, 0xA6, 0xAF, 0x56, 0x1C}},
		"???","Unspecified Property Set",
		PropSet90_IDS
	},
	{	{0xCC6F4F24, 0x6083, 0x4BD4, {0x87, 0x54, 0x67, 0x4D, 0x0D, 0xE8, 0x7A, 0xB8}},
		"???","Unspecified Property Set",
		PropSet91_IDS
	},
	{	{0xA0E74609, 0xB84D, 0x4F49, {0xB8, 0x60, 0x46, 0x2B, 0xD9, 0x97, 0x1F, 0x98}},
		"???","Unspecified Property Set",
		PropSet92_IDS
	},
	{	{0xD68DBD8A, 0x3374, 0x4B81, {0x99, 0x72, 0x3E, 0xC3, 0x06, 0x82, 0xDB, 0x3D}},
		"???","Unspecified Property Set",
		PropSet93_IDS
	},
	{	{0x2CBAA8F5, 0xD81F, 0x47CA, {0xB1, 0x7A, 0xF8, 0xD8, 0x22, 0x30, 0x01, 0x31}},
		"???","Unspecified Property Set",
		PropSet94_IDS
	},
	{	{0x72FAB781, 0xACDA, 0x43E5, {0xB1, 0x55, 0xB2, 0x43, 0x4F, 0x85, 0xE6, 0x78}},
		"???","Unspecified Property Set",
		PropSet95_IDS
	},
	{	{0x6B8DA074, 0x3B5C, 0x43BC, {0x88, 0x6F, 0x0A, 0x2C, 0xDC, 0xE0, 0x0B, 0x6F}},
		"???","Unspecified Property Set",
		PropSet96_IDS
	},
	{	{0x18BBD425, 0xECFD, 0x46EF, {0xB6, 0x12, 0x7B, 0x4A, 0x60, 0x34, 0xED, 0xA0}},
		"???","Unspecified Property Set",
		PropSet97_IDS
	},
	{	{0x276D7BB0, 0x5B34, 0x4FB0, {0xAA, 0x4B, 0x15, 0x8E, 0xD1, 0x2A, 0x18, 0x09}},
		"???","Unspecified Property Set",
		PropSet99_IDS
	},
	{	{0xFEC690B7, 0x5F30, 0x4646, {0xAE, 0x47, 0x4C, 0xAA, 0xFB, 0xA8, 0x84, 0xA3}},
		"???","Unspecified Property Set",
		PropSet100_IDS
	},
	{	{0x46B4E8DE, 0xCDB2, 0x440D, {0x88, 0x5C, 0x16, 0x58, 0xEB, 0x65, 0xB9, 0x14}},
		"???","Unspecified Property Set",
		PropSet101_IDS
	},
	{	{0xF628FD8C, 0x7BA8, 0x465A, {0xA6, 0x5B, 0xC5, 0xAA, 0x79, 0x26, 0x3A, 0x9E}},
		"???","Unspecified Property Set",
		PropSet102_IDS
	},
	{	{0x7A7D76F4, 0xB630, 0x4BD7, {0x95, 0xFF, 0x37, 0xCC, 0x51, 0xA9, 0x75, 0xC9}},
		"???","Unspecified Property Set",
		PropSet103_IDS
	},
	{	{0x446F787F, 0x10C4, 0x41CB, {0xA6, 0xC4, 0x4D, 0x03, 0x43, 0x55, 0x15, 0x97}},
		"???","Unspecified Property Set",
		PropSet104_IDS
	},
	{	{0xA9EA193C, 0xC511, 0x498A, {0xA0, 0x6B, 0x58, 0xE2, 0x77, 0x6D, 0xCC, 0x28}},
		"???","Unspecified Property Set",
		PropSet105_IDS
	},
	{	{0x97B0AD89, 0xDF49, 0x49CC, {0x83, 0x4E, 0x66, 0x09, 0x74, 0xFD, 0x75, 0x5B}},
		"???","Unspecified Property Set",
		PropSet106_IDS
	},
	{	{0xF6272D18, 0xCECC, 0x40B1, {0xB2, 0x6A, 0x39, 0x11, 0x71, 0x7A, 0xA7, 0xBD}},
		"???","Unspecified Property Set",
		PropSet107_IDS
	},
	{	{0x61478C08, 0xB600, 0x4A84, {0xBB, 0xE4, 0xE9, 0x9C, 0x45, 0xF0, 0xA0, 0x72}},
		"???","Unspecified Property Set",
		PropSet108_IDS
	},
	{	{0xBCCC8A3C, 0x8CEF, 0x42E5, {0x9B, 0x1C, 0xC6, 0x90, 0x79, 0x39, 0x8B, 0xC7}},
		"???","Unspecified Property Set",
		PropSet109_IDS
	},
	{	{0x9AD5BADB, 0xCEA7, 0x4470, {0xA0, 0x3D, 0xB8, 0x4E, 0x51, 0xB9, 0x94, 0x9E}},
		"???","Unspecified Property Set",
		PropSet110_IDS
	},
	{	{0xF1A24AA7, 0x9CA7, 0x40F6, {0x89, 0xEC, 0x97, 0xDE, 0xF9, 0xFF, 0xE8, 0xDB}},
		"???","Unspecified Property Set",
		PropSet111_IDS
	},
	{	{0x3602C812, 0x0F3B, 0x45F0, {0x85, 0xAD, 0x60, 0x34, 0x68, 0xD6, 0x94, 0x23}},
		"???","Unspecified Property Set",
		PropSet112_IDS
	},
	{	{0xA6F360D2, 0x55F9, 0x48DE, {0xB9, 0x09, 0x62, 0x0E, 0x09, 0x0A, 0x64, 0x7C}},
		"???","Unspecified Property Set",
		PropSet113_IDS
	},
	{	{0x897B3694, 0xFE9E, 0x43E6, {0x80, 0x66, 0x26, 0x0F, 0x59, 0x0C, 0x01, 0x00}},
		"???","Unspecified Property Set",
		PropSet114_IDS
	},
	{	{0x8619A4B6, 0x9F4D, 0x4429, {0x8C, 0x0F, 0xB9, 0x96, 0xCA, 0x59, 0xE3, 0x35}},
		"???","Unspecified Property Set",
		PropSet115_IDS
	},
	{	{0xA26F4AFC, 0x7346, 0x4299, {0xBE, 0x47, 0xEB, 0x1A, 0xE6, 0x13, 0x13, 0x9F}},
		"???","Unspecified Property Set",
		PropSet116_IDS
	},
	{	{0xBC4E71CE, 0x17F9, 0x48D5, {0xBE, 0xE9, 0x02, 0x1D, 0xF0, 0xEA, 0x54, 0x09}},
		"???","Unspecified Property Set",
		PropSet117_IDS
	},
	{	{0x65A98875, 0x3C80, 0x40AB, {0xAB, 0xBC, 0xEF, 0xDA, 0xF7, 0x7D, 0xBE, 0xE2}},
		"???","Unspecified Property Set",
		PropSet118_IDS
	},
	{	{0x84D8F337, 0x981D, 0x44B3, {0x96, 0x15, 0xC7, 0x59, 0x6D, 0xBA, 0x17, 0xE3}},
		"???","Unspecified Property Set",
		PropSet119_IDS
	},
	{	{0xBE1A72C6, 0x9A1D, 0x46B7, {0xAF, 0xE7, 0xAF, 0xAF, 0x8C, 0xEF, 0x49, 0x99}},
		"???","Unspecified Property Set",
		PropSet120_IDS
	},
	{	{0x8F367200, 0xC270, 0x457C, {0xB1, 0xD4, 0xE0, 0x7C, 0x5B, 0xCD, 0x90, 0xC7}},
		"???","Unspecified Property Set",
		PropSet121_IDS
	},
	{	{0x428040AC, 0xA177, 0x4C8A, {0x97, 0x60, 0xF6, 0xF7, 0x61, 0x22, 0x7F, 0x9A}},
		"???","Unspecified Property Set",
		PropSet122_IDS
	},
	{	{0xA3B29791, 0x7713, 0x4E1D, {0xBB, 0x40, 0x17, 0xDB, 0x85, 0xF0, 0x18, 0x31}},
		"???","Unspecified Property Set",
		PropSet123_IDS
	},
	{	{0xBCEEE283, 0x35DF, 0x4D53, {0x82, 0x6A, 0xF3, 0x6A, 0x3E, 0xEF, 0xC6, 0xBE}},
		"???","Unspecified Property Set",
		PropSet124_IDS
	},
	{	{0x91EFF6F3, 0x2E27, 0x42CA, {0x93, 0x3E, 0x7C, 0x99, 0x9F, 0xBE, 0x31, 0x0B}},
		"???","Unspecified Property Set",
		PropSet125_IDS
	},
	{	{0x5CBF2787, 0x48CF, 0x4208, {0xB9, 0x0E, 0xEE, 0x5E, 0x5D, 0x42, 0x02, 0x94}},
		"???","Unspecified Property Set",
		PropSet126_IDS
	},
	{	{0x1B5439E7, 0xEBA1, 0x4AF8, {0xBD, 0xD7, 0x7A, 0xF1, 0xD4, 0x54, 0x94, 0x93}},
		"???","Unspecified Property Set",
		PropSet127_IDS
	},
	{	{0x08C7CC5F, 0x60F2, 0x4494, {0xAD, 0x75, 0x55, 0xE3, 0xE0, 0xB5, 0xAD, 0xD0}},
		"???","Unspecified Property Set",
		PropSet128_IDS
	},
	{	{0x7FE3AA27, 0x2648, 0x42F3, {0x89, 0xB0, 0x45, 0x4E, 0x5C, 0xB1, 0x50, 0xC3}},
		"???","Unspecified Property Set",
		PropSet129_IDS
	},
	{	{0xE53D799D, 0x0F3F, 0x466E, {0xB2, 0xFF, 0x74, 0x63, 0x4A, 0x3C, 0xB7, 0xA4}},
		"???","Unspecified Property Set",
		PropSet130_IDS
	},
	{	{0x4776CAFA, 0xBCE4, 0x4CB1, {0xA2, 0x3E, 0x26, 0x5E, 0x76, 0xD8, 0xEB, 0x11}},
		"???","Unspecified Property Set",
		PropSet131_IDS
	},
	{	{0x71B377D6, 0xE570, 0x425F, {0xA1, 0x70, 0x80, 0x9F, 0xAE, 0x73, 0xE5, 0x4E}},
		"???","Unspecified Property Set",
		PropSet132_IDS
	},
	{	{0x3143BF7C, 0x80A8, 0x4854, {0x88, 0x80, 0xE2, 0xE4, 0x01, 0x89, 0xBD, 0xD0}},
		"???","Unspecified Property Set",
		PropSet133_IDS
	},
	{	{0xA6744477, 0xC237, 0x475B, {0xA0, 0x75, 0x54, 0xF3, 0x44, 0x98, 0x29, 0x2A}},
		"???","Unspecified Property Set",
		PropSet134_IDS
	},
	{	{0xC9C34F84, 0x2241, 0x4401, {0xB6, 0x07, 0xBD, 0x20, 0xED, 0x75, 0xAE, 0x7F}},
		"???","Unspecified Property Set",
		PropSet135_IDS
	},
	{	{0xF8FA7FA3, 0xD12B, 0x4785, {0x8A, 0x4E, 0x69, 0x1A, 0x94, 0xF7, 0xA3, 0xE7}},
		"???","Unspecified Property Set",
		PropSet136_IDS
	},
	{	{0x7268AF55, 0x1CE4, 0x4F6E, {0xA4, 0x1F, 0xB6, 0xE4, 0xEF, 0x10, 0xE4, 0xA9}},
		"???","Unspecified Property Set",
		PropSet137_IDS
	},
	{	{0xE1D4A09E, 0xD758, 0x4CD1, {0xB6, 0xEC, 0x34, 0xA8, 0xB5, 0xA7, 0x3F, 0x80}},
		"???","Unspecified Property Set",
		PropSet138_IDS
	},
	{	{0xD7313FF1, 0xA77A, 0x401C, {0x8C, 0x99, 0x3D, 0xBD, 0xD6, 0x8A, 0xDD, 0x36}},
		"???","Unspecified Property Set",
		PropSet139_IDS
	},
	{	{0xF85BF840, 0xA925, 0x4BC2, {0xB0, 0xC4, 0x8E, 0x36, 0xB5, 0x98, 0x67, 0x9E}},
		"???","Unspecified Property Set",
		PropSet140_IDS
	},
	{	{0x668CDFA5, 0x7A1B, 0x4323, {0xAE, 0x4B, 0xE5, 0x27, 0x39, 0x3A, 0x1D, 0x81}},
		"???","Unspecified Property Set",
		PropSet141_IDS
	},
	{	{0xEE3D3D8A, 0x5381, 0x4CFA, {0xB1, 0x3B, 0xAA, 0xF6, 0x6B, 0x5F, 0x4E, 0xC9}},
		"???","Unspecified Property Set",
		PropSet142_IDS
	},
	{	{0xD0C7F054, 0x3F72, 0x4725, {0x85, 0x27, 0x12, 0x9A, 0x57, 0x7C, 0xB2, 0x69}},
		"???","Unspecified Property Set",
		PropSet143_IDS
	},
	{	{0x3C8CEE58, 0xD4F0, 0x4CF9, {0xB7, 0x56, 0x4E, 0x5D, 0x24, 0x44, 0x7B, 0xCD}},
		"???","Unspecified Property Set",
		PropSet144_IDS
	},
	{	{0x6E682923, 0x7F7B, 0x4F0C, {0xA3, 0x37, 0xCF, 0xCA, 0x29, 0x66, 0x87, 0xBF}},
		"???","Unspecified Property Set",
		PropSet145_IDS
	},
	{	{0xFD122953, 0xFA93, 0x4EF7, {0x92, 0xC3, 0x04, 0xC9, 0x46, 0xB2, 0xF7, 0xC8}},
		"???","Unspecified Property Set",
		PropSet146_IDS
	},
	{	{0x0BE1C8E7, 0x1981, 0x4676, {0xAE, 0x14, 0xFD, 0xD7, 0x8F, 0x05, 0xA6, 0xE7}},
		"???","Unspecified Property Set",
		PropSet147_IDS
	},
	{	{0xF1176DFE, 0x7138, 0x4640, {0x8B, 0x4C, 0xAE, 0x37, 0x5D, 0xC7, 0x0A, 0x6D}},
		"???","Unspecified Property Set",
		PropSet148_IDS
	},
	{	{0x95BEB1FC, 0x326D, 0x4644, {0xB3, 0x96, 0xCD, 0x3E, 0xD9, 0x0E, 0x6D, 0xDF}},
		"???","Unspecified Property Set",
		PropSet149_IDS
	},
	{	{0xDDD1460F, 0xC0BF, 0x4553, {0x8C, 0xE4, 0x10, 0x43, 0x3C, 0x90, 0x8F, 0xB0}},
		"???","Unspecified Property Set",
		PropSet150_IDS
	},
	{	{0x9B174B34, 0x40FF, 0x11D2, {0xA2, 0x7E, 0x00, 0xC0, 0x4F, 0xC3, 0x08, 0x71}},
		"???","Unspecified Property Set",
		PropSet151_IDS
	},
	{	{0x08A65AA1, 0xF4C9, 0x43DD, {0x9D, 0xDF, 0xA3, 0x3D, 0x8E, 0x7E, 0xAD, 0x85}},
		"???","Unspecified Property Set",
		PropSet152_IDS
	},
	{	{0x084D8A0A, 0xE6D5, 0x40DE, {0xBF, 0x1F, 0xC8, 0x82, 0x0E, 0x7C, 0x87, 0x7C}},
		"???","Unspecified Property Set",
		PropSet153_IDS
	},
	{	{0x841E4F90, 0xFF59, 0x4D16, {0x89, 0x47, 0xE8, 0x1B, 0xBF, 0xFA, 0xB3, 0x6D}},
		"???","Unspecified Property Set",
		PropSet154_IDS
	},
	{	{0xFC9F7306, 0xFF8F, 0x4D49, {0x9F, 0xB6, 0x3F, 0xFE, 0x5C, 0x09, 0x51, 0xEC}},
		"???","Unspecified Property Set",
		PropSet155_IDS
	},
	{	{0x53DA57CF, 0x62C0, 0x45C4, {0x81, 0xDE, 0x76, 0x10, 0xBC, 0xEF, 0xD7, 0xF5}},
		"???","Unspecified Property Set",
		PropSet156_IDS
	},
	{	{0xF8D3F6AC, 0x4874, 0x42CB, {0xBE, 0x59, 0xAB, 0x45, 0x4B, 0x30, 0x71, 0x6A}},
		"???","Unspecified Property Set",
		PropSet157_IDS
	},
	{	{0x4684FE97, 0x8765, 0x4842, {0x9C, 0x13, 0xF0, 0x06, 0x44, 0x7B, 0x17, 0x8C}},
		"???","Unspecified Property Set",
		PropSet158_IDS
	},
	{	{0xC449D5CB, 0x9EA4, 0x4809, {0x82, 0xE8, 0xAF, 0x9D, 0x59, 0xDE, 0xD6, 0xD1}},
		"???","Unspecified Property Set",
		PropSet159_IDS
	},
	{	{0x3F8472B5, 0xE0AF, 0x4DB2, {0x80, 0x71, 0xC5, 0x3F, 0xE7, 0x6A, 0xE7, 0xCE}},
		"???","Unspecified Property Set",
		PropSet160_IDS
	},
	{	{0x0CEF7D53, 0xFA64, 0x11D1, {0xA2, 0x03, 0x00, 0x00, 0xF8, 0x1F, 0xED, 0xEE}},
		"???","Unspecified Property Set",
		PropSet161_IDS
	},
	{	{0xFDF84370, 0x031A, 0x4ADD, {0x9E, 0x91, 0x0D, 0x77, 0x5F, 0x1C, 0x66, 0x05}},
		"???","Unspecified Property Set",
		PropSet162_IDS
	},
	{	{0x6D748DE2, 0x8D38, 0x4CC3, {0xAC, 0x60, 0xF0, 0x09, 0xB0, 0x57, 0xC5, 0x57}},
		"???","Unspecified Property Set",
		PropSet163_IDS
	},
	{	{0x2579E5D0, 0x1116, 0x4084, {0xBD, 0x9A, 0x9B, 0x4F, 0x7C, 0xB4, 0xDF, 0x5E}},
		"???","Unspecified Property Set",
		PropSet164_IDS
	},
	{	{0xC554493C, 0xC1F7, 0x40C1, {0xA7, 0x6C, 0xEF, 0x8C, 0x06, 0x14, 0x00, 0x3E}},
		"???","Unspecified Property Set",
		PropSet165_IDS
	},
	{	{0x0DA41CFA, 0xD224, 0x4A18, {0xAE, 0x2F, 0x59, 0x61, 0x58, 0xDB, 0x4B, 0x3A}},
		"???","Unspecified Property Set",
		PropSet166_IDS
	},
	{	{0xA82D9EE7, 0xCA67, 0x4312, {0x96, 0x5E, 0x22, 0x6B, 0xCE, 0xA8, 0x50, 0x23}},
		"???","Unspecified Property Set",
		PropSet167_IDS
	},
	{	{0x09329B74, 0x40A3, 0x4C68, {0xBF, 0x07, 0xAF, 0x9A, 0x57, 0x2F, 0x60, 0x7C}},
		"???","Unspecified Property Set",
		PropSet168_IDS
	},
	{	{0x9A93244D, 0xA7AD, 0x4FF8, {0x9B, 0x99, 0x45, 0xEE, 0x4C, 0xC0, 0x9A, 0xF6}},
		"???","Unspecified Property Set",
		PropSet169_IDS
	},
	{	{0xF04BEF95, 0xC585, 0x4197, {0xA2, 0xB7, 0xDF, 0x46, 0xFD, 0xC9, 0xEE, 0x6D}},
		"???","Unspecified Property Set",
		PropSet170_IDS
	},
	{	{0x59DDE9F2, 0x5253, 0x40EA, {0x9A, 0x8B, 0x47, 0x9E, 0x96, 0xC6, 0x24, 0x9A}},
		"???","Unspecified Property Set",
		PropSet171_IDS
	},
	{	{0x6444048F, 0x4C8B, 0x11D1, {0x8B, 0x70, 0x08, 0x00, 0x36, 0xB1, 0x1A, 0x03}},
		"???","Unspecified Property Set",
		PropSet172_IDS
	},
	{	{0x9A9BC088, 0x4F6D, 0x469E, {0x99, 0x19, 0xE7, 0x05, 0x41, 0x20, 0x40, 0xF9}},
		"???","Unspecified Property Set",
		PropSet173_IDS
	},
	{	{0x6336B95E, 0xC7A7, 0x426D, {0x86, 0xFD, 0x7A, 0xE3, 0xD3, 0x9C, 0x84, 0xB4}},
		"???","Unspecified Property Set",
		PropSet174_IDS
	},
	{	{0xC06238B2, 0x0BF9, 0x4279, {0xA7, 0x23, 0x25, 0x85, 0x67, 0x15, 0xCB, 0x9D}},
		"???","Unspecified Property Set",
		PropSet175_IDS
	},
	{	{0xEC0B4191, 0xAB0B, 0x4C66, {0x90, 0xB6, 0xC6, 0x63, 0x7C, 0xDE, 0xBB, 0xAB}},
		"???","Unspecified Property Set",
		PropSet176_IDS
	},
	{	{0x660E04D6, 0x81AB, 0x4977, {0xA0, 0x9F, 0x82, 0x31, 0x31, 0x13, 0xAB, 0x26}},
		"???","Unspecified Property Set",
		PropSet177_IDS
	},
	{	{0xDC54FD2E, 0x189D, 0x4871, {0xAA, 0x01, 0x08, 0xC2, 0xF5, 0x7A, 0x4A, 0xBC}},
		"???","Unspecified Property Set",
		PropSet178_IDS
	},
	{	{0xCD102C9C, 0x5540, 0x4A88, {0xA6, 0xF6, 0x64, 0xE4, 0x98, 0x1C, 0x8C, 0xD1}},
		"???","Unspecified Property Set",
		PropSet179_IDS
	},
	{	{0x1F856A9F, 0x6900, 0x4ABA, {0x95, 0x05, 0x2D, 0x5F, 0x1B, 0x4D, 0x66, 0xCB}},
		"???","Unspecified Property Set",
		PropSet180_IDS
	},
	{	{0x90197CA7, 0xFD8F, 0x4E8C, {0x9D, 0xA3, 0xB5, 0x7E, 0x1E, 0x60, 0x92, 0x95}},
		"???","Unspecified Property Set",
		PropSet181_IDS
	},
	{	{0xF334115E, 0xDA1B, 0x4509, {0x9B, 0x3D, 0x11, 0x95, 0x04, 0xDC, 0x7A, 0xBB}},
		"???","Unspecified Property Set",
		PropSet182_IDS
	},
	{	{0xBF53D1C3, 0x49E0, 0x4F7F, {0x85, 0x67, 0x5A, 0x82, 0x1D, 0x8A, 0xC5, 0x42}},
		"???","Unspecified Property Set",
		PropSet183_IDS
	},
	{	{0xC75FAA05, 0x96FD, 0x49E7, {0x9C, 0xB4, 0x9F, 0x60, 0x10, 0x82, 0xD5, 0x53}},
		"???","Unspecified Property Set",
		PropSet184_IDS
	},
	{	{0x2E4B640D, 0x5019, 0x46D8, {0x88, 0x81, 0x55, 0x41, 0x4C, 0xC5, 0xCA, 0xA0}},
		"???","Unspecified Property Set",
		PropSet185_IDS
	},
	{	{0x6B8B68F6, 0x200B, 0x47EA, {0x8D, 0x25, 0xD8, 0x05, 0x0F, 0x57, 0x33, 0x9F}},
		"???","Unspecified Property Set",
		PropSet186_IDS
	},
	{	{0x2D152B40, 0xCA39, 0x40DB, {0xB2, 0xCC, 0x57, 0x37, 0x25, 0xB2, 0xFE, 0xC5}},
		"???","Unspecified Property Set",
		PropSet187_IDS
	},
	{	{0x1E005EE6, 0xBF27, 0x428B, {0xB0, 0x1C, 0x79, 0x67, 0x6A, 0xCD, 0x28, 0x70}},
		"???","Unspecified Property Set",
		PropSet188_IDS
	},
	{	{0xD6304E01, 0xF8F5, 0x4F45, {0x8B, 0x15, 0xD0, 0x24, 0xA6, 0x29, 0x67, 0x89}},
		"???","Unspecified Property Set",
		PropSet189_IDS
	},
	{	{0x402B5934, 0xEC5A, 0x48C3, {0x93, 0xE6, 0x85, 0xE8, 0x6A, 0x2D, 0x93, 0x4E}},
		"???","Unspecified Property Set",
		PropSet190_IDS
	},
	{	{0x9AEBAE7A, 0x9644, 0x487D, {0xA9, 0x2C, 0x65, 0x75, 0x85, 0xED, 0x75, 0x1A}},
		"???","Unspecified Property Set",
		PropSet191_IDS
	},
	{	{0x63C25B20, 0x96BE, 0x488F, {0x87, 0x88, 0xC0, 0x9C, 0x40, 0x7A, 0xD8, 0x12}},
		"???","Unspecified Property Set",
		PropSet192_IDS
	},
	{	{0x48FD6EC8, 0x8A12, 0x4CDF, {0xA0, 0x3E, 0x4E, 0xC5, 0xA5, 0x11, 0xED, 0xDE}},
		"???","Unspecified Property Set",
		PropSet193_IDS
	},
	{	{0x64440491, 0x4C8B, 0x11D1, {0x8B, 0x70, 0x08, 0x00, 0x36, 0xB1, 0x1A, 0x03}},
		"???","Unspecified Property Set",
		PropSet194_IDS
	},
	{	{0xC0AC206A, 0x827E, 0x4650, {0x95, 0xAE, 0x77, 0xE2, 0xBB, 0x74, 0xFC, 0xC9}},
		"???","Unspecified Property Set",
		PropSet195_IDS
	}
};

static const value_string version_vals[] = {
	{0x00000102, "Windows Vista or 2008"},
	{0x00000109, "Windows XP or 2003 with Windows Search 4.0"},
	{0x00000700, "Windows 7 or 2008 R2"},
	{0x00010102, "Windows Vista or 2008 (64 bit)"},
	{0x00010109, "Windows XP or 2003 with Windows Search 4.0 (64 bit)"},
	{0x00010700, "Windows 7 or 2008 R2 (64 bit)"},
	{0, NULL}
};

static struct GuidPropertySet *GuidPropertySet_find_guid(const e_guid_t *guid)
{
	unsigned i;
	for (i=0; i<array_length(GuidPropertySet); i++) {
		if (guid_cmp(&GuidPropertySet[i].guid, guid) == 0) {
			return &GuidPropertySet[i];
		}
	}
	return NULL;
}

static void get_name_from_fullpropspec(struct CFullPropSpec *v, char *out, int bufsize)
{
	struct GuidPropertySet *pset = GuidPropertySet_find_guid(&v->guid);
	const char *id_str, *guid_str;
	char *dest = out;
	id_str = pset ? try_val_to_str(v->u.propid, pset->id_map) : NULL;

	if (id_str) {
		g_snprintf(dest, bufsize, "%s", id_str);
	} else {
		guid_str = guids_get_guid_name(&v->guid);
		if (guid_str) {
			g_snprintf(dest, bufsize, "\"%s\"", guid_str);
		} else {
			guid_str = guid_to_str(wmem_packet_scope(), &v->guid);
			g_snprintf(dest, bufsize, "{%s}", guid_str);
		}
		if (v->kind == PRSPEC_LPWSTR) {
			g_snprintf(dest, bufsize, "%s \"%s\"", guid_str, v->u.name);
		} else if (v->kind == PRSPEC_PROPID) {
			g_snprintf(dest, bufsize, "%s 0x%08x", guid_str, v->u.propid);
		} else {
			g_snprintf(dest, bufsize, "%s <INVALID>", dest);
		}
	}
}

/******************************************************************************/
static int parse_uin32_array(tvbuff_t *tvb, int offset, proto_tree *tree, guint32 count, const char *fmt, ...)
{
	guint32 v, i;
	proto_item *item;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	proto_tree_add_subtree(tree, tvb, offset, count * 4, ett_mswsp_uin32_array, &item, txt);
	proto_item_append_text(item, " count %u [", count);
	for (i=0; i<count; i++) {
		v = tvb_get_letohl(tvb, offset);
		offset += 4;
		if (i>0) {
			proto_item_append_text(item, ",%u", v);
		} else {
			proto_item_append_text(item, "%u", v);
		}
	}
	proto_item_append_text(item, "]");
	return offset;
}

static int parse_padding(tvbuff_t *tvb, int offset, int alignment, proto_tree *pad_tree, const char *fmt, ...)
{
	if (offset % alignment) {
		const int padding = alignment - (offset % alignment);
		const char *txt;
		va_list ap;
		proto_item *ti;
		va_start(ap, fmt);
		txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
		proto_tree_add_subtree(pad_tree, tvb, offset, padding, ett_mswsp_msg_padding, &ti, txt);
		va_end(ap);

		proto_item_append_text(ti, " (%d)", padding);
		offset += padding;
	}
	DISSECTOR_ASSERT((offset % alignment) == 0);
	return offset;
}

static int parse_guid(tvbuff_t *tvb, int offset, proto_tree *tree, e_guid_t *guid, const char *text)
{
	const char *guid_str, *name, *bytes;
	proto_tree *tr;

	tvb_get_letohguid(tvb, offset, guid);
	guid_str =  guid_to_str(wmem_packet_scope(), guid);
	name = guids_get_guid_name(guid);

	tr = proto_tree_add_subtree_format(tree, tvb, offset, 16, ett_GUID, NULL, "%s: %s {%s}", text, name ? name : "", guid_str);


	proto_tree_add_item(tr, hf_mswsp_guid_time_low, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(tr, hf_mswsp_guid_time_mid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(tr, hf_mswsp_guid_time_high, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(tr, hf_mswsp_guid_time_clock_hi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(tr, hf_mswsp_guid_time_clock_low, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	bytes = bytestring_to_str(wmem_packet_scope(), &guid->data4[2], 6, ':');
	proto_tree_add_string(tr, hf_mswsp_guid_node, tvb, offset, 6, bytes);

	offset += 6;

	return offset;
}

/*Language Code ID: http://msdn.microsoft.com/en-us/library/cc233968(v=prot.20).aspx */
static int parse_lcid(tvbuff_t *tvb, int offset, proto_tree *parent_tree, const char *text)
{
	proto_item *item;
	proto_tree *tree;
	guint32 lcid;

	lcid = tvb_get_letohl(tvb, offset);
	item = proto_tree_add_uint_format(parent_tree, hf_mswsp_lcid, tvb, offset, 4, lcid, "%s: 0x%x", text, lcid);
	tree = proto_item_add_subtree(item, ett_LCID);

	proto_tree_add_uint(tree, hf_mswsp_lcid_langid, tvb, offset + 2, 2, lcid);
	proto_tree_add_uint(tree, hf_mswsp_lcid_sortid, tvb, offset + 1, 1, (lcid >> 16) & 0xF);
	offset += 4;
	return offset;
}

/*****************************************************************************************/
/* 2.2.1.1 CBaseStorageVariant */
static int parse_CBaseStorageVariant(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CBaseStorageVariant *value, const char *text);

/* 2.2.1.2 CFullPropSpec */
static int parse_CFullPropSpec(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree, struct CFullPropSpec *v, const char *fmt, ...);

/* 2.2.1.3 CContentRestriction */
static int parse_CContentRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CContentRestriction *v, const char *fmt, ...);

/* 2.2.1.5 CNatLanguageRestriction */
static int parse_CNatLanguageRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CNatLanguageRestriction *v, const char *fmt, ...);

/* 2.2.1.6 CNodeRestriction */
static int parse_CNodeRestriction(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree, struct CNodeRestriction *v, const char* fmt, ...);

/* 2.2.1.7 CPropertyRestriction */
static int parse_CPropertyRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CPropertyRestriction *v, const char *fmt, ...);

/* 2.2.1.8 CReuseWhere */
static int parse_CReuseWhere(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree _U_, struct CReuseWhere *v, const char *fmt, ...);

/* 2.2.1.10 CSort */
static int parse_CSort(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree _U_, const char *fmt, ...);

/* 2.2.1.12 CCoercionRestriction */
static int parse_CCoercionRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CCoercionRestriction *v, const char *fmt, ...);
/* 2.2.1.16 CRestrictionArray */
static int parse_CRestrictionArray(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.17 CRestriction */
static int parse_CRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CRestriction *v, const char *fmt, ...);

/* 2.2.1.18 CColumnSet */
static int parse_CColumnSet(tvbuff_t *tvb, int offset, proto_tree *tree, const char *fmt, ...);

/* 2.2.1.20 CCategorizationSpec */
static int parse_CCategorizationSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.21 CCategSpec */
static int parse_CCategSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.22 CRangeCategSpec */
static int parse_CRangeCategSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.23 RANGEBOUNDARY */
static int parse_RANGEBOUNDARY(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.24 CAggregSet */
static int parse_CAggregSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.25 CAggregSpec */
static int parse_CAggregSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.26 CSortAggregSet */
static int parse_CSortAggregSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.27 CAggregSortKey */
static int parse_CAggregSortKey(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.28 CInGroupSortAggregSets */
static int parse_CInGroupSortAggregSets(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.29 CInGroupSortAggregSet */
static int parse_CInGroupSortAggregSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.30 CDbColId */
static int parse_CDbColId(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *text);

/* 2.2.1.31 CDbProp */
static int parse_CDbProp(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct GuidPropertySet *propset, const char *fmt, ...);

/* 2.2.1.32 CDbPropSet */
static int parse_CDbPropSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.33 CPidMapper */
static int parse_CPidMapper(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.34 CColumnGroupArray */
static int parse_CColumnGroupArray(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.35 CColumnGroup */
static int parse_CColumnGroup(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.41 CRowsetProperties */
static int parse_CRowsetProperties(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.43 CSortSet */
static int parse_CSortSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.44 CTableColumn */
static int parse_CTableColumn(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CTableColumn *col, const char *fmt, ...);


/*
2.2.1.4 CInternalPropertyRestriction
2.2.1.9 CScopeRestriction
2.2.1.11 CVectorRestriction
2.2.1.13 CRelDocRestriction
2.2.1.14 CProbRestriction
2.2.1.15 CFeedbackRestriction
2.2.1.19 CCategorizationSet
2.2.1.45 SERIALIZEDPROPERTYVALUE
2.2.1.46 CCompletionCategSp
*/

static int parse_CSort(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree _U_, const char *fmt, ...)
{
	guint32 col, ord, ind;

	proto_item *item;
	proto_tree *tree;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CSort, &item, txt);

	col = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cscort_column, tvb, offset, 4, col);
	offset += 4;

	ord = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cscort_order, tvb, offset, 4, ord);
	offset += 4;

	ind = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cscort_individual, tvb, offset, 4, ind);
	offset += 4;

	offset = parse_lcid(tvb, offset, tree, "lcid");

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int parse_CSortSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	guint32 count, i;

	proto_item *item;
	proto_tree *tree;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CSortSet, &item, txt);

	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cscortset_count, tvb, offset, 4, count);
	offset += 4;

	for (i=0; i<count; i++) {
		offset = parse_padding(tvb, offset, 4, tree, "padding_sortArray[%u]", i);
		offset = parse_CSort(tvb, offset, tree, pad_tree, "sortArray[%u]", i);
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int parse_CTableColumn(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CTableColumn *col, const char *fmt, ...)
{
	static const value_string DBAGGTTYPE[] = {
		{0x0, "DBAGGTTYPE_BYNONE"},
		{0x1, "DBAGGTTYPE_SUM"},
		{0x2, "DBAGGTTYPE_MAX"},
		{0x3, "DBAGGTTYPE_MIN"},
		{0x4, "DBAGGTTYPE_AVG"},
		{0x5, "DBAGGTTYPE_COUNT"},
		{0x6, "DBAGGTTYPE_CHILDCOUNT"},
		{0x7, "DBAGGTTYPE_BYFREQ"},
		{0x8, "DBAGGTTYPE_FIRST"},
		{0x9, "DBAGGTTYPE_DATERANGE"},
		{0xA, "DBAGGTTYPE_REPRESENTATIVEOF"},
		{0xB, "DBAGGTTYPE_EDITDISTANCE"},
		{0, NULL}
	};

	proto_item *item;
	proto_tree *tree;
	va_list ap;
	struct vtype_data *type;
	enum vType vtype_val = VT_EMPTY;
	enum vType vtype_valhi = VT_EMPTY;
	struct CFullPropSpec v;
	const char *txt;
	guint8 used;

	const char *modifier = "";
	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CTableColumn, &item, txt);

	offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v, "PropSpec");
	get_name_from_fullpropspec(&v, col->name, PROP_LENGTH);
	col->vtype = tvb_get_letohl(tvb, offset);
	vtype_val = (enum vType)col->vtype;
	vtype_valhi = (enum vType)(col->vtype & 0xFF00);
	if (vtype_valhi) {
		if (vtype_valhi == VT_VECTOR) {
			modifier = "|VT_VECTOR";
		} else if (vtype_valhi == VT_ARRAY) {
			modifier = "|VT_ARRAY";
		} else {
			modifier = "|(Unknown, possibly error)";
		}
	}
	type = vType_get_type(vtype_val);
	DISSECTOR_ASSERT(type != NULL);
	proto_tree_add_string_format_value(tree, hf_mswsp_ctablecolumn_vtype, tvb, offset, 4, type->str, "%s%s", type->str, modifier);
	offset += 4;

	used = tvb_get_guint8(tvb, offset);
	col->aggregateused = used;
	proto_tree_add_uint(tree, hf_mswsp_ctablecolumn_aggused, tvb, offset, 1, used);
	offset += 1;

	if (used) {
		col->aggregatetype = tvb_get_guint8(tvb, offset);
		proto_tree_add_string(tree, hf_mswsp_ctablecolumn_aggtype, tvb, offset, 1, val_to_str(col->aggregatetype, DBAGGTTYPE, "(Unknown: 0x%x)"));
		offset += 1;
	}
	col->valueused = tvb_get_guint8(tvb, offset);
	used = col->valueused;
	proto_tree_add_uint(tree, hf_mswsp_ctablecolumn_valused, tvb, offset, 1, used);
	offset += 1;

	if (used) {
		offset = parse_padding(tvb, offset, 2, pad_tree, "padding_Value");

		col->valueoffset = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_ctablecolumn_valoffset, tvb, offset, 2,  col->valueoffset);
		offset += 2;

		col->valuesize = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_ctablecolumn_valsize, tvb, offset, 2, col->valuesize);
		offset += 2;
	}

	used = tvb_get_guint8(tvb, offset);
	col->statusused = used;
	proto_tree_add_uint(tree, hf_mswsp_ctablecolumn_statused, tvb, offset, 1, used);
	offset += 1;

	if (used) {
		offset = parse_padding(tvb, offset, 2, pad_tree, "padding_Status");

		col->statusoffset = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_ctablecolumn_statoffset, tvb, offset, 2, col->statusoffset);
		offset += 2;
	}

	used = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_ctablecolumn_lenused, tvb, offset, 1, used);
	col->lengthused = used;
	offset += 1;

	if (used) {
		offset = parse_padding(tvb, offset, 2, pad_tree, "padding_Length");

		col->lengthoffset = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_ctablecolumn_lenoffset, tvb, offset, 2, col->lengthoffset);
		offset += 2;
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int parse_PRSPEC_Kind(tvbuff_t *tvb, int offset, proto_tree *tree, enum PRSPEC_Kind *prspec)
{
	static const value_string KIND[] = {
		{0, "PRSPEC_LPWSTR"},
		{1, "PRSPEC_PROPID"},
		{0, NULL}
	};

	gint32 kind = tvb_get_letohl(tvb, offset);
	DISSECTOR_ASSERT(kind < (PRSPEC_PROPID + 1));
	if (kind) {
		*prspec = PRSPEC_PROPID;
	} else {
		*prspec = PRSPEC_LPWSTR;
	}
	proto_tree_add_string(tree, hf_mswsp_cfullpropspec_kind, tvb, offset, 4, val_to_str(*prspec, KIND, "(Unknown: 0x%x)"));
	offset += 4;
	return offset;
}

static int parse_CFullPropSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CFullPropSpec *v, const char *fmt, ...)
{
	struct GuidPropertySet *pset;
	const char *id_str, *guid_str, *txt;

	proto_item *item;
	proto_tree *tree;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CFullPropSpec, &item, txt);

	offset = parse_padding(tvb, offset, 8, pad_tree, "paddingPropSet");

	offset = parse_guid(tvb, offset, tree, &v->guid, "GUID");
	pset = GuidPropertySet_find_guid(&v->guid);

	offset = parse_PRSPEC_Kind(tvb, offset, tree, &v->kind);

	v->u.propid = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cfullpropspec_propid, tvb, offset, 4, v->u.propid);
	offset += 4;

	if (v->kind == PRSPEC_LPWSTR) {
		int len = 2*v->u.propid;
		proto_tree_add_item_ret_string(tree, hf_mswsp_cfullpropspec_propname, tvb, offset, len, ENC_LITTLE_ENDIAN | ENC_UCS_2, wmem_packet_scope(), &v->u.name);
		offset += len;
	}

	id_str = pset ? try_val_to_str(v->u.propid, pset->id_map) : NULL;

	if (id_str) {
		proto_item_append_text(item, ": %s", id_str);
	} else {
		guid_str = guids_get_guid_name(&v->guid);
		if (guid_str) {
			proto_item_append_text(item, ": \"%s\"", guid_str);
		} else {
			guid_str = guid_to_str(wmem_packet_scope(), &v->guid);
			proto_item_append_text(item, ": {%s}", guid_str);
		}

		if (v->kind == PRSPEC_LPWSTR) {
			proto_item_append_text(item, " \"%s\"", v->u.name);
		} else if (v->kind == PRSPEC_PROPID) {
			proto_item_append_text(item, " 0x%08x", v->u.propid);
		} else {
			proto_item_append_text(item, " <INVALID>");
		}
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}



static const value_string PR_VALS[] = {
	{PRLT, "PRLT"},
	{PRLE, "PRLE"},
	{PRGT, "PRGT"},
	{PRGE, "PRGE"},
	{PREQ, "PREQ"},
	{PRNE, "PRNE"},
	{PRRE, "PRRE"},
	{PRAllBits, "PRAllBits"},
	{PRSomeBits, "PRSomeBits"},
	{PRAll, "PRAll"},
	{PRAny, "PRAny"},
	{0, NULL}
};

static int parse_relop(tvbuff_t *tvb, int offset,  proto_tree *tree, guint32 *relop, const char **str)
{
	const char *str1 = NULL, *str2 = NULL;
	guint32 tmp = tvb_get_letohl(tvb, offset);
	guint32 modifier = (tmp & 0xF00);
	DISSECTOR_ASSERT((tmp & 0xf) < PRSomeBits +1);

	switch(tmp & 0xf) {
		case PRLT:
			*relop = PRLT;
			break;
		case PRLE:
			*relop = PRLE;
			break;
		case PRGT:
			*relop = PRGT;
			break;
		case PRGE:
			*relop = PRGE;
			break;
		case PREQ:
			*relop = PREQ;
			break;
		case PRNE:
			*relop = PRNE;
			break;
		case PRRE:
			*relop = PRRE;
			break;
		case PRAllBits:
			*relop = PRAllBits;
			break;
		case PRSomeBits:
			*relop = PRSomeBits;
			break;
		default:
			break;
	}

	str2 = val_to_str(*relop, PR_VALS, "0x%04x");

	if (modifier) {
		switch (modifier) {
			case PRAll:
				*relop = *relop | PRAll;
				break;
			case PRAny:
				*relop |= PRAny;
				break;
			default:
				DISSECTOR_ASSERT(FALSE);
				break;
		}
		str1 = try_val_to_str((modifier), PR_VALS);
		if (str1) {
			str1 = wmem_strdup_printf(wmem_packet_scope(), "%s | ", str1);
			str2 = wmem_strdup_printf(wmem_packet_scope(), "%s%s", str1, str2);
		}
	}
	proto_tree_add_string_format_value(tree, hf_mswsp_cproprestrict_relop, tvb, offset, 4, str2, "%s (0x%04x)", str2[0]=='\0' ? "" : str2, *relop);

	if (str) {
		*str = str2;
	}
	return offset + 4;
}
static int parse_CPropertyRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CPropertyRestriction *v, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	const char *txt, *str = NULL;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CPropertyRestriction, &item, txt);

	offset = parse_relop(tvb, offset, tree, &v->relop, &str);
	proto_item_append_text(item, " Op: %s", str);

	offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v->property, "Property");

	offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &v->prval, "prval");

	offset = parse_padding(tvb, offset, 4, pad_tree, "padding_lcid");

	v->lcid = tvb_get_letohl(tvb, offset);
	offset = parse_lcid(tvb, offset, tree, "lcid");

	proto_item_set_end(item, tvb, offset);

	return offset;
}

static int parse_CCoercionRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CCoercionRestriction *v, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CCoercionRestriction, &item, txt);

	v->value = tvb_get_letohieee_float(tvb, offset);
	proto_tree_add_float(tree, hf_mswsp_ccoercerestrict_value, tvb, offset, 4, v->value);

	offset += 4;

	offset = parse_CRestriction(tvb, offset, tree, pad_tree, &v->child, "child");

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int parse_CContentRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CContentRestriction *v, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	va_list ap;
	guint32 cc;
	const char *txt;


	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CContentRestriction, &item, txt);

	offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v->property, "Property");

	offset = parse_padding(tvb, offset, 4, pad_tree, "Padding1");

	cc = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_ccontentrestrict_cc, tvb, offset, 4, cc);
	offset += 4;

	proto_tree_add_item_ret_string(tree, hf_mswsp_ccontentrestrict_phrase, tvb, offset, 2*cc, ENC_LITTLE_ENDIAN | ENC_UCS_2, wmem_packet_scope(), &v->phrase);
	offset += 2*cc;

	offset = parse_padding(tvb, offset, 4, pad_tree, "Padding2");

	v->lcid = tvb_get_letohl(tvb, offset);
	offset = parse_lcid(tvb, offset, tree, "lcid");

	v->method = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_ccontentrestrict_method, tvb, offset, 4, v->method);
	offset += 4;

	proto_item_set_end(item, tvb, offset);
	return offset;
}

int parse_CNatLanguageRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CNatLanguageRestriction *v, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	va_list ap;
	guint32 cc;
	const char *txt;


	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CNatLanguageRestriction, &item, txt);

	offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v->property, "Property");

	offset = parse_padding(tvb, offset, 4, pad_tree, "padding_cc");

	cc = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_natlangrestrict_cc, tvb, offset, 4, cc);
	offset += 4;

	proto_tree_add_item_ret_string(tree, hf_mswsp_natlangrestrict_phrase, tvb, offset, 2*cc, ENC_LITTLE_ENDIAN | ENC_UCS_2, wmem_packet_scope(), &v->phrase);
	offset += 2*cc;

	offset = parse_padding(tvb, offset, 4, pad_tree, "padding_lcid");

	v->lcid = tvb_get_letohl(tvb, offset);
	offset = parse_lcid(tvb, offset, tree, "lcid");

	proto_item_set_end(item, tvb, offset);
	return offset;
}


static int parse_CReuseWhere(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree _U_, struct CReuseWhere *v, const char *fmt, ...)
{
	proto_item *item;
	va_list ap;
	const char *txt;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_mswsp_msg_creusewhere, &item, txt);
	v->whereId = tvb_get_letohl(tvb, offset);
	offset += 4;

	proto_item_append_text(item, " Id: %u", v->whereId);

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static const value_string RT_VALS[] =  {
	{RTNone, "RTNone"},
	{RTAnd, "RTAnd"},
	{RTOr, "RTOr"},
	{RTNot, "RTNot"},
	{RTContent, "RTContent"},
	{RTProperty, "RTProperty"},
	{RTProximity, "RTProximity"},
	{RTVector, ""},
	{RTNatLanguage, "RTNatLanguage"},
	{RTScope, "RTScope"},
	{RTCoerce_Add, "RTCoerce_Add"},
	{RTCoerce_Multiply, "RTCoerce_Multiply"},
	{RTCoerce_Absolute, "RTCoerce_Absolute"},
	{RTProb, "RTProb"},
	{RTFeedback, "RTFeedback"},
	{RTReldoc, "RTReldoc"},
	{RTReuseWhere, "RTReuseWhere"},
	{RTInternalProp, "RTInternalProp"},
	{RTPhrase, "RTInternalProp"},
	{0, NULL}
};

#define EP_ALLOC(T) (T*)wmem_alloc(wmem_packet_scope(), sizeof(T))

static int parse_rType(tvbuff_t *tvb, int offset, proto_tree *tree, enum rType *rtype, const char **str)
{
	const char *txt = NULL;
	guint32 type = tvb_get_letohl(tvb, offset);
	switch(type) {
		case RTNone:
			*rtype = RTNone;
			break;
		case RTAnd:
			*rtype = RTAnd;
			break;
		case RTOr:
			*rtype = RTOr;
			break;
		case RTNot:
			*rtype = RTNot;
			break;
		case RTContent:
			*rtype = RTContent;
			break;
		case RTProperty:
			*rtype = RTProperty;
			break;
		case RTProximity:
			*rtype = RTProximity;
			break;
		case RTVector:
			*rtype = RTVector;
			break;
		case RTNatLanguage:
			*rtype = RTNatLanguage;
			break;
		case RTScope:
			*rtype = RTScope;
			break;
		case RTCoerce_Add:
			*rtype = RTCoerce_Add;
			break;
		case RTCoerce_Multiply:
			*rtype = RTCoerce_Multiply;
			break;
		case RTCoerce_Absolute:
			*rtype = RTCoerce_Absolute;
			break;
		case RTProb:
			*rtype = RTProb;
			break;
		case RTFeedback:
			*rtype = RTFeedback;
			break;
		case RTReldoc:
			*rtype = RTReldoc;
			break;
		case RTReuseWhere:
			*rtype = RTReuseWhere;
			break;
		case RTInternalProp:
			*rtype = RTInternalProp;
			break;
		default:
			DISSECTOR_ASSERT(FALSE);
			break;
	}
	txt = val_to_str(*rtype, RT_VALS, "0x%.8x");
	proto_tree_add_string_format_value(tree, hf_mswsp_crestrict_ultype, tvb, offset, 4, txt, "%s (0x%.8x)",  txt[0] == '0' ? "" : txt, *rtype);
	if (str) {
		*str = txt;
	}
	return offset + 4;
}

static int parse_CRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CRestriction *v, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	const char *str, *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRestriction, &item, txt);


	offset = parse_rType(tvb, offset, tree, &v->ulType, &str);
	proto_item_append_text(item, " Type: %s", str);

	v->Weight = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_crestrict_weight, tvb, offset, 4, v->Weight);
	offset += 4;

	switch(v->ulType) {
	case RTNone:
		break;
	case RTAnd:
	case RTOr:
	case RTProximity:
	case RTPhrase: {
		v->u.RTAnd = EP_ALLOC(struct CNodeRestriction);
		offset = parse_CNodeRestriction(tvb, offset, tree, pad_tree, v->u.RTAnd, "CNodeRestriction");
		break;
	}
	case RTNot: {
		v->u.RTNot = EP_ALLOC(struct CRestriction);
		offset = parse_CRestriction(tvb, offset, tree, pad_tree,
									v->u.RTNot, "CRestriction");
		break;
	}
	case RTProperty: {
		v->u.RTProperty = EP_ALLOC(struct CPropertyRestriction);
		offset = parse_CPropertyRestriction(tvb, offset, tree, pad_tree,
											v->u.RTProperty, "CPropertyRestriction");
		break;
	}
	case RTCoerce_Add:
	case RTCoerce_Multiply:
	case RTCoerce_Absolute: {
		v->u.RTCoerce_Add = EP_ALLOC(struct CCoercionRestriction);
		offset = parse_CCoercionRestriction(tvb, offset, tree, pad_tree,
											v->u.RTCoerce_Add, "CCoercionRestriction");
		break;
	}
	case RTContent: {
		v->u.RTContent = EP_ALLOC(struct CContentRestriction);
		offset = parse_CContentRestriction(tvb, offset, tree, pad_tree,
										   v->u.RTContent, "CContentRestriction");
		break;
	}
	case RTReuseWhere: {
		v->u.RTReuseWhere = EP_ALLOC(struct CReuseWhere);
		offset = parse_CReuseWhere(tvb, offset, tree, pad_tree,
								   v->u.RTReuseWhere, "CReuseWhere");
		break;
	}
	case RTNatLanguage: {
		v->u.RTNatLanguage = EP_ALLOC(struct CNatLanguageRestriction);
		offset = parse_CNatLanguageRestriction(tvb, offset, tree, pad_tree,
											   v->u.RTNatLanguage, "CNatLanguageRestriction");
		break;
	}
	default:
		proto_item_append_text(item, " Not supported!");
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int parse_CRestrictionArray(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	guint8 present, count;

	proto_tree *tree;
	proto_item *item;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRestrictionArray, &item, txt);

	pad_tree = tree;

	count = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_crestrictarray_count, tvb, offset, 1, count);
	offset += 1;

	present = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_crestrictarray_present, tvb, offset, 1, present);
	offset += 1;

	if (present) {
		unsigned i;
		offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCRestrictionPresent");

		for (i=0; i<count; i++) {
			struct CRestriction r;
			offset = parse_CRestriction(tvb, offset, tree, pad_tree, &r, "Restriction[%d]", i);
		}
	}
	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int parse_CNodeRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct CNodeRestriction *v, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	unsigned i;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CNodeRestriction, &item, txt);

	v->cNode = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cnoderestrict_cnode, tvb, offset, 4, v->cNode);
	offset += 4;

	for (i=0; i<v->cNode; i++) {
		struct CRestriction r;
		ZERO_STRUCT(r);
		offset = parse_CRestriction(tvb, offset, tree, pad_tree, &r, "paNode[%u]", i);
		offset = parse_padding(tvb, offset, 4, tree, "padding_paNode[%u]", i); /*at begin or end of loop ????*/

	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}


/*****************************************************************************************/

static int vvalue_tvb_get0(tvbuff_t *tvb _U_, int offset _U_, void *val _U_)
{
	return 0;
}

static int vvalue_tvb_get1(tvbuff_t *tvb, int offset, void *val)
{
	guint8 *ui1 = (guint8*)val;
	*ui1 = tvb_get_guint8(tvb, offset);
	return 1;
}

static int vvalue_tvb_get2(tvbuff_t *tvb, int offset, void *val)
{
	guint16 *ui2 = (guint16*)val;
	*ui2 = tvb_get_letohs(tvb, offset);
	return 2;
}

static int vvalue_tvb_get4(tvbuff_t *tvb, int offset, void *val)
{
	guint32 *ui4 = (guint32*)val;
	*ui4 = tvb_get_letohl(tvb, offset);
	return 4;
}

static int vvalue_tvb_get8(tvbuff_t *tvb, int offset, void *val)
{
	guint64 *ui8 = (guint64*)val;
	*ui8 = tvb_get_letoh64(tvb, offset);
	return 8;
}

static int vvalue_tvb_blob(tvbuff_t *tvb, int offset, void *val)
{
	struct data_blob *blob = (struct data_blob*)val;
	guint32 len = tvb_get_letohl(tvb, offset);

	blob->size = len;
	blob->data = (guint8*)tvb_memdup(wmem_packet_scope(), tvb, offset + 4, len);

	return 4 + len;
}

static int vvalue_tvb_lpstr(tvbuff_t *tvb, int offset, void *val)
{
	struct data_str *str = (struct data_str*)val;
	gint len;

	str->len = tvb_get_letohl(tvb, offset);
	str->str = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset + 4, &len,
								   ENC_ASCII|ENC_LITTLE_ENDIAN);
	/* XXX test str->len == len */
	return 4 + len;
}

static int vvalue_tvb_lpwstr_len(tvbuff_t *tvb, int offset, int length, void *val)
{
	struct data_str *str = (struct data_str*)val;
	const gchar *ptr;
	int len;

	if (length == 0) {
		/* we don't know the length */
		ptr = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &len,
								  ENC_UTF_16|ENC_LITTLE_ENDIAN);
	} else {
		ptr =  tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length,
								  ENC_UTF_16|ENC_LITTLE_ENDIAN);
		len = length;
	}
	str->str = ptr;
	return len;
}

static int vvalue_tvb_lpwstr(tvbuff_t *tvb, int offset, void *val)
{
	struct data_str *str = (struct data_str*)val;

	str->len = tvb_get_letohl(tvb, offset);

	return 4 + vvalue_tvb_lpwstr_len(tvb, offset + 4, 0, val);
}

static int vvalue_tvb_vector_internal(tvbuff_t *tvb, int offset, struct vt_vector *val, struct vtype_data *type, guint num)
{
	const int offset_in = offset;
	const gboolean varsize = (type->size == -1);
	const guint elsize = varsize ? (guint)sizeof(struct data_blob) : (guint)type->size;
	guint8 *data;
	int len;
	guint i;

	/*
	 * Make sure we actually *have* the data we're going to fetch
	 * here, before making a possibly-doomed attempt to allocate
	 * memory for it.
	 *
	 * First, check for an overflow.
	 */
	if ((guint64)elsize * (guint64)num > G_MAXUINT) {
		/*
		 * We never have more than G_MAXUINT bytes in a tvbuff,
		 * so this will *definitely* fail.
		 */
		THROW(ReportedBoundsError);
	}

	/*
	 * No overflow; now make sure we at least have that data.
	 */
	tvb_ensure_bytes_exist(tvb, offset, elsize * num);

	/*
	 * OK, it exists; allocate a buffer into which to fetch it.
	 */
	data = (guint8*)wmem_alloc(wmem_packet_scope(), elsize * num);

	val->len = num;
	val->u.vt_ui1 = data;
	DISSECTOR_ASSERT((void*)&val->u == ((void*)&val->u.vt_ui1));

	for (i=0; i<num; i++) {
		DISSECTOR_ASSERT_HINT(type->tvb_get != 0,
				      "type that we don't know yet how to handle, please submit a bug with trace");
		len = type->tvb_get(tvb, offset, data);
		data += elsize;
		offset += len;
		if (varsize && (offset % 4) ) { /* at begin or end of loop ??? */
			int padding = 4 - (offset % 4);
			offset += padding;
		}
	}
	return offset - offset_in;
}

static int vvalue_tvb_vector(tvbuff_t *tvb, int offset, struct vt_vector *val, struct vtype_data *type)
{
	const guint num = tvb_get_letohl(tvb, offset);
	return 4 + vvalue_tvb_vector_internal(tvb, offset+4, val, type, num);
}

static void vvalue_strbuf_append_null(wmem_strbuf_t *strbuf _U_, void *ptr _U_)
{}

static void vvalue_strbuf_append_i1(wmem_strbuf_t *strbuf, void *ptr)
{
	gint8 i1 = *(gint8*)ptr;
	wmem_strbuf_append_printf(strbuf, "%d", (int)i1);
}

static void vvalue_strbuf_append_i2(wmem_strbuf_t *strbuf, void *ptr)
{
	gint16 i2 = *(gint16*)ptr;
	wmem_strbuf_append_printf(strbuf, "%d", (int)i2);
}

static void vvalue_strbuf_append_i4(wmem_strbuf_t *strbuf, void *ptr)
{
	gint32 i4 = *(gint32*)ptr;
	wmem_strbuf_append_printf(strbuf, "%d", i4);
}

static void vvalue_strbuf_append_i8(wmem_strbuf_t *strbuf, void *ptr)
{
	gint64 i8 = *(gint64*)ptr;
	wmem_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "d", i8);
}

static void vvalue_strbuf_append_ui1(wmem_strbuf_t *strbuf, void *ptr)
{
	guint8 ui1 = *(guint8*)ptr;
	wmem_strbuf_append_printf(strbuf, "%u", (unsigned)ui1);
}

static void vvalue_strbuf_append_ui2(wmem_strbuf_t *strbuf, void *ptr)
{
	guint16 ui2 = *(guint16*)ptr;
	wmem_strbuf_append_printf(strbuf, "%u", (unsigned)ui2);
}

static void vvalue_strbuf_append_ui4(wmem_strbuf_t *strbuf, void *ptr)
{
	guint32 ui4 = *(guint32*)ptr;
	wmem_strbuf_append_printf(strbuf, "%d", ui4);
}

static void vvalue_strbuf_append_ui8(wmem_strbuf_t *strbuf, void *ptr)
{
	guint64 ui8 = *(guint64*)ptr;
	wmem_strbuf_append_printf(strbuf, "%" G_GINT64_MODIFIER "u", ui8);
}

static void vvalue_strbuf_append_r4(wmem_strbuf_t *strbuf, void *ptr)
{
	float r4 = *(float*)ptr;
	wmem_strbuf_append_printf(strbuf, "%g", (double)r4);
}

static void vvalue_strbuf_append_r8(wmem_strbuf_t *strbuf, void *ptr)
{
	double r8 = *(double*)ptr;
	wmem_strbuf_append_printf(strbuf, "%g", r8);
}

static void vvalue_strbuf_append_str(wmem_strbuf_t *strbuf, void *ptr)
{
	struct data_str *str = (struct data_str*)ptr;
	wmem_strbuf_append_printf(strbuf, "\"%s\"", str->str);
}

static void vvalue_strbuf_append_blob(wmem_strbuf_t *strbuf, void *ptr)
{
	struct data_blob *blob = (struct data_blob*)ptr;
	wmem_strbuf_append_printf(strbuf, "size: %d", (int)blob->size);
}

static void vvalue_strbuf_append_bool(wmem_strbuf_t *strbuf, void *ptr)
{
	guint16 val = *(guint*)ptr;
	switch (val) {
	case 0:
		wmem_strbuf_append(strbuf, "False");
		break;
	case 0xffff:
		wmem_strbuf_append(strbuf, "True");
		break;
	default:
		wmem_strbuf_append_printf(strbuf, "Invalid (0x%4x)", val);
	}
}

static void vvalue_strbuf_append_vector(wmem_strbuf_t *strbuf, struct vt_vector val, struct vtype_data *type)
{
	const int elsize = (type->size == -1) ? (int)sizeof(struct data_blob) : type->size;
	unsigned i;
	guint8 *data = val.u.vt_ui1;
	wmem_strbuf_append_c(strbuf, '[');
	for (i=0; i<val.len; i++) {
		if (i>0) {
			wmem_strbuf_append_c(strbuf, ',');
		}
		type->strbuf_append(strbuf, data);
		data += elsize;
	}
	wmem_strbuf_append_c(strbuf, ']');
}

static struct vtype_data VT_TYPE[] = {
	{VT_EMPTY,             "VT_EMPTY",              0, vvalue_tvb_get0, NULL, vvalue_strbuf_append_null},
	{VT_NULL,              "VT_NULL",               0, vvalue_tvb_get0, NULL, vvalue_strbuf_append_null},
	{VT_I2,                "VT_I2",                 2, vvalue_tvb_get2, NULL, vvalue_strbuf_append_i2},
	{VT_I4,                "VT_I4",                 4, vvalue_tvb_get4, NULL, vvalue_strbuf_append_i4},
	{VT_R4,                "VT_R4",                 4, vvalue_tvb_get4, NULL, vvalue_strbuf_append_r4},
	{VT_R8,                "VT_R8",                 8, vvalue_tvb_get8, NULL, vvalue_strbuf_append_r8},
	{VT_CY,                "VT_CY",                 8, vvalue_tvb_get8, NULL, vvalue_strbuf_append_i8},
	{VT_DATE,              "VT_DATE",               8, vvalue_tvb_get8, NULL, vvalue_strbuf_append_r8},
	{VT_BSTR,              "VT_BSTR",              -1, vvalue_tvb_lpwstr, vvalue_tvb_lpwstr_len, vvalue_strbuf_append_str},
	{VT_ERROR,             "VT_ERROR",              4, vvalue_tvb_get4, NULL, vvalue_strbuf_append_ui4},
	{VT_BOOL,              "VT_BOOL",               2, vvalue_tvb_get2, NULL, vvalue_strbuf_append_bool},
	{VT_VARIANT,           "VT_VARIANT",           -1, NULL, NULL, NULL},
	{VT_DECIMAL,           "VT_DECIMAL",           16, NULL, NULL, NULL},
	{VT_I1,                "VT_I1",                 1, vvalue_tvb_get1, NULL, vvalue_strbuf_append_i1},
	{VT_UI1,               "VT_UI1",                1, vvalue_tvb_get1, NULL, vvalue_strbuf_append_ui1},
	{VT_UI2,               "VT_UI2",                2, vvalue_tvb_get2, NULL, vvalue_strbuf_append_ui2},
	{VT_UI4,               "VT_UI4",                4, vvalue_tvb_get4, NULL, vvalue_strbuf_append_ui4},
	{VT_I8,                "VT_I8",                 8, vvalue_tvb_get8, NULL, vvalue_strbuf_append_i8},
	{VT_UI8,               "VT_UI8",                8, vvalue_tvb_get8, NULL, vvalue_strbuf_append_ui8},
	{VT_INT,               "VT_INT",                4, vvalue_tvb_get4, NULL, vvalue_strbuf_append_i4},
	{VT_UINT,              "VT_UINT",               4, vvalue_tvb_get4, NULL, vvalue_strbuf_append_ui4},
	{VT_LPSTR,             "VT_LPSTR",             -1, vvalue_tvb_lpstr, NULL, vvalue_strbuf_append_str},
	{VT_LPWSTR,            "VT_LPWSTR",            -1, vvalue_tvb_lpwstr, vvalue_tvb_lpwstr_len, vvalue_strbuf_append_str},
	{VT_COMPRESSED_LPWSTR, "VT_COMPRESSED_LPWSTR", -1, NULL, NULL, vvalue_strbuf_append_str},
	{VT_FILETIME,          "VT_FILETIME",           8, vvalue_tvb_get8, NULL, vvalue_strbuf_append_i8},
	{VT_BLOB,              "VT_BLOB",              -1, vvalue_tvb_blob, NULL, vvalue_strbuf_append_blob},
	{VT_BLOB_OBJECT,       "VT_BLOB_OBJECT",       -1, vvalue_tvb_blob, NULL, vvalue_strbuf_append_blob},
	{VT_CLSID,             "VT_CLSID",             16, NULL, NULL, NULL}
};

static struct vtype_data *vType_get_type(guint16 t)
{
	unsigned i;
	t = (t & 0xFF);
	for (i=0; i<array_length(VT_TYPE); i++) {
		if (t == VT_TYPE[i].tag) {
			return &VT_TYPE[i];
		}
	}
	return NULL;
}

static const char *str_CBaseStorageVariant(struct CBaseStorageVariant *value, gboolean print_type)
{

	wmem_strbuf_t *strbuf = wmem_strbuf_new(wmem_packet_scope(), "");
	if (value == NULL) {
		return "<NULL>";
	}

	if (value->type == NULL) {
		return "<??""?>";
	}

	if (print_type) {
		wmem_strbuf_append(strbuf, value->type->str);

		if (value->vType & 0xFF00) {
			wmem_strbuf_append_printf(strbuf, "[%d]", value->vValue.vt_vector.len);
		}
		wmem_strbuf_append(strbuf, ": ");
	}

	switch (value->vType & 0xFF00) {
	case 0:
		value->type->strbuf_append(strbuf, &value->vValue);
		break;
	case VT_ARRAY:
		vvalue_strbuf_append_vector(strbuf, value->vValue.vt_array.vData, value->type);
		break;
	case VT_VECTOR:
		vvalue_strbuf_append_vector(strbuf, value->vValue.vt_vector, value->type);
		break;
	default:
		wmem_strbuf_append(strbuf, "Invalid");
	}

	return wmem_strbuf_get_str(strbuf);
}

static int parse_vType(tvbuff_t *tvb, int offset, guint16 *vtype)
{
	guint16 tmp_vtype = tvb_get_letohs(tvb, offset);
	guint16 modifier =  tmp_vtype & 0xFF00;

	switch (tmp_vtype & 0xFF) {
		case VT_EMPTY:
			*vtype = VT_EMPTY;
			break;
		case VT_NULL:
			*vtype = VT_NULL;
			break;
		case VT_I2:
			*vtype = VT_I2;
			break;
		case VT_I4:
			*vtype = VT_I4;
			break;
		case VT_R4:
			*vtype = VT_R4;
			break;
		case VT_R8:
			*vtype = VT_R8;
			break;
		case VT_CY:
			*vtype = VT_CY;
			break;
		case VT_DATE:
			*vtype = VT_DATE;
			break;
		case VT_BSTR:
			*vtype = VT_BSTR;
			break;
		case VT_ERROR:
			*vtype = VT_ERROR;
			break;
		case VT_BOOL:
			*vtype = VT_BOOL;
			break;
		case VT_VARIANT:
			*vtype = VT_VARIANT;
			break;
		case VT_DECIMAL:
			*vtype = VT_DECIMAL;
			break;
		case VT_I1:
			*vtype = VT_I1;
			break;
		case VT_UI1:
			*vtype = VT_UI1;
			break;
		case VT_UI2:
			*vtype = VT_UI2;
			break;
		case VT_UI4:
			*vtype = VT_UI4;
			break;
		case VT_I8:
			*vtype = VT_I8;
			break;
		case VT_UI8:
			*vtype = VT_UI8;
			break;
		case VT_INT:
			*vtype = VT_INT;
			break;
		case VT_UINT:
			*vtype = VT_UINT;
			break;
		case VT_LPSTR:
			*vtype = VT_LPSTR;
			break;
		case VT_LPWSTR:
			*vtype = VT_LPWSTR;
			break;
		case VT_COMPRESSED_LPWSTR:
			*vtype = VT_COMPRESSED_LPWSTR;
			break;
		case VT_FILETIME:
			*vtype = VT_FILETIME;
			break;
		case VT_BLOB:
			*vtype = VT_BLOB;
			break;
		case VT_BLOB_OBJECT:
			*vtype = VT_BLOB_OBJECT;
			break;
		case VT_CLSID:
			*vtype = VT_CLSID;
			break;
		default:
			DISSECTOR_ASSERT(FALSE);
			break;
	}
	if (modifier) {
		switch (modifier) {
			case VT_VECTOR:
				*vtype |= VT_VECTOR;
				break;
			case VT_ARRAY:
				*vtype |= VT_ARRAY;
				break;
			default:
				DISSECTOR_ASSERT(FALSE);
				break;
		}
	}
	return offset + 2;
}

static int parse_CBaseStorageVariant(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree _U_, struct CBaseStorageVariant *value, const char *text)
{
	int i, len;
	proto_item *ti, *ti_type, *ti_val;
	proto_tree *tree, *tr;
	enum vType highType;

	ZERO_STRUCT(*value);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CBaseStorageVariant, &ti, text);

	parse_vType(tvb, offset, &value->vType);
	value->type = vType_get_type(value->vType);
	DISSECTOR_ASSERT(value->type != NULL);

	ti_type = proto_tree_add_string(tree, hf_mswsp_cbasestorvariant_vtype, tvb, offset, 2, value->type->str);
	offset += 2;

	value->vData1 = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cbasestorvariant_vdata1, tvb, offset, 1, value->vData1);
	offset += 1;

	value->vData2 = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cbasestorvariant_vdata2, tvb, offset, 1, value->vData2);
	offset += 1;

	highType = (enum vType)(value->vType & 0xFF00);

	ti_val = proto_tree_add_string(tree, hf_mswsp_cbasestorvariant_vvalue, tvb, offset, 0, "");

	switch (highType) {
	case VT_EMPTY:
		DISSECTOR_ASSERT_HINT(value->type->tvb_get != 0,
				      "type that we don't know yet how to handle, please submit a bug with trace");
		len = value->type->tvb_get(tvb, offset, &value->vValue.vt_single);
		offset += len;
		break;
	case VT_VECTOR:
		proto_item_append_text(ti_type, "|VT_VECTOR");
		tr = proto_item_add_subtree(ti_val, ett_CBaseStorageVariant_Vector);

		len = vvalue_tvb_vector(tvb, offset, &value->vValue.vt_vector, value->type);
		proto_tree_add_uint(tr, hf_mswsp_cbasestorvariant_num, tvb, offset, 4, value->vValue.vt_vector.len);
		offset += len;
		break;
	case VT_ARRAY: {
		guint16 cDims, fFeatures;
		guint32 cbElements, cElements, lLbound;
		int num = 1;

		proto_item_append_text(ti_type, "|VT_ARRAY");
		tr = proto_item_add_subtree(ti_val, ett_CBaseStorageVariant_Array);

		cDims = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tr, hf_mswsp_cbasestorvariant_cdims, tvb, offset, 2, cDims);
		offset += 2;

		fFeatures = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tr, hf_mswsp_cbasestorvariant_ffeatures, tvb, offset, 2, fFeatures);
		offset += 2;

		cbElements = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tr, hf_mswsp_cbasestorvariant_cbelements, tvb, offset, 4, cbElements);
		offset += 4;
		for (i=0; i<cDims; i++) {
			cElements = tvb_get_letohl(tvb, offset);
			lLbound =  tvb_get_letohl(tvb, offset + 4);
			proto_tree_add_string_format(tr, hf_mswsp_cbasestorvariant_rgsabound, tvb, offset, 8, "", "Rgsabound[%d]: (%d:%d)", i, cElements, lLbound);
			offset += 8;
			num *= cElements;
		}

		len = vvalue_tvb_vector_internal(tvb, offset, &value->vValue.vt_array.vData, value->type, num);
		offset += len;
		break;
	}
	default:
		proto_item_append_text(ti_type, "|0x%x", highType);
	}
	proto_item_set_end(ti, tvb, offset);
	proto_item_set_end(ti_val, tvb, offset);

	proto_item_append_text(ti_val, " %s", str_CBaseStorageVariant(value, FALSE));
	proto_item_append_text(ti, " %s", str_CBaseStorageVariant(value, TRUE));

	return offset;
}

enum {
	DBKIND_GUID_NAME = 0,
	DBKIND_GUID_PROPID = 1
};

static int parse_CDbColId(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *text)
{
	guint32 eKind, ulId;
	e_guid_t guid;
	const char *str;
	static const char *KIND[] = {"DBKIND_GUID_NAME", "DBKIND_GUID_PROPID"};

	proto_item *tree_item;
	proto_tree *tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CDbColId, &tree_item, text);

	eKind = tvb_get_letohl(tvb, offset);
	str = (eKind < 2 ? KIND[eKind] : "???");
	proto_tree_add_string_format_value(tree, hf_mswsp_cdbcolid_ekind, tvb, offset, 4,  str, "%s (%u)", str, eKind);
	offset += 4;

	offset = parse_padding(tvb, offset, 8, pad_tree, "paddingGuidAlign");

	offset = parse_guid(tvb, offset, tree, &guid, "GUID");

	ulId = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cdbcolid_ulid, tvb, offset, 4, ulId);
	offset += 4;

	if (eKind == DBKIND_GUID_NAME) {
		char *name;
		int len = ulId;
		name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len, ENC_LITTLE_ENDIAN | ENC_UCS_2);
		proto_item_append_text(tree_item, " \"%s\"", name);
		proto_tree_add_string_format_value(tree, hf_mswsp_cdbcolid_vstring, tvb, offset, len, name, "\"%s\"", name);
		offset += len;
	} else if (eKind == DBKIND_GUID_PROPID) {
		proto_item_append_text(tree_item, " %08x", ulId);
	} else {
		proto_item_append_text(tree_item, "<INVALID>");
	}

	proto_item_set_end(tree_item, tvb, offset);

	return offset;
}

static int parse_CDbProp(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, struct GuidPropertySet *propset, const char *fmt, ...)
{
	static const value_string EMPTY_VS[] = {{0, NULL}};
	const value_string *vs = (propset && propset->id_map) ? propset->id_map : EMPTY_VS;
	guint32 id, opt, status;
	struct CBaseStorageVariant value;
	proto_item *item;
	proto_tree *tree;
	const char *str, *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CDbProp, &item, txt);

	id = tvb_get_letohl(tvb, offset);
	str = val_to_str(id, vs, "0x%08x");
	proto_tree_add_string_format_value(tree, hf_mswsp_cdbprop_id, tvb, offset, 4, str, "%s (0x%08x)", (str[0] == '0' ? "" : str), id);
	offset += 4;
	proto_item_append_text(item, " Id: %s", str);

	opt = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cdbprop_options, tvb, offset, 4, opt);
	offset += 4;

	status = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cdbprop_status, tvb, offset, 4, status);
	offset += 4;

	offset = parse_CDbColId(tvb, offset, tree, pad_tree, "colid");

	offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &value, "vValue");

	str = str_CBaseStorageVariant(&value, TRUE);
	proto_item_append_text(item, " %s", str);
	proto_item_set_end(item, tvb, offset);

	return offset;
}

static int parse_CDbPropSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	int i, num;
	e_guid_t guid;
	struct GuidPropertySet *pset;
	proto_item *item;
	proto_tree *tree;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CDbPropSet, &item, txt);

	offset = parse_guid(tvb, offset, tree, &guid, "guidPropertySet");

	pset = GuidPropertySet_find_guid(&guid);

	if (pset) {
		proto_item_append_text(item, " \"%s\" (%s)", pset->desc, pset->def);
	} else {
		const char *guid_str = guid_to_str(wmem_packet_scope(), &guid);
		proto_item_append_text(item, " {%s}", guid_str);
	}

	offset = parse_padding(tvb, offset, 4, pad_tree, "guidPropertySet");

	num = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cdbpropset_cprops, tvb, offset, 4,  num);
	offset += 4;
	proto_item_append_text(item, " Num: %d", num);

	for (i = 0; i<num; i++) {
		offset = parse_padding(tvb, offset, 4, pad_tree, "aProp[%d]", i);
		offset = parse_CDbProp(tvb, offset, tree, pad_tree, pset, "aProp[%d]", i);
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int parse_PropertySetArray(tvbuff_t *tvb, int offset, int size_offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	const int offset_in = offset;
	guint32 size, num;
	int i;
	proto_tree *tree;
	proto_item *item;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CDbPropSet_Array, &item, txt);

	size = tvb_get_letohl(tvb, size_offset);
	proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_Blob1, tvb,
						size_offset, 4, ENC_LITTLE_ENDIAN);

	num = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_PropSets_num, tvb,
						offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	for (i = 0; i < (int)num; i++) {
		offset = parse_CDbPropSet(tvb, offset, tree, pad_tree, "PropertySet[%d]", i);
	}

	proto_item_set_end(item, tvb, offset);
	DISSECTOR_ASSERT(offset - offset_in == (int)size);
	return offset;
}

int parse_CColumnSet(tvbuff_t *tvb, int offset, proto_tree *tree, const char *fmt, ...)
{
	guint32 count, v, i;
	proto_item *item;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	count = tvb_get_letohl(tvb, offset);
	offset += 4;
	proto_tree_add_subtree(tree, tvb, offset, count * 4, ett_mswsp_uin32_array, &item, txt);
	proto_item_append_text(item, " Count %u [", count);

	for (i=0; i<count; i++) {
		v = tvb_get_letohl(tvb, offset);
		offset += 4;
		if (i>0) {
			proto_item_append_text(item, ",%u", v);
		} else {
			proto_item_append_text(item, "%u", v);
		}
	}
	proto_item_append_text(item, "]");
	return offset;
}

/* 2.2.1.23 RANGEBOUNDARY */
int parse_RANGEBOUNDARY(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	guint32 ulType;
	guint8 labelPresent;
	proto_item *item;
	proto_tree *tree;
	const char *txt;
	struct CBaseStorageVariant prval;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree =proto_tree_add_subtree (parent_tree, tvb, offset, 0, ett_RANGEBOUNDARY, &item, txt);

	ulType = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_mswsp_rangeboundry_ultype, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_item_append_text(item, ": Type 0x%08x", ulType);
	offset += 4;

	ZERO_STRUCT(prval);
	offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &prval, "prVal");

	labelPresent = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_mswsp_rangeboundry_labelpresent, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	if (labelPresent) {
		guint32 ccLabel;
		const guint8* label;
		offset = parse_padding(tvb, offset, 4, pad_tree, "paddingLabelPresent");

		ccLabel = tvb_get_letohl(tvb, offset);
		proto_tree_add_item_ret_uint(tree, hf_mswsp_rangeboundry_cclabel, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ccLabel);
		offset += 4;

		proto_tree_add_item_ret_string(tree, hf_mswsp_rangeboundry_label, tvb, offset, 2*ccLabel, ENC_LITTLE_ENDIAN | ENC_UCS_2, wmem_packet_scope(), &label);
		proto_item_append_text(item, " Label: \"%s\"", label);
		offset += 2*ccLabel;
	}

	proto_item_append_text(item, " Val: %s", str_CBaseStorageVariant(&prval, TRUE));

	proto_item_set_end(item, tvb, offset);
	return offset;
}


/* 2.2.1.22 CRangeCategSpec */
int parse_CRangeCategSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	proto_item *item;
	proto_tree *tree;
	va_list ap;
	unsigned i;
	const char *txt;
	guint32 cRange;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRangeCategSpec, &item, txt);

	offset = parse_lcid(tvb, offset, tree, "lcid");

	cRange = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_crangecategspec_crange, tvb, offset, 4, cRange);
	offset += 4;

	for (i=0; i<cRange; i++) {
		offset = parse_RANGEBOUNDARY(tvb, offset, tree, pad_tree, "aRangeBegin[%u]", i);

	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.21 CCategSpec */
int parse_CCategSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	proto_item *item;
	proto_tree *tree;

	va_list ap;
	guint32 type;
	const char *txt;
	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CCategSpec, &item, txt);

	type = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_ccategspec_type, tvb, offset, 4, type);
	proto_item_append_text(item, " Type %u", type);
	offset += 4;

	offset = parse_CSort(tvb, offset, tree, pad_tree, "CSort");

	offset = parse_CRangeCategSpec(tvb, offset, tree, pad_tree, "CRangeCategSpec");

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.25 CAggregSpec */
static int parse_CAggregSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	proto_item *item;
	proto_tree *tree;
	va_list ap;
	guint8 type;
	guint32 ccAlias, idColumn;
	const char *txt;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CAggregSpec, &item, txt);

	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_caggregspec_type, tvb, offset, 1, type);
	proto_item_append_text(item, "type: %u", type);
	offset += 1;

	offset = parse_padding(tvb, offset, 4, pad_tree, "padding");

	ccAlias = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_caggregspec_ccalias, tvb, offset, 1, ccAlias);
	offset += 4;

	proto_tree_add_item(tree, hf_mswsp_caggregspec_alias, tvb, offset, 2*ccAlias, ENC_LITTLE_ENDIAN | ENC_UCS_2);
	offset += 2*ccAlias;

	idColumn = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_caggregspec_idcolumn, tvb, offset, 1, idColumn);
	offset += 4;
	/* Optional ???
	   ulMaxNumToReturn, idRepresentative;
	*/

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.24 CAggregSet */
static int parse_CAggregSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	guint32 cCount, i;
	proto_item *item;
	proto_tree *tree;
	const char *txt;

	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CAggregSet, &item, txt);

	cCount = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_caggregset_count, tvb, offset, 4, cCount);
	offset += 4;

	for (i=0; i<cCount; i++) {
		/* 2.2.1.25 CAggregSpec */
		offset = parse_CAggregSpec(tvb, offset, tree, pad_tree, "AggregSpecs[%u]", i);
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.27 CAggregSortKey */
static int parse_CAggregSortKey(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	guint32 order;
	proto_item *item;
	proto_tree *tree;
	const char *txt;

	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CAggregSortKey, &item, txt);

	order = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_caggregsortkey_order, tvb, offset, 4, order);
	offset += 4;

	offset = parse_CAggregSpec(tvb, offset, tree, pad_tree, "ColumnSpec");

	proto_item_set_end(item, tvb, offset);
	return offset;
}


/* 2.2.1.26 CSortAggregSet */
static int parse_CSortAggregSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	guint32 cCount, i;
	proto_item *item;
	proto_tree *tree;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CSortAggregSet, &item, txt);

	cCount = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_csortaggregset_count, tvb, offset, 4, cCount);
	offset += 4;

	for (i=0; i<cCount; i++) {
		/* 2.2.1.27 CAggregSortKey */
		offset = parse_CAggregSortKey(tvb, offset, tree, pad_tree, "SortKeys[%u]", i);
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

enum CInGroupSortAggregSet_type {
	GroupIdDefault = 0x00, /* The default for all ranges. */
	GroupIdMinValue = 0x01, /*The first range in the parent's group.*/
	GroupIdNull = 0x02, /*The last range in the parent's group.*/
	GroupIdValue = 0x03
};

static int parse_CInGroupSortAggregSet_type(tvbuff_t *tvb, int offset, proto_tree *tree, enum CInGroupSortAggregSet_type *type)
{
	guint8 tmp = tvb_get_guint8(tvb, offset);
	switch(tmp) {
		case GroupIdDefault:
			*type = GroupIdDefault;
			break;
		case GroupIdMinValue:
			*type = GroupIdMinValue;
			break;
		case GroupIdNull:
			*type = GroupIdNull;
			break;
		case GroupIdValue:
			*type = GroupIdValue;
			break;
		default:
			DISSECTOR_ASSERT(FALSE);
			break;
	}
	proto_tree_add_uint(tree, hf_mswsp_cingroupsortaggregset_type, tvb, offset, 1, *type);
	return offset + 1;
}

/* 2.2.1.29 CInGroupSortAggregSet */
static int parse_CInGroupSortAggregSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	proto_item *item;
	proto_tree *tree;
	va_list ap;
	enum CInGroupSortAggregSet_type type;
	const char *txt;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CInGroupSortAggregSet, &item, txt);

	offset = parse_CInGroupSortAggregSet_type(tvb, offset, tree, &type);
	offset = parse_padding(tvb, offset, 4, pad_tree, "CInGroupSortAggregSet");

	if (type == GroupIdValue) {
		struct CBaseStorageVariant id;
		offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &id, "inGroupId");
	}

	offset = parse_CSortSet(tvb, offset, tree, pad_tree, "SortSet");

	proto_item_set_end(item, tvb, offset);
	return offset;
}


/* 2.2.1.28 CInGroupSortAggregSets */
static int parse_CInGroupSortAggregSets(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	guint32 cCount, i;
	proto_item *item;
	proto_tree *tree;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CInGroupSortAggregSets, &item, txt);

	cCount = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cingroupsortaggregsets_count, tvb, offset, 4, cCount);
	offset += 4;

	for (i=0; i<cCount; i++) {
		/* 2.2.1.29 CInGroupSortAggregSet */
		offset = parse_CInGroupSortAggregSet(tvb, offset, tree, pad_tree, "SortSets[%u]", i);
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.20 CCategorizationSpec */
int parse_CCategorizationSpec(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	proto_item *item;
	proto_tree *tree;
	const char *txt;

	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CCategorizationSpec, &item, txt);

	/* 2.2.1.18  CColumnSet */
	offset = parse_CColumnSet(tvb, offset, tree, "csColumns");

	/* 2.2.1.21 CCategSpec */
	offset = parse_CCategSpec(tvb, offset, tree, pad_tree, "Spec");

	/* 2.2.1.24 CAggregSet */
	offset = parse_CAggregSet(tvb, offset, tree, pad_tree, "AggregSet");

	/* 2.2.1.26 CSortAggregSet */
	offset = parse_CSortAggregSet(tvb, offset, tree, pad_tree, "SortAggregSet");

	/* 2.2.1.28 CInGroupSortAggregSets */
	offset = parse_CInGroupSortAggregSets(tvb, offset, tree, pad_tree, "InGroupSortAggregSets");

	proto_tree_add_item(tree, hf_mswsp_categorizationspec_cmaxres, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static const int *mswsp_bool_options[] = {
	&hf_mswsp_bool_options_cursor,
	&hf_mswsp_bool_options_async,
	&hf_mswsp_bool_options_firstrows,
	&hf_mswsp_bool_options_holdrows,
	&hf_mswsp_bool_options_chaptered,
	&hf_mswsp_bool_options_useci,
	&hf_mswsp_bool_options_defertrim,
	&hf_mswsp_bool_options_rowsetevents,
	&hf_mswsp_bool_options_dontcomputeexpensive,
	NULL
};

int parse_CRowsetProperties(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree _U_, const char *fmt, ...)
{
	proto_item *item;
	proto_tree *tree;
	const char *txt;

	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);

	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRowsetProperties, &item, txt);

	proto_tree_add_bitmask_with_flags(tree, tvb, offset,
hf_mswsp_bool_options, ett_mswsp_bool_options, mswsp_bool_options, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);

	offset += 4;

	proto_tree_add_item(tree, hf_mswsp_crowsetprops_ulmaxopenrows, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mswsp_crowsetprops_ulmemusage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mswsp_crowsetprops_cmaxresults, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mswsp_crowsetprops_ccmdtimeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_item_set_end(item, tvb, offset);
	return offset;
}

int parse_CPidMapper(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	proto_item *item;
	proto_tree *tree;
	va_list ap;
	guint32 count, i;
	const char *txt;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CPidMapper, &item, txt);

	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_cpidmapper_count, tvb, offset, 4, count);
	offset += 4;

	offset = parse_padding(tvb, offset, 8, pad_tree, "CPidMapper_PropSpec");

	for (i=0; i<count; i++) {
		struct CFullPropSpec v;
		ZERO_STRUCT(v);
		/*at begin or end of loop???*/
		offset = parse_padding(tvb, offset, 4, pad_tree,
							   "CPidMapper_PropSpec[%u]", i);
		offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v, "PropSpec[%u]", i);
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.35 CColumnGroup */
int parse_CColumnGroup(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree _U_, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item, *ti;
	va_list ap;
	const char *txt;
	guint32 count, groupPid, i;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CColumnGroup, &item, txt);

	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_ccolumngroup_count, tvb, offset, 4, count);
	offset += 4;

	groupPid = tvb_get_letohl(tvb, offset);
	ti = proto_tree_add_uint(tree, hf_mswsp_ccolumngroup_grouppid, tvb, offset, 4, groupPid);
	if ((0xFFFF0000 & groupPid) == 0x7FFF0000) {
		proto_item_append_text(ti, " Idx: %u", groupPid & 0xFFFF);
	} else {
		proto_item_append_text(ti, "<Invalid>");
	}
	offset += 4;

	for (i=0; i<count; i++) {
		/* 2.2.1.36 SProperty */
		guint32 pid, weight;
		pid = tvb_get_letohl(tvb, offset);
		weight = tvb_get_letohl(tvb, offset + 4);
		proto_tree_add_uint_format(tree, hf_mswsp_ccolumngroup_pid, tvb, offset, 8, pid, "Props[%u]: pid: %u weight: %u", i, pid, weight);
		offset += 8;
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.34 CColumnGroupArray */
int parse_CColumnGroupArray(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	va_list ap;
	const char *txt;

	guint32 count, i;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CColumnGroupArray, &item, txt);

	count = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_mswsp_ccolumngrouparray_count, tvb, offset, 4, count);
	offset += 4;

	for (i=0; i<count; i++) {
		offset = parse_padding(tvb, offset, 4, pad_tree, "aGroupArray[%u]", i);
		offset = parse_CColumnGroup(tvb, offset, tree, pad_tree, "aGroupArray[%u]", i);
	}

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int parse_UInt32Array(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint32 count, const char *item_name, const char *fmt, ...)
{
	guint32 v, i;
	proto_tree *tree;
	proto_item *item;
	const char *txt;

	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_Array, &item, txt);

	for (i=0; i<count; i++) {
		v = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint_format(tree, hf_mswsp_int32array_value, tvb, offset, 4, v, "%s[%u] = %u", item_name,i, v);
		offset += 4;
	}
	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.40 CRowSeekNext */
static int parse_CRowSeekNext(tvbuff_t *tvb, int offset, proto_tree *parent_tree, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRowsSeekNext, &item, txt);

	proto_tree_add_item(tree, hf_mswsp_crowseeknext_cskip, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_item_set_end(item, tvb, offset);
	return offset;
}


/* 2.2.1.37 CRowSeekAt */
static int parse_CRowSeekAt(tvbuff_t *tvb, int offset, proto_tree *parent_tree, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	va_list ap;
	const char *txt;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRowsSeekAt, &item, txt);

	proto_tree_add_item(tree, hf_mswsp_crowseekat_bmkoffset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;


	proto_tree_add_item(tree, hf_mswsp_crowseekat_skip, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mswsp_crowseekat_hregion, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.38 CRowSeekAtRatio */
static int parse_CRowSeekAtRatio(tvbuff_t *tvb, int offset, proto_tree *parent_tree, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	va_list ap;
	const char *txt;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRowsSeekAtRatio, &item, txt);

	proto_tree_add_item(tree, hf_mswsp_crowseekatratio_ulnumerator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;


	proto_tree_add_item(tree, hf_mswsp_crowseekatratio_uldenominator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_mswsp_crowseekatratio_hregion, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_item_set_end(item, tvb, offset);
	return offset;
}

/* 2.2.1.39 CRowSeekByBookmark */
static int parse_CRowSeekByBookmark(tvbuff_t *tvb, int offset, proto_tree *parent_tree, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	guint32 num;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRowsSeekByBookmark, &item, txt);

	num =  tvb_get_letohl(tvb,offset);
	proto_tree_add_item(tree, hf_mswsp_crowseekbybookmark_cbookmarks, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	offset = parse_UInt32Array(tvb, offset, tree, num, "abookmark", "abookmarks");

	num =  tvb_get_letohl(tvb,offset);
	proto_tree_add_item(tree, hf_mswsp_crowseekbybookmark_maxret, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	offset = parse_UInt32Array(tvb, offset, tree, num, "ascret", "ascret");

	proto_item_set_end(item, tvb, offset);
	return offset;
}

static int get_fixed_vtype_dataize(enum vType vtype)
{
	struct vtype_data *vt_type = vType_get_type(vtype);
	if (vt_type) {
		return vt_type->size;
	}
	return -1;
}

static int parse_CRowVariantArrayInfo(tvbuff_t *tvb, int offset, proto_tree *tree, gboolean is_64bit, struct CRowVariant *variant)
{
	if (is_64bit) {
		variant->content.array_vector.i64.count =
					tvb_get_letoh64(tvb, offset);
		proto_tree_add_uint64(tree, hf_mswsp_crowvariantinfo_count64, tvb, offset, 8, variant->content.array_vector.i64.count);
		offset += 8;
		variant->content.array_vector.i64.array_address = tvb_get_letoh64(tvb, offset);
		proto_tree_add_uint64(tree, hf_mswsp_arrayvector_address64, tvb, offset, 8, variant->content.array_vector.i64.array_address);
		offset += 8;

	} else {
		variant->content.array_vector.i32.count =
					tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_crowvariantinfo_count32, tvb, offset, 4, variant->content.array_vector.i32.count );
		offset += 4;
		variant->content.array_vector.i32.array_address = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_arrayvector_address32, tvb, offset, 4, variant->content.array_vector.i32.array_address);
		offset += 4;
	}
	return offset;
}

static int parse_VariantColVector(tvbuff_t *tvb, int offset, proto_tree *tree, guint64 base_address, gboolean is_64bit, struct CRowVariant *variant)
{
	guint32 i = 0;
	guint64 count = 0;
	int buf_offset = 0;
	proto_tree *sub_tree;
	struct vtype_data *vt_list_type =
		vType_get_type((enum vType)(variant->vtype & 0x00FF));
	wmem_strbuf_t *strbuf;

	DISSECTOR_ASSERT(vt_list_type != NULL);
	offset = parse_CRowVariantArrayInfo(tvb, offset, tree, is_64bit, variant);
	if (is_64bit) {
		buf_offset =
			(int)(variant->content.array_vector.i64.array_address - base_address);
		count = variant->content.array_vector.i64.count;
	} else {
		buf_offset =
			(int)(variant->content.array_vector.i32.array_address - base_address);
		count = variant->content.array_vector.i32.count;
	}
	sub_tree = proto_tree_add_subtree(tree, tvb, buf_offset, 0, ett_CRowVariant_Vector, NULL, "values");
	for (i = 0; i < count; i++) {
		guint64 item_address = 0;
		gint address_of_address = 0;
		int size;
		union vt_single value;
		int len;
		if (is_64bit) {
			size = 8;
			address_of_address = buf_offset + (i * size);
			item_address = tvb_get_letoh64(tvb, address_of_address);
			proto_tree_add_uint64_format(sub_tree, hf_mswsp_rowvariant_item_address64, tvb, address_of_address, size, item_address, "address[%d] 0x%" G_GINT64_MODIFIER "x", i, item_address);
		} else {
			size = 4;
			item_address = tvb_get_letohl(tvb, buf_offset + (i * size));
			proto_tree_add_uint_format(sub_tree, hf_mswsp_rowvariant_item_address32, tvb, address_of_address, size, (guint32)item_address, "address[%d] 0x%x", i, (guint32)item_address);
		}
		strbuf = wmem_strbuf_new(wmem_packet_scope(), "");
		if (vt_list_type->size == -1) {
			/* dynamic type */
			DISSECTOR_ASSERT_HINT(vt_list_type->tvb_get_value_only != 0,
								  "appears this is a vector of dynamic types that we don't know yet how to handle, please submit a bug with trace");
			len = vt_list_type->tvb_get_value_only(tvb, (int)(item_address - base_address), 0, &value);
			vt_list_type->strbuf_append(strbuf, &value);
		} else {
			/*
			 * assume non dynamic size types are stored directly.
			 * Note: not test as not seen in the wild.
			 */
			len = vt_list_type->size;
			DISSECTOR_ASSERT_HINT(vt_list_type->tvb_get != 0,
					      "appears this is a vector of fixed types that we don't know yet how to handle, please submit a bug with trace");

			vt_list_type->tvb_get(tvb, (int)(item_address - base_address), &value);
			vt_list_type->strbuf_append(strbuf, &value);
		}
		proto_tree_add_string(sub_tree, hf_mswsp_rowvariant_item_value, tvb, (gint)(item_address - base_address), len, wmem_strbuf_get_str(strbuf));
	}
	return offset;
}

static int parse_VariantCol(tvbuff_t *tvb, int offset, proto_tree *parent_tree, guint64 base_address, guint32 length _U_, gboolean is_64bit, struct CRowVariant *variant, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;

	va_list ap;
	struct vtype_data *vt_type;
	const char *modifier = "", *txt;
	int size;
	guint16 vtype_high;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_CRowVariant, &item, txt);

	variant->vtype = tvb_get_letohs(tvb, offset);
	vt_type = vType_get_type((enum vType)variant->vtype);
	DISSECTOR_ASSERT(vt_type != NULL);

	vtype_high = (variant->vtype & 0xFF00);
	if (vtype_high) {
		if (vtype_high == VT_VECTOR) {
			modifier = "|VT_VECTOR";
		} else if (vtype_high == VT_ARRAY) {
			modifier = "|VT_ARRAY";
		} else {
			modifier = "|Unknown, possibly error";
		}
	}

	proto_tree_add_string_format_value(tree, hf_mswsp_rowvariant_vtype, tvb, offset, 2, vt_type->str, "%s%s", vt_type->str, modifier);
	offset += 2;

	proto_tree_add_item(tree, hf_mswsp_rowvariant_reserved1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	variant->reserved1 = tvb_get_letohs(tvb, offset);

	offset += 2;
	proto_tree_add_item(tree, hf_mswsp_rowvariant_reserved2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	variant->reserved2 = tvb_get_letohl(tvb, offset);
	offset += 4;

	size = get_fixed_vtype_dataize((enum vType)(variant->vtype & 0x00FF));

	if (vtype_high == VT_VECTOR || vtype_high == VT_ARRAY) {
		offset = parse_VariantColVector(tvb, offset, tree, base_address,
										is_64bit, variant);
	} else {
		wmem_strbuf_t *strbuf = wmem_strbuf_new(wmem_packet_scope(), "");
		if (size != -1) {
			/* single fixed size value type */
			const char* desc = vt_type->str;

			DISSECTOR_ASSERT_HINT(vt_type->tvb_get != 0,
					      "appears fixed type that we don't know yet how to handle, please submit a bug with trace");
			vt_type->tvb_get(tvb, offset, &variant->content);
			vt_type->strbuf_append(strbuf, &variant->content);
			proto_tree_add_string_format_value(tree, hf_mswsp_rowvariant_item_value, tvb, offset, size, desc, "%s: %s", desc, wmem_strbuf_get_str(strbuf));
		} else {
			gint64 value_address;
			int buf_offset = offset;
			int len;
			union vt_single non_fixed_size_val;
			DISSECTOR_ASSERT_HINT(vt_type->tvb_get_value_only != 0, "appears this is a dynamic type that we don't know yet how to handle, please submit a bug with network trace");
			if (is_64bit) {
				variant->content.hyperw = tvb_get_letoh64(tvb, offset);
				offset += 8;
				value_address = variant->content.hyperw;
				proto_tree_add_uint64(tree, hf_mswsp_rowvariant_item_address64, tvb, buf_offset, 8, value_address);
			} else {
				variant->content.longw = tvb_get_letohl(tvb, offset);
				offset += 4;
				value_address = variant->content.longw;
				proto_tree_add_uint(tree, hf_mswsp_rowvariant_item_address32, tvb, buf_offset, 4, (guint32)value_address);
			}

			len = vt_type->tvb_get_value_only(tvb, (int)(value_address - base_address), 0, &non_fixed_size_val);
			vt_type->strbuf_append(strbuf, &non_fixed_size_val);
			proto_tree_add_string(tree, hf_mswsp_rowvariant_item_value, tvb, (gint)(value_address - base_address), len, wmem_strbuf_get_str(strbuf));
		}
	}

	return offset;
}

static int parse_RowsBufferCol(tvbuff_t *tvb, int offset, guint32 row, guint32 col, struct CPMSetBindingsIn *bindingsin, struct rows_data *rowsin, gboolean b_is_64bit, proto_tree *parent_tree, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	guint32 buf_start = offset;
	guint32 buf_offset = buf_start + (row * bindingsin->brow);
	struct CTableColumn *pcol = &bindingsin->acolumns[col];

	static const value_string STATUS[] = {
		{0, "StoreStatusOk"},
		{1, "StoreStatusDeferred"},
		{2, "StoreStatusNull"},
		{0, NULL}
	};

	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);
	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_GetRowsColumn, &item, txt);
    proto_item_append_text(item, " (%s)", pcol->name);
	if (pcol->statusused) {
		int tmp_offset = buf_offset + pcol->statusoffset;
		proto_tree_add_string(tree, hf_mswsp_ctablecolumn_status, tvb, tmp_offset, 1, val_to_str(tvb_get_guint8(tvb, tmp_offset), STATUS, "(Invalid: 0x%x)"));
	}
	if (pcol->lengthused) {
		int tmp_offset = buf_offset + pcol->lengthoffset;
		proto_tree_add_item(tree, hf_mswsp_ctablecolumn_length, tvb, tmp_offset, 1, ENC_LITTLE_ENDIAN);
	}
	if (pcol->valueused) {
		int tmp_offset = buf_offset + pcol->valueoffset;
		struct CRowVariant variant;
		guint32 len = pcol->valuesize;
		guint64 base_address = rowsin->ulclientbase;/*( + rowsin->cbreserved;*/
		ZERO_STRUCT(variant);

		if (pcol->lengthused) {
			len = tvb_get_letohs(tvb, buf_offset + pcol->lengthoffset) - pcol->valuesize;
		}
		if (pcol->vtype == VT_VARIANT) {
			parse_VariantCol(tvb, tmp_offset, tree, base_address, len, b_is_64bit, &variant, "CRowVariant");
		}
	}
	return offset;
}

static int parse_RowsBuffer(tvbuff_t *tvb, int offset, guint32 num_rows, struct CPMSetBindingsIn *bindingsin, struct rows_data *rowsin, gboolean is64bit, proto_tree *parent_tree, const char *fmt, ...)
{
	proto_tree *tree;
	proto_item *item;
	guint32 num;
	const char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = wmem_strdup_vprintf(wmem_packet_scope(), fmt, ap);
	va_end(ap);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0, ett_GetRowsRow, &item, txt);

	for (num = 0; num < num_rows; ++num) {
		guint32 col;
		proto_tree *row_tree;
		row_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_GetRowsRow, NULL, "Row[%d]", num);
		for (col = 0; col < bindingsin->ccolumns; col++) {
			parse_RowsBufferCol(tvb, offset, num, col, bindingsin, rowsin, is64bit, row_tree, "Col[%d]", col);
		}
	}
	return offset;
}
/* Code to actually dissect the packets */

static int dissect_CPMConnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *private_data)
{
	proto_item *ti;
	proto_tree *tree;
	gint offset = 16;
	guint len;
	guint32 version;
	struct message_data *data = NULL;
	struct mswsp_ct *ct = NULL;

	ti = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_mswsp_msg);
	proto_item_set_text(ti, "CPMConnect%s", in ? "In" : "Out");
	col_append_str(pinfo->cinfo, COL_INFO, "Connect");

	ti = proto_tree_add_item_ret_uint(tree, hf_mswsp_msg_Connect_Version, tvb,
							 offset, 4, ENC_LITTLE_ENDIAN, &version);

	ct = get_create_converstation_data(pinfo);

	if (ct) {
		data = find_or_create_message_data(ct, pinfo, 0xC8, in, private_data);
		if (data) {
			data->content.version = version;
		}
	}
	offset += 4;

	if (in) {
		guint32 blob_size1_off, blob_size2_off;
		proto_tree *pad_tree;

		pad_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mswsp_pad, &ti, "Padding");

		proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_ClientIsRemote, tvb,
							offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* _cbBlob1 */
		blob_size1_off = offset;
		offset += 4;

		offset = parse_padding(tvb, offset, 8, pad_tree, "_paddingcbBlob2");

		/* _cbBlob2 */
		blob_size2_off = offset;
		offset += 4;

		offset = parse_padding(tvb, offset, 16, pad_tree, "_padding");

		len = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_MachineName, tvb,
								 offset, len, ENC_LITTLE_ENDIAN | ENC_UCS_2);
		offset += len;

		len = tvb_unicode_strsize(tvb, offset);
		ti = proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_UserName, tvb,
								 offset, len, ENC_LITTLE_ENDIAN | ENC_UCS_2);
		offset += len;

		offset = parse_padding(tvb, offset, 8, pad_tree, "_paddingcPropSets");

		offset = parse_PropertySetArray(tvb, offset, blob_size1_off, tree, pad_tree, "PropSets");

		offset = parse_padding(tvb, offset, 8, pad_tree, "paddingExtPropset");

		offset = parse_PropertySetArray(tvb, offset, blob_size2_off, tree, pad_tree, "ExtPropset");

		offset = parse_padding(tvb, offset, 8, pad_tree, "???");

		DISSECTOR_ASSERT(offset == (int)tvb_reported_length(tvb));

		/* make "Padding" the last item */
		proto_tree_move_item(tree, ti, proto_tree_get_parent(pad_tree));
	} else {

	}
	return tvb_reported_length(tvb);
}

static int dissect_CPMDisconnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_, void *data _U_)
{
	col_append_str(pinfo->cinfo, COL_INFO, "Disconnect");
	return tvb_reported_length(tvb);
}

static int dissect_CPMCreateQuery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);

	proto_item_set_text(item, "CPMCreateQuery%s", in ? "In" : "Out");
	col_append_str(pinfo->cinfo, COL_INFO, "CreateQuery");

	if (in) {
		proto_item *ti;
		proto_tree *pad_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mswsp_pad, &ti, "Padding");
		guint8 CColumnSetPresent, CRestrictionPresent, CSortSetPresent, CCategorizationSetPresent;
		guint32 size = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_msg_cpmcreatequery_size, tvb, offset, 4, size);
		offset += 4;

		CColumnSetPresent = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcreatequery_ccolumnsetpresent, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		if (CColumnSetPresent) {
			offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCColumnSetPresent");
			offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCColumnSetPresent");
			offset = parse_CColumnSet(tvb, offset, tree, "CColumnSet");
		}

		CRestrictionPresent = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcreatequery_crestrictionpresent, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		if (CRestrictionPresent) {
			offset = parse_CRestrictionArray(tvb, offset, tree, pad_tree, "RestrictionArray");
		}

		CSortSetPresent = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcreatequery_csortpresent, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		if (CSortSetPresent) {
			offset = parse_padding(tvb, offset, 4, tree, "paddingCSortSetPresent");
			offset = parse_CInGroupSortAggregSets(tvb, offset, tree, pad_tree, "GroupSortAggregSets");

		}

		CCategorizationSetPresent = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcreatequery_ccategpresent, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		if (CCategorizationSetPresent) {
			guint32 count, i;
			offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCCategorizationSetPresent");
			/* 2.2.1.19 CCategorizationSet */
			count = tvb_get_letohl(tvb, offset);
			proto_tree_add_uint(tree, hf_mswsp_msg_cpmcreatequery_ccateg_count, tvb, offset, 4, count);
			offset += 4;
			for (i=0; i<count; i++) {
				offset = parse_CCategorizationSpec(tvb, offset, tree, pad_tree, "categories[%u]", i);
			}
		}

		offset = parse_padding(tvb, offset, 4, tree, "XXXX");

		offset = parse_CRowsetProperties(tvb, offset, tree, pad_tree, "RowSetProperties");

		offset = parse_CPidMapper(tvb, offset, tree, pad_tree, "PidMapper");

		parse_CColumnGroupArray(tvb, offset, tree, pad_tree, "GroupArray");
	} else { /* out */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcreatequery_trueseq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcreatequery_workid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		/*
		     * #FIXME Cursors is an array of uint32 where the size of the array is
		     * determined by categories in the CategorizationSet in the CPMQuery
		     * request message.
		     */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcreatequery_cursors, tvb, offset, -1, ENC_NA);
	}

	return tvb_reported_length(tvb);
}

static int dissect_CPMFreeCursor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_, void *data _U_)
{
	col_append_str(pinfo->cinfo, COL_INFO, "FreeCursor");
	return tvb_reported_length(tvb);
}

static int dissect_CPMGetRows(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *private_data)
{
	struct mswsp_ct *ct = NULL;
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;
	proto_tree *seek_tree;
	guint32 eType = 0;

	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, in ? 0 : -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);

	proto_item_set_text(item, "GetRows%s", in ? "In" : "Out");
	col_append_str(pinfo->cinfo, COL_INFO, "GetRows");

	ct = get_create_converstation_data(pinfo);
	if (in) {
		/* 2.2.3.11 */
		struct message_data *data = NULL;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_hcursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_rowstotransfer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_rowwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_cbseek, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		data = find_or_create_message_data(ct, pinfo, 0xCC, in, private_data);
		if (data) {
			data->content.rowsin.cbreserved = tvb_get_letohl(tvb, offset);
		}
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_cbreserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_cbreadbuffer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		if (data) {
			data->content.rowsin.ulclientbase = tvb_get_letohl(tvb, offset);
		}

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_ulclientbase, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_fbwdfetch, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		eType = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_etype, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_chapt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		seek_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_SeekDescription, NULL, "SeekDescription");
		switch (eType) {
		case 0: /* eRowSeekNone */
			break;
		case 1: /* eRowSeekNext */
			parse_CRowSeekNext(tvb, offset, seek_tree, "CRowSeekNext");
			break;
		case 2: /* eRowSeekAt */
			parse_CRowSeekAt(tvb, offset, seek_tree, "CRowSeekAt");

			break;
		case 3: /* eRowSeekAtRatio */
			parse_CRowSeekAtRatio(tvb, offset, seek_tree, "CRowSeekAtRatio");
			break;
		case 4: /* eRowSeekByBookmark */
			parse_CRowSeekByBookmark(tvb, offset, seek_tree, "CRowSeekByRatio");
			break;
		default: /*error*/
			break;
		}
	} else {
		/* 2.2.3.12 */
		/*
		 * GetRows response needs information from GetRow & SetBindings
		 * requests
		 */
		/* find the preceeding SetBinding data */
		guint32 num_rows = 0;
		proto_item *ti;
		proto_tree *pad_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mswsp_pad, &ti, "Padding");
		struct CPMSetBindingsIn *bindingsin = find_binding_msg_data(ct, pinfo,
											  private_data);
		struct rows_data *rowsin = find_rowsin_msg_data(ct, pinfo, private_data);
		gboolean b_64bit_mode = FALSE;
		gboolean b_has_arch = is_64bit_mode(ct, pinfo, &b_64bit_mode, private_data);
		num_rows = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_crowsreturned, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		eType = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_etype, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrows_chapt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		seek_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_SeekDescription, NULL, "SeekDescription");
		switch (eType) {
		case 0: /* eRowSeekNone */
			break;
		case 1: /* eRowSeekNext */
			parse_CRowSeekNext(tvb, offset, seek_tree, "CRowSeekNext");
			break;
		case 2: /* eRowSeekAt */
			parse_CRowSeekAt(tvb, offset, seek_tree, "CRowSeekAt");

			break;
		case 3: /* eRowSeekAtRatio */
			parse_CRowSeekAtRatio(tvb, offset, seek_tree, "CRowSeekAtRatio");
			break;
		case 4: /* eRowSeekByBookmark */
			parse_CRowSeekByBookmark(tvb, offset, seek_tree, "CRowSeekByRatio");
			break;
		default: /*error*/
			break;
		}

		if (b_has_arch && bindingsin && rowsin) {
			offset = parse_padding(tvb, offset, rowsin->cbreserved, pad_tree,
								   "paddingRows");
			parse_RowsBuffer(tvb, offset, num_rows, bindingsin, rowsin, b_64bit_mode, tree, "Rows");
		} else {
			gint nbytes = tvb_reported_length_remaining(tvb, offset);
			proto_tree_add_expert_format(tree, pinfo, &ei_missing_msg_context, tvb, offset, nbytes, "Undissected %d bytes (due to missing preceding msg(s))", nbytes);
		}
	}

	return tvb_reported_length(tvb);

}

static int dissect_CPMRatioFinished(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;
	col_append_str(pinfo->cinfo, COL_INFO, "RatioFinished");
	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);
	proto_item_set_text(item, "RationFinised%s", in ? "In" : "Out");
	if (in) {
		proto_tree_add_item(tree, hf_mswsp_msg_cpmratiofinished_hcursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmratiofinished_fquick, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_mswsp_msg_cpmratiofinished_ulnumerator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmratiofinished_uldenominator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmratiofinished_crows, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmratiofinished_fnewrows, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}

	return tvb_reported_length(tvb);
}

static int dissect_CPMCompareBmk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, in ? 0 : -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);

	proto_item_set_text(item, "CompareBmk%s", in ? "In" : "Out");
	col_append_str(pinfo->cinfo, COL_INFO, "CompareBmk");
	if (in) {
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcomparebmk_hcursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcomparebmk_chapt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcomparebmk_bmkfirst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcomparebmk_bmksecond, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcomparebmk_dwcomparison, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}
	return tvb_reported_length(tvb);
}

static int dissect_CPMGetApproximatePosition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, in ? 0 : -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);

	proto_item_set_text(item, "GetApproximatePosition%s", in ? "In" : "Out");
	col_append_str(pinfo->cinfo, COL_INFO, "GetApproximatePosition");
	if (in) {
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetapproxpos_hcursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetapproxpos_chapt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetapproxpos_bmk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetapproxpos_numerator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetapproxpos_denominator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}
	return tvb_reported_length(tvb);
}

/* 2.2.3.10 */
static int dissect_CPMSetBindings(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *private_data)
{
	gint offset = 16;
	struct CPMSetBindingsIn request;

	col_append_str(pinfo->cinfo, COL_INFO, "SetBindings");
	if (in) {

		struct mswsp_ct *ct = NULL;
		struct message_data *data = NULL;
		proto_item *ti;
		proto_tree *tree, *pad_tree;
		guint32 size, num, n;
		gint64 column_size;

		ti = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(ti, ett_mswsp_msg);

		proto_item_set_text(ti, "SetBindingsIn");

		pad_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mswsp_pad, &ti, "Padding");

		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetbinding_hcursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		request.hcursor = tvb_get_letohl(tvb, offset);
		offset += 4;
		request.brow = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetbinding_cbrow, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		size = tvb_get_letohl(tvb, offset);
		request.bbindingdesc = size;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetbinding_desc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		request.dummy = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetbinding_dummy, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		num = tvb_get_letohl(tvb, offset);
		request.ccolumns = num;
		ti = proto_tree_add_item(tree, hf_mswsp_msg_cpmsetbinding_ccolumns, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetbinding_acolumns, tvb, offset, size-4, ENC_NA);

		/* Sanity check size value */
		column_size = num*MIN_CTABLECOL_SIZE;
		if (column_size > tvb_reported_length_remaining(tvb, offset))
		{
			expert_add_info(pinfo, ti, &ei_mswsp_msg_cpmsetbinding_ccolumns);
			return tvb_reported_length(tvb);
		}

		ct = get_create_converstation_data(pinfo);

		request.acolumns = (struct CTableColumn*)wmem_alloc(wmem_file_scope(),
						   sizeof(struct CTableColumn) * num);
		for (n=0; n<num; n++) {
			offset = parse_padding(tvb, offset, 4, pad_tree, "padding_aColumns[%u]", n);
			offset = parse_CTableColumn(tvb, offset, tree, pad_tree, &request.acolumns[n],"aColumns[%u]", n);
		}
		data = find_or_create_message_data(ct, pinfo,0xD0,in, private_data);
		if (data) {
			data->content.bindingsin = request;
		}

	} else { /* server only returns status with header */
	}

	return tvb_reported_length(tvb);
}

static int dissect_CPMGetNotify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_, void *data _U_)
{
	col_append_str(pinfo->cinfo, COL_INFO, "GetNotify");
	return tvb_reported_length(tvb);
}

static int dissect_CPMSendNotifyOut(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in _U_, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	col_append_str(pinfo->cinfo, COL_INFO, "SendNotify");
	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);
	proto_item_set_text(item, "GetSendNotifyOut");
	proto_tree_add_item(tree, hf_mswsp_msg_cpmsendnotify_watchnotify, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	return tvb_reported_length(tvb);
}

static int dissect_CPMGetQueryStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);

	proto_item_set_text(item, "GetQueryStatus%s", in ? "In" : "Out");
	col_append_str(pinfo->cinfo, COL_INFO, "GetQueryStatus");

	if (in) {
		/* 2.2.3.7 */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetquerystatus_hcursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		/* 2.2.3.7 */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetquerystatus_qstatus, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}

	return tvb_reported_length(tvb);
}

static int dissect_CPMCiState(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	col_append_str(pinfo->cinfo, COL_INFO, "CiState");

	if (!in) {
		item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mswsp_msg);
		proto_item_set_text(item, "CiStateOut");
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cbstruct, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cwordlist, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cpersistindex, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cqueries, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cfreshtest, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cfreshtest, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_dwmergeprogress, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_estate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cfiltereddocs, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_ctotaldocs, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cpendingscans, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_dwindexsize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_cuniquekeys, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_csecqdocuments, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmcistate_dwpropcachesize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}
	return tvb_reported_length(tvb);
}

static int dissect_CPMFetchValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree, *pad_tree;
	col_append_str(pinfo->cinfo, COL_INFO, "FetchValue");

	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
	tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, 0, ett_mswsp_msg, &item, "FetchValue%s", in ? "In" : "Out");
	pad_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_mswsp_pad, NULL, "Padding");
	if (in) {
		struct CFullPropSpec prop;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmfetchvalue_wid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmfetchvalue_cbsofar, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmfetchvalue_cbpropspec, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmfetchvalue_cbchunk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &prop,
									 "PropSpec");
		parse_padding(tvb, offset, 4, pad_tree,"_padding");
	} else {
		guint32 cbValue = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_mswsp_msg_cpmfetchvalue_cbvalue, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmfetchvalue_fmoreexists, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmfetchvalue_fvalueexists, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmfetchvalue_vvalue, tvb, offset, cbValue, ENC_NA);
	}
	return tvb_reported_length(tvb);
}

static int dissect_CPMGetQueryStatusEx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);

	proto_item_set_text(item, "GetQueryStatusEx%s", in ? "In" : "Out");
	col_append_str(pinfo->cinfo, COL_INFO, "GetQueryStatusEx");

	if (in) {
		/* 2.2.3.8 */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_hcursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_bmk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	} else {
		/* 2.2.3.9 */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_qstatus, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_cfiltereddocs, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_cdocstofilter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_dwratiodenom, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_dwrationumer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_irowbmk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_crowstotal, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_maxrank, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_cresultsfound, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmquerystatusex_whereid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}
	return tvb_reported_length(tvb);
}

static int dissect_CPMRestartPosition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	col_append_str(pinfo->cinfo, COL_INFO, "CPMRestartPosition");

	if (in) {
		item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mswsp_msg);
		proto_item_set_text(item, "CPMRestartPosition");
		proto_tree_add_item(tree, hf_mswsp_msg_cpmrestartposition_hcursor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmrestartposition_chapt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}

	col_append_str(pinfo->cinfo, COL_INFO, "RestartPosition");
	return tvb_reported_length(tvb);
}

static int dissect_CPMSetCatState(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_, void *data _U_)
{
	col_append_str(pinfo->cinfo, COL_INFO, "SetCatState");
	return tvb_reported_length(tvb);
}

static int dissect_CPMGetRowsetNotify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;
	col_append_str(pinfo->cinfo, COL_INFO, "GetRowsetNotify");
	if (!in) {
		item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mswsp_msg);
		proto_item_set_text(item, "GetRowsetNotifyOut");
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrowsetnotify_wid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* moveevents */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrowsetnotify_moreevents, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		/*  eventType */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrowsetnotify_eventtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* rowSetItemState */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrowsetnotify_rowsetitemstate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* changedItemState */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrowsetnotify_changeditemstate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* rowSetEvent */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrowsetnotify_rowsetevent, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrowsetnotify_rowseteventdata1, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmgetrowsetnotify_rowseteventdata2, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		/* it seems there is an extra unknow 8 bytes following */
	}
	return tvb_reported_length(tvb);
}

static int dissect_CPMFindIndices(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;
	col_append_str(pinfo->cinfo, COL_INFO, "FindIndices");
	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);
	proto_item_set_text(item, "FindIndices%s", in ? "In" : "Out");

	if (in) {
		guint32 cWids;
		guint32 cDepthPrev;
		cWids = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_msg_cpmfindindices_cwids, tvb, offset, 4, cWids);
		offset += 4;
		cDepthPrev = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_msg_cpmfindindices_cdepthprev, tvb, offset, 4, cDepthPrev);
		offset += 4;
		offset = parse_uin32_array(tvb, offset, tree, cWids, "pwids");
		parse_uin32_array(tvb, offset, tree, cDepthPrev, "prgiRowPrev");
	} else {
		guint32 cDepthNext;
		cDepthNext = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_mswsp_msg_cpmfindindices_cdepthnext, tvb, offset, 4, cDepthNext);
		offset += 4;
		parse_uin32_array(tvb, offset, tree, cDepthNext, "prgiRowNext");
	}
	return tvb_reported_length(tvb);
}

static int dissect_CPMSetScopePrioritization(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{
	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	col_append_str(pinfo->cinfo, COL_INFO, "SetScopePrioritization");

	if (in) {
		item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mswsp_msg);
		proto_item_set_text(item, "SetScopePrioritizationIn");
		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetscopeprioritization_priority, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetscopeprioritization_eventfreq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}
	return tvb_reported_length(tvb);
}

static int dissect_CPMGetScopeStatistics(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in, void *data _U_)
{

	gint offset = 16;
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, in ? 0 : -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_mswsp_msg);

	proto_item_set_text(item, "GetScopeStatistics%s", in ? "In" : "Out");
	col_append_str(pinfo->cinfo, COL_INFO, "GetScopeStatistics");

	if (in) {
		/* 2.2.3.33 */
	} else {
		/* 2.2.3.34 */
		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetscopestatisics_dwindexitems, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetscopestatisics_dwoutstandingadds, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_mswsp_msg_cpmsetscopestatisics_dwoutstandingmodifies, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}

	return tvb_reported_length(tvb);
}


static const value_string msg_ids[] = {
	{0x000000C8, "CPMConnect"},                /* In/Out */
	{0x000000C9, "CPMDisconnect"},
	{0x000000CA, "CPMCreateQuery"},            /* In/Out */
	{0x000000CB, "CPMFreeCursor"},             /* In/Out */
	{0x000000CC, "CPMGetRows"},                /* In/Out */
	{0x000000CD, "CPMRatioFinished"},          /* In/Out */
	{0x000000CE, "CPMCompareBmk"},             /* In/Out */
	{0x000000CF, "CPMGetApproximatePosition"}, /* In/Out */
	{0x000000D0, "CPMSetBindingsIn"},
	{0x000000D1, "CPMGetNotify"},
	{0x000000D2, "CPMSendNotifyOut"},
	{0x000000D7, "CPMGetQueryStatusIn"},       /* In/Out */
	{0x000000D9, "CPMCiStateInOut"},
	{0x000000E4, "CPMFetchValue"},             /* In/Out */
	{0x000000E7, "CPMGetQueryStatusEx"},       /* In/Out */
	{0x000000E8, "CPMRestartPositionIn"},
	{0x000000EC, "CPMSetCatStateIn"},          /* (not supported) */
	{0x000000F1, "CPMGetRowsetNotify"},        /* In/Out */
	{0x000000F2, "CPMFindIndices"},            /* In/Out */
	{0x000000F3, "CPMSetScopePrioritization"}, /* In/Out */
	{0x000000F4, "CPMGetScopeStatistics"},     /* In/Out */
	{0, NULL}
};


static int
dissect_mswsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean in, void *data)
{
	proto_tree *mswsp_tree = NULL;
	proto_tree *hdr_tree;
	proto_item *ti, *hti;
	guint32 msg;
	guint32 status;


	if (tvb_reported_length(tvb) < 16) {
		return 0;
	}

	/* col_set_str(pinfo->cinfo, COL_PROTOCOL, "MS-WSP"); */
	col_append_str(pinfo->cinfo, COL_PROTOCOL, " WSP");
	/*    col_clear(pinfo->cinfo, COL_INFO); */

	col_set_str(pinfo->cinfo, COL_INFO, "WSP ");
	col_append_str(pinfo->cinfo, COL_INFO, in ? "Request: " : "Response: ");

	ti = proto_tree_add_item(tree, proto_mswsp, tvb, 0, -1, ENC_NA);
	mswsp_tree = proto_item_add_subtree(ti, ett_mswsp);

	hti = proto_tree_add_item(mswsp_tree, hf_mswsp_hdr, tvb, 0, 16, ENC_NA);
	hdr_tree = proto_item_add_subtree(hti, ett_mswsp_hdr);

	proto_tree_add_item_ret_uint(hdr_tree, hf_mswsp_hdr_msg, tvb,
						0, 4, ENC_LITTLE_ENDIAN, &msg);
	proto_item_append_text(hti, " %s", val_to_str(msg, VALS(msg_ids),
						   "(Unknown: 0x%x)"));

	proto_tree_add_item_ret_uint(hdr_tree, hf_mswsp_hdr_status, tvb,
						4, 4, ENC_LITTLE_ENDIAN, &status);
	if (!in || status != 0) {
		proto_item_append_text(hti, " %s",
							   val_to_str(status, VALS(dcom_hresult_vals),
										  "(Unknown: 0x%x)"));
	}

	proto_tree_add_checksum(hdr_tree, tvb, 8, hf_mswsp_hdr_checksum, -1, NULL, pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
	/* todo: validate checksum */

	proto_tree_add_item(hdr_tree, hf_mswsp_hdr_reserved, tvb,
						12, 4, ENC_LITTLE_ENDIAN);


	switch(msg) {
	case 0xC8:
		dissect_CPMConnect(tvb, pinfo, tree, in, data);
		break;
	case 0xC9:
		dissect_CPMDisconnect(tvb, pinfo, tree, in, data);
		break;
	case 0xCA:
		dissect_CPMCreateQuery(tvb, pinfo, tree, in, data);
		break;
	case 0xCB:
		dissect_CPMFreeCursor(tvb, pinfo, tree, in, data);
		break;
	case 0xCC:
		dissect_CPMGetRows(tvb, pinfo, tree, in, data);
		break;
	case 0xCD:
		dissect_CPMRatioFinished(tvb, pinfo, tree, in, data);
		break;
	case 0xCE:
		dissect_CPMCompareBmk(tvb, pinfo, tree, in, data);
		break;
	case 0xCF:
		dissect_CPMGetApproximatePosition(tvb, pinfo, tree, in, data);
		break;
	case 0xD0:
		dissect_CPMSetBindings(tvb, pinfo, tree, in, data);
		break;
	case 0xD1:
		dissect_CPMGetNotify(tvb, pinfo, tree, in, data);
		break;
	case 0xD2:
		dissect_CPMSendNotifyOut(tvb, pinfo, tree, in, data);
		break;
	case  0xD7:
		dissect_CPMGetQueryStatus(tvb, pinfo, tree, in, data);
		break;
	case  0xD9:
		dissect_CPMCiState(tvb, pinfo, tree, in, data);
		break;
	case  0xE4:
		dissect_CPMFetchValue(tvb, pinfo, tree, in, data);
		break;
	case  0xE7:
		dissect_CPMGetQueryStatusEx(tvb, pinfo, tree, in, data);
		break;
	case  0xE8:
		dissect_CPMRestartPosition(tvb, pinfo, tree, in, data);
		break;
	case  0xEC:
		 dissect_CPMSetCatState(tvb, pinfo, tree, in, data);
		break;
	case  0xF1:
		dissect_CPMGetRowsetNotify(tvb, pinfo, tree, in, data);
		break;
	case  0xF2:
		dissect_CPMFindIndices(tvb, pinfo, tree, in, data);
		break;
	case  0xF3:
		dissect_CPMSetScopePrioritization(tvb, pinfo, tree, in, data);
		break;
	case  0xF4:
		dissect_CPMGetScopeStatistics(tvb, pinfo, tree, in, data);
		break;
	default:
		return 0;
	}

	/* Return the amount of data this dissector was able to dissect */
	return tvb_reported_length(tvb);
}


void
proto_register_mswsp(void)
{
	expert_module_t* expert_mswsp = NULL;
	static hf_register_info hf[] = {
		{
			&hf_mswsp_hdr,
			{
				"Header", "mswsp.hdr",
				FT_NONE, BASE_NONE, NULL, 0,
				"Message header", HFILL
			}
		},
		{
			&hf_mswsp_hdr_msg,
			{
				"Msg id", "mswsp.hdr.id",
				FT_UINT32, BASE_HEX, VALS(msg_ids), 0,
				"Message id", HFILL
			}
		},
		{
			&hf_mswsp_hdr_status,
			{
				"Status", "mswsp.hdr.status",
				FT_UINT32, BASE_HEX, VALS(dcom_hresult_vals), 0,
				"Message Status", HFILL
			}
		},
		{
			&hf_mswsp_hdr_checksum,
			{
				"checksum", "mswsp.hdr.checksum",
				FT_UINT32, BASE_HEX, NULL, 0,
				"Message Checksum", HFILL
			}
		},
		{
			&hf_mswsp_hdr_reserved,
			{
				"Reserved", "mswsp.hdr.reserved",
				FT_UINT32, BASE_HEX, NULL, 0,
				"Reserved bytes", HFILL
			}
		},
		{
			&hf_mswsp_msg,
			{
				"msg", "mswsp.msg",
				FT_NONE, BASE_NONE, NULL, 0,
				"Message", HFILL
			}
		},
		{
			&hf_mswsp_msg_Connect_Version,
			{
				"Version", "mswsp.Connect.version",
				FT_UINT32, BASE_HEX, VALS(version_vals), 0,
				"OS Version", HFILL
			}
		},
		{
			&hf_mswsp_msg_ConnectIn_ClientIsRemote,
			{
				"Remote", "mswsp.ConnectIn.isRemote",
				FT_BOOLEAN, BASE_HEX, NULL, 0,
				"Client is remote",HFILL
			}
		},
		{
			&hf_mswsp_msg_ConnectIn_Blob1,
			{
				"Size", "mswsp.ConnectIn.propset.size",
				FT_UINT32, BASE_DEC, NULL, 0,
				"Size of PropSet fields",HFILL
			}
		},
		{
			&hf_mswsp_msg_ConnectIn_MachineName,
			{
				"Remote machine", "mswsp.ConnectIn.machine",
				FT_STRINGZ, BASE_NONE, NULL, 0,
				"Name of remote machine",HFILL
			}
		},
		{
			&hf_mswsp_msg_ConnectIn_UserName,
			{
				"User", "mswsp.ConnectIn.user",
				FT_STRINGZ, BASE_NONE, NULL, 0,
				"Name of remote user",HFILL
			}
		},
		{
			&hf_mswsp_msg_ConnectIn_PropSets_num,
			{
				"Num", "mswsp.ConnectIn.propset.num",
				FT_UINT32, BASE_DEC, NULL, 0,
				"Number of Property Sets", HFILL
			}
		},
		{
			&hf_mswsp_bool_options,
			{
				"uBooleanOptions", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions",
				FT_UINT32, BASE_HEX, NULL, 0, "Boolean options", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_cursor,
			{
				"Cursor", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions", FT_UINT32,
				BASE_HEX, VALS(cursor_vals), 0x0000000007, "Cursor Type", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_async,
			{
				"eAsynchronous", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions.eAsyncronous",
				FT_BOOLEAN, 32, NULL, eAsynchronous, "The client will not wait for execution completion", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_firstrows,
			{
				"eFirstRows", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions.eFirstRows",
				FT_BOOLEAN, 32, NULL, eFirstRows, "Return the first rows encountered, not the best matches.", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_holdrows,
			{
				"eHoldRows", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions.eHoldRows",
				FT_BOOLEAN, 32, NULL, eHoldRows, "The server MUST NOT discard rows until the client is done with a query.", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_chaptered,
			{
				"eChaptered", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions.eChaptered",
				FT_BOOLEAN, 32, NULL, eChaptered, "The rowset supports chapters.", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_useci,
			{
				"eUseCI", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions.eUseCI",
				FT_BOOLEAN, 32, NULL, eUseCI, "Use the inverted index to evaluate content restrictions even if it is out of date.", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_defertrim,
			{
				"eDeferTrimming", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions.eDeferTrimming",
				FT_BOOLEAN, 32, NULL, eDeferTrimming, "Defer Non-indexed trimming operations like scoping or security checking which can be expensive.", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_rowsetevents,
			{
				"eEnableRowsetEvents", "mswsp.RowSetProperties.CPMCreateQuery.uBooleanOptions.eEnableRowsetEvents",
				FT_BOOLEAN, 32, NULL, eEnableRowsetEvents, "Enables storage of rowset events on the server side.", HFILL
			}
		},
		{
			&hf_mswsp_bool_options_dontcomputeexpensive,
			{
				"eDoNotComputeExpensiveProps", "mswsp.CPMCreateQuery.RowSetProperties.uBooleanOptions.eDoNotComputeExpensiveProps",
				FT_BOOLEAN, 32, NULL, eDoNotComputeExpensiveProps, "Prevents computation of expensive properties.", HFILL
			}
		},
		{
			&hf_mswsp_guid_time_low,
			{
				"time-low", "mswsp.guid.time_low",
				FT_UINT32, BASE_HEX, NULL, 0, "time low value", HFILL
			}
		},
		{
			&hf_mswsp_guid_time_mid,
			{
				"time-mid", "mswsp.guid.time_mid",
				FT_UINT16, BASE_HEX, NULL, 0, "time mid value", HFILL
			}
		},
		{
			&hf_mswsp_guid_time_high,
			{
				"time-high", "mswsp.guid.time_high",
				FT_UINT16, BASE_HEX, NULL, 0, "time high value", HFILL
			}
		},
		{
			&hf_mswsp_guid_time_clock_hi,
			{
				"clock_seq_hi_and_reserved", "mswsp.guid.time_clock_high",
				FT_UINT8, BASE_HEX, NULL, 0, "time clock high value", HFILL
			}
		},
		{
			&hf_mswsp_guid_time_clock_low,
			{
				"clock_seq_low", "mswsp.guid.time_clock_low",
				FT_UINT8, BASE_HEX, NULL, 0, "time clock high low", HFILL
			}
		},
		{
			&hf_mswsp_guid_node,
			{
				"node", "mswsp.guid.node",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_lcid,
			{
				"lcid", "mswsp.lcid",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_lcid_sortid,
			{
				"Sort ID", "mswsp.lcid.sortid",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_lcid_langid,
			{
				"Language ID", "mswsp.lcid.langid",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cscort_column,
			{
				"column", "mswsp.csort.column",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cscort_order,
			{
				"order", "mswsp.csort.order",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cscort_individual,
			{
				"inidvidual", "mswsp.csort.individual",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cscortset_count,
			{
				"count", "mswsp.csortset.count",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_vtype,
			{
				"vType", "mswsp.ctablecolumn.vtype",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_aggused,
			{
				"AggreagateUsed", "mswsp.ctablecolumn.aggused",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_aggtype,
			{
				"AggreagateType", "mswsp.ctablecolumn.aggtype",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_valused,
			{
				"ValueUsed", "mswsp.ctablecolumn.valused",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_valoffset,
			{
				"ValueOffset", "mswsp.ctablecolumn.valused",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_valsize,
			{
				"ValueSize", "mswsp.ctablecolumn.valsize",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_statused,
			{
				"StatusUsed", "mswsp.ctablecolumn.statused",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_statoffset,
			{
				"StatusOffset", "mswsp.ctablecolumn.statoffset",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_lenused,
			{
				"LengthUsed", "mswsp.ctablecolumn.lenused",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_lenoffset,
			{
				"LengthOffset", "mswsp.ctablecolumn.lenoffset",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cfullpropspec_kind,
			{
				"ulKind", "mswsp.cfullpropspec.kind",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cfullpropspec_propid,
			{
				"propid", "mswsp.cfullpropspec.propid",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cfullpropspec_propname,
			{
				"propname", "mswsp.cfullpropspec.propname",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cproprestrict_relop,
			{
				"relop", "mswsp.cproprestrict.relop",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccoercerestrict_value,
			{
				"value", "mswsp.ccoercerestrict.value",
				FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccontentrestrict_cc,
			{
				"cc", "mswsp.ccontentrestrict.cc",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccontentrestrict_phrase,
			{
				"phrase", "mswsp.ccontentrestrict.phrase",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccontentrestrict_method,
			{
				"method", "mswsp.ccontentrestrict.method",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_natlangrestrict_cc,
			{
				"cc", "mswsp.ccontentrestrict.cc",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_natlangrestrict_phrase,
			{
				"phrase", "mswsp.ccontentrestrict.phrase",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crestrict_ultype,
			{
				"ulType", "mswsp.crestrict.ultype",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crestrict_weight,
			{
				"Weight", "mswsp.crestrict.weight",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crestrictarray_count,
			{
				"count", "mswsp.crestrictarray.count",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crestrictarray_present,
			{
				"present", "mswsp.crestrictarray.present",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cnoderestrict_cnode,
			{
				"Weight", "mswsp.cnoderestrict.cnode",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_vtype,
			{
				"vType", "mswsp.cbasestorvariant.vtype",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_vvalue,
			{
				"vValue", "mswsp.cbasestorvariant.vvalue",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_vdata1,
			{
				"vData1", "mswsp.cbasestorvariant.vdata1",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_vdata2,
			{
				"vData2", "mswsp.cbasestorvariant.vdata2",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_num,
			{
				"num", "mswsp.cbasestorvariant.num",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_cdims,
			{
				"cDims", "mswsp.cbasestorvariant.cdims",
				FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_ffeatures,
			{
				"fFeatures", "mswsp.cbasestorvariant.ffeatures",
				FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_cbelements,
			{
				"cbElements", "mswsp.cbasestorvariant.cbelements",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cbasestorvariant_rgsabound,
			{
				"Rgsabound", "mswsp.cbasestorvariant.rgsabound",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cdbcolid_ekind,
			{
				"eKind", "mswsp.cdbcolid.ekind",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cdbcolid_ulid,
			{
				"ulId", "mswsp.cdbcolid.ulid",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cdbcolid_vstring,
			{
				"vString", "mswsp.cdbcolid.vstring",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cdbprop_id,
			{
				"Id", "mswsp.cdbprop.id",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cdbprop_options,
			{
				"Options", "mswsp.cdbprop.options",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cdbprop_status,
			{
				"Status", "mswsp.cdbprop.status",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cdbpropset_cprops,
			{
				"cProperties", "mswsp.cdbpropset.cprops",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rangeboundry_ultype,
			{
				"ulType", "mswsp.rangeboundry.ultype",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rangeboundry_labelpresent,
			{
				"labelPresent", "mswsp.rangeboundry.labelpresent",
				FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rangeboundry_cclabel,
			{
				"ccLabel", "mswsp.rangeboundry.cclabel",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rangeboundry_label,
			{
				"Label", "mswsp.rangeboundry.label",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crangecategspec_crange,
			{
				"cRange", "mswsp.crangecategspec.crange",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccategspec_type,
			{
				"type", "mswsp.ccategspec.type",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_caggregspec_type,
			{
				"type", "mswsp.caggregspec.type",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_caggregspec_ccalias,
			{
				"ccAlias", "mswsp.caggregspec.ccalias",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_caggregspec_alias,
			{
				"Alias", "mswsp.caggregspec.alias",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_caggregspec_idcolumn,
			{
				"idColumn", "mswsp.caggregspec.idcolumn",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_caggregset_count,
			{
				"count", "mswsp.caggregset.count",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_caggregsortkey_order,
			{
				"order", "mswsp.caggregsortkey.order",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_csortaggregset_count,
			{
				"count", "mswsp.csortaggregset.count",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cingroupsortaggregset_type,
			{
				"Type", "mswsp.cingroupsortaggregset.type",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cingroupsortaggregsets_count,
			{
				"count", "mswsp.cingroupsortaggregsets.count",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_categorizationspec_cmaxres,
			{
				"cMaxResults", "mswsp.categorizationspec.cmaxres",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowsetprops_ulmaxopenrows,
			{
				"ulMaxOpenRows (ignored)", "mswsp.crowsetprops.ulmaxopenrows",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowsetprops_ulmemusage,
			{
				"ulMemUsage (ignored)", "mswsp.crowsetprops.ulmemusage",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowsetprops_cmaxresults,
			{
				"cMaxResults", "mswsp.crowsetprops.cmaxresults",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowsetprops_ccmdtimeout,
			{
				"cCmdTimeout", "mswsp.crowsetprops.ccmdtimeout",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_cpidmapper_count,
			{
				"count", "mswsp.cpidmapper.count",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccolumngroup_count,
			{
				"count", "mswsp.ccolumngroup.count",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccolumngroup_grouppid,
			{
				"groupPid", "mswsp.ccolumngroup.grouppid",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccolumngroup_pid,
			{
				"pid", "mswsp.ccolumngroup.pid",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ccolumngrouparray_count,
			{
				"count", "mswsp.ccolumngrouparray.count",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_int32array_value,
			{
				"value", "mswsp.int32array.value",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseeknext_cskip,
			{
				"cskip", "mswsp.crowseeknext.cskip",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseekat_bmkoffset,
			{
				"bmkoffset", "mswsp.crowseekat.bmkoffset",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseekat_skip,
			{
				"skip", "mswsp.crowseekat.skip",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseekat_hregion,
			{
				"hregion", "mswsp.crowseekat.hregion",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseekatratio_ulnumerator,
			{
				"ulnumerator", "mswsp.crowseekatratio.ulnumerator",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseekatratio_uldenominator,
			{
				"uldenominator", "mswsp.crowseekatratio.uldenominator",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseekatratio_hregion,
			{
				"hregion", "mswsp.crowseekatratio.hregion",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseekbybookmark_cbookmarks,
			{
				"cbookmarks", "mswsp.crowseekbybookmark.cbookmarks",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowseekbybookmark_maxret,
			{
				"maxret", "mswsp.crowseekbybookmark.maxret",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowvariantinfo_count64,
			{
				"count", "mswsp.crowvariantinfo.count64",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_arrayvector_address64,
			{
				"address of array", "mswsp.arrayvector.address64",
				FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_crowvariantinfo_count32,
			{
				"count", "mswsp.crowvariantinfo.count32",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_arrayvector_address32,
			{
				"address of array", "mswsp.arrayvector.address",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rowvariant_item_address64,
			{
				"address", "mswsp.rowvariant.item.address64",
				FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rowvariant_item_address32,
			{
				"address", "mswsp.rowvariant.item.address32",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rowvariant_item_value,
			{
				"value", "mswsp.rowvariant.item.value",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rowvariant_vtype,
			{
				"vtype", "mswsp.rowvariant.vtype",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rowvariant_reserved1,
			{
				"reserved1", "mswsp.rowvariant.reserved1",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_rowvariant_reserved2,
			{
				"reserved2", "mswsp.rowvariant.reserved2",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_status,
			{
				"status", "mswsp.ctablecolumn.name",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_ctablecolumn_length,
			{
				"length", "mswsp.ctablecolumn.length",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_size,
			{
				"size", "mswsp.cpmcreatequery.size",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_ccolumnsetpresent,
			{
				"CColumnSetPresent", "mswsp.cpmcreatequery.ccolumnsetpresent",
				FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_crestrictionpresent,
			{
				"CRestrictionPresent", "mswsp.cpmcreatequery.crestrictionpresent",
				FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_csortpresent,
			{
				"CSortPresent", "mswsp.cpmcreatequery.csortpresent",
				FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_ccategpresent,
			{
				"CCategorizationSetPresent", "mswsp.cpmcreatequery.ccategpresent",
				FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_ccateg_count,
			{
				"count", "mswsp.cpmcreatequery.ccateg.count",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_trueseq,
			{
				"TrueSequential", "mswsp.cpmcreatequery.trueseq",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_workid,
			{
				"WorkId", "mswsp.cpmcreatequery.trueseq",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcreatequery_cursors,
			{
				"Cursors", "mswsp.cpmcreatequery.cursors",
				FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_hcursor,
			{
				"hCursor", "mswsp.msg.cpmgetrows.hcursor",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_rowstotransfer,
			{
				"cRowsToTransfer", "mswsp.msg.cpmgetrows.rowstotransfer",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_rowwidth,
			{
				"cbRowWidth", "mswsp.msg.cpmgetrows.rowswidth",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_cbseek,
			{
				"cbSeek", "mswsp.msg.cpmgetrows.cbseek",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_cbreserved,
			{
				"cbReserved", "mswsp.msg.cpmgetrows.cbreserved",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_cbreadbuffer,
			{
				"cbReadBuffer", "mswsp.msg.cpmgetrows.cbreadbuffer",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_ulclientbase,
			{
				"ulClientBase", "mswsp.msg.cpmgetrows.ulclientbase",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_fbwdfetch,
			{
				"fBwdFetch", "mswsp.msg.cpmgetrows.fbwdfetch",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_etype,
			{
				"eType", "mswsp.msg.cpmgetrows.etype",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_chapt,
			{
				"chapt", "mswsp.msg.cpmgetrows.chapt",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrows_crowsreturned,
			{
				"cRowsReturned", "mswsp.msg.cpmgetrows.crowsreturned",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmratiofinished_hcursor,
			{
				"hCursor", "mswsp.msg.cpmratiofinished_hcursor",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmratiofinished_fquick,
			{
				"fQuick", "mswsp.msg.cpmratiofinished_fquick",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmratiofinished_ulnumerator,
			{
				"ulNumerator", "mswsp.msg.cpmratiofinished_ulnumerator",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmratiofinished_uldenominator,
			{
				"ulDenominator", "mswsp.msg.cpmratiofinished_uldenominator",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmratiofinished_crows,
			{
				"cRows", "mswsp.msg.cpmratiofinished_crows",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmratiofinished_fnewrows,
			{
				"fNewRows", "mswsp.msg.cpmratiofinished_fnewrows",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcomparebmk_hcursor,
			{
				"hCursor", "mswsp.msg.cpmcomparebmk.hcursor",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcomparebmk_chapt,
			{
				"chapt", "mswsp.msg.cpmcomparebmk.chapt",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcomparebmk_bmkfirst,
			{
				"bmkFirst", "mswsp.msg.cpmcomparebmk.bmkfirst",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcomparebmk_bmksecond,
			{
				"bmkSecond", "mswsp.msg.cpmcomparebmk.bmksecond",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcomparebmk_dwcomparison,
			{
				"dwComparison", "mswsp.msg.cpmcomparebmk.dwcomparison",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetapproxpos_hcursor,
			{
				"hCursor", "mswsp.msg.cpmgetapproxpos.hcursor",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetapproxpos_chapt,
			{
				"chapt", "mswsp.msg.cpmgetapproxpos.chapt",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetapproxpos_bmk,
			{
				"bmk", "mswsp.msg.cpmgetapproxpos.bmk",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetapproxpos_numerator,
			{
				"numerator", "mswsp.msg.cpmgetapproxpos.numerator",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetapproxpos_denominator,
			{
				"denominator", "mswsp.msg.cpmgetapproxpos.denominator",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetbinding_hcursor,
			{
				"hCursor", "mswsp.msg.cpmsetbinding.hcursor",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetbinding_cbrow,
			{
				"cBrow", "mswsp.msg.cpmsetbinding.cbrow",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetbinding_desc,
			{
				"cbBindingDesc", "mswsp.msg.cpmsetbinding.desc",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetbinding_dummy,
			{
				"dummy", "mswsp.msg.cpmsetbinding.dummy",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetbinding_ccolumns,
			{
				"cColumns", "mswsp.msg.cpmsetbinding.ccolumns",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetbinding_acolumns,
			{
				"aColumns", "mswsp.msg.cpmsetbinding.acolumns",
				FT_BYTES, SEP_DOT, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsendnotify_watchnotify,
			{
				"watchNotify", "mswsp.msg.cpmsendnotify.watchnotify",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetquerystatus_hcursor,
			{
				"hCursor", "mswsp.msg.cpmquerystatus.hcursor",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetquerystatus_qstatus,
			{
				"QStatus", "mswsp.msg.cpmquerystatus.qstatus",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_cbstruct,
			{
				"cbStruct", "mswsp.msg.cpmcistate.cbstruct",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_cwordlist,
			{
				"cbWordList", "mswsp.msg.cpmcistate.cbwordlist",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_cpersistindex,
			{
				"cbPersistentIndex", "mswsp.msg.cpmcistate.cbpersistindex",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_cqueries,
			{
				"cQueries", "mswsp.msg.cpmcistate.cqueries",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_cfreshtest,
			{
				"cFreshTest", "mswsp.msg.cpmcistate.cfreshtest",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_dwmergeprogress,
			{
				"dwMergeProgress", "mswsp.msg.cpmcistate.dwmergeprogress",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_estate,
			{
				"eState", "mswsp.msg.cpmcistate.estate",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_cfiltereddocs,
			{
				"cFilteredDocuments", "mswsp.msg.cpmcistate.cfiltereddocs",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_ctotaldocs,
			{
				"cTotalDocuments", "mswsp.msg.cpmcistate.ctotaldocs",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_cpendingscans,
			{
				"cPendingScans", "mswsp.msg.cpmcistate.cpendingscans",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_dwindexsize,
			{
				"dwIndexSize", "mswsp.msg.cpmcistate.dwindexsize",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_cuniquekeys,
			{
				"cUniqueKeys", "mswsp.msg.cpmcistate.cuniquekeys",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_csecqdocuments,
			{
				"cSecQDocuments", "mswsp.msg.cpmcistate.csecqdocuments",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmcistate_dwpropcachesize,
			{
				"dwPropCacheSize", "mswsp.msg.cpmcistate.dwpropcachesize",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfetchvalue_wid,
			{
				"wid", "mswsp.msg.cpmfetchvalue.wid",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfetchvalue_cbsofar,
			{
				"cbSoFar", "mswsp.msg.cpmfetchvalue.cbsofar",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfetchvalue_cbpropspec,
			{
				"cbPropSpec", "mswsp.msg.cpmfetchvalue.cbpropspec",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfetchvalue_cbchunk,
			{
				"cbChunk", "mswsp.msg.cpmfetchvalue.chunk",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfetchvalue_cbvalue,
			{
				"cbValue", "mswsp.msg.cpmfetchvalue.cbvalue",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfetchvalue_fmoreexists,
			{
				"fMoreExists", "mswsp.msg.cpmfetchvalue.fmoreexists",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfetchvalue_fvalueexists,
			{
				"fValueExists", "mswsp.msg.cpmfetchvalue.fvalueexists",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfetchvalue_vvalue,
			{
				"vvalue", "mswsp.msg.cpmfetchvalue.vvalue",
				FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_qstatus,
			{
				"qStatus", "mswsp.msg.cpmquerystatusex.qstatus",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_hcursor,
			{
				"hCursor", "mswsp.msg.cpmquerystatusex.hcursor",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_bmk,
			{
				"bmk", "mswsp.msg.cpmquerystatusex.bmk",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_cfiltereddocs,
			{
				"cFilteredDocuments", "mswsp.msg.cpmquerystatusex.cfiltereddocs",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_cdocstofilter,
			{
				"cDocumentsToFilter", "mswsp.msg.cpmquerystatusex.cdocstofilter",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_dwratiodenom,
			{
				"dwRatioFinishedDenomenator", "mswsp.msg.cpmquerystatusex.dwratiodenom",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_dwrationumer,
			{
				"dwRatioFinishedNumerator", "mswsp.msg.cpmquerystatusex.dwrationumer",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_irowbmk,
			{
				"iRowBmk", "mswsp.msg.cpmquerystatusex.irowbmk",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_crowstotal,
			{
				"cRowsTotal", "mswsp.msg.cpmquerystatusex.crowstotal",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_maxrank,
			{
				"maxRank", "mswsp.msg.cpmquerystatusex.maxrank",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_cresultsfound,
			{
				"cResultsFound", "mswsp.msg.cpmquerystatusex.cresultsfound",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmquerystatusex_whereid,
			{
				"whereId", "mswsp.msg.cpmquerystatusex.whereid",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmrestartposition_hcursor,
			{
				"hCursor", "mswsp.msg.cpmrestartposition.hcursor",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmrestartposition_chapt,
			{
				"chapt", "mswsp.msg.cpmrestartposition.chapt",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrowsetnotify_wid,
			{
				"wid", "mswsp.msg.cpmgetrowsetnotify.wid",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrowsetnotify_moreevents,
			{
				"moreEvents", "mswsp.msg.cpmgetrowsetnotify.moreevents",
				FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrowsetnotify_eventtype,
			{
				"eventType", "mswsp.msg.cpmgetrowsetnotify.eventType",
				FT_UINT8, BASE_DEC, NULL, 0xFE, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrowsetnotify_rowsetitemstate,
			{
				"rowSetItemState", "mswsp.msg.cpmgetrowsetnotify.rowsetitemstate",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrowsetnotify_changeditemstate,
			{
				"changedItemState", "mswsp.msg.cpmgetrowsetnotify.changeditemState",
				FT_UINT8, BASE_DEC, NULL, 0, 0, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrowsetnotify_rowsetevent,
			{
				"rowSetEvent", "mswsp.msg.cpmgetrowsetnotify.rowsetevent",
				FT_UINT8, BASE_DEC, NULL, 0, 0, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrowsetnotify_rowseteventdata1,
			{
				"rowSetEventdata1", "mswsp.msg.cpmgetrowsetnotify.rowseteventdata1",
				FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmgetrowsetnotify_rowseteventdata2,
			{
				"rowSetEventdata2", "mswsp.msg.cpmgetrowsetnotify.rowseteventdata2",
				FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfindindices_cwids,
			{
				"cWids", "mswsp.msg.cpmfindindices.cwids",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfindindices_cdepthprev,
			{
				"cDepthPrev", "mswsp.msg.cpmfindindices.cdepthprev",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmfindindices_cdepthnext,
			{
				"cDepthNext", "mswsp.msg.cpmfindindices.cdepthnext",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetscopeprioritization_priority,
			{
				"priority", "mswsp.msg.cpmsetscopeprioritization.priority",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetscopeprioritization_eventfreq,
			{
				"eventFrequency", "mswsp.msg.cpmsetscopeprioritization.eventfreq",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetscopestatisics_dwindexitems,
			{
				"dwIndexedItems", "mswsp.msg.cpmsetscopestatistics.dwindexitems",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetscopestatisics_dwoutstandingadds,
			{
				"dwOutstandingAdds", "mswsp.msg.cpmsetscopestatistics.dwoutstandingadds",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_mswsp_msg_cpmsetscopestatisics_dwoutstandingmodifies,
			{
				"dwOutstandingModifies", "mswsp.msg.cpmsetscopestatistics.dwoutstandingmodifies",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		}
	};

	static gint *ett[] = {
		&ett_mswsp,
		&ett_mswsp_hdr,
		&ett_mswsp_msg,
		&ett_mswsp_pad,
		&ett_mswsp_property_restriction,
		&ett_CRestrictionArray,
		&ett_CBaseStorageVariant,
		&ett_CBaseStorageVariant_Vector,
		&ett_CBaseStorageVariant_Array,
		&ett_CDbColId,
		&ett_GUID,
		&ett_CDbProp,
		&ett_CDbPropSet,
		&ett_CDbPropSet_Array,
		&ett_CRestriction,
		&ett_CNodeRestriction,
		&ett_CPropertyRestriction,
		&ett_CCoercionRestriction,
		&ett_CContentRestriction,
		&ett_RANGEBOUNDARY,
		&ett_CRangeCategSpec,
		&ett_CCategSpec,
		&ett_CAggregSpec,
		&ett_CAggregSet,
		&ett_CCategorizationSpec,
		&ett_CAggregSortKey,
		&ett_CSortAggregSet,
		&ett_CInGroupSortAggregSet,
		&ett_CInGroupSortAggregSets,
		&ett_CRowsetProperties,
		&ett_CFullPropSpec,
		&ett_CPidMapper,
		&ett_CSort,
		&ett_CSortSet,
		&ett_CNatLanguageRestriction,
		&ett_CColumnGroup,
		&ett_CColumnGroupArray,
		&ett_LCID,
		&ett_CTableColumn,
		&ett_Array,
		&ett_SeekDescription,
		&ett_CRowsSeekNext,
		&ett_CRowsSeekAt,
		&ett_CRowsSeekAtRatio,
		&ett_CRowsSeekByBookmark,
		&ett_GetRowsRow,
		&ett_GetRowsColumn,
		&ett_CRowVariant,
		&ett_CRowVariant_Vector,
		&ett_mswsp_bool_options,
		&ett_mswsp_uin32_array,
		&ett_mswsp_msg_padding,
		&ett_mswsp_msg_creusewhere
	};

	static ei_register_info ei[] = {
		{ &ei_missing_msg_context, { "mswsp.msg.cpmgetrows.missing_msg_context", PI_SEQUENCE, PI_WARN, "previous messages needed for context not captured", EXPFILL }},
		{ &ei_mswsp_msg_cpmsetbinding_ccolumns, { "mswsp.msg.cpmsetbinding.ccolumns.invalude", PI_PROTOCOL, PI_WARN, "Invalid number of cColumns for packet", EXPFILL }}
	};
	int i;

	proto_mswsp = proto_register_protocol("Windows Search Protocol",
										  "MS-WSP", "mswsp");

	proto_register_field_array(proto_mswsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mswsp = expert_register_protocol(proto_mswsp);
	expert_register_field_array(expert_mswsp, ei, array_length(ei));
	for (i=0; i<(int)array_length(GuidPropertySet); i++) {
		guids_add_guid(&GuidPropertySet[i].guid, GuidPropertySet[i].def);
	}
}

static int dissect_mswsp_smb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	smb_info_t *si = (smb_info_t*)data;
	gboolean in = si->request;

	smb_fid_info_t *fid_info = NULL;
	fid_info = find_fid_info(si);

	if (!fid_info || !fid_info->fsi || !fid_info->fsi->filename) {
		return 0;
	}


	if (g_ascii_strcasecmp(fid_info->fsi->filename, "\\MsFteWds") != 0) {
		return 0;
	}
	p_add_proto_data(wmem_file_scope(), pinfo, proto_mswsp, 0, (void*)&SMB1);
	return dissect_mswsp(tvb, pinfo, tree, in, data);
}


static int dissect_mswsp_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	smb2_info_t *si = (smb2_info_t*)data;
	gboolean in;
	char* fid_name = NULL;
	guint32     open_frame = 0, close_frame = 0;

	if (!si) {
		return 0;
	}

	if (si->saved) {
		dcerpc_fetch_polhnd_data(&si->saved->policy_hnd, &fid_name, NULL, &open_frame, &close_frame, pinfo->num);
	}

	if (!fid_name || strcmp(fid_name, "File: MsFteWds") != 0) {
		return 0;
	}

	in = !(si->flags & SMB2_FLAGS_RESPONSE);
	p_add_proto_data(wmem_file_scope(), pinfo, proto_mswsp, 0, (void*)&SMB2);
	return dissect_mswsp(tvb, pinfo, tree, in, data);
}

void
proto_reg_handoff_mswsp(void)
{
	heur_dissector_add("smb_transact", dissect_mswsp_smb, "WSP over SMB1", "smb1_wsp", proto_mswsp, HEURISTIC_ENABLE);
	heur_dissector_add("smb2_pipe_subdissectors", dissect_mswsp_smb2, "WSP over SMB2", "smb2_wsp", proto_mswsp, HEURISTIC_ENABLE);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
