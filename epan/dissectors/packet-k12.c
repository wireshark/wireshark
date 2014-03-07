/* packet-k12.c
* Helper-dissector for Tektronix k12xx-k15xx .rf5 file type
*
* Luis E. Garcia Ontanon <luis@ontanon.org>
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998
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
#include "config.h"

#include <errno.h>
#include <glib.h>
#include <string.h>
#include <wsutil/str_util.h>
#include <epan/packet.h>
#include <wsutil/pint.h>
#include <epan/conversation.h>
#include <prefs.h>
#include <wiretap/wtap.h>
#include <epan/emem.h>
#include <epan/wmem/wmem.h>
#include <epan/uat.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include "packet-sscop.h"
#include "packet-umts_fp.h"

void proto_reg_handoff_k12(void);
void proto_register_k12(void);

typedef struct _k12_hdls_t {
	char* match;
	char* protos;
	dissector_handle_t* handles;
} k12_handles_t;

static int proto_k12 = -1;

static int hf_k12_port_id = -1;
static int hf_k12_port_name = -1;
static int hf_k12_stack_file = -1;
static int hf_k12_port_type = -1;
static int hf_k12_atm_vp = -1;
static int hf_k12_atm_vc = -1;
static int hf_k12_atm_cid = -1;

static int hf_k12_ts = -1;

static gint ett_k12 = -1;
static gint ett_port = -1;
static gint ett_stack_item = -1;

static expert_field ei_k12_unmatched_stk_file = EI_INIT;

static dissector_handle_t k12_handle;
static dissector_handle_t data_handle;
static dissector_handle_t sscop_handle;
static dissector_handle_t fp_handle;

extern int proto_sscop;
extern int proto_fp;

static wmem_tree_t* port_handles = NULL;
static uat_t* k12_uat = NULL;
static k12_handles_t* k12_handles = NULL;
static guint nk12_handles = 0;

static const value_string  k12_port_types[] = {
	{ K12_PORT_DS1,		"Ds1" },
	{ K12_PORT_DS0S,	"Ds0 Range" },
	{ K12_PORT_ATMPVC,	"ATM PVC" },
	{ 0,			NULL }
};

static void
fill_fp_info(fp_info *p_fp_info, guchar *extra_info, guint32 length)
{
	guint adj = 0;
			/* 0x11=control frame 0x30=data frame */
	guint info_type = pntoh16(extra_info);
			/* 1=FDD, 2=TDD 3.84, 3=TDD 1.28 */
	guchar radio_mode = extra_info[14];
	guchar channel_type = 0;
	guint i;

	if (!p_fp_info || length < 22)
		return;

	/* Store division type */
	p_fp_info->division = (enum division_type)radio_mode;

	/* Format used by K15, later fields are shifted by 8 bytes. */
	if (pntoh16(extra_info+2) == 5)
		adj = 8;

	p_fp_info->iface_type = IuB_Interface;

	p_fp_info->release = 0;       /* dummy */
	p_fp_info->release_year = 0;  /* dummy */
	p_fp_info->release_month = 0; /* dummy */

				/* 1=UL, 2=DL */
	if (extra_info[15] == 1)
		p_fp_info->is_uplink = 1;
	else
		p_fp_info->is_uplink = 0;

	if (info_type == 0x11) /* control frame */
		channel_type = extra_info[21 + adj];
	else if (info_type == 0x30) /* data frame */
		channel_type = extra_info[22 + adj];

	switch (channel_type) {
		case 1:
			p_fp_info->channel = CHANNEL_BCH;
			break;
		case 2:
			p_fp_info->channel = CHANNEL_PCH;
			p_fp_info->paging_indications = 0; /* dummy */
			break;
		case 3:
			p_fp_info->channel = CHANNEL_CPCH;
			break;
		case 4:
			if (radio_mode == 1)
				p_fp_info->channel = CHANNEL_RACH_FDD;
			else if (radio_mode == 2)
				p_fp_info->channel = CHANNEL_RACH_TDD;
			else
				p_fp_info->channel = CHANNEL_RACH_TDD_128;
			break;
		case 5:
			if (radio_mode == 1)
				p_fp_info->channel = CHANNEL_FACH_FDD;
			else
				p_fp_info->channel = CHANNEL_FACH_TDD;
			break;
		case 6:
			if (radio_mode == 2)
				p_fp_info->channel = CHANNEL_USCH_TDD_384;
			else
				p_fp_info->channel = CHANNEL_USCH_TDD_128;
			break;
		case 7:
			if (radio_mode == 1)
				p_fp_info->channel = CHANNEL_DSCH_FDD;
			else
				p_fp_info->channel = CHANNEL_DSCH_TDD;
			break;
		case 8:
			p_fp_info->channel = CHANNEL_DCH;
			break;
	}

	p_fp_info->dch_crc_present = 2; /* information not available */

	if (info_type == 0x30) { /* data frame */
		p_fp_info->num_chans = extra_info[23 + adj];
		/* For each channel */
		for (i = 0; i < (guint)p_fp_info->num_chans && (36+i*104+adj) <= length; ++i) {
			/* Read TB size */
			p_fp_info->chan_tf_size[i] = pntoh32(extra_info+28+i*104+adj);
			if (p_fp_info->chan_tf_size[i])
				/* Work out number of TBs on this channel */
				p_fp_info->chan_num_tbs[i] = pntoh32(extra_info+32+i*104+adj)
							     / p_fp_info->chan_tf_size[i];
		}
	}
}

static void
dissect_k12(tvbuff_t* tvb,packet_info* pinfo,proto_tree* tree)
{
	static dissector_handle_t data_handles[] = {NULL,NULL};
	proto_item* k12_item;
	proto_tree* k12_tree;
	proto_item* stack_item;
	dissector_handle_t sub_handle = NULL;
	dissector_handle_t* handles;
	guint i;

	k12_item = proto_tree_add_protocol_format(tree, proto_k12, tvb, 0, 0,
						  "Packet from: '%s' (0x%.8x)",
						  pinfo->pseudo_header->k12.input_name,
						  pinfo->pseudo_header->k12.input);

	k12_tree = proto_item_add_subtree(k12_item, ett_k12);

	proto_tree_add_uint(k12_tree, hf_k12_port_id, tvb, 0,0,pinfo->pseudo_header->k12.input);
	proto_tree_add_string(k12_tree, hf_k12_port_name, tvb, 0,0,pinfo->pseudo_header->k12.input_name);
	stack_item = proto_tree_add_string(k12_tree, hf_k12_stack_file, tvb, 0,0,pinfo->pseudo_header->k12.stack_file);

	k12_item = proto_tree_add_uint(k12_tree, hf_k12_port_type, tvb, 0, 0,
				       pinfo->pseudo_header->k12.input_type);

	k12_tree = proto_item_add_subtree(k12_item, ett_port);

	switch ( pinfo->pseudo_header->k12.input_type ) {
		case K12_PORT_DS0S:
			proto_tree_add_uint(k12_tree, hf_k12_ts, tvb, 0,0,pinfo->pseudo_header->k12.input_info.ds0mask);
			break;
		case K12_PORT_ATMPVC:
		{
		gchar* circuit_str = wmem_strdup_printf(wmem_packet_scope(), "%u:%u:%u",
						      (guint)pinfo->pseudo_header->k12.input_info.atm.vp,
						      (guint)pinfo->pseudo_header->k12.input_info.atm.vc,
						      (guint)pinfo->pseudo_header->k12.input_info.atm.cid);

			    /*
			     * XXX: this is prone to collisions!
			     * we need an uniform way to manage circuits between dissectors
			     */
		pinfo->circuit_id = g_str_hash(circuit_str);

		proto_tree_add_uint(k12_tree, hf_k12_atm_vp, tvb, 0, 0,
				    pinfo->pseudo_header->k12.input_info.atm.vp);
		proto_tree_add_uint(k12_tree, hf_k12_atm_vc, tvb, 0, 0,
				    pinfo->pseudo_header->k12.input_info.atm.vc);
		if (pinfo->pseudo_header->k12.input_info.atm.cid)
		    proto_tree_add_uint(k12_tree, hf_k12_atm_cid, tvb, 0, 0,
					pinfo->pseudo_header->k12.input_info.atm.cid);
			    break;
		}
		default:
			break;
	}

	handles = (dissector_handle_t *)wmem_tree_lookup32(port_handles, pinfo->pseudo_header->k12.input);

	if (! handles ) {
		for (i=0 ; i < nk12_handles; i++) {
			if ( epan_strcasestr(pinfo->pseudo_header->k12.stack_file, k12_handles[i].match)
			     || epan_strcasestr(pinfo->pseudo_header->k12.input_name, k12_handles[i].match) ) {
				handles = k12_handles[i].handles;
				break;
			}
		}

		if (!handles) {
			data_handles[0] = data_handle;
			handles = data_handles;
		}

		wmem_tree_insert32(port_handles, pinfo->pseudo_header->k12.input, handles);

	}

	if (handles == data_handles) {
		proto_tree* stack_tree = proto_item_add_subtree(stack_item, ett_stack_item);
		proto_item* item;

		expert_add_info(pinfo, stack_item, &ei_k12_unmatched_stk_file);

		item = proto_tree_add_text(stack_tree,tvb,0,0,
					   "Info: You can edit the 'K12 Protocols' table from Preferences->Protocols->k12xx");
		PROTO_ITEM_SET_GENERATED(item);

		call_dissector(data_handle, tvb, pinfo, tree);
		return;
	}

	/* Setup subdissector information */

	for (i = 0; handles[i] && handles[i+1]; ++i) {
		if (handles[i] == sscop_handle) {
			sscop_payload_info *p_sscop_info = (sscop_payload_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_sscop, 0);
			if (!p_sscop_info) {
				p_sscop_info = wmem_new0(wmem_file_scope(), sscop_payload_info);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_sscop, 0, p_sscop_info);
                p_sscop_info->subdissector = handles[i+1];
			}
		}
		/* Add more protocols here */
	}

	sub_handle = handles[0];

	/* Setup information required by certain protocols */
	if (sub_handle == fp_handle) {
		fp_info *p_fp_info = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
		if (!p_fp_info) {
			p_fp_info = wmem_new0(wmem_file_scope(), fp_info);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_fp, 0, p_fp_info);

            fill_fp_info(p_fp_info,
                         pinfo->pseudo_header->k12.extra_info,
                         pinfo->pseudo_header->k12.extra_length);
		}
	}

	call_dissector(sub_handle, tvb, pinfo, tree);
}

static void
k12_update_cb(void* r, const char** err)
{
	k12_handles_t* h = (k12_handles_t *)r;
	gchar** protos;
	guint num_protos, i;

	protos = g_strsplit(h->protos,":",0);

	for (num_protos = 0; protos[num_protos]; num_protos++)
		g_strstrip(protos[num_protos]);

	g_free(h->handles);
	h->handles = (dissector_handle_t *)g_malloc0(sizeof(dissector_handle_t)*(num_protos < 2 ? 2 : num_protos));

	for (i = 0; i < num_protos; i++) {
		if ( ! (h->handles[i] = find_dissector(protos[i])) ) {
			h->handles[i] = data_handle;
			g_strfreev(protos);
			*err = g_strdup_printf("Could not find dissector for: '%s'",protos[i]);
			return;
		}
	}

	g_strfreev(protos);
	*err = NULL;
}

static void*
k12_copy_cb(void* dest, const void* orig, size_t len _U_)
{
	k12_handles_t* d = (k12_handles_t *)dest;
	const k12_handles_t* o = (const k12_handles_t *)orig;
	gchar** protos = ep_strsplit(d->protos,":",0);
	guint num_protos;

	for (num_protos = 0; protos[num_protos]; num_protos++)
		g_strstrip(protos[num_protos]);

	d->match = g_strdup(o->match);
	d->protos = g_strdup(o->protos);
	d->handles = (dissector_handle_t *)g_memdup(o->handles,(guint)(sizeof(dissector_handle_t)*(num_protos+1)));

	return dest;
}

static void
k12_free_cb(void* r)
{
	k12_handles_t* h = (k12_handles_t *)r;

	g_free(h->match);
	g_free(h->protos);
	g_free(h->handles);
}


static gboolean
protos_chk_cb(void* r _U_, const char* p, guint len, const void* u1 _U_, const void* u2 _U_, const char** err)
{
	gchar** protos;
	gchar* line = ep_strndup(p,len);
	guint num_protos, i;

	g_strstrip(line);
	ascii_strdown_inplace(line);

	protos = ep_strsplit(line,":",0);

	for (num_protos = 0; protos[num_protos]; num_protos++)
		g_strstrip(protos[num_protos]);

	if (!num_protos) {
		*err = ep_strdup_printf("No protocols given");
		return FALSE;
	}

	for (i = 0; i < num_protos; i++) {
		if (!find_dissector(protos[i])) {
			*err = ep_strdup_printf("Could not find dissector for: '%s'",protos[i]);
			return FALSE;
		}
	}

	return TRUE;
}

UAT_CSTRING_CB_DEF(k12,match,k12_handles_t)
UAT_CSTRING_CB_DEF(k12,protos,k12_handles_t)

/* Make sure handles for various protocols are initialized */
static void
initialize_handles_once(void)
{
	static gboolean initialized = FALSE;
	if (!initialized) {
		k12_handle = find_dissector("k12");
		data_handle = find_dissector("data");
		sscop_handle = find_dissector("sscop");
		fp_handle = find_dissector("fp");
		initialized = TRUE;
	}
}

void proto_reg_handoff_k12(void)
{
	initialize_handles_once();
	dissector_add_uint("wtap_encap", WTAP_ENCAP_K12, k12_handle);
}

void
proto_register_k12(void)
{
    static hf_register_info hf[] = {
	{ &hf_k12_port_id, { "Port Id", "k12.port_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_k12_port_name, { "Port Name", "k12.port_name", FT_STRING, BASE_NONE, NULL, 0x0,NULL, HFILL }},
	{ &hf_k12_stack_file, { "Stack file used", "k12.stack_file", FT_STRING, BASE_NONE, NULL, 0x0,NULL, HFILL }},
	{ &hf_k12_port_type, { "Port type", "k12.input_type", FT_UINT32, BASE_HEX, VALS(k12_port_types), 0x0,NULL, HFILL }},
	{ &hf_k12_ts, { "Timeslot mask", "k12.ds0.ts", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_k12_atm_vp, { "ATM VPI", "atm.vpi", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_k12_atm_vc, { "ATM VCI", "atm.vci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_k12_atm_cid, { "AAL2 CID", "aal2.cid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}
	};

  static gint *ett[] = {
	  &ett_k12,
	  &ett_port,
	  &ett_stack_item
  };

  static ei_register_info ei[] = {
     { &ei_k12_unmatched_stk_file, { "k12.unmatched_stk_file", PI_UNDECODED, PI_WARN, "Warning: stk file not matched in the 'K12 Protocols' table", EXPFILL }},
  };

  static uat_field_t uat_k12_flds[] = {
      UAT_FLD_CSTRING_ISPRINT(k12,match,"Match string",
			      "A string that will be matched (a=A) against an .stk filename or the name of a port.\n"
			      "The first match wins, the order of entries in the table is important!."),
      UAT_FLD_CSTRING_OTHER(k12,protos,"Protocol",protos_chk_cb,
			    "The lowest layer protocol described by this .stk file (eg: mtp2).\n"
			    "Use (sscop:sscf-nni) for sscf-nni (MTP3b) with sscop"),
      UAT_END_FIELDS
  };

  module_t *k12_module;
  expert_module_t* expert_k12;

  proto_k12 = proto_register_protocol("K12xx", "K12xx", "k12");
  proto_register_field_array(proto_k12, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_k12 = expert_register_protocol(proto_k12);
  expert_register_field_array(expert_k12, ei, array_length(ei));
  register_dissector("k12", dissect_k12, proto_k12);

  k12_uat = uat_new("K12 Protocols",
		    sizeof(k12_handles_t),
		    "k12_protos",             /* filename */
		    TRUE,                     /* from_profile */
		    &k12_handles,             /* data_ptr */
		    &nk12_handles,            /* numitems_ptr */
		    UAT_AFFECTS_DISSECTION,   /* affects dissection of packets, but not set of named fields */
		    "ChK12ProtocolsSection",  /* help */
		    k12_copy_cb,
		    k12_update_cb,
		    k12_free_cb,
                    NULL,
		    uat_k12_flds);

  k12_module = prefs_register_protocol(proto_k12, NULL);

  prefs_register_obsolete_preference(k12_module, "config");

  prefs_register_uat_preference(k12_module, "cfg",
				"K12 Protocols",
				"A table of matches vs stack filenames and relative protocols",
				k12_uat);

  port_handles = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

}
