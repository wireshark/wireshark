/* packet-mate.c
 * Routines for the mate Facility's Pseudo-Protocol dissection
 *
 * Copyright 2004, Luis E. Garcia Ontanon <gopo@webflies.org>
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


/**************************************************************************
 * This is the pseudo protocol dissector for the mate module.          ***
 * It is intended for this to be just the user interface to the module. ***
 **************************************************************************/

#include "mate.h"
#include <epan/expert.h>

void proto_register_mate(void);
void proto_reg_handoff_mate(void);

static int mate_tap_data = 0;
static mate_config* mc = NULL;

static int proto_mate = -1;

static int hf_mate_released_time = -1;
static int hf_mate_duration = -1;
static int hf_mate_number_of_pdus = -1;
static int hf_mate_started_at = -1;
static int hf_mate_gop_key = -1;

static expert_field ei_mate_undefined_attribute = EI_INIT;

static const gchar* pref_mate_config_filename = "";
static const gchar* current_mate_config_filename = NULL;

static proto_item *mate_i = NULL;

static void
pdu_attrs_tree(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, mate_pdu* pdu)
{
	AVPN* c;
	proto_tree *avpl_t;
	int* hfi_p;

	avpl_t = proto_tree_add_subtree_format(tree,tvb,0,0,pdu->cfg->ett_attr,NULL,"%s Attributes",pdu->cfg->name);

	for ( c = pdu->avpl->null.next; c->avp; c = c->next) {
		hfi_p = (int *)g_hash_table_lookup(pdu->cfg->my_hfids,(char*)c->avp->n);

		if (hfi_p) {
			proto_tree_add_string(avpl_t,*hfi_p,tvb,0,0,c->avp->v);
		} else {
			proto_tree_add_expert_format(avpl_t,pinfo,&ei_mate_undefined_attribute,tvb,0,0,"Undefined attribute: %s=%s",c->avp->n, c->avp->v);
		}
	}
}

static void
gop_attrs_tree(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, mate_gop* gop)
{
	AVPN* c;
	proto_tree *avpl_t;
	int* hfi_p;

	avpl_t = proto_tree_add_subtree_format(tree,tvb,0,0,gop->cfg->ett_attr,NULL,"%s Attributes",gop->cfg->name);

	for ( c = gop->avpl->null.next; c->avp; c = c->next) {
		hfi_p = (int *)g_hash_table_lookup(gop->cfg->my_hfids,(char*)c->avp->n);

		if (hfi_p) {
			proto_tree_add_string(avpl_t,*hfi_p,tvb,0,0,c->avp->v);
		} else {
			proto_tree_add_expert_format(avpl_t,pinfo,&ei_mate_undefined_attribute,tvb,0,0,"Undefined attribute: %s=%s",c->avp->n, c->avp->v);
		}
	}
}

static void
gog_attrs_tree(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, mate_gog* gog)
{
	AVPN* c;
	proto_tree *avpl_t;
	int* hfi_p;

	avpl_t = proto_tree_add_subtree_format(tree,tvb,0,0,gog->cfg->ett_attr,NULL,"%s Attributes",gog->cfg->name);

	for ( c = gog->avpl->null.next; c->avp; c = c->next) {
		hfi_p = (int *)g_hash_table_lookup(gog->cfg->my_hfids,(char*)c->avp->n);

		if (hfi_p) {
			proto_tree_add_string(avpl_t,*hfi_p,tvb,0,0,c->avp->v);
		} else {
			proto_tree_add_expert_format(avpl_t,pinfo,&ei_mate_undefined_attribute,tvb,0,0,"Undefined attribute: %s=%s",c->avp->n, c->avp->v);
		}
	}
}

static void mate_gop_tree(proto_tree* pdu_tree, packet_info *pinfo, tvbuff_t *tvb, mate_gop* gop);

static void
mate_gog_tree(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, mate_gog* gog, mate_gop* gop)
{
	proto_item *gog_item;
	proto_tree *gog_tree;
	proto_tree *gog_time_tree;
	proto_item *gog_gops_item;
	proto_tree *gog_gops_tree;
	mate_gop* gog_gops;
	proto_item *gog_gop_item;
	proto_tree *gog_gop_tree;
	mate_pdu* pdu;

	gog_item = proto_tree_add_uint(tree,gog->cfg->hfid,tvb,0,0,gog->id);
	gog_tree = proto_item_add_subtree(gog_item,gog->cfg->ett);

	gog_attrs_tree(gog_tree,pinfo,tvb,gog);

	if (gog->cfg->show_times) {
		gog_time_tree = proto_tree_add_subtree_format(gog_tree,tvb,0,0,gog->cfg->ett_times,NULL,"%s Times",gog->cfg->name);

		proto_tree_add_float(gog_time_tree, gog->cfg->hfid_start_time, tvb, 0, 0, gog->start_time);
		proto_tree_add_float(gog_time_tree, gog->cfg->hfid_last_time, tvb, 0, 0, gog->last_time - gog->start_time);
	}

	gog_gops_item = proto_tree_add_uint(gog_tree, gog->cfg->hfid_gog_num_of_gops, tvb, 0, 0, gog->num_of_gops);

	gog_gops_tree = proto_item_add_subtree(gog_gops_item, gog->cfg->ett_children);

	for (gog_gops = gog->gops; gog_gops; gog_gops = gog_gops->next) {

		if (gop != gog_gops) {
			if (gog->cfg->gop_tree_mode == GOP_FULL_TREE) {
				mate_gop_tree(gog_gops_tree, pinfo, tvb, gog_gops);
			} else {
				gog_gop_item = proto_tree_add_uint(gog_gops_tree,gog_gops->cfg->hfid,tvb,0,0,gog_gops->id);

				if (gog->cfg->gop_tree_mode == GOP_BASIC_TREE) {
					gog_gop_tree = proto_item_add_subtree(gog_gop_item, gog->cfg->ett_gog_gop);

					proto_tree_add_float(gog_gop_tree, hf_mate_started_at, tvb,0,0,gog_gops->start_time);

					proto_tree_add_float_format(gog_gop_tree, hf_mate_duration, tvb,0,0, gog_gops->last_time - gog_gops->start_time,
								    "%s Duration: %f", gog_gops->cfg->name, gog_gops->last_time - gog_gops->start_time);

					if (gog_gops->released)
						proto_tree_add_float_format(gog_gop_tree, hf_mate_released_time, tvb,0,0, gog_gops->release_time - gog_gops->start_time,
									    "%s has been released, Time: %f", gog_gops->cfg->name, gog_gops->release_time - gog_gops->start_time);

					proto_tree_add_uint(gog_gop_tree, hf_mate_number_of_pdus, tvb,0,0, gog_gops->num_of_pdus);

					if (gop->pdus && gop->cfg->pdu_tree_mode != GOP_NO_TREE) {
						proto_tree_add_uint(gog_gop_tree,gog->cfg->hfid_gog_gopstart,tvb,0,0,gog_gops->pdus->frame);

						for (pdu = gog_gops->pdus->next ; pdu; pdu = pdu->next) {
							if (pdu->is_stop) {
								proto_tree_add_uint(gog_gop_tree,gog->cfg->hfid_gog_gopstop,tvb,0,0,pdu->frame);
								break;
							}
						}
					}
				}

			}
		} else {
			 proto_tree_add_uint_format(gog_gops_tree,gop->cfg->hfid,tvb,0,0,gop->id,"current %s Gop: %d",gop->cfg->name,gop->id);
		}
	}
}

static void
mate_gop_tree(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, mate_gop* gop)
{
	proto_item *gop_item;
	proto_tree *gop_time_tree;
	proto_tree *gop_tree;
	proto_item *gop_pdu_item;
	proto_tree *gop_pdu_tree;
	mate_pdu* gop_pdus;
	float rel_time;
	float pdu_rel_time;
	const gchar* pdu_str;
	const gchar* type_str;
	guint32 pdu_item;

	gop_item = proto_tree_add_uint(tree,gop->cfg->hfid,tvb,0,0,gop->id);
	gop_tree = proto_item_add_subtree(gop_item, gop->cfg->ett);

	if (gop->gop_key) proto_tree_add_string(gop_tree,hf_mate_gop_key,tvb,0,0,gop->gop_key);

	gop_attrs_tree(gop_tree,pinfo,tvb,gop);

	if (gop->cfg->show_times) {
		gop_time_tree = proto_tree_add_subtree_format(gop_tree,tvb,0,0,gop->cfg->ett_times,NULL,"%s Times",gop->cfg->name);

		proto_tree_add_float(gop_time_tree, gop->cfg->hfid_start_time, tvb, 0, 0, gop->start_time);

		if (gop->released) {
			proto_tree_add_float(gop_time_tree, gop->cfg->hfid_stop_time, tvb, 0, 0, gop->release_time - gop->start_time);
			proto_tree_add_float(gop_time_tree, gop->cfg->hfid_last_time, tvb, 0, 0, gop->last_time - gop->start_time);
		} else {
			proto_tree_add_float(gop_time_tree, gop->cfg->hfid_last_time, tvb, 0, 0, gop->last_time - gop->start_time);
		}
	}

	gop_pdu_item = proto_tree_add_uint(gop_tree, gop->cfg->hfid_gop_num_pdus, tvb, 0, 0,gop->num_of_pdus);

	if (gop->cfg->pdu_tree_mode != GOP_NO_TREE) {

		gop_pdu_tree = proto_item_add_subtree(gop_pdu_item, gop->cfg->ett_children);

		rel_time = gop->start_time;

		type_str = (gop->cfg->pdu_tree_mode == GOP_FRAME_TREE ) ? "in frame:" : "id:";

		for (gop_pdus = gop->pdus; gop_pdus; gop_pdus = gop_pdus->next) {

			pdu_item = (gop->cfg->pdu_tree_mode == GOP_FRAME_TREE ) ? gop_pdus->frame : gop_pdus->id;

			if (gop_pdus->is_start) {
				pdu_str = "Start ";
			} else if (gop_pdus->is_stop) {
				pdu_str = "Stop ";
			} else if (gop_pdus->after_release) {
				pdu_str = "After stop ";
			} else {
				pdu_str = "";
			}

			pdu_rel_time = gop_pdus->time_in_gop != 0.0 ? gop_pdus->time_in_gop - rel_time : (float) 0.0;

			proto_tree_add_uint_format(gop_pdu_tree,gop->cfg->hfid_gop_pdu,tvb,0,0,pdu_item,
						   "%sPDU: %s %i (%f : %f)",pdu_str, type_str,
						   pdu_item, gop_pdus->time_in_gop,
						   pdu_rel_time);

			rel_time = gop_pdus->time_in_gop;

		}
	}
}


static void
mate_pdu_tree(mate_pdu *pdu, packet_info *pinfo, tvbuff_t *tvb, proto_tree* tree)
{
	proto_item *pdu_item;
	proto_tree *pdu_tree;

	if ( ! pdu ) return;

	if (pdu->gop && pdu->gop->gog) {
		proto_item_append_text(mate_i," %s:%d->%s:%d->%s:%d",
				       pdu->cfg->name,pdu->id,
				       pdu->gop->cfg->name,pdu->gop->id,
				       pdu->gop->gog->cfg->name,pdu->gop->gog->id);
	} else if (pdu->gop) {
		proto_item_append_text(mate_i," %s:%d->%s:%d",
				       pdu->cfg->name,pdu->id,
				       pdu->gop->cfg->name,pdu->gop->id);
	} else {
		proto_item_append_text(mate_i," %s:%d",pdu->cfg->name,pdu->id);
	}

	pdu_item = proto_tree_add_uint(tree,pdu->cfg->hfid,tvb,0,0,pdu->id);
	pdu_tree = proto_item_add_subtree(pdu_item, pdu->cfg->ett);
	proto_tree_add_float(pdu_tree,pdu->cfg->hfid_pdu_rel_time, tvb, 0, 0, pdu->rel_time);

	if (pdu->gop) {
		proto_tree_add_float(pdu_tree,pdu->cfg->hfid_pdu_time_in_gop, tvb, 0, 0, pdu->time_in_gop);
		mate_gop_tree(tree,pinfo,tvb,pdu->gop);

		if (pdu->gop->gog)
			mate_gog_tree(tree,pinfo,tvb,pdu->gop->gog,pdu->gop);
	}

	if (pdu->avpl) {
		pdu_attrs_tree(pdu_tree,pinfo,tvb,pdu);
	}
}

static int
mate_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	mate_pdu* pdus;
	proto_tree *mate_t;

	if ( ! mc || ! tree )
		return tvb_captured_length(tvb);

	mate_analyze_frame(pinfo,tree);

	if (( pdus = mate_get_pdus(pinfo->num) )) {
		for ( ; pdus; pdus = pdus->next_in_frame) {
			mate_i = proto_tree_add_protocol_format(tree,mc->hfid_mate,tvb,0,0,"MATE");
			mate_t = proto_item_add_subtree(mate_i, mc->ett_root);
			mate_pdu_tree(pdus,pinfo,tvb,mate_t);
		}
	}
	return tvb_captured_length(tvb);
}

static int
mate_packet(void *prs _U_,  packet_info* tree _U_, epan_dissect_t *edt _U_, const void *dummy _U_)
{
	/* nothing to do yet */
	return 0;
}

extern
void
proto_reg_handoff_mate(void)
{
	GString* tap_error = NULL;

	if ( *pref_mate_config_filename != '\0' ) {

		if (current_mate_config_filename) {
			report_failure("MATE cannot reconfigure itself.\n"
				       "For changes to be applied you have to restart Wireshark\n");
			return;
		}

		if (!mc) {
			mc = mate_make_config(pref_mate_config_filename,proto_mate);

			if (mc) {
				/* XXX: alignment warnings, what do they mean? */
				proto_register_field_array(proto_mate, (hf_register_info*)(void *)mc->hfrs->data, mc->hfrs->len );
				proto_register_subtree_array((gint**)(void*)mc->ett->data, mc->ett->len);
				register_init_routine(initialize_mate_runtime);

				tap_error = register_tap_listener("frame", &mate_tap_data,
				    (char*) mc->tap_filter,
				    0,
				    (tap_reset_cb) NULL,
				    mate_packet,
				    (tap_draw_cb) NULL);

				if ( tap_error ) {
					g_warning("mate: couldn't (re)register tap: %s",tap_error->str);
					g_string_free(tap_error, TRUE);
					mate_tap_data = 0;
					return;
				}

				initialize_mate_runtime();
			}

			current_mate_config_filename = pref_mate_config_filename;

		}
	}
}

extern
void
proto_register_mate(void)
{
	static hf_register_info hf[] = {
		{ &hf_mate_started_at, { "Started at", "mate.started_at", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_mate_duration, { "Duration", "mate.duration", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_mate_released_time, { "Release time", "mate.released_time", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_mate_number_of_pdus, { "Number of Pdus", "mate.number_of_pdus", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_mate_gop_key, { "GOP Key", "mate.gop_key", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static ei_register_info ei[] = {
		{ &ei_mate_undefined_attribute, { "mate.undefined_attribute", PI_PROTOCOL, PI_ERROR, "Undefined attribute", EXPFILL }},
	};

	expert_module_t* expert_mate;
	module_t *mate_module;
	dissector_handle_t mate_handle;

	proto_mate = proto_register_protocol("Meta Analysis Tracing Engine", "MATE", "mate");
	proto_register_field_array(proto_mate, hf, array_length(hf));
	expert_mate = expert_register_protocol(proto_mate);
	expert_register_field_array(expert_mate, ei, array_length(ei));

	mate_handle = register_dissector("mate",mate_tree,proto_mate);
	mate_module = prefs_register_protocol(proto_mate, proto_reg_handoff_mate);
	prefs_register_filename_preference(mate_module, "config",
					   "Configuration Filename",
					   "The name of the file containing the mate module's configuration",
					   &pref_mate_config_filename);

	register_postdissector(mate_handle);
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
