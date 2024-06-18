/* packet-mate.c
 * Routines for the mate Facility's Pseudo-Protocol dissection
 *
 * Copyright 2004, Luis E. Garcia Ontanon <gopo@webflies.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/**************************************************************************
 * This is the pseudo protocol dissector for the mate module.          ***
 * It is intended for this to be just the user interface to the module. ***
 **************************************************************************/

#include "config.h"

#include "mate.h"
#include <epan/expert.h>

void proto_register_mate(void);
void proto_reg_handoff_mate(void);

static mate_config* mc;

static int proto_mate;

static int hf_mate_released_time;
static int hf_mate_duration;
static int hf_mate_number_of_pdus;
static int hf_mate_started_at;
static int hf_mate_gop_key;

static expert_field ei_mate_undefined_attribute;

static const char* pref_mate_config_filename = "";
static const char* current_mate_config_filename;

#ifdef _AVP_DEBUGGING
static int pref_avp_debug_general;
static int pref_avp_debug_avp;
static int pref_avp_debug_avp_op;
static int pref_avp_debug_avpl;
static int pref_avp_debug_avpl_op;
#endif

static dissector_handle_t mate_handle;

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

		proto_tree_add_double(gog_time_tree, gog->cfg->hfid_start_time, tvb, 0, 0, gog->start_time);
		proto_tree_add_double(gog_time_tree, gog->cfg->hfid_last_time, tvb, 0, 0, gog->last_time - gog->start_time);
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

					proto_tree_add_double(gog_gop_tree, hf_mate_started_at, tvb,0,0,gog_gops->start_time);

					proto_tree_add_double_format(gog_gop_tree, hf_mate_duration, tvb,0,0, gog_gops->last_time - gog_gops->start_time,
								    "%s Duration: %f", gog_gops->cfg->name, gog_gops->last_time - gog_gops->start_time);

					if (gog_gops->released)
						proto_tree_add_double_format(gog_gop_tree, hf_mate_released_time, tvb,0,0, gog_gops->release_time - gog_gops->start_time,
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
	double rel_time;
	double pdu_rel_time;
	const char* pdu_str;
	const char* type_str;
	uint32_t pdu_item;

	gop_item = proto_tree_add_uint(tree,gop->cfg->hfid,tvb,0,0,gop->id);
	gop_tree = proto_item_add_subtree(gop_item, gop->cfg->ett);

	if (gop->gop_key) proto_tree_add_string(gop_tree,hf_mate_gop_key,tvb,0,0,gop->gop_key);

	gop_attrs_tree(gop_tree,pinfo,tvb,gop);

	if (gop->cfg->show_times) {
		gop_time_tree = proto_tree_add_subtree_format(gop_tree,tvb,0,0,gop->cfg->ett_times,NULL,"%s Times",gop->cfg->name);

		proto_tree_add_double(gop_time_tree, gop->cfg->hfid_start_time, tvb, 0, 0, gop->start_time);

		if (gop->released) {
			proto_tree_add_double(gop_time_tree, gop->cfg->hfid_stop_time, tvb, 0, 0, gop->release_time - gop->start_time);
			proto_tree_add_double(gop_time_tree, gop->cfg->hfid_last_time, tvb, 0, 0, gop->last_time - gop->start_time);
		} else {
			proto_tree_add_double(gop_time_tree, gop->cfg->hfid_last_time, tvb, 0, 0, gop->last_time - gop->start_time);
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

			pdu_rel_time = gop_pdus->time_in_gop != 0.0 ? gop_pdus->time_in_gop - rel_time : 0.0;

			proto_tree_add_uint_format(gop_pdu_tree,gop->cfg->hfid_gop_pdu,tvb,0,0,pdu_item,
						   "%sPDU: %s %i (%f : %f)",pdu_str, type_str,
						   pdu_item, gop_pdus->time_in_gop,
						   pdu_rel_time);

			rel_time = gop_pdus->time_in_gop;

		}
	}
}


static void
mate_pdu_tree(mate_pdu *pdu, packet_info *pinfo, tvbuff_t *tvb, proto_item *item, proto_tree* tree)
{
	proto_item *pdu_item;
	proto_tree *pdu_tree;

	if ( ! pdu ) return;

	if (pdu->gop && pdu->gop->gog) {
		proto_item_append_text(item," %s:%d->%s:%d->%s:%d",
				       pdu->cfg->name,pdu->id,
				       pdu->gop->cfg->name,pdu->gop->id,
				       pdu->gop->gog->cfg->name,pdu->gop->gog->id);
	} else if (pdu->gop) {
		proto_item_append_text(item," %s:%d->%s:%d",
				       pdu->cfg->name,pdu->id,
				       pdu->gop->cfg->name,pdu->gop->id);
	} else {
		proto_item_append_text(item," %s:%d",pdu->cfg->name,pdu->id);
	}

	pdu_item = proto_tree_add_uint(tree,pdu->cfg->hfid,tvb,0,0,pdu->id);
	pdu_tree = proto_item_add_subtree(pdu_item, pdu->cfg->ett);
	proto_tree_add_double(pdu_tree,pdu->cfg->hfid_pdu_rel_time, tvb, 0, 0, pdu->rel_time);

	if (pdu->gop) {
		proto_tree_add_double(pdu_tree,pdu->cfg->hfid_pdu_time_in_gop, tvb, 0, 0, pdu->time_in_gop);
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
	proto_item *mate_i;
	proto_tree *mate_t;

	/* If there is no MATE configuration, don't claim the packet */
	if ( mc == NULL)
		return 0;

	/* There is a MATE configuration, just no tree, so there's nothing to do */
	if ( tree == NULL)
		return tvb_captured_length(tvb);

	mate_analyze_frame(mc, pinfo,tree);

	if (( pdus = mate_get_pdus(pinfo->num) )) {
		for ( ; pdus; pdus = pdus->next_in_frame) {
			mate_i = proto_tree_add_protocol_format(tree,mc->hfid_mate,tvb,0,0,"MATE");
			mate_t = proto_item_add_subtree(mate_i, mc->ett_root);
			mate_pdu_tree(pdus,pinfo,tvb,mate_i,mate_t);
		}
	}
	return tvb_captured_length(tvb);
}

static void
initialize_mate(void)
{
	initialize_mate_runtime(mc);
#ifdef _AVP_DEBUGGING
	setup_avp_debug(mc->dbg_facility,
		&pref_avp_debug_general,
		&pref_avp_debug_avp,
		&pref_avp_debug_avp_op,
		&pref_avp_debug_avpl,
		&pref_avp_debug_avpl_op);
#endif
}

static void
flush_mate_debug(void)
{
	/* Flush debug information */
	if (mc->dbg_facility)
		fflush(mc->dbg_facility);
}

extern
void
proto_reg_handoff_mate(void)
{
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
				proto_register_subtree_array((int**)(void*)mc->ett->data, mc->ett->len);
				register_init_routine(initialize_mate);
				register_postseq_cleanup_routine(flush_mate_debug);

				/*
				 * Set the list of hfids we want.
				 */
				set_postdissector_wanted_hfids(mate_handle,
				    mc->wanted_hfids);
				/* XXX: Due to #17877, any protocol added to the tree with length -1
				 * that changes its length later (and there are many, such as TCP)
				 * doesn't actually change its length unless the tree is visible,
				 * which means that entire range checking work in MATE to split up
				 * multiple PDUs of the target protocol in the same frame doesn't
				 * work. Set the tree as visible as with Lua postdissectors that
				 * need all fields. It's overkill and bad for performance, though.
				 */
				epan_set_always_visible(true);

				initialize_mate_runtime(mc);
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
		{ &hf_mate_started_at, { "Started at", "mate.started_at", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_mate_duration, { "Duration", "mate.duration", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_mate_released_time, { "Release time", "mate.released_time", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_mate_number_of_pdus, { "Number of Pdus", "mate.number_of_pdus", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_mate_gop_key, { "GOP Key", "mate.gop_key", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static ei_register_info ei[] = {
		{ &ei_mate_undefined_attribute, { "mate.undefined_attribute", PI_PROTOCOL, PI_ERROR, "Undefined attribute", EXPFILL }},
	};

	expert_module_t* expert_mate;
	module_t *mate_module;

	proto_mate = proto_register_protocol("Meta Analysis Tracing Engine", "MATE", "mate");
	proto_register_field_array(proto_mate, hf, array_length(hf));
	expert_mate = expert_register_protocol(proto_mate);
	expert_register_field_array(expert_mate, ei, array_length(ei));

	mate_handle = register_dissector("mate",mate_tree,proto_mate);
	mate_module = prefs_register_protocol(proto_mate, proto_reg_handoff_mate);
	prefs_register_filename_preference(mate_module, "config",
					   "Configuration Filename",
					   "The name of the file containing the mate module's configuration",
					   &pref_mate_config_filename, false);
#ifdef _AVP_DEBUGGING
	prefs_register_uint_preference(mate_module, "avp_debug_general",
					    "AVP Debug general",
					    "General debugging level (0..5)",
					    10,
					   &pref_avp_debug_general);
	prefs_register_uint_preference(mate_module, "avp_debug_avp",
					    "Debug AVP",
					    "Attribute Value Pairs debugging level (0..5)",
					    10,
					   &pref_avp_debug_avp);
	prefs_register_uint_preference(mate_module, "avp_debug_avp_op",
					    "Debug AVP operations",
					    "Attribute Value Pairs operations debugging level (0..5)",
					    10,
					   &pref_avp_debug_avp_op);
	prefs_register_uint_preference(mate_module, "avp_debug_avpl",
					    "Debug AVP list",
					    "Attribute Value Pairs list debugging level (0..5)",
					    10,
					   &pref_avp_debug_avpl);
	prefs_register_uint_preference(mate_module, "avp_debug_avpl_op",
					    "Debug AVP list operations",
					    "Attribute Value Pairs list operations debugging level (0..5)",
					    10,
					   &pref_avp_debug_avpl_op);
#endif

	register_postdissector(mate_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
