/* packet-mate.c
 * Routines for the mate Facility's Pseudo-Protocol dissection
 *
 * Copyright 2004, Luis E. Garcia Ontanon <gopo@webflies.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/**************************************************************************
 * This is the pseudo protocol dissector for the mate module.          ***
 * It is intended for this to be just the user interface to the module. ***
 **************************************************************************/

#include "mate.h"

static int mate_tap_data = 0;
static mate_config* mc = NULL;

static int proto_mate = -1;

static gint ett_mate = -1;
static gint ett_mate_pdu = -1;
static gint ett_mate_pdu_attr = -1;

static gint ett_mate_gop = -1;
static gint ett_mate_gop_attr = -1;
static gint ett_mate_gop_pdus = -1;
static gint ett_mate_gop_times = -1;

static gint ett_mate_gog = -1;
static gint ett_mate_gog_attr = -1;
static gint ett_mate_gog_gops = -1;
static gint ett_mate_gop_in_gog = -1;

static char* pref_mate_config_filename = "config.mate";

static proto_item *mate_i = NULL;

void attrs_tree(proto_tree* tree, tvbuff_t *tvb,mate_item* item) {
	AVPN* c;
	proto_item *avpl_i;
	proto_tree *avpl_t;
	int* hfi_p;
	
	gint our_ett;
	
	switch (item->cfg->type) {
		case MATE_PDU_TYPE:
			our_ett = ett_mate_pdu_attr;
			break;
		case MATE_GOP_TYPE:
			our_ett = ett_mate_pdu_attr;
			break;
		case MATE_GOG_TYPE:
			our_ett = ett_mate_pdu_attr;
			break;
		default:
			our_ett = ett_mate;
			break;
	}
			
	avpl_i = proto_tree_add_text(tree,tvb,0,0,"%s Attributes",item->cfg->name);
	avpl_t = proto_item_add_subtree(avpl_i, our_ett);

	for ( c = item->avpl->null.next; c->avp; c = c->next) {
		hfi_p = g_hash_table_lookup(item->cfg->my_hfids,c->avp->n);

		if (hfi_p) {
			proto_tree_add_string(avpl_t,*hfi_p,tvb,0,0,c->avp->v);
		} else {
			g_warning("MATE: error: undefined attribute: mate.%s.%s",item->cfg->name,c->avp->n);
			proto_tree_add_text(avpl_t,tvb,0,0,"Undefined attribute: %s=%s",c->avp->n, c->avp->v);
		}
	}
}

void mate_gop_tree(proto_tree* pdu_tree, tvbuff_t *tvb, mate_gop* gop, gint ett);

void mate_gog_tree(proto_tree* tree, tvbuff_t *tvb, mate_gog* gog, mate_gop* gop) {
	proto_item *gog_item;
	proto_tree *gog_tree;
	proto_item *gog_gop_item;
	proto_tree *gog_gop_tree;
	mate_gop* gog_gops;
#ifdef _MATE_DEBUGGING
	proto_item* gog_key_item;
	proto_tree* gog_key_tree;
	guint i;
#endif
	
	gog_item = proto_tree_add_uint(tree,gog->cfg->hfid,tvb,0,0,gog->id);
	gog_tree = proto_item_add_subtree(gog_item,ett_mate_gog);
			
	attrs_tree(gog_tree,tvb,gog);
	
	gog_gop_item = proto_tree_add_uint(gog_tree, gog->cfg->hfid_gog_num_of_gops,
									   tvb, 0, 0, gog->num_of_gops);
	
	gog_gop_tree = proto_item_add_subtree(gog_gop_item, ett_mate_gog_gops);
	
	for (gog_gops = gog->gops; gog_gops; gog_gops = gog_gops->next) {
		
		if (gop != gog_gops) {
			mate_gop_tree(gog_gop_tree, tvb, gog_gops, ett_mate_gop_in_gog);
		} else {
			 proto_tree_add_uint_format(gog_gop_tree,gop->cfg->hfid,tvb,0,0,gop->id,"%s of current frame: %d",gop->cfg->name,gop->id);
		}
	}
	
}

void mate_gop_tree(proto_tree* tree, tvbuff_t *tvb, mate_gop* gop, gint gop_ett) {
	proto_item *gop_item;
	proto_tree *gop_time_tree;
	proto_item *gop_time_item;
	proto_tree *gop_tree;
	proto_item *gop_pdu_item;
	proto_tree *gop_pdu_tree;
	mate_pdu* gop_pdus;
	float  rel_time;
	float  gop_time;

	gop_item = proto_tree_add_uint(tree,gop->cfg->hfid,tvb,0,0,gop->id);
	gop_tree = proto_item_add_subtree(gop_item, gop_ett);
	
	if (gop->gop_key) proto_tree_add_text(gop_tree,tvb,0,0,"GOP Key: %s",gop->gop_key);
	
	attrs_tree(gop_tree,tvb,gop);
	
	if (gop->cfg->show_gop_times) {
		gop_time_item = proto_tree_add_text(gop_tree,tvb,0,0,"%s Times",gop->cfg->name);
		gop_time_tree = proto_item_add_subtree(gop_time_item, ett_mate_gop_times);
		
		proto_tree_add_float(gop_time_tree, gop->cfg->hfid_gop_start_time, tvb, 0, 0, gop->start_time);
		
		if (gop->released) { 
			proto_tree_add_float(gop_time_tree, gop->cfg->hfid_gop_stop_time, tvb, 0, 0, gop->release_time);
			if (gop->release_time != gop->last_time) {
				proto_tree_add_float(gop_time_tree, gop->cfg->hfid_gop_last_time, tvb, 0, 0, gop->last_time); 
			}
		} else {
			proto_tree_add_float(gop_time_tree, gop->cfg->hfid_gop_last_time, tvb, 0, 0, gop->last_time); 
		}
	}

	rel_time = gop_time = gop->start_time;

	gop_pdu_item = proto_tree_add_uint(gop_tree, gop->cfg->hfid_gop_num_pdus, tvb, 0, 0,gop->num_of_pdus);
	gop_pdu_tree = proto_item_add_subtree(gop_pdu_item, ett_mate_gop_pdus);
	
	if (gop->cfg->show_pdu_tree) {
		for (gop_pdus = gop->pdus; gop_pdus; gop_pdus = gop_pdus->next) {
			if (gop_pdus->is_start) {
				proto_tree_add_uint_format(gop_pdu_tree,gop->cfg->hfid_gop_pdu,
										   tvb,0,0,gop_pdus->frame,
										   "Start PDU: in frame %i",
										   gop_pdus->frame);
			} else if (gop_pdus->is_stop) {
				proto_tree_add_uint_format(gop_pdu_tree,gop->cfg->hfid_gop_pdu,
										   tvb,0,0,gop_pdus->frame,
										   "Stop PDU: in frame %i (%f : %f)",
										   gop_pdus->frame,
										   gop_pdus->rel_time,
										   gop_pdus->rel_time-rel_time);
				
			} else if (gop_pdus->after_release) {
				proto_tree_add_uint_format(gop_pdu_tree,gop->cfg->hfid_gop_pdu,
										   tvb,0,0,gop_pdus->frame,
										   "After stop PDU: in frame %i (%f : %f)",
										   gop_pdus->frame,
										   gop_pdus->rel_time,
										   gop_pdus->rel_time-rel_time);
			} else {
				proto_tree_add_uint_format(gop_pdu_tree,gop->cfg->hfid_gop_pdu,
										   tvb,0,0,gop_pdus->frame,
										   "PDU: in frame %i (%f : %f)",
										   gop_pdus->frame,
										   gop_pdus->rel_time,
										   gop_pdus->rel_time-rel_time);
			}
			
			rel_time = gop_pdus->rel_time;
			
		}
	}
}


void mate_pdu_tree(mate_pdu *pdu, tvbuff_t *tvb, proto_tree* tree) {
	proto_item *pdu_item;
	proto_tree *pdu_tree;
	guint32 len;
	
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
	
	len = pdu->end - pdu->start;
	pdu_item = proto_tree_add_uint(tree,pdu->cfg->hfid,tvb,pdu->start,len,pdu->id);
	pdu_tree = proto_item_add_subtree(pdu_item, ett_mate_pdu);
	proto_tree_add_float(pdu_tree,pdu->cfg->hfid_pdu_rel_time, tvb, 0, 0, pdu->rel_time);		

	if (pdu->gop) {
		mate_gop_tree(pdu_tree,tvb,pdu->gop,ett_mate_gop);

		if (pdu->gop->gog)
			mate_gog_tree(pdu_tree,tvb,pdu->gop->gog,pdu->gop);
	}
	
	if (pdu->avpl) {
		attrs_tree(pdu_tree,tvb,pdu);
	}
}

extern void mate_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	mate_pdu* pdus;
	proto_tree *mate_t;
	
	if (! tree ) return;

	if (( pdus = mate_get_pdus(pinfo->fd->num) )) {
		
		mate_i = proto_tree_add_text(tree,tvb,0,0,"mate");
		
		mate_t = proto_item_add_subtree(mate_i, ett_mate);
		
		for ( ; pdus; pdus = pdus->next_in_frame) {
			mate_pdu_tree(pdus,tvb,mate_t);			
		}
	}
}

static void init_mate(void) {
	GString* tap_error = NULL;

	tap_error = register_tap_listener("frame", &mate_tap_data,
									  mc->tap_filter,
									  NULL,
									  mate_packet,
									  NULL);
	
	if ( tap_error ) {
		g_warning("mate: couldn't (re)register tap: %s",tap_error->str);
		g_string_free(tap_error, TRUE);
		mate_tap_data = 0;
		return;
	} else {
		mate_tap_data = 1;
	}
	
	init_mate_runtime_data();
}

extern
void
proto_reg_handoff_mate(void)
{
}  


extern
void
proto_register_mate(void)
{                 
	static gint *ett[] = {
		&ett_mate,
		&ett_mate_pdu,
		&ett_mate_pdu_attr,
		&ett_mate_gop,
		&ett_mate_gop_attr,
		&ett_mate_gop_times,
		&ett_mate_gop_pdus,
		&ett_mate_gog,
		&ett_mate_gog_gops,
		&ett_mate_gog_attr,
		&ett_mate_gop_in_gog
	};

	mc = mate_make_config(pref_mate_config_filename);
	
	if (mc) {

		proto_mate = proto_register_protocol("Meta Analysis Tracing Engine", "mate", "mate");
		

		proto_register_field_array(proto_mate, (hf_register_info*) mc->hfrs->data, mc->hfrs->len );
		
		proto_register_subtree_array(ett, array_length(ett));
		
		register_dissector("mate",mate_tree,proto_mate);
		
		register_init_routine(init_mate);
		
	}
}

