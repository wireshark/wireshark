/* packet-pres.c
 * Routine to dissect ISO 8823 OSI Presentation Protocol packets
 * Based on the dissector by
 * Yuriy Sidelnikov <YSidelnikov@hotmail.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/uat.h>

#include <string.h>

#include <epan/asn1.h>
#include <epan/oids.h>
#include "packet-ber.h"
#include "packet-ses.h"
#include "packet-pres.h"
#include "packet-rtse.h"


#define PNAME  "ISO 8823 OSI Presentation Protocol"
#define PSNAME "PRES"
#define PFNAME "pres"

#define CLPNAME  "ISO 9576-1 OSI Connectionless Presentation Protocol"
#define CLPSNAME "CLPRES"
#define CLPFNAME "clpres"

/* Initialize the protocol and registered fields */
static int proto_pres = -1;

/* Initialize the connectionles protocol */
static int proto_clpres = -1;


/*   type of session envelop */
static struct SESSION_DATA_STRUCTURE* session = NULL;

/*      pointers for acse dissector  */
proto_tree *global_tree  = NULL;
packet_info *global_pinfo = NULL;

static const char *abstract_syntax_name_oid;
static guint32 presentation_context_identifier;

/* to keep track of presentation context identifiers and protocol-oids */
typedef struct _pres_ctx_oid_t {
	guint32 ctx_id;
	char *oid;
	guint32 index;
} pres_ctx_oid_t;
static GHashTable *pres_ctx_oid_table = NULL;

typedef struct _pres_user_t {
   guint ctx_id;
   char *oid;
} pres_user_t;

static pres_user_t *pres_users;
static guint num_pres_users;

static int hf_pres_CP_type = -1;
static int hf_pres_CPA_PPDU = -1;
static int hf_pres_Abort_type = -1;
static int hf_pres_CPR_PPDU = -1;
static int hf_pres_Typed_data_type = -1;

#include "packet-pres-hf.c"

/* Initialize the subtree pointers */
static gint ett_pres           = -1;

#include "packet-pres-ett.c"

UAT_DEC_CB_DEF(pres_users, ctx_id, pres_user_t)
UAT_CSTRING_CB_DEF(pres_users, oid, pres_user_t)

static guint
pres_ctx_oid_hash(gconstpointer k)
{
	pres_ctx_oid_t *pco=(pres_ctx_oid_t *)k;
	return pco->ctx_id;
}

static gint
pres_ctx_oid_equal(gconstpointer k1, gconstpointer k2)
{
	pres_ctx_oid_t *pco1=(pres_ctx_oid_t *)k1;
	pres_ctx_oid_t *pco2=(pres_ctx_oid_t *)k2;
	return (pco1->ctx_id==pco2->ctx_id && pco1->index==pco2->index);
}

static void
pres_init(void)
{
	if( pres_ctx_oid_table ){
		g_hash_table_destroy(pres_ctx_oid_table);
		pres_ctx_oid_table = NULL;
	}
	pres_ctx_oid_table = g_hash_table_new(pres_ctx_oid_hash,
			pres_ctx_oid_equal);

}

static void
register_ctx_id_and_oid(packet_info *pinfo _U_, guint32 idx, const char *oid)
{
	pres_ctx_oid_t *pco, *tmppco;
	conversation_t *conversation;

	if(!oid){
		/* we did not get any oid name, malformed packet? */
		return;
	}

	pco=se_alloc(sizeof(pres_ctx_oid_t));
	pco->ctx_id=idx;
	pco->oid=se_strdup(oid);
	conversation=find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	if (conversation) {
		pco->index = conversation->index;
	} else {
		pco->index = 0;
	}

	/* if this ctx already exists, remove the old one first */
	tmppco=(pres_ctx_oid_t *)g_hash_table_lookup(pres_ctx_oid_table, pco);
	if(tmppco){
		g_hash_table_remove(pres_ctx_oid_table, tmppco);

	}
	g_hash_table_insert(pres_ctx_oid_table, pco, pco);
}

char *
find_oid_by_pres_ctx_id(packet_info *pinfo _U_, guint32 idx)
{
	pres_ctx_oid_t pco, *tmppco;
	conversation_t *conversation;

	pco.ctx_id=idx;
	conversation=find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	if (conversation) {
		pco.index = conversation->index;
	} else {
		pco.index = 0;
	}

	tmppco=(pres_ctx_oid_t *)g_hash_table_lookup(pres_ctx_oid_table, &pco);
	if(tmppco){
		return tmppco->oid;
	}
	return NULL;
}

static void *
pres_copy_cb(void *dest, const void *orig, size_t len _U_)
{
	pres_user_t *u = dest;
	const pres_user_t *o = orig;

	u->ctx_id = o->ctx_id;
	u->oid = g_strdup(o->oid);

	return dest;
}

static void
pres_free_cb(void *r)
{
	pres_user_t *u = r;

	g_free(u->oid);
}

static gboolean
pres_try_users_table(guint32 ctx_id, tvbuff_t *tvb, int offset, packet_info *pinfo)
{
	tvbuff_t *next_tvb;
	guint i;

	for (i = 0; i < num_pres_users; i++) {
		pres_user_t *u = &(pres_users[i]);

		if (u->ctx_id == ctx_id) {
			/* Register oid so other dissectors can find this connection */
			register_ctx_id_and_oid(pinfo, u->ctx_id, u->oid);
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_ber_oid_callback(u->oid, next_tvb, offset, pinfo, global_tree);
			return TRUE;
		}
	}

	return FALSE;
}


#include "packet-pres-fn.c"


/*
 * Dissect an PPDU.
 */
static int
dissect_ppdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *pres_tree = NULL;
	guint s_type;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* do we have spdu type from the session dissector?  */
	if( !pinfo->private_data ){
		if(tree){
			proto_tree_add_text(tree, tvb, offset, -1,
				"Internal error:can't get spdu type from session dissector.");
			return 0;
		}
	}else{
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
		if(session->spdu_type == 0 ){
			if(tree){
				proto_tree_add_text(tree, tvb, offset, -1,
					"Internal error:wrong spdu type %x from session dissector.",session->spdu_type);
				return 0;
			}
		}
	}
	/* get type of tag */
	s_type = tvb_get_guint8(tvb, offset);
	/*  set up type of PPDU */
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(session->spdu_type, ses_vals, "Unknown PPDU type (0x%02x)"));
	if (tree){
		ti = proto_tree_add_item(tree, proto_pres, tvb, offset, -1, ENC_NA);
		pres_tree = proto_item_add_subtree(ti, ett_pres);
	}

	switch(session->spdu_type){
		case SES_CONNECTION_REQUEST:
			offset = dissect_pres_CP_type(FALSE, tvb, offset, &asn1_ctx, pres_tree, hf_pres_CP_type);
			break;
		case SES_CONNECTION_ACCEPT:
			offset = dissect_pres_CPA_PPDU(FALSE, tvb, offset, &asn1_ctx, pres_tree, hf_pres_CPA_PPDU);
			break;
		case SES_ABORT:
		case SES_ABORT_ACCEPT:
			offset = dissect_pres_Abort_type(FALSE, tvb, offset, &asn1_ctx, pres_tree, hf_pres_Abort_type);
			break;
		case SES_DATA_TRANSFER:
			offset = dissect_pres_CPC_type(FALSE, tvb, offset, &asn1_ctx, pres_tree, hf_pres_user_data);
			break;
		case SES_TYPED_DATA:
			offset = dissect_pres_Typed_data_type(FALSE, tvb, offset, &asn1_ctx, pres_tree, hf_pres_Typed_data_type);
			break;
		case SES_RESYNCHRONIZE:
			offset = dissect_pres_RS_PPDU(FALSE, tvb, offset, &asn1_ctx, pres_tree, -1);
			break;
		case SES_RESYNCHRONIZE_ACK:
			offset = dissect_pres_RSA_PPDU(FALSE, tvb, offset, &asn1_ctx, pres_tree, -1);
			break;
		case SES_REFUSE:
			offset = dissect_pres_CPR_PPDU(FALSE, tvb, offset, &asn1_ctx, pres_tree, hf_pres_CPR_PPDU);
			break;
		default:
			offset = dissect_pres_CPC_type(FALSE, tvb, offset, &asn1_ctx, pres_tree, hf_pres_user_data);
			break;
	}

	return offset;
}

static void
dissect_pres(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0, old_offset;

	session = ((struct SESSION_DATA_STRUCTURE*)(pinfo->private_data));

	/* first, try to check length   */
	/* do we have at least 4 bytes  */
	if (!tvb_bytes_exist(tvb, 0, 4)){
		if (session && session->spdu_type != SES_MAJOR_SYNC_POINT) {
			proto_tree_add_text(parent_tree, tvb, offset,
					    tvb_reported_length_remaining(tvb,offset),"User data");
			return;  /* no, it isn't a presentation PDU */
		}
	}

	/* save pointers for calling the acse dissector  */
	global_tree = parent_tree;
	global_pinfo = pinfo;

	/* if the session unit-data packet then we process it */
	/* as a connectionless presentation protocol unit data */
	if(session && session->spdu_type == CLSES_UNIT_DATA)
	{
		proto_tree * clpres_tree = NULL;
		proto_item *ti;

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CL-PRES");
  		col_clear(pinfo->cinfo, COL_INFO);

		if (parent_tree)
		{
			ti = proto_tree_add_item(parent_tree, proto_clpres, tvb, offset, -1, ENC_NA);
			clpres_tree = proto_item_add_subtree(ti, ett_pres);
		}

		/* dissect the packet */
		dissect_UD_type_PDU(tvb, pinfo, clpres_tree);
		return;
	}

	/*  we can't make any additional checking here   */
	/*  postpone it before dissector will have more information */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PRES");
  	col_clear(pinfo->cinfo, COL_INFO);

	if (session && session->spdu_type == SES_MAJOR_SYNC_POINT) {
		/* This is a reassembly initiated in packet-ses */
		char *oid = find_oid_by_pres_ctx_id (pinfo, session->pres_ctx_id);
		if (oid) {
			call_ber_oid_callback (oid, tvb, offset, pinfo, parent_tree);
		} else {
			proto_tree_add_text(parent_tree, tvb, offset,
					    tvb_reported_length_remaining(tvb,offset),"User data");
		}
		return;
         }

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset = offset;
		offset = dissect_ppdu(tvb, offset, pinfo, parent_tree);
		if(offset <= old_offset){
			proto_tree_add_text(parent_tree, tvb, offset, -1,"Invalid offset");
			THROW(ReportedBoundsError);
		}
	}
}


/*--- proto_register_pres -------------------------------------------*/
void proto_register_pres(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pres_CP_type,
      { "CP-type", "pres.cptype",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_CPA_PPDU,
      { "CPA-PPDU", "pres.cpapdu",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_Abort_type,
      { "Abort type", "pres.aborttype",
        FT_UINT32, BASE_DEC, VALS(pres_Abort_type_vals), 0,
        NULL, HFILL }},
    { &hf_pres_CPR_PPDU,
      { "CPR-PPDU", "pres.cprtype",
        FT_UINT32, BASE_DEC, VALS(pres_CPR_PPDU_vals), 0,
        NULL, HFILL }},
    { &hf_pres_Typed_data_type,
      { "Typed data type", "pres.Typed_data_type",
        FT_UINT32, BASE_DEC, VALS(pres_Typed_data_type_vals), 0,
        NULL, HFILL }},


#include "packet-pres-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		&ett_pres,
#include "packet-pres-ettarr.c"
  };

  static uat_field_t users_flds[] = {
    UAT_FLD_DEC(pres_users,ctx_id,"Context Id","Presentation Context Identifier"),
    UAT_FLD_CSTRING(pres_users,oid,"Syntax Name OID","Abstract Syntax Name (Object Identifier)"),
    UAT_END_FIELDS
  };

  uat_t* users_uat = uat_new("PRES Users Context List",
                             sizeof(pres_user_t),
                             "pres_context_list",
                             TRUE,
                             (void*) &pres_users,
                             &num_pres_users,
                             UAT_CAT_PORTS,
                             "ChPresContextList",
                             pres_copy_cb,
                             NULL,
                             pres_free_cb,
                             NULL,
                             users_flds);

  static module_t *pres_module;

  /* Register protocol */
  proto_pres = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("pres", dissect_pres, proto_pres);

  /* Register connectionless protocol (just for the description) */
  proto_clpres = proto_register_protocol(CLPNAME, CLPSNAME, CLPFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pres, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(pres_init);

  pres_module = prefs_register_protocol(proto_pres, NULL);

  prefs_register_uat_preference(pres_module, "users_table", "Users Context List",
                                "A table that enumerates user protocols to be used against"
                                " specific presentation context identifiers",
                                users_uat);
}


/*--- proto_reg_handoff_pres ---------------------------------------*/
void proto_reg_handoff_pres(void) {

/*	register_ber_oid_dissector("0.4.0.0.1.1.1.1", dissect_pres, proto_pres,
	  "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) abstractSyntax(1) pres(1) version1(1)"); */

}
