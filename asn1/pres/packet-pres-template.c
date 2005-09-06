/* packet-pres.c
 * Routine to dissect ISO 8823 OSI Presentation Protocol packets
 * Based on the dissector by 
 * Yuriy Sidelnikov <YSidelnikov@hotmail.com>
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
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-ses.h"
#include "packet-pres.h"
#include "packet-rtse.h"


#define PNAME  "ISO 8823 OSI Presentation Protocol"
#define PSNAME "PRES"
#define PFNAME "pres"

/* Initialize the protocol and registered fields */
int proto_pres = -1;
/*   type of session envelop */
static struct SESSION_DATA_STRUCTURE* session = NULL;

/*      pointers for acse dissector  */
proto_tree *global_tree  = NULL;
packet_info *global_pinfo = NULL;

/* dissector for data */
static dissector_handle_t data_handle;

static char abstract_syntax_name_oid[BER_MAX_OID_STR_LEN];
static guint32 presentation_context_identifier;

/* to keep track of presentation context identifiers and protocol-oids */
typedef struct _pres_ctx_oid_t {
	/* XXX here we should keep track of ADDRESS/PORT as well */
	guint32 ctx_id;
	char *oid;
} pres_ctx_oid_t;
static GHashTable *pres_ctx_oid_table = NULL;

static int hf_pres_CP_type = -1;
static int hf_pres_CPA_PPDU = -1;
static int hf_pres_Abort_type = -1;
static int hf_pres_CPR_PPDU = -1;
static int hf_pres_Typed_data_type = -1;

#include "packet-pres-hf.c"

/* Initialize the subtree pointers */
static gint ett_pres           = -1;

#include "packet-pres-ett.c"


static guint
pres_ctx_oid_hash(gconstpointer k)
{
	pres_ctx_oid_t *pco=(pres_ctx_oid_t *)k;
	return pco->ctx_id;
}
/* XXX this one should be made ADDRESS/PORT aware */
static gint
pres_ctx_oid_equal(gconstpointer k1, gconstpointer k2)
{
	pres_ctx_oid_t *pco1=(pres_ctx_oid_t *)k1;
	pres_ctx_oid_t *pco2=(pres_ctx_oid_t *)k2;
	return pco1->ctx_id==pco2->ctx_id;
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
register_ctx_id_and_oid(packet_info *pinfo _U_, guint32 idx, char *oid)
{
	pres_ctx_oid_t *pco, *tmppco;
	pco=se_alloc(sizeof(pres_ctx_oid_t));
	pco->ctx_id=idx;
	pco->oid=se_strdup(oid);

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
	pco.ctx_id=idx;
	tmppco=(pres_ctx_oid_t *)g_hash_table_lookup(pres_ctx_oid_table, &pco);
	if(tmppco){
		return tmppco->oid;
	}
	return NULL;
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
/* do we have spdu type from the session dissector?  */
	if( !pinfo->private_data ){
		if(tree){
			proto_tree_add_text(tree, tvb, offset, -1,
				"Internal error:can't get spdu type from session dissector.");
			return  FALSE;
		}
	}else{
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
		if(session->spdu_type == 0 ){
			if(tree){
				proto_tree_add_text(tree, tvb, offset, -1,
					"Internal error:wrong spdu type %x from session dissector.",session->spdu_type);
				return  FALSE;
			}
		}
	}
/* get type of tag      */
	s_type = tvb_get_guint8(tvb, offset);
		/*  set up type of Ppdu */
  	if (check_col(pinfo->cinfo, COL_INFO))
					col_add_str(pinfo->cinfo, COL_INFO,
						val_to_str(session->spdu_type, ses_vals, "Unknown Ppdu type (0x%02x)"));
  if (tree){
	  ti = proto_tree_add_item(tree, proto_pres, tvb, offset, -1,
		    FALSE);
	  pres_tree = proto_item_add_subtree(ti, ett_pres);
  }

	switch(session->spdu_type){
		case SES_CONNECTION_REQUEST:
			offset = dissect_pres_CP_type(FALSE, tvb, offset, pinfo, pres_tree, hf_pres_CP_type);
			break;
		case SES_CONNECTION_ACCEPT:
			offset = dissect_pres_CPA_PPDU(FALSE, tvb, offset, pinfo, pres_tree, hf_pres_CPA_PPDU);
			break;
		case SES_ABORT:
		case SES_ABORT_ACCEPT:
			offset = dissect_pres_Abort_type(FALSE, tvb, offset, pinfo, pres_tree, hf_pres_Abort_type);
			break;
		case SES_DATA_TRANSFER:
			offset = dissect_pres_CPC_type(FALSE, tvb, offset, pinfo, pres_tree, hf_pres_user_data);
			break;
		case SES_TYPED_DATA:
			offset = dissect_pres_Typed_data_type(FALSE, tvb, offset, pinfo, pres_tree, hf_pres_Typed_data_type);
			break;
		case SES_RESYNCHRONIZE:
			offset = dissect_pres_RS_PPDU(FALSE, tvb, offset, pinfo, pres_tree, -1);
			break;
		case SES_RESYNCHRONIZE_ACK:
			offset = dissect_pres_RSA_PPDU(FALSE, tvb, offset, pinfo, pres_tree, -1);
			break;
		default:
			offset = dissect_pres_CPC_type(FALSE, tvb, offset, pinfo, pres_tree, hf_pres_user_data);
			break;
	}

	return offset;
}

void
dissect_pres(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0, old_offset;
/* first, try to check length   */
/* do we have at least 4 bytes  */
	if (!tvb_bytes_exist(tvb, 0, 4)){
		proto_tree_add_text(parent_tree, tvb, offset, 
			tvb_reported_length_remaining(tvb,offset),"User data");
		return;  /* no, it isn't a presentation PDU */
	}

	/*  we can't make any additional checking here   */
	/*  postpone it before dissector will have more information */

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PRES");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);
	/* save pointers for calling the acse dissector  */
	global_tree = parent_tree;
	global_pinfo = pinfo;

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
        "", HFILL }},
    { &hf_pres_CPA_PPDU,
      { "CPA-PPDU", "pres.cpapdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_pres_Abort_type,
      { "Abort type", "pres.aborttype",
        FT_UINT32, BASE_DEC, VALS(pres_Abort_type_vals), 0,
        "", HFILL }},
    { &hf_pres_CPR_PPDU,
      { "CPR-PPDU", "pres.cprtype",
        FT_UINT32, BASE_DEC, VALS(pres_CPR_PPDU_vals), 0,
        "", HFILL }},
    { &hf_pres_Typed_data_type,
      { "Typed data type", "pres.Typed_data_type",
        FT_UINT32, BASE_DEC, VALS(pres_Typed_data_type_vals), 0,
        "", HFILL }},


#include "packet-pres-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		&ett_pres,
#include "packet-pres-ettarr.c"
  };

  /* Register protocol */
  proto_pres = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("pres", dissect_pres, proto_pres);
  /* Register fields and subtrees */
  proto_register_field_array(proto_pres, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(pres_init);

}


/*--- proto_reg_handoff_pres ---------------------------------------*/
void proto_reg_handoff_pres(void) {

/*	register_ber_oid_dissector("0.4.0.0.1.1.1.1", dissect_pres, proto_pres, 
	  "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) abstractSyntax(1) pres(1) version1(1)"); */

	data_handle = find_dissector("data");

}
