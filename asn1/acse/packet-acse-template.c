/*XXX
  There is a bug in asn2eth that it can not yet handle tagged assignments such
  as EXTERNAL  ::=  [UNIVERSAL 8] IMPLICIT SEQUENCE {

  This bug is workedaround by some .cnf magic but this should be cleaned up 
  once asn2eth learns how to deal with tagged assignments
*/

/* packet-acse.c
 * Routines for ACSE packet dissection
 *   Ronnie Sahlberg 2005
 * dissect_acse() based original handwritten dissector by Sid
 *   Yuriy Sidelnikov <YSidelnikov@hotmail.com>
 *  
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
#include <epan/emem.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ses.h"
#include "packet-pres.h"
#include "packet-x509if.h"

#define PNAME  "ACSE"
#define PSNAME "ACSE"
#define PFNAME "acse"

/* Initialize the protocol and registered fields */
int proto_acse = -1;
#include "packet-acse-hf.c"

/* Initialize the subtree pointers */
static gint ett_acse = -1;
#include "packet-acse-ett.c"

static struct SESSION_DATA_STRUCTURE* session = NULL;

static char object_identifier_id[MAX_OID_STR_LEN];
/* indirect_reference, used to pick up the signalling so we know what
   kind of data is transferred in SES_DATA_TRANSFER_PDUs */
static guint32 indir_ref=0;

static proto_tree *top_tree=NULL;

#if NOT_NEEDED
/* to keep track of presentation context identifiers and protocol-oids */
typedef struct _acse_ctx_oid_t {
	/* XXX here we should keep track of ADDRESS/PORT as well */
	guint32 ctx_id;
	char *oid;
} acse_ctx_oid_t;
static GHashTable *acse_ctx_oid_table = NULL;

static guint
acse_ctx_oid_hash(gconstpointer k)
{
	acse_ctx_oid_t *aco=(acse_ctx_oid_t *)k;
	return aco->ctx_id;
}
/* XXX this one should be made ADDRESS/PORT aware */
static gint
acse_ctx_oid_equal(gconstpointer k1, gconstpointer k2)
{
	acse_ctx_oid_t *aco1=(acse_ctx_oid_t *)k1;
	acse_ctx_oid_t *aco2=(acse_ctx_oid_t *)k2;
	return aco1->ctx_id==aco2->ctx_id;
}

static void
acse_init(void)
{
	if( acse_ctx_oid_table ){
		g_hash_table_destroy(acse_ctx_oid_table);
		acse_ctx_oid_table = NULL;
	}
	acse_ctx_oid_table = g_hash_table_new(acse_ctx_oid_hash,
			acse_ctx_oid_equal);

}

static void
register_ctx_id_and_oid(packet_info *pinfo _U_, guint32 idx, char *oid)
{
	acse_ctx_oid_t *aco, *tmpaco;
	aco=se_alloc(sizeof(acse_ctx_oid_t));
	aco->ctx_id=idx;
	aco->oid=se_strdup(oid);

	/* if this ctx already exists, remove the old one first */
	tmpaco=(acse_ctx_oid_t *)g_hash_table_lookup(acse_ctx_oid_table, aco);
	if(tmpaco){
		g_hash_table_remove(acse_ctx_oid_table, tmpaco);
	}
	g_hash_table_insert(acse_ctx_oid_table, aco, aco);
}
static char *
find_oid_by_ctx_id(packet_info *pinfo _U_, guint32 idx)
{
	acse_ctx_oid_t aco, *tmpaco;
	aco.ctx_id=idx;
	tmpaco=(acse_ctx_oid_t *)g_hash_table_lookup(acse_ctx_oid_table, &aco);
	if(tmpaco){
		return tmpaco->oid;
	}
	return NULL;
}

# endif /* NOT_NEEDED */

#include "packet-acse-fn.c"


/*
* Dissect ACSE PDUs inside a PPDU.
*/
static void
dissect_acse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	proto_item    *item=NULL;
	proto_tree    *tree=NULL;
	char *oid;

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	/* first, try to check length   */
	/* do we have at least 2 bytes  */
	if (!tvb_bytes_exist(tvb, 0, 2)){
		proto_tree_add_text(parent_tree, tvb, offset, 
			tvb_reported_length_remaining(tvb,offset),
			"User data");
		return;  /* no, it isn't a ACSE PDU */
	}
	/* do we have spdu type from the session dissector?  */
	if( !pinfo->private_data ){
		if(parent_tree){
			REPORT_DISSECTOR_BUG("Can't get SPDU type from session dissector.");
		} 
		return  ;
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
		if(session->spdu_type == 0 ) {
			if(parent_tree){
				REPORT_DISSECTOR_BUG(
					ep_strdup_printf("Wrong spdu type %x from session dissector.",session->spdu_type));
				return  ;
			}
		}
	}
	/*  ACSE has only AARQ,AARE,RLRQ,RLRE,ABRT type of pdu */
	/*  reject everything else                              */
	/*  data pdu is not ACSE pdu and has to go directly to app dissector */
	switch(session->spdu_type){
	case SES_CONNECTION_REQUEST:		/*   AARQ   */
	case SES_CONNECTION_ACCEPT:		/*   AARE   */
	case SES_REFUSE:			/*   RLRE   */
	case SES_DISCONNECT:			/*   RLRQ   */
	case SES_FINISH:			/*   RLRE   */
	case SES_ABORT:				/*   ABRT   */
		break;
	case SES_DATA_TRANSFER:
		oid=find_oid_by_pres_ctx_id(pinfo, indir_ref);
		if(oid){
			call_ber_oid_callback(oid, tvb, offset, pinfo, parent_tree);
		} else {
			proto_tree_add_text(parent_tree, tvb, offset, -1,
			    "dissector is not available");
		}
		return;
	default:
		return;
	}

	/* create display subtree for the protocol */
	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_acse, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_acse);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACSE");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);


	/*  we can't make any additional checking here   */
	/*  postpone it before dissector will have more information */
	while (tvb_reported_length_remaining(tvb, offset) > 0){
		int old_offset=offset;
		offset = dissect_acse_ACSE_apdu(FALSE, tvb, offset, pinfo, tree, -1);
		if(offset == old_offset ){
			proto_tree_add_text(tree, tvb, offset, -1,"Malformed packet");
			offset = tvb_length(tvb);
			break;
		}
	}

}

/*--- proto_register_acse ----------------------------------------------*/
void proto_register_acse(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-acse-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_acse,
#include "packet-acse-ettarr.c"
  };

  /* Register protocol */
  proto_acse = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("acse", dissect_acse, proto_acse);

  /* Register fields and subtrees */
  proto_register_field_array(proto_acse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_acse -------------------------------------------*/
void proto_reg_handoff_acse(void) {
/*#include "packet-acse-dis-tab.c"*/

	register_ber_oid_name("2.2.3.1.1","aCSE-id");
	register_ber_oid_dissector("2.2.1.0.1", dissect_acse, proto_acse, "acse-as-id");


}

