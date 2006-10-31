/* packet-cmp.c
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-cmp.h"
#include "packet-crmf.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include <epan/emem.h>
#include "packet-tcp.h"
#include <epan/prefs.h>
#include <epan/nstime.h>

#define PNAME  "Certificate Management Protocol"
#define PSNAME "CMP"
#define PFNAME "cmp"

#define TCP_PORT_CMP 829

/* desegmentation of CMP over TCP */
static gboolean cmp_desegment = TRUE;

/* Initialize the protocol and registered fields */
int proto_cmp = -1;
static int hf_cmp_type_oid = -1;
static int hf_cmp_rm = -1;
static int hf_cmp_type = -1;
static int hf_cmp_poll_ref = -1;
static int hf_cmp_next_poll_ref = -1;
static int hf_cmp_ttcb = -1;
#include "packet-cmp-hf.c"

/* Initialize the subtree pointers */
static gint ett_cmp = -1;
#include "packet-cmp-ett.c"

static const char *object_identifier_id;


#include "packet-cmp-fn.c"

static int
dissect_cmp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_cmp_PKIMessage(FALSE, tvb, 0, pinfo, tree, -1);
}

#define CMP_TYPE_PKIMSG		0
#define CMP_TYPE_POLLREP	1
#define CMP_TYPE_POLLREQ	2
#define CMP_TYPE_NEGPOLLREP	3
#define CMP_TYPE_PARTIALMSGREP	4
#define CMP_TYPE_FINALMSGREP	5
#define CMP_TYPE_ERRORMSGREP	6
static const value_string cmp_pdu_types[] = {
	{ CMP_TYPE_PKIMSG,		"pkiMsg" },
	{ CMP_TYPE_POLLREP,		"pollRep" },
	{ CMP_TYPE_POLLREQ,		"pollReq" },
	{ CMP_TYPE_NEGPOLLREP,		"negPollRep" },
	{ CMP_TYPE_PARTIALMSGREP,	"partialMsgRep" },
	{ CMP_TYPE_FINALMSGREP,		"finalMsgRep" },
	{ CMP_TYPE_ERRORMSGREP,		"errorMsgRep" },
	{ 0, NULL },
};

static void dissect_cmp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	tvbuff_t   *next_tvb;
	guint32 pdu_len;
	guint8 pdu_type;
	nstime_t	ts;

	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "PKIXCMP");
	}


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_guint8(tvb, 4);

	proto_tree_add_uint(tree, hf_cmp_rm, tvb, 0, 4, pdu_len);
	proto_tree_add_uint(tree, hf_cmp_type, tvb, 4, 1, pdu_type);

        if (check_col (pinfo->cinfo, COL_INFO)) {
            col_set_str (pinfo->cinfo, COL_INFO, val_to_str (pdu_type, cmp_pdu_types, "0x%x"));
        }

	switch(pdu_type){
	case CMP_TYPE_PKIMSG:
		next_tvb = tvb_new_subset(tvb, 5, tvb_length_remaining(tvb, 5), pdu_len);
		dissect_cmp_pdu(next_tvb, pinfo, tree);
		break;
	case CMP_TYPE_POLLREP:
		proto_tree_add_item(tree, hf_cmp_poll_ref, tvb, 0, 4, FALSE);

		ts.secs = tvb_get_ntohl(tvb, 4);
		ts.nsecs = 0;
		proto_tree_add_time(tree, hf_cmp_ttcb, tvb, 4, 4, &ts);
		break;
	case CMP_TYPE_POLLREQ:
		proto_tree_add_item(tree, hf_cmp_poll_ref, tvb, 0, 4, FALSE);
		break;
	case CMP_TYPE_NEGPOLLREP:
		break;
	case CMP_TYPE_PARTIALMSGREP:
		proto_tree_add_item(tree, hf_cmp_next_poll_ref, tvb, 0, 4, FALSE);

		ts.secs = tvb_get_ntohl(tvb, 4);
		ts.nsecs = 0;
		proto_tree_add_time(tree, hf_cmp_ttcb, tvb, 4, 4, &ts);

		next_tvb = tvb_new_subset(tvb, 13, tvb_length_remaining(tvb, 13), pdu_len);
		dissect_cmp_pdu(next_tvb, pinfo, tree);
		break;
	case CMP_TYPE_FINALMSGREP:
		next_tvb = tvb_new_subset(tvb, 5, tvb_length_remaining(tvb, 5), pdu_len);
		dissect_cmp_pdu(next_tvb, pinfo, tree);
		break;
	case CMP_TYPE_ERRORMSGREP:
		/*XXX to be added*/
		break;
	}

}

static guint get_cmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 plen;

  /*
   * Get the length of the CMP-over-TCP packet.
   */
  plen = tvb_get_ntohl(tvb, offset);

  return plen+4;
}

/* CMP over TCP    RFC2510 section 5.2 */
static int
dissect_cmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint32 pdu_len;
	guint8 pdu_type;

	/* only attempt to dissect it as CMP over TCP if we have
	 * at least 5 bytes.
	 */
	if (!tvb_bytes_exist(tvb, 0, 5)) {
		return 0;
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_guint8(tvb, 4);

	/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes 
	 * in size.
	 * It is definitely at least 1 byte to accomodate the flags byte 
	 */
	if((pdu_len<=0)||(pdu_len>10000)){
		return 0;
	}
	/* type is between 0 and 6 */
	if(pdu_type>6){
		return 0;
	}
	/* type 0 contains a PKI message and must therefore be >= 3 bytes 
	 * long (flags + BER TAG + BER LENGTH
	 */
	if((pdu_type==0)&&(pdu_len<3)){
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, parent_tree, cmp_desegment, 4, get_cmp_pdu_len,
		dissect_cmp_tcp_pdu);

	return tvb_length(tvb);
}

static int
dissect_cmp_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "PKIXCMP");
	}


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	return dissect_cmp_pdu(tvb, pinfo, tree);
}


/*--- proto_register_cmp ----------------------------------------------*/
void proto_register_cmp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmp_type_oid,
      { "InfoType", "cmp.type.oid",
        FT_STRING, BASE_NONE, NULL, 0,
        "Type of InfoTypeAndValue", HFILL }},
    { &hf_cmp_rm,
      { "Record Marker", "cmp.rm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Record Marker  length of PDU in bytes", HFILL }},
    { &hf_cmp_type,
      { "Type", "cmp.type",
        FT_UINT8, BASE_DEC, VALS(cmp_pdu_types), 0,
        "PDU Type", HFILL }},
    { &hf_cmp_poll_ref,
      { "Polling Reference", "cmp.poll_ref",
        FT_UINT32, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_cmp_next_poll_ref,
      { "Next Polling Reference", "cmp.next_poll_ref",
        FT_UINT32, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_cmp_ttcb,
      { "Time to check Back", "cmp.ttcb",
        FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0,
        "", HFILL }},
#include "packet-cmp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_cmp,
#include "packet-cmp-ettarr.c"
  };
  module_t *cmp_module;

  /* Register protocol */
  proto_cmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  cmp_module = prefs_register_protocol(proto_cmp, NULL);
  prefs_register_bool_preference(cmp_module, "desegment",
		"Reassemble CMP-over-TCP messages spanning multiple TCP segments",
		"Whether the CMP-over-TCP dissector should reassemble messages spanning multiple TCP segments. "
		"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&cmp_desegment);
}


/*--- proto_reg_handoff_cmp -------------------------------------------*/
void proto_reg_handoff_cmp(void) {
	dissector_handle_t cmp_http_handle;
	dissector_handle_t cmp_tcp_handle;

	cmp_http_handle = new_create_dissector_handle(dissect_cmp_http, proto_cmp);
	dissector_add_string("media_type", "application/pkixcmp", cmp_http_handle);

	cmp_tcp_handle = new_create_dissector_handle(dissect_cmp_tcp, proto_cmp);
	dissector_add("tcp.port", TCP_PORT_CMP, cmp_tcp_handle);

/*#include "packet-cmp-dis-tab.c"*/
}

