/* packet-kpasswd.c
 * Routines for kpasswd packet dissection
 *    Ronnie Sahlberg 2003
 *
 * See RFC 3244 
 *
 * $Id: packet-kpasswd.c,v 1.1 2003/11/07 05:26:27 sahlberg Exp $
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

#include <epan/packet.h>
#include "prefs.h"

static int proto_kpasswd = -1;
static int hf_kpasswd_message_len = -1;
static int hf_kpasswd_version = -1;
static int hf_kpasswd_ap_req_len = -1;
static int hf_kpasswd_ap_req_data = -1;
static int hf_kpasswd_krb_priv_message = -1;

static gint ett_kpasswd = -1;
static gint ett_ap_req_data = -1;
static gint ett_krb_priv_message = -1;



#define UDP_PORT_KPASSWD		464


static const value_string vers_vals[] = {
	{ 0x0001,	"Reply" },
	{ 0xff80,	"Request" },
	{ 0,	NULL },
};


static void
dissect_kpasswd_ap_req_data(packet_info *pinfo _U_, tvbuff_t *tvb, proto_tree *parent_tree)
{
	proto_item *it;
	proto_tree *tree=NULL;

	if(parent_tree){
		it=proto_tree_add_item(parent_tree, hf_kpasswd_ap_req_data, tvb, 0, -1, FALSE);
		tree=proto_item_add_subtree(it, ett_ap_req_data);
	}
	/* XXX we should dissect the AP_REQ data here */
}

static void
dissect_kpasswd_krb_priv_message(packet_info *pinfo _U_, tvbuff_t *tvb, proto_tree *parent_tree)
{
	proto_item *it;
	proto_tree *tree=NULL;

	if(parent_tree){
		it=proto_tree_add_item(parent_tree, hf_kpasswd_krb_priv_message, tvb, 0, -1, FALSE);
		tree=proto_item_add_subtree(it, ett_krb_priv_message);
	}
	/* XXX we should dissect the KRB-PRIV data here */
}


static void
dissect_kpasswd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *kpasswd_item;
	proto_tree *kpasswd_tree=NULL;
	int offset = 0;
	guint16 message_len, version, ap_req_len;
	tvbuff_t *next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "KPASSWD");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	message_len=tvb_get_ntohs(tvb, offset);
	version=tvb_get_ntohs(tvb, offset+2);
	ap_req_len=tvb_get_ntohs(tvb, offset+4);
	if(tree){
		kpasswd_item=proto_tree_add_item(tree, proto_kpasswd, tvb, offset, message_len, FALSE);
		kpasswd_tree=proto_item_add_subtree(kpasswd_item, ett_kpasswd);
	}

	proto_tree_add_uint(kpasswd_tree, hf_kpasswd_message_len, tvb, offset, 2, message_len);
	proto_tree_add_uint(kpasswd_tree, hf_kpasswd_version, tvb, offset+2, 2, version);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, val_to_str(version, vers_vals, "Unknown command"));
	proto_tree_add_uint(kpasswd_tree, hf_kpasswd_ap_req_len, tvb, offset+4, 2, ap_req_len);
	offset+=6;

	/* AP_REQ data */
	next_tvb=tvb_new_subset(tvb, offset, ap_req_len, ap_req_len);
	dissect_kpasswd_ap_req_data(pinfo, next_tvb, kpasswd_tree);
	offset+=ap_req_len;

	/* KRB-PRIB message */
	next_tvb=tvb_new_subset(tvb, offset, -1, -1);
	dissect_kpasswd_krb_priv_message(pinfo, next_tvb, kpasswd_tree);

}


void
proto_register_kpasswd(void)
{
	static hf_register_info hf[] = {
	{ &hf_kpasswd_message_len,
	  	{ "Message Length", "kpasswd.message_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Message Length", HFILL }},
	{ &hf_kpasswd_ap_req_len,
	  	{ "AP_REQ Length", "kpasswd.ap_req_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of AP_REQ data", HFILL }},
	{ &hf_kpasswd_version,
	  	{ "Version", "kpasswd.version", FT_UINT16, BASE_HEX,
		VALS(vers_vals), 0, "Version", HFILL }},
	{ &hf_kpasswd_ap_req_data,
		{ "AP_REQ", "kpasswd.ap_req", FT_NONE, BASE_NONE,
		NULL, 0, "AP_REQ structure", HFILL }},
	{ &hf_kpasswd_krb_priv_message,
		{ "KRB-PRIV", "kpasswd.krb_priv", FT_NONE, BASE_NONE,
		NULL, 0, "KRB-PRIV message", HFILL }},
	};

	static gint *ett[] = {
		&ett_kpasswd,
		&ett_ap_req_data,
		&ett_krb_priv_message,
	};

	proto_kpasswd = proto_register_protocol("MS Kpasswd",
		"Kpasswd", "kpasswd");
	proto_register_field_array(proto_kpasswd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_kpasswd(void)
{
	dissector_handle_t kpasswd_handle;

	kpasswd_handle = create_dissector_handle(dissect_kpasswd, proto_kpasswd);
	dissector_add("udp.port", UDP_PORT_KPASSWD, kpasswd_handle);
}
