/* packet-kpasswd.c
 * Routines for kpasswd packet dissection
 *    Ronnie Sahlberg 2003
 *
 * See RFC 3244 
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

#include <epan/packet.h>
#include "packet-kerberos.h"
#include "packet-ber.h"
#include <epan/prefs.h>

static int proto_kpasswd = -1;
static int hf_kpasswd_message_len = -1;
static int hf_kpasswd_version = -1;
static int hf_kpasswd_result = -1;
static int hf_kpasswd_result_string = -1;
static int hf_kpasswd_newpassword = -1;
static int hf_kpasswd_ap_req_len = -1;
static int hf_kpasswd_ap_req_data = -1;
static int hf_kpasswd_krb_priv_message = -1;
static int hf_kpasswd_ChangePasswdData = -1;

static gint ett_kpasswd = -1;
static gint ett_ap_req_data = -1;
static gint ett_krb_priv_message = -1;
static gint ett_ChangePasswdData = -1;


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
	dissect_kerberos_main(tvb, pinfo, tree, FALSE, NULL);
}


static int dissect_kpasswd_newpassword(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_kpasswd_newpassword, NULL);

	return offset;
}

static ber_sequence_t ChangePasswdData_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_kpasswd_newpassword },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, 
		dissect_krb5_cname },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, 
		dissect_krb5_realm },
	{ 0, 0, 0, NULL }
};

static int
dissect_kpasswd_user_data_request(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree)
{
    int offset=0;

    offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, ChangePasswdData_sequence, hf_kpasswd_ChangePasswdData, ett_ChangePasswdData);

    return offset;
}

static kerberos_callbacks cb_req[] = {
    { KRB_CBTAG_PRIV_USER_DATA,      dissect_kpasswd_user_data_request },
    { 0, NULL }
};

#define KRB5_KPASSWD_SUCCESS             0
#define KRB5_KPASSWD_MALFORMED           1
#define KRB5_KPASSWD_HARDERROR           2
#define KRB5_KPASSWD_AUTHERROR           3
#define KRB5_KPASSWD_SOFTERROR           4
#define KRB5_KPASSWD_ACCESSDENIED        5
#define KRB5_KPASSWD_BAD_VERSION         6
#define KRB5_KPASSWD_INITIAL_FLAG_NEEDED 7
static const value_string kpasswd_result_types[] = {
    { KRB5_KPASSWD_SUCCESS, "Success" },
    { KRB5_KPASSWD_MALFORMED, "Malformed" },
    { KRB5_KPASSWD_HARDERROR, "HardError" },
    { KRB5_KPASSWD_AUTHERROR, "AuthError" },
    { KRB5_KPASSWD_SOFTERROR, "SoftError" },
    { KRB5_KPASSWD_ACCESSDENIED, "AccessDenied" },
    { KRB5_KPASSWD_BAD_VERSION, "BadVersion" },
    { KRB5_KPASSWD_INITIAL_FLAG_NEEDED, "InitialFlagNeeded" },
    { 0, NULL }
};

static int
dissect_kpasswd_user_data_reply(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree)
{
    int offset=0;
    guint16 result;

    /* result */
    result = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_kpasswd_result, tvb, offset, 2, result);
    offset+=2;
    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, 
                   val_to_str(result, kpasswd_result_types, "Result: %u"));

   
    /* optional result string */
    if(tvb_length_remaining(tvb, offset)){
        proto_tree_add_item(tree, hf_kpasswd_result_string, tvb, offset, tvb_length_remaining(tvb, offset), FALSE); 
	offset+=tvb_length_remaining(tvb, offset);
    }

    return offset;
}


static kerberos_callbacks cb_rep[] = {
    { KRB_CBTAG_PRIV_USER_DATA,      dissect_kpasswd_user_data_reply },
    { 0, NULL }
};

static void
dissect_kpasswd_krb_priv_message(packet_info *pinfo _U_, tvbuff_t *tvb, proto_tree *parent_tree, gboolean isrequest)
{
	proto_item *it;
	proto_tree *tree=NULL;

	if(parent_tree){
		it=proto_tree_add_item(parent_tree, hf_kpasswd_krb_priv_message, tvb, 0, -1, FALSE);
		tree=proto_item_add_subtree(it, ett_krb_priv_message);
	}
	if(isrequest){
		dissect_kerberos_main(tvb, pinfo, tree, FALSE, cb_req);
	} else {
		dissect_kerberos_main(tvb, pinfo, tree, FALSE, cb_rep);
	}
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

	/* it might be a KERBEROS ERROR */
	if(tvb_get_guint8(tvb, offset)==0x7e){
		next_tvb=tvb_new_subset(tvb, offset, -1, -1);
		dissect_kerberos_main(next_tvb, pinfo, tree, FALSE, NULL);
		return;
	}

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
	dissect_kpasswd_krb_priv_message(pinfo, next_tvb, kpasswd_tree, (version==0xff80));

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
	{ &hf_kpasswd_result,
	  	{ "Result", "kpasswd.result", FT_UINT16, BASE_DEC,
		VALS(kpasswd_result_types), 0, "Result", HFILL }},
	{ &hf_kpasswd_result_string,
	  	{ "Result String", "kpasswd.result_string", FT_STRING, BASE_NONE,
		NULL, 0, "Result String", HFILL }},
	{ &hf_kpasswd_newpassword,
	  	{ "New Password", "kpasswd.new_password", FT_STRING, BASE_NONE,
		NULL, 0, "New Password", HFILL }},
	{ &hf_kpasswd_ap_req_data,
		{ "AP_REQ", "kpasswd.ap_req", FT_NONE, BASE_NONE,
		NULL, 0, "AP_REQ structure", HFILL }},
	{ &hf_kpasswd_krb_priv_message,
		{ "KRB-PRIV", "kpasswd.krb_priv", FT_NONE, BASE_NONE,
		NULL, 0, "KRB-PRIV message", HFILL }},
	{ &hf_kpasswd_ChangePasswdData, {
	    "ChangePasswdData", "kpasswd.ChangePasswdData", FT_NONE, BASE_DEC,
	    NULL, 0, "Change Password Data structure", HFILL }},
	};

	static gint *ett[] = {
		&ett_kpasswd,
		&ett_ap_req_data,
		&ett_krb_priv_message,
		&ett_ChangePasswdData,
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
