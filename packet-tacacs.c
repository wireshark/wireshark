/* packet-tacacs.c
 * Routines for cisco tacacs/xtacacs/tacacs+ packet dissection
 * Copyright 2001, Paul Ionescu <paul@acorp.ro>
 *
 * $Id: packet-tacacs.c,v 1.13 2001/07/10 21:06:53 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from old packet-tacacs.c
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


/* rfc-1492 for tacacs and xtacacs 
 * draft-grant-tacacs-00.txt for tacacs+ (tacplus)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

static int proto_tacacs = -1;

static gint ett_tacacs = -1;

static const value_string tacacs_type_vals[] = {
	{ 1  , "Login" },
	{ 2  , "Response" },
	{ 3  , "Change" },
	{ 4  , "Follow" },
	{ 5  , "Connect" },
	{ 6  , "Superuser" },
	{ 7  , "Logout" },
	{ 8  , "Reload" },
	{ 9  , "SLIP on" },
	{ 10 , "SLIP off" },
	{ 11 , "SLIP Addr" },
	{ 0  , NULL }};	

static const value_string tacacs_reason_vals[] = {
	{ 0  , "none" },
	{ 1  , "expiring" },
	{ 2  , "password" },
	{ 3  , "denied" },
	{ 4  , "quit" },
	{ 5  , "idle" },
	{ 6  , "drop" },
	{ 7  , "bad" }};

static const value_string tacacs_resp_vals[] = {
	{ 0  , "this is not a response" },
	{ 1  , "accepted" },
	{ 2  , "rejected" }};

#define TAC_PLUS_AUTHEN 1
#define TAC_PLUS_AUTHOR 2
#define TAC_PLUS_ACCT   3

static const value_string tacplus_type_vals[] = {
	{ TAC_PLUS_AUTHEN  , "Authentication" },
	{ TAC_PLUS_AUTHOR  , "Authorization" },
	{ TAC_PLUS_ACCT    , "Accounting" },
	{ 0 , NULL }};

#define UDP_PORT_TACACS	49
#define TCP_PORT_TACACS	49

static void
dissect_tacacs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *tacacs_tree, *ti;
	guint8		txt_buff[256],version,type,userlen,passlen;

	version = tvb_get_guint8(tvb,0);
	type = tvb_get_guint8(tvb,1);
	
	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, version==0 ? "TACACS":"XTACACS");

	if (check_col(pinfo->fd, COL_INFO))
		col_add_str(pinfo->fd, COL_INFO, val_to_str(type, tacacs_type_vals, "Unknown Type"));

	if (tree) 
	{
		ti = proto_tree_add_protocol_format(tree, proto_tacacs,
		 tvb, 0, tvb_length(tvb), version==0?"TACACS":"XTACACS");
		tacacs_tree = proto_item_add_subtree(ti, ett_tacacs);

		proto_tree_add_text(tacacs_tree, tvb, 0, 1, "Version = %s ",version==0?"TACACS":"XTACACS" );
		proto_tree_add_text(tacacs_tree, tvb, 1, 1, "Type    = %s ",val_to_str(type, tacacs_type_vals, "Unknown Type"));
		proto_tree_add_text(tacacs_tree, tvb, 2, 2, "Nonce   = 0x%04X ",tvb_get_ntohs(tvb,2));

	if (version==0)
	    {
	    if (type!=2)
	    	{
	    	userlen=tvb_get_guint8(tvb,4);
	    	passlen=tvb_get_guint8(tvb,5);
		proto_tree_add_text(tacacs_tree, tvb, 4, 1, "Username length = %d ",userlen);
		proto_tree_add_text(tacacs_tree, tvb, 5, 1, "Password length = %d ",passlen);
		tvb_get_nstringz0(tvb,6,userlen,txt_buff);
		proto_tree_add_text(tacacs_tree, tvb, 6, userlen,         "User      = %s ",txt_buff);
		tvb_get_nstringz0(tvb,6+userlen,passlen,txt_buff);
		proto_tree_add_text(tacacs_tree, tvb, 6+userlen, passlen, "Password  = %s ",txt_buff);
		}
	    else
	    	{
	    	proto_tree_add_text(tacacs_tree, tvb, 4, 1, "Response = %s",
	    	 val_to_str(tvb_get_guint8(tvb,4), tacacs_resp_vals, "Unknown Response"));
	    	proto_tree_add_text(tacacs_tree, tvb, 5, 1, "Reason   = %s",
	    	 val_to_str(tvb_get_guint8(tvb,5), tacacs_reason_vals, "Unknown Reason"));
		}
	    }
	else
	    {
	    userlen=tvb_get_guint8(tvb,4);
	    passlen=tvb_get_guint8(tvb,5);
	    proto_tree_add_text(tacacs_tree, tvb,  4, 1, "Username length = %d ",userlen);
	    proto_tree_add_text(tacacs_tree, tvb,  5, 1, "Password length = %d ",passlen);
	    proto_tree_add_text(tacacs_tree, tvb,  6, 1, "Response = %s",
	     val_to_str(tvb_get_guint8(tvb,6), tacacs_resp_vals, "Unknown Response"));
	    proto_tree_add_text(tacacs_tree, tvb,  7, 1, "Reason   = %s",
	     val_to_str(tvb_get_guint8(tvb,7), tacacs_reason_vals, "Unknown Reason"));
            proto_tree_add_text(tacacs_tree, tvb,  8, 4, "Result1  = 0x%08X ",tvb_get_ntohl(tvb,8));
            tvb_memcpy(tvb,txt_buff,12,4);
            proto_tree_add_text(tacacs_tree, tvb, 12, 4, "IP addr  = %s ",ip_to_str(txt_buff));
            proto_tree_add_text(tacacs_tree, tvb, 16, 2, "Dst port = %d ",tvb_get_ntohs(tvb,16));
            proto_tree_add_text(tacacs_tree, tvb, 18, 2, "Line     = tty%d ",tvb_get_ntohs(tvb,18));
            proto_tree_add_text(tacacs_tree, tvb, 20, 4, "Result2  = 0x%08X ",tvb_get_ntohl(tvb,20));
            proto_tree_add_text(tacacs_tree, tvb, 24, 2, "Result3  = 0x%04X ",tvb_get_ntohs(tvb,24));
            if (type!=2)
            	{
	    	tvb_get_nstringz0(tvb,26,userlen,txt_buff);
	    	proto_tree_add_text(tacacs_tree, tvb, 26, userlen,         "User      = %s ",txt_buff);
	    	tvb_get_nstringz0(tvb,26+userlen,passlen,txt_buff);
	    	proto_tree_add_text(tacacs_tree, tvb, 26+userlen, passlen, "Password  = %s ",txt_buff);
	    	}
	    }
	}
}

static void
dissect_tacplus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *tacacs_tree, *ti;
	guint8		version,type,seq_no,flags;
	guint32		len;
	gboolean	request=(pinfo->match_port == pinfo->destport);

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "TACACS+");

	if (check_col(pinfo->fd, COL_INFO))
	{
		col_add_str(pinfo->fd, COL_INFO,
			request ? "Request" : "Response");	  
	}

	if (tree) 
	{
		ti = proto_tree_add_protocol_format(tree, proto_tacacs,
		 tvb, 0, tvb_length(tvb), "TACACS+");

		version = tvb_get_guint8(tvb,0);
		type = tvb_get_guint8(tvb,1);
		seq_no = tvb_get_guint8(tvb,2);
		flags = tvb_get_guint8(tvb,3);
		len = tvb_get_ntohl(tvb,8);

		tacacs_tree = proto_item_add_subtree(ti, ett_tacacs);
		proto_tree_add_text(tacacs_tree, tvb, 0, 1, "Major version = %s ",(version&0xf0)==0xc0?"TACACS+":"Unknown Version" );
		proto_tree_add_text(tacacs_tree, tvb, 0, 1, "Minor version = %d ",version&0xf);
		proto_tree_add_text(tacacs_tree, tvb, 1, 1, "Type    = %s ",val_to_str(type, tacplus_type_vals, "Unknown Type"));
		proto_tree_add_text(tacacs_tree, tvb, 2, 1, "Seq. no = %d ",tvb_get_guint8(tvb,2));
		proto_tree_add_text(tacacs_tree, tvb, 3, 1, "Flags   = %s, %s ",
		 (flags&1)==0?"Encripted payload":"Unencripted payload",(flags&4)==0?"Multiple Connections":"Single connection");
		proto_tree_add_text(tacacs_tree, tvb, 4, 4, "Session ID = %d ",tvb_get_ntohl(tvb,4));
		proto_tree_add_text(tacacs_tree, tvb, 8, 4, "Packet len = %d ",len);

		if ((flags&1)==0)
			proto_tree_add_text(tacacs_tree, tvb, 12, len, "Encripted payload");
		else
			proto_tree_add_text(tacacs_tree, tvb, 12, len, "Payload");


	}
}

void
proto_register_tacacs(void)
{
	static gint *ett[] = {
		&ett_tacacs,
	};
	proto_tacacs = proto_register_protocol("TACACS", "TACACS", "tacacs");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tacacs(void)
{
	dissector_add("udp.port", UDP_PORT_TACACS, dissect_tacacs,
	    proto_tacacs);
	dissector_add("tcp.port", TCP_PORT_TACACS, dissect_tacplus,
	    proto_tacacs);
}
