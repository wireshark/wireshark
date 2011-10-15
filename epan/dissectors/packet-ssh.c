/* packet-ssh.c
 * Routines for ssh packet dissection
 *
 * Huagang XIE <huagang@intruvert.com>
 * Kees Cook <kees@outflux.net>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-mysql.c
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
 *
 *
 * Note:  support SSH v1 and v2  now.
 *
 */

/* SSH version 2 is defined in:
 *
 * RFC 4250: The Secure Shell (SSH) Protocol Assigned Numbers
 * RFC 4251: The Secure Shell (SSH) Protocol Architecture
 * RFC 4252: The Secure Shell (SSH) Authentication Protocol
 * RFC 4253: The Secure Shell (SSH) Transport Layer Protocol
 * RFC 4254: The Secure Shell (SSH) Connection Protocol
 *
 * SSH versions under 2 were never officially standardized.
 */

/* "SSH" prefixes are for version 2, whereas "SSH1" is for version 1 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include "packet-tcp.h"
#include <epan/prefs.h>

/* SSH Version 1 definition , from openssh ssh1.h */
#define SSH1_MSG_NONE				0	/* no message */
#define SSH1_MSG_DISCONNECT			1	/* cause (string) */
#define SSH1_SMSG_PUBLIC_KEY			2	/* ck,msk,srvk,hostk */
#define SSH1_CMSG_SESSION_KEY			3	/* key (BIGNUM) */
#define SSH1_CMSG_USER				4	/* user (string) */


#define SSH_VERSION_UNKNOWN 	0
#define SSH_VERSION_1		1
#define SSH_VERSION_2		2

/* proto data */

struct ssh_pdu_data{
	guint	counter;
	guint	number;
};

struct ssh_flow_data {
	guint 	req_counter;
	guint	rsp_counter;
	guint 	version;

	gchar*  mac_client_request;
	gchar*  mac_server_offer;
	gchar*	mac;
	gint	mac_length;

	gchar*  enc_client_request;
	gchar*  enc_server_offer;
	gchar*	enc;

	gchar*  comp_client_request;
	gchar*  comp_server_offer;
	gchar*	comp;
};

static int proto_ssh = -1;
static int hf_ssh_packet_length= -1;
static int hf_ssh_padding_length= -1;
static int hf_ssh_payload= -1;
static int hf_ssh_protocol= -1;
static int hf_ssh_dh_gex_min= -1;
static int hf_ssh_dh_gex_nbits= -1;
static int hf_ssh_dh_gex_max= -1;
static int hf_ssh_encrypted_packet= -1;
static int hf_ssh_padding_string= -1;
static int hf_ssh_mac_string= -1;
static int hf_ssh_msg_code = -1;
static int hf_ssh_cookie = -1;
static int hf_ssh_mpint_g= -1;
static int hf_ssh_mpint_p= -1;
static int hf_ssh_mpint_e= -1;
static int hf_ssh_mpint_f= -1;
static int hf_ssh_mpint_length= -1;
static int hf_ssh_kexdh_host_key= -1;
static int hf_ssh_kexdh_host_key_length= -1;
static int hf_ssh_kexdh_h_sig= -1;
static int hf_ssh_kexdh_h_sig_length= -1;
static int hf_ssh_kex_algorithms = -1;
static int hf_ssh_server_host_key_algorithms = -1;
static int hf_ssh_encryption_algorithms_client_to_server = -1;
static int hf_ssh_encryption_algorithms_server_to_client = -1;
static int hf_ssh_mac_algorithms_client_to_server=-1;
static int hf_ssh_mac_algorithms_server_to_client=-1;
static int hf_ssh_compression_algorithms_client_to_server=-1;
static int hf_ssh_compression_algorithms_server_to_client=-1;
static int hf_ssh_languages_client_to_server=-1;
static int hf_ssh_languages_server_to_client=-1;
static int hf_ssh_kex_algorithms_length= -1;
static int hf_ssh_server_host_key_algorithms_length= -1;
static int hf_ssh_encryption_algorithms_client_to_server_length= -1;
static int hf_ssh_encryption_algorithms_server_to_client_length= -1;
static int hf_ssh_mac_algorithms_client_to_server_length= -1;
static int hf_ssh_mac_algorithms_server_to_client_length= -1;
static int hf_ssh_compression_algorithms_client_to_server_length= -1;
static int hf_ssh_compression_algorithms_server_to_client_length= -1;
static int hf_ssh_languages_client_to_server_length= -1;
static int hf_ssh_languages_server_to_client_length= -1;
static int hf_ssh_kex_first_packet_follows = -1;
static int hf_ssh_kex_reserved = -1;

static gint ett_ssh = -1;
static gint ett_key_exchange= -1;
static gint ett_key_init= -1;
static gint ett_ssh1= -1;
static gint ett_ssh2= -1;

static gboolean ssh_desegment = TRUE;

#define TCP_PORT_SSH  22

/* Message Numbers (from RFC 4250) (1-255) */

/* Transport layer protocol: generic (1-19) */
#define SSH_MSG_DISCONNECT			1
#define SSH_MSG_IGNORE				2
#define SSH_MSG_UNIMPLEMENTED			3
#define SSH_MSG_DEBUG				4
#define SSH_MSG_SERVICE_REQUEST			5
#define SSH_MSG_SERVICE_ACCEPT			6

/* Transport layer protocol: Algorithm negotiation (20-29) */
#define SSH_MSG_KEXINIT				20
#define SSH_MSG_NEWKEYS				21

/* Transport layer: Key exchange method specific (reusable) (30-49) */
#define SSH_MSG_KEXDH_INIT			30
#define SSH_MSG_KEXDH_REPLY			31
#define SSH_MSG_KEX_DH_GEX_INIT			32
#define SSH_MSG_KEX_DH_GEX_REPLY		33
#define SSH_MSG_KEX_DH_GEX_REQUEST		34

/* User authentication protocol: generic (50-59) */
#define SSH_MSG_USERAUTH_REQUEST		50
#define SSH_MSG_USERAUTH_FAILURE		51
#define SSH_MSG_USERAUTH_SUCCESS		52
#define SSH_MSG_USERAUTH_BANNER			53

/* User authentication protocol: method specific (reusable) (50-79) */

/* Connection protocol: generic (80-89) */
#define SSH_MSG_GLOBAL_REQUEST			80
#define SSH_MSG_REQUEST_SUCCESS			81
#define SSH_MSG_REQUEST_FAILURE			82

/* Connection protocol: channel related messages (90-127) */
#define SSH_MSG_CHANNEL_OPEN			90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION	91
#define SSH_MSG_CHANNEL_OPEN_FAILURE		92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST		93
#define SSH_MSG_CHANNEL_DATA			94
#define SSH_MSG_CHANNEL_EXTENDED_DATA		95
#define SSH_MSG_CHANNEL_EOF			96
#define SSH_MSG_CHANNEL_CLOSE			97
#define SSH_MSG_CHANNEL_REQUEST			98
#define SSH_MSG_CHANNEL_SUCCESS			99
#define SSH_MSG_CHANNEL_FAILURE			100

/* 128-191 reserved for client protocols */
/* 192-255 local extensions */

static const value_string ssh2_msg_vals[] = {
	{ SSH_MSG_DISCONNECT, "Disconnect" },
	{ SSH_MSG_IGNORE, "Ignore" },
	{ SSH_MSG_UNIMPLEMENTED, "Unimplemented" },
	{ SSH_MSG_DEBUG, "Debug" },
	{ SSH_MSG_SERVICE_REQUEST, "Service Request" },
	{ SSH_MSG_SERVICE_ACCEPT, "Service Accept" },
	{ SSH_MSG_KEXINIT, "Key Exchange Init" },
	{ SSH_MSG_NEWKEYS, "New Keys" },
	{ SSH_MSG_KEXDH_INIT, "Diffie-Hellman Key Exchange Init" },
	{ SSH_MSG_KEXDH_REPLY, "Diffie-Hellman Key Exchange Reply" },
	{ SSH_MSG_KEX_DH_GEX_INIT, "Diffie-Hellman GEX Init" },
	{ SSH_MSG_KEX_DH_GEX_REPLY, "Diffie-Hellman GEX Reply" },
	{ SSH_MSG_KEX_DH_GEX_REQUEST, "Diffie-Hellman GEX Request" },
	{ SSH_MSG_USERAUTH_REQUEST, "User Authentication Request" },
	{ SSH_MSG_USERAUTH_FAILURE, "User Authentication Failure" },
	{ SSH_MSG_USERAUTH_SUCCESS, "User Authentication Success" },
	{ SSH_MSG_USERAUTH_BANNER, "User Authentication Banner" },
	{ SSH_MSG_GLOBAL_REQUEST, "Global Request" },
	{ SSH_MSG_REQUEST_SUCCESS, "Request Success" },
	{ SSH_MSG_REQUEST_FAILURE, "Request Failure" },
	{ SSH_MSG_CHANNEL_OPEN, "Channel Open" },
	{ SSH_MSG_CHANNEL_OPEN_CONFIRMATION, "Channel Open Confirmation" },
	{ SSH_MSG_CHANNEL_OPEN_FAILURE, "Channel Open Failure" },
	{ SSH_MSG_CHANNEL_WINDOW_ADJUST, "Window Adjust" },
	{ SSH_MSG_CHANNEL_DATA, "Channel Data" },
	{ SSH_MSG_CHANNEL_EXTENDED_DATA, "Channel Extended Data" },
	{ SSH_MSG_CHANNEL_EOF, "Channel EOF" },
	{ SSH_MSG_CHANNEL_CLOSE, "Channel Close" },
	{ SSH_MSG_CHANNEL_REQUEST, "Channel Request" },
	{ SSH_MSG_CHANNEL_SUCCESS, "Channel Success" },
	{ SSH_MSG_CHANNEL_FAILURE, "Channel Failure" },
  	{ 0, NULL }
};

static const value_string ssh1_msg_vals[] = {
	{SSH1_MSG_NONE,"No Message"},
	{SSH1_MSG_DISCONNECT, "Disconnect"},
	{SSH1_SMSG_PUBLIC_KEY,"Public Key"},
	{SSH1_CMSG_SESSION_KEY,"Session Key"},
	{SSH1_CMSG_USER,"User"},
	{0, NULL}
};


static const value_string ssh_opcode_vals[] _U_ = {
  { 0,          NULL }
};

static int ssh_dissect_key_init(tvbuff_t *tvb, int offset, proto_tree *tree,
		int is_response,
		struct ssh_flow_data *global_data);

static int ssh_dissect_ssh1(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
		int offset, proto_tree *tree,int is_response,
		int number, gboolean *need_desegmentation);
static int ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
		int offset, proto_tree *tree,int is_response,
		int number, gboolean *need_desegmentation );
static int ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
		int offset, proto_tree *tree,int is_response,
		int number, gboolean *need_desegmentation );
static int ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
		int offset, proto_tree *tree,int is_response,guint *version,
		gboolean *need_desegmentation);
static int ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
		int offset, proto_tree *tree,int is_response);
static proto_item * ssh_proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian);



static void
dissect_ssh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_tree	*ssh_tree = NULL;
	proto_item	*ti;
	conversation_t  *conversation=NULL;
	gint		remain_length;
	int		last_offset;
	guint		this_number,number;

	int		offset = 0;

	gboolean	is_response;
	gboolean 	is_newdata;
	gboolean 	need_desegmentation;
	guint		version;

	struct ssh_pdu_data *this_data=NULL;
	struct ssh_flow_data *global_data=NULL;

	is_newdata = FALSE;
	this_data = p_get_proto_data(pinfo->fd, proto_ssh);

	conversation = find_or_create_conversation(pinfo);

	global_data = conversation_get_proto_data(conversation,proto_ssh);
	if(!global_data ) {
		global_data = se_alloc0(sizeof(struct ssh_flow_data));
		global_data->version=SSH_VERSION_UNKNOWN;
		global_data->mac_length=-1;

		conversation_add_proto_data(conversation,proto_ssh,global_data);
	}

/*
 *	end of attaching data
 */
	if (pinfo->destport == pinfo->match_uint) {
	  	is_response=FALSE;
		if(!this_data) {
			this_data = se_alloc(sizeof(struct ssh_pdu_data));
			this_data->counter = global_data->req_counter++;
			p_add_proto_data(pinfo->fd, proto_ssh, this_data);
			is_newdata = TRUE;
		}
	}else {
		is_response=TRUE;
		if(!this_data) {
			this_data = se_alloc(sizeof(struct ssh_flow_data));
			this_data->counter = global_data->rsp_counter++;
			p_add_proto_data(pinfo->fd, proto_ssh, this_data);
			is_newdata = TRUE;
		}
	}
	if(tree) {
		  ti = proto_tree_add_item(tree, proto_ssh, tvb, offset, -1, FALSE);
		  ssh_tree = proto_item_add_subtree(ti, ett_ssh);
	}
	number = 0;

	version = global_data->version;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		switch(version) {
			case SSH_VERSION_UNKNOWN:
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSH");
				break;
			case SSH_VERSION_1:
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv1");
				break;
			case SSH_VERSION_2:
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv2");
				break;

		}
	}

	if(this_data->counter != 0 && version == SSH_VERSION_UNKNOWN) {
		offset = ssh_dissect_encrypted_packet(tvb, pinfo,
			global_data,
			offset,ssh_tree,is_response);
		return;
	}

	while(tvb_reported_length_remaining(tvb,offset)> 0 ) {
		need_desegmentation = FALSE;
		last_offset = offset;
		this_number = this_data->counter+number;

		if(number > 1 && is_newdata) {
			/* update the this_data and flow_data */
			if(is_response) {
				global_data->rsp_counter++;
			} else {
				global_data->req_counter++;
			}
		}

		number++;
		if(this_number == 0)  {
			offset = ssh_dissect_protocol(tvb, pinfo,
					global_data,
					offset,ssh_tree, is_response,
					&version, &need_desegmentation);
			if(!is_response) {
				global_data->version= version;
			}
		} else {
			switch(version) {

			case SSH_VERSION_UNKNOWN:
				/*
				 * We use "tvb_ensure_length_remaining()"
				 * to make sure there actually *is* data
				 * remaining.
				 *
				 * This means we're guaranteed that
				 * "remain_length" is positive.
				 */
				remain_length = tvb_ensure_length_remaining(tvb,
				    offset);
				proto_tree_add_text(ssh_tree, tvb, offset,
						remain_length,
						"Unknown SSH version data");
				offset += remain_length;
				break;

			case SSH_VERSION_1:
				offset = ssh_dissect_ssh1(tvb, pinfo, global_data,
						offset,ssh_tree,is_response,this_number,
						&need_desegmentation);
				break;

			case SSH_VERSION_2:
				offset = ssh_dissect_ssh2(tvb, pinfo, global_data,
						offset,ssh_tree,is_response,this_number,
						&need_desegmentation);
				break;
			}
		}

		if(need_desegmentation) return;
                if(offset <= last_offset)
                        THROW(ReportedBoundsError);
	}
}

static int
ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
	       	int offset, proto_tree *tree,int is_response, int this_number,
		gboolean *need_desegmentation)
{
	proto_item *ti;
	proto_item *ssh2_tree=NULL;

	if(tree) {
		GString *title=g_string_new("SSH Version 2");

		if (global_data->enc || global_data->mac || global_data->comp) {
			g_string_append_printf(title," (");
			if (global_data->enc)
				g_string_append_printf(title,"encryption:%s%s",
					global_data->enc,
					global_data->mac || global_data->comp
						? " " : "");
			if (global_data->mac)
				g_string_append_printf(title,"mac:%s%s",
					global_data->mac,
					global_data->comp ? " " : "");
			if (global_data->comp)
				g_string_append_printf(title,"compression:%s",
					global_data->comp);
			g_string_append_printf(title,")");
		}

		ti=proto_tree_add_text(tree,tvb,offset,-1, "%s", title->str);
		ssh2_tree = proto_item_add_subtree(ti ,ett_ssh2);
		if (title) g_string_free(title,TRUE);
	}

	if((is_response && this_number > 3) || (!is_response && this_number>4)) {
		offset = ssh_dissect_encrypted_packet(tvb, pinfo,
				global_data,
				offset,ssh2_tree,is_response);
	} else {
		offset = ssh_dissect_key_exchange(tvb,pinfo, global_data,
			offset,ssh2_tree,is_response,this_number,
			need_desegmentation);
	}

	return offset;
}
static int
ssh_dissect_ssh1(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data _U_,
	       	int offset, proto_tree *tree,int is_response,
		int number, gboolean *need_desegmentation)
{
	guint 	plen, padding_length,len;
	guint8 	msg_code;
	guint	remain_length;

	proto_item *ti;
	proto_item *ssh1_tree =NULL;

	if(tree) {
		ti=proto_tree_add_text(tree,tvb,offset,-1,"SSH Version 1");
		ssh1_tree = proto_item_add_subtree(ti ,ett_ssh1);
	}

	/*
	 * We use "tvb_ensure_length_remaining()" to make sure there
	 * actually *is* data remaining.
	 *
	 * This means we're guaranteed that "remain_length" is positive.
	 */
	remain_length = tvb_ensure_length_remaining(tvb,offset);
	/*
	 * Can we do reassembly?
	 */
	if (ssh_desegment && pinfo->can_desegment) {
		/*
		 * Yes - would an SSH header starting at this offset be split
		 * across segment boundaries?
		 */
		if(remain_length < 4) {
			/*
			 * Yes.  Tell the TCP dissector where the data for
			 * this message starts in the data it handed us and
			 * that we need "some more data."  Don't tell it
			 * exactly how many bytes we need because if/when we
			 * ask for even more (after the header) that will
			 * break reassembly.
			 */
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                	*need_desegmentation = TRUE;
                	return offset;
		}
	}
	plen = tvb_get_ntohl(tvb, offset) ;
	padding_length  = 8 - plen%8;


	if (ssh_desegment && pinfo->can_desegment) {
		if(plen+4+padding_length >  remain_length ) {
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = plen+padding_length - remain_length;
                	*need_desegmentation = TRUE;
                	return offset;
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
  		col_add_fstr(pinfo->cinfo, COL_INFO, "%s: ",
			is_response?"Server":"Client");
	}

	if(plen >= 0xffff) {
		if (ssh1_tree && plen > 0) {
			  proto_tree_add_uint_format(ssh1_tree, hf_ssh_packet_length, tvb,
			    offset, 4, plen,"Overly large length %x",plen);
		}
		plen = remain_length-4-padding_length;
	} else {
		if (ssh1_tree && plen > 0) {
			  proto_tree_add_uint(ssh1_tree, hf_ssh_packet_length, tvb,
			    offset, 4, plen);
		}
	}
	offset+=4;
/* padding length */

	if (tree) {
		  proto_tree_add_uint(ssh1_tree, hf_ssh_padding_length, tvb,
		    offset, padding_length, padding_length);
	}
	offset += padding_length;
/*
	if(tree) {
		tf=proto_tree_add_text(tree,tvb,offset,-1,"SSH Version 1");
		ssh1_tree = proto_item_add_subtree(tf ,ett_ssh1);
	}
*/
	/* msg_code */
	if(number == 1 ) {
		msg_code = tvb_get_guint8(tvb, offset);
		if (tree) {
		  	proto_tree_add_uint_format(ssh1_tree, hf_ssh_msg_code, tvb,
		    		offset, 1, msg_code,"Msg code: %s (%u)",
				val_to_str(msg_code, ssh1_msg_vals, "Unknown (%u)"),
				msg_code);
		}
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO,
			val_to_str(msg_code, ssh1_msg_vals, "Unknown (%u)"));
		}
		offset += 1;
		len = plen -1;
	} else {
		len = plen;
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, "Encrypted packet len=%d", len);
		}
	}
	/* payload */
	if (ssh1_tree ) {
		ssh_proto_tree_add_item(ssh1_tree, hf_ssh_payload,
		    tvb, offset, len, ENC_NA);
	}
	offset+=len;

	return offset;
}

static int
ssh_tree_add_mpint(tvbuff_t *tvb, int offset, proto_tree *tree,
	int hf_ssh_mpint_selection)
{
	guint len = tvb_get_ntohl(tvb, offset);
	if (tree) {
		proto_tree_add_uint(tree, hf_ssh_mpint_length, tvb,
			offset, 4, len);
	}
	offset+=4;
	if (tree) {
		ssh_proto_tree_add_item(tree, hf_ssh_mpint_selection,
			tvb, offset, len, FALSE);
	}
	return 4+len;
}

static int
ssh_tree_add_string(tvbuff_t *tvb, int offset, proto_tree *tree,
	int hf_ssh_string, int hf_ssh_string_length)
{
	guint len = tvb_get_ntohl(tvb, offset);
	if (tree) {
		proto_tree_add_uint(tree, hf_ssh_string_length, tvb,
			offset, 4, len);
	}
	offset+=4;
	if (tree) {
		ssh_proto_tree_add_item(tree, hf_ssh_string,
			tvb, offset, len, FALSE);
	}
	return 4+len;
}

static int
ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
	       	int offset, proto_tree *tree,int is_response,int number,
		gboolean *need_desegmentation)
{
	guint 	plen,len;
	guint8	padding_length;
	guint	remain_length;
	int 	last_offset=offset;
	guint 	msg_code;

	proto_item *tf;
	proto_item *key_ex_tree =NULL;

	/*
	 * We use "tvb_ensure_length_remaining()" to make sure there
	 * actually *is* data remaining.
	 *
	 * This means we're guaranteed that "remain_length" is positive.
	 */
	remain_length = tvb_ensure_length_remaining(tvb,offset);
	/*
	 * Can we do reassembly?
	 */
	if (ssh_desegment && pinfo->can_desegment) {
		/*
		 * Yes - would an SSH header starting at this offset
		 * be split across segment boundaries?
		 */
		if(remain_length < 4) {
			/*
			 * Yes.  Tell the TCP dissector where the data for
			 * this message starts in the data it handed us and
			 * that we need "some more data."  Don't tell it
			 * exactly how many bytes we need because if/when we
			 * ask for even more (after the header) that will
			 * break reassembly.
			 */
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                	*need_desegmentation = TRUE;
                	return offset;
		}
	}
	plen = tvb_get_ntohl(tvb, offset) ;

	if (ssh_desegment && pinfo->can_desegment) {
		if(plen +4 >  remain_length ) {
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = plen+4 - remain_length;
                	*need_desegmentation = TRUE;
                	return offset;
		}
	}
	/*
	 * Need to check plen > 0x80000000 here
	 */

	if (check_col(pinfo->cinfo, COL_INFO)) {
  		col_add_fstr(pinfo->cinfo, COL_INFO, "%s: ",
			is_response?"Server":"Client");
	}

	if(plen >= 0xffff) {
		if (tree) {
		  	proto_tree_add_uint_format(tree, hf_ssh_packet_length, tvb,
		    		offset, 4, plen,"Overly large number 0x%x",plen);
		}
		plen = remain_length-4;
	} else {
		if (tree) {
		  	proto_tree_add_uint(tree, hf_ssh_packet_length, tvb,
		    		offset, 4, plen);
		}
	}
	offset+=4;
/* padding length */
	padding_length = tvb_get_guint8(tvb, offset);
	if (tree) {
		  proto_tree_add_uint(tree, hf_ssh_padding_length, tvb,
		    offset, 1, padding_length);
	}
	offset += 1;

	if(tree) {
		tf=proto_tree_add_text(tree,tvb,offset,-1,"Key Exchange");
		key_ex_tree = proto_item_add_subtree(tf ,ett_key_exchange);
	}
	/* msg_code */
	msg_code = tvb_get_guint8(tvb, offset);
	if (tree) {
		  proto_tree_add_uint_format(key_ex_tree, hf_ssh_msg_code, tvb,
		    offset, 1, msg_code,"Msg code: %s (%u)",
			val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"),
			msg_code);

	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_str(pinfo->cinfo, COL_INFO,
			val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
	}
	offset += 1;

	/* 16 bytes cookie  */
	if(number == 1) {
		offset = ssh_dissect_key_init(tvb, offset, key_ex_tree, is_response, global_data);
	}
	else {
		/* DH GEX Request (min/nbits/max) */
		if (msg_code == 34) {
			ssh_proto_tree_add_item(key_ex_tree, hf_ssh_dh_gex_min,
			    tvb, offset, 4, ENC_NA);
			offset+=4;
			ssh_proto_tree_add_item(key_ex_tree, hf_ssh_dh_gex_nbits,
			    tvb, offset, 4, ENC_NA);
			offset+=4;
			ssh_proto_tree_add_item(key_ex_tree, hf_ssh_dh_gex_max,
			    tvb, offset, 4, ENC_NA);
			offset+=4;
		}
		/* DH Key Exchange Reply (g/p) */
		if (msg_code == 31) {
			offset+=ssh_tree_add_mpint(tvb,offset,key_ex_tree,hf_ssh_mpint_p);
			offset+=ssh_tree_add_mpint(tvb,offset,key_ex_tree,hf_ssh_mpint_g);
		}
		/* DH GEX Init (e) */
		if (msg_code == 32) {
			offset+=ssh_tree_add_mpint(tvb,offset,key_ex_tree,hf_ssh_mpint_e);
		}
		/* DH GEX Reply (f) */
		if (msg_code == 33) {
			offset+=ssh_tree_add_string(tvb,offset,key_ex_tree,hf_ssh_kexdh_host_key,hf_ssh_kexdh_host_key_length);
			offset+=ssh_tree_add_mpint(tvb,offset,key_ex_tree,hf_ssh_mpint_f);
			offset+=ssh_tree_add_string(tvb,offset,key_ex_tree,hf_ssh_kexdh_h_sig,hf_ssh_kexdh_h_sig_length);
		}
 	}

	len = plen+4-padding_length-(offset-last_offset);
	if (tree ) {
		ssh_proto_tree_add_item(key_ex_tree, hf_ssh_payload,
		    tvb, offset, len, ENC_NA);
	}
	offset +=len;

	/* padding */
	if(tree) {
		ssh_proto_tree_add_item(key_ex_tree, hf_ssh_padding_string,
		    		tvb, offset, padding_length, ENC_NA);
	}
	offset+= padding_length;

	/* MAC , if there is still bytes, treat it as 16bytes MAC*/
	if(msg_code == SSH_MSG_KEX_DH_GEX_REPLY) {
		len = tvb_reported_length_remaining(tvb,offset);
		if(len == 16) {
			if(tree) {
				proto_tree_add_item(key_ex_tree, hf_ssh_mac_string,
		    			tvb, offset, len , ENC_NA);
			}
			offset+=len;
		}
	}

	return offset;
}
static int
ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
	       	int offset, proto_tree *tree,int is_response)
{
	gint len;

	len = tvb_reported_length_remaining(tvb,offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
  		col_add_fstr(pinfo->cinfo, COL_INFO, "Encrypted %s packet len=%d",
			is_response?"response":"request",len);
	}
	if (tree ) {
		gint encrypted_len = len;

		if (global_data && global_data->mac_length>0)
			encrypted_len -= global_data->mac_length;

		ssh_proto_tree_add_item(tree, hf_ssh_encrypted_packet,
		    		tvb, offset, encrypted_len, ENC_NA);

		if (global_data && global_data->mac_length>0)
			ssh_proto_tree_add_item(tree, hf_ssh_mac_string,
				tvb, offset+encrypted_len,
				global_data->mac_length , ENC_NA);
  	}
	offset+=len;
	return offset;
}

static int
ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
		struct ssh_flow_data *global_data,
	       	int offset, proto_tree *tree, int is_response, guint * version,
		gboolean *need_desegmentation)
{
	guint	remain_length;
	gint	linelen, protolen;

	/*
	 *  If the first packet do not contain the banner,
	 *  it is dump in the middle of a flow or not a ssh at all
	 */
	if(tvb_strncaseeql(tvb,offset,"SSH-",4) != 0 ) {
		offset = ssh_dissect_encrypted_packet(tvb, pinfo,
			global_data,
			offset,tree,is_response);
		return offset;
	}

	if(!is_response) {
	       	if(tvb_strncaseeql(tvb,offset,"SSH-2.",6) == 0 ) {
			*(version) = SSH_VERSION_2;
		}else if(tvb_strncaseeql(tvb,offset,"SSH-1.99-",9) == 0 ) {
			*(version) = SSH_VERSION_2;
	       	}else if(tvb_strncaseeql(tvb,offset,"SSH-1.",6) == 0 ) {
			*(version) = SSH_VERSION_1;
	       }
	}

	/*
	 * We use "tvb_ensure_length_remaining()" to make sure there
	 * actually *is* data remaining.
	 *
	 * This means we're guaranteed that "remain_length" is positive.
	 */
	remain_length = tvb_ensure_length_remaining(tvb,offset);
	/*linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	 */
	linelen = tvb_find_guint8(tvb, offset, -1, '\n');

	if (ssh_desegment && pinfo->can_desegment) {
		if(linelen == -1 || remain_length < (guint)linelen-offset ) {
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = linelen-remain_length;
                	*need_desegmentation = TRUE;
                	return offset;
		}
	}
	if(linelen == -1 ) {
		/* XXX - reassemble across segment boundaries? */
		linelen = remain_length;
		protolen = linelen;
	} else {
		linelen = linelen - offset + 1;
		protolen = linelen - 1;
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
  		col_add_fstr(pinfo->cinfo, COL_INFO, "%s Protocol: %s",
			is_response?"Server":"Client",
			tvb_format_text(tvb,offset,protolen));
	}
	if (tree ) {
		ssh_proto_tree_add_item(tree, hf_ssh_protocol,
		    		tvb, offset, linelen, ENC_ASCII|ENC_NA);
  	}
	offset+=linelen;
	return offset;
}

#define SSH_PROPOSAL(item)\
	{ &hf_ssh_ ## item, &hf_ssh_ ## item ## _length }

static struct {
	int *value, *length;
} ssh_proposals[] = {
	SSH_PROPOSAL(kex_algorithms),
	SSH_PROPOSAL(server_host_key_algorithms),
	SSH_PROPOSAL(encryption_algorithms_client_to_server),
	SSH_PROPOSAL(encryption_algorithms_server_to_client),
	SSH_PROPOSAL(mac_algorithms_client_to_server),
	SSH_PROPOSAL(mac_algorithms_server_to_client),
	SSH_PROPOSAL(compression_algorithms_client_to_server),
	SSH_PROPOSAL(compression_algorithms_server_to_client),
	SSH_PROPOSAL(languages_client_to_server),
	SSH_PROPOSAL(languages_server_to_client),
	{NULL, NULL}
};

static void
ssh_set_mac_length(struct ssh_flow_data *global_data, gchar *mac_name)
{
	char *size_str;
	guint size=0;

	if (!global_data || !mac_name) return;

	if ((size_str=g_strrstr(mac_name,"-")) && ((size=atoi(size_str+1)))) {
		global_data->mac_length = size;
	}
	else if (strcmp(mac_name,"hmac-sha1") == 0) {
		global_data->mac_length = 20;
	}
	else if (strcmp(mac_name,"hmac-md5") == 0) {
		global_data->mac_length = 12;
	}
	else if (strcmp(mac_name,"none") == 0) {
		global_data->mac_length = 0;
	}
}

static gint
ssh_gslist_compare_strings(gconstpointer a, gconstpointer b)
{
	if (a == NULL && b == NULL)
		return 0;
	if (a == NULL)
		return -1;
	if (b == NULL)
		return 1;
	return strcmp((char*)a,(char*)b);
}

/* expects that *result is NULL */
static void
ssh_choose_algo(gchar *client, gchar *server, gchar **result)
{
	gchar **server_strings=NULL;
	gchar **client_strings=NULL;
	gchar **step;
	GSList* server_list = NULL;

	if (!client || !server || !result || *result)
		return;

	server_strings = g_strsplit(server,",",0);
	for (step = server_strings; *step; step++) {
		server_list = g_slist_append(server_list, *step);
	}

	client_strings = g_strsplit(client,",",0);
	for (step = client_strings; *step; step++) {
		GSList *agreed;
		if ((agreed=g_slist_find_custom(server_list, *step, ssh_gslist_compare_strings))) {
			*result = se_strdup(agreed->data);
			break;
		}
	}

	g_strfreev(client_strings);
	g_slist_free(server_list);
	g_strfreev(server_strings);
}

static void
ssh_evaluate_negotiation(tvbuff_t *tvb, int offset, int len,
			 int hf_value, int hf_client, int hf_server,
                         gchar **client, gchar **server, gchar **agreed)
{
	if (!tvb || !client || !server || !agreed) return;

	if (hf_value == hf_client && !*client) {
		*client = tvb_get_seasonal_string(tvb, offset, len);
	}

	if (hf_value == hf_server && !*server) {
		*server = tvb_get_seasonal_string(tvb, offset, len);
	}

	if (*client && *server && !*agreed) {
		ssh_choose_algo(*client, *server, agreed);
	}
}

static int
ssh_dissect_key_init(tvbuff_t *tvb, int offset, proto_tree *tree,
		int is_response _U_,
		struct ssh_flow_data *global_data )
{
	guint	len;
	int	i;
	int start_offset = offset;

	proto_item *tf = NULL;
	proto_item *key_init_tree=NULL;

	if (tree) {
		tf=proto_tree_add_text(tree,tvb,offset,-1,"Algorithms");
		key_init_tree = proto_item_add_subtree(tf, ett_key_init);
		proto_tree_add_item(key_init_tree, hf_ssh_cookie,
		    tvb, offset, 16, ENC_NA);
	}
	offset += 16;

	for (i = 0; ssh_proposals[i].value; i++) {
		len = tvb_get_ntohl(tvb, offset);
		if (key_init_tree) {
			proto_tree_add_uint(key_init_tree,
				*ssh_proposals[i].length, tvb, offset, 4, len);
		}
		offset+=4;
		if (key_init_tree) {
			ssh_proto_tree_add_item(key_init_tree,
				*ssh_proposals[i].value, tvb, offset, len, FALSE);
		}
		/* record negotiations */
		if (global_data) {
			/* figure out MAC */
			ssh_evaluate_negotiation(tvb, offset, len,
						 *ssh_proposals[i].value,
						 hf_ssh_mac_algorithms_client_to_server,
						 hf_ssh_mac_algorithms_server_to_client,
						 &global_data->mac_client_request,
						 &global_data->mac_server_offer,
						 &global_data->mac);
			if (global_data->mac && global_data->mac_length<0)
				ssh_set_mac_length(global_data, global_data->mac);

			/* figure out Encryption */
			ssh_evaluate_negotiation(tvb, offset, len,
						 *ssh_proposals[i].value,
						 hf_ssh_encryption_algorithms_client_to_server,
						 hf_ssh_encryption_algorithms_server_to_client,
						 &global_data->enc_client_request,
						 &global_data->enc_server_offer,
						 &global_data->enc);

			/* figure out Compression */
			ssh_evaluate_negotiation(tvb, offset, len,
						 *ssh_proposals[i].value,
						 hf_ssh_compression_algorithms_client_to_server,
						 hf_ssh_compression_algorithms_server_to_client,
						 &global_data->comp_client_request,
						 &global_data->comp_server_offer,
						 &global_data->comp);
		}

		offset+=len;
	}

	ssh_proto_tree_add_item(key_init_tree, hf_ssh_kex_first_packet_follows,
	    tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	ssh_proto_tree_add_item(key_init_tree, hf_ssh_kex_reserved,
	    tvb, offset, 4, ENC_NA);
	offset+=4;

	if (tf != NULL) {
		proto_item_set_len(tf, offset-start_offset);
	}

	return offset;
}
static proto_item *
ssh_proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian)
{
	if (tree && length <0xffff && length > 0) {
		return proto_tree_add_item(tree, hfindex, tvb, start, length,little_endian);
	}
	return NULL;
}

void
proto_register_ssh(void)
{
  static hf_register_info hf[] = {
    { &hf_ssh_packet_length,
      { "Packet Length",      "ssh.packet_length",
        FT_UINT32, BASE_DEC, NULL,  0x0,
        "SSH packet length", HFILL }},

    { &hf_ssh_padding_length,
      { "Padding Length",  "ssh.padding_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "SSH Packet Number", HFILL }},

    { &hf_ssh_msg_code,
      { "Message Code",  "ssh.message_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "SSH Message Code", HFILL }},

    { &hf_ssh_mpint_g,
      { "DH base (G)",  "ssh.dh.g",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH DH base (G)", HFILL }},

    { &hf_ssh_mpint_p,
      { "DH modulus (P)",  "ssh.dh.p",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH DH modulus (P)", HFILL }},

    { &hf_ssh_mpint_e,
      { "DH client e",  "ssh.dh.e",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH DH client e", HFILL }},

    { &hf_ssh_mpint_f,
      { "DH server f",  "ssh.dh.f",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH DH server f", HFILL }},

    { &hf_ssh_mpint_length,
      { "Multi Precision Integer Length",      "ssh.mpint_length",
        FT_UINT32, BASE_DEC, NULL,  0x0,
        "SSH mpint length", HFILL }},

    { &hf_ssh_kexdh_host_key,
      { "KEX DH host key",         "ssh.kexdh.host_key",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH KEX DH host key", HFILL }},

    { &hf_ssh_kexdh_h_sig,
      { "KEX DH H signature",         "ssh.kexdh.h_sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH KEX DH H signature", HFILL }},

    { &hf_ssh_kexdh_host_key_length,
      { "KEX DH host key length",         "ssh.kexdh.host_key_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH KEX DH host key length", HFILL }},

    { &hf_ssh_kexdh_h_sig_length,
      { "KEX DH H signature length",         "ssh.kexdh.h_sig_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH KEX DH H signature length", HFILL }},

    { &hf_ssh_encrypted_packet,
      { "Encrypted Packet",  "ssh.encrypted_packet",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH Protocol Packet", HFILL }},

    { &hf_ssh_protocol,
      { "Protocol",  "ssh.protocol",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "SSH Protocol", HFILL }},

    { &hf_ssh_cookie,
      { "Cookie",  "ssh.cookie",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH Cookie", HFILL }},

    { &hf_ssh_kex_first_packet_follows,
      { "KEX First Packet Follows",      "ssh.kex.first_packet_follows",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "SSH KEX Fist Packet Follows", HFILL }},

    { &hf_ssh_kex_reserved,
      { "Reserved",  "ssh.kex.reserved",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH Protocol KEX Reserved", HFILL }},

    { &hf_ssh_dh_gex_min,
      { "DH GEX Min",  "ssh.dh_gex.min",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH DH GEX Minimum", HFILL }},

    { &hf_ssh_dh_gex_nbits,
      { "DH GEX Numbers of Bits",  "ssh.dh_gex.nbits",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH DH GEX Number of Bits", HFILL }},

    { &hf_ssh_dh_gex_max,
      { "DH GEX Max",  "ssh.dh_gex.max",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH DH GEX Maximum", HFILL }},

    { &hf_ssh_payload,
      { "Payload",  "ssh.payload",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH Payload", HFILL }},

    { &hf_ssh_padding_string,
      { "Padding String",  "ssh.padding_string",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH Padding String", HFILL }},

    { &hf_ssh_mac_string,
      { "MAC",  "ssh.mac",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "SSH Protocol Packet MAC", HFILL }},

    { &hf_ssh_kex_algorithms,
      { "kex_algorithms string",         "ssh.kex_algorithms",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH kex_algorithms string", HFILL }},

    { &hf_ssh_server_host_key_algorithms,
      { "server_host_key_algorithms string",         "ssh.server_host_key_algorithms",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH server_host_key_algorithms string", HFILL }},

    { &hf_ssh_encryption_algorithms_client_to_server,
      { "encryption_algorithms_client_to_server string",         "ssh.encryption_algorithms_client_to_server",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH encryption_algorithms_client_to_server string", HFILL }},

    { &hf_ssh_encryption_algorithms_server_to_client,
      { "encryption_algorithms_server_to_client string",         "ssh.encryption_algorithms_server_to_client",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH encryption_algorithms_server_to_client string", HFILL }},

    { &hf_ssh_mac_algorithms_client_to_server,
      { "mac_algorithms_client_to_server string",         "ssh.mac_algorithms_client_to_server",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH mac_algorithms_client_to_server string", HFILL }},

    { &hf_ssh_mac_algorithms_server_to_client,
      { "mac_algorithms_server_to_client string",         "ssh.mac_algorithms_server_to_client",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH mac_algorithms_server_to_client string", HFILL }},

    { &hf_ssh_compression_algorithms_client_to_server,
      { "compression_algorithms_client_to_server string",         "ssh.compression_algorithms_client_to_server",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH compression_algorithms_client_to_server string", HFILL }},

    { &hf_ssh_compression_algorithms_server_to_client,
      { "compression_algorithms_server_to_client string",         "ssh.compression_algorithms_server_to_client",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH compression_algorithms_server_to_client string", HFILL }},

    { &hf_ssh_languages_client_to_server,
      { "languages_client_to_server string",         "ssh.languages_client_to_server",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH languages_client_to_server string", HFILL }},

    { &hf_ssh_languages_server_to_client,
      { "languages_server_to_client string",         "ssh.languages_server_to_client",
        FT_STRINGZ, BASE_NONE, NULL, 0x0,
        "SSH languages_server_to_client string", HFILL }},

    { &hf_ssh_kex_algorithms_length,
      { "kex_algorithms length",         "ssh.kex_algorithms_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH kex_algorithms length", HFILL }},

    { &hf_ssh_server_host_key_algorithms_length,
      { "server_host_key_algorithms length",         "ssh.server_host_key_algorithms_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH server_host_key_algorithms length", HFILL }},

    { &hf_ssh_encryption_algorithms_client_to_server_length,
      { "encryption_algorithms_client_to_server length",         "ssh.encryption_algorithms_client_to_server_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH encryption_algorithms_client_to_server length", HFILL }},

    { &hf_ssh_encryption_algorithms_server_to_client_length,
      { "encryption_algorithms_server_to_client length",         "ssh.encryption_algorithms_server_to_client_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH encryption_algorithms_server_to_client length", HFILL }},

    { &hf_ssh_mac_algorithms_client_to_server_length,
      { "mac_algorithms_client_to_server length",         "ssh.mac_algorithms_client_to_server_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH mac_algorithms_client_to_server length", HFILL }},

    { &hf_ssh_mac_algorithms_server_to_client_length,
      { "mac_algorithms_server_to_client length",         "ssh.mac_algorithms_server_to_client_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH mac_algorithms_server_to_client length", HFILL }},

    { &hf_ssh_compression_algorithms_client_to_server_length,
      { "compression_algorithms_client_to_server length",         "ssh.compression_algorithms_client_to_server_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH compression_algorithms_client_to_server length", HFILL }},

    { &hf_ssh_compression_algorithms_server_to_client_length,
      { "compression_algorithms_server_to_client length",         "ssh.compression_algorithms_server_to_client_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH compression_algorithms_server_to_client length", HFILL }},

    { &hf_ssh_languages_client_to_server_length,
      { "languages_client_to_server length",         "ssh.languages_client_to_server_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH languages_client_to_server length", HFILL }},

    { &hf_ssh_languages_server_to_client_length,
      { "languages_server_to_client length",         "ssh.languages_server_to_client_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SSH languages_server_to_client length", HFILL }},
  	};

  	static gint *ett[] = {
    		&ett_ssh,
		&ett_key_exchange,
		&ett_ssh1,
		&ett_ssh2,
		&ett_key_init
  	};
  	module_t *ssh_module;

  	proto_ssh = proto_register_protocol("SSH Protocol", "SSH", "ssh");
	proto_register_field_array(proto_ssh, hf, array_length(hf));
  	proto_register_subtree_array(ett, array_length(ett));

  	ssh_module = prefs_register_protocol(proto_ssh, NULL);
	prefs_register_bool_preference(ssh_module, "desegment_buffers",
		"Reassemble SSH buffers spanning multiple TCP segments",
		"Whether the SSH dissector should reassemble SSH buffers spanning multiple TCP segments. "
		"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&ssh_desegment);
}

void
proto_reg_handoff_ssh(void)
{
	dissector_handle_t ssh_handle;

	ssh_handle = create_dissector_handle(dissect_ssh, proto_ssh);

	dissector_add_uint("tcp.port", TCP_PORT_SSH, ssh_handle);
}
