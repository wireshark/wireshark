/* packet-ssh.c
 * Routines for ssh packet dissection
 *
 * Huagang XIE <huagang@intruvert.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include "packet-tcp.h"
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/emem.h>

/* get from openssh ssh2.h */
#define SSH2_MSG_DISCONNECT				1
#define SSH2_MSG_IGNORE					2
#define SSH2_MSG_UNIMPLEMENTED				3
#define SSH2_MSG_DEBUG					4
#define SSH2_MSG_SERVICE_REQUEST			5
#define SSH2_MSG_SERVICE_ACCEPT				6

/* transport layer: alg negotiation */

#define SSH2_MSG_KEXINIT				20
#define SSH2_MSG_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#define SSH2_MSG_KEXDH_INIT				30
#define SSH2_MSG_KEXDH_REPLY				31

/*
#define SSH2_MSG_KEX_DH_GEX_REQUEST_OLD			30
#define SSH2_MSG_KEX_DH_GEX_GROUP			31
*/
#define SSH2_MSG_KEX_DH_GEX_INIT			32
#define SSH2_MSG_KEX_DH_GEX_REPLY			33
#define SSH2_MSG_KEX_DH_GEX_REQUEST			34

/* SSH Version 1 definition , from openssh ssh1.h */

#define SSH_MSG_NONE				0	/* no message */
#define SSH_MSG_DISCONNECT			1	/* cause (string) */
#define SSH_SMSG_PUBLIC_KEY			2	/* ck,msk,srvk,hostk */
#define SSH_CMSG_SESSION_KEY			3	/* key (BIGNUM) */
#define SSH_CMSG_USER				4	/* user (string) */


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
};

static int proto_ssh = -1;
static int hf_ssh_packet_length= -1;
static int hf_ssh_padding_length= -1;
static int hf_ssh_payload= -1;
static int hf_ssh_protocol= -1;
static int hf_ssh_encrypted_packet= -1;
static int hf_ssh_padding_string= -1;
static int hf_ssh_mac_string= -1;
static int hf_ssh_msg_code = -1;
static int hf_ssh_cookie = -1;
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

static gint ett_ssh = -1;
static gint ett_key_exchange= -1;
static gint ett_key_init= -1;
static gint ett_ssh1= -1;
static gint ett_ssh2= -1;

static gboolean ssh_desegment = TRUE;

#define TCP_PORT_SSH  22 

static const value_string ssh2_msg_vals[] = {
	{SSH2_MSG_DISCONNECT, "Disconnect"},
	{SSH2_MSG_IGNORE, "Ignore"},
	{SSH2_MSG_UNIMPLEMENTED, "Unimplemented"},
	{SSH2_MSG_DEBUG, "Debug"},
	{SSH2_MSG_SERVICE_REQUEST, "Service Request"},
	{SSH2_MSG_SERVICE_ACCEPT, "Service Accept"},
	{SSH2_MSG_KEXINIT, "Key Exchange Init"},
	{SSH2_MSG_NEWKEYS, "New Keys"},
	{SSH2_MSG_KEXDH_INIT, "Diffie-Hellman Key Exchange Init"},
	{SSH2_MSG_KEXDH_REPLY, "Diffie-Hellman Key Exchange Reply"},
	{SSH2_MSG_KEX_DH_GEX_INIT, "Diffie-Hellman GEX Init"},	
	{SSH2_MSG_KEX_DH_GEX_REPLY, "Diffie-Hellman GEX Reply"},
	{SSH2_MSG_KEX_DH_GEX_REQUEST, "Diffie-Hellman GEX Request"},
  	{ 0,          NULL }
};

static const value_string ssh1_msg_vals[] = {
	{SSH_MSG_NONE,"No Message"},
	{SSH_MSG_DISCONNECT, "Disconnect"},
	{SSH_SMSG_PUBLIC_KEY,"Public Key"},
	{SSH_CMSG_SESSION_KEY,"Session Key"},
	{SSH_CMSG_USER,"User"},
};


static const value_string ssh_opcode_vals[] = {
  { 0,          NULL }
};

static int ssh_dissect_key_init(tvbuff_t *tvb, int offset, proto_tree *tree);

static int ssh_dissect_ssh1(tvbuff_t *tvb, packet_info *pinfo,
		int offset, proto_tree *tree,int is_response,
		int number, gboolean *need_desegmentation);
static int ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo, 
		int offset, proto_tree *tree,int is_response,
		int number, gboolean *need_desegmentation );
static int ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo, 
		int offset, proto_tree *tree,int is_response,
		int number, gboolean *need_desegmentation );
static int ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo, 
		int offset, proto_tree *tree,int is_response,int *version,
		gboolean *need_desegmentation);
static int ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
		int offset, proto_tree *tree,int is_response);
proto_item * ssh_proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
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

	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	if (!conversation) {
		/* create a new conversation */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
			pinfo->srcport, pinfo->destport, 0);
	}

	global_data = conversation_get_proto_data(conversation,proto_ssh);
	if(!global_data ) {
		global_data = se_alloc(sizeof(struct ssh_flow_data));
		global_data->req_counter=0;
		global_data->rsp_counter=0;
		global_data->version=SSH_VERSION_UNKNOWN;
		conversation_add_proto_data(conversation,proto_ssh,global_data);
	}

/*
 *	end of attaching data
 */ 	
	if (pinfo->destport == pinfo->match_port) {
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
			offset,ssh_tree,is_response);
		return;
	}
			
	while((remain_length = tvb_reported_length_remaining(tvb,offset))> 0 ) {
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
				offset = ssh_dissect_ssh1(tvb, pinfo,
						offset,ssh_tree,is_response,this_number, 
						&need_desegmentation);
				break;

			case SSH_VERSION_2:
				offset = ssh_dissect_ssh2(tvb, pinfo,
						offset,ssh_tree,is_response,this_number,
						&need_desegmentation);
				break;
			}
		}

		if(need_desegmentation) return;
	}
}

static int 
ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
	       	int offset, proto_tree *tree,int is_response, int this_number,
		gboolean *need_desegmentation)
{
	proto_item *ti; 
	proto_item *ssh2_tree=NULL;

	if(tree) {
		ti=proto_tree_add_text(tree,tvb,offset,-1,"SSH Version 2");
		ssh2_tree = proto_item_add_subtree(ti ,ett_ssh2);
	}
	
	if((is_response && this_number > 3) || (!is_response && this_number>4)) {
		offset = ssh_dissect_encrypted_packet(tvb, pinfo,
				offset,ssh2_tree,is_response);
	} else {
		offset = ssh_dissect_key_exchange(tvb,pinfo,
			offset,ssh2_tree,is_response,this_number,
			need_desegmentation);
	}

	return offset;
}
static int 
ssh_dissect_ssh1(tvbuff_t *tvb, packet_info *pinfo,
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
	if (ssh_desegment && pinfo->can_desegment) {
		if(remain_length < 4) {
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = 4-remain_length;
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
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s", 
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
		    tvb, offset, len, FALSE);
	}
	offset+=len;

	return offset;
}

static int 
ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
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
	if (ssh_desegment && pinfo->can_desegment) {
		if(remain_length < 4) {
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = 4-remain_length;
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
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s", 
			val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
	}
	offset += 1;
	
	/* 16 bytes cookie  */
	if(number == 1) { 
		offset = ssh_dissect_key_init(tvb, offset,key_ex_tree);
	}

	len = plen+4-padding_length-(offset-last_offset);
	if (tree ) {
		ssh_proto_tree_add_item(key_ex_tree, hf_ssh_payload,
		    tvb, offset, len, FALSE);
	}
	offset +=len; 

	/* padding */
	if(tree) {
		ssh_proto_tree_add_item(key_ex_tree, hf_ssh_padding_string,
		    		tvb, offset, padding_length, FALSE);
	}
	offset+= padding_length;

	/* MAC , if there is still bytes, treat it as 16bytes MAC*/
	if(msg_code == SSH2_MSG_KEX_DH_GEX_REPLY) {
		len = tvb_reported_length_remaining(tvb,offset);
		if(len == 16) {
			if(tree) {
				proto_tree_add_item(key_ex_tree, hf_ssh_mac_string,
		    			tvb, offset, len , FALSE);
			}
			offset+=len;
		}
	}

	return offset;
}
static int 
ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
	       	int offset, proto_tree *tree,int is_response)
{
	gint len;

	len = tvb_reported_length_remaining(tvb,offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
  		col_add_fstr(pinfo->cinfo, COL_INFO, "Encrypted %s packet len=%d", 
			is_response?"response":"request",len);
	}
	if (tree ) {
		ssh_proto_tree_add_item(tree, hf_ssh_encrypted_packet,
		    		tvb, offset, len, FALSE);
  	}
	offset+=len;
	return offset;
}
	
static int
ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
	       	int offset, proto_tree *tree, int is_response, int * version,
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
		    		tvb, offset, linelen, FALSE);
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

static int
ssh_dissect_key_init(tvbuff_t *tvb, int offset, proto_tree *tree )
{
	guint	len;
	int	i;

	proto_item *tf;
	proto_item *key_init_tree=NULL;

	if (tree) {
		tf=proto_tree_add_text(tree,tvb,offset,-1,"Algorithms");
		key_init_tree = proto_item_add_subtree(tf, ett_key_init);
		proto_tree_add_item(key_init_tree, hf_ssh_cookie,
		    tvb, offset, 16, FALSE);
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
		offset+=len;
	}
	return offset;
}
proto_item *
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
      { "Packet Length",	      "ssh.packet_length",
	FT_UINT32, BASE_DEC, NULL,  0x0,
      	"SSH packet length", HFILL }},

    { &hf_ssh_padding_length,
      { "Padding Length",	  "ssh.padding_length",
	FT_UINT8, BASE_DEC, NULL, 0x0,
      	"SSH Packet Number", HFILL }},

    { &hf_ssh_msg_code,
      { "Message Code",	  "ssh.message_code",
	FT_UINT8, BASE_DEC, NULL, 0x0,
      	"SSH Message Code", HFILL }},

    { &hf_ssh_cookie,
      { "Cookie",	  "ssh.cookie",
	FT_BYTES, BASE_NONE, NULL, 0x0,
      	"SSH Cookie", HFILL }},

    { &hf_ssh_encrypted_packet,
      { "Encrypted Packet",	  "ssh.encrypted_packet",
	FT_BYTES, BASE_NONE, NULL, 0x0,
      	"SSH Protocol Packet", HFILL }},

    { &hf_ssh_protocol,
      { "Protocol",	  "ssh.protocol",
	FT_STRING, BASE_NONE, NULL, 0x0,
      	"SSH Protocol", HFILL }},

    { &hf_ssh_payload,
      { "Payload",	  "ssh.payload",
	FT_BYTES, BASE_NONE, NULL, 0x0,
      	"SSH Payload", HFILL }},

    { &hf_ssh_padding_string,
      { "Padding String",	  "ssh.padding_string",
	FT_STRING, BASE_NONE, NULL, 0x0,
      	"SSH Padding String", HFILL }},

    { &hf_ssh_mac_string,
      { "MAC String",	  "ssh.mac_string",
	FT_STRING, BASE_NONE, NULL, 0x0,
      	"SSH MAC String", HFILL }},

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

  	proto_ssh = proto_register_protocol("SSH Protocol",
				       "SSH", "ssh");
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
  
	dissector_add("tcp.port", TCP_PORT_SSH, ssh_handle);
}
