/* packet-ssh.c
 * Routines for ssh packet dissection
 *
 * Huagang XIE <huagang@intruvert.com>
 *
 * $Id: packet-ssh.c,v 1.1 2003/01/25 00:22:50 guy Exp $
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
 * Note:  only support SSHv2 now. 
 * 
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include "packet-smb-common.h"
#include "packet-tcp.h"
#include "reassemble.h"
#include "prefs.h"

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

/* proto data */

struct ssh_pdu_data{
	guint	counter;
	guint	number;
};

struct ssh_flow_data {
	guint 	req_counter;
	guint	rsp_counter;
	gboolean is_ssh2;
};
static GMemChunk *ssh_this_data=NULL;
static GMemChunk *ssh_global_data = NULL;

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

static gboolean ssh_desegment = TRUE;

#define TCP_PORT_SSH  22 

static const value_string ssh_msg_vals[] = {
	{SSH2_MSG_DISCONNECT, "Disconnect"},
	{SSH2_MSG_IGNORE, "Ignore"},
	{SSH2_MSG_UNIMPLEMENTED, "Unimplemented"},
	{SSH2_MSG_DEBUG, "Debug"}	,
	{SSH2_MSG_SERVICE_REQUEST,"Service Request"},
	{SSH2_MSG_SERVICE_ACCEPT,"Service Accept"},
	{SSH2_MSG_KEXINIT, "Key Exchange"},
	{SSH2_MSG_NEWKEYS,"New Keys"},
	{SSH2_MSG_KEXDH_INIT, "Key Init"},
	{SSH2_MSG_KEXDH_REPLY,"Key Reply"},
	{SSH2_MSG_KEX_DH_GEX_INIT,"Diffie-Hellman GEX Init"},	
	{SSH2_MSG_KEX_DH_GEX_REPLY,"Diffie-Hellman GEX Reply"},
	{SSH2_MSG_KEX_DH_GEX_REQUEST,"Diffie-Hellman GEX Request"},
  	{ 0,          NULL }
};


static const value_string ssh_opcode_vals[] = {
  { 0,          NULL }
};

static int ssh_dissect_key_init(tvbuff_t *tvb, int offset, proto_tree *tree);

static int ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo, 
		int offset, proto_tree *tree,int is_response,
		int number, gboolean *need_desegmentation );
static int ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo, 
		int offset, proto_tree *tree,int is_response,int *is_ssh2,
		gboolean *need_desegmentation);
static int ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
		int offset, proto_tree *tree,int is_response);

static void
ssh_init_protocol(void)
{
  	if (ssh_global_data)
    		g_mem_chunk_destroy(ssh_global_data);
  	if (ssh_this_data)
    		g_mem_chunk_destroy(ssh_this_data);

  	ssh_global_data = g_mem_chunk_new("ssh_global_datas",
				      sizeof(struct ssh_flow_data),
				      100* sizeof(struct ssh_flow_data), G_ALLOC_AND_FREE);
  	ssh_this_data = g_mem_chunk_new("ssh_pku_data",
				      sizeof(struct ssh_pdu_data),
				      100* sizeof(struct ssh_pdu_data), G_ALLOC_AND_FREE);

}

static void
dissect_ssh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_tree	*ssh_tree = NULL;
	proto_item	*ti;
	conversation_t  *conversation=NULL;
	guint		remain_length;
	guint		last_offset;
	guint		this_number,number;

	int		offset = 0;

	gboolean	is_response;
	gboolean 	is_newdata;
	gboolean 	need_desegmentation;
	gboolean	is_ssh2 ;

	struct ssh_pdu_data *this_data=NULL;
	struct ssh_flow_data *global_data=NULL;

	is_newdata = FALSE;
	this_data = p_get_proto_data(pinfo->fd, proto_ssh);

	conversation = find_conversation(&pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	if (!conversation) {
		/* create a new conversation */
		conversation = conversation_new(&pinfo->src, &pinfo->dst, pinfo->ptype,
			pinfo->srcport, pinfo->destport, 0);
	}

	global_data = conversation_get_proto_data(conversation,proto_ssh);
	if(!global_data ) {
		global_data = g_mem_chunk_alloc(ssh_global_data);
		global_data->req_counter=0;
		global_data->rsp_counter=0;
		global_data->is_ssh2=TRUE;
		conversation_add_proto_data(conversation,proto_ssh,global_data);
	}

/*
 *	end of attaching data
 */ 	
	if (pinfo->destport == pinfo->match_port) {
	  	is_response=FALSE;
		if(!this_data) {
			this_data = g_mem_chunk_alloc(ssh_this_data);
			this_data->counter = global_data->req_counter++;
			p_add_proto_data(pinfo->fd, proto_ssh, this_data);
			is_newdata = TRUE;
		}
	}else {
		is_response=TRUE;
		if(!this_data) {
			this_data = g_mem_chunk_alloc(ssh_global_data);
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
	
	is_ssh2 = global_data->is_ssh2;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		if(this_data->counter == 0 ) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSH");
		}else {
			if(is_ssh2) {
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv2");
			}else {
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv1");
			}
		}
	}

	/* we will not decode SSH1 now */
	if(!is_ssh2) {
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
			offset = ssh_dissect_protocol(tvb, pinfo,offset,ssh_tree,
					is_response,&is_ssh2, &need_desegmentation);
			if(!is_response) {
				global_data->is_ssh2 = is_ssh2;
			}
		} else { 
			/* response, 1, 2 is key_exchange */
			/* request, 1,2,3,4 is key_exchange */
			if((is_response && this_number > 3) || (!is_response && this_number>4)) {
				offset = ssh_dissect_encrypted_packet(tvb, pinfo,
						offset,ssh_tree,is_response);
			} else {
				offset = ssh_dissect_key_exchange(tvb,pinfo,
						offset,ssh_tree,is_response,this_number,
						&need_desegmentation);
			}
		}
		if(need_desegmentation) return;
	}
}


static int 
ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
	       	int offset, proto_tree *tree,int is_response,int number,
		gboolean *need_desegmentation)
{
	guint 	plen,len;
	guint8	padding_length;
	guint	remain_length=0;
	guint 	last_offset=offset;
	guint 	msg_code;

	proto_item *tf;
	proto_item *key_ex_tree =NULL;
	
	if (ssh_desegment && pinfo->can_desegment) {
		remain_length = tvb_reported_length_remaining(tvb,offset);
		if(remain_length < 4) {
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = 4-remain_length;
                	*need_desegmentation = TRUE;
                	return offset;
		}
	}
	plen = tvb_get_ntohl(tvb, offset) ;

	if (ssh_desegment && pinfo->can_desegment) {
		if(plen < remain_length - 4 ) {
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = plen+4 - remain_length;
                	*need_desegmentation = TRUE;
                	return offset;
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
  		col_add_fstr(pinfo->cinfo, COL_INFO, "%s: ", 
			is_response?"Server":"Client");
	}

	if (tree) {
		  proto_tree_add_uint(tree, hf_ssh_packet_length, tvb,
		    offset, 4, plen);
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
			val_to_str(msg_code, ssh_msg_vals, "Unknown (%u)"),
			msg_code);
		    
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s", 
			val_to_str(msg_code, ssh_msg_vals, "Unknown (%u)"));
	}
	offset += 1;
	
	/* 16 bytes cookie */
	if(number == 1) { 
		offset = ssh_dissect_key_init(tvb, offset,key_ex_tree);
	}

	len = plen+4-padding_length-(offset-last_offset);
	if (tree) {
		proto_tree_add_item(key_ex_tree, hf_ssh_payload,
		    tvb, offset, len, FALSE);
	}
	offset +=len; 

	/* padding */
	if(tree) {
		proto_tree_add_item(key_ex_tree, hf_ssh_padding_string,
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
	guint len;

	len = tvb_reported_length_remaining(tvb,offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
  		col_add_fstr(pinfo->cinfo, COL_INFO, "Encrypted %s packet", 
			is_response?"response":"request");
	}
	if (tree ) {
		proto_tree_add_item(tree, hf_ssh_encrypted_packet,
		    		tvb, offset, len, FALSE);
  	}
	offset+=len;
	return offset;
}
	
static int
ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
	       	int offset, proto_tree *tree, int is_response, int * is_ssh2,
		gboolean *need_desegmentation)
{
	guint	linelen,next_offset;
	guint	remain_length;
	
	remain_length = tvb_reported_length_remaining(tvb,offset);
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

	if (ssh_desegment && pinfo->can_desegment) {
		if(remain_length < linelen) {
                	pinfo->desegment_offset = offset;
                	pinfo->desegment_len = linelen-remain_length;
                	*need_desegmentation = TRUE;
                	return offset;
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
  		col_add_fstr(pinfo->cinfo, COL_INFO, "%s Protocol: %s", 
			is_response?"Server":"Client", 
			tvb_format_text(tvb,offset,linelen)); 
	}
	if (tree ) {
		proto_tree_add_item(tree, hf_ssh_protocol,
		    		tvb, offset, linelen+1, FALSE);
  	}
	if(!is_response && tvb_strncaseeql(tvb,offset,"SSH-2.0-",8)) {
		*(is_ssh2) = FALSE;
	}
	offset+=linelen+1;
	return offset;
}

static int
ssh_dissect_key_init(tvbuff_t *tvb, int offset, proto_tree *tree )
{
	guint	len;

	proto_item *tf;
	proto_item *key_init_tree=NULL;


	if(tree) {
		tf=proto_tree_add_text(tree,tvb,offset,-1,"Keys");
		key_init_tree = proto_item_add_subtree(tf ,ett_key_init);
	}
	if (tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_cookie,
		    tvb, offset, 16, FALSE);
	}
	offset += 16;

	/* kex_algorithms */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_kex_algorithms_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_kex_algorithms,
			tvb, offset, len , FALSE);
	}
	offset+=len;

	/* server_host_key_algorithms */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_server_host_key_algorithms_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_server_host_key_algorithms,
			tvb, offset, len , FALSE);
	}
	offset+=len;

	/* encryption_algorithms_client_to_server */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_encryption_algorithms_client_to_server_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_encryption_algorithms_client_to_server,
			tvb, offset, len , FALSE);
	}
	offset+=len;
	/* encryption_algorithms_server_to_client */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_encryption_algorithms_server_to_client_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_encryption_algorithms_server_to_client,
			tvb, offset, len , FALSE);
	}
	offset+=len;

	/* mac_algorithms_client_to_server */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_mac_algorithms_client_to_server_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_mac_algorithms_client_to_server,
			tvb, offset, len , FALSE);
	}
	offset+=len;

	/* mac_algorithms_server_to_client */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_mac_algorithms_server_to_client_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_mac_algorithms_server_to_client,
			tvb, offset, len , FALSE);
	}
	offset+=len;
	
	/* compression_algorithms_client_to_server */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_compression_algorithms_client_to_server_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_compression_algorithms_client_to_server,
			tvb, offset, len , FALSE);
	}
	offset+=len;

	/* compression_algorithms_server_to_client */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_compression_algorithms_server_to_client_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree) {
		proto_tree_add_item(key_init_tree, hf_ssh_compression_algorithms_server_to_client,
			tvb, offset, len , FALSE);
	}
	offset+=len;

	/* languages_client_to_server */
	len = tvb_get_ntohl(tvb, offset) ;
	if(key_init_tree ) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_languages_client_to_server_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (key_init_tree && len) {
		proto_tree_add_item(key_init_tree, hf_ssh_languages_client_to_server,
			tvb, offset, len , FALSE);
	}
	offset+=len;

	/* languages_server_to_client */
	len = tvb_get_ntohl(tvb, offset) ;
	if(tree ) {
		proto_tree_add_uint(key_init_tree,
			hf_ssh_languages_server_to_client_length ,tvb,offset,4, len);
	}
	offset+=4;
	if (tree && len ) {
		proto_tree_add_item(tree, hf_ssh_languages_server_to_client,
			tvb, offset, len , FALSE);
	}
	offset+=len;

	return offset;
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
	FT_STRING, BASE_DEC, NULL, 0x0,
      	"SSH Cookie", HFILL }},


    { &hf_ssh_encrypted_packet,
      { "Encrypted Packet",	  "ssh.encrypted_packet",
	FT_STRING, BASE_DEC, NULL, 0x0,
      	"SSH Protocol Packet", HFILL }},

    { &hf_ssh_protocol,
      { "Protocol",	  "ssh.protocol",
	FT_STRING, BASE_DEC, NULL, 0x0,
      	"SSH Protocol", HFILL }},

    { &hf_ssh_payload,
      { "Payload String",	  "ssh.payload",
	FT_STRING, BASE_DEC, NULL, 0x0,
      	"SSH Payload String", HFILL }},

    { &hf_ssh_padding_string,
      { "Padding String",	  "ssh.padding_string",
	FT_STRING, BASE_DEC, NULL, 0x0,
      	"SSH Padding String", HFILL }},

    { &hf_ssh_mac_string,
      { "MAC String",	  "ssh.mac_string",
	FT_STRING, BASE_DEC, NULL, 0x0,
      	"SSH MAC String", HFILL }},

  { &hf_ssh_kex_algorithms,
      { "kex_algorithms string",         "ssh.kex_algorithms",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH kex_algorithms string", HFILL }},

  { &hf_ssh_server_host_key_algorithms,
      { "server_host_key_algorithms string",         "ssh.server_host_key_algorithms",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH server_host_key_algorithms string", HFILL }},

  { &hf_ssh_encryption_algorithms_client_to_server,
      { "encryption_algorithms_client_to_server string",         "ssh.encryption_algorithms_client_to_server",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH encryption_algorithms_client_to_server string", HFILL }},

  { &hf_ssh_encryption_algorithms_server_to_client,
      { "encryption_algorithms_server_to_client string",         "ssh.encryption_algorithms_server_to_client",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH encryption_algorithms_server_to_client string", HFILL }},

  { &hf_ssh_mac_algorithms_client_to_server,
      { "mac_algorithms_client_to_server string",         "ssh.mac_algorithms_client_to_server",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH mac_algorithms_client_to_server string", HFILL }},

  { &hf_ssh_mac_algorithms_server_to_client,
      { "mac_algorithms_server_to_client string",         "ssh.mac_algorithms_server_to_client",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH mac_algorithms_server_to_client string", HFILL }},

  { &hf_ssh_compression_algorithms_client_to_server,
      { "compression_algorithms_client_to_server string",         "ssh.compression_algorithms_client_to_server",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH compression_algorithms_client_to_server string", HFILL }},

  { &hf_ssh_compression_algorithms_server_to_client,
      { "compression_algorithms_server_to_client string",         "ssh.compression_algorithms_server_to_client",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH compression_algorithms_server_to_client string", HFILL }},

  { &hf_ssh_languages_client_to_server,
      { "languages_client_to_server string",         "ssh.languages_client_to_server",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
        "SSH languages_client_to_server string", HFILL }},

  { &hf_ssh_languages_server_to_client,
      { "languages_server_to_client string",         "ssh.languages_server_to_client",
        FT_STRINGZ, BASE_DEC, NULL, 0x0,
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
		&ett_key_init
  	};
  	module_t *ssh_module;

  	proto_ssh = proto_register_protocol("SSH Protocol",
				       "SSH", "ssh");
 	 proto_register_field_array(proto_ssh, hf, array_length(hf));
  	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&ssh_init_protocol);

  	ssh_module = prefs_register_protocol(proto_ssh, NULL);
	prefs_register_bool_preference(ssh_module, "desegment_buffers",
		"Desegment all SSH buffers spanning multiple TCP segments",
		"Whether the SSH dissector should desegment all SSH buffers spanning multiple TCP segments",
		&ssh_desegment);
}

void
proto_reg_handoff_ssh(void)
{
	dissector_handle_t ssh_handle;

	ssh_handle = create_dissector_handle(dissect_ssh, proto_ssh);
  
	dissector_add("tcp.port", TCP_PORT_SSH, ssh_handle);
}
