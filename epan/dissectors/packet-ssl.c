/* packet-ssl.c
 * Routines for ssl dissection
 * Copyright (c) 2000-2001, Scott Renfro <scott@renfro.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * See
 *
 *	http://www.netscape.com/eng/security/SSL_2.html
 *
 * for SSL 2.0 specs.
 *
 * See
 *
 *	http://www.netscape.com/eng/ssl3/
 *
 * for SSL 3.0 specs.
 *
 * See RFC 2246 for SSL 3.1/TLS 1.0 specs.
 *
 * See (among other places)
 *
 *	http://www.graphcomp.com/info/specs/ms/pct.htm
 *
 * for PCT 1 draft specs.
 *
 * See
 *
 *	http://research.sun.com/projects/crypto/draft-ietf-tls-ecc-05.txt
 *
 * for Elliptic Curve Cryptography cipher suites.
 *
 * See
 *
 * 	http://www.ietf.org/internet-drafts/draft-ietf-tls-camellia-04.txt
 *
 * for Camellia-based cipher suites.
 *
 * Notes:
 *
 *   - Does not support dissection
 *     of frames that would require state maintained between frames
 *     (e.g., single ssl records spread across multiple tcp frames)
 *
 *   - Identifies, but does not fully dissect the following messages:
 *
 *     - SSLv3/TLS (These need more state from previous handshake msgs)
 *       - Server Key Exchange
 *       - Client Key Exchange
 *       - Certificate Verify
 *
 *     - SSLv2 (These don't appear in the clear)
 *       - Error
 *       - Client Finished
 *       - Server Verify
 *       - Server Finished
 *       - Request Certificate
 *       - Client Certificate
 *
 *    - Decryption is supported only for session that use RSA key exchange,
 *      if the host private key is provided via preference.
 *
 *    - Decryption need to be performed 'sequentially', so it's done
 *      at packet reception time. This may cause a significative packet capture
 *      slow down. This also cause do dissect some ssl info that in previous
 *      dissector version were dissected only when a proto_tree context was
 *      available
 *
 *     We are at Packet reception if time pinfo->fd->flags.visited == 0
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <glib.h>

#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/inet_v6defs.h>
#include <epan/dissectors/packet-x509af.h>
#include <epan/emem.h>
#include <epan/tap.h>
#include "packet-ssl.h"
#include "packet-ssl-utils.h"


static gboolean ssl_desegment = TRUE;
static gboolean ssl_desegment_app_data = TRUE;


/*********************************************************************
 *
 * Protocol Constants, Variables, Data Structures
 *
 *********************************************************************/

/* Initialize the protocol and registered fields */
static gint ssl_tap                           = -1;
static gint proto_ssl                         = -1;
static gint hf_ssl_record                     = -1;
static gint hf_ssl_record_content_type        = -1;
static gint hf_ssl_record_version             = -1;
static gint hf_ssl_record_length              = -1;
static gint hf_ssl_record_appdata             = -1;
static gint hf_ssl2_record                    = -1;
static gint hf_ssl2_record_is_escape          = -1;
static gint hf_ssl2_record_padding_length     = -1;
static gint hf_ssl2_msg_type                  = -1;
static gint hf_pct_msg_type                   = -1;
static gint hf_ssl_change_cipher_spec         = -1;
static gint hf_ssl_alert_message              = -1;
static gint hf_ssl_alert_message_level        = -1;
static gint hf_ssl_alert_message_description  = -1;
static gint hf_ssl_handshake_protocol         = -1;
static gint hf_ssl_handshake_type             = -1;
static gint hf_ssl_handshake_length           = -1;
static gint hf_ssl_handshake_client_version   = -1;
static gint hf_ssl_handshake_server_version   = -1;
static gint hf_ssl_handshake_random_time      = -1;
static gint hf_ssl_handshake_random_bytes     = -1;
static gint hf_ssl_handshake_cipher_suites_len = -1;
static gint hf_ssl_handshake_cipher_suites    = -1;
static gint hf_ssl_handshake_cipher_suite     = -1;
static gint hf_ssl_handshake_session_id       = -1;
static gint hf_ssl_handshake_comp_methods_len = -1;
static gint hf_ssl_handshake_comp_methods     = -1;
static gint hf_ssl_handshake_comp_method      = -1;
static gint hf_ssl_handshake_extensions_len   = -1;
static gint hf_ssl_handshake_extension_type   = -1;
static gint hf_ssl_handshake_extension_len    = -1;
static gint hf_ssl_handshake_extension_data   = -1;
static gint hf_ssl_handshake_certificates_len = -1;
static gint hf_ssl_handshake_certificates     = -1;
static gint hf_ssl_handshake_certificate      = -1;
static gint hf_ssl_handshake_certificate_len  = -1;
static gint hf_ssl_handshake_cert_types_count = -1;
static gint hf_ssl_handshake_cert_types       = -1;
static gint hf_ssl_handshake_cert_type        = -1;
static gint hf_ssl_handshake_finished         = -1;
static gint hf_ssl_handshake_md5_hash         = -1;
static gint hf_ssl_handshake_sha_hash         = -1;
static gint hf_ssl_handshake_session_id_len   = -1;
static gint hf_ssl_handshake_dnames_len       = -1;
static gint hf_ssl_handshake_dnames           = -1;
static gint hf_ssl_handshake_dname_len        = -1;
static gint hf_ssl_handshake_dname            = -1;
static gint hf_ssl2_handshake_cipher_spec_len = -1;
static gint hf_ssl2_handshake_session_id_len  = -1;
static gint hf_ssl2_handshake_challenge_len   = -1;
static gint hf_ssl2_handshake_cipher_spec     = -1;
static gint hf_ssl2_handshake_challenge       = -1;
static gint hf_ssl2_handshake_clear_key_len   = -1;
static gint hf_ssl2_handshake_enc_key_len     = -1;
static gint hf_ssl2_handshake_key_arg_len     = -1;
static gint hf_ssl2_handshake_clear_key       = -1;
static gint hf_ssl2_handshake_enc_key         = -1;
static gint hf_ssl2_handshake_key_arg         = -1;
static gint hf_ssl2_handshake_session_id_hit  = -1;
static gint hf_ssl2_handshake_cert_type       = -1;
static gint hf_ssl2_handshake_connection_id_len = -1;
static gint hf_ssl2_handshake_connection_id   = -1;
static gint hf_pct_handshake_cipher_spec	= -1;
static gint hf_pct_handshake_hash_spec	= -1;
static gint hf_pct_handshake_cert_spec	= -1;
static gint hf_pct_handshake_cert	= -1;
static gint hf_pct_handshake_server_cert	= -1;
static gint hf_pct_handshake_exch_spec	= -1;
static gint hf_pct_handshake_hash	= -1;
static gint hf_pct_handshake_cipher	= -1;
static gint hf_pct_handshake_exch	= -1;
static gint hf_pct_handshake_sig		= -1;
static gint hf_pct_msg_error_type	= -1;

/* Initialize the subtree pointers */
static gint ett_ssl                   = -1;
static gint ett_ssl_record            = -1;
static gint ett_ssl_alert             = -1;
static gint ett_ssl_handshake         = -1;
static gint ett_ssl_cipher_suites     = -1;
static gint ett_ssl_comp_methods      = -1;
static gint ett_ssl_extension         = -1;
static gint ett_ssl_certs             = -1;
static gint ett_ssl_cert_types        = -1;
static gint ett_ssl_dnames            = -1;
static gint ett_ssl_random            = -1;
static gint ett_pct_cipher_suites	  = -1;
static gint ett_pct_hash_suites		  = -1;
static gint ett_pct_cert_suites		  = -1;
static gint ett_pct_exch_suites		  = -1;

static GHashTable *ssl_session_hash = NULL;
static GHashTable *ssl_key_hash = NULL;
static GTree* ssl_associations = NULL;
static dissector_handle_t ssl_handle = NULL;
static StringInfo ssl_decrypted_data = {NULL, 0};
static gint ssl_decrypted_data_avail = 0;

static gchar* ssl_keys_list = NULL;
static gchar* ssl_debug_file_name = NULL;

/* Forward declaration we need below */
void proto_reg_handoff_ssl(void);

/* initialize/reset per capture state data (ssl sessions cache) */
static void
ssl_init(void)
{
  ssl_common_init(&ssl_session_hash, &ssl_decrypted_data);
}

/* parse ssl related preferences (private keys and ports association strings) */
static void
ssl_parse(void)
{
	ep_stack_t tmp_stack;
	SslAssociation *tmp_assoc;

    ssl_set_debug(ssl_debug_file_name);

    if (ssl_key_hash)
    {
        g_hash_table_foreach(ssl_key_hash, ssl_private_key_free, NULL);
        g_hash_table_destroy(ssl_key_hash);
    }

	/* remove only associations created from key list */
	tmp_stack = ep_stack_new();
    g_tree_traverse(ssl_associations, ssl_assoc_from_key_list, G_IN_ORDER, tmp_stack);
	while (tmp_assoc = ep_stack_pop(tmp_stack)) {
		ssl_association_remove(ssl_associations, tmp_assoc);
	}

    /* parse private keys string, load available keys and put them in key hash*/
    ssl_key_hash = g_hash_table_new(ssl_private_key_hash,ssl_private_key_equal);

    if (ssl_keys_list && (ssl_keys_list[0] != 0))
    {
        ssl_parse_key_list(ssl_keys_list,ssl_key_hash,ssl_associations,ssl_handle,TRUE);
    }

}

/* function that save app_data during sub protocol reassembling */
static void
ssl_add_app_data(SslDecryptSession* ssl, guchar* data, gint data_len){
  StringInfo * app;
  app=&ssl->app_data_segment;

  if(app->data_len!=0){
    guchar* tmp;
    gint tmp_len;
    tmp=g_malloc(app->data_len);
    tmp_len=app->data_len;
    memcpy(tmp,app->data,app->data_len);
    if(app->data!=NULL)
      g_free(app->data);
    app->data_len=0;
    app->data=g_malloc(tmp_len+data_len);
    app->data_len=tmp_len+data_len;
    memcpy(app->data,tmp,tmp_len);
    g_free(tmp);
    memcpy(app->data+tmp_len, data,data_len);
  }
  else{
    /* it's new */
    if(app->data!=NULL)
      g_free(app->data);
    app->data=g_malloc(data_len);
    app->data_len=data_len;
    memcpy(app->data,data,data_len);
  }
}

static void
ssl_desegment_ssl_app_data(SslDecryptSession * ssl,  packet_info *pinfo){
   SslPacketInfo* pi;
   SslAssociation* association;
   SslPacketInfo* pi2;
   pi = p_get_proto_data(pinfo->fd, proto_ssl);
	  if (pi && pi->app_data.data)
	    {
	      tvbuff_t* new_tvb;
	      packet_info * pp;
	      /* find out a dissector using server port*/
	      association = ssl_association_find(ssl_associations, pinfo->srcport, pinfo->ptype == PT_TCP);
	      association = association ? association: ssl_association_find(ssl_associations, pinfo->destport, pinfo->ptype == PT_TCP);
	      /* create a copy of packet_info */
	      pp=g_malloc(sizeof(packet_info));
	      memcpy(pp, pinfo, sizeof(packet_info));

	      if (association && association->handle) {
		/* it's the first SS segmented packet */
		if(ssl->app_data_segment.data==NULL){
		  /* create new tvbuff for the decrypted data */
		  new_tvb = tvb_new_real_data(pi->app_data.data,
					      pi->app_data.data_len, pi->app_data.data_len);
		  tvb_set_free_cb(new_tvb, g_free);
		  /* we allow subdissector to tell us more bytes */
		  pp->can_desegment=2;
		  /* subdissector call  */
		  call_dissector(association->handle, new_tvb, pp, NULL);
		  /* if the dissector need more bytes */
		  if(pp->desegment_len>0){
		    /* we save the actual data to reuse them later */
		    ssl_add_app_data(ssl, pi->app_data.data, pi->app_data.data_len);
		    /* we remove data to forbid subdissection */
		    p_remove_proto_data(pinfo->fd, proto_ssl);
		    /* update of COL_INFO */
		    if (check_col(pinfo->cinfo, COL_INFO)){
		      col_append_str(pinfo->cinfo, COL_INFO, "[SSL segment of a reassembled PDU]");
		      pinfo->cinfo->writable=FALSE;
		    }
		    return;
		  }
		}
		else
		  {
		    /* it isn't the first SSL segmented packet */
		    /* we add actual data to reuse them later */
		    ssl_add_app_data(ssl, pi->app_data.data, pi->app_data.data_len);
		    /* create new tvbuff for the decrypted data */
		    new_tvb = tvb_new_real_data(ssl->app_data_segment.data,
						ssl->app_data_segment.data_len,
						ssl->app_data_segment.data_len);
		    tvb_set_free_cb(new_tvb, g_free);
		    /* we allow subdissector to tell us more bytes */
		    pp->can_desegment=2;
		    /* subdissector call  */
		    call_dissector(association->handle, new_tvb, pp, NULL);
		    /* if the dissector need more bytes */
		    if(pp->desegment_len>0){
		      /* we remove data to forbid subdissection */
		      p_remove_proto_data(pinfo->fd, proto_ssl);
		      /* update of COL_INFO */
		      if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_str(pinfo->cinfo, COL_INFO, "[SSL segment of a reassembled PDU]");
			pinfo->cinfo->writable=FALSE;
		      }
		      return;
		    }
		    else
		      {
			/* we create SslPacketInfo to save data */
			pi2=g_malloc(sizeof(SslPacketInfo));
			pi2->app_data.data=g_malloc(ssl->app_data_segment.data_len);
			memcpy(pi2->app_data.data,ssl->app_data_segment.data,ssl->app_data_segment.data_len);
			pi2->app_data.data_len=ssl->app_data_segment.data_len;

			/* we remove data if it's useful */
			p_remove_proto_data(pinfo->fd, proto_ssl);
			/* we add reassembled subprotocol data */
			p_add_proto_data(pinfo->fd, proto_ssl, pi2);
			/* we delete saved app_data */
			if(ssl->app_data_segment.data)
			  g_free(ssl->app_data_segment.data);
			ssl->app_data_segment.data=NULL;
			ssl->app_data_segment.data_len=0;
		      }
		  }
		/* we delete pp structure  */
		g_free(pp);

	      }
	    }


}
/*********************************************************************
 *
 * Forward Declarations
 *
 *********************************************************************/

/*
 * SSL version 3 and TLS dissectors
 *
 */
/* record layer dissector */
static gint dissect_ssl3_record(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint *conv_version,
                               gboolean *need_desegmentation,
                               SslDecryptSession *conv_data);

/* change cipher spec dissector */
static void dissect_ssl3_change_cipher_spec(tvbuff_t *tvb,
                                            proto_tree *tree,
                                            guint32 offset,
                                            guint *conv_version, guint8 content_type);

/* alert message dissector */
static void dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint *conv_version);

/* handshake protocol dissector */
static void dissect_ssl3_handshake(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, guint32 offset,
                                   guint32 record_length,
                                   guint *conv_version,
                                   SslDecryptSession *conv_data, guint8 content_type);


static void dissect_ssl3_hnd_cli_hello(tvbuff_t *tvb,
                                       proto_tree *tree,
                                       guint32 offset, guint32 length,
                                       SslDecryptSession* ssl);

static void dissect_ssl3_hnd_srv_hello(tvbuff_t *tvb,
                                       proto_tree *tree,
                                       guint32 offset, guint32 length,
                                       SslDecryptSession* ssl);

static void dissect_ssl3_hnd_cert(tvbuff_t *tvb,
                                  proto_tree *tree, guint32 offset, packet_info *pinfo);

static void dissect_ssl3_hnd_cert_req(tvbuff_t *tvb,
                                      proto_tree *tree,
                                      guint32 offset);

static void dissect_ssl3_hnd_finished(tvbuff_t *tvb,
                                      proto_tree *tree,
                                      guint32 offset,
                                      guint* conv_version);


/*
 * SSL version 2 dissectors
 *
 */

/* record layer dissector */
static gint dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, guint32 offset,
                               guint *conv_version,
                               gboolean *need_desegmentation,
                               SslDecryptSession* ssl);

/* client hello dissector */
static void dissect_ssl2_hnd_client_hello(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset,
                                          SslDecryptSession* ssl);

static void dissect_pct_msg_client_hello(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset);

/* client master key dissector */
static void dissect_ssl2_hnd_client_master_key(tvbuff_t *tvb,
                                               proto_tree *tree,
                                               guint32 offset);
static void dissect_pct_msg_client_master_key(tvbuff_t *tvb,
					      proto_tree *tree,
					      guint32 offset);

/* server hello dissector */
static void dissect_ssl2_hnd_server_hello(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset, packet_info *pinfo);
static void dissect_pct_msg_server_hello(tvbuff_t *tvb,
					 proto_tree *tree,
					 guint32 offset, packet_info *pinfo);


static void dissect_pct_msg_server_verify(tvbuff_t *tvb,
					      proto_tree *tree,
					      guint32 offset);

static void dissect_pct_msg_error(tvbuff_t *tvb,
					      proto_tree *tree,
					      guint32 offset);

/*
 * Support Functions
 *
 */
/*static void ssl_set_conv_version(packet_info *pinfo, guint version);*/
static gint  ssl_is_valid_handshake_type(guint8 type);
static gint  ssl_is_valid_ssl_version(guint16 version);
static gint  ssl_is_authoritative_version_message(guint8 content_type,
                                                guint8 next_byte);
static gint  ssl_is_v2_client_hello(tvbuff_t *tvb, guint32 offset);
static gint  ssl_looks_like_sslv2(tvbuff_t *tvb, guint32 offset);
static gint  ssl_looks_like_sslv3(tvbuff_t *tvb, guint32 offset);
static gint  ssl_looks_like_valid_v2_handshake(tvbuff_t *tvb,
                                              guint32 offset,
                                              guint32 record_length);
static gint  ssl_looks_like_valid_pct_handshake(tvbuff_t *tvb,
                                               guint32 offset,
                                               guint32 record_length);
/*********************************************************************
 *
 * Main dissector
 *
 *********************************************************************/
/*
 * Code to actually dissect the packets
 */
static void
dissect_ssl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    conversation_t *conversation;
    void *conv_data;
    proto_item *ti;
    proto_tree *ssl_tree;
    guint32 offset;
    gboolean first_record_in_frame;
    gboolean need_desegmentation;
    SslDecryptSession* ssl_session;
    guint* conv_version;
    ti = NULL;
    ssl_tree   = NULL;
    offset = 0;
    first_record_in_frame = TRUE;
    ssl_session = NULL;

    /* Track the version using conversations to reduce the
     * chance that a packet that simply *looks* like a v2 or
     * v3 packet is dissected improperly.  This also allows
     * us to more frequently set the protocol column properly
     * for continuation data frames.
     *
     * Also: We use the copy in conv_version as our cached copy,
     *       so that we don't have to search the conversation
     *       table every time we want the version; when setting
     *       the conv_version, must set the copy in the conversation
     *       in addition to conv_version
     */
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                                     pinfo->srcport, pinfo->destport, 0);

    if (!conversation)
    {
        /* create a new conversation */
        conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                                        pinfo->srcport, pinfo->destport, 0);
    }
    conv_data = conversation_get_proto_data(conversation, proto_ssl);

    /* PAOLO: manage ssl decryption data */
    /*get a valid ssl session pointer*/
    if (conv_data != NULL)
        ssl_session = conv_data;
    else {
        SslService dummy;

        ssl_session = se_alloc0(sizeof(SslDecryptSession));
        ssl_session_init(ssl_session);
        ssl_session->version = SSL_VER_UNKNOWN;
        conversation_add_proto_data(conversation, proto_ssl, ssl_session);

        /* we need to know witch side of conversation is speaking*/
        if (ssl_packet_from_server(ssl_associations, pinfo->srcport, pinfo->ptype == PT_TCP)) {
            dummy.addr = pinfo->src;
            dummy.port = pinfo->srcport;
        }
        else {
            dummy.addr = pinfo->dst;
            dummy.port = pinfo->destport;
        }
        ssl_debug_printf("dissect_ssl server %hhd.%hhd.%hhd.%hhd:%d\n",
            dummy.addr.data[0],
            dummy.addr.data[1],dummy.addr.data[2],
            dummy.addr.data[3],dummy.port);

        /* try to retrive private key for this service. Do it now 'cause pinfo
         * is not always available
         * Note that with HAVE_LIBGNUTLS undefined private_key is allways 0
         * and thus decryption never engaged*/
        ssl_session->private_key = g_hash_table_lookup(ssl_key_hash, &dummy);
        if (!ssl_session->private_key)
            ssl_debug_printf("dissect_ssl can't find private key for this server!\n");
    }
    conv_version= & ssl_session->version;

    /* try decryption only the first time we see this packet
     * (to keep cipher syncronized)and only if we have
     * the server private key*/
    if (!ssl_session->private_key || pinfo->fd->flags.visited)
         ssl_session = NULL;

    /* Initialize the protocol column; we'll set it later when we
     * figure out what flavor of SSL it is (assuming we don't
     * throw an exception before we get the chance to do so). */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSL");
    }
    /* clear the the info column */
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    /* TCP packets and SSL records are orthogonal.
     * A tcp packet may contain multiple ssl records and an ssl
     * record may be spread across multiple tcp packets.
     *
     * This loop accounts for multiple ssl records in a single
     * frame, but not a single ssl record across multiple tcp
     * packets.
     *
     * Handling the single ssl record across multiple packets
     * may be possible using ethereal conversations, but
     * probably not cleanly.  May have to wait for tcp stream
     * reassembly.
     */

    /* Create display subtree for SSL as a whole */
    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_ssl, tvb, 0, -1, FALSE);
        ssl_tree = proto_item_add_subtree(ti, ett_ssl);
    }
    /* iterate through the records in this tvbuff */
    while (tvb_reported_length_remaining(tvb, offset) != 0)
    {
        /* on second and subsequent records per frame
         * add a delimiter on info column
         */
        if (!first_record_in_frame
            && check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }

	/*
	 * Assume, for now, that this doesn't need desegmentation.
	 */
	need_desegmentation = FALSE;

        /* first try to dispatch off the cached version
         * known to be associated with the conversation
         */
        switch(*conv_version) {
        case SSL_VER_SSLv2:
        case SSL_VER_PCT:
            offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                         offset, conv_version,
                                         &need_desegmentation,
                                         ssl_session);
            break;

        case SSL_VER_SSLv3:
        case SSL_VER_TLS:
            /* the version tracking code works too well ;-)
             * at times, we may visit a v2 client hello after
             * we already know the version of the connection;
             * work around that here by detecting and calling
             * the v2 dissector instead
             */
            if (ssl_is_v2_client_hello(tvb, offset))
            {
                offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                             offset, conv_version,
                                             &need_desegmentation,
                                             ssl_session);
            }
            else
            {
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, conv_version,
                                             &need_desegmentation,
                                             ssl_session);
            }
            break;

            /* that failed, so apply some heuristics based
             * on this individual packet
             */
        default:
            if (ssl_looks_like_sslv2(tvb, offset))
            {
                /* looks like sslv2 or pct client hello */
                offset = dissect_ssl2_record(tvb, pinfo, ssl_tree,
                                             offset, conv_version,
                                             &need_desegmentation,
                                             ssl_session);
            }
            else if (ssl_looks_like_sslv3(tvb, offset))
            {
                /* looks like sslv3 or tls */
                offset = dissect_ssl3_record(tvb, pinfo, ssl_tree,
                                             offset, conv_version,
                                             &need_desegmentation,
                                             ssl_session);
            }
            else
            {
                /* looks like something unknown, so lump into
                 * continuation data
                 */
                offset = tvb_length(tvb);
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_append_str(pinfo->cinfo, COL_INFO,
                                   "Continuation Data");

                /* Set the protocol column */
                if (check_col(pinfo->cinfo, COL_PROTOCOL))
                {
                    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                         ssl_version_short_names[*conv_version]);
                }
            }
            break;
        }

        /* Desegmentation return check */
        if (need_desegmentation)
          return;
        /* set up for next record in frame, if any */
        first_record_in_frame = FALSE;
    }
    tap_queue_packet(ssl_tap, pinfo, (gpointer)proto_ssl);
}

static gint
decrypt_ssl3_record(tvbuff_t *tvb, packet_info *pinfo, guint32 offset,
        guint32 record_length, guint8 content_type, SslDecryptSession* ssl,
        gboolean save_plaintext)
{
    gint ret;
    gint direction;
    SslDecoder* decoder;
    ret = 0;
    /* if we can decrypt and decryption have success
    * add decrypted data to this packet info*/
    ssl_debug_printf("decrypt_ssl3_record: app_data len %d ssl state %X\n",
        record_length, ssl->state);
    if (!(ssl->state & SSL_HAVE_SESSION_KEY)) {
        ssl_debug_printf("decrypt_ssl3_record: no session key\n");
        return ret;
    }

    /* retrive decoder for this packet direction*/
    if ((direction = ssl_packet_from_server(ssl_associations, pinfo->srcport, pinfo->ptype == PT_TCP)) != 0) {
        ssl_debug_printf("decrypt_ssl3_record: using server decoder\n");
        decoder = &ssl->server;
    }
    else {
        ssl_debug_printf("decrypt_ssl3_record: using client decoder\n");
        decoder = &ssl->client;
    }

    /* ensure we have enough storage space for decrypted data */
    if (record_length > ssl_decrypted_data.data_len)
    {
        ssl_debug_printf("decrypt_ssl3_record: allocating %d bytes"
                " for decrypt data (old len %d)\n",
                record_length + 32, ssl_decrypted_data.data_len);
        ssl_decrypted_data.data = g_realloc(ssl_decrypted_data.data,
            record_length + 32);
        ssl_decrypted_data.data_len = record_length + 32;
    }

    /* run decryption and add decrypted payload to protocol data, if decryption
    * is successful*/
    ssl_decrypted_data_avail = ssl_decrypted_data.data_len;
    if (ssl_decrypt_record(ssl, decoder,
          content_type, tvb_get_ptr(tvb, offset, record_length),
          record_length,  ssl_decrypted_data.data, &ssl_decrypted_data_avail) == 0)
        ret = 1;
    if (ret && save_plaintext)
    {
        SslPacketInfo* pi;
        pi = p_get_proto_data(pinfo->fd, proto_ssl);
        if (!pi)
        {
            ssl_debug_printf("decrypt_ssl3_record: allocating app_data %d "
                "bytes for app data\n", ssl_decrypted_data_avail);
            /* first app data record: allocate and put packet data*/
            pi = se_alloc0(sizeof(SslPacketInfo));
            pi->app_data.data = se_alloc(ssl_decrypted_data_avail);
            pi->app_data.data_len = ssl_decrypted_data_avail;
            memcpy(pi->app_data.data, ssl_decrypted_data.data, ssl_decrypted_data_avail);
        }
        else {
            guchar* store;
            /* update previus record*/
            ssl_debug_printf("decrypt_ssl3_record: reallocating app_data "
                "%d bytes for app data (total %d appdata bytes)\n",
                ssl_decrypted_data_avail, pi->app_data.data_len + ssl_decrypted_data_avail);
            store = se_alloc(pi->app_data.data_len + ssl_decrypted_data_avail);
            memcpy(store, pi->app_data.data, pi->app_data.data_len);
            memcpy(&store[pi->app_data.data_len], ssl_decrypted_data.data, ssl_decrypted_data_avail);
            pi->app_data.data_len += ssl_decrypted_data_avail;

            /* old decrypted data ptr here appare to be leaked, but it's
             * collected by emem allocator */
            pi->app_data.data = store;

            /* data ptr is changed, so remove old one and re-add the new one*/
            ssl_debug_printf("decrypt_ssl3_record: removing old app_data ptr\n");
            p_remove_proto_data(pinfo->fd, proto_ssl);
        }

        ssl_debug_printf("decrypt_ssl3_record: setting decrypted app_data ptr %p\n",pi);
        p_add_proto_data(pinfo->fd, proto_ssl, pi);
    }
    return ret;
}



/*********************************************************************
 *
 * SSL version 3 and TLS Dissection Routines
 *
 *********************************************************************/
static gint
dissect_ssl3_record(tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, guint32 offset,
                    guint *conv_version, gboolean *need_desegmentation,
                    SslDecryptSession* ssl)
{

    /*
     *    struct {
     *        uint8 major, minor;
     *    } ProtocolVersion;
     *
     *
     *    enum {
     *        change_cipher_spec(20), alert(21), handshake(22),
     *        application_data(23), (255)
     *    } ContentType;
     *
     *    struct {
     *        ContentType type;
     *        ProtocolVersion version;
     *        uint16 length;
     *        opaque fragment[TLSPlaintext.length];
     *    } TLSPlaintext;
     */
    guint32 record_length;
    guint16 version;
    guint8 content_type;
    guint8 next_byte;
    proto_tree *ti;
    proto_tree *ssl_record_tree;
    guint32 available_bytes;
    SslPacketInfo* pi;
    SslAssociation* association;
    ti = NULL;
    ssl_record_tree = NULL;
    available_bytes = 0;

    available_bytes = tvb_length_remaining(tvb, offset);

   /*
     * Can we do reassembly?
     */
    if (ssl_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the record header split across segment boundaries?
         */
        if (available_bytes < 5) {
            /*
             * Yes.  Tell the TCP dissector where the data for this
             * message starts in the data it handed us, and how many
             * more bytes we need, and return.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = 5 - available_bytes;
            *need_desegmentation = TRUE;
            return offset;
        }
    }

    /*
     * Get the record layer fields of interest
     */
    content_type  = tvb_get_guint8(tvb, offset);
    version       = tvb_get_ntohs(tvb, offset + 1);
    record_length = tvb_get_ntohs(tvb, offset + 3);

    if (ssl_is_valid_content_type(content_type)) {

        /*
         * Can we do reassembly?
         */
        if (ssl_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the record split across segment boundaries?
             */
            if (available_bytes < record_length + 5) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this
                 * message starts in the data it handed us, and how many
                 * more bytes we need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = (record_length + 5) - available_bytes;
                *need_desegmentation = TRUE;
                return offset;
            }
        }

    } else {

    /* if we don't have a valid content_type, there's no sense
     * continuing any further
     */
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "Continuation Data");

        /* Set the protocol column */
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL,
                        ssl_version_short_names[*conv_version]);
        }
        return offset + 5 + record_length;
    }

    /*
     * If GUI, fill in record layer part of tree
     */
    if (tree)
    {

        /* add the record layer subtree header */
        tvb_ensure_bytes_exist(tvb, offset, 5 + record_length);
        ti = proto_tree_add_item(tree, hf_ssl_record, tvb,
                                 offset, 5 + record_length, 0);
        ssl_record_tree = proto_item_add_subtree(ti, ett_ssl_record);
    }
    if (ssl_record_tree)
    {

        /* show the one-byte content type */
        proto_tree_add_item(ssl_record_tree, hf_ssl_record_content_type,
                            tvb, offset, 1, 0);
        offset++;

        /* add the version */
        proto_tree_add_item(ssl_record_tree, hf_ssl_record_version, tvb,
                            offset, 2, FALSE);
        offset += 2;

        /* add the length */
        proto_tree_add_uint(ssl_record_tree, hf_ssl_record_length, tvb,
                            offset, 2, record_length);
        offset += 2;    /* move past length field itself */
    }
    else
    {
        /* if no GUI tree, then just skip over those fields */
        offset += 5;
    }


    /*
     * if we don't already have a version set for this conversation,
     * but this message's version is authoritative (i.e., it's
     * not client_hello, then save the version to to conversation
     * structure and print the column version
     */
    next_byte = tvb_get_guint8(tvb, offset);
    if (*conv_version == SSL_VER_UNKNOWN
        && ssl_is_authoritative_version_message(content_type, next_byte))
    {
        if (version == SSLV3_VERSION)
        {
            *conv_version = SSL_VER_SSLv3;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
        else if (version == TLSV1_VERSION)
        {

            *conv_version = SSL_VER_TLS;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
        else if (version == TLSV1DOT1_VERSION)
        {

            *conv_version = SSL_VER_TLSv1DOT1;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
    }
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
            col_set_str(pinfo->cinfo, COL_PROTOCOL,
                        ssl_version_short_names[*conv_version]);
    }

    /*
     * now dissect the next layer
     */
    ssl_debug_printf("dissect_ssl3_record: content_type %d\n",content_type);

    /* PAOLO try to decrypt each record (we must keep ciphers "in sync")
     * store plain text only for app data */

    switch (content_type) {
    case SSL_ID_CHG_CIPHER_SPEC:
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "Change Cipher Spec");
        dissect_ssl3_change_cipher_spec(tvb, ssl_record_tree,
                                        offset, conv_version, content_type);
        ssl_debug_printf("dissect_ssl3_change_cipher_spec\n");
        break;
    case SSL_ID_ALERT:
      {
	tvbuff_t* decrypted;
	decrypted=0;
	if (ssl&&decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, FALSE))
	  ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
			      ssl_decrypted_data_avail, offset);

	/* try to retrive and use decrypted alert record, if any. */
        decrypted = ssl_get_record_info(proto_ssl, pinfo, offset);
        if (decrypted)
	  dissect_ssl3_alert(decrypted, pinfo, ssl_record_tree, 0,
			     conv_version);
	else
	  dissect_ssl3_alert(tvb, pinfo, ssl_record_tree, offset,
			     conv_version);
        break;
      }
    case SSL_ID_HANDSHAKE:
    {
        tvbuff_t* decrypted;
	decrypted=0;
        /* try to decrypt handshake record, if possible. Store decrypted
         * record for later usage. The offset is used as 'key' to itentify
         * this record into the packet (we can have multiple handshake records
         * in the same frame) */
        if (ssl && decrypt_ssl3_record(tvb, pinfo, offset,
                record_length, content_type, ssl, FALSE))
            ssl_add_record_info(proto_ssl, pinfo, ssl_decrypted_data.data,
                ssl_decrypted_data_avail, offset);

        /* try to retrive and use decrypted handshake record, if any. */
        decrypted = ssl_get_record_info(proto_ssl, pinfo, offset);
        if (decrypted) {
		    /* add desegmented data to the data source list */
		    add_new_data_source(pinfo, decrypted, "Decrypted SSL record");
            dissect_ssl3_handshake(decrypted, pinfo, ssl_record_tree, 0,
                 decrypted->length, conv_version, ssl, content_type);
		} else {
            dissect_ssl3_handshake(tvb, pinfo, ssl_record_tree, offset,
                               record_length, conv_version, ssl, content_type);
		}
        break;
    }
    case SSL_ID_APP_DATA:
        if (ssl){
	    decrypt_ssl3_record(tvb, pinfo, offset,
			    record_length, content_type, ssl, TRUE);
	    /* if application data desegmentation is allowed */
	    if(ssl_desegment_app_data)
		ssl_desegment_ssl_app_data(ssl,pinfo);

        }


        /* show on info colum what we are decoding */
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "Application Data");

        if (!ssl_record_tree)
            break;

        /* we need dissector information when the selected packet is shown.
         * ssl session pointer is NULL at that time, so we can't access
         * info cached there*/
        association = ssl_association_find(ssl_associations, pinfo->srcport, pinfo->ptype == PT_TCP);
        association = association ? association: ssl_association_find(ssl_associations, pinfo->destport, pinfo->ptype == PT_TCP);

        proto_item_set_text(ssl_record_tree,
            "%s Record Layer: %s Protocol: %s",
            ssl_version_short_names[*conv_version],
            val_to_str(content_type, ssl_31_content_type, "unknown"),
            association?association->info:"Application Data");


        proto_tree_add_item(ssl_record_tree, hf_ssl_record_appdata, tvb,
                       offset, record_length, 0);

        /* show decrypted data info, if available */
        pi = p_get_proto_data(pinfo->fd, proto_ssl);
        if (pi && pi->app_data.data)
        {
            tvbuff_t* new_tvb;

            /* try to dissect decrypted data*/
            ssl_debug_printf("dissect_ssl3_record decrypted len %d\n",
                pi->app_data.data_len);

            /* create new tvbuff for the decrypted data */
            new_tvb = tvb_new_real_data(pi->app_data.data,
                pi->app_data.data_len, pi->app_data.data_len);

	    /* add this tvb as a child to the original one */
	    tvb_set_child_real_data_tvbuff(tvb, new_tvb);

	    /* add desegmented data to the data source list */
	    add_new_data_source(pinfo, new_tvb, "Decrypted SSL data");

            /* find out a dissector using server port*/
            if (association && association->handle) {
                ssl_debug_printf("dissect_ssl3_record found association %p\n", association);
                ssl_print_text_data("decrypted app data",pi->app_data.data,
                    pi->app_data.data_len);

                call_dissector(association->handle, new_tvb, pinfo, proto_tree_get_root(tree));
            }
        }
        break;

    default:
        /* shouldn't get here since we check above for valid types */
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "Bad SSLv3 Content Type");
        break;
    }
    offset += record_length; /* skip to end of record */

    return offset;
}

/* dissects the change cipher spec procotol, filling in the tree */
static void
dissect_ssl3_change_cipher_spec(tvbuff_t *tvb,
                                proto_tree *tree, guint32 offset,
                                guint* conv_version, guint8 content_type)
{
    /*
     * struct {
     *     enum { change_cipher_spec(1), (255) } type;
     * } ChangeCipherSpec;
     *
     */
    if (tree)
    {
        proto_item_set_text(tree,
                            "%s Record Layer: %s Protocol: Change Cipher Spec",
                            ssl_version_short_names[*conv_version],
                            val_to_str(content_type, ssl_31_content_type, "unknown"));
        proto_tree_add_item(tree, hf_ssl_change_cipher_spec, tvb,
                            offset++, 1, FALSE);
    }
}

/* dissects the alert message, filling in the tree */
static void
dissect_ssl3_alert(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, guint32 offset,
                   guint* conv_version)
{
    /*     struct {
     *         AlertLevel level;
     *         AlertDescription description;
     *     } Alert;
     */
    proto_tree *ti;
    proto_tree *ssl_alert_tree;
    const gchar *level;
    const gchar *desc;
    guint8 byte;
    ssl_alert_tree = NULL;
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_ssl_alert_message, tvb,
                                 offset, 2, 0);
        ssl_alert_tree = proto_item_add_subtree(ti, ett_ssl_alert);
    }

    /*
     * set the record layer label
     */

    /* first lookup the names for the alert level and description */
    byte = tvb_get_guint8(tvb, offset); /* grab the level byte */
    level = match_strval(byte, ssl_31_alert_level);

    byte = tvb_get_guint8(tvb, offset+1); /* grab the desc byte */
    desc = match_strval(byte, ssl_31_alert_description);

    /* now set the text in the record layer line */
    if (level && desc)
    {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            "Alert (Level: %s, Description: %s)",
                            level, desc);
    }
    else
    {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Alert");
    }

    if (tree)
    {
        if (level && desc)
        {
            proto_item_set_text(tree, "%s Record Layer: Alert "
                                "(Level: %s, Description: %s)",
                                ssl_version_short_names[*conv_version],
                                level, desc);
            proto_tree_add_item(ssl_alert_tree, hf_ssl_alert_message_level,
                                tvb, offset++, 1, FALSE);

            proto_tree_add_item(ssl_alert_tree, hf_ssl_alert_message_description,
                                tvb, offset++, 1, FALSE);
        }
        else
        {
            proto_item_set_text(tree,
                                "%s Record Layer: Encrypted Alert",
                                ssl_version_short_names[*conv_version]);
            proto_item_set_text(ssl_alert_tree,
                                "Alert Message: Encrypted Alert");
        }
    }
}


/* dissects the handshake protocol, filling the tree */
static void
dissect_ssl3_handshake(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, guint32 offset,
                       guint32 record_length, guint *conv_version,
                       SslDecryptSession* ssl, guint8 content_type)
{
    /*     struct {
     *         HandshakeType msg_type;
     *         uint24 length;
     *         select (HandshakeType) {
     *             case hello_request:       HelloRequest;
     *             case client_hello:        ClientHello;
     *             case server_hello:        ServerHello;
     *             case certificate:         Certificate;
     *             case server_key_exchange: ServerKeyExchange;
     *             case certificate_request: CertificateRequest;
     *             case server_hello_done:   ServerHelloDone;
     *             case certificate_verify:  CertificateVerify;
     *             case client_key_exchange: ClientKeyExchange;
     *             case finished:            Finished;
     *         } body;
     *     } Handshake;
     */
    proto_tree *ti;
    proto_tree *ssl_hand_tree;
    const gchar *msg_type_str;
    guint8 msg_type;
    guint32 length;
    gboolean first_iteration;
    ti = NULL;
    ssl_hand_tree = NULL;
    msg_type_str = NULL;
    first_iteration = TRUE;

    /* just as there can be multiple records per packet, there
     * can be multiple messages per record as long as they have
     * the same content type
     *
     * we really only care about this for handshake messages
     */

    /* set record_length to the max offset */
    record_length += offset;
    while (offset < record_length)
    {
        msg_type = tvb_get_guint8(tvb, offset);
        msg_type_str = match_strval(msg_type, ssl_31_handshake_type);
        length   = tvb_get_ntoh24(tvb, offset + 1);

        ssl_debug_printf("dissect_ssl3_handshake iteration %d type %d offset %d lenght %d "
            "bytes, remaning %d \n", first_iteration, msg_type, offset, length, record_length);
        if (!msg_type_str && !first_iteration)
        {
            /* only dissect / report messages if they're
             * either the first message in this record
             * or they're a valid message type
             */
            return;
        }

        /* on second and later iterations, add comma to info col */
        if (!first_iteration)
        {
            if (check_col(pinfo->cinfo, COL_INFO))
                col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
        }

        /*
         * Update our info string
         */
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s", (msg_type_str != NULL)
                            ? msg_type_str : "Encrypted Handshake Message");

        if (tree)
        {
            /* set the label text on the record layer expanding node */
            if (first_iteration)
            {
                proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s",
                                    ssl_version_short_names[*conv_version],
                                    val_to_str(content_type, ssl_31_content_type, "unknown"),
                                    (msg_type_str!=NULL) ? msg_type_str :
                                        "Encrypted Handshake Message");
            }
            else
            {
                proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s",
                                    ssl_version_short_names[*conv_version],
                                    val_to_str(content_type, ssl_31_content_type, "unknown"),
                                    "Multiple Handshake Messages");
            }

            /* add a subtree for the handshake protocol */
            ti = proto_tree_add_item(tree, hf_ssl_handshake_protocol, tvb,
                                     offset, length + 4, 0);
            ssl_hand_tree = proto_item_add_subtree(ti, ett_ssl_handshake);

            if (ssl_hand_tree)
            {
                /* set the text label on the subtree node */
                proto_item_set_text(ssl_hand_tree, "Handshake Protocol: %s",
                                    (msg_type_str != NULL) ? msg_type_str :
                                    "Encrypted Handshake Message");
            }
        }

        /* if we don't have a valid handshake type, just quit dissecting */
        if (!msg_type_str)
            return;

        /* PAOLO: if we are doing ssl decryption we must dissect some requests type */
        if (ssl_hand_tree || ssl)
        {
            /* add nodes for the message type and message length */
            if (ssl_hand_tree)
                proto_tree_add_item(ssl_hand_tree, hf_ssl_handshake_type,
                                    tvb, offset, 1, msg_type);
            offset++;
            if (ssl_hand_tree)
                proto_tree_add_uint(ssl_hand_tree, hf_ssl_handshake_length,
                                tvb, offset, 3, length);
            offset += 3;

            /* now dissect the handshake message, if necessary */
            switch (msg_type) {
            case SSL_HND_HELLO_REQUEST:
                /* hello_request has no fields, so nothing to do! */
                break;

            case SSL_HND_CLIENT_HELLO:
                dissect_ssl3_hnd_cli_hello(tvb, ssl_hand_tree, offset, length, ssl);
            break;

            case SSL_HND_SERVER_HELLO:
                dissect_ssl3_hnd_srv_hello(tvb, ssl_hand_tree, offset, length, ssl);
                break;

            case SSL_HND_CERTIFICATE:
                dissect_ssl3_hnd_cert(tvb, ssl_hand_tree, offset, pinfo);
                break;

            case SSL_HND_SERVER_KEY_EXCHG:
                /* unimplemented */
                break;

            case SSL_HND_CERT_REQUEST:
                dissect_ssl3_hnd_cert_req(tvb, ssl_hand_tree, offset);
                break;

            case SSL_HND_SVR_HELLO_DONE:
                /* server_hello_done has no fields, so nothing to do! */
                break;

            case SSL_HND_CERT_VERIFY:
                /* unimplemented */
                break;

            case SSL_HND_CLIENT_KEY_EXCHG:
                {
                    /* PAOLO: here we can have all the data to build session key*/
                    StringInfo encrypted_pre_master;
                    gint ret;
                    guint encrlen, skip;
    		    encrlen = length;
		    skip = 0;

                    if (!ssl)
                        break;

                    /* check for required session data */
                    ssl_debug_printf("dissect_ssl3_handshake found SSL_HND_CLIENT_KEY_EXCHG state %X\n",
                        ssl->state);
                    if ((ssl->state & (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) !=
                            (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) {
                        ssl_debug_printf("dissect_ssl3_handshake not enough data to generate key (required %X)\n",
                            (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION));
                        break;
                    }

                    /* get encrypted data, on tls1 we have to skip two bytes
                     * (it's the encrypted len and should be equal to record len - 2)
                     */
                    if (ssl->version == SSL_VER_TLS||ssl->version == SSL_VER_TLSv1DOT1)
                    {
                        encrlen  = tvb_get_ntohs(tvb, offset);
                        skip = 2;
                        if (encrlen > length - 2)
                        {
                            ssl_debug_printf("dissect_ssl3_handshake wrong encrypted length (%d max %d)\n",
                                encrlen, length);
                            break;
                        }
                    }
                    encrypted_pre_master.data = se_alloc(encrlen);
                    encrypted_pre_master.data_len = encrlen;
                    tvb_memcpy(tvb, encrypted_pre_master.data, offset+skip, encrlen);

                    if (!ssl->private_key) {
                        ssl_debug_printf("dissect_ssl3_handshake can't find private key\n");
                        break;
                    }

                    /* go with ssl key processessing; encrypted_pre_master
                     * will be used for master secret store*/
                    ret = ssl_decrypt_pre_master_secret(ssl, &encrypted_pre_master, ssl->private_key);
                    if (ret < 0) {
                        ssl_debug_printf("dissect_ssl3_handshake can't decrypt pre master secret\n");
                        break;
                    }
                    if (ssl_generate_keyring_material(ssl)<0) {
                        ssl_debug_printf("dissect_ssl3_handshake can't generate keyring material\n");
                        break;
                    }
                    ssl->state |= SSL_HAVE_SESSION_KEY;
                    ssl_save_session(ssl, ssl_session_hash);
                    ssl_debug_printf("dissect_ssl3_handshake session keys succesfully generated\n");
                }
                break;

            case SSL_HND_FINISHED:
                dissect_ssl3_hnd_finished(tvb, ssl_hand_tree,
                                          offset, conv_version);
                break;
            }

        }
        else
            offset += 4;        /* skip the handshake header when handshake is not processed*/

        offset += length;
        first_iteration = FALSE; /* set up for next pass, if any */
    }
}

static gint
dissect_ssl3_hnd_hello_common(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, SslDecryptSession* ssl, gint from_server)
{
    /* show the client's random challenge */
    nstime_t gmt_unix_time;
    guint8  session_id_length;
	proto_item *ti_rnd;
	proto_tree *ssl_rnd_tree;

    session_id_length = 0;

    if (ssl)
    {
        /* PAOLO: get proper peer information*/
        StringInfo* rnd;
        if (from_server)
            rnd = &ssl->server_random;
        else
            rnd = &ssl->client_random;

        /* get provided random for keyring generation*/
        tvb_memcpy(tvb, rnd->data, offset, 32);
        rnd->data_len = 32;
        if (from_server)
            ssl->state |= SSL_SERVER_RANDOM;
        else
            ssl->state |= SSL_CLIENT_RANDOM;
        ssl_debug_printf("dissect_ssl3_hnd_hello_common found random state %X\n",
            ssl->state);

        session_id_length = tvb_get_guint8(tvb, offset + 32);
        /* check stored session id info */
        if (from_server && (session_id_length == ssl->session_id.data_len) &&
                 (tvb_memeql(tvb, offset+33, ssl->session_id.data, session_id_length) == 0))
        {
            /* clinet/server id match: try to restore a previous cached session*/
            ssl_restore_session(ssl, ssl_session_hash);
        }
        else {
            tvb_memcpy(tvb,ssl->session_id.data, offset+33, session_id_length);
            ssl->session_id.data_len = session_id_length;
        }
    }

    if (tree)
    {
		ti_rnd = proto_tree_add_text(tree, tvb, offset, 32, "Random");
		ssl_rnd_tree = proto_item_add_subtree(ti_rnd, ett_ssl_random);

        /* show the time */
        gmt_unix_time.secs = tvb_get_ntohl(tvb, offset);
        gmt_unix_time.nsecs = 0;
        proto_tree_add_time(ssl_rnd_tree, hf_ssl_handshake_random_time,
                                     tvb, offset, 4, &gmt_unix_time);
        offset += 4;

        /* show the random bytes */
        proto_tree_add_item(ssl_rnd_tree, hf_ssl_handshake_random_bytes,
                            tvb, offset, 28, FALSE);
        offset += 28;

        /* show the session id */
        session_id_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_ssl_handshake_session_id_len,
                            tvb, offset++, 1, 0);
        if (session_id_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, session_id_length);
            proto_tree_add_bytes_format(tree, hf_ssl_handshake_session_id,
                                         tvb, offset, session_id_length,
                                         tvb_get_ptr(tvb, offset, session_id_length),
                                         "Session ID (%u byte%s)",
                                         session_id_length,
                                         plurality(session_id_length, "", "s"));
            offset += session_id_length;
        }

    }

    /* XXXX */
    return session_id_length+33;
}

static gint
dissect_ssl3_hnd_hello_ext(tvbuff_t *tvb,
                           proto_tree *tree, guint32 offset, guint32 left)
{
    guint16 extension_length;
    guint16 ext_type;
    guint16 ext_len;
    proto_item *pi;
    proto_tree *ext_tree;

    if (left < 2)
	return offset;

    extension_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_ssl_handshake_extensions_len,
			tvb, offset, 2, extension_length);
    offset += 2;
    left -= 2;

    while (left >= 4)
    {
	ext_type = tvb_get_ntohs(tvb, offset);
	ext_len = tvb_get_ntohs(tvb, offset + 2);

	pi = proto_tree_add_text(tree, tvb, offset, 4 + ext_len,
				 "Extension: %s",
				 val_to_str(ext_type,
					    tls_hello_extension_types,
					    "Unknown %u"));
	ext_tree = proto_item_add_subtree(pi, ett_ssl_extension);
	if (!ext_tree)
	    ext_tree = tree;

	proto_tree_add_uint(ext_tree, hf_ssl_handshake_extension_type,
			    tvb, offset, 2, ext_type);
	offset += 2;

	proto_tree_add_uint(ext_tree, hf_ssl_handshake_extension_len,
			    tvb, offset, 2, ext_len);
	offset += 2;

	proto_tree_add_bytes_format(ext_tree, hf_ssl_handshake_extension_data,
				    tvb, offset, ext_len,
				    tvb_get_ptr(tvb, offset, ext_len),
				    "Data (%u byte%s)",
				    ext_len, plurality(ext_len, "", "s"));
	offset += ext_len;
	left -= 2 + 2 + ext_len;
    }

    return offset;
}

static void
dissect_ssl3_hnd_cli_hello(tvbuff_t *tvb,
       proto_tree *tree, guint32 offset, guint32 length,
       SslDecryptSession*ssl)
{
    /* struct {
     *     ProtocolVersion client_version;
     *     Random random;
     *     SessionID session_id;
     *     CipherSuite cipher_suites<2..2^16-1>;
     *     CompressionMethod compression_methods<1..2^8-1>;
     *     Extension client_hello_extension_list<0..2^16-1>;
     * } ClientHello;
     *
     */
    proto_tree *ti;
    proto_tree *cs_tree;
    guint16 cipher_suite_length;
    guint8  compression_methods_length;
    guint8  compression_method;
    guint16 start_offset;
    cipher_suite_length = 0;
    compression_methods_length = 0;
    start_offset = offset;

    if (tree || ssl)
    {
        /* show the client version */
        if (tree)
            proto_tree_add_item(tree, hf_ssl_handshake_client_version, tvb,
                            offset, 2, FALSE);
        offset += 2;

        /* show the fields in common with server hello */
        offset += dissect_ssl3_hnd_hello_common(tvb, tree, offset, ssl, 0);

        /* tell the user how many cipher suites there are */
        cipher_suite_length = tvb_get_ntohs(tvb, offset);
        if (!tree)
            return;
        proto_tree_add_uint(tree, hf_ssl_handshake_cipher_suites_len,
                        tvb, offset, 2, cipher_suite_length);
        offset += 2;            /* skip opaque length */

        if (cipher_suite_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, cipher_suite_length);
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_cipher_suites,
                                            tvb, offset, cipher_suite_length,
                                            "Cipher Suites (%u suite%s)",
                                            cipher_suite_length / 2,
                                            plurality(cipher_suite_length/2, "", "s"));

            /* make this a subtree */
            cs_tree = proto_item_add_subtree(ti, ett_ssl_cipher_suites);
            if (!cs_tree)
            {
                cs_tree = tree; /* failsafe */
            }

            while (cipher_suite_length > 0)
            {
                proto_tree_add_item(cs_tree, hf_ssl_handshake_cipher_suite,
                                    tvb, offset, 2, FALSE);
                offset += 2;
                cipher_suite_length -= 2;
            }
        }

        /* tell the user how man compression methods there are */
        compression_methods_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_comp_methods_len,
                            tvb, offset, 1, compression_methods_length);
        offset++;

        if (compression_methods_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, compression_methods_length);
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_comp_methods,
                                            tvb, offset, compression_methods_length,
                                            "Compression Methods (%u method%s)",
                                            compression_methods_length,
                                            plurality(compression_methods_length,
                                              "", "s"));

            /* make this a subtree */
            cs_tree = proto_item_add_subtree(ti, ett_ssl_comp_methods);
            if (!cs_tree)
            {
                cs_tree = tree; /* failsafe */
            }

            while (compression_methods_length > 0)
            {
                compression_method = tvb_get_guint8(tvb, offset);
                if (compression_method < 64)
                    proto_tree_add_uint(cs_tree, hf_ssl_handshake_comp_method,
                                    tvb, offset, 1, compression_method);
                else if (compression_method > 63 && compression_method < 193)
                    proto_tree_add_text(cs_tree, tvb, offset, 1,
                      "Compression Method: Reserved - to be assigned by IANA (%u)",
                      compression_method);
                else
                    proto_tree_add_text(cs_tree, tvb, offset, 1,
                       "Compression Method: Private use range (%u)",
                       compression_method);
                offset++;
                compression_methods_length--;
            }
        }

	if (length > offset - start_offset)
	{
	    offset = dissect_ssl3_hnd_hello_ext(tvb, tree, offset,
						length -
						(offset - start_offset));
	}
    }
}

static void
dissect_ssl3_hnd_srv_hello(tvbuff_t *tvb,
                           proto_tree *tree, guint32 offset, guint32 length, SslDecryptSession* ssl)
{
    /* struct {
     *     ProtocolVersion server_version;
     *     Random random;
     *     SessionID session_id;
     *     CipherSuite cipher_suite;
     *     CompressionMethod compression_method;
     *     Extension server_hello_extension_list<0..2^16-1>;
     * } ServerHello;
     */
    guint16 start_offset;
    start_offset = offset;

    if (tree || ssl)
    {
        /* show the server version */
        if (tree)
                proto_tree_add_item(tree, hf_ssl_handshake_server_version, tvb,
                            offset, 2, FALSE);
        offset += 2;

        /* first display the elements conveniently in
         * common with client hello
         */
        offset += dissect_ssl3_hnd_hello_common(tvb, tree, offset, ssl, 1);

        /* PAOLO: handle session cipher suite  */
        if (ssl) {
            /* store selected cipher suite for decryption */
            ssl->cipher = tvb_get_ntohs(tvb, offset);
            if (ssl_find_cipher(ssl->cipher,&ssl->cipher_suite) < 0) {
                ssl_debug_printf("dissect_ssl3_hnd_srv_hello can't find cipher suite %X\n", ssl->cipher);
                goto no_cipher;
            }

            ssl->state |= SSL_CIPHER;
            ssl_debug_printf("dissect_ssl3_hnd_srv_hello found cipher %X, state %X\n",
                ssl->cipher, ssl->state);

            /* if we have restored a session now we can have enought material
             * to build session key, check it out*/
            if ((ssl->state &
                    (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION|SSL_MASTER_SECRET)) !=
                    (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION|SSL_MASTER_SECRET)) {
                ssl_debug_printf("dissect_ssl3_hnd_srv_hello not enough data to generate key (required %X)\n",
                    (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION|SSL_MASTER_SECRET));
                goto no_cipher;
            }

            ssl_debug_printf("dissect_ssl3_hnd_srv_hello trying to generate keys\n");
            if (ssl_generate_keyring_material(ssl)<0) {
                ssl_debug_printf("dissect_ssl3_hnd_srv_hello can't generate keyring material\n");
                goto no_cipher;
            }
            ssl->state |= SSL_HAVE_SESSION_KEY;
        }
no_cipher:
        if (!tree)
            return;

        /* now the server-selected cipher suite */
        proto_tree_add_item(tree, hf_ssl_handshake_cipher_suite,
                    tvb, offset, 2, FALSE);
        offset += 2;

        /* and the server-selected compression method */
        proto_tree_add_item(tree, hf_ssl_handshake_comp_method,
                            tvb, offset, 1, FALSE);
	offset++;

	if (length > offset - start_offset)
	{
	    offset = dissect_ssl3_hnd_hello_ext(tvb, tree, offset,
						length -
						(offset - start_offset));
	}
    }
}

static void
dissect_ssl3_hnd_cert(tvbuff_t *tvb,
                      proto_tree *tree, guint32 offset, packet_info *pinfo)
{

    /* opaque ASN.1Cert<2^24-1>;
     *
     * struct {
     *     ASN.1Cert certificate_list<1..2^24-1>;
     * } Certificate;
     */
    guint32 certificate_list_length;
    proto_tree *ti;
    proto_tree *subtree;

    if (tree)
    {
        certificate_list_length = tvb_get_ntoh24(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_certificates_len,
                            tvb, offset, 3, certificate_list_length);
        offset += 3;            /* 24-bit length value */

        if (certificate_list_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, certificate_list_length);
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_certificates,
                                            tvb, offset, certificate_list_length,
                                            "Certificates (%u byte%s)",
                                            certificate_list_length,
                                            plurality(certificate_list_length,
                                              "", "s"));

            /* make it a subtree */
            subtree = proto_item_add_subtree(ti, ett_ssl_certs);
            if (!subtree)
            {
                subtree = tree; /* failsafe */
            }

            /* iterate through each certificate */
            while (certificate_list_length > 0)
            {
                /* get the length of the current certificate */
                guint32 cert_length;
		cert_length = tvb_get_ntoh24(tvb, offset);
                certificate_list_length -= 3 + cert_length;

                proto_tree_add_item(subtree, hf_ssl_handshake_certificate_len,
                                    tvb, offset, 3, FALSE);
                offset += 3;

		dissect_x509af_Certificate(FALSE, tvb, offset, pinfo, subtree, hf_ssl_handshake_certificate);
		offset += cert_length;
            }
        }

    }
}

static void
dissect_ssl3_hnd_cert_req(tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset)
{
    /*
     *    enum {
     *        rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
     *        (255)
     *    } ClientCertificateType;
     *
     *    opaque DistinguishedName<1..2^16-1>;
     *
     *    struct {
     *        ClientCertificateType certificate_types<1..2^8-1>;
     *        DistinguishedName certificate_authorities<3..2^16-1>;
     *    } CertificateRequest;
     *
     */
    proto_tree *ti;
    proto_tree *subtree;
    guint8      cert_types_count;
    gint         dnames_length;
    cert_types_count = 0;
    dnames_length = 0;

    if (tree)
    {
        cert_types_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_cert_types_count,
                            tvb, offset, 1, cert_types_count);
        offset++;

        if (cert_types_count > 0)
        {
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_cert_types,
                                            tvb, offset, cert_types_count,
                                            "Certificate types (%u type%s)",
                                            cert_types_count,
                                            plurality(cert_types_count, "", "s"));
            subtree = proto_item_add_subtree(ti, ett_ssl_cert_types);
            if (!subtree)
            {
                subtree = tree;
            }

            while (cert_types_count > 0)
            {
                proto_tree_add_item(subtree, hf_ssl_handshake_cert_type,
                                    tvb, offset, 1, FALSE);
                offset++;
                cert_types_count--;
            }
        }

        dnames_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(tree, hf_ssl_handshake_dnames_len,
                            tvb, offset, 2, dnames_length);
        offset += 2;

        if (dnames_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, dnames_length);
            ti = proto_tree_add_none_format(tree,
                                            hf_ssl_handshake_dnames,
                                            tvb, offset, dnames_length,
                                            "Distinguished Names (%d byte%s)",
                                            dnames_length,
                                            plurality(dnames_length, "", "s"));
            subtree = proto_item_add_subtree(ti, ett_ssl_dnames);
            if (!subtree)
            {
                subtree = tree;
            }

            while (dnames_length > 0)
            {
                /* get the length of the current certificate */
                guint16 name_length;
		name_length = tvb_get_ntohs(tvb, offset);
                dnames_length -= 2 + name_length;

                proto_tree_add_item(subtree, hf_ssl_handshake_dname_len,
                                    tvb, offset, 2, FALSE);
                offset += 2;

                tvb_ensure_bytes_exist(tvb, offset, name_length);
                proto_tree_add_bytes_format(subtree,
                                            hf_ssl_handshake_dname,
                                            tvb, offset, name_length,
                                            tvb_get_ptr(tvb, offset, name_length),
                                            "Distinguished Name (%u byte%s)",
                                            name_length,
                                            plurality(name_length, "", "s"));
                offset += name_length;
            }
        }
    }

}

static void
dissect_ssl3_hnd_finished(tvbuff_t *tvb,
                          proto_tree *tree, guint32 offset,
                          guint* conv_version)
{
    /* For TLS:
     *     struct {
     *         opaque verify_data[12];
     *     } Finished;
     *
     * For SSLv3:
     *     struct {
     *         opaque md5_hash[16];
     *         opaque sha_hash[20];
     *     } Finished;
     */

    /* this all needs a tree, so bail if we don't have one */
    if (!tree)
    {
        return;
    }

    switch(*conv_version) {
    case SSL_VER_TLS:
    case SSL_VER_TLSv1DOT1:
        proto_tree_add_item(tree, hf_ssl_handshake_finished,
                            tvb, offset, 12, FALSE);
        break;

    case SSL_VER_SSLv3:
        proto_tree_add_item(tree, hf_ssl_handshake_md5_hash,
                            tvb, offset, 16, FALSE);
        offset += 16;
        proto_tree_add_item(tree, hf_ssl_handshake_sha_hash,
                            tvb, offset, 20, FALSE);
        offset += 20;
        break;
    }
}

/*********************************************************************
 *
 * SSL version 2 Dissectors
 *
 *********************************************************************/


/* record layer dissector */
static gint
dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint32 offset, guint* conv_version,
                    gboolean *need_desegmentation,
                    SslDecryptSession* ssl)
{
    guint32 initial_offset;
    guint8  byte;
    guint8  record_length_length;
    guint32 record_length;
    gint    is_escape;
    gint16  padding_length;
    guint8  msg_type;
    const gchar *msg_type_str;
    guint32 available_bytes;
    proto_tree *ti;
    proto_tree *ssl_record_tree;

    initial_offset       = offset;
    byte                 = 0;
    record_length_length = 0;
    record_length        = 0;
    is_escape            = -1;
    padding_length       = -1;
    msg_type             = 0;
    msg_type_str         = NULL;
    available_bytes      = 0;
    ssl_record_tree      = NULL;

    /* pull first byte; if high bit is set, then record
     * length is three bytes due to padding; otherwise
     * record length is two bytes
     */
    byte = tvb_get_guint8(tvb, offset);
    record_length_length = (byte & 0x80) ? 2 : 3;

    /*
     * Can we do reassembly?
     */
    available_bytes = tvb_length_remaining(tvb, offset);

    if (ssl_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the record header split across segment boundaries?
         */
        if (available_bytes < record_length_length) {
            /*
             * Yes.  Tell the TCP dissector where the data for this
             * message starts in the data it handed us, and how many
             * more bytes we need, and return.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = record_length_length - available_bytes;
            *need_desegmentation = TRUE;
            return offset;
        }
    }

    /* parse out the record length */
    switch(record_length_length) {
    case 2:                     /* two-byte record length */
        record_length = (byte & 0x7f) << 8;
        byte = tvb_get_guint8(tvb, offset + 1);
        record_length += byte;
        break;
    case 3:                     /* three-byte record length */
        is_escape = (byte & 0x40) ? TRUE : FALSE;
        record_length = (byte & 0x3f) << 8;
        byte = tvb_get_guint8(tvb, offset + 1);
        record_length += byte;
        byte = tvb_get_guint8(tvb, offset + 2);
        padding_length = byte;
    }

    /*
     * Can we do reassembly?
     */
    if (ssl_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the record split across segment boundaries?
         */
        if (available_bytes < (record_length_length + record_length)) {
            /*
             * Yes.  Tell the TCP dissector where the data for this
             * message starts in the data it handed us, and how many
             * more bytes we need, and return.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = (record_length_length + record_length)
		                   - available_bytes;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    offset += record_length_length;

    /* add the record layer subtree header */
    ti = proto_tree_add_item(tree, hf_ssl2_record, tvb, initial_offset,
                             record_length_length + record_length, 0);
    ssl_record_tree = proto_item_add_subtree(ti, ett_ssl_record);

    /* pull the msg_type so we can bail if it's unknown */
    msg_type = tvb_get_guint8(tvb, initial_offset + record_length_length);

    /* if we get a server_hello or later handshake in v2, then set
     * this to sslv2
     */
    if (*conv_version == SSL_VER_UNKNOWN)
    {
        if (ssl_looks_like_valid_pct_handshake(tvb,
                                               (initial_offset +
                                                record_length_length),
                                               record_length)) {
            *conv_version = SSL_VER_PCT;
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
        else if (msg_type >= 2 && msg_type <= 8)
        {
            *conv_version = SSL_VER_SSLv2;
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
    }

    /* if we get here, but don't have a version set for the
     * conversation, then set a version for just this frame
     * (e.g., on a client hello)
     */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL,
                    (*conv_version == SSL_VER_PCT) ? "PCT" : "SSLv2");
    }

    /* see if the msg_type is valid; if not the payload is
     * probably encrypted, so note that fact and bail
     */
    msg_type_str = match_strval(msg_type,
                                (*conv_version == SSL_VER_PCT)
				? pct_msg_types : ssl_20_msg_types);
    if (!msg_type_str
        || ((*conv_version != SSL_VER_PCT) &&
	    !ssl_looks_like_valid_v2_handshake(tvb, initial_offset
					       + record_length_length,
					       record_length))
	|| ((*conv_version == SSL_VER_PCT) &&
	    !ssl_looks_like_valid_pct_handshake(tvb, initial_offset
						+ record_length_length,
						record_length)))
    {
        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "%s Record Layer: %s",
                                (*conv_version == SSL_VER_PCT)
                                ? "PCT" : "SSLv2",
                                "Encrypted Data");
        }
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "Encrypted Data");
        return initial_offset + record_length_length + record_length;
    }
    else
    {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, msg_type_str);

        if (ssl_record_tree)
        {
            proto_item_set_text(ssl_record_tree, "%s Record Layer: %s",
                                (*conv_version == SSL_VER_PCT)
                                ? "PCT" : "SSLv2",
                                msg_type_str);
        }
    }

    /* We have a valid message type, so move foward, filling in the
     * tree by adding the length, is_escape boolean and padding_length,
     * if present in the original packet
     */
    if (ssl_record_tree)
    {
        /* add the record length */
        tvb_ensure_bytes_exist(tvb, offset, record_length_length);
        ti = proto_tree_add_uint (ssl_record_tree,
                                  hf_ssl_record_length, tvb,
                                  initial_offset, record_length_length,
                                  record_length);
    }
    if (ssl_record_tree && is_escape != -1)
    {
        proto_tree_add_boolean(ssl_record_tree,
                               hf_ssl2_record_is_escape, tvb,
                               initial_offset, 1, is_escape);
        }
    if (ssl_record_tree && padding_length != -1)
    {
        proto_tree_add_uint(ssl_record_tree,
                            hf_ssl2_record_padding_length, tvb,
                            initial_offset + 2, 1, padding_length);
    }

    /*
     * dissect the record data
     */

    /* jump forward to the start of the record data */
    offset = initial_offset + record_length_length;

    /* add the message type */
    if (ssl_record_tree)
    {
        proto_tree_add_item(ssl_record_tree,
                            (*conv_version == SSL_VER_PCT)
                            ? hf_pct_msg_type : hf_ssl2_msg_type,
                            tvb, offset, 1, 0);
    }
    offset++;                   /* move past msg_type byte */

    if (*conv_version != SSL_VER_PCT)
    {
        /* dissect the message (only handle client hello right now) */
        switch (msg_type) {
        case SSL2_HND_CLIENT_HELLO:
            dissect_ssl2_hnd_client_hello(tvb, ssl_record_tree, offset, ssl);
            break;

        case SSL2_HND_CLIENT_MASTER_KEY:
            dissect_ssl2_hnd_client_master_key(tvb, ssl_record_tree, offset);
            break;

        case SSL2_HND_SERVER_HELLO:
            dissect_ssl2_hnd_server_hello(tvb, ssl_record_tree, offset, pinfo);
            break;

        case SSL2_HND_ERROR:
        case SSL2_HND_CLIENT_FINISHED:
        case SSL2_HND_SERVER_VERIFY:
        case SSL2_HND_SERVER_FINISHED:
        case SSL2_HND_REQUEST_CERTIFICATE:
        case SSL2_HND_CLIENT_CERTIFICATE:
            /* unimplemented */
            break;

        default:                    /* unknown */
            break;
        }
    }
    else
    {
        /* dissect the message */
        switch (msg_type) {
        case PCT_MSG_CLIENT_HELLO:
			dissect_pct_msg_client_hello(tvb, ssl_record_tree, offset);
			break;
        case PCT_MSG_SERVER_HELLO:
			dissect_pct_msg_server_hello(tvb, ssl_record_tree, offset, pinfo);
			break;
        case PCT_MSG_CLIENT_MASTER_KEY:
			dissect_pct_msg_client_master_key(tvb, ssl_record_tree, offset);
			break;
        case PCT_MSG_SERVER_VERIFY:
			dissect_pct_msg_server_verify(tvb, ssl_record_tree, offset);
			break;
		case PCT_MSG_ERROR:
			dissect_pct_msg_error(tvb, ssl_record_tree, offset);
            break;

        default:                    /* unknown */
            break;
        }
    }
    return (initial_offset + record_length_length + record_length);
}

static void
dissect_ssl2_hnd_client_hello(tvbuff_t *tvb,
                              proto_tree *tree, guint32 offset,
                              SslDecryptSession* ssl)
{
    /* struct {
     *    uint8 msg_type;
     *     Version version;
     *     uint16 cipher_spec_length;
     *     uint16 session_id_length;
     *     uint16 challenge_length;
     *     V2CipherSpec cipher_specs[V2ClientHello.cipher_spec_length];
     *     opaque session_id[V2ClientHello.session_id_length];
     *     Random challenge;
     * } V2ClientHello;
     *
     * Note: when we get here, offset's already pointing at Version
     *
     */
    guint16 version;
    guint16 cipher_spec_length;
    guint16 session_id_length;
    guint16 challenge_length;

    proto_tree *ti;
    proto_tree *cs_tree;
    cs_tree=0;

    version = tvb_get_ntohs(tvb, offset);
    if (!ssl_is_valid_ssl_version(version))
    {
        /* invalid version; probably encrypted data */
        return;
    }

    if (tree || ssl)
    {
        /* show the version */
        if (tree)
            proto_tree_add_item(tree, hf_ssl_record_version, tvb,
                            offset, 2, FALSE);
        offset += 2;

        cipher_spec_length = tvb_get_ntohs(tvb, offset);
        if (tree)
            proto_tree_add_item(tree, hf_ssl2_handshake_cipher_spec_len,
                            tvb, offset, 2, FALSE);
        offset += 2;

        session_id_length = tvb_get_ntohs(tvb, offset);
        if (tree)
            proto_tree_add_item(tree, hf_ssl2_handshake_session_id_len,
                            tvb, offset, 2, FALSE);
        offset += 2;

        challenge_length = tvb_get_ntohs(tvb, offset);
        if (tree)
            proto_tree_add_item(tree, hf_ssl2_handshake_challenge_len,
                            tvb, offset, 2, FALSE);
        offset += 2;

        if (tree)
        {
            /* tell the user how many cipher specs they've won */
            tvb_ensure_bytes_exist(tvb, offset, cipher_spec_length);
            ti = proto_tree_add_none_format(tree, hf_ssl_handshake_cipher_suites,
                                        tvb, offset, cipher_spec_length,
                                        "Cipher Specs (%u specs)",
                                        cipher_spec_length/3);

            /* make this a subtree and expand the actual specs below */
            cs_tree = proto_item_add_subtree(ti, ett_ssl_cipher_suites);
            if (!cs_tree)
            {
                cs_tree = tree;     /* failsafe */
            }
        }

        /* iterate through the cipher specs, showing them */
        while (cipher_spec_length > 0)
        {
            if (cs_tree)
                proto_tree_add_item(cs_tree, hf_ssl2_handshake_cipher_spec,
                                tvb, offset, 3, FALSE);
            offset += 3;        /* length of one cipher spec */
            cipher_spec_length -= 3;
        }

        /* if there's a session id, show it */
        if (session_id_length > 0)
        {
            if (tree)
            {
                tvb_ensure_bytes_exist(tvb, offset, session_id_length);
                proto_tree_add_bytes_format(tree,
                                             hf_ssl_handshake_session_id,
                                             tvb, offset, session_id_length,
                                             tvb_get_ptr(tvb, offset, session_id_length),
                                             "Session ID (%u byte%s)",
                                             session_id_length,
                                             plurality(session_id_length, "", "s"));
            }

            /* PAOLO: get session id and reset session state for key [re]negotiation */
            if (ssl)
            {
                tvb_memcpy(tvb,ssl->session_id.data, offset, session_id_length);
                ssl->session_id.data_len = session_id_length;
                ssl->state &= ~(SSL_HAVE_SESSION_KEY|SSL_MASTER_SECRET|
                        SSL_CIPHER|SSL_SERVER_RANDOM);
            }
            offset += session_id_length;
        }

        /* if there's a challenge, show it */
        if (challenge_length > 0)
        {
            tvb_ensure_bytes_exist(tvb, offset, challenge_length);

            if (tree)
                proto_tree_add_item(tree, hf_ssl2_handshake_challenge,
                                tvb, offset, challenge_length, 0);
            if (ssl)
            {
                /* PAOLO: get client random data; we get at most 32 bytes from
                 challenge */
                gint max;
                max = challenge_length > 32? 32: challenge_length;

                ssl_debug_printf("client random len: %d padded to 32\n",
                    challenge_length);

                /* client random is padded with zero and 'right' aligned */
                memset(ssl->client_random.data, 0, 32 - max);
                tvb_memcpy(tvb, &ssl->client_random.data[32 - max], offset, max);
                ssl->client_random.data_len = 32;
                ssl->state |= SSL_CLIENT_RANDOM;

            }
            offset += challenge_length;
        }
    }
}

static void
dissect_pct_msg_client_hello(tvbuff_t *tvb,
							proto_tree *tree, guint32 offset)
{
	guint16 CH_CLIENT_VERSION, CH_OFFSET, CH_CIPHER_SPECS_LENGTH, CH_HASH_SPECS_LENGTH, CH_CERT_SPECS_LENGTH, CH_EXCH_SPECS_LENGTH, CH_KEY_ARG_LENGTH;
	proto_item *CH_CIPHER_SPECS_ti, *CH_HASH_SPECS_ti, *CH_CERT_SPECS_ti, *CH_EXCH_SPECS_ti;
	proto_tree *CH_CIPHER_SPECS_tree, *CH_HASH_SPECS_tree, *CH_CERT_SPECS_tree, *CH_EXCH_SPECS_tree;
	gint i;

	CH_CLIENT_VERSION = tvb_get_ntohs(tvb, offset);
	if(CH_CLIENT_VERSION != PCT_VERSION_1)
		proto_tree_add_text(tree, tvb, offset, 2, "Client Version, should be %x in PCT version 1", PCT_VERSION_1);
	else
		proto_tree_add_text(tree, tvb, offset, 2, "Client Version (%x)", PCT_VERSION_1);
	offset += 2;

	proto_tree_add_text(tree, tvb, offset, 1, "PAD");
	offset += 1;

	proto_tree_add_text(tree, tvb, offset, 32, "Client Session ID Data (32 bytes)");
	offset += 32;

	proto_tree_add_text(tree, tvb, offset, 32, "Challange Data(32 bytes)");
	offset += 32;

	CH_OFFSET = tvb_get_ntohs(tvb, offset);
	if(CH_OFFSET != PCT_CH_OFFSET_V1)
		proto_tree_add_text(tree, tvb, offset, 2, "CH_OFFSET: %d, should be %d in PCT version 1", CH_OFFSET, PCT_CH_OFFSET_V1);
	else
		proto_tree_add_text(tree, tvb, offset, 2, "CH_OFFSET: %d", CH_OFFSET);
	offset += 2;

	CH_CIPHER_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "CIPHER_SPECS Length: %d", CH_CIPHER_SPECS_LENGTH);
	offset += 2;

	CH_HASH_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "HASH_SPECS Length: %d", CH_HASH_SPECS_LENGTH);
	offset += 2;

	CH_CERT_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "CERT_SPECS Length: %d", CH_CERT_SPECS_LENGTH);
	offset += 2;

	CH_EXCH_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "EXCH_SPECS Length: %d", CH_EXCH_SPECS_LENGTH);
	offset += 2;

	CH_KEY_ARG_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "IV Length: %d", CH_KEY_ARG_LENGTH);
	offset += 2;

	if(CH_CIPHER_SPECS_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CH_CIPHER_SPECS_LENGTH);
		CH_CIPHER_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_cipher_spec, tvb, offset, CH_CIPHER_SPECS_LENGTH, FALSE);
		CH_CIPHER_SPECS_tree = proto_item_add_subtree(CH_CIPHER_SPECS_ti, ett_pct_cipher_suites);

		for(i=0; i<(CH_CIPHER_SPECS_LENGTH/4); i++) {
			proto_tree_add_item(CH_CIPHER_SPECS_tree, hf_pct_handshake_cipher, tvb, offset, 2, FALSE);
			offset += 2;
			proto_tree_add_text(CH_CIPHER_SPECS_tree, tvb, offset, 1, "Encryption key length: %d", tvb_get_guint8(tvb, offset));
			offset += 1;
			proto_tree_add_text(CH_CIPHER_SPECS_tree, tvb, offset, 1, "MAC key length in bits: %d", tvb_get_guint8(tvb, offset) + 64);
			offset += 1;
		}
	}

	if(CH_HASH_SPECS_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CH_HASH_SPECS_LENGTH);
		CH_HASH_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_hash_spec, tvb, offset, CH_HASH_SPECS_LENGTH, FALSE);
		CH_HASH_SPECS_tree = proto_item_add_subtree(CH_HASH_SPECS_ti, ett_pct_hash_suites);

		for(i=0; i<(CH_HASH_SPECS_LENGTH/2); i++) {
			proto_tree_add_item(CH_HASH_SPECS_tree, hf_pct_handshake_hash, tvb, offset, 2, FALSE);
			offset += 2;
		}
	}

	if(CH_CERT_SPECS_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CH_CERT_SPECS_LENGTH);
		CH_CERT_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_cert_spec, tvb, offset, CH_CERT_SPECS_LENGTH, FALSE);
		CH_CERT_SPECS_tree = proto_item_add_subtree(CH_CERT_SPECS_ti, ett_pct_cert_suites);

		for(i=0; i< (CH_CERT_SPECS_LENGTH/2); i++) {
			proto_tree_add_item(CH_CERT_SPECS_tree, hf_pct_handshake_cert, tvb, offset, 2, FALSE);
			offset += 2;
		}
	}

	if(CH_EXCH_SPECS_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CH_EXCH_SPECS_LENGTH);
		CH_EXCH_SPECS_ti = proto_tree_add_item(tree, hf_pct_handshake_exch_spec, tvb, offset, CH_EXCH_SPECS_LENGTH, FALSE);
		CH_EXCH_SPECS_tree = proto_item_add_subtree(CH_EXCH_SPECS_ti, ett_pct_exch_suites);

		for(i=0; i<(CH_EXCH_SPECS_LENGTH/2); i++) {
			proto_tree_add_item(CH_EXCH_SPECS_tree, hf_pct_handshake_exch, tvb, offset, 2, FALSE);
			offset += 2;
		}
	}

	if(CH_KEY_ARG_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CH_KEY_ARG_LENGTH);
		proto_tree_add_text(tree, tvb, offset, CH_KEY_ARG_LENGTH, "IV data (%d bytes)", CH_KEY_ARG_LENGTH);
		offset += CH_KEY_ARG_LENGTH;
	}
}

static void
dissect_pct_msg_server_hello(tvbuff_t *tvb, proto_tree *tree, guint32 offset, packet_info *pinfo)
{
/* structure:
char SH_MSG_SERVER_HELLO
char SH_PAD
char SH_SERVER_VERSION_MSB
char SH_SERVER_VERSION_LSB
char SH_RESTART_SESSION_OK
char SH_CLIENT_AUTH_REQ
char SH_CIPHER_SPECS_DATA[4]
char SH_HASH_SPECS_DATA[2]
char SH_CERT_SPECS_DATA[2]
char SH_EXCH_SPECS_DATA[2]
char SH_CONNECTION_ID_DATA[32]
char SH_CERTIFICATE_LENGTH_MSB
char SH_CERTIFICATE_LENGTH_LSB
char SH_CLIENT_CERT_SPECS_LENGTH_MSB
char SH_CLIENT_CERT_SPECS_LENGTH_LSB
char SH_CLIENT_SIG_SPECS_LENGTH_MSB
char SH_CLIENT_SIG_SPECS_LENGTH_LSB
char SH_RESPONSE_LENGTH_MSB
char SH_RESPONSE_LENGTH_LSB
char SH_CERTIFICATE_DATA[MSB<<8|LSB]
char SH_CLIENT_CERT_SPECS_DATA[MSB<<8|LSB]
char SH_CLIENT_SIG_SPECS_DATA[MSB<<8|LSB]
char SH_RESPONSE_DATA[MSB<<8|LSB]

*/

	guint16 SH_SERVER_VERSION, SH_CERT_LENGTH, SH_CERT_SPECS_LENGTH, SH_CLIENT_SIG_LENGTH, SH_RESPONSE_LENGTH;

	proto_tree_add_text(tree, tvb, offset, 1, "PAD");
	offset += 1;

	SH_SERVER_VERSION = tvb_get_ntohs(tvb, offset);
	if(SH_SERVER_VERSION != PCT_VERSION_1)
		proto_tree_add_text(tree, tvb, offset, 2, "Server Version, should be %x in PCT version 1", PCT_VERSION_1);
	else
		proto_tree_add_text(tree, tvb, offset, 2, "Server Version (%x)", PCT_VERSION_1);
	offset += 2;

	proto_tree_add_text(tree, tvb, offset, 1, "SH_RESTART_SESSION_OK flag");
	offset += 1;

	proto_tree_add_text(tree, tvb, offset, 1, "SH_CLIENT_AUTH_REQ flag");
	offset += 1;

	proto_tree_add_item(tree, hf_pct_handshake_cipher, tvb, offset, 2, FALSE);
	offset += 2;
	proto_tree_add_text(tree, tvb, offset, 1, "Encryption key length: %d", tvb_get_guint8(tvb, offset));
	offset += 1;
	proto_tree_add_text(tree, tvb, offset, 1, "MAC key length in bits: %d", tvb_get_guint8(tvb, offset) + 64);
	offset += 1;

	proto_tree_add_item(tree, hf_pct_handshake_hash, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_pct_handshake_cert, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_pct_handshake_exch, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_text(tree, tvb, offset, 32, "Connection ID Data (32 bytes)");
	offset += 32;

	SH_CERT_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Server Certificate Length: %d", SH_CERT_LENGTH);
	offset += 2;

	SH_CERT_SPECS_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Client CERT_SPECS Length: %d", SH_CERT_SPECS_LENGTH);
	offset += 2;

	SH_CLIENT_SIG_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Client SIG_SPECS Length: %d", SH_CLIENT_SIG_LENGTH);
	offset += 2;

	SH_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Response Length: %d", SH_RESPONSE_LENGTH);
	offset += 2;

	if(SH_CERT_LENGTH) {
		dissect_x509af_Certificate(FALSE, tvb, offset, pinfo, tree, hf_pct_handshake_server_cert);
		offset += SH_CERT_LENGTH;
	}

	if(SH_CERT_SPECS_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, SH_CERT_SPECS_LENGTH);
		proto_tree_add_text(tree, tvb, offset, SH_CERT_SPECS_LENGTH, "Client CERT_SPECS (%d bytes)", SH_CERT_SPECS_LENGTH);
		offset += SH_CERT_SPECS_LENGTH;
	}

	if(SH_CLIENT_SIG_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, SH_CLIENT_SIG_LENGTH);
		proto_tree_add_text(tree, tvb, offset, SH_CLIENT_SIG_LENGTH, "Client Signature (%d bytes)", SH_CLIENT_SIG_LENGTH);
		offset += SH_CLIENT_SIG_LENGTH;
	}

	if(SH_RESPONSE_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, SH_RESPONSE_LENGTH);
		proto_tree_add_text(tree, tvb, offset, SH_RESPONSE_LENGTH, "Server Response (%d bytes)", SH_RESPONSE_LENGTH);
		offset += SH_RESPONSE_LENGTH;
	}

}

static void
dissect_pct_msg_client_master_key(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
	guint16 CMK_CLEAR_KEY_LENGTH, CMK_ENCRYPTED_KEY_LENGTH, CMK_KEY_ARG_LENGTH, CMK_VERIFY_PRELUDE, CMK_CLIENT_CERT_LENGTH, CMK_RESPONSE_LENGTH;

	proto_tree_add_text(tree, tvb, offset, 1, "PAD");
	offset += 1;

	proto_tree_add_item(tree, hf_pct_handshake_cert, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_pct_handshake_sig, tvb, offset, 2, FALSE);
	offset += 2;

	CMK_CLEAR_KEY_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Clear Key Length: %d",CMK_CLEAR_KEY_LENGTH);
	offset += 2;

	CMK_ENCRYPTED_KEY_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Encrypted Key Length: %d",CMK_ENCRYPTED_KEY_LENGTH);
	offset += 2;

	CMK_KEY_ARG_LENGTH= tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "IV Length: %d",CMK_KEY_ARG_LENGTH);
	offset += 2;

	CMK_VERIFY_PRELUDE = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Verify Prelude Length: %d",CMK_VERIFY_PRELUDE);
	offset += 2;

	CMK_CLIENT_CERT_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Client Cert Length: %d",CMK_CLIENT_CERT_LENGTH);
	offset += 2;

	CMK_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Response Length: %d",CMK_RESPONSE_LENGTH);
	offset += 2;

	if(CMK_CLEAR_KEY_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CMK_CLEAR_KEY_LENGTH);
		proto_tree_add_text(tree, tvb, offset, CMK_CLEAR_KEY_LENGTH, "Clear Key data (%d bytes)", CMK_CLEAR_KEY_LENGTH);
		offset += CMK_CLEAR_KEY_LENGTH;
	}
	if(CMK_ENCRYPTED_KEY_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CMK_ENCRYPTED_KEY_LENGTH);
		proto_tree_add_text(tree, tvb, offset, CMK_ENCRYPTED_KEY_LENGTH, "Encrypted Key data (%d bytes)", CMK_ENCRYPTED_KEY_LENGTH);
		offset += CMK_ENCRYPTED_KEY_LENGTH;
	}
	if(CMK_KEY_ARG_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CMK_KEY_ARG_LENGTH);
		proto_tree_add_text(tree, tvb, offset, CMK_KEY_ARG_LENGTH, "IV data (%d bytes)", CMK_KEY_ARG_LENGTH);
		offset += CMK_KEY_ARG_LENGTH;
	}
	if(CMK_VERIFY_PRELUDE) {
                tvb_ensure_bytes_exist(tvb, offset, CMK_VERIFY_PRELUDE);
		proto_tree_add_text(tree, tvb, offset, CMK_VERIFY_PRELUDE, "Verify Prelude data (%d bytes)", CMK_VERIFY_PRELUDE);
		offset += CMK_VERIFY_PRELUDE;
	}
	if(CMK_CLIENT_CERT_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CMK_CLIENT_CERT_LENGTH);
		proto_tree_add_text(tree, tvb, offset, CMK_CLIENT_CERT_LENGTH, "Client Certificate data (%d bytes)", CMK_CLIENT_CERT_LENGTH);
		offset += CMK_CLIENT_CERT_LENGTH;
	}
	if(CMK_RESPONSE_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, CMK_RESPONSE_LENGTH);
		proto_tree_add_text(tree, tvb, offset, CMK_RESPONSE_LENGTH, "Response data (%d bytes)", CMK_RESPONSE_LENGTH);
		offset += CMK_RESPONSE_LENGTH;
	}
}

static void
dissect_pct_msg_server_verify(tvbuff_t *tvb,
							proto_tree *tree, guint32 offset)
{
	guint16 SV_RESPONSE_LENGTH;

	proto_tree_add_text(tree, tvb, offset, 1, "PAD");
	offset += 1;

	proto_tree_add_text(tree, tvb, offset, 32, "Server Session ID data (32 bytes)");
	offset += 32;

	SV_RESPONSE_LENGTH = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Server Response Length: %d", SV_RESPONSE_LENGTH);
	offset += 2;

	if(SV_RESPONSE_LENGTH) {
                tvb_ensure_bytes_exist(tvb, offset, SV_RESPONSE_LENGTH);
		proto_tree_add_text(tree, tvb, offset, SV_RESPONSE_LENGTH, "Server Response (%d bytes)", SV_RESPONSE_LENGTH);
		offset += SV_RESPONSE_LENGTH;
	}
}

static void
dissect_pct_msg_error(tvbuff_t *tvb,
							proto_tree *tree, guint32 offset)
{
	guint16 ERROR_CODE, INFO_LEN;

	ERROR_CODE = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_pct_msg_error_type, tvb, offset, 2, FALSE);
	offset += 2;

	INFO_LEN = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Eror Information Length: %d", INFO_LEN);
	offset += 2;
	if (ERROR_CODE == PCT_ERR_SPECS_MISMATCH && INFO_LEN == 6)
	{
		proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_CIPHER");
		offset += 1;
		proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_HASH");
		offset += 1;
		proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_CERT");
		offset += 1;
		proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_EXCH");
		offset += 1;
		proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_CLIENT_CERT");
		offset += 1;
		proto_tree_add_text(tree, tvb, offset, 1, "SPECS_MISMATCH_CLIENT_SIG");
		offset += 1;
	}
	else if(INFO_LEN) {
		proto_tree_add_text(tree, tvb, offset, INFO_LEN, "Error Information dta (%d bytes)", INFO_LEN);
		offset += INFO_LEN;
	}
}

static void
dissect_ssl2_hnd_client_master_key(tvbuff_t *tvb,
                                   proto_tree *tree, guint32 offset)
{
    /* struct {
     *    uint8 msg_type;
     *    V2Cipherspec cipher;
     *    uint16 clear_key_length;
     *    uint16 encrypted_key_length;
     *    uint16 key_arg_length;
     *    opaque clear_key_data[V2ClientMasterKey.clear_key_length];
     *    opaque encrypted_key_data[V2ClientMasterKey.encrypted_key_length];
     *    opaque key_arg_data[V2ClientMasterKey.key_arg_length];
     * } V2ClientMasterKey;
     *
     * Note: when we get here, offset's already pointing at cipher
     */
    guint16 clear_key_length;
    guint16 encrypted_key_length;
    guint16 key_arg_length;

    /* at this point, everything we do involves the tree,
     * so quit now if we don't have one ;-)
     */
    if (!tree)
    {
        return;
    }

    /* show the selected cipher */
    proto_tree_add_item(tree, hf_ssl2_handshake_cipher_spec,
                        tvb, offset, 3, FALSE);
    offset += 3;

    /* get the fixed fields */
    clear_key_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_clear_key_len,
                        tvb, offset, 2, FALSE);
    offset += 2;

    encrypted_key_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_enc_key_len,
                        tvb, offset, 2, FALSE);
    offset += 2;

    key_arg_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssl2_handshake_key_arg_len,
                        tvb, offset, 2, FALSE);
    offset += 2;

    /* show the variable length fields */
    if (clear_key_length > 0)
    {
        tvb_ensure_bytes_exist(tvb, offset, clear_key_length);
        proto_tree_add_item(tree, hf_ssl2_handshake_clear_key,
                            tvb, offset, clear_key_length, FALSE);
        offset += clear_key_length;
    }

    if (encrypted_key_length > 0)
    {
        tvb_ensure_bytes_exist(tvb, offset, encrypted_key_length);
        proto_tree_add_item(tree, hf_ssl2_handshake_enc_key,
                            tvb, offset, encrypted_key_length, FALSE);
        offset += encrypted_key_length;
    }

    if (key_arg_length > 0)
    {
        tvb_ensure_bytes_exist(tvb, offset, key_arg_length);
        proto_tree_add_item(tree, hf_ssl2_handshake_key_arg,
                            tvb, offset, key_arg_length, FALSE);
        offset += key_arg_length;
    }

}

static void
dissect_ssl2_hnd_server_hello(tvbuff_t *tvb,
                              proto_tree *tree, guint32 offset, packet_info *pinfo)
{
    /* struct {
     *    uint8  msg_type;
     *    uint8  session_id_hit;
     *    uint8  certificate_type;
     *    uint16 server_version;
     *    uint16 certificate_length;
     *    uint16 cipher_specs_length;
     *    uint16 connection_id_length;
     *    opaque certificate_data[V2ServerHello.certificate_length];
     *    opaque cipher_specs_data[V2ServerHello.cipher_specs_length];
     *    opaque connection_id_data[V2ServerHello.connection_id_length];
     * } V2ServerHello;
     *
     * Note: when we get here, offset's already pointing at session_id_hit
     */
    guint16 certificate_length;
    guint16 cipher_spec_length;
    guint16 connection_id_length;
    guint16 version;
    proto_tree *ti;
    proto_tree *subtree;

    /* everything we do only makes sense with a tree, so
     * quit now if we don't have one
     */
    if (!tree)
    {
        return;
    }

    version = tvb_get_ntohs(tvb, offset + 2);
    if (!ssl_is_valid_ssl_version(version))
    {
        /* invalid version; probably encrypted data */
        return;
    }


    /* is there a hit? */
    proto_tree_add_item(tree, hf_ssl2_handshake_session_id_hit,
                        tvb, offset, 1, FALSE);
    offset++;

    /* what type of certificate is this? */
    proto_tree_add_item(tree, hf_ssl2_handshake_cert_type,
                        tvb, offset, 1, FALSE);
    offset++;

    /* now the server version */
    proto_tree_add_item(tree, hf_ssl_handshake_server_version,
                        tvb, offset, 2, FALSE);
    offset += 2;

    /* get the fixed fields */
    certificate_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_ssl_handshake_certificate_len,
                        tvb, offset, 2, certificate_length);
    offset += 2;

    cipher_spec_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_ssl2_handshake_cipher_spec_len,
                        tvb, offset, 2, cipher_spec_length);
    offset += 2;

    connection_id_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_ssl2_handshake_connection_id_len,
                        tvb, offset, 2, connection_id_length);
    offset += 2;

    /* now the variable length fields */
    if (certificate_length > 0)
    {
	dissect_x509af_Certificate(FALSE, tvb, offset, pinfo, tree, hf_ssl_handshake_certificate);
	offset += certificate_length;
    }

    if (cipher_spec_length > 0)
    {
        /* provide a collapsing node for the cipher specs */
        tvb_ensure_bytes_exist(tvb, offset, cipher_spec_length);
        ti = proto_tree_add_none_format(tree,
                                        hf_ssl_handshake_cipher_suites,
                                        tvb, offset, cipher_spec_length,
                                        "Cipher Specs (%u spec%s)",
                                        cipher_spec_length/3,
                                        plurality(cipher_spec_length/3, "", "s"));
        subtree = proto_item_add_subtree(ti, ett_ssl_cipher_suites);
        if (!subtree)
        {
            subtree = tree;
        }

        /* iterate through the cipher specs */
        while (cipher_spec_length > 0)
        {
            proto_tree_add_item(subtree, hf_ssl2_handshake_cipher_spec,
                                tvb, offset, 3, FALSE);
            offset += 3;
            cipher_spec_length -= 3;
        }
    }

    if (connection_id_length > 0)
    {
        tvb_ensure_bytes_exist(tvb, offset, connection_id_length);
        proto_tree_add_item(tree, hf_ssl2_handshake_connection_id,
                            tvb, offset, connection_id_length, FALSE);
        offset += connection_id_length;
    }

}




/*********************************************************************
 *
 * Support Functions
 *
 *********************************************************************/
#if 0
static void
ssl_set_conv_version(packet_info *pinfo, guint version)
{
    conversation_t *conversation;

    if (pinfo->fd->flags.visited)
    {
        /* We've already processed this frame; no need to do any more
         * work on it.
         */
        return;
    }

    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                                     pinfo->srcport, pinfo->destport, 0);

    if (conversation == NULL)
    {
        /* create a new conversation */
        conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                                        pinfo->srcport, pinfo->destport, 0);
    }

    if (conversation_get_proto_data(conversation, proto_ssl) != NULL)
    {
        /* get rid of the current data */
        conversation_delete_proto_data(conversation, proto_ssl);
    }
    conversation_add_proto_data(conversation, proto_ssl, GINT_TO_POINTER(version));
}
#endif

static gint
ssl_is_valid_handshake_type(guint8 type)
{

    switch (type) {
    case SSL_HND_HELLO_REQUEST:
    case SSL_HND_CLIENT_HELLO:
    case SSL_HND_SERVER_HELLO:
    case SSL_HND_CERTIFICATE:
    case SSL_HND_SERVER_KEY_EXCHG:
    case SSL_HND_CERT_REQUEST:
    case SSL_HND_SVR_HELLO_DONE:
    case SSL_HND_CERT_VERIFY:
    case SSL_HND_CLIENT_KEY_EXCHG:
    case SSL_HND_FINISHED:
        return 1;
    }
    return 0;
}

static gint
ssl_is_valid_ssl_version(guint16 version)
{
    const gchar *version_str;
    version_str = match_strval(version, ssl_versions);
    return version_str != NULL;
}

static gint
ssl_is_authoritative_version_message(guint8 content_type,
                                     guint8 next_byte)
{
    if (content_type == SSL_ID_HANDSHAKE
        && ssl_is_valid_handshake_type(next_byte))
    {
        return (next_byte != SSL_HND_CLIENT_HELLO);
    }
    else if (ssl_is_valid_content_type(content_type)
             && content_type != SSL_ID_HANDSHAKE)
    {
        return 1;
    }
    return 0;
}

static gint
ssl_is_v2_client_hello(tvbuff_t *tvb, guint32 offset)
{
    guint8 byte;

    byte = tvb_get_guint8(tvb, offset);
    if (byte != 0x80)           /* v2 client hello should start this way */
    {
        return 0;
    }

    byte = tvb_get_guint8(tvb, offset+2);
    if (byte != 0x01)           /* v2 client hello msg type */
    {
        return 0;
    }

    /* 1 in 2^16 of being right; improve later if necessary */
    return 1;
}

/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid sslv2 record.  this isn't really possible,
 * but we'll try to do a reasonable job anyway.
 */
static gint
ssl_looks_like_sslv2(tvbuff_t *tvb, guint32 offset)
{
    /* here's the current approach:
     *
     * we only try to catch unencrypted handshake messages, so we can
     * assume that there is not padding.  This means that the
     * first byte must be >= 0x80 and there must be a valid sslv2
     * msg_type in the third byte
     */

    /* get the first byte; must have high bit set */
    guint8 byte;
    byte = tvb_get_guint8(tvb, offset);

    if (byte < 0x80)
    {
        return 0;
    }

    /* get the supposed msg_type byte; since we only care about
     * unencrypted handshake messages (we can't tell the type for
     * encrypted messages), we just check against that list
     */
    byte = tvb_get_guint8(tvb, offset + 2);
    switch(byte) {
    case SSL2_HND_ERROR:
    case SSL2_HND_CLIENT_HELLO:
    case SSL2_HND_CLIENT_MASTER_KEY:
    case SSL2_HND_SERVER_HELLO:
    case PCT_MSG_CLIENT_MASTER_KEY:
    case PCT_MSG_ERROR:
        return 1;
    }
    return 0;
}

/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid sslv3 record.  this is somewhat more reliable
 * than sslv2 due to the structure of the v3 protocol
 */
static gint
ssl_looks_like_sslv3(tvbuff_t *tvb, guint32 offset)
{
    /* have to have a valid content type followed by a valid
     * protocol version
     */
    guint8 byte;
    guint16 version;

    /* see if the first byte is a valid content type */
    byte = tvb_get_guint8(tvb, offset);
    if (!ssl_is_valid_content_type(byte))
    {
        return 0;
    }

    /* now check to see if the version byte appears valid */
    version = tvb_get_ntohs(tvb, offset + 1);
    if (version != SSLV3_VERSION && version != TLSV1_VERSION && version != TLSV1DOT1_VERSION)
    {
        return 0;
    }

    return 1;
}

/* applies a heuristic to determine whether
 * or not the data beginning at offset looks
 * like a valid, unencrypted v2 handshake message.
 * since it isn't possible to completely tell random
 * data apart from a valid message without state,
 * we try to help the odds.
 */
static gint
ssl_looks_like_valid_v2_handshake(tvbuff_t *tvb, guint32 offset,
                                  guint32 record_length)
{
    /* first byte should be a msg_type.
     *
     *   - we know we only see client_hello, client_master_key,
     *     and server_hello in the clear, so check to see if
     *     msg_type is one of those (this gives us a 3 in 2^8
     *     chance of saying yes with random payload)
     *
     *   - for those three types that we know about, do some
     *     further validation to reduce the chance of an error
     */
    guint8 msg_type;
    guint16 version;
    guint32 sum;

    /* fetch the msg_type */
    msg_type = tvb_get_guint8(tvb, offset);

    switch (msg_type) {
    case SSL2_HND_CLIENT_HELLO:
        /* version follows msg byte, so verify that this is valid */
        version = tvb_get_ntohs(tvb, offset+1);
        return ssl_is_valid_ssl_version(version);
        break;

    case SSL2_HND_SERVER_HELLO:
        /* version is three bytes after msg_type */
        version = tvb_get_ntohs(tvb, offset+3);
        return ssl_is_valid_ssl_version(version);
        break;

    case SSL2_HND_CLIENT_MASTER_KEY:
        /* sum of clear_key_length, encrypted_key_length, and key_arg_length
         * must be less than record length
         */
        sum  = tvb_get_ntohs(tvb, offset + 4); /* clear_key_length */
        sum += tvb_get_ntohs(tvb, offset + 6); /* encrypted_key_length */
        sum += tvb_get_ntohs(tvb, offset + 8); /* key_arg_length */
        if (sum > record_length)
        {
            return 0;
        }
        return 1;
        break;

    default:
        return 0;
    }
    return 0;
}

/* applies a heuristic to determine whether
 * or not the data beginning at offset looks
 * like a valid, unencrypted v2 handshake message.
 * since it isn't possible to completely tell random
 * data apart from a valid message without state,
 * we try to help the odds.
 */
static gint
ssl_looks_like_valid_pct_handshake(tvbuff_t *tvb, guint32 offset,
				   guint32 record_length)
{
    /* first byte should be a msg_type.
     *
     *   - we know we only see client_hello, client_master_key,
     *     and server_hello in the clear, so check to see if
     *     msg_type is one of those (this gives us a 3 in 2^8
     *     chance of saying yes with random payload)
     *
     *   - for those three types that we know about, do some
     *     further validation to reduce the chance of an error
     */
    guint8 msg_type;
    guint16 version;
    guint32 sum;

    /* fetch the msg_type */
    msg_type = tvb_get_guint8(tvb, offset);

    switch (msg_type) {
    case PCT_MSG_CLIENT_HELLO:
        /* version follows msg byte, so verify that this is valid */
        version = tvb_get_ntohs(tvb, offset+1);
        return version == PCT_VERSION_1;
        break;

    case PCT_MSG_SERVER_HELLO:
        /* version is one byte after msg_type */
        version = tvb_get_ntohs(tvb, offset+2);
        return version == PCT_VERSION_1;
        break;

    case PCT_MSG_CLIENT_MASTER_KEY:
        /* sum of various length fields must be less than record length */
        sum  = tvb_get_ntohs(tvb, offset + 6); /* clear_key_length */
        sum += tvb_get_ntohs(tvb, offset + 8); /* encrypted_key_length */
        sum += tvb_get_ntohs(tvb, offset + 10); /* key_arg_length */
        sum += tvb_get_ntohs(tvb, offset + 12); /* verify_prelude_length */
        sum += tvb_get_ntohs(tvb, offset + 14); /* client_cert_length */
        sum += tvb_get_ntohs(tvb, offset + 16); /* response_length */
        if (sum > record_length)
        {
            return 0;
        }
        return 1;
        break;

    case PCT_MSG_SERVER_VERIFY:
	/* record is 36 bytes longer than response_length */
	sum = tvb_get_ntohs(tvb, offset + 34); /* response_length */
	if ((sum + 36) == record_length)
	    return 1;
	else
	    return 0;
	break;

    default:
        return 0;
    }
    return 0;
}


/*********************************************************************
 *
 * Standard Ethereal Protocol Registration and housekeeping
 *
 *********************************************************************/
void
proto_register_ssl(void)
{

    /* Setup list of header fields See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_ssl_record,
          { "Record Layer", "ssl.record",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Record layer", HFILL }
        },
        { &hf_ssl_record_content_type,
          { "Content Type", "ssl.record.content_type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_content_type), 0x0,
            "Content type", HFILL}
        },
        { &hf_ssl2_msg_type,
          { "Handshake Message Type", "ssl.handshake.type",
            FT_UINT8, BASE_DEC, VALS(ssl_20_msg_types), 0x0,
            "SSLv2 handshake message type", HFILL}
        },
        { &hf_pct_msg_type,
          { "Handshake Message Type", "ssl.pct_handshake.type",
            FT_UINT8, BASE_DEC, VALS(pct_msg_types), 0x0,
            "PCT handshake message type", HFILL}
        },
        { &hf_ssl_record_version,
          { "Version", "ssl.record.version",
            FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
            "Record layer version.", HFILL }
        },
        { &hf_ssl_record_length,
          { "Length", "ssl.record.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of SSL record data", HFILL }
        },
        { &hf_ssl_record_appdata,
          { "Encrypted Application Data", "ssl.app_data",
            FT_BYTES, BASE_HEX, NULL, 0x0,
            "Payload is encrypted application data", HFILL }
        },

        { & hf_ssl2_record,
          { "SSLv2/PCT Record Header", "ssl.record",
            FT_NONE, BASE_DEC, NULL, 0x0,
            "SSLv2/PCT record data", HFILL }
        },
        { &hf_ssl2_record_is_escape,
          { "Is Escape", "ssl.record.is_escape",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Indicates a security escape", HFILL}
        },
        { &hf_ssl2_record_padding_length,
          { "Padding Length", "ssl.record.padding_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of padding at end of record", HFILL }
        },
        { &hf_ssl_change_cipher_spec,
          { "Change Cipher Spec Message", "ssl.change_cipher_spec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Signals a change in cipher specifications", HFILL }
        },
        { & hf_ssl_alert_message,
          { "Alert Message", "ssl.alert_message",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Alert message", HFILL }
        },
        { & hf_ssl_alert_message_level,
          { "Level", "ssl.alert_message.level",
            FT_UINT8, BASE_DEC, VALS(ssl_31_alert_level), 0x0,
            "Alert message level", HFILL }
        },
        { &hf_ssl_alert_message_description,
          { "Description", "ssl.alert_message.desc",
            FT_UINT8, BASE_DEC, VALS(ssl_31_alert_description), 0x0,
            "Alert message description", HFILL }
        },
        { &hf_ssl_handshake_protocol,
          { "Handshake Protocol", "ssl.handshake",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Handshake protocol message", HFILL}
        },
        { &hf_ssl_handshake_type,
          { "Handshake Type", "ssl.handshake.type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_handshake_type), 0x0,
            "Type of handshake message", HFILL}
        },
        { &hf_ssl_handshake_length,
          { "Length", "ssl.handshake.length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of handshake message", HFILL }
        },
        { &hf_ssl_handshake_client_version,
          { "Version", "ssl.handshake.version",
            FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
            "Maximum version supported by client", HFILL }
        },
        { &hf_ssl_handshake_server_version,
          { "Version", "ssl.handshake.version",
            FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
            "Version selected by server", HFILL }
        },
        { &hf_ssl_handshake_random_time,
          { "gmt_unix_time", "ssl.handshake.random_time",
            FT_ABSOLUTE_TIME, 0, NULL, 0x0,
            "Unix time field of random structure", HFILL }
        },
        { &hf_ssl_handshake_random_bytes,
          { "random_bytes", "ssl.handshake.random_bytes",
            FT_BYTES, 0, NULL, 0x0,
            "Random challenge used to authenticate server", HFILL }
        },
        { &hf_ssl_handshake_cipher_suites_len,
          { "Cipher Suites Length", "ssl.handshake.cipher_suites_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of cipher suites field", HFILL }
        },
        { &hf_ssl_handshake_cipher_suites,
          { "Cipher Suites", "ssl.handshake.ciphersuites",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of cipher suites supported by client", HFILL }
        },
        { &hf_ssl_handshake_cipher_suite,
          { "Cipher Suite", "ssl.handshake.ciphersuite",
            FT_UINT16, BASE_HEX, VALS(ssl_31_ciphersuite), 0x0,
            "Cipher suite", HFILL }
        },
        { &hf_ssl2_handshake_cipher_spec,
          { "Cipher Spec", "ssl.handshake.cipherspec",
            FT_UINT24, BASE_HEX, VALS(ssl_20_cipher_suites), 0x0,
            "Cipher specification", HFILL }
        },
        { &hf_ssl_handshake_session_id,
          { "Session ID", "ssl.handshake.session_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Identifies the SSL session, allowing later resumption", HFILL }
        },
        { &hf_ssl_handshake_comp_methods_len,
          { "Compression Methods Length", "ssl.handshake.comp_methods_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of compression methods field", HFILL }
        },
        { &hf_ssl_handshake_comp_methods,
          { "Compression Methods", "ssl.handshake.comp_methods",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of compression methods supported by client", HFILL }
        },
        { &hf_ssl_handshake_comp_method,
          { "Compression Method", "ssl.handshake.comp_method",
            FT_UINT8, BASE_DEC, VALS(ssl_31_compression_method), 0x0,
            "Compression Method", HFILL }
        },
        { &hf_ssl_handshake_extensions_len,
          { "Extensions Length", "ssl.handshake.extensions_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of hello extensions", HFILL }
        },
        { &hf_ssl_handshake_extension_type,
          { "Type", "ssl.handshake.extension.type",
            FT_UINT16, BASE_HEX, VALS(tls_hello_extension_types), 0x0,
            "Hello extension type", HFILL }
        },
        { &hf_ssl_handshake_extension_len,
          { "Length", "ssl.handshake.extension.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of a hello extension", HFILL }
        },
        { &hf_ssl_handshake_extension_data,
          { "Data", "ssl.handshake.extension.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Hello Extension data", HFILL }
        },
        { &hf_ssl_handshake_certificates_len,
          { "Certificates Length", "ssl.handshake.certificates_length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of certificates field", HFILL }
        },
        { &hf_ssl_handshake_certificates,
          { "Certificates", "ssl.handshake.certificates",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of certificates", HFILL }
        },
        { &hf_ssl_handshake_certificate,
          { "Certificate", "ssl.handshake.certificate",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Certificate", HFILL }
        },
        { &hf_ssl_handshake_certificate_len,
          { "Certificate Length", "ssl.handshake.certificate_length",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Length of certificate", HFILL }
        },
        { &hf_ssl_handshake_cert_types_count,
          { "Certificate types count", "ssl.handshake.cert_types_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Count of certificate types", HFILL }
        },
        { &hf_ssl_handshake_cert_types,
          { "Certificate types", "ssl.handshake.cert_types",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of certificate types", HFILL }
        },
        { &hf_ssl_handshake_cert_type,
          { "Certificate type", "ssl.handshake.cert_type",
            FT_UINT8, BASE_DEC, VALS(ssl_31_client_certificate_type), 0x0,
            "Certificate type", HFILL }
        },
        { &hf_ssl_handshake_finished,
          { "Verify Data", "ssl.handshake.verify_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Opaque verification data", HFILL }
        },
        { &hf_ssl_handshake_md5_hash,
          { "MD5 Hash", "ssl.handshake.md5_hash",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Hash of messages, master_secret, etc.", HFILL }
        },
        { &hf_ssl_handshake_sha_hash,
          { "SHA-1 Hash", "ssl.handshake.sha_hash",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Hash of messages, master_secret, etc.", HFILL }
        },
        { &hf_ssl_handshake_session_id_len,
          { "Session ID Length", "ssl.handshake.session_id_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of session ID field", HFILL }
        },
        { &hf_ssl_handshake_dnames_len,
          { "Distinguished Names Length", "ssl.handshake.dnames_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of list of CAs that server trusts", HFILL }
        },
        { &hf_ssl_handshake_dnames,
          { "Distinguished Names", "ssl.handshake.dnames",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "List of CAs that server trusts", HFILL }
        },
        { &hf_ssl_handshake_dname_len,
          { "Distinguished Name Length", "ssl.handshake.dname_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of distinguished name", HFILL }
        },
        { &hf_ssl_handshake_dname,
          { "Distinguished Name", "ssl.handshake.dname",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Distinguished name of a CA that server trusts", HFILL }
        },
        { &hf_ssl2_handshake_challenge,
          { "Challenge", "ssl.handshake.challenge",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Challenge data used to authenticate server", HFILL }
        },
        { &hf_ssl2_handshake_cipher_spec_len,
          { "Cipher Spec Length", "ssl.handshake.cipher_spec_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of cipher specs field", HFILL }
        },
        { &hf_ssl2_handshake_session_id_len,
          { "Session ID Length", "ssl.handshake.session_id_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of session ID field", HFILL }
        },
        { &hf_ssl2_handshake_challenge_len,
          { "Challenge Length", "ssl.handshake.challenge_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of challenge field", HFILL }
        },
        { &hf_ssl2_handshake_clear_key_len,
          { "Clear Key Data Length", "ssl.handshake.clear_key_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of clear key data", HFILL }
        },
        { &hf_ssl2_handshake_enc_key_len,
          { "Encrypted Key Data Length", "ssl.handshake.encrypted_key_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of encrypted key data", HFILL }
        },
        { &hf_ssl2_handshake_key_arg_len,
          { "Key Argument Length", "ssl.handshake.key_arg_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of key argument", HFILL }
        },
        { &hf_ssl2_handshake_clear_key,
          { "Clear Key Data", "ssl.handshake.clear_key_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Clear portion of MASTER-KEY", HFILL }
        },
        { &hf_ssl2_handshake_enc_key,
          { "Encrypted Key", "ssl.handshake.encrypted_key",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Secret portion of MASTER-KEY encrypted to server", HFILL }
        },
        { &hf_ssl2_handshake_key_arg,
          { "Key Argument", "ssl.handshake.key_arg",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Key Argument (e.g., Initialization Vector)", HFILL }
        },
        { &hf_ssl2_handshake_session_id_hit,
          { "Session ID Hit", "ssl.handshake.session_id_hit",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Did the server find the client's Session ID?", HFILL }
        },
        { &hf_ssl2_handshake_cert_type,
          { "Certificate Type", "ssl.handshake.cert_type",
            FT_UINT8, BASE_DEC, VALS(ssl_20_certificate_type), 0x0,
            "Certificate Type", HFILL }
        },
        { &hf_ssl2_handshake_connection_id_len,
          { "Connection ID Length", "ssl.handshake.connection_id_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of connection ID", HFILL }
        },
        { &hf_ssl2_handshake_connection_id,
          { "Connection ID", "ssl.handshake.connection_id",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Server's challenge to client", HFILL }
        },
        { &hf_pct_handshake_cipher_spec,
          { "Cipher Spec", "pct.handshake.cipherspec",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "PCT Cipher specification", HFILL }
        },
        { &hf_pct_handshake_cipher,
          { "Cipher", "pct.handshake.cipher",
                FT_UINT16, BASE_HEX, VALS(pct_cipher_type), 0x0,
                "PCT Ciper", HFILL }
	},
        { &hf_pct_handshake_hash_spec,
          { "Hash Spec", "pct.handshake.hashspec",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "PCT Hash specification", HFILL }
        },
        { &hf_pct_handshake_hash,
          { "Hash", "pct.handshake.hash",
                FT_UINT16, BASE_HEX, VALS(pct_hash_type), 0x0,
                "PCT Hash", HFILL }
        },
        { &hf_pct_handshake_cert_spec,
          { "Cert Spec", "pct.handshake.certspec",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "PCT Certificate specification", HFILL }
        },
        { &hf_pct_handshake_cert,
          { "Cert", "pct.handshake.cert",
                FT_UINT16, BASE_HEX, VALS(pct_cert_type), 0x0,
                "PCT Certificate", HFILL }
        },
        { &hf_pct_handshake_exch_spec,
          { "Exchange Spec", "pct.handshake.exchspec",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "PCT Exchange specification", HFILL }
        },
        { &hf_pct_handshake_exch,
          { "Exchange", "pct.handshake.exch",
                FT_UINT16, BASE_HEX, VALS(pct_exch_type), 0x0,
                "PCT Exchange", HFILL }
        },
        { &hf_pct_handshake_sig,
          { "Sig Spec", "pct.handshake.sig",
                FT_UINT16, BASE_HEX, VALS(pct_sig_type), 0x0,
                "PCT Signature", HFILL }
        },
        { &hf_pct_msg_error_type,
          { "PCT Error Code", "pct.msg_error_code",
                FT_UINT16, BASE_HEX, VALS(pct_error_code), 0x0,
                "PCT Error Code", HFILL }
        },
        { &hf_pct_handshake_server_cert,
          { "Server Cert", "pct.handshake.server_cert",
                FT_NONE, BASE_NONE, NULL , 0x0,
                "PCT Server Certificate", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ssl,
        &ett_ssl_record,
        &ett_ssl_alert,
        &ett_ssl_handshake,
        &ett_ssl_cipher_suites,
        &ett_ssl_comp_methods,
	&ett_ssl_extension,
        &ett_ssl_certs,
        &ett_ssl_cert_types,
        &ett_ssl_dnames,
        &ett_ssl_random,
	&ett_pct_cipher_suites,
	&ett_pct_hash_suites,
	&ett_pct_cert_suites,
	&ett_pct_exch_suites,
    };

    /* Register the protocol name and description */
    proto_ssl = proto_register_protocol("Secure Socket Layer",
                                        "SSL", "ssl");

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_ssl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    {
      module_t *ssl_module = prefs_register_protocol(proto_ssl, proto_reg_handoff_ssl);
      prefs_register_bool_preference(ssl_module,
             "desegment_ssl_records",
             "Reassemble SSL records spanning multiple TCP segments",
             "Whether the SSL dissector should reassemble SSL records spanning multiple TCP segments. "
             "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
             &ssl_desegment);
      prefs_register_bool_preference(ssl_module,
             "desegment_ssl_application_data",
             "Reassemble SSL Application Data spanning multiple SSL records",
             "Whether the SSL dissector should reassemble SSL Application Data spanning multiple SSL records. ",
             &ssl_desegment_app_data);
#ifdef HAVE_LIBGNUTLS
       prefs_register_string_preference(ssl_module, "keys_list", "RSA keys list",
             "semicolon separated list of private RSA keys used for SSL decryption; "
             "each list entry must be in the form of <ip>,<port>,<protocol>,<key_file_name>"
             "<key_file_name>   is the local file name of the RSA private key used by the specified server\n",
             (const gchar **)&ssl_keys_list);
        prefs_register_string_preference(ssl_module, "debug_file", "SSL debug file",
             "redirect ssl debug to file name; leave empty to disable debug, "
             "use \"" SSL_DEBUG_USE_STDERR "\" to redirect output to stderr\n",
             (const gchar **)&ssl_debug_file_name);
#endif
    }

    register_dissector("ssl", dissect_ssl, proto_ssl);
    ssl_handle = find_dissector("ssl");

    ssl_associations = g_tree_new(ssl_association_cmp);

    register_init_routine(ssl_init);
    ssl_lib_init();
    ssl_tap = register_tap("ssl");
    ssl_debug_printf("proto_register_ssl: registered tap %s:%d\n",
        "ssl", ssl_tap);
}

/* If this dissector uses sub-dissector registration add a registration
 * routine.  This format is required because a script is used to find
 * these routines and create the code that calls these routines.
 */
void
proto_reg_handoff_ssl(void)
{

    /* parse key list */
    ssl_parse();

    /* add ssl dissection to defaults ports */
    ssl_dissector_add(443, "http", TRUE);
    ssl_dissector_add(636, "ldap", TRUE);
    ssl_dissector_add(993, "imap", TRUE);
    ssl_dissector_add(995, "pop", TRUE);
}

void
ssl_dissector_add(guint port, const gchar *protocol, gboolean tcp)
{
	SslAssociation *assoc;

	assoc = ssl_association_find(ssl_associations, port, tcp);
	if (assoc) {
		ssl_association_remove(ssl_associations, assoc);
	}

    ssl_association_add(ssl_associations, ssl_handle, port, protocol, tcp, FALSE);
}

void
ssl_dissector_delete(guint port, const gchar *protocol, gboolean tcp)
{
	SslAssociation *assoc;

	assoc = ssl_association_find(ssl_associations, port, tcp);
	if (assoc && (assoc->handle == find_dissector(protocol))) {
		ssl_association_remove(ssl_associations, assoc);
	}
}
