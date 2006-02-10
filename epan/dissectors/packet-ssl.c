/* packet-ssl.c
 * Routines for ssl dissection
 * Copyright (c) 2000-2001, Scott Renfro <scott@renfro.org>
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

#include <glib.h>

#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/inet_v6defs.h>
#include <epan/dissectors/packet-x509af.h>
#include <epan/emem.h>
#include <epan/tap.h>
#include "packet-ssl-utils.h"


static gboolean ssl_desegment = TRUE;


/*********************************************************************
 *
 * Protocol Constants, Variables, Data Structures
 *
 *********************************************************************/

/* Initialize the protocol and registered fields */
static int ssl_tap                           = -1;
static int proto_ssl                         = -1;
static int hf_ssl_record                     = -1;
static int hf_ssl_record_content_type        = -1;
static int hf_ssl_record_version             = -1;
static int hf_ssl_record_length              = -1;
static int hf_ssl_record_appdata             = -1;
static int hf_ssl_record_appdata_decrypted   = -1;
static int hf_ssl2_record                    = -1;
static int hf_ssl2_record_is_escape          = -1;
static int hf_ssl2_record_padding_length     = -1;
static int hf_ssl2_msg_type                  = -1;
static int hf_pct_msg_type                   = -1;
static int hf_ssl_change_cipher_spec         = -1;
static int hf_ssl_alert_message              = -1;
static int hf_ssl_alert_message_level        = -1;
static int hf_ssl_alert_message_description  = -1;
static int hf_ssl_handshake_protocol         = -1;
static int hf_ssl_handshake_type             = -1;
static int hf_ssl_handshake_length           = -1;
static int hf_ssl_handshake_client_version   = -1;
static int hf_ssl_handshake_server_version   = -1;
static int hf_ssl_handshake_random_time      = -1;
static int hf_ssl_handshake_random_bytes     = -1;
static int hf_ssl_handshake_cipher_suites_len = -1;
static int hf_ssl_handshake_cipher_suites    = -1;
static int hf_ssl_handshake_cipher_suite     = -1;
static int hf_ssl_handshake_session_id       = -1;
static int hf_ssl_handshake_comp_methods_len = -1;
static int hf_ssl_handshake_comp_methods     = -1;
static int hf_ssl_handshake_comp_method      = -1;
static int hf_ssl_handshake_extensions_len   = -1;
static int hf_ssl_handshake_extension_type   = -1;
static int hf_ssl_handshake_extension_len    = -1;
static int hf_ssl_handshake_extension_data   = -1;
static int hf_ssl_handshake_certificates_len = -1;
static int hf_ssl_handshake_certificates     = -1;
static int hf_ssl_handshake_certificate      = -1;
static int hf_ssl_handshake_certificate_len  = -1;
static int hf_ssl_handshake_cert_types_count = -1;
static int hf_ssl_handshake_cert_types       = -1;
static int hf_ssl_handshake_cert_type        = -1;
static int hf_ssl_handshake_finished         = -1;
static int hf_ssl_handshake_md5_hash         = -1;
static int hf_ssl_handshake_sha_hash         = -1;
static int hf_ssl_handshake_session_id_len   = -1;
static int hf_ssl_handshake_dnames_len       = -1;
static int hf_ssl_handshake_dnames           = -1;
static int hf_ssl_handshake_dname_len        = -1;
static int hf_ssl_handshake_dname            = -1;
static int hf_ssl2_handshake_cipher_spec_len = -1;
static int hf_ssl2_handshake_session_id_len  = -1;
static int hf_ssl2_handshake_challenge_len   = -1;
static int hf_ssl2_handshake_cipher_spec     = -1;
static int hf_ssl2_handshake_challenge       = -1;
static int hf_ssl2_handshake_clear_key_len   = -1;
static int hf_ssl2_handshake_enc_key_len     = -1;
static int hf_ssl2_handshake_key_arg_len     = -1;
static int hf_ssl2_handshake_clear_key       = -1;
static int hf_ssl2_handshake_enc_key         = -1;
static int hf_ssl2_handshake_key_arg         = -1;
static int hf_ssl2_handshake_session_id_hit  = -1;
static int hf_ssl2_handshake_cert_type       = -1;
static int hf_ssl2_handshake_connection_id_len = -1;
static int hf_ssl2_handshake_connection_id   = -1;
static int hf_pct_handshake_cipher_spec	= -1;
static int hf_pct_handshake_hash_spec	= -1;
static int hf_pct_handshake_cert_spec	= -1;
static int hf_pct_handshake_cert	= -1;
static int hf_pct_handshake_server_cert	= -1;
static int hf_pct_handshake_exch_spec	= -1;
static int hf_pct_handshake_hash	= -1;
static int hf_pct_handshake_cipher	= -1;
static int hf_pct_handshake_exch	= -1;
static int hf_pct_handshake_sig		= -1;
static int hf_pct_msg_error_type	= -1;

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
static gint ett_pct_cipher_suites	  = -1;
static gint ett_pct_hash_suites		  = -1;
static gint ett_pct_cert_suites		  = -1;
static gint ett_pct_exch_suites		  = -1;

typedef struct {
    unsigned int ssl_port;
    unsigned int decrypted_port;
    dissector_handle_t handle;
    char* info;
} SslAssociation;

static char* ssl_keys_list = NULL;
static char* ssl_ports_list = NULL;

typedef struct _SslService {
    address addr;
    guint port;
} SslService;

static GHashTable *ssl_session_hash = NULL;
static GHashTable *ssl_key_hash = NULL;
static GTree* ssl_associations = NULL;
static dissector_handle_t ssl_handle = NULL;
static StringInfo ssl_decrypted_data = {NULL, 0};

/* Hash Functions for ssl sessions table and private keys table*/
static gint  
ssl_equal (gconstpointer v, gconstpointer v2)
{
    const StringInfo *val1 = (const StringInfo *)v;
    const StringInfo *val2 = (const StringInfo *)v2;

    if (val1->data_len == val2->data_len &&
            !memcmp(val1->data, val2->data, val2->data_len)) {
        return 1;
    }
    return 0;
}

static guint 
ssl_hash  (gconstpointer v)
{    
    guint l,hash = 0;
    StringInfo* id = (StringInfo*) v;
    guint* cur = (guint*) id->data;
    for (l=4; (l<id->data_len); l+=4, cur++)
        hash = hash ^ (*cur);
        
    return hash;
}

static gint 
ssl_private_key_equal (gconstpointer v, gconstpointer v2)
{
    const SslService *val1 = (const SslService *)v;
    const SslService *val2 = (const SslService *)v2;

    if ((val1->port == val2->port) &&
            ! CMP_ADDRESS(&val1->addr, &val2->addr)) {
        return 1;
    }
    return 0;
}

static guint 
ssl_private_key_hash  (gconstpointer v)
{    
    const SslService *key = (const SslService *)v;
    guint l,hash = key->port, len = key->addr.len;
    
    guint* cur = (guint*) key->addr.data;
    for (l=4; (l<len); l+=4, cur++)
        hash = hash ^ (*cur);
        
    return hash;
}

/* private key table entries have a scope 'larger' then packet capture,
 * so we can't relay on se_alloc** function */
static void 
ssl_private_key_free(gpointer id, gpointer key, gpointer dummy _U_)
{
    g_free(id);
    ssl_free_key((SSL_PRIVATE_KEY*) key);
}

/* handling of association between ssl ports and clear text protocol */
static void 
ssl_association_add(unsigned int port, unsigned int ctport, 
        const char* info)
{
    dissector_table_t tcp_dissectors = find_dissector_table( "tcp.port");
    SslAssociation* assoc = g_malloc(sizeof(SslAssociation)+strlen(info)+1);

    assoc->info = (char*) assoc+sizeof(SslAssociation);
    strcpy(assoc->info, info);
    assoc->ssl_port = port;
    assoc->decrypted_port = ctport;
    assoc->handle = dissector_get_port_handle(tcp_dissectors, ctport);
    
    ssl_debug_printf("ssl_association_add port %d ctport %d info %s handle %p\n",
        port, ctport, info, assoc->handle);

    dissector_add("tcp.port", port, ssl_handle);    
    g_tree_insert(ssl_associations, (gpointer)port, assoc);
}

static gint 
ssl_association_cmp(gconstpointer a, gconstpointer b)
{
    return (gint)a-(gint)b;
}

static inline 
SslAssociation* ssl_association_find(unsigned int port)
{
    register SslAssociation* ret = g_tree_lookup(ssl_associations, (gpointer)port);
    ssl_debug_printf("ssl_association_find: port %d found %p\n", port, ret);
    return ret;
}

static gint 
ssl_association_remove_handle (gpointer key _U_, 
    gpointer  data, gpointer  user_data _U_)
{
    SslAssociation* assoc = (SslAssociation*) data;
    ssl_debug_printf("ssl_association_remove_handle removing ptr %p handle %p\n",
        data, assoc->handle);
    if (assoc->handle)
        dissector_delete("tcp.port", assoc->ssl_port, assoc->handle);
    g_free(data);
    return 0;
}

static inline int ssl_packet_from_server(unsigned int port)
{
    register int ret = ssl_association_find(port) != 0;
    ssl_debug_printf("ssl_packet_from_server: is from server %d\n", ret);    
    return ret;
}    

/* initialize/reset per capture state data (ssl sessions cache) */
static void ssl_init(void)
{
    if (ssl_session_hash)
        g_hash_table_destroy(ssl_session_hash);
    ssl_session_hash = g_hash_table_new(ssl_hash, ssl_equal);
    if (ssl_decrypted_data.data)
        g_free(ssl_decrypted_data.data);
    ssl_decrypted_data.data = g_malloc0(32);
    ssl_decrypted_data.data_len = 32;
}

/* parse ssl related preferences (private keys and ports association strings) */
static void ssl_parse(void)
{
    if (ssl_key_hash)
    {
        g_hash_table_foreach(ssl_key_hash, ssl_private_key_free, NULL);
        g_hash_table_destroy(ssl_key_hash);
    }
    if (ssl_associations)
    {
        g_tree_traverse(ssl_associations, ssl_association_remove_handle, G_IN_ORDER, NULL);
        g_tree_destroy(ssl_associations);
    }

    /* parse private keys string, load available keys and put them in key hash*/
    ssl_key_hash = g_hash_table_new(ssl_private_key_hash,ssl_private_key_equal);
    ssl_associations = g_tree_new(ssl_association_cmp);
    
    if (ssl_keys_list && (ssl_keys_list[0] != 0)) 
    {
        char* end;
        char* start = strdup(ssl_keys_list);
        char* tmp = start;
        
        ssl_debug_printf("ssl_init keys string %s\n", start);
        do {
            char* addr, *port, *filename;
            unsigned char* ip;
            SslService* service;
            SSL_PRIVATE_KEY * private_key;
            FILE* fp;
            
            addr = start;
            /* split ip/file couple with ',' separator*/
            end = strchr(start, ',');
            if (end) {
                *end = 0;
                start = end+1;
            }
            
            /* for each entry split ip, port, filename with ':' separator */
            ssl_debug_printf("ssl_init found host entry %s\n", addr);
            port = strchr(addr, ':');
            if (!port)
            {
                ssl_debug_printf("ssl_init entry malformed can't find port in %s\n", addr);
                break;
            }
            *port = 0;
            port++;
            
            filename = strchr(port,':');
            if (!filename)
            {
                ssl_debug_printf("ssl_init entry malformed can't find filename in %s\n", port);
                break;
            }
            *filename=0;
            filename++;
            
            /* convert ip and port string to network rappresentation*/
            service = g_malloc(sizeof(SslService) + 4);
            service->addr.type = AT_IPv4;
            service->addr.len = 4;
            service->addr.data = ip = ((unsigned char*)service) + sizeof(SslService);
            sscanf(addr, "%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]);
            service->port = atoi(port);
            ssl_debug_printf("ssl_init addr %hhu.%hhu.%hhu.%hhu port %d filename %s\n", 
                ip[0], ip[1], ip[2], ip[3], service->port, filename);
    
            /* try to load pen file*/
            fp = fopen(filename, "rb");
            if (!fp) {
                fprintf(stderr, "can't open file %s \n",filename);
                break;
            }        
            
            private_key = ssl_load_key(fp);
            if (!private_key) {
                fprintf(stderr,"can't load private key from %s\n",
                    filename);
                break;
            }
            fclose(fp);
            
            ssl_debug_printf("ssl_init private key file %s successfully loaded\n", 
                filename);
            g_hash_table_insert(ssl_key_hash, service, private_key);
               
        } while (end != NULL);
        free(tmp);
    }

    /* parse ssl ports string and add ssl dissector to specifed port[s]*/    
    if (ssl_ports_list && (ssl_ports_list[0] != 0)) 
    {
        char* end;
        char* start = strdup(ssl_ports_list);
        char* tmp = start;
        
        ssl_debug_printf("ssl_init ports string %s\n", start);
        do {
            char* port, *ctport, *info;
            unsigned int portn, ctportn;
            
            port = start;
            /* split ip/file couple with ',' separator*/
            end = strchr(start, ',');
            if (end) {
                *end = 0;
                start = end+1;
            }
            
            /* for each entry split ip, port, filename with ':' separator */
            ssl_debug_printf("ssl_init found port entry %s\n", port);
            ctport = strchr(port, ':');
            if (!ctport)
                break;
            *ctport = 0;
            ctport++;
            
            info = strchr(ctport,':');
            if (!info)
                break;
            *info=0;
            info++;
            
            /* add dissector to this port */
            portn = atoi(port);
            ctportn = atoi(ctport);
            if (!portn || !ctportn)
                break;
            
            ssl_debug_printf("ssl_init adding dissector to port %d (ct port %d)\n", portn, ctportn);
            ssl_association_add(portn, ctportn, info);
        } while (end != NULL);
        free(tmp);
    }

    /* [re] add ssl dissection to defaults ports */
    ssl_association_add(443, 80, "Hypertext transfer protocol");
    ssl_association_add(636, 389, "Lightweight directory access protocol");
    ssl_association_add(993, 143, "Interactive mail access protocol");
    ssl_association_add(995, 110, "Post office protocol");    
}

/* store master secret into session data cache */
static void ssl_save_session(SslDecryptSession* ssl)
{
    /* allocate stringinfo chunks for session id and master secret data*/
    StringInfo* session_id = se_alloc0(sizeof(StringInfo) + ssl->session_id.data_len);
    StringInfo* master_secret = se_alloc0(48 + sizeof(StringInfo));
    
    master_secret->data = ((unsigned char*)master_secret+sizeof(StringInfo));
    session_id->data = ((unsigned char*)session_id+sizeof(StringInfo));
    
    ssl_data_set(session_id, ssl->session_id.data, ssl->session_id.data_len);
    ssl_data_set(master_secret, ssl->master_secret.data, ssl->master_secret.data_len);
    g_hash_table_insert(ssl_session_hash, session_id, master_secret);
    ssl_print_string("ssl_save_session stored session id", session_id);
    ssl_print_string("ssl_save_session stored master secret", master_secret);
}

static void ssl_restore_session(SslDecryptSession* ssl)
{
    StringInfo* ms = g_hash_table_lookup(ssl_session_hash, &ssl->session_id);
    if (!ms) {
        ssl_debug_printf("ssl_restore_session can't find stored session\n");
        return;
    }
    ssl_data_set(&ssl->master_secret, ms->data, ms->data_len);
    ssl->state |= SSL_MASTER_SECRET;    
    ssl_debug_printf("ssl_restore_session master key retrived\n");
}

/* The TCP port to associate with by default */
#define TCP_PORT_SSL                    443
#define TCP_PORT_SSL_LDAP               636
#define TCP_PORT_SSL_IMAP               993
#define TCP_PORT_SSL_POP                995

/* version state tables */
#define SSL_VER_UNKNOWN                   0
#define SSL_VER_SSLv2                     1
#define SSL_VER_SSLv3                     2
#define SSL_VER_TLS                       3
#define SSL_VER_PCT                       4

/* corresponds to the #defines above */
static const gchar* ssl_version_short_names[] = {
    "SSL",
    "SSLv2",
    "SSLv3",
    "TLS",
    "PCT"
};

/* other defines */
#define SSL_ID_CHG_CIPHER_SPEC         0x14
#define SSL_ID_ALERT                   0x15
#define SSL_ID_HANDSHAKE               0x16
#define SSL_ID_APP_DATA                0x17

#define SSL_HND_HELLO_REQUEST          0
#define SSL_HND_CLIENT_HELLO           1
#define SSL_HND_SERVER_HELLO           2
#define SSL_HND_CERTIFICATE            11
#define SSL_HND_SERVER_KEY_EXCHG       12
#define SSL_HND_CERT_REQUEST           13
#define SSL_HND_SVR_HELLO_DONE         14
#define SSL_HND_CERT_VERIFY            15
#define SSL_HND_CLIENT_KEY_EXCHG       16
#define SSL_HND_FINISHED               20

#define SSL2_HND_ERROR                 0x00
#define SSL2_HND_CLIENT_HELLO          0x01
#define SSL2_HND_CLIENT_MASTER_KEY     0x02
#define SSL2_HND_CLIENT_FINISHED       0x03
#define SSL2_HND_SERVER_HELLO          0x04
#define SSL2_HND_SERVER_VERIFY         0x05
#define SSL2_HND_SERVER_FINISHED       0x06
#define SSL2_HND_REQUEST_CERTIFICATE   0x07
#define SSL2_HND_CLIENT_CERTIFICATE    0x08

#define PCT_VERSION_1					0x8001

#define PCT_MSG_CLIENT_HELLO			0x01
#define PCT_MSG_SERVER_HELLO			0x02
#define PCT_MSG_CLIENT_MASTER_KEY		0x03
#define PCT_MSG_SERVER_VERIFY			0x04
#define PCT_MSG_ERROR					0x05

#define PCT_CH_OFFSET_V1				0xa

#define PCT_CIPHER_DES					0x01
#define PCT_CIPHER_IDEA					0x02
#define PCT_CIPHER_RC2					0x03
#define PCT_CIPHER_RC4					0x04
#define PCT_CIPHER_DES_112				0x05
#define PCT_CIPHER_DES_168				0x06

#define PCT_HASH_MD5					0x0001
#define PCT_HASH_MD5_TRUNC_64			0x0002
#define PCT_HASH_SHA					0x0003
#define PCT_HASH_SHA_TRUNC_80			0x0004
#define PCT_HASH_DES_DM					0x0005

#define PCT_CERT_NONE					0x00
#define PCT_CERT_X509					0x01
#define PCT_CERT_PKCS7					0x02

#define PCT_SIG_NONE					0x0000
#define PCT_SIG_RSA_MD5					0x0001
#define PCT_SIG_RSA_SHA					0x0002
#define PCT_SIG_DSA_SHA					0x0003

#define PCT_EXCH_RSA_PKCS1				0x01
#define PCT_EXCH_RSA_PKCS1_TOKEN_DES	0x02
#define PCT_EXCH_RSA_PKCS1_TOKEN_DES3	0x03
#define PCT_EXCH_RSA_PKCS1_TOKEN_RC2	0x04
#define PCT_EXCH_RSA_PKCS1_TOKEN_RC4	0x05
#define PCT_EXCH_DH_PKCS3				0x06
#define PCT_EXCH_DH_PKCS3_TOKEN_DES		0x07
#define PCT_EXCH_DH_PKCS3_TOKEN_DES3	0x08
#define PCT_EXCH_FORTEZZA_TOKEN			0x09

#define PCT_ERR_BAD_CERTIFICATE			0x01
#define PCT_ERR_CLIENT_AUTH_FAILED		0x02
#define PCT_ERR_ILLEGAL_MESSAGE			0x03
#define PCT_ERR_INTEGRITY_CHECK_FAILED	0x04
#define PCT_ERR_SERVER_AUTH_FAILED		0x05
#define PCT_ERR_SPECS_MISMATCH			0x06

/*
 * Lookup tables
 *
 */
static const value_string ssl_20_msg_types[] = {
    { SSL2_HND_ERROR,               "Error" },
    { SSL2_HND_CLIENT_HELLO,        "Client Hello" },
    { SSL2_HND_CLIENT_MASTER_KEY,   "Client Master Key" },
    { SSL2_HND_CLIENT_FINISHED,     "Client Finished" },
    { SSL2_HND_SERVER_HELLO,        "Server Hello" },
    { SSL2_HND_SERVER_VERIFY,       "Server Verify" },
    { SSL2_HND_SERVER_FINISHED,     "Server Finished" },
    { SSL2_HND_REQUEST_CERTIFICATE, "Request Certificate" },
    { SSL2_HND_CLIENT_CERTIFICATE,  "Client Certificate" },
    { 0x00, NULL },
};

static const value_string ssl_20_cipher_suites[] = {
    { 0x010080, "SSL2_RC4_128_WITH_MD5" },
    { 0x020080, "SSL2_RC4_128_EXPORT40_WITH_MD5" },
    { 0x030080, "SSL2_RC2_CBC_128_CBC_WITH_MD5" },
    { 0x040080, "SSL2_RC2_CBC_128_CBC_WITH_MD5" },
    { 0x050080, "SSL2_IDEA_128_CBC_WITH_MD5" },
    { 0x060040, "SSL2_DES_64_CBC_WITH_MD5" },
    { 0x0700c0, "SSL2_DES_192_EDE3_CBC_WITH_MD5" },
    { 0x080080, "SSL2_RC4_64_WITH_MD5" },
    { 0x000000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x000001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x000002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x000003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x000004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x000005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x000006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x000007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x000008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x00000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x00000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x000010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x000013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x000016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x000018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x000019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x00001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x00001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
    { 0x00001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
    { 0x00002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x000035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x000041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000047, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x000048, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x000049, "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA" },
    { 0x00004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x000060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x000061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    { 0x000062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    { 0x000084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0x00fefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0x00feff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* Microsoft's old PCT protocol. These are from Eric Rescorla's
       book "SSL and TLS" */
    { 0x8f8001, "PCT_SSL_COMPAT | PCT_VERSION_1" },
    { 0x800003, "PCT_SSL_CERT_TYPE | PCT1_CERT_X509_CHAIN" },
    { 0x800001, "PCT_SSL_CERT_TYPE | PCT1_CERT_X509" },
    { 0x810001, "PCT_SSL_HASH_TYPE | PCT1_HASH_MD5" },
    { 0x810003, "PCT_SSL_HASH_TYPE | PCT1_HASH_SHA" },
    { 0x820001, "PCT_SSL_EXCH_TYPE | PCT1_EXCH_RSA_PKCS1" },
    { 0x830004, "PCT_SSL_CIPHER_TYPE_1ST_HALF | PCT1_CIPHER_RC4" },
    { 0x848040, "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_128 | PCT1_MAC_BITS_128" },
    { 0x842840, "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_40 | PCT1_MAC_BITS_128" },
    /* note that ciphersuites of {0x00????} are TLS cipher suites in
     * a sslv2 client hello message; the ???? above is the two-byte
     * tls cipher suite id
     */
    { 0x00, NULL }
};

static const value_string ssl_20_certificate_type[] = {
    { 0x00, "N/A" },
    { 0x01, "X.509 Certificate" },
    { 0x00, NULL },
};

static const value_string ssl_31_content_type[] = {
    { 20, "Change Cipher Spec" },
    { 21, "Alert" },
    { 22, "Handshake" },
    { 23, "Application Data" },
    { 0x00, NULL }
};

static const value_string ssl_versions[] = {
    { 0x0301, "TLS 1.0" },
    { 0x0300, "SSL 3.0" },
    { 0x0002, "SSL 2.0" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected the body of a Change Cipher Spec
   message. */
static const value_string ssl_31_change_cipher_spec[] = {
    { 1, "Change Cipher Spec" },
    { 0x00, NULL },
};
#endif

static const value_string ssl_31_alert_level[] = {
    { 1, "Warning" },
    { 2, "Fatal" },
    { 0x00, NULL }
};

static const value_string ssl_31_alert_description[] = {
    {  0,  "Close Notify" },
    { 10,  "Unexpected Message" },
    { 20,  "Bad Record MAC" },
    { 21,  "Decryption Failed" },
    { 22,  "Record Overflow" },
    { 30,  "Decompression Failure" },
    { 40,  "Handshake Failure" },
    { 42,  "Bad Certificate" },
    { 43,  "Unsupported Certificate" },
    { 44,  "Certificate Revoked" },
    { 45,  "Certificate Expired" },
    { 46,  "Certificate Unknown" },
    { 47,  "Illegal Parameter" },
    { 48,  "Unknown CA" },
    { 49,  "Access Denied" },
    { 50,  "Decode Error" },
    { 51,  "Decrypt Error" },
    { 60,  "Export Restriction" },
    { 70,  "Protocol Version" },
    { 71,  "Insufficient Security" },
    { 80,  "Internal Error" },
    { 90,  "User Canceled" },
    { 100, "No Renegotiation" },
    { 0x00, NULL }
};

static const value_string ssl_31_handshake_type[] = {
    { SSL_HND_HELLO_REQUEST,     "Hello Request" },
    { SSL_HND_CLIENT_HELLO,      "Client Hello" },
    { SSL_HND_SERVER_HELLO,      "Server Hello" },
    { SSL_HND_CERTIFICATE,       "Certificate" },
    { SSL_HND_SERVER_KEY_EXCHG,  "Server Key Exchange" },
    { SSL_HND_CERT_REQUEST,      "Certificate Request" },
    { SSL_HND_SVR_HELLO_DONE,    "Server Hello Done" },
    { SSL_HND_CERT_VERIFY,       "Certificate Verify" },
    { SSL_HND_CLIENT_KEY_EXCHG,  "Client Key Exchange" },
    { SSL_HND_FINISHED,          "Finished" },
    { 0x00, NULL }
};

static const value_string ssl_31_compression_method[] = {
    { 0, "null" },
    { 1, "ZLIB" },
    { 64, "LZS" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected a Signature, as would be
   seen in a server key exchange or certificate verify message. */
static const value_string ssl_31_key_exchange_algorithm[] = {
    { 0, "RSA" },
    { 1, "Diffie Hellman" },
    { 0x00, NULL }
};

static const value_string ssl_31_signature_algorithm[] = {
    { 0, "Anonymous" },
    { 1, "RSA" },
    { 2, "DSA" },
    { 0x00, NULL }
};
#endif

static const value_string ssl_31_client_certificate_type[] = {
    { 1, "RSA Sign" },
    { 2, "DSS Sign" },
    { 3, "RSA Fixed DH" },
    { 4, "DSS Fixed DH" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected exchange keys, as would be
   seen in a client key exchange message. */
static const value_string ssl_31_public_value_encoding[] = {
    { 0, "Implicit" },
    { 1, "Explicit" },
    { 0x00, NULL }
};
#endif

static const value_string ssl_31_ciphersuite[] = {
    { 0x0000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x0001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x0002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x0004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x0005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x0018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
    { 0x001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
    { 0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0047, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x0048, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x0049, "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA" },
    { 0x004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    { 0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0xfefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0xfeff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites 0xff00 - 0xffff are private */
    { 0x00, NULL }
};

static const value_string pct_msg_types[] = {
    { PCT_MSG_CLIENT_HELLO,         "Client Hello" },
    { PCT_MSG_SERVER_HELLO,         "Server Hello" },
    { PCT_MSG_CLIENT_MASTER_KEY,    "Client Master Key" },
    { PCT_MSG_SERVER_VERIFY,        "Server Verify" },
    { PCT_MSG_ERROR,                "Error" },
    { 0x00, NULL },
};

static const value_string pct_cipher_type[] = {
	{ PCT_CIPHER_DES, "DES" },
	{ PCT_CIPHER_IDEA, "IDEA" },
	{ PCT_CIPHER_RC2, "RC2" },
	{ PCT_CIPHER_RC4, "RC4" },
	{ PCT_CIPHER_DES_112, "DES 112 bit" },
	{ PCT_CIPHER_DES_168, "DES 168 bit" },
	{ 0x00, NULL },
};

static const value_string pct_hash_type[] = {
	{ PCT_HASH_MD5, "MD5" },
	{ PCT_HASH_MD5_TRUNC_64, "MD5_TRUNC_64"},
	{ PCT_HASH_SHA, "SHA"},
	{ PCT_HASH_SHA_TRUNC_80, "SHA_TRUNC_80"},
	{ PCT_HASH_DES_DM, "DES_DM"},
	{ 0x00, NULL },
};

static const value_string pct_cert_type[] = {
	{ PCT_CERT_NONE, "None" },
	{ PCT_CERT_X509, "X.509" },
	{ PCT_CERT_PKCS7, "PKCS #7" },
	{ 0x00, NULL },
};
static const value_string pct_sig_type[]  = {
	{ PCT_SIG_NONE, "None" },
	{ PCT_SIG_RSA_MD5, "MD5" },
	{ PCT_SIG_RSA_SHA, "RSA SHA" },
	{ PCT_SIG_DSA_SHA, "DSA SHA" },
	{ 0x00, NULL },
};

static const value_string pct_exch_type[] = {
	{ PCT_EXCH_RSA_PKCS1, "RSA PKCS#1" },
	{ PCT_EXCH_RSA_PKCS1_TOKEN_DES, "RSA PKCS#1 Token DES" },
	{ PCT_EXCH_RSA_PKCS1_TOKEN_DES3, "RSA PKCS#1 Token 3DES" },	
	{ PCT_EXCH_RSA_PKCS1_TOKEN_RC2, "RSA PKCS#1 Token RC-2" },
	{ PCT_EXCH_RSA_PKCS1_TOKEN_RC4, "RSA PKCS#1 Token RC-4" },
	{ PCT_EXCH_DH_PKCS3, "DH PKCS#3" },
	{ PCT_EXCH_DH_PKCS3_TOKEN_DES, "DH PKCS#3 Token DES" },
	{ PCT_EXCH_DH_PKCS3_TOKEN_DES3, "DH PKCS#3 Token 3DES" },
	{ PCT_EXCH_FORTEZZA_TOKEN, "Fortezza" },
	{ 0x00, NULL },
};

static const value_string pct_error_code[] = {
	{ PCT_ERR_BAD_CERTIFICATE, "PCT_ERR_BAD_CERTIFICATE" },
	{ PCT_ERR_CLIENT_AUTH_FAILED, "PCT_ERR_CLIENT_AUTH_FAILE" },
	{ PCT_ERR_ILLEGAL_MESSAGE, "PCT_ERR_ILLEGAL_MESSAGE" },
	{ PCT_ERR_INTEGRITY_CHECK_FAILED, "PCT_ERR_INTEGRITY_CHECK_FAILED" },
	{ PCT_ERR_SERVER_AUTH_FAILED, "PCT_ERR_SERVER_AUTH_FAILED" },
	{ PCT_ERR_SPECS_MISMATCH, "PCT_ERR_SPECS_MISMATCH" },
	{ 0x00, NULL },
};

/* RFC 3546 */
static const value_string tls_hello_extension_types[] = {
	{ 0, "server_name" },
	{ 1, "max_fragment_length" },
	{ 2, "client_certificate_url" },
	{ 3, "trusted_ca_keys" },
	{ 4, "truncated_hmac" },
	{ 5, "status_request" },
	{ 35, "EAP-FAST PAC-Opaque" /* draft-cam-winget-eap-fast-00.txt */ },
	{ 0, NULL }
};

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
static int dissect_ssl3_record(tvbuff_t *tvb, packet_info *pinfo,
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
static int dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo,
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
static int  ssl_is_valid_handshake_type(guint8 type);
static int  ssl_is_valid_content_type(guint8 type);
static int  ssl_is_valid_ssl_version(guint16 version);
static int  ssl_is_authoritative_version_message(guint8 content_type,
                                                guint8 next_byte);
static int  ssl_is_v2_client_hello(tvbuff_t *tvb, guint32 offset);
static int  ssl_looks_like_sslv2(tvbuff_t *tvb, guint32 offset);
static int  ssl_looks_like_sslv3(tvbuff_t *tvb, guint32 offset);
static int  ssl_looks_like_valid_v2_handshake(tvbuff_t *tvb,
                                              guint32 offset,
                                              guint32 record_length);
static int  ssl_looks_like_valid_pct_handshake(tvbuff_t *tvb,
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
    proto_item *ti         = NULL;
    proto_tree *ssl_tree   = NULL;
    guint32 offset         = 0;
    gboolean first_record_in_frame = TRUE;
    gboolean need_desegmentation;
    SslDecryptSession* ssl_session = NULL;
    guint* conv_version;

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
        if (ssl_packet_from_server(pinfo->srcport)) {
            dummy.addr = pinfo->net_src;
            dummy.port = pinfo->srcport;
        }
        else {
            dummy.addr = pinfo->net_dst;
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

static void 
decrypt_ssl3_record(tvbuff_t *tvb, packet_info *pinfo, guint32 offset, 
        guint32 record_length, guint8 content_type, SslDecryptSession* ssl,
        gboolean save_plaintext)
{
    int len, direction;
    SslDecoder* decoder;
    
    /* if we can decrypt and decryption have success
    * add decrypted data to this packet info*/
    ssl_debug_printf("decrypt_ssl3_record: app_data len %d ssl state %X\n", 
        record_length, ssl->state);
    if (!(ssl->state & SSL_HAVE_SESSION_KEY)) {
        ssl_debug_printf("decrypt_ssl3_record: no session key\n");
        return ;
    }
    
    /* retrive decoder for this packet direction*/    
    if ((direction = ssl_packet_from_server(pinfo->srcport)) != 0) {
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
    len = ssl_decrypted_data.data_len; 
    if ((ssl_decrypt_record(ssl, decoder, 
        content_type, tvb_get_ptr(tvb, offset, record_length),
        record_length,  ssl_decrypted_data.data, &len) == 0) && 
        save_plaintext)
    {
        StringInfo* data = p_get_proto_data(pinfo->fd, proto_ssl);
        if (!data) 
        {
            ssl_debug_printf("decrypt_ssl3_record: allocating app_data %d "
                "bytes for app data\n", len);
            /* first app data record: allocate and put packet data*/
            data = se_alloc(sizeof(StringInfo));
            data->data = se_alloc(len);
            data->data_len = len;
            memcpy(data->data, ssl_decrypted_data.data, len);
        }
        else { 
            unsigned char* store;
            /* update previus record*/
            ssl_debug_printf("decrypt_ssl3_record: reallocating app_data "
                "%d bytes for app data (total %d appdata bytes)\n", 
                len, data->data_len + len);
            store = se_alloc(data->data_len + len);
            memcpy(store, data->data, data->data_len);
            memcpy(&store[data->data_len], ssl_decrypted_data.data, len);
            data->data_len += len;
            
            /* old decrypted data ptr here appare to be leaked, but it's 
             * collected by emem allocator */
            data->data = store;
            
            /* data ptr is changed, so remove old one and re-add the new one*/
            ssl_debug_printf("decrypt_ssl3_record: removing old app_data ptr\n");
            p_remove_proto_data(pinfo->fd, proto_ssl);
        }
     
        ssl_debug_printf("decrypt_ssl3_record: setting decrypted app_data ptr %p\n",data);
        p_add_proto_data(pinfo->fd, proto_ssl, data);
    }
}



/*********************************************************************
 *
 * SSL version 3 and TLS Dissection Routines
 *
 *********************************************************************/
static int
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
    proto_tree *ti              = NULL;
    proto_tree *ssl_record_tree = NULL;
    guint32 available_bytes     = 0;
    StringInfo* decrypted;
    SslAssociation* association;

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
        if (version == 0x0300)
        {
            *conv_version = SSL_VER_SSLv3;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
        else if (version == 0x0301)
        {
            
            *conv_version = SSL_VER_TLS;
            if (ssl) {
                ssl->version_netorder = version;
                ssl->state |= SSL_VERSION;
            }
            /*ssl_set_conv_version(pinfo, ssl->version);*/
        }
    }
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        if (version == 0x0300)
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL,
                        ssl_version_short_names[SSL_VER_SSLv3]);
        }
        else if (version == 0x0301)
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL,
                        ssl_version_short_names[SSL_VER_TLS]);
        }
        else
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL,
                        ssl_version_short_names[*conv_version]);
        }
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
        break;
    case SSL_ID_ALERT:
        if (ssl)
            decrypt_ssl3_record(tvb, pinfo, offset, 
                record_length, content_type, ssl, FALSE);
        dissect_ssl3_alert(tvb, pinfo, ssl_record_tree, offset,
                           conv_version);
        break;
    case SSL_ID_HANDSHAKE:
        if (ssl)
            decrypt_ssl3_record(tvb, pinfo, offset, 
                record_length, content_type, ssl, FALSE);
        dissect_ssl3_handshake(tvb, pinfo, ssl_record_tree, offset,
                               record_length, conv_version, ssl, content_type);
        break;
    case SSL_ID_APP_DATA:
        if (ssl)
            decrypt_ssl3_record(tvb, pinfo, offset, 
                record_length, content_type, ssl, TRUE);
        
        /* show on info colum what we are decoding */
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO, "Application Data");
                
        if (!ssl_record_tree)
            break;
        
        /* we need dissector information when the selected packet is shown.
         * ssl session pointer is NULL at that time, so we can't access
         * info cached there*/         
        association = ssl_association_find(pinfo->srcport);
        association = association ? association: ssl_association_find(pinfo->destport);

        proto_item_set_text(ssl_record_tree,
            "%s Record Layer: %s Protocol: %s",
            ssl_version_short_names[*conv_version],
            val_to_str(content_type, ssl_31_content_type, "unknown"),
            association?association->info:"Application Data");
     
        /* show decrypted data info, if available */         
        decrypted = p_get_proto_data(pinfo->fd, proto_ssl);
        if (decrypted)
        {
            tvbuff_t* new_tvb;
            
            /* try to dissect decrypted data*/
            ssl_debug_printf("dissect_ssl3_record decrypted len %d\n", decrypted->data_len);
            
             /* create new tvbuff for the decrypted data */
            new_tvb = tvb_new_real_data(decrypted->data, 
                decrypted->data_len, decrypted->data_len);
            tvb_set_free_cb(new_tvb, g_free);
            /* tvb_set_child_real_data_tvbuff(tvb, new_tvb); */
            
            /* find out a dissector using server port*/
            if (association && association->handle) {
                ssl_debug_printf("dissect_ssl3_record found association %p\n", association);
                ssl_print_text_data("decrypted app data",decrypted->data, 
                    decrypted->data_len);
                
                call_dissector(association->handle, new_tvb, pinfo, ssl_record_tree);
            }
            /* add raw decrypted data only if a decoder is not found*/
            else 
                proto_tree_add_string(ssl_record_tree, hf_ssl_record_appdata_decrypted, tvb,
                        offset, decrypted->data_len, (char*) decrypted->data);
        }
        else {
            tvb_ensure_bytes_exist(tvb, offset, record_length);
            proto_tree_add_item(ssl_record_tree, hf_ssl_record_appdata, tvb,
                       offset, record_length, 0);
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
    proto_tree *ssl_alert_tree = NULL;
    const gchar *level;
    const gchar *desc;
    guint8 byte;

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
    proto_tree *ti            = NULL;
    proto_tree *ssl_hand_tree = NULL;
    const gchar *msg_type_str = NULL;
    guint8 msg_type;
    guint32 length;
    gboolean first_iteration  = TRUE;


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
                    int ret;
                    unsigned encrlen = length, skip = 0;
    
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
                                
                    /* get encrypted data, on tls1 we have to byte to skip
                     * (it's the encrypted len and should be equal to record len - 2) 
                     */
                    if (ssl->version == SSL_VER_TLS)
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
                    ssl_save_session(ssl);
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

static int
dissect_ssl3_hnd_hello_common(tvbuff_t *tvb, proto_tree *tree,
                              guint32 offset, SslDecryptSession* ssl, gint from_server)
{
    /* show the client's random challenge */
    nstime_t gmt_unix_time;
    guint8  session_id_length = 0;

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
            ssl_restore_session(ssl); 
        }
        else {
            /* reset state on renegotiation*/
            if (!from_server)
                ssl->state &= ~(SSL_HAVE_SESSION_KEY|SSL_MASTER_SECRET|
                    SSL_CIPHER|SSL_SERVER_RANDOM);
            
            tvb_memcpy(tvb,ssl->session_id.data, offset+33, session_id_length);
            ssl->session_id.data_len = session_id_length;
        }                
    }
     
    if (tree)
    {
        /* show the time */
        gmt_unix_time.secs = tvb_get_ntohl(tvb, offset);
        gmt_unix_time.nsecs = 0;
        proto_tree_add_time(tree, hf_ssl_handshake_random_time,
                                     tvb, offset, 4, &gmt_unix_time);
        offset += 4;

        /* show the random bytes */
        proto_tree_add_item(tree, hf_ssl_handshake_random_bytes,
                            tvb, offset, 28, 0);
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

static int
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
    guint16 cipher_suite_length = 0;
    guint8  compression_methods_length = 0;
    guint8  compression_method;
    guint16 start_offset = offset;

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
    guint16 start_offset = offset;

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
                guint32 cert_length = tvb_get_ntoh24(tvb, offset);
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
    guint8      cert_types_count = 0;
    int         dnames_length = 0;

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
                guint16 name_length = tvb_get_ntohs(tvb, offset);
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
static int
dissect_ssl2_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint32 offset, guint* conv_version,
                    gboolean *need_desegmentation,
                    SslDecryptSession* ssl)
{
    guint32 initial_offset       = offset;
    guint8  byte                 = 0;
    guint8  record_length_length = 0;
    guint32 record_length        = 0;
    gint    is_escape            = -1;
    gint16  padding_length       = -1;
    guint8  msg_type             = 0;
    const gchar *msg_type_str    = NULL;
    guint32 available_bytes      = 0;

    proto_tree *ti;
    proto_tree *ssl_record_tree = NULL;

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
    proto_tree *cs_tree=0;

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
                int max = challenge_length > 32? 32: challenge_length;
                
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

static int
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

static int
ssl_is_valid_content_type(guint8 type)
{
    if (type >= 0x14 && type <= 0x17)
    {
        return 1;
    }

    return 0;
}

static int
ssl_is_valid_ssl_version(guint16 version)
{
    const gchar *version_str = match_strval(version, ssl_versions);
    return version_str != NULL;
}

static int
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

static int
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
static int
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
    guint8 byte = tvb_get_guint8(tvb, offset);
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
static int
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
    if (version != 0x0300 && version != 0x0301)
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
static int
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
static int
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
          { "Application Data", "ssl.app_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Payload is application data", HFILL }
        },
        { &hf_ssl_record_appdata_decrypted,
          { "Application Data decrypted", "ssl.app_data_decrypted",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Payload is decrypted application data", HFILL }
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
          { "Random.gmt_unix_time", "ssl.handshake.random_time",
            FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
            "Unix time field of random structure", HFILL }
        },
        { &hf_ssl_handshake_random_bytes,
          { "Random.bytes", "ssl.handshake.random",
            FT_NONE, BASE_NONE, NULL, 0x0,
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
      module_t *ssl_module = prefs_register_protocol(proto_ssl, ssl_parse);
      prefs_register_bool_preference(ssl_module,
             "desegment_ssl_records",
             "Reassemble SSL records spanning multiple TCP segments",
             "Whether the SSL dissector should reassemble SSL records spanning multiple TCP segments. "
             "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
             &ssl_desegment);
       prefs_register_string_preference(ssl_module, "keys_list", "RSA keys list",
             "comma separated list of private RSA keys used for SSL decryption; "
             "each list entry must be in the form of <ip>:<port>:<key_file_name>"
             "<key_file_name>   is the local file name of the RSA private key used by the specified server\n",
             (const char **)&ssl_keys_list);
        prefs_register_string_preference(ssl_module, "ports_list", "SSL ports list",
             "comma separated list of tcp ports numbers to be dissectes as SSL; "
             "each list entry must be in the form of <port>:<clear-text-port>"
             "<clear-text-port>   is the port numbert associated with the protocol tunneled over SSL for this port\n",
             (const char **)&ssl_ports_list);
    }

    register_dissector("ssl", dissect_ssl, proto_ssl);
    
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
    ssl_handle = find_dissector("ssl");
    
    /* add now dissector to default ports.*/
    ssl_parse();
}
