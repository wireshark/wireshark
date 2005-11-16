/* packet-cms.c
 * Routines for RFC2630 Cryptographic Message Syntax packet dissection
 *   Ronnie Sahlberg 2004
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-cms.h"
#include "packet-x509af.h"
#include "packet-x509if.h"

#include <epan/sha1.h>
#include <epan/crypt-md5.h>

#define PNAME  "Cryptographic Message Syntax"
#define PSNAME "CMS"
#define PFNAME "cms"

/* Initialize the protocol and registered fields */
int proto_cms = -1;
static int hf_cms_ci_contentType = -1;
#include "packet-cms-hf.c"

/* Initialize the subtree pointers */
#include "packet-cms-ett.c"

static int dissect_cms_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) ; /* XXX kill a compiler warning until asn2eth stops generating these silly wrappers */


static const char *object_identifier_id;
static tvbuff_t *content_tvb = NULL;

static proto_tree *top_tree=NULL;

#define HASH_SHA1 "1.3.14.3.2.26"
#define SHA1_BUFFER_SIZE  20

#define HASH_MD5 "1.2.840.113549.2.5"
#define MD5_BUFFER_SIZE  16


/* SHA-2 variants */
#define HASH_SHA224 "2.16.840.1.101.3.4.2.4"
#define SHA224_BUFFER_SIZE  32 /* actually 28 */
#define HASH_SHA256 "2.16.840.1.101.3.4.2.1"
#define SHA256_BUFFER_SIZE  32

unsigned char digest_buf[MAX(SHA1_BUFFER_SIZE, MD5_BUFFER_SIZE)];

static void
cms_verify_msg_digest(proto_item *pi, tvbuff_t *content, char *alg, tvbuff_t *tvb, int offset)
{
  sha1_context sha1_ctx;
  md5_state_t md5_ctx;
  int i= 0, buffer_size = 0;

  /* we only support two algorithms at the moment  - if we do add SHA2
     we should add a registration process to use a registration process */

  if(strcmp(alg, HASH_SHA1) == 0) {

    sha1_starts(&sha1_ctx);

    sha1_update(&sha1_ctx, 
		(guint8*)tvb_get_ptr(content, 0, tvb_length(content)), 
		tvb_length(content));

    sha1_finish(&sha1_ctx, digest_buf);

    buffer_size = SHA1_BUFFER_SIZE;

  } else if(strcmp(alg, HASH_MD5) == 0) {

    md5_init(&md5_ctx);

    md5_append(&md5_ctx, 
	       (const guint8*) tvb_get_ptr(content, 0, tvb_length(content)), 
	       tvb_length(content));
    
    md5_finish(&md5_ctx, digest_buf);

    buffer_size = MD5_BUFFER_SIZE;
  }

  if(buffer_size) {
    /* compare our computed hash with what we have received */  

    if(tvb_bytes_exist(tvb, offset, buffer_size) &&
       (memcmp(tvb_get_ptr(tvb, offset, buffer_size), digest_buf, buffer_size) != 0)) { 
      proto_item_append_text(pi, " [incorrect, should be ");
      for(i = 0; i < buffer_size; i++)
	proto_item_append_text(pi, "%02X", digest_buf[i]);

      proto_item_append_text(pi, "]");
    }
    else
      proto_item_append_text(pi, " [correct]");
  } else {
    proto_item_append_text(pi, " [unable to verify]");
  }

}

#include "packet-cms-fn.c"

/*--- proto_register_cms ----------------------------------------------*/
void proto_register_cms(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cms_ci_contentType,
      { "contentType", "cms.contentInfo.contentType",
        FT_STRING, BASE_NONE, NULL, 0,
        "ContentType", HFILL }},
#include "packet-cms-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-cms-ettarr.c"
  };

  /* Register protocol */
  proto_cms = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cms, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_cms -------------------------------------------*/
void proto_reg_handoff_cms(void) {
#include "packet-cms-dis-tab.c"
}

