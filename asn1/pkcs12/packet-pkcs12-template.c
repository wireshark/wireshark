/* packet-pkcs12.c
 * Routines for PKCS#12: Personal Information Exchange packet dissection
 * Graeme Lunt 2006
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
#include <epan/oid_resolv.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-pkcs12.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-cms.h"

#define PNAME  "PKCS#12: Personal Information Exchange"
#define PSNAME "PKCS12"
#define PFNAME "pkcs12"

/* Initialize the protocol and registered fields */
int proto_pkcs12 = -1;

static const char *object_identifier_id = NULL; 
static const gchar *pref_password = NULL;


static void dissect_AuthenticatedSafe_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_SafeContents_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#include "packet-pkcs12-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkcs12-ett.c"

#include "packet-pkcs12-fn.c"

static int strip_octet_string(tvbuff_t *tvb, proto_tree *tree) 
{
  gint8 class;
  gboolean pc, ind;
  gint32 tag;
  guint32 len;
  int offset = 0;

  /* PKCS#7 encodes the content as OCTET STRING, whereas CMS is just any ANY */
  /* if we use CMS (rather than PKCS#7) - which we are - we need to strip the OCTET STRING tag */
  /* before proceeding */

  offset = get_ber_identifier(tvb, 0, &class, &pc, &tag);
  offset = get_ber_length(NULL, tvb, offset, &len, &ind);

  if((class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_OCTETSTRING))
    return offset;

  proto_tree_add_text(tree, tvb, 0, 1, "BER Error: OCTET STRING expected");

  return 0;

}

static void dissect_AuthenticatedSafe_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset = 0;

  if((offset = strip_octet_string(tvb, tree)) > 0)
    dissect_pkcs12_AuthenticatedSafe(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_AuthenticatedSafe_PDU);
}

static void dissect_SafeContents_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
  int offset = 0;

  if((offset = strip_octet_string(tvb, tree)) > 0)
    dissect_pkcs12_SafeContents(FALSE, tvb, offset, pinfo, tree, hf_pkcs12_SafeContents_PDU);
}

#if 0 
static int decrypt_data(tvbuff_t *encrypted_data, 
			/* enc_params */
			gnu_tls_ciper_algorithm cipher,
			int iter_count,
			/* kdf_params */
			gnutls_datum_t *salt, size_t salt_size,
			gnutls_datum_t *iv, size_t iv_size,
			size_t key_size, 
			tvb_buff_t **decrypted_data)
{


  

  if(key_size == 0) 
    key_size = gnutls_cipher_get_key_size(cipher);


}
			
# endif /* 0 */

/*--- proto_register_pkcs12 ----------------------------------------------*/
void proto_register_pkcs12(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-pkcs12-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-pkcs12-ettarr.c"
  };

  /* Register protocol */
  proto_pkcs12 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkcs12, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_ber_syntax_dissector("PKCS#12", proto_pkcs12, dissect_PFX_PDU); 
  register_ber_oid_syntax(".p12", NULL, "PKCS#12");
  register_ber_oid_syntax(".pfx", NULL, "PKCS#12");
}


/*--- proto_reg_handoff_pkcs12 -------------------------------------------*/
void proto_reg_handoff_pkcs12(void) {
#include "packet-pkcs12-dis-tab.c"

}

