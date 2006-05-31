#define BER_UNI_TAG_TeletexString	    20  /* workaround bug in asn2wrs */

/* packet-pkix1explicit.c
 * Routines for PKIX1Explitic packet dissection
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

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-pkix1explicit.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509ce.h"

#define PNAME  "PKIX1Explitit"
#define PSNAME "PKIX1EXPLICIT"
#define PFNAME "pkix1explicit"

/* Initialize the protocol and registered fields */
static int proto_pkix1explicit = -1;
static int hf_pkix1explicit_object_identifier_id = -1;
#include "packet-pkix1explicit-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkix1explicit-ett.c"


static const char *object_identifier_id;

int
dissect_pkix1explicit_Certificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_Certificate(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_CertificateList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_CertificateList(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_GeneralName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509ce_GeneralName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509if_Name(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_AlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

int
dissect_pkix1explicit_SubjectPublicKeyInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_SubjectPublicKeyInfo(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


#include "packet-pkix1explicit-fn.c"


/*--- proto_register_pkix1explicit ----------------------------------------------*/
void proto_register_pkix1explicit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pkix1explicit_object_identifier_id, 
      { "Id", "pkix1explicit.id", FT_STRING, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
#include "packet-pkix1explicit-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-pkix1explicit-ettarr.c"
  };

  /* Register protocol */
  proto_pkix1explicit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkix1explicit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkix1explicit -------------------------------------------*/
void proto_reg_handoff_pkix1explicit(void) {
#include "packet-pkix1explicit-dis-tab.c"
}

