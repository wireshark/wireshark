/* packet-x509af.c
 * Routines for X.509 Authentication Framework packet dissection
 *
 * $Id: packet-x509af-template.c,v 1.2 2004/05/25 21:07:43 guy Exp $
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
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#define PNAME  "X.509 Authentication Framework"
#define PSNAME "X509AF"
#define PFNAME "x509af"

/* Initialize the protocol and registered fields */
static int proto_x509af = -1;
static int hf_x509af_algorithm_id = -1;
static int hf_x509af_extension_id = -1;
static int hf_x509af_critical = -1;               /* BOOLEAN */
static int hf_x509af_id_at_userCertificate = -1;
static int hf_x509af_id_at_cAcertificate = -1;
#include "packet-x509af-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509af-ett.c"


static char extension_id[64]; /*64 chars should be long enough? */
static int 
dissect_hf_x509af_extension_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset = dissect_ber_object_identifier(FALSE, pinfo, tree, tvb, offset,
                                         hf_x509af_extension_id, extension_id);
  return offset;
}
/* BOOLEAN from template, remove later if the compiler starts generating it */
static int
dissect_x509af_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_boolean(pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_critical(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509af_critical);
}

static int 
dissect_hf_x509af_extension_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset=call_ber_oid_callback(extension_id, tvb, offset, pinfo, tree);

  return offset;
}

static ber_sequence Extension_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_hf_x509af_extension_id },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_critical },
  { BER_CLASS_ANY, 0, 0, dissect_hf_x509af_extension_type },
  { 0, 0, 0, NULL }
};

static int
dissect_x509af_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Extension_sequence, hf_index, ett_x509af_Extension);

  return offset;
}

static char algorithm_id[64]; /*64 chars should be long enough? */
static int 
dissect_hf_x509af_algorithm_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset = dissect_ber_object_identifier(FALSE, pinfo, tree, tvb, offset,
                                         hf_x509af_algorithm_id, algorithm_id);
  return offset;
}

static int 
dissect_hf_x509af_algorithm_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset=call_ber_oid_callback(algorithm_id, tvb, offset, pinfo, tree);

  return offset;
}

/* Algorithm Identifier can not yet be handled by the compiler */
static ber_sequence AlgorithmIdentifier_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_hf_x509af_algorithm_id },
  { BER_CLASS_ANY, 0, 0, dissect_hf_x509af_algorithm_type },
  { 0, 0, 0, NULL }
};

int
dissect_x509af_AlgorithmIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AlgorithmIdentifier_sequence, hf_index, ett_x509af_AlgorithmIdentifier);

  return offset;
}

#include "packet-x509af-fn.c"


static void
dissect_x509af_userCertificate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509af_Certificate(FALSE, tvb, 0, pinfo, tree, hf_x509af_id_at_userCertificate);
}

static void
dissect_x509af_cAcertificate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509af_Certificate(FALSE, tvb, 0, pinfo, tree, hf_x509af_id_at_cAcertificate);
}

/*--- proto_register_x509af ----------------------------------------------*/
void proto_register_x509af(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509af_id_at_userCertificate,
      { "userCertificate", "x509af.id_at_userCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "id-at-userCertificate", HFILL }},
    { &hf_x509af_id_at_cAcertificate,
      { "cAcertificate", "x509af.id_at_cAcertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "id-at-cAcertificate", HFILL }},
    { &hf_x509af_algorithm_id,
      { "Algorithm Id", "x509af.algorithm.id",
        FT_STRING, BASE_NONE, NULL, 0,
        "Algorithm Id", HFILL }},
    { &hf_x509af_extension_id,
      { "Extension Id", "x509af.extension.id",
        FT_STRING, BASE_NONE, NULL, 0,
        "Extension Id", HFILL }},
    { &hf_x509af_critical,
      { "critical", "x509af.critical",
        FT_BOOLEAN, 8, NULL, 0,
        "Extension/critical", HFILL }},
#include "packet-x509af-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-x509af-ettarr.c"
  };

  /* Register protocol */
  proto_x509af = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509af, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509af -------------------------------------------*/
void proto_reg_handoff_x509af(void) {
	register_ber_oid_dissector("2.5.4.36", dissect_x509af_userCertificate_callback, proto_x509af, "id-at-userCertificate");
	register_ber_oid_dissector("2.5.4.37", dissect_x509af_cAcertificate_callback, proto_x509af, "id-at-cAcertificate");
}

