/* packet-cms.c
 * Routines for RFC2630 Cryptographic Message Syntax packet dissection
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

#define PNAME  "Cryptographic Message Syntax"
#define PSNAME "CMS"
#define PFNAME "cms"

/* Initialize the protocol and registered fields */
int proto_cms = -1;
static int hf_cms_keyAttr_id = -1;
static int hf_cms_ci_contentType = -1;
#include "packet-cms-hf.c"

/* Initialize the subtree pointers */
static gint ett_cms_ContentInfo = -1;
#include "packet-cms-ett.c"

static int dissect_cms_OtherKeyAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index);


#include "packet-cms-fn.c"


static char keyAttr_id[64]; /*64 chars should be long enough? */
static int 
dissect_keyAttrId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset = dissect_ber_object_identifier(FALSE, pinfo, tree, tvb, offset,
                                         hf_cms_keyAttr_id, keyAttr_id);
  return offset;
}

static int 
dissect_keyAttr_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset=call_ber_oid_callback(keyAttr_id, tvb, offset, pinfo, tree);

  return offset;
}

static const ber_sequence OtherKeyAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_keyAttrId },
  { BER_CLASS_ANY, 0, 0, dissect_keyAttr_type },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_OtherKeyAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                OtherKeyAttribute_sequence, hf_index, ett_cms_OtherKeyAttribute);

  return offset;
}

static void
dissect_cms_SignedData_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_cms_SignedData(FALSE, tvb, 0, pinfo, tree, -1);
}

static void
dissect_cms_EnvelopedData_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_cms_EnvelopedData(FALSE, tvb, 0, pinfo, tree, -1);
}

static void
dissect_cms_DigestedData_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_cms_DigestedData(FALSE, tvb, 0, pinfo, tree, -1);
}


static void
dissect_cms_EncryptedData_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_cms_EncryptedData(FALSE, tvb, 0, pinfo, tree, -1);
}

static void
dissect_cms_AuthenticatedData_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_cms_AuthenticatedData(FALSE, tvb, 0, pinfo, tree, -1);
}



/* ContentInfo can not yet be handled by the compiler */
static char ci_contentType[64]; /*64 chars should be long enough? */
static int 
dissect_hf_cms_contentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset = dissect_ber_object_identifier(FALSE, pinfo, tree, tvb, offset,
                                         hf_cms_ci_contentType, ci_contentType);
  return offset;
}
static int 
dissect_hf_cms_contentType_content(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset=call_ber_oid_callback(ci_contentType, tvb, offset, pinfo, tree);

  return offset;
}

static const ber_sequence ContentInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_hf_cms_contentType },
  { BER_CLASS_ANY, 0, 0, dissect_hf_cms_contentType_content },
  { 0, 0, 0, NULL }
};

int
dissect_cms_ContentInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ContentInfo_sequence, hf_index, ett_cms_ContentInfo);

  return offset;
}


/*--- proto_register_cms ----------------------------------------------*/
void proto_register_cms(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cms_ci_contentType,
      { "contentType", "cms.contentInfo.contentType",
        FT_STRING, BASE_NONE, NULL, 0,
        "ContentType", HFILL }},
    { &hf_cms_keyAttr_id,
      { "keyAttr_id", "cms.keyAttr_id",
        FT_STRING, BASE_NONE, NULL, 0,
        "keyAttr_id", HFILL }},
#include "packet-cms-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	&ett_cms_ContentInfo,
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
	register_ber_oid_dissector("1.2.840.113549.1.7.2", dissect_cms_SignedData_callback, proto_cms, "id-signedData");
	register_ber_oid_dissector("1.2.840.113549.1.7.3", dissect_cms_EnvelopedData_callback, proto_cms, "id-envelopedData");
	register_ber_oid_dissector("1.2.840.113549.1.7.5", dissect_cms_DigestedData_callback, proto_cms, "id-digestedData");
	register_ber_oid_dissector("1.2.840.113549.1.7.6", dissect_cms_EncryptedData_callback, proto_cms, "id-encryptedData");
	register_ber_oid_dissector("1.2.840.113549.1.9.16.1.2", dissect_cms_AuthenticatedData_callback, proto_cms, "id-ct-authenticatedData");
}

