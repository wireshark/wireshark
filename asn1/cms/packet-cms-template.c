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
static int hf_cms_eci_eContentType = -1;
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


/* Do the same thing for EncapsulatedContentInfo */
static char eci_eContentType[64]; /*64 chars should be long enough? */
static int
dissect_hf_cms_eContentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
  offset = dissect_ber_object_identifier(FALSE, pinfo, tree, tvb, offset,
                                         hf_cms_eci_eContentType, eci_eContentType);
  return offset;
}
static int
dissect_hf_cms_eContentType_content(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
  guint8 class;
  gboolean pc, ind;
  guint32 tag, len;
  int pdu_offset = offset;

  /* XXX Do we care about printing out the octet string? */
  offset = dissect_cms_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cms_eContent);

  pdu_offset = get_ber_identifier(tvb, pdu_offset, &class, &pc, &tag);
  pdu_offset = get_ber_length(tvb, pdu_offset, &len, &ind);
  pdu_offset = call_ber_oid_callback(eci_eContentType, tvb, pdu_offset, pinfo, tree);

  return offset;
}

static const ber_sequence EncapsulatedContentInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_hf_cms_eContentType },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_hf_cms_eContentType_content },
  { 0, 0, 0, NULL }
};

int
dissect_cms_EncapsulatedContentInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                EncapsulatedContentInfo_sequence, hf_index, ett_cms_EncapsulatedContentInfo);

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
    { &hf_cms_eci_eContentType,
      { "eContentType", "cms.encapContentInfo.eContentType",
        FT_STRING, BASE_NONE, NULL, 0,
        "EncapsulatedContentType", HFILL }},
    { &hf_cms_keyAttr_id,
      { "keyAttr_id", "cms.keyAttr_id",
        FT_STRING, BASE_NONE, NULL, 0,
        "keyAttr_id", HFILL }},
#include "packet-cms-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	&ett_cms_ContentInfo,
	&ett_cms_EncapsulatedContentInfo,
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

