/* packet-x509if.c
 * Routines for X.509 Information Framework packet dissection
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
#include "packet-x509if.h"

#define PNAME  "X.509 Information Framework"
#define PSNAME "X509IF"
#define PFNAME "x509if"

/* Initialize the protocol and registered fields */
int proto_x509if = -1;
int hf_x509if_ATADV_attribute_id = -1;
#include "packet-x509if-hf.c"

/* Initialize the subtree pointers */
static gint ett_x509if_Attribute = -1;
#include "packet-x509if-ett.c"


static const ber_sequence Attribute_sequence[] = {
  /*  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_hf_x509if_type },*/
  /*XXX  missing stuff here */
  { 0, 0, 0, NULL }
};

int
dissect_x509if_Attribute(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Attribute_sequence, hf_index, ett_x509if_Attribute);

  return offset;
}



static char ATADV_attribute_id[64]; /*64 chars should be long enough? */
static int 
dissect_hf_x509if_ATADV_attribute_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset = dissect_ber_object_identifier(FALSE, pinfo, tree, tvb, offset,
                                         hf_x509if_ATADV_attribute_id, ATADV_attribute_id);
  return offset;
}
static int 
dissect_hf_x509if_ATADV_attribute_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset=call_ber_oid_callback(ATADV_attribute_id, tvb, offset, pinfo, tree);
  return offset;
}

static const ber_sequence AttributeTypeAndDistinguishedValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_hf_x509if_ATADV_attribute_id },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_hf_x509if_ATADV_attribute_value },
  /*XXX  missing stuff here */
  { 0, 0, 0, NULL }
};

static int
dissect_x509if_AttributeTypeAndDistinguishedValue(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AttributeTypeAndDistinguishedValue_sequence, hf_index, ett_x509if_AttributeTypeAndDistinguishedValue);

  return offset;
}

#include "packet-x509if-fn.c"


/*--- proto_register_x509if ----------------------------------------------*/
void proto_register_x509if(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509if_ATADV_attribute_id,
      { "Attribute Id", "x509if.attribute.id",
        FT_STRING, BASE_NONE, NULL, 0,
        "Attribute Id", HFILL }},
#include "packet-x509if-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x509if_Attribute,
#include "packet-x509if-ettarr.c"
  };

  /* Register protocol */
  proto_x509if = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509if, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509if -------------------------------------------*/
void proto_reg_handoff_x509if(void) {
}

