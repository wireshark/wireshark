/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-pkix1implicit.c                                                   */
/* ../../tools/asn2eth.py -e -X -b -p pkix1implicit -c pkix1implicit.cnf -s packet-pkix1implicit-template PKIX1IMPLICIT93.asn */

/* Input file: packet-pkix1implicit-template.c */

/* packet-pkix1implicit.c
 * Routines for PKIX1Implitic packet dissection
 *
 * $Id: packet-pkix1implicit-template.c 12203 2004-10-05 09:18:55Z guy $
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
#include "packet-pkix1implicit.h"

#define PNAME  "PKIX1Implitit"
#define PSNAME "PKIX1IMPLICIT"
#define PFNAME "pkix1implicit"

/* Initialize the protocol and registered fields */
static int proto_pkix1implicit = -1;

/*--- Included file: packet-pkix1implicit-hf.c ---*/

static int hf_pkix1implicit_noticeRef = -1;       /* NoticeReference */
static int hf_pkix1implicit_explicitText = -1;    /* DisplayText */
static int hf_pkix1implicit_organization = -1;    /* DisplayText */
static int hf_pkix1implicit_noticeNumbers = -1;   /* SEQUNCE_OF_INTEGER */
static int hf_pkix1implicit_noticeNumbers_item = -1;  /* INTEGER */
static int hf_pkix1implicit_visibleString = -1;   /* VisibleString */
static int hf_pkix1implicit_bmpString = -1;       /* BMPString */
static int hf_pkix1implicit_utf8String = -1;      /* UTF8String */

/*--- End of included file: packet-pkix1implicit-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-pkix1implicit-ett.c ---*/

static gint ett_pkix1implicit_UserNotice = -1;
static gint ett_pkix1implicit_NoticeReference = -1;
static gint ett_pkix1implicit_SEQUNCE_OF_INTEGER = -1;
static gint ett_pkix1implicit_DisplayText = -1;

/*--- End of included file: packet-pkix1implicit-ett.c ---*/




/*--- Included file: packet-pkix1implicit-fn.c ---*/

/*--- Fields for imported types ---*/



static int
dissect_pkix1implicit_VisibleString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}
static int dissect_visibleString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_VisibleString(FALSE, tvb, offset, pinfo, tree, hf_pkix1implicit_visibleString);
}


static int
dissect_pkix1implicit_BMPString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}
static int dissect_bmpString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_BMPString(FALSE, tvb, offset, pinfo, tree, hf_pkix1implicit_bmpString);
}


static int
dissect_pkix1implicit_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}
static int dissect_utf8String(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_UTF8String(FALSE, tvb, offset, pinfo, tree, hf_pkix1implicit_utf8String);
}


static const value_string DisplayText_vals[] = {
  {   0, "visibleString" },
  {   1, "bmpString" },
  {   2, "utf8String" },
  { 0, NULL }
};

static const ber_choice DisplayText_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_visibleString },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_bmpString },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_utf8String },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_pkix1implicit_DisplayText(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              DisplayText_choice, hf_index, ett_pkix1implicit_DisplayText);

  return offset;
}
static int dissect_explicitText(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_DisplayText(FALSE, tvb, offset, pinfo, tree, hf_pkix1implicit_explicitText);
}
static int dissect_organization(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_DisplayText(FALSE, tvb, offset, pinfo, tree, hf_pkix1implicit_organization);
}



static int
dissect_pkix1implicit_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_noticeNumbers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkix1implicit_noticeNumbers_item);
}

static const ber_sequence SEQUNCE_OF_INTEGER_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_noticeNumbers_item },
};

static int
dissect_pkix1implicit_SEQUNCE_OF_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   SEQUNCE_OF_INTEGER_sequence_of, hf_index, ett_pkix1implicit_SEQUNCE_OF_INTEGER);

  return offset;
}
static int dissect_noticeNumbers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_SEQUNCE_OF_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkix1implicit_noticeNumbers);
}

static const ber_sequence NoticeReference_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_organization },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_noticeNumbers },
  { 0, 0, 0, NULL }
};

static int
dissect_pkix1implicit_NoticeReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NoticeReference_sequence, hf_index, ett_pkix1implicit_NoticeReference);

  return offset;
}
static int dissect_noticeRef(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_NoticeReference(FALSE, tvb, offset, pinfo, tree, hf_pkix1implicit_noticeRef);
}

static const ber_sequence UserNotice_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_noticeRef },
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_explicitText },
  { 0, 0, 0, NULL }
};

int
dissect_pkix1implicit_UserNotice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UserNotice_sequence, hf_index, ett_pkix1implicit_UserNotice);

  return offset;
}


/*--- End of included file: packet-pkix1implicit-fn.c ---*/



/*--- proto_register_pkix1implicit ----------------------------------------------*/
void proto_register_pkix1implicit(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkix1implicit-hfarr.c ---*/

    { &hf_pkix1implicit_noticeRef,
      { "noticeRef", "pkix1implicit.noticeRef",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserNotice/noticeRef", HFILL }},
    { &hf_pkix1implicit_explicitText,
      { "explicitText", "pkix1implicit.explicitText",
        FT_UINT32, BASE_DEC, VALS(DisplayText_vals), 0,
        "UserNotice/explicitText", HFILL }},
    { &hf_pkix1implicit_organization,
      { "organization", "pkix1implicit.organization",
        FT_UINT32, BASE_DEC, VALS(DisplayText_vals), 0,
        "NoticeReference/organization", HFILL }},
    { &hf_pkix1implicit_noticeNumbers,
      { "noticeNumbers", "pkix1implicit.noticeNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NoticeReference/noticeNumbers", HFILL }},
    { &hf_pkix1implicit_noticeNumbers_item,
      { "Item", "pkix1implicit.noticeNumbers_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "NoticeReference/noticeNumbers/_item", HFILL }},
    { &hf_pkix1implicit_visibleString,
      { "visibleString", "pkix1implicit.visibleString",
        FT_STRING, BASE_NONE, NULL, 0,
        "DisplayText/visibleString", HFILL }},
    { &hf_pkix1implicit_bmpString,
      { "bmpString", "pkix1implicit.bmpString",
        FT_STRING, BASE_NONE, NULL, 0,
        "DisplayText/bmpString", HFILL }},
    { &hf_pkix1implicit_utf8String,
      { "utf8String", "pkix1implicit.utf8String",
        FT_STRING, BASE_NONE, NULL, 0,
        "DisplayText/utf8String", HFILL }},

/*--- End of included file: packet-pkix1implicit-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkix1implicit-ettarr.c ---*/

    &ett_pkix1implicit_UserNotice,
    &ett_pkix1implicit_NoticeReference,
    &ett_pkix1implicit_SEQUNCE_OF_INTEGER,
    &ett_pkix1implicit_DisplayText,

/*--- End of included file: packet-pkix1implicit-ettarr.c ---*/

  };

  /* Register protocol */
  proto_pkix1implicit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkix1implicit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkix1implicit -------------------------------------------*/
void proto_reg_handoff_pkix1implicit(void) {
}

