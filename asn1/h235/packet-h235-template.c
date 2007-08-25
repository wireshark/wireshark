/* packet-h235.c
 * Routines for H.235 packet dissection
 * 2004  Tomas Kukosa
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
#include <epan/oids.h>
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include "packet-per.h"
#include "packet-h235.h"
#include "packet-h225.h"

#define PNAME  "H235-SECURITY-MESSAGES"
#define PSNAME "H.235"
#define PFNAME "h235"

#define OID_MIKEY         "0.0.8.235.0.3.76"
#define OID_MIKEY_PS      "0.0.8.235.0.3.72"
#define OID_MIKEY_DHHMAC  "0.0.8.235.0.3.73"
#define OID_MIKEY_PK_SIGN "0.0.8.235.0.3.74"
#define OID_MIKEY_DH_SIGN "0.0.8.235.0.3.75"
#define OID_TG            "0.0.8.235.0.3.70"
#define OID_SG            "0.0.8.235.0.3.71"

/* Initialize the protocol and registered fields */
int proto_h235 = -1;
#include "packet-h235-hf.c"

/* Initialize the subtree pointers */
#include "packet-h235-ett.c"

static dissector_handle_t mikey_handle=NULL;

static int
dissect_xxx_ToBeSigned(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
PER_NOT_DECODED_YET("ToBeSigned");
  return offset;
}

#include "packet-h235-fn.c"


/*--- proto_register_h235 ----------------------------------------------*/
void proto_register_h235(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h235-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-h235-ettarr.c"
  };

  /* Register protocol */
  proto_h235 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h235, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* OID names */
  /* H.235.1, Chapter 15, Table 3 */
    /* A */
    add_oid_str_name("0.0.8.235.0.1.1", "itu-t(0) recommendation(0) h(8) 235 version(0) 1 1 - all fields in RAS/CS");
    add_oid_str_name("0.0.8.235.0.2.1", "itu-t(0) recommendation(0) h(8) 235 version(0) 2 1 - all fields in RAS/CS");
    /* T */
    add_oid_str_name("0.0.8.235.0.1.5", "itu-t(0) recommendation(0) h(8) 235 version(0) 1 5 - ClearToken");
    add_oid_str_name("0.0.8.235.0.2.5", "itu-t(0) recommendation(0) h(8) 235 version(0) 2 5 - ClearToken");
    /* U */
    add_oid_str_name("0.0.8.235.0.1.6", "itu-t(0) recommendation(0) h(8) 235 version(0) 1 6 - HMAC-SHA1-96");
    add_oid_str_name("0.0.8.235.0.2.6", "itu-t(0) recommendation(0) h(8) 235 version(0) 2 6 - HMAC-SHA1-96");
  /* H.235.7, Chapter 5, Table 1 */
    add_oid_str_name(OID_MIKEY,         "itu-t(0) recommendation(0) h(8) 235 version(0) 3 76 - MIKEY");
    add_oid_str_name(OID_MIKEY_PS,      "itu-t(0) recommendation(0) h(8) 235 version(0) 3 72 - MIKEY-PS");
    add_oid_str_name(OID_MIKEY_DHHMAC,  "itu-t(0) recommendation(0) h(8) 235 version(0) 3 73 - MIKEY-DHHMAC");
    add_oid_str_name(OID_MIKEY_PK_SIGN, "itu-t(0) recommendation(0) h(8) 235 version(0) 3 74 - MIKEY-PK-SIGN");
    add_oid_str_name(OID_MIKEY_DH_SIGN, "itu-t(0) recommendation(0) h(8) 235 version(0) 3 75 - MIKEY-DH-SIGN");
  /* H.235.7, Chapter 8.5 */
    add_oid_str_name(OID_TG, "itu-t(0) recommendation(0) h(8) 235 version(0) 3 70 - TG");
  /* H.235.7, Chapter 9.5 */
    add_oid_str_name(OID_SG, "itu-t(0) recommendation(0) h(8) 235 version(0) 3 71 - SG");
}


/*--- proto_reg_handoff_h235 -------------------------------------------*/
void proto_reg_handoff_h235(void) {

  mikey_handle = find_dissector("mikey");

  /* H.235.7, Chapter 7.1, MIKEY operation at "session level" */
  dissector_add_string("h245.gen_par", OID_MIKEY         "-0", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY_PS      "-0", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY_DHHMAC  "-0", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY_PK_SIGN "-0", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY_DH_SIGN "-0", mikey_handle);
  dissector_add_string("h245.gen_par", "EncryptionSync-0", mikey_handle);
  /* H.235.7, Chapter 7.2, MIKEY operation at "media level" */
  dissector_add_string("h245.gen_par", "EncryptionSync-76", mikey_handle);
  dissector_add_string("h245.gen_par", "EncryptionSync-72", mikey_handle);
  dissector_add_string("h245.gen_par", "EncryptionSync-73", mikey_handle);
  dissector_add_string("h245.gen_par", "EncryptionSync-74", mikey_handle);
  dissector_add_string("h245.gen_par", "EncryptionSync-75", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY         "-76", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY_PS      "-72", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY_DHHMAC  "-73", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY_PK_SIGN "-74", mikey_handle);
  dissector_add_string("h245.gen_par", OID_MIKEY_DH_SIGN "-75", mikey_handle);

}

