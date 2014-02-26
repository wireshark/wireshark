/* packet-h235.c
 * Routines for H.235 packet dissection
 * 2004  Tomas Kukosa
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

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

void proto_register_h235(void);
void proto_reg_handoff_h235(void);

/* Initialize the protocol and registered fields */
static int proto_h235 = -1;
#include "packet-h235-hf.c"

/* Initialize the subtree pointers */
#include "packet-h235-ett.c"


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
    oid_add_from_string("all fields in RAS/CS","0.0.8.235.0.1.1");
    oid_add_from_string("all fields in RAS/CS","0.0.8.235.0.2.1");
    /* T */
    oid_add_from_string("ClearToken","0.0.8.235.0.1.5");
    oid_add_from_string("ClearToken","0.0.8.235.0.2.5");
    /* U */
    oid_add_from_string("HMAC-SHA1-96","0.0.8.235.0.1.6");
    oid_add_from_string("HMAC-SHA1-96","0.0.8.235.0.2.6");
  /* H.235.7, Chapter 5, Table 1 */
    oid_add_from_string("MIKEY",		OID_MIKEY);
    oid_add_from_string("MIKEY-PS",		OID_MIKEY_PS);
    oid_add_from_string("MIKEY-DHHMAC",		OID_MIKEY_DHHMAC);
    oid_add_from_string("MIKEY-PK-SIGN",	OID_MIKEY_PK_SIGN);
    oid_add_from_string("MIKEY-DH-SIGN",	OID_MIKEY_DH_SIGN);
  /* H.235.7, Chapter 8.5 */
    oid_add_from_string("TG",OID_TG);
  /* H.235.7, Chapter 9.5 */
    oid_add_from_string("SG",OID_SG);
  /* H.235.8, Chapter 4.2, Table 2 */
    oid_add_from_string("AES_CM_128_HMAC_SHA1_80","0.0.8.235.0.4.91");
    oid_add_from_string("AES_CM_128_HMAC_SHA1_32","0.0.8.235.0.4.92");
    oid_add_from_string("F8_128_HMAC_SHA1_80","0.0.8.235.0.4.93");
}


/*--- proto_reg_handoff_h235 -------------------------------------------*/
void proto_reg_handoff_h235(void) {
  dissector_handle_t mikey_handle;

  mikey_handle = find_dissector("mikey");

  /* H.235.7, Chapter 7.1, MIKEY operation at "session level" */
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY         "/nonCollapsing/0", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY_PS      "/nonCollapsing/0", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY_DHHMAC  "/nonCollapsing/0", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY_PK_SIGN "/nonCollapsing/0", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY_DH_SIGN "/nonCollapsing/0", mikey_handle);
  dissector_add_string("h245.gef.content", "EncryptionSync/0", mikey_handle);
  /* H.235.7, Chapter 7.2, MIKEY operation at "media level" */
  dissector_add_string("h245.gef.content", "EncryptionSync/76", mikey_handle);
  dissector_add_string("h245.gef.content", "EncryptionSync/72", mikey_handle);
  dissector_add_string("h245.gef.content", "EncryptionSync/73", mikey_handle);
  dissector_add_string("h245.gef.content", "EncryptionSync/74", mikey_handle);
  dissector_add_string("h245.gef.content", "EncryptionSync/75", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY         "/nonCollapsing/76", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY_PS      "/nonCollapsing/72", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY_DHHMAC  "/nonCollapsing/73", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY_PK_SIGN "/nonCollapsing/74", mikey_handle);
  dissector_add_string("h245.gef.content", "GenericCapability/" OID_MIKEY_DH_SIGN "/nonCollapsing/75", mikey_handle);

  /* H.235.8, Chapter 4.1.2, SrtpCryptoCapability transport */
  dissector_add_string("h245.gef.content", "GenericCapability/0.0.8.235.0.4.90/nonCollapsingRaw",
                       new_create_dissector_handle(dissect_SrtpCryptoCapability_PDU, proto_h235));

}

