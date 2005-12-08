/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-wlancertextn.c                                                    */
/* ../../tools/asn2eth.py -X -b -e -p wlancertextn -c wlancertextn.cnf -s packet-wlancertextn-template WLANCERTEXTN.asn */

/* Input file: packet-wlancertextn-template.c */

#line 1 "packet-wlancertextn-template.c"
/* packet-wlancertextn.c
 * Routines for Wireless Certificate Extension (RFC3770)
 *  Ronnie Sahlberg 2005
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
#include "packet-wlancertextn.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509sat.h"

#define PNAME  "Wlan Certificate Extension"
#define PSNAME "WLANCERTEXTN"
#define PFNAME "wlancertextn"

/* Initialize the protocol and registered fields */
int proto_wlancertextn = -1;

/*--- Included file: packet-wlancertextn-hf.c ---*/
#line 1 "packet-wlancertextn-hf.c"
static int hf_wlancertextn_SSIDList_PDU = -1;     /* SSIDList */
static int hf_wlancertextn_SSIDList_item = -1;    /* SSID */

/*--- End of included file: packet-wlancertextn-hf.c ---*/
#line 50 "packet-wlancertextn-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-wlancertextn-ett.c ---*/
#line 1 "packet-wlancertextn-ett.c"
static gint ett_wlancertextn_SSIDList = -1;

/*--- End of included file: packet-wlancertextn-ett.c ---*/
#line 53 "packet-wlancertextn-template.c"


/*--- Included file: packet-wlancertextn-fn.c ---*/
#line 1 "packet-wlancertextn-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_wlancertextn_SSID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_SSIDList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_wlancertextn_SSID(FALSE, tvb, offset, pinfo, tree, hf_wlancertextn_SSIDList_item);
}


static const ber_sequence_t SSIDList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_SSIDList_item },
};

static int
dissect_wlancertextn_SSIDList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SSIDList_sequence_of, hf_index, ett_wlancertextn_SSIDList);

  return offset;
}

/*--- PDUs ---*/

static void dissect_SSIDList_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_wlancertextn_SSIDList(FALSE, tvb, 0, pinfo, tree, hf_wlancertextn_SSIDList_PDU);
}


/*--- End of included file: packet-wlancertextn-fn.c ---*/
#line 55 "packet-wlancertextn-template.c"


/*--- proto_register_wlancertextn ----------------------------------------------*/
void proto_register_wlancertextn(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-wlancertextn-hfarr.c ---*/
#line 1 "packet-wlancertextn-hfarr.c"
    { &hf_wlancertextn_SSIDList_PDU,
      { "SSIDList", "wlancertextn.SSIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SSIDList", HFILL }},
    { &hf_wlancertextn_SSIDList_item,
      { "Item", "wlancertextn.SSIDList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SSIDList/_item", HFILL }},

/*--- End of included file: packet-wlancertextn-hfarr.c ---*/
#line 63 "packet-wlancertextn-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-wlancertextn-ettarr.c ---*/
#line 1 "packet-wlancertextn-ettarr.c"
    &ett_wlancertextn_SSIDList,

/*--- End of included file: packet-wlancertextn-ettarr.c ---*/
#line 68 "packet-wlancertextn-template.c"
  };

  /* Register protocol */
  proto_wlancertextn = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_wlancertextn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_wlancertextn -------------------------------------------*/
void proto_reg_handoff_wlancertextn(void) {

/*--- Included file: packet-wlancertextn-dis-tab.c ---*/
#line 1 "packet-wlancertextn-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.13", dissect_SSIDList_PDU, proto_wlancertextn, "id-pe-wlanSSID");
  register_ber_oid_dissector("1.3.6.1.5.5.7.10.6", dissect_SSIDList_PDU, proto_wlancertextn, "id-aca-wlanSSID");


/*--- End of included file: packet-wlancertextn-dis-tab.c ---*/
#line 83 "packet-wlancertextn-template.c"
  register_ber_oid_name("1.3.6.1.5.5.7.3.13","id-kp-eapOverPPP");
  register_ber_oid_name("1.3.6.1.5.5.7.3.14","id-kp-eapOverLAN");
}

