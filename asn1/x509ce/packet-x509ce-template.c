/* packet-x509ce.c
 * Routines for X.509 Certificate Extensions packet dissection
 *  Ronnie Sahlberg 2004
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

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-x509ce.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-p1.h"

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

void proto_register_x509ce(void);
void proto_reg_handoff_x509ce(void);

/* Initialize the protocol and registered fields */
static int proto_x509ce = -1;
static int hf_x509ce_id_ce_invalidityDate = -1;
static int hf_x509ce_id_ce_baseUpdateTime = -1;
static int hf_x509ce_object_identifier_id = -1;
static int hf_x509ce_IPAddress = -1;
#include "packet-x509ce-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509ce-ett.c"
#include "packet-x509ce-fn.c"

/* CI+ (www.ci-plus.com) defines some X.509 certificate extensions
    that use OIDs which are not officially assigned
   dissection of these extensions can be enabled temporarily using the
    functions below */
void
x509ce_enable_ciplus(void)
{
	dissector_handle_t dh25, dh26, dh27;

	dh25 = create_dissector_handle(dissect_ScramblerCapabilities_PDU, proto_x509ce);
	dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.25", dh25);
	dh26 = create_dissector_handle(dissect_CiplusInfo_PDU, proto_x509ce);
	dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.26", dh26);
	dh27 = create_dissector_handle(dissect_CicamBrandId_PDU, proto_x509ce);
	dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.27", dh27);
}

void
x509ce_disable_ciplus(void)
{
	dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.25");
	dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.26");
	dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.27");
}


static int
dissect_x509ce_invalidityDate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	return dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509ce_id_ce_invalidityDate);
}

static int
dissect_x509ce_baseUpdateTime_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	return dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509ce_id_ce_baseUpdateTime);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_baseUpdateTime,
      { "baseUpdateTime", "x509ce.id_ce_baseUpdateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_id_ce_invalidityDate,
      { "invalidityDate", "x509ce.id_ce_invalidityDate",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_object_identifier_id,
      { "Id", "x509ce.id", FT_OID, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
    { &hf_x509ce_IPAddress,
      { "iPAddress", "x509ce.IPAddress", FT_IPv4, BASE_NONE, NULL, 0,
        "IP Address", HFILL }},

#include "packet-x509ce-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-x509ce-ettarr.c"
  };

  /* Register protocol */
  proto_x509ce = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509ce, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509ce -------------------------------------------*/
void proto_reg_handoff_x509ce(void) {
#include "packet-x509ce-dis-tab.c"
	register_ber_oid_dissector("2.5.29.24", dissect_x509ce_invalidityDate_callback, proto_x509ce, "id-ce-invalidityDate");
	register_ber_oid_dissector("2.5.29.51", dissect_x509ce_baseUpdateTime_callback, proto_x509ce, "id-ce-baseUpdateTime");
}

