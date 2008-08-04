/* packet-diameter_3gpp.c
 * Routines for dissecting 3GPP OctetSting AVP:s
 * Copyright 2008, Anders Broman <anders.broman[at]ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

 /* This dissector registers a dissector table for 3GPP Vendor specific
  * AVP:s which will be called from the Diameter dissector to dissect
  * the content of AVP:s of the OctetString type(or similar).
  */

  #ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>

#include "packet-gsm_a_common.h"
#include "packet-e212.h"

/* Initialize the protocol and registered fields */
static int proto_diameter_3gpp			= -1; 

static int hf_diameter_3gpp_ipaddr					= -1;
static int hf_diameter_3gpp_mbms_required_qos_prio	= -1;
static int hf_diameter_3gpp_tmgi					= -1;
static int hf_diameter_mbms_service_id				= -1;

static gint diameter_3gpp_tmgi_ett					= -1;

/* Used for Diameter */

static int
dissect_diameter_3gpp_tmgi(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	proto_item* item;
	proto_tree *sub_tree;
	int offset = 0;

	item = proto_tree_add_item(tree, hf_diameter_3gpp_tmgi, tvb, offset, 6, FALSE);
	sub_tree = proto_item_add_subtree(item,diameter_3gpp_tmgi_ett);

	/* MBMS Service ID consisting of three octets. MBMS Service ID consists of a 6-digit
	 * fixed-length hexadecimal number between 000000 and FFFFFF. 
	 * MBMS Service ID uniquely identifies an MBMS bearer service within a PLMN.
	 */

	proto_tree_add_item(sub_tree, hf_diameter_mbms_service_id, tvb, offset, 3, FALSE);
	offset = offset+3;
	offset = dissect_e212_mcc_mnc(tvb,sub_tree, offset);

	return offset;

}

static int 
dissect_diameter_3gpp_ipaddr(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	int offset = 0;

	proto_tree_add_item(tree, hf_diameter_3gpp_ipaddr, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;

}

static int 
dissect_diameter_3gpp_mbms_required_qos(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

	int offset = 0;
	guint length;

	/* Octet
	 * 1		Allocation/Retention Priority as specified in 3GPP TS 23.107. 
	 *			This octet encodes each priority level defined in 3GPP TS 23.107
	 *			as the binary value of the priority level. It specifies the relative
	 *			importance of the actual MBMS bearer service compared to other MBMS
	 *			and non-MBMS bearer services for allocation and retention of the 
	 *			MBMS bearer service.
	 * 2-N		QoS Profile as specified by the Quality-of-Service information element,
	 *			from octet 3 onwards, in 3GPP TS 24.008
	 */
	proto_tree_add_item(tree, hf_diameter_3gpp_mbms_required_qos_prio, tvb, offset, 1, FALSE);
	offset++;
	length = tvb_length(tvb) - 1;
	de_sm_qos(tvb, tree, offset, length, NULL, 0);
	return offset+length;

}

void
proto_reg_handoff_diameter_3gpp(void)
{

	/* AVP Code: 900 TMGI */
	dissector_add("diameter.3gpp", 900, new_create_dissector_handle(dissect_diameter_3gpp_tmgi, proto_diameter_3gpp));

	/* AVP Code: 918 MBMS-BMSC-SSM-IP-Address */
	dissector_add("diameter.3gpp", 918, new_create_dissector_handle(dissect_diameter_3gpp_ipaddr, proto_diameter_3gpp));

	/* AVP Code: 913 MBMS-Required-QoS */
	dissector_add("diameter.3gpp", 913, new_create_dissector_handle(dissect_diameter_3gpp_mbms_required_qos, proto_diameter_3gpp));


}

void
proto_register_diameter_3gpp(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_diameter_3gpp_ipaddr,
			{ "IPv4 Address",           "diameter.3gpp.ipaddr",
			FT_IPv4, BASE_DEC, NULL, 0x0,          
			"IPv4 Address", HFILL }
		},
		{ &hf_diameter_3gpp_mbms_required_qos_prio,
			{ "Allocation/Retention Priority",           "diameter.3gpp.mbms_required_qos_prio",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"Allocation/Retention Priority", HFILL }
		},
		{ &hf_diameter_3gpp_tmgi,
			{ "TMGI",           "diameter.3gpp.tmgi",
			FT_BYTES, BASE_HEX, NULL, 0x0,          
			"TMGI", HFILL }
		},
		{ &hf_diameter_mbms_service_id,
			{ "MBMS Service ID",           "diameter.3gpp.mbms_service_id",
			FT_UINT24, BASE_HEX, NULL, 0x0,          
			"MBMS Service ID", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&diameter_3gpp_tmgi_ett,
	};

	/* Required function calls to register the header fields and subtrees used */
	proto_diameter_3gpp = proto_register_protocol("Diameter 3GPP","Diameter3GPP", "diameter3gpp");
	proto_register_field_array(proto_diameter_3gpp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
