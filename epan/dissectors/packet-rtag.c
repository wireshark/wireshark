/* packet-rtag.c
 * Dissector for IEEE 802.1CB R-TAG tags
 * By Stephen Williams <steve.williams@getcruise.com>
 * Copyright 2020-present, Cruise LLC
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

# include  "config.h"
# include  <epan/packet.h>
# include  <epan/etypes.h>

static int proto_rtag;

static dissector_handle_t ethertype_handle;
static dissector_handle_t rtag_handle;

/*
 * These values and tables are a breakdown of the R-TAG parts.
 */
static int hf_rtag_reserved;
static int hf_rtag_sequence;
static int hf_rtag_protocol;
static int hf_rtag_trailer;
static hf_register_info rtag_breakdown[] = {
      { &hf_rtag_reserved,
	{ "<reserved>", "rtag.reserved",
	  FT_UINT16, BASE_HEX,
	  NULL, 0x0,
	  NULL, HFILL }
      },
      { &hf_rtag_sequence,
	{ "Sequence number", "rtag.seqno",
	  FT_UINT16, BASE_DEC,
	  NULL, 0x0,
	  NULL, HFILL }
      },
      { &hf_rtag_protocol,
	{ "Type", "rtag.protocol",
	  FT_UINT16, BASE_HEX,
	  VALS(etype_vals), 0x0,
	  "Ethertype", HFILL }
      },
      { &hf_rtag_trailer,
        { "Trailer", "rtag.trailer",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "R-TAG Trailer", HFILL }
      },
};

/*
 */
static int ett_rtag;
static int *ett[] = { &ett_rtag };

/*
 * Dissect the R-TAG portion of a given packet. This is called with
 * the tvb pointing to where our payload starts (i.e. not including
 * the 0xf1c1 tag that got us here.)
 */
static int dissect_rtag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
      proto_item*ti;
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "R-TAG");
	/* Clear the info column */
      col_clear(pinfo->cinfo, COL_INFO);

	/*
	 * The R-TAG is 6 octets: 2 reserved, 2 sequence number, and
	 * 2 encapsulated protocol.
	 */
      ti = proto_tree_add_item(tree, proto_rtag, tvb, 0, 6, ENC_NA);

      uint16_t seqno = tvb_get_ntohs(tvb, 2);
      uint16_t rtag_protocol = tvb_get_ntohs(tvb, 4);

      proto_tree *rtag_subtree = proto_item_add_subtree(ti, ett_rtag);
      proto_tree_add_item(rtag_subtree, hf_rtag_reserved, tvb, 0, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(rtag_subtree, hf_rtag_sequence, tvb, 2, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(rtag_subtree, hf_rtag_protocol, tvb, 4, 2, ENC_BIG_ENDIAN);

	/* Add a quick summary in the info column. */
      col_add_fstr(pinfo->cinfo, COL_INFO, "R-TAG: %u", seqno);

	/*
	 * Process the encapsulated packet as an encapsulated Ethernet
	 * PDU. We have the encapsulated protocol type (and ethertype)
	 * as part of the R-TAG protocol
	 */
      ethertype_data_t ethertype_data;
      ethertype_data.etype = rtag_protocol;
      ethertype_data.payload_offset = 6;
      ethertype_data.fh_tree = tree;
      ethertype_data.trailer_id = hf_rtag_trailer;
      ethertype_data.fcs_len = 0;
      call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);

      return tvb_captured_length(tvb);
}

/*
 * This function is called to register a protocol description.
 */
void proto_register_rtag(void)
{
      proto_rtag = proto_register_protocol (
	   "802.1cb R-TAG", /* name        */
	   "R-TAG",         /* short name  */
	   "rtag"           /* filter_name */
	  );

      proto_register_field_array(proto_rtag, rtag_breakdown,
				 array_length(rtag_breakdown));
      proto_register_subtree_array(ett, array_length(ett));
}

/*
 * This function is called to register the actual dissector.
 */
void proto_reg_handoff_rtag(void)
{
      rtag_handle = create_dissector_handle(dissect_rtag, proto_rtag);
      dissector_add_uint("ethertype", ETHERTYPE_IEEE_802_1CB, rtag_handle);

	/* Get a handle for the ethertype dissector. */
      ethertype_handle = find_dissector_add_dependency("ethertype", proto_rtag);
}
