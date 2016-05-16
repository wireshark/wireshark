/* packet-manolito.c
 * Routines for Blubster/Piolet Manolito Protocol dissection
 * Copyright 2003-2004, Jeff Connelly <shellreef+mp2p@gmail.com>
 *
 * Official home page: http://openlito.sourceforge.net/
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
#include <epan/expert.h>

void proto_register_manolito(void);
void proto_reg_handoff_manolito(void);

static int proto_manolito = -1;

static int hf_manolito_checksum = -1;
static int hf_manolito_seqno = -1;
static int hf_manolito_src = -1;
static int hf_manolito_dest = -1;
static int hf_manolito_options_short = -1;
static int hf_manolito_options = -1;
static int hf_manolito_string = -1;
static int hf_manolito_integer = -1;

static gint ett_manolito = -1;

static expert_field ei_manolito_type = EI_INIT;

static int
dissect_manolito(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* dissector_data _U_)
{
	gint offset = 0;

	proto_item *ti;
	proto_tree *manolito_tree;
	const char* packet_type = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MANOLITO");

	ti = proto_tree_add_item(tree, proto_manolito, tvb, offset, -1, ENC_NA);

	manolito_tree = proto_item_add_subtree(ti, ett_manolito);

	/* MANOLITO packet header (network byte order) */
	proto_tree_add_item(manolito_tree,
	    hf_manolito_checksum, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(manolito_tree,
	    hf_manolito_seqno, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(manolito_tree,
	    hf_manolito_src, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(manolito_tree,
	    hf_manolito_dest, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if (tvb_reported_length_remaining(tvb, offset) == 3) {
		proto_tree_add_item(manolito_tree,
		    hf_manolito_options_short, tvb, offset, 3, ENC_BIG_ENDIAN);
		offset += 3;
		col_set_str(pinfo->cinfo, COL_INFO, "Ping (truncated)");
		return offset;
	}

	proto_tree_add_item(manolito_tree,
			hf_manolito_options, tvb, 16, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if (tvb_reported_length_remaining(tvb, offset) == 0) {
		col_set_str(pinfo->cinfo, COL_INFO, "Ping");
		return offset;
	}

	/* fields format: 2-byte name, optional NULL, 1-byte lenlen, */
	/* that many bytes(len or data), for NI,CN,VL is len, more */
	/* (that many bytes) data follows; else is raw data. */
	do
	{
		guint16     field_name;        /* 16-bit field name */
		guint8      dtype;             /* data-type */
		guint8      length;            /* length */
		int         start;             /* field starting location */
		guint8     *field_name_str;
		const char *longname;          /* human-friendly field name */

		start = offset;

		/* 2-byte field name */
		field_name = tvb_get_ntohs(tvb, offset);
		field_name_str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 2, ENC_ASCII);
		offset += 2;

		/* Identify the packet based on existing fields */
		/* Maybe using the options fields is a better idea...*/
		if (field_name == 0x434b)    /* CK */
			packet_type = "Search Hit";
		if (field_name == 0x4e43)    /* NC */
			packet_type = "User Information";
		if (field_name == 0x464e)    /* FN - if only field */
			packet_type = "Search Query";
		if (field_name == 0x4944)    /* ID ?? search by CK? */
			packet_type = "Search Query (by hash)";
		if (field_name == 0x5054)    /* PT */
			packet_type = "Download Request";
		if (field_name == 0x4d45)    /* ME */
			packet_type = "Chat";

		/* Find the long name of the field */
		switch(field_name)
		{
			case 0x5346: longname = "Shared Files";     break; /* SF */
			case 0x534b: longname = "Shared Kilobytes"; break; /* SK */
			case 0x4e49: longname = "Network ID";       break; /* NI */
			case 0x4e43: longname = "Num. Connections"; break; /* NC */
			case 0x4356: longname = "Client Version";   break; /* CV */
			case 0x564c: longname = "Velocity";         break; /* VL */
			case 0x464e: longname = "Filename";         break; /* FN */
			case 0x464c: longname = "File Length";      break; /* FL */
			case 0x4252: longname = "Bit Rate";         break; /* BR */
			case 0x4643: longname = "Frequency";        break; /* FC */
			case 0x5354: longname = "???";              break; /* ST */
			case 0x534c: longname = "Song Length (s)";  break; /* SL */
			case 0x434b: longname = "Checksum";         break; /* CK */
			case 0x4e4e: longname = "Nickname";         break; /* NN */
			case 0x434e: longname = "Client Name";      break; /* CN */
			case 0x5054: longname = "Port";             break; /* PT */
			case 0x484e: longname = "???";              break; /* HN */
			case 0x4d45: longname = "Message";          break; /* ME */
			case 0x4944: longname = "Identification";   break; /* ID */
			case 0x4144: longname = "???";              break; /* AD */
			default:     longname = "unknown";          break;
		}

		/* 1-byte data type */
#define MANOLITO_STRING		1
#define MANOLITO_INTEGER	0
		dtype = tvb_get_guint8(tvb, offset);
		offset++;
		length = tvb_get_guint8(tvb, offset);
		offset++;

		if (dtype == MANOLITO_STRING)
		{
			guint8 *str;

			str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
			proto_tree_add_string_format(manolito_tree, hf_manolito_string, tvb, start,
					4+length, str, "%s (%s): %s", (char*)field_name_str, longname, str);
			offset += length;
		} else if (dtype == MANOLITO_INTEGER) {
			gboolean len_ok = TRUE;
			guint64 n = 0;

			/* integers can be up to 5 bytes */
			switch(length)
			{
				case 5:
					n = tvb_get_ntoh40(tvb, offset);
					break;
				case 4:
					n = tvb_get_ntohl(tvb, offset);
					break;
				case 3:
					n = tvb_get_ntoh24(tvb, offset);
					break;
				case 2:
					n = tvb_get_ntohs(tvb, offset);
					break;
				case 1:
					n = tvb_get_guint8(tvb, offset);
					break;

				default:
					len_ok = FALSE;
			}

			if (len_ok) {
				ti = proto_tree_add_uint64_format(manolito_tree, hf_manolito_integer, tvb, start,
						4+length, n, "%s (%s): %" G_GINT64_MODIFIER "u",
						(char*)field_name_str, longname, n);
			}
			else {
				/* XXX - expert info */
			}
			offset += length;
		} else {
			proto_tree_add_expert_format(manolito_tree, pinfo, &ei_manolito_type,
					tvb, start, offset - start, "Unknown type %d", dtype);
		}

	} while(tvb_reported_length_remaining(tvb, offset));

	if (packet_type)
	{
		col_set_str(pinfo->cinfo, COL_INFO, packet_type);
	}
	return tvb_captured_length(tvb);
}


void
proto_register_manolito(void)
{
	static hf_register_info hf[] = {
		{ &hf_manolito_checksum,
		  { "Checksum",		"manolito.checksum",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "Checksum used for verifying integrity", HFILL }
		},
		{ &hf_manolito_seqno,
		  { "Sequence Number",	  "manolito.seqno",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "Incremental sequence number", HFILL }
		},
		{ &hf_manolito_src,
		  { "Forwarded IP Address",    "manolito.src",
		    FT_IPv4, BASE_NONE, NULL, 0,
		    "Host packet was forwarded from (or 0)", HFILL }
		},
		{ &hf_manolito_dest,
		  { "Destination IP Address","manolito.dest",
		    FT_IPv4, BASE_NONE, NULL, 0,
		    "Destination IPv4 address", HFILL }
		},
		{ &hf_manolito_options_short,
		  { "Options", "manolito.options",
		    FT_UINT24, BASE_HEX, NULL, 0,
		    "Packet-dependent data", HFILL }
		},
		{ &hf_manolito_options,
		  { "Options", "manolito.options",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "Packet-dependent data", HFILL }
		},
		{ &hf_manolito_string,
		  { "String field", "manolito.string",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_manolito_integer,
		  { "Integer field", "manolito.integer",
		    FT_UINT40, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_manolito,
	};

	static ei_register_info ei[] = {
		{ &ei_manolito_type, { "manolito.type.unknown", PI_PROTOCOL, PI_WARN, "Unknown type", EXPFILL }},
	};

	expert_module_t* expert_manolito;

	proto_manolito = proto_register_protocol("Blubster/Piolet MANOLITO Protocol", "Manolito", "manolito");

	proto_register_field_array(proto_manolito, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_manolito = expert_register_protocol(proto_manolito);
	expert_register_field_array(expert_manolito, ei, array_length(ei));
}


void
proto_reg_handoff_manolito(void)
{
	dissector_handle_t manolito_handle;

	manolito_handle = create_dissector_handle(dissect_manolito,
	    proto_manolito);
	dissector_add_uint("udp.port", 41170, manolito_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
