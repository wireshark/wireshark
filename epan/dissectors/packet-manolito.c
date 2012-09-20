/* packet-manolito.c
 * Routines for Blubster/Piolet Manolito Protocol dissection
 * Copyright 2003-2004, Jeff Connelly <shellreef+mp2p@gmail.com>
 *
 * Official home page: http://openlito.sourceforge.net/
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>

/* Initialize the protocol and registered fields */
static int proto_manolito = -1;
static int hf_manolito_checksum = -1;
static int hf_manolito_seqno = -1;
static int hf_manolito_src = -1;
static int hf_manolito_dest = -1;
static int hf_manolito_options_short = -1;
static int hf_manolito_options = -1;

/* Initialize the subtree pointers */
static gint ett_manolito = -1;

/* Code to actually dissect the packets */
static void
dissect_manolito(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	unsigned int offset;

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *manolito_tree;
	const char* packet_type = 0;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MANOLITO");

	ti = proto_tree_add_item(tree, proto_manolito, tvb, 0, -1, ENC_NA);

	manolito_tree = proto_item_add_subtree(ti, ett_manolito);

	/* MANOLITO packet header (network byte order) */
	proto_tree_add_item(manolito_tree,
	    hf_manolito_checksum, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(manolito_tree,
	    hf_manolito_seqno, tvb, 4, 4, ENC_BIG_ENDIAN);

	proto_tree_add_item(manolito_tree,
	    hf_manolito_src, tvb, 8, 4, ENC_BIG_ENDIAN);

	proto_tree_add_item(manolito_tree,
	    hf_manolito_dest, tvb, 12, 4, ENC_BIG_ENDIAN);

	if (tvb_reported_length(tvb) == 19) {
		packet_type = "Ping (truncated)";
		proto_tree_add_item(manolito_tree,
		    hf_manolito_options_short, tvb, 16, 3, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(manolito_tree,
		    hf_manolito_options, tvb, 16, 4, ENC_BIG_ENDIAN);
	}

	if (tvb_reported_length(tvb) <= 20)      /* no payload, just headers */
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Ping");
	} else {
		offset = 20;            /* fields start here */

	 	/* fields format: 2-byte name, optional NULL, 1-byte lenlen, */
		/* that many bytes(len or data), for NI,CN,VL is len, more */
		/* (that many bytes) data follows; else is raw data. */
		do
		{
			guint16 field_name;      /* 16-bit field name */
			guint8 dtype;            /* data-type */
			guint8 length;           /* length */
			guint8* data;            /* payload */
			int start;               /* field starting location */
			char field_name_str[3];  /* printable name */
			const char* longname;    /* human-friendly field name */

			start = offset;

			/* 2-byte field name */
			field_name = tvb_get_ntohs(tvb, offset);
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

			if (tvb_reported_length(tvb) == 20)   /* no fields */
				packet_type = "Ping";

			/* Find the long name of the field */
			switch(field_name)
			{
			case 0x5346: longname = "Shared Files"; break;    /* SF */
			case 0x534b: longname = "Shared Kilobytes";break; /* SK */
			case 0x4e49: longname = "Network ID"; break;      /* NI */
			case 0x4e43: longname = "Num. Connections";break; /* NC */
			case 0x4356: longname = "Client Version"; break;  /* CV */
			case 0x564c: longname = "Velocity"; break;        /* VL */
			case 0x464e: longname = "Filename"; break;        /* FN */
			case 0x464c: longname = "File Length"; break;     /* FL */
			case 0x4252: longname = "Bit Rate"; break;        /* BR */
			case 0x4643: longname = "Frequency"; break;       /* FC */
			case 0x5354: longname = "???"; break;             /* ST */
			case 0x534c: longname = "Song Length (s)"; break; /* SL */
			case 0x434b: longname = "Checksum"; break;    /* CK */
			case 0x4e4e: longname = "Nickname"; break;        /* NN */
			case 0x434e: longname = "Client Name"; break;     /* CN */
			case 0x5054: longname = "Port"; break;            /* PT */
			case 0x484e: longname = "???"; break;             /* HN */
			case 0x4d45: longname = "Message"; break;         /* ME */
			case 0x4944: longname = "Identification"; break;  /* ID */
			case 0x4144: longname = "???"; break;             /* AD */
			default: longname = "unknown"; break;
			}

			/* 1-byte data type */
#define MANOLITO_STRING		1
#define MANOLITO_INTEGER	0
			dtype = tvb_get_guint8(tvb, offset);
			length = tvb_get_guint8(tvb, ++offset);

			/*
			 * Get the payload.
			 *
			 * XXX - is the cast necessary?  I think the
			 * "usual arithmetic conversions" should
			 * widen it past 8 bits, so there shouldn't
			 * be an overflow.
			 */
			data = ep_alloc((guint)length + 1);
			tvb_memcpy(tvb, data, ++offset, length);
			offset += length;

			/* convert the 16-bit integer field name to a string */
                        /* XXX: changed this to use g_htons */
			field_name_str[0] = g_htons(field_name) & 0x00ff;
			field_name_str[1] = (g_htons(field_name) & 0xff00) >> 8;
			field_name_str[2] = 0;

			if (dtype == MANOLITO_STRING)
			{
				data[length] = 0;
				proto_tree_add_text(manolito_tree, tvb, start,
					offset - start, "%s (%s): %s",
					(char*)field_name_str, longname, data);
			} else if (dtype == MANOLITO_INTEGER) {
			 	int n = 0;

				/* integers can be up to 5 bytes */
				switch(length)
				{
				case 5: n += data[4] << ((length - 5) * 8);
				case 4: n += data[3] << ((length - 4) * 8);
				case 3: n += data[2] << ((length - 3) * 8);
				case 2: n += data[1] << ((length - 2) * 8);
				case 1: n += data[0] << ((length - 1) * 8);
				}
				proto_tree_add_text(manolito_tree, tvb, start,
					offset - start, "%s (%s): %d",
					(char*)field_name_str, longname, n);
			} else {
				proto_tree_add_text(manolito_tree, tvb, start,
					offset - start, "unknown type %d", dtype);
			}

		} while(offset < tvb_reported_length(tvb));

	}

	if (packet_type)
	{
		col_set_str(pinfo->cinfo, COL_INFO, packet_type);
	}
}


/* Register the protocol with Wireshark */

void
proto_register_manolito(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_manolito_checksum,
			{ "Checksum",           "manolito.checksum",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Checksum used for verifying integrity", HFILL }
		},
                { &hf_manolito_seqno,
                        { "Sequence Number",      "manolito.seqno",
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
	};

	static gint *ett[] = {
		&ett_manolito,
	};

	proto_manolito = proto_register_protocol("Blubster/Piolet MANOLITO Protocol",
	    "Manolito", "manolito");

	proto_register_field_array(proto_manolito, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_manolito(void)
{
	dissector_handle_t manolito_handle;

	manolito_handle = create_dissector_handle(dissect_manolito,
	    proto_manolito);
	dissector_add_uint("udp.port", 41170, manolito_handle);
}

