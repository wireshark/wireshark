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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/charsets.h>

void proto_register_manolito(void);
void proto_reg_handoff_manolito(void);

static dissector_handle_t manolito_handle;

#define MANOLITO_PORT   41170 /* Not IANA registered */

static int proto_manolito;

static int hf_manolito_checksum;
static int hf_manolito_checksum_status;
static int hf_manolito_checksum_padding;
static int hf_manolito_checksum_codepages;
static int hf_manolito_seqno;
static int hf_manolito_src;
static int hf_manolito_dest;
static int hf_manolito_options_short;
static int hf_manolito_options;
static int hf_manolito_string;
static int hf_manolito_integer;

static int ett_manolito;

static expert_field ei_manolito_type;
static expert_field ei_manolito_checksum_bad;

/* The sender converts its ANSI message to Unicode (VB6 StrConv(s, vbUnicode))
 * before checksumming, so every byte >= 0x80 hashes as the UTF-16LE code unit
 * of its code-page character.  The conversion uses the *sender's* Windows ANSI
 * code page: 20523 of 20528 corpus frames reproduce under Windows-1252; the
 * exceptions were single frames from a CP1250 (Polish) and a CP1255 (Israeli)
 * sender.  This dissector verifies with Windows-1252 and additionally tries
 * every candidate code page, reporting in manolito.checksum.codepages which
 * ones could have produced the stored checksum. */

#define MANOLITO_STRING  1
#define MANOLITO_INTEGER 0

static const value_string field_longname[] = {
	{ 0x4144, "???" },
	{ 0x4252, "Bit Rate" },
	{ 0x434b, "Checksum" },
	{ 0x434e, "Client Name" },
	{ 0x4356, "Client Version" },
	{ 0x4643, "Frequency" },
	{ 0x464c, "File Length" },
	{ 0x464e, "Filename" },
	{ 0x484e, "???" },
	{ 0x4944, "Identification" },
	{ 0x4d45, "Message" },
	{ 0x4e43, "Num. Connections" },
	{ 0x4e49, "Network ID" },
	{ 0x4e4e, "Nickname" },
	{ 0x5054, "Port" },
	{ 0x5346, "Shared Files" },
	{ 0x534b, "Shared Kilobytes" },
	{ 0x534c, "Song Length (s)" },
	{ 0x5354, "???" },
	{ 0x564c, "Velocity" },
	{ 0, NULL }
};
static value_string_ext field_longname_ext = VALUE_STRING_EXT_INIT(field_longname);

static const value_string manolito_checksum_status[] = {
	{ PROTO_CHECKSUM_E_BAD,        "Bad" },
	{ PROTO_CHECKSUM_E_GOOD,       "Good" },
	{ PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
	{ PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },
	{ 0, NULL }
};

/* --- manolito checksum core: begin --- */

/* Show the candidate code pages inline with the checksum when at most this
 * many match; a longer list belongs in manolito.checksum.codepages only. */
#define MANOLITO_MAX_DISPLAY	4

/* CRC-16/CCITT: poly 0x1021, MSB first, init 0, no final xor. */
#define MANOLITO_CRC16_POLY	0x1021
#define MANOLITO_CRC16_INIT	0x0000

static uint16_t
manolito_crc16_byte(uint16_t crc, uint8_t byte)
{
	unsigned bit;

	crc ^= (uint16_t)byte << 8;
	for (bit = 0; bit < 8; bit++) {
		if (crc & 0x8000)
			crc = (uint16_t)((crc << 1) ^ MANOLITO_CRC16_POLY);
		else
			crc = (uint16_t)(crc << 1);
	}
	return crc;
}

/*
 * Candidate sender code pages: every Windows ANSI code page a VB6 program
 * could have run on (the VB6 runtime converts the ANSI message to Unicode
 * with the system code page before hashing).  The mappings are the shared
 * tables from epan/charsets.c.  A byte a page leaves undefined (U+FFFD in
 * those tables) hashes as itself, which is what the sender's conversion
 * does for it.  The order defines the match-mask bits.
 */
struct manolito_codepage {
	const char      *name;
	const gunichar2 *high;	/* 0x80..0xff -> Unicode */
};

enum manolito_page {
	MANOLITO_PAGE_CP1250,
	MANOLITO_PAGE_CP1251,
	MANOLITO_PAGE_CP1252,
	MANOLITO_PAGE_CP1253,
	MANOLITO_PAGE_CP1254,
	MANOLITO_PAGE_CP1255,
	MANOLITO_PAGE_CP1256,
	MANOLITO_PAGE_CP1257,
	MANOLITO_PAGE_CP1258,
	MANOLITO_PAGE_CP874,
	MANOLITO_PAGE_MAX
};

static const struct manolito_codepage manolito_codepages[MANOLITO_PAGE_MAX] = {
	{ "Windows-1250", charset_table_cp1250 },
	{ "Windows-1251", charset_table_cp1251 },
	{ "Windows-1252", charset_table_cp1252 },
	{ "Windows-1253", charset_table_cp1253 },
	{ "Windows-1254", charset_table_cp1254 },
	{ "Windows-1255", charset_table_cp1255 },
	{ "Windows-1256", charset_table_cp1256 },
	{ "Windows-1257", charset_table_cp1257 },
	{ "Windows-1258", charset_table_cp1258 },
	{ "Windows-874",  charset_table_cp874 }
};

/* Checksum of an ANSI message under one code page: the CRC runs over the
 * UTF-16LE bytes of the decoded Unicode string, i.e. every input byte
 * contributes two bytes. */
static uint16_t
manolito_checksum_page(const uint8_t *buf, unsigned len, unsigned page)
{
	const gunichar2 *high = manolito_codepages[page].high;
	uint16_t crc = MANOLITO_CRC16_INIT;
	unsigned i;

	for (i = 0; i < len; i++) {
		uint16_t u = buf[i];
		if (u >= 0x80) {
			uint16_t uni = high[u - 0x80];
			if (uni != UNICODE_REPLACEMENT_CHARACTER)
				u = uni;
		}
		crc = manolito_crc16_byte(crc, (uint8_t)(u & 0x00ff));
		crc = manolito_crc16_byte(crc, (uint8_t)(u >> 8));
	}
	return crc;
}

/* Bit mask of every candidate code page whose checksum of the message
 * equals want.  A single bit identifies the sender's code page. */
static uint32_t
manolito_checksum_match_mask(const uint8_t *buf, unsigned len, uint16_t want)
{
	uint32_t mask = 0;
	unsigned page;

	for (page = 0; page < MANOLITO_PAGE_MAX; page++) {
		if (manolito_checksum_page(buf, len, page) == want)
			mask |= ((uint32_t)1 << page);
	}
	return mask;
}
/* --- manolito checksum core: end --- */


static int
dissect_manolito(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* dissector_data _U_)
{
	unsigned offset = 0;
	proto_item *ti;
	proto_tree *manolito_tree;
	char *packet_type = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MANOLITO");

	ti = proto_tree_add_item(tree, proto_manolito, tvb, offset, -1, ENC_NA);

	manolito_tree = proto_item_add_subtree(ti, ett_manolito);

	/* MANOLITO packet header (network byte order) */
	/* The 32-bit field only carries a 16-bit checksum (bytes 2..3 are always
	 * zero).  It covers everything after it, but the sender hashed the
	 * UTF-16 form of the message, not the raw bytes. */
	{
		unsigned   plen = tvb_reported_length(tvb);
		uint16_t   stored = 0;
		uint16_t   computed = 0;
		uint32_t   mask = 0;
		bool       ascii_only = true;
		unsigned   i;
		unsigned   matches = 0;
		bool       have_high = false;
		wmem_strbuf_t *pages;

		if (plen > 4) {
			uint8_t *msg = (uint8_t *)tvb_memdup(pinfo->pool, tvb, 4, plen - 4);

			for (i = 0; i < plen - 4; i++) {
				if (msg[i] >= 0x80) { have_high = true; break; }
			}
			computed = manolito_checksum_page(msg, plen - 4,
			    MANOLITO_PAGE_CP1252);
			mask = manolito_checksum_match_mask(msg, plen - 4,
			    tvb_get_ntohs(tvb, offset));
			for (i = 0; i < MANOLITO_PAGE_MAX; i++) {
				if (mask & ((uint32_t)1 << i))
					matches++;
			}
		}
		ascii_only = !have_high;
		stored = tvb_get_ntohs(tvb, offset);

		/* The sender's code page is part of the input to the CRC, so the
		 * checksum is good if any candidate page reproduces it. */
		proto_tree_add_checksum(manolito_tree, tvb, offset, hf_manolito_checksum,
		    hf_manolito_checksum_status, &ei_manolito_checksum_bad, pinfo,
		    mask != 0 ? stored : computed, ENC_BIG_ENDIAN,
		    PROTO_CHECKSUM_VERIFY);
		proto_tree_add_item(manolito_tree, hf_manolito_checksum_padding,
		    tvb, offset + 2, 2, ENC_BIG_ENDIAN);

		/* Which sender code page(s) could have produced this checksum?
		 * List the candidates in manolito.checksum.codepages; show them
		 * inline next to the checksum only when the set is small enough
		 * to be informative (MANOLITO_MAX_DISPLAY or fewer). */
		pages = wmem_strbuf_new(pinfo->pool, NULL);
		if (plen <= 4) {
			wmem_strbuf_append(pages, "n/a");
		} else if (ascii_only) {
			wmem_strbuf_append(pages,
			    "any (ASCII message; all code pages hash identically)");
		} else if (mask == 0) {
			wmem_strbuf_append(pages,
			    "none (no candidate code page reproduces it)");
		} else {
			for (i = 0; i < MANOLITO_PAGE_MAX; i++) {
				if (mask & ((uint32_t)1 << i)) {
					if (pages->len > 0)
						wmem_strbuf_append(pages, "/");
					wmem_strbuf_append(pages, manolito_codepages[i].name);
				}
			}
		}
		proto_tree_add_string(manolito_tree, hf_manolito_checksum_codepages,
		    tvb, offset, 0, wmem_strbuf_get_str(pages));

		if (plen > 4) {
			if (stored == computed)
				proto_item_append_text(ti, " (checksum valid)");
			else if (matches >= 1 && matches <= MANOLITO_MAX_DISPLAY)
				proto_item_append_text(ti,
				    " (checksum valid, code page: %s)",
				    wmem_strbuf_get_str(pages));
			else
				proto_item_append_text(ti, " (bad checksum)");
		}
	}
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
		uint16_t    field_name;        /* 16-bit field name */
		uint8_t     dtype;             /* data-type */
		uint8_t     length;            /* length */
		int         start;             /* field starting location */
		uint8_t    *field_name_str;

		start = offset;

		/* 2-byte field name */
		field_name = tvb_get_ntohs(tvb, offset);
		field_name_str = tvb_get_string_enc(pinfo->pool, tvb, offset, 2, ENC_ASCII);
		if (!packet_type) {
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
		}
		offset += 2;

		/* 1-byte data type */
		dtype = tvb_get_uint8(tvb, offset);
		offset++;
		length = tvb_get_uint8(tvb, offset);
		offset++;

		if (dtype == MANOLITO_STRING) {
			const char *str;

			str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII);
			proto_tree_add_string_format(manolito_tree, hf_manolito_string, tvb, start,
					4+length, str, "%s (%s): %s",
					field_name_str,
					val_to_str_ext_const(field_name, &field_longname_ext, "unknown"),
					str);
			offset += length;
		}
		else if (dtype == MANOLITO_INTEGER) {
			bool len_ok = true;
			uint64_t n = 0;

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
					n = tvb_get_uint8(tvb, offset);
					break;

				default:
					len_ok = false;
			}

			if (len_ok) {
				proto_tree_add_uint64_format(manolito_tree, hf_manolito_integer, tvb, start,
						4+length, n, "%s (%s): %" PRIu64,
						field_name_str,
						val_to_str_ext_const(field_name, &field_longname_ext, "unknown"),
						n);
			}
			else {
				/* XXX - expert info */
			}
			offset += length;
		}
		else {
			proto_tree_add_expert_format(manolito_tree, pinfo, &ei_manolito_type,
					tvb, start, offset - start, "Unknown type %d", dtype);
		}

	} while(tvb_reported_length_remaining(tvb, offset));

	if (packet_type)
		col_set_str(pinfo->cinfo, COL_INFO, packet_type);

	return offset;
}


void
proto_register_manolito(void)
{
	static hf_register_info hf[] = {
		{ &hf_manolito_checksum,
		  { "Checksum", "manolito.checksum",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Checksum over the rest of the packet", HFILL }
		},
		{ &hf_manolito_checksum_status,
		  { "Checksum Status", "manolito.checksum.status",
		    FT_UINT8, BASE_DEC, VALS(manolito_checksum_status), 0,
		    NULL, HFILL }
		},
		{ &hf_manolito_checksum_padding,
		  { "Checksum Padding", "manolito.checksum.padding",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Always zero; the field is 32 bits wide but only 16 are used", HFILL }
		},
		{ &hf_manolito_checksum_codepages,
		  { "Possible Sender Code Pages", "manolito.checksum.codepages",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "Code pages whose checksum of this packet reproduces the stored value", HFILL }
		},
		{ &hf_manolito_seqno,
		  { "Sequence Number", "manolito.seqno",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "Incremental sequence number", HFILL }
		},
		{ &hf_manolito_src,
		  { "Forwarded IP Address", "manolito.src",
		    FT_IPv4, BASE_NONE, NULL, 0,
		    "Host packet was forwarded from (or 0)", HFILL }
		},
		{ &hf_manolito_dest,
		  { "Destination IP Address", "manolito.dest",
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

	static int *ett[] = {
		&ett_manolito,
	};

	static ei_register_info ei[] = {
		{ &ei_manolito_type, { "manolito.type.unknown", PI_PROTOCOL, PI_WARN, "Unknown type", EXPFILL }},
		{ &ei_manolito_checksum_bad, { "manolito.checksum.bad", PI_CHECKSUM, PI_WARN, "Bad checksum", EXPFILL }},
	};

	expert_module_t* expert_manolito;

	proto_manolito = proto_register_protocol("Blubster/Piolet MANOLITO Protocol", "Manolito", "manolito");

	proto_register_field_array(proto_manolito, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_manolito = expert_register_protocol(proto_manolito);
	expert_register_field_array(expert_manolito, ei, array_length(ei));

	manolito_handle = register_dissector("manolito", dissect_manolito, proto_manolito);
}


void
proto_reg_handoff_manolito(void)
{
	dissector_add_uint_with_preference("udp.port", MANOLITO_PORT, manolito_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
