/* packet-id3v2.c
 * Routines for ID3v2 dissection
 * Copyright 2022, Jeff Morriss <jeff.morriss.ws [AT] gmai.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ID3v2 offers a flexible way of storing audio metadata within the audio
 * file itself.  It's the de facto standard for storing metadata in MP3s
 * but is also supported in other file types including AIFF, WAV, and MP4.
 *
 * This dissector was written against ID3 v2.4 and v2.3:
 * https://id3.org/id3v2.4.0-structure
 * https://id3.org/id3v2.4.0-frames
 * https://id3.org/id3v2.3.0
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/mpeg-audio.h>

void proto_reg_handoff_id3v2(void);
void proto_register_id3v2(void);

static dissector_table_t media_type_dissector_table;

static int proto_id3v2;
static int hf_id3v2;
static int hf_id3v2_file_id;
static int hf_id3v2_version;
static int hf_id3v2_flags;
static int hf_id3v2_size;
static int hf_id3v2_frame;
static int hf_id3v2_frame_id;
static int hf_id3v2_frame_size;
static int hf_id3v2_frame_flags;
static int hf_id3v2_frame_text_encoding;
static int hf_id3v2_frame_text_description;
static int hf_id3v2_frame_text_value;
static int hf_id3v2_frame_ufi_owner;
static int hf_id3v2_frame_ufi_id;
static int hf_id3v2_frame_apic_mime_type;
static int hf_id3v2_frame_apic_picture_type;
static int hf_id3v2_frame_apic_description;
static int hf_id3v2_frame_private;
static int hf_id3v2_frame_comment_language;
static int hf_id3v2_frame_comment_description;
static int hf_id3v2_frame_comment_text;
static int hf_id3v2_undecoded;
static int hf_id3v2_padding;

static int ett_id3v2;
static int ett_id3v2_frame;

static expert_field ei_id3v2_undecoded;

#define ID3V2_MIN_LENGTH 10

/* Technically this is version + revision; break it up into multiple fields? */
static const value_string id3v2_version_values[] = {
	{ 0x0200, "2.2" },
	{ 0x0300, "2.3" },
	{ 0x0400, "2.4" },
	{ 0,      NULL } };

/* The below are v2.3 unless otherwise noted */
static const string_string id3v2_tag_names[] = {
	{ "AENC", "Audio encryption" },
	{ "APIC", "Attached picture" },
	{ "ASPI", "Audio seek point index" },
	{ "COMM", "Comments" },
	{ "COMR", "Commercial frame" },
	{ "ENCR", "Encryption method registration" },
	{ "EQUA", "Equalization" }, /* v2.3 */
	{ "EQU2", "Equalization (2)" }, /* v2.4 */
	{ "ETCO", "Event timing codes" },
	{ "GEOB", "General encapsulated object" },
	{ "GRID", "Group identification registration" },
	{ "IPLS", "Involved people list" }, /* v2.3 */
	{ "TIPL", "Involved people list" }, /* v2.4 */
	{ "LINK", "Linked information" },
	{ "MCDI", "Music CD identifier" },
	{ "MLLT", "MPEG location lookup table" },
	{ "OWNE", "Ownership frame" },
	{ "PRIV", "Private frame" },
	{ "PCNT", "Play counter" },
	{ "POPM", "Popularimeter" },
	{ "POSS", "Position synchronisation frame" },
	{ "RBUF", "Recommended buffer size" },
	{ "RVAD", "Relative volume adjustment" }, /* v2.3 */
	{ "RVA2", "Relative volume adjustment (2)" }, /* v2.4 */
	{ "RVRB", "Reverb" },
	{ "SEEK", "Seek frame" }, /* v2.4 */
	{ "SIGN", "Signature frame" }, /* v2.4 */
	{ "SYLT", "Synchronized lyric/text" },
	{ "SYTC", "Synchronized tempo codes" },
	{ "TALB", "Album/Movie/Show title" },
	{ "TBPM", "BPM (beats per minute)" },
	{ "TCOM", "Composer" },
	{ "TCON", "Content type" },
	{ "TCOP", "Copyright message" },
	{ "TDAT", "Date" },
	{ "TDEN", "Encoding time" },
	{ "TDLY", "Playlist delay" },
	{ "TDRC", "Recording time" }, /* v2.4 */
	{ "TDRL", "Release time" }, /* v2.4 */
	{ "TDTG", "Tagging time" }, /* v2.4 */
	{ "TENC", "Encoded by" },
	{ "TEXT", "Lyricist/Text writer" },
	{ "TFLT", "File type" },
	{ "TIME", "Time" },
	{ "TIT1", "Content group description" },
	{ "TIT2", "Title/songname/content description" },
	{ "TIT3", "Subtitle/Description refinement" },
	{ "TKEY", "Initial key" },
	{ "TLAN", "Language(s)" },
	{ "TLEN", "Length" },
	{ "TMED", "Media type" },
	{ "TMOO", "Mood" }, /* v2.4 */
	{ "TMCL", "Musicians credits list" }, /* v2.4 */
	{ "TOAL", "Original album/movie/show title" },
	{ "TOFN", "Original filename" },
	{ "TOLY", "Original lyricist(s)/text writer(s)" },
	{ "TOPE", "Original artist(s)/performer(s)" },
	{ "TORY", "Original release year" }, /* v2.3 */
	{ "TDOR", "Original release time" }, /* v2.4 */
	{ "TOWN", "File owner/licensee" },
	{ "TPE1", "Lead performer(s)/Soloist(s)" },
	{ "TPE2", "Band/orchestra/accompaniment" },
	{ "TPE3", "Conductor/performer refinement" },
	{ "TPE4", "Interpreted, remixed, or otherwise modified by" },
	{ "TPOS", "Part of a set" },
	{ "TPUB", "Publisher" },
	{ "TPRO", "Produced notice" },
	{ "TRCK", "Track number/Position in set" },
	{ "TRDA", "Recording dates" },
	{ "TRSN", "Internet radio station name" },
	{ "TRSO", "Internet radio station owner" },
	{ "TSOA", "Album sort order" }, /* v2.4 */
	{ "TSO2", "Album artist sort order" }, /* iTunes */
	{ "TSOP", "Performer sort order" }, /* v2.4 */
	{ "TSOT", "Title sort order" }, /* v2.4 */
	{ "TSIZ", "Size" },
	{ "TSRC", "ISRC (international standard recording code)" },
	{ "TSSE", "Software/Hardware and settings used for encoding" },
	{ "TSST", "Set subtitle" }, /* v2.4 */
	{ "TYER", "Year" },
	{ "TXXX", "User defined" },
	{ "UFID", "Unique file identifier" },
	{ "USER", "Terms of use" },
	{ "USLT", "Unsynchronized lyric/text transcription" },
	{ "WCOM", "Commercial information" },
	{ "WCOP", "Copyright/Legal information" },
	{ "WOAF", "Official audio file webpage" },
	{ "WOAR", "Official artist/performer webpage" },
	{ "WOAS", "Official audio source webpage" },
	{ "WORS", "Official internet radio station homepage" },
	{ "WPAY", "Payment" },
	{ "WPUB", "Publishers official webpage" },
	{ "WXXX", "User defined URL link frame" },
	{ NULL,      NULL } };

static const value_string id3v2_apic_types[] = {
	{ 0x00,   "Other" },
	{ 0x01,   "32x32 pixels 'file icon' (PNG only)" },
	{ 0x02,   "Other file icon" },
	{ 0x03,   "Cover (front)" },
	{ 0x04,   "Cover (back)" },
	{ 0x05,   "Leaflet page" },
	{ 0x06,   "Media (e.g. label side of CD)" },
	{ 0x07,   "Lead artist/lead performer/soloist" },
	{ 0x08,   "Artist/performer" },
	{ 0x09,   "Conductor" },
	{ 0x0A,   "Band/Orchestra" },
	{ 0x0B,   "Composer" },
	{ 0x0C,   "Lyricist/text writer" },
	{ 0x0D,   "Recording Location" },
	{ 0x0E,   "During recording" },
	{ 0x0F,   "During performance" },
	{ 0x10,   "Movie/video screen capture" },
	{ 0x11,   "A bright coloured fish" },
	{ 0x12,   "Illustration" },
	{ 0x13,   "Band/artist logotype" },
	{ 0x14,   "Publisher/Studio logotype" },
	{ 0,      NULL } };

static const value_string id3v2_text_encoding_values[] = {
	{ 0x00,  "ISO-8859-1" },
	{ 0x01,  "UTF-16 with BOM" },
	{ 0x02,  "UTF-16BE" },
	{ 0x03,  "UTF-8" },
	{ 0,     NULL } };

static unsigned
id3v2_decode_encoding(uint8_t id3_encoding)
{
	unsigned encoding;

	switch (id3_encoding) {
		case 0x00:
			encoding = ENC_ISO_8859_1;
			break;
		case 0x01:
			encoding = ENC_UTF_16|ENC_BOM|ENC_LITTLE_ENDIAN;
			break;
		case 0x02:
			encoding = ENC_UTF_16|ENC_BIG_ENDIAN;
			break;
		case 0x03:
		default:
			encoding = ENC_UTF_8;
			break;
	}

	return encoding;
}

static char *
id3v2_dissect_textz_item(wmem_allocator_t *scope, tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint8_t id3_encoding, int hf)
{
	unsigned encoding;
	char *text_value;
	unsigned text_length;

	encoding = id3v2_decode_encoding(id3_encoding);

	text_value = tvb_get_stringz_enc(scope, tvb, *offset, &text_length, encoding);
	proto_tree_add_item(tree, hf, tvb, *offset, text_length, encoding);
	*offset += text_length;

	return text_value;
}

static char *
id3v2_dissect_text_item(wmem_allocator_t *scope, tvbuff_t *tvb, proto_tree *tree, unsigned *offset, unsigned end, uint8_t id3_encoding, int hf)
{
	unsigned encoding;
	char *text_value;

	encoding = id3v2_decode_encoding(id3_encoding);

	text_value = tvb_get_string_enc(scope, tvb, *offset, (end - *offset), encoding);
	proto_tree_add_item(tree, hf, tvb, *offset, (end - *offset), encoding);

	return text_value;
}

static void
dissect_id3v2_comment_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, unsigned length, proto_item *pi)
{
	uint8_t id3_encoding;
	unsigned end = offset + length;
	char *comment_value;

	id3_encoding = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_id3v2_frame_text_encoding, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_id3v2_frame_comment_language, tvb, offset, 3, ENC_ISO_8859_1);
	offset += 3;

	id3v2_dissect_textz_item(pinfo->pool, tvb, tree, &offset, id3_encoding, hf_id3v2_frame_comment_description);

	comment_value = id3v2_dissect_text_item(pinfo->pool, tvb, tree, &offset, end, id3_encoding, hf_id3v2_frame_comment_text);
	proto_item_append_text(pi, ": %s", comment_value);
}

static void
dissect_id3v2_apic_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, unsigned length)
{
	uint8_t id3_encoding;
	unsigned end = offset + length;
	char *mime_type;
	tvbuff_t *image_tvb;

	id3_encoding = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_id3v2_frame_text_encoding, tvb, offset, 1, ENC_NA);
	offset += 1;

	mime_type = id3v2_dissect_textz_item(pinfo->pool, tvb, tree, &offset, id3_encoding, hf_id3v2_frame_apic_mime_type);

	proto_tree_add_item(tree, hf_id3v2_frame_apic_picture_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	id3v2_dissect_textz_item(pinfo->pool, tvb, tree, &offset, id3_encoding, hf_id3v2_frame_apic_description);

	image_tvb = tvb_new_subset_length(tvb, offset, (end - offset));
	dissector_try_string(media_type_dissector_table, mime_type, image_tvb, pinfo, tree, NULL);
}

static char *
dissect_id3v2_text_frame(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, unsigned offset, unsigned length, bool is_txxx)
{
	uint8_t id3_encoding;
	char *text_value;
	unsigned end = offset + length;

	id3_encoding = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_id3v2_frame_text_encoding, tvb, offset, 1, ENC_NA);
	offset += 1;

	if (is_txxx) {
		/* This is a user-defined text frame (contains a description and a value) */

		text_value = id3v2_dissect_textz_item(pinfo->pool, tvb, tree, &offset, id3_encoding, hf_id3v2_frame_text_description);
		proto_item_append_text(item, ": %s", text_value);
	}

	text_value = id3v2_dissect_text_item(pinfo->pool, tvb, tree, &offset, end, id3_encoding, hf_id3v2_frame_text_value);
	proto_item_append_text(item, ": %s", text_value);

	return text_value;
}

static int
dissect_id3v2_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint8_t id3_version)
{
	proto_item *frame_item;
	proto_tree *frame_tree;
	uint32_t size;
	char *frame_id;

	frame_id = tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ISO_8859_1);

	if (strlen(frame_id) == 0) {
		proto_tree_add_item(tree, hf_id3v2_padding, tvb, offset, -1, ENC_NA);
		return offset + tvb_reported_length_remaining(tvb, offset);
	}

	frame_item = proto_tree_add_item(tree, hf_id3v2_frame, tvb, offset, -1, ENC_NA);
	frame_tree = proto_item_add_subtree(frame_item, ett_id3v2_frame);

	proto_tree_add_item(frame_tree, hf_id3v2_frame_id, tvb, offset, 4, ENC_ISO_8859_1);
	offset += 4;
	proto_item_set_text(frame_item, "%s", str_to_str(frame_id, id3v2_tag_names, "Unknown: %s"));

	if (id3_version == 0x04)
		size = decode_synchsafe_int(tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN));
	else
		size = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
	proto_tree_add_uint(frame_tree, hf_id3v2_frame_size, tvb, offset, 4, size);
	/* `size` does not include the 10-byte header */
	proto_item_set_len(frame_item, size+10);
	offset += 4;

	/* TODO: decode each flag */
	proto_tree_add_item(frame_tree, hf_id3v2_frame_flags, tvb, offset, 2, ENC_NA);
	offset += 2;

	if (frame_id[0] == 'T') {
		char *tv;

		tv = dissect_id3v2_text_frame(tvb, pinfo, frame_item, frame_tree, offset, size, !strcmp(frame_id, "TXXX"));
		offset += size;

		if (!strcmp(frame_id, "TIT2"))
			col_append_fstr(pinfo->cinfo, COL_INFO, "Title: %s, ", tv);
		if (!strcmp(frame_id, "TPE1"))
			col_append_fstr(pinfo->cinfo, COL_INFO, "Artist: %s, ", tv);
	} else if (!strcmp(frame_id, "UFID")) {
		unsigned text_length;
		char *text_value;

		text_value = tvb_get_stringz_enc(pinfo->pool, tvb, offset, &text_length, ENC_UTF_8);
		proto_tree_add_item(frame_tree, hf_id3v2_frame_ufi_owner, tvb, offset, text_length, ENC_ISO_8859_1);
		offset += text_length;
		proto_item_append_text(frame_item, " (Owner: %s)", text_value);

		DISSECTOR_ASSERT(size >= text_length);
		proto_tree_add_item(frame_tree, hf_id3v2_frame_ufi_id, tvb, offset, size-text_length, ENC_NA);
		offset += (size-text_length);
	} else if (!strcmp(frame_id, "APIC")) {
		dissect_id3v2_apic_frame(tvb, pinfo, frame_tree, offset, size);
		offset += size;
	} else if (!strcmp(frame_id, "COMM")) {
		dissect_id3v2_comment_frame(tvb, pinfo, frame_tree, offset, size, frame_item);
		offset += size;
	} else if (!strcmp(frame_id, "PRIV")) {
		proto_tree_add_item(frame_tree, hf_id3v2_frame_private, tvb, offset, size, ENC_NA);
		offset += size;
	} else {
		proto_item *pi;

		/* TODO: decode the rest */
		pi = proto_tree_add_item(frame_tree, hf_id3v2_undecoded, tvb, offset, size, ENC_NA);
		expert_add_info(pinfo, pi, &ei_id3v2_undecoded);
		offset += size;
	}

	return offset;
}

static int
dissect_id3v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *id3v2_item;
	proto_tree *id3v2_tree;
        tvbuff_t   *id3v2_tvb;
	unsigned    offset = 0;
	uint32_t    size;
	uint8_t     id3_version;

	/* Check that the packet is long enough for it to belong to us. */
	if (tvb_reported_length(tvb) < ID3V2_MIN_LENGTH)
		return 0;

	/* Check if the first 3 bytes are "ID3" */
	if (tvb_get_uint24(tvb, 0, ENC_BIG_ENDIAN) != 0x494433)
		return 0;

	/* Check if any of the high bits of the (synchsafe int) size are set */
	if (tvb_get_uint8(tvb, 7) & 0x80 ||
	    tvb_get_uint8(tvb, 8) & 0x80 ||
	    tvb_get_uint8(tvb, 9) & 0x80 ||
	    tvb_get_uint8(tvb, 10) & 0x80)
		return 0;

	/* Looks like this is ID3v2... */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ID3v2");
	col_clear(pinfo->cinfo, COL_INFO);

	size = decode_synchsafe_int(tvb_get_uint32(tvb, 6, ENC_BIG_ENDIAN));
	/* `size` does not include the 10-byte header */
        id3v2_tvb = tvb_new_subset_length(tvb, offset, size+10);
	id3v2_item = proto_tree_add_item(tree, hf_id3v2, id3v2_tvb, offset, tvb_captured_length(id3v2_tvb), ENC_NA);
	id3v2_tree = proto_item_add_subtree(id3v2_item, ett_id3v2);

	proto_tree_add_item(id3v2_tree, hf_id3v2_file_id, id3v2_tvb, offset, 3, ENC_ISO_8859_1);
	offset += 3;

	id3_version = tvb_get_uint8(tvb, offset); /* Fetch just the major version info */
	proto_tree_add_item(id3v2_tree, hf_id3v2_version, id3v2_tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* TODO: decode each flag */
	proto_tree_add_item(id3v2_tree, hf_id3v2_flags, id3v2_tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_uint(id3v2_tree, hf_id3v2_size, id3v2_tvb, offset, 4, size);
	offset += 4;

	/* TODO: detect and dissect extended header */

	while(tvb_reported_length_remaining(id3v2_tvb, offset)) {
		offset = dissect_id3v2_frame(id3v2_tvb, pinfo, id3v2_tree, offset, id3_version);
	}

	/* TODO: detect and dissect footer */

	return tvb_reported_length(id3v2_tvb);
}

void
proto_register_id3v2(void)
{
	expert_module_t *expert_id3v2;

	static hf_register_info hf[] = {
	    { &hf_id3v2,
	      { "ID3v2", "id3v2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_file_id,
	      { "File Identifier", "id3v2.file_id",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_version,
	      { "Version", "id3v2.version",
		FT_UINT16, BASE_HEX, VALS(id3v2_version_values), 0, NULL, HFILL }},
	    { &hf_id3v2_flags,
	      { "Flags", "id3v2.flags",
		FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_size,
	      { "Size", "id3v2.size",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame,
	      { "Frame", "id3v2.frame",
		FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_id,
	      { "Frame Identifier", "id3v2.frame.id",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_size,
	      { "Frame Size", "id3v2.frame.size",
		FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_flags,
	      { "Frame Flags", "id3v2.frame.flags",
		FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_text_encoding,
	      { "Text Encoding", "id3v2.frame.text_encoding",
		FT_UINT8, BASE_HEX, VALS(id3v2_text_encoding_values), 0, NULL, HFILL }},
	    { &hf_id3v2_frame_text_description,
	      { "Text description", "id3v2.frame.text_description",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_text_value,
	      { "Text value", "id3v2.frame.text_value",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_ufi_owner,
	      { "Unique file identifier owner", "id3v2.unique_file_identifier_owner",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_ufi_id,
	      { "Unique file identifier", "id3v2.unique_file_identifier",
		FT_BYTES, BASE_SHOW_UTF_8_PRINTABLE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_apic_mime_type,
	      { "Attached picture MIME type", "id3v2.apic.mime_type",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_apic_picture_type,
	      { "Attached picture type", "id3v2.apic.type",
		FT_UINT8, BASE_NONE, VALS(id3v2_apic_types), 0, NULL, HFILL }},
	    { &hf_id3v2_frame_apic_description,
	      { "Attached picture description", "id3v2.apic.description",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_private,
	      { "Private frame", "id3v2.private",
		FT_BYTES, BASE_SHOW_UTF_8_PRINTABLE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_comment_language,
	      { "Comment language", "id3v2.comment.language",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_comment_description,
	      { "Comment description", "id3v2.comment.description",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_frame_comment_text,
	      { "Comment text", "id3v2.comment.text",
		FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_undecoded,
	      { "Undecoded frame", "id3v2.undecoded",
		FT_BYTES, BASE_SHOW_UTF_8_PRINTABLE, NULL, 0, NULL, HFILL }},
	    { &hf_id3v2_padding,
	      { "Padding", "id3v2.padding",
		FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	};

	static int *ett[] = {
	    &ett_id3v2,
	    &ett_id3v2_frame,
	};

	static ei_register_info ei[] = {
	    { &ei_id3v2_undecoded,
	      { "id3v2.undecoded", PI_UNDECODED, PI_NOTE,
		"Undecoded frame", EXPFILL }
	    }
	};

	proto_id3v2 = proto_register_protocol("ID3v2", "ID3v2", "id3v2");

	proto_register_field_array(proto_id3v2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_id3v2 = expert_register_protocol(proto_id3v2);
	expert_register_field_array(expert_id3v2, ei, array_length(ei));

	/* Allow other dissectors to find this one by name. */
	register_dissector("id3v2", dissect_id3v2, proto_id3v2);
}

void
proto_reg_handoff_id3v2(void)
{
	media_type_dissector_table = find_dissector_table("media_type");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
