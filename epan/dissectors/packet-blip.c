/* packet-blip.c
 *
 * BLIP protocol for Couchbase Lite <-> Sync Gateway 2.0+ Replication
 *
 * Spec: https://github.com/couchbaselabs/BLIP-Cpp/blob/master/docs/BLIP%20Protocol.md
 *
 * Copyright 2018, Traun Leyden <traun@couchbase.com>
 * Copyright 2018, Jim Borden <jim.borden@couchbase.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include "proto_data.h"

#if defined(HAVE_ZLIB) && !defined(HAVE_ZLIBNG)
#define ZLIB_PREFIX(x) x
#include <zlib.h>
typedef z_stream zlib_stream;
#endif /* HAVE_ZLIB */

#ifdef HAVE_ZLIBNG
#define ZLIB_PREFIX(x) zng_ ## x
#include <zlib-ng.h>
typedef zng_stream zlib_stream;
#endif /* HAVE_ZLIBNG */
void proto_reg_handoff_blip(void);
void proto_register_blip(void);

#define BLIP_BODY_CHECKSUM_SIZE 4

// blip_conversation_entry_t is metadata that the blip dissector associates w/ each wireshark conversation
typedef struct {

	// Keep track of the largest frame number seen.  This is useful for determining whether
	// this is the first frame in a request message or not.

	// key: msgtype:srcport:destport:messagenumber -> value: frame number for the _first_ frame in this request message
	// Example: "MSG:23243:4984:56" -> 12
	// which means: "the first frame for blip message number 56, originating from source port 23243,
	//              ... and going to port 4984 for message type = MSG occurred in wireshark packet #12"
	wmem_map_t *blip_requests;

#if defined(HAVE_ZLIB) || defined(HAVE_ZLIBNG)
	// The streams used to decode a particular connection.	These are per direction and per connection.
	wmem_map_t *decompress_streams;
#endif
} blip_conversation_entry_t;

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
typedef enum
{
	no_error = 0,
	zlib_error,
	overflow_error
} decompress_error_t;

typedef struct
{
	decompress_error_t domain;
	int code;
	size_t size;
	void* buf;
} decompress_result_t;
#endif

// File level variables
static dissector_handle_t blip_handle;
static int proto_blip;
static int hf_blip_message_number;
static int hf_blip_frame_flags;
static int hf_blip_properties_length;
static int hf_blip_properties;
static int hf_blip_message_body;
static int hf_blip_ack_size;
static int hf_blip_checksum;

static int ett_blip;

static expert_field ei_blip_decompress_buffer_error;

// Compressed = 0x08
// Urgent	  = 0x10
// NoReply	  = 0x20
// MoreComing = 0x40
// In ascending order so that a binary search will be used as per the
// README.dissector
static const value_string flag_combos[] = {
	{ 0x00, "None" },
	{ 0x08, "Compressed" },
	{ 0x10, "Urgent" },
	{ 0x10|0x08, "Compressed|Urgent" },
	{ 0x20, "NoReply" },
	{ 0x20|0x08, "Compressed|NoReply" },
	{ 0x20|0x10, "Urgent|NoReply" },
	{ 0x20|0x10|0x08, "Compressed|Urgent|NoReply" },
	{ 0x40, "MoreComing" },
	{ 0x40|0x08, "Compressed|MoreComing" },
	{ 0x40|0x10, "Urgent|MoreComing" },
	{ 0x40|0x10|0x08, "Compressed|Urgent|MoreComing" },
	{ 0x40|0x20, "NoReply|MoreComing" },
	{ 0x40|0x20|0x08, "Compressed|NoReply|MoreComing" },
	{ 0x40|0x20|0x10, "Urgent|NoReply|MoreComing" },
	{ 0x40|0x20|0x10|0x08, "Compressed|Urgent|NoReply|MoreComing" },
	{ 0, NULL }
};

static value_string_ext flag_combos_ext = VALUE_STRING_EXT_INIT(flag_combos);

static const val64_string msg_types[] = {
	{ 0x00ll, "MSG" },
	{ 0x01ll, "RPY" },
	{ 0x02ll, "ERR" },
	{ 0x04ll, "ACKMSG" },
	{ 0x05ll, "ACKRPY" },
	{ 0, NULL }
};

// Preferences
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
static unsigned max_uncompressed_size = 64; // Max uncompressed body size in Kb
#endif

// MSG =	0x00
// RPY =	0x01
// ERR =	0x02
// ACKMSG = 0x04
// ACKRPY = 0x05
static const char*
get_message_type(uint64_t value_frame_flags)
{
	// Mask out the least significant bits: 0000 0111
	uint64_t type_mask_val = (0x07ll & value_frame_flags);
	return val64_to_str_const(type_mask_val, msg_types, "???");
}

static bool
is_ack_message(uint64_t value_frame_flags) {
	// Note, even though this is a 64-bit int, only the least significant byte has meaningful information,
	// since frame flags all fit into one byte at the time this code was written.

	// Mask out the least significant bits: 0000 0111
	uint64_t type_mask_val = (0x07ll & value_frame_flags);

	// ACKMSG
	if (type_mask_val == 0x04ll) {
		return true;
	}

	// ACKRPY
	if (type_mask_val == 0x05ll) {
		return true;
	}

	return false;
}

static bool
is_compressed(uint64_t value_frame_flags)
{
	// Note, even though this is a 64-bit int, only the least significant byte has meaningful information,
	// since frame flags all fit into one byte at the time this code was written.

	if ((0x08ll & value_frame_flags) == 0x08ll) {
		return true;
	}

	return false;

}

static char*
message_hash_key_convo(packet_info *pinfo,
				  uint64_t value_frame_flags,
				  uint64_t value_message_num)
{
	// Derive the hash key to use
	// msgtype:srcport:destport:messagenum

	const char *msg_type = get_message_type(value_frame_flags);
	char *hash_key = wmem_strdup_printf(pinfo->pool, "%s:%u:%u:%" PRIu64,
			msg_type, pinfo->srcport, pinfo->destport, value_message_num);

	return hash_key;
}

// Finds out whether this is the first blip frame in the blip message (which can consist of a series of frames).
// If it is, updates the conversation_entry_ptr->blip_requests hash to record the pinfo->num (wireshark packet number)
static bool
is_first_frame_in_msg(blip_conversation_entry_t *conversation_entry_ptr, packet_info *pinfo,
					  uint64_t value_frame_flags, uint64_t value_message_num) {

	bool first_frame_in_msg = true;

	// Temporary pool for the lookup hash_key.	Will get duplicated on the file_scope() pool if needed to be
	// stored in the hashtable.
	char *hash_key = message_hash_key_convo(pinfo, value_frame_flags, value_message_num);
	unsigned* first_frame_number_for_msg = (unsigned*)wmem_map_lookup(conversation_entry_ptr->blip_requests, (void *) hash_key);

	if (first_frame_number_for_msg != NULL) {
		if (GPOINTER_TO_UINT(first_frame_number_for_msg) != pinfo->num) {
			first_frame_in_msg = false;
		}
	} else {
		// If storing the key in the hashmap, re-allocate it with the file_scope() allocator
		char *hash_key_copy = wmem_strdup(wmem_file_scope(), hash_key);

		wmem_map_insert(conversation_entry_ptr->blip_requests, (void *) hash_key_copy, GUINT_TO_POINTER(pinfo->num));
	}

	return first_frame_in_msg;
}

static int
handle_ack_message(tvbuff_t *tvb, _U_ packet_info *pinfo, proto_tree *blip_tree, int offset, _U_ uint64_t value_frame_flags)
{
	// This gets the number of ack bytes received  as a var int in order to find out how much to bump
	// the offset for the next proto_tree item
	uint64_t value_ack_size;
	unsigned varint_ack_size_length = tvb_get_varint(
			tvb,
			offset,
			FT_VARINT_MAX_LEN,
			&value_ack_size,
			ENC_VARINT_PROTOBUF);

	proto_tree_add_item(blip_tree, hf_blip_ack_size, tvb, offset, varint_ack_size_length, ENC_VARINT_PROTOBUF);

	return tvb_captured_length(tvb);
}

static blip_conversation_entry_t*
get_blip_conversation(packet_info* pinfo)
{
	// Create a new conversation if needed and associate the blip_conversation_entry_t with it
	// Adapted from sample code in doc/README.dissector
	conversation_t *conversation;
	conversation = find_or_create_conversation(pinfo);
	blip_conversation_entry_t *conversation_entry_ptr = (blip_conversation_entry_t*)conversation_get_proto_data(conversation, proto_blip);
	if (conversation_entry_ptr == NULL) {

		// create a new blip_conversation_entry_t
		conversation_entry_ptr = wmem_new(wmem_file_scope(), blip_conversation_entry_t);

		// create a new hash map and save a reference in blip_conversation_entry_t
		conversation_entry_ptr->blip_requests = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);
#if defined(HAVE_ZLIB) || defined(HAVE_ZLIBNG)
		conversation_entry_ptr->decompress_streams = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
#endif
		conversation_add_proto_data(conversation, proto_blip, conversation_entry_ptr);
	}

	return conversation_entry_ptr;
}

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
static bool
z_stream_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
	zlib_stream*decompress_stream = (zlib_stream*)user_data;
        ZLIB_PREFIX(inflateEnd)(decompress_stream);
	return false;
}

static zlib_stream*
get_decompress_stream(packet_info* pinfo)
{
	const blip_conversation_entry_t* blip_convo = get_blip_conversation(pinfo);

	// Store compression state per srcport/destport.
	uint32_t hash_key = (pinfo->srcport << 16) | pinfo->destport;
        zlib_stream* decompress_stream = (zlib_stream*)wmem_map_lookup(blip_convo->decompress_streams, GUINT_TO_POINTER(hash_key));
	if(decompress_stream) {
		return decompress_stream;
	}

	decompress_stream = wmem_new0(wmem_file_scope(), zlib_stream);
	wmem_map_insert(blip_convo->decompress_streams, GUINT_TO_POINTER(hash_key), decompress_stream);
	wmem_register_callback(wmem_file_scope(), z_stream_destroy_cb, decompress_stream);

	return decompress_stream;
}

static tvbuff_t*
decompress(packet_info* pinfo, proto_tree* tree, tvbuff_t* tvb, int offset, int length)
{
	if(PINFO_FD_VISITED(pinfo)) {
		const decompress_result_t* saved_data = (decompress_result_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_blip, 0);
		if(!saved_data) {
			proto_tree_add_string(tree, hf_blip_message_body, tvb, offset, tvb_reported_length_remaining(tvb, offset), "<Error decompressing data>");
			return NULL;
		}

		if(saved_data->domain) {
			proto_item* field = proto_tree_add_string(tree, hf_blip_message_body, tvb, offset, tvb_reported_length_remaining(tvb, offset), "<Error decompressing data>");
			if(saved_data->domain == zlib_error) {
				expert_add_info_format(pinfo, field, &ei_blip_decompress_buffer_error, "Unable to decompress message, got zlib error %d", saved_data->code);
			} else {
				expert_add_info_format(pinfo, field, &ei_blip_decompress_buffer_error, "Unable to decompress message, buffer too small (%u Kb).  Please adjust in settings.", max_uncompressed_size);
			}

			return NULL;
		} else {
			tvbuff_t* decompressedChild = tvb_new_child_real_data(tvb, (uint8_t *)saved_data->buf,
				(int)saved_data->size, (int)saved_data->size);
			add_new_data_source(pinfo, decompressedChild, "Decompressed Payload");
			return decompressedChild;
		}
	}

	static bool size_overflow = false;
	const uint8_t* buf = tvb_get_ptr(tvb, offset, length);
        zlib_stream* decompress_stream = get_decompress_stream(pinfo);
	static Byte trailer[4] = { 0x00, 0x00, 0xff, 0xff };
	if(!decompress_stream->next_out) {
		decompress_stream->zalloc = 0;
		decompress_stream->zfree = 0;
		decompress_stream->opaque = 0;
		int err = ZLIB_PREFIX(inflateInit2)(decompress_stream, -MAX_WBITS);
		if(err != Z_OK) {
			decompress_stream->next_out = 0;
			REPORT_DISSECTOR_BUG("Unable to create INFLATE context to decompress messages");
			return NULL;
		}
	}

	// Create a temporary buffer of the maximum size, which will get cleaned up later
	// when the packet scope is freed
	uInt buffer_size = max_uncompressed_size * 1024;
	Bytef* decompress_buffer = (Bytef*)wmem_alloc(pinfo->pool, buffer_size);
	decompress_stream->next_in = (Bytef*)buf;
	decompress_stream->avail_in = length;
	decompress_stream->next_out = decompress_buffer;
	decompress_stream->avail_out = buffer_size;
	uLong start = decompress_stream->total_out;
	int err = ZLIB_PREFIX(inflate)(decompress_stream, Z_NO_FLUSH);
	if(err != Z_OK) {
		proto_item* field = proto_tree_add_string(tree, hf_blip_message_body, tvb, offset, tvb_reported_length_remaining(tvb, offset), "<Error decompressing data>");
		decompress_result_t* data_to_save = wmem_new0(wmem_file_scope(), decompress_result_t);
		if(size_overflow && err == Z_DATA_ERROR) {
			data_to_save->domain = overflow_error;
			expert_add_info_format(pinfo, field, &ei_blip_decompress_buffer_error, "Unable to decompress message, buffer too small (%u Kb).  Please adjust in settings.", max_uncompressed_size);
		} else {
			data_to_save->domain = zlib_error;
			data_to_save->code = err;
			expert_add_info_format(pinfo, field, &ei_blip_decompress_buffer_error, "Unable to decompress message, got zlib error %d", err);
		}

		p_add_proto_data(wmem_file_scope(), pinfo, proto_blip, 0, data_to_save);
		return NULL;
	}

	decompress_stream->next_in = trailer;
	decompress_stream->avail_in = 4;
	err = ZLIB_PREFIX(inflate)(decompress_stream, Z_SYNC_FLUSH);
	if(err != Z_OK) {
		proto_item* field = proto_tree_add_string(tree, hf_blip_message_body, tvb, offset, tvb_reported_length_remaining(tvb, offset), "<Error decompressing data>");
		decompress_result_t* data_to_save = wmem_new0(wmem_file_scope(), decompress_result_t);
		if(err == Z_BUF_ERROR) {
			data_to_save->domain = overflow_error;
			size_overflow = true;
			expert_add_info_format(pinfo, field, &ei_blip_decompress_buffer_error, "Unable to decompress message, buffer too small (%u Kb).  Please adjust in settings.", max_uncompressed_size);
		} else {
			data_to_save->domain = zlib_error;
			data_to_save->code = err;
			expert_add_info_format(pinfo, field, &ei_blip_decompress_buffer_error, "Unable to decompress message, got zlib error %d", err);
		}

		p_add_proto_data(wmem_file_scope(), pinfo, proto_blip, 0, data_to_save);
		return NULL;
	}

	// Shrink the buffer so that there is not wasted space on the end of it since
	// it will be long lived in the file scope
	uLong bodyLength = decompress_stream->total_out - start;
	Bytef* shortened_buffer = (Bytef *)wmem_memdup(wmem_file_scope(), decompress_buffer, bodyLength);

	tvbuff_t* decompressedChild = tvb_new_child_real_data(tvb, shortened_buffer, (unsigned)bodyLength, (int)bodyLength);
	add_new_data_source(pinfo, decompressedChild, "Decompressed Payload");
	decompress_result_t* data_to_save = wmem_new0(wmem_file_scope(), decompress_result_t);
	data_to_save->size = (size_t)bodyLength;
	data_to_save->buf = shortened_buffer;
	p_add_proto_data(wmem_file_scope(), pinfo, proto_blip, 0, data_to_save);

	return decompressedChild;
}
#endif /* HAVE_ZLIB */

static int
dissect_blip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, _U_ void *data)
{

	proto_tree *blip_tree;
	int offset = 0;

	/* Set the protocol column to say BLIP */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLIP");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	// ------------------------------------- Setup BLIP tree -----------------------------------------------------------


	/* Add a subtree to dissection.  See WSDG 9.2.2. Dissecting the details of the protocol  */
	proto_item *blip_item = proto_tree_add_item(tree, proto_blip, tvb, offset, -1, ENC_NA);

	blip_tree = proto_item_add_subtree(blip_item, ett_blip);


	// ------------------------ BLIP Frame Header: Message Number VarInt -----------------------------------------------

	// This gets the message number as a var int in order to find out how much to bump
	// the offset for the next proto_tree item
	uint64_t value_message_num;
	unsigned varint_message_num_length = tvb_get_varint(
			tvb,
			offset,
			FT_VARINT_MAX_LEN,
			&value_message_num,
			ENC_VARINT_PROTOBUF);

	proto_tree_add_item(blip_tree, hf_blip_message_number, tvb, offset, varint_message_num_length, ENC_VARINT_PROTOBUF);

	offset += varint_message_num_length;

	// ------------------------ BLIP Frame Header: Frame Flags VarInt --------------------------------------------------

	// This gets the message number as a var int in order to find out how much to bump
	// the offset for the next proto_tree item
	uint64_t value_frame_flags;
	unsigned varint_frame_flags_length = tvb_get_varint(
			tvb,
			offset,
			FT_VARINT_MAX_LEN,
			&value_frame_flags,
			ENC_VARINT_PROTOBUF);

	uint64_t masked = value_frame_flags & ~0x07;
	proto_tree_add_uint(blip_tree, hf_blip_frame_flags, tvb, offset, varint_frame_flags_length, (uint8_t)masked);

	offset += varint_frame_flags_length;

	const char* msg_type = get_message_type(value_frame_flags);
	char* msg_num = wmem_strdup_printf(pinfo->pool, "#%" PRIu64, value_message_num);
	char* col_info = wmem_strconcat(pinfo->pool, msg_type, msg_num, NULL);
	col_add_str(pinfo->cinfo, COL_INFO, col_info);

	// If it's an ACK message, handle that separately, since there are no properties etc.
	if (is_ack_message(value_frame_flags) == true) {
		return handle_ack_message(tvb, pinfo, blip_tree, offset, value_frame_flags);
	}


	// ------------------------------------- Conversation Tracking -----------------------------------------------------

	blip_conversation_entry_t *conversation_entry_ptr = get_blip_conversation(pinfo);

	// Is this the first frame in a blip message with multiple frames?
	bool first_frame_in_msg = is_first_frame_in_msg(
			conversation_entry_ptr,
			pinfo,
			value_frame_flags,
			value_message_num
	);

	tvbuff_t* tvb_to_use = tvb;
	bool compressed = is_compressed(value_frame_flags);

	if(compressed) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
		tvb_to_use = decompress(pinfo, blip_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset) - BLIP_BODY_CHECKSUM_SIZE);
		if(!tvb_to_use) {
			return tvb_reported_length(tvb);
		}
		offset = 0;
#else /* ! HAVE_ZLIB */
		proto_tree_add_string(tree, hf_blip_message_body, tvb, offset, tvb_reported_length_remaining(tvb, offset), "<decompression support is not available>");
		return tvb_reported_length(tvb);
#endif /* ! HAVE_ZLIB */
	}

	// Is this the first frame in a message?
	if (first_frame_in_msg == true) {

		// ------------------------ BLIP Frame Header: Properties Length VarInt --------------------------------------------------

		// WARNING: this only works because this code assumes that ALL MESSAGES FIT INTO ONE FRAME, which is absolutely not true.
		// In other words, as soon as there is a message that spans two frames, this code will break.

		uint64_t value_properties_length;
		unsigned value_properties_length_varint_length = tvb_get_varint(
				tvb_to_use,
				offset,
				FT_VARINT_MAX_LEN,
				&value_properties_length,
				ENC_VARINT_PROTOBUF);

		proto_tree_add_item(blip_tree, hf_blip_properties_length, tvb_to_use, offset, value_properties_length_varint_length, ENC_VARINT_PROTOBUF);

		offset += value_properties_length_varint_length;

		// ------------------------ BLIP Frame: Properties --------------------------------------------------

		// WARNING: this only works because this code assumes that ALL MESSAGES FIT INTO ONE FRAME, which is absolutely not true.
		// In other words, as soon as there is a message that spans two frames, this code will break.

		// At this point, the length of the properties is known and is stored in value_properties_length.
		// This reads the entire properties out of the tvb and into a buffer (buf).
		uint8_t* buf = tvb_get_string_enc(pinfo->pool, tvb_to_use, offset, (int) value_properties_length, ENC_UTF_8);

		// "Profile\0subChanges\0continuous\0true\0foo\0bar" -> "Profile:subChanges:continuous:true:foo:bar"
		// Iterate over buf and change all the \0 null characters to ':', since otherwise trying to set a header
		// field to this buffer via proto_tree_add_item() will end up only printing it up to the first null character,
		// for example "Profile", even though there are many more properties that follow.
		for (int i = 0; i < (int) value_properties_length; i++) {
			if (i < (int) (value_properties_length - 1)) {
				if (buf[i] == '\0') {  // TODO: I don't even know if this is actually a safe assumption in a UTF-8 encoded string
					buf[i] = ':';
				}
			}
		}

		if(value_properties_length > 0) {
			proto_tree_add_string(blip_tree, hf_blip_properties, tvb_to_use, offset, (int)value_properties_length, (const char *)buf);
		}

		// Bump the offset by the length of the properties
		offset += (int)value_properties_length;
	}

	// ------------------------ BLIP Frame: Message Body --------------------------------------------------

	// WS_DLL_PUBLIC int tvb_reported_length_remaining(const tvbuff_t *tvb, const int offset);
	int reported_length_remaining = tvb_reported_length_remaining(tvb_to_use, offset);

	// Don't read in the trailing checksum at the end
	if (!compressed && reported_length_remaining >= BLIP_BODY_CHECKSUM_SIZE) {
		reported_length_remaining -= BLIP_BODY_CHECKSUM_SIZE;
	}

	if(reported_length_remaining > 0) {
		proto_tree_add_item(blip_tree, hf_blip_message_body, tvb_to_use, offset, reported_length_remaining, ENC_UTF_8);
	}

	proto_tree_add_item(blip_tree, hf_blip_checksum, tvb, tvb_reported_length(tvb) - BLIP_BODY_CHECKSUM_SIZE, BLIP_BODY_CHECKSUM_SIZE, ENC_BIG_ENDIAN);

	// -------------------------------------------- Etc ----------------------------------------------------------------

	return tvb_captured_length(tvb);
}

void
proto_register_blip(void)
{
	static hf_register_info hf[] = {
	{ &hf_blip_message_number,
		{ "Message Number", "blip.messagenum", FT_UINT64, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
	},
	{ &hf_blip_frame_flags,
		{ "Frame Flags", "blip.frameflags", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
			&flag_combos_ext, 0x0, NULL, HFILL }
	},
	{ &hf_blip_properties_length,
		{ "Properties Length", "blip.propslength", FT_UINT64, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
	},
	{ &hf_blip_properties,
		{ "Properties", "blip.props", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
	{ &hf_blip_message_body,
		{ "Message Body", "blip.messagebody", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
	},
	{ &hf_blip_ack_size,
		{ "ACK num bytes", "blip.numackbytes", FT_UINT64, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
	},
	{ &hf_blip_checksum,
		{ "Checksum", "blip.checksum", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
	}
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_blip
	};

	/* Expert Infos */
	static ei_register_info ei[] = {
		{ &ei_blip_decompress_buffer_error, { "blip.decompress_buffer_error", PI_UNDECODED, PI_WARN, "Decompression error", EXPFILL }}
	};

	proto_blip = proto_register_protocol("BLIP Couchbase Mobile", "BLIP", "blip");
	expert_module_t* expert_blip = expert_register_protocol(proto_blip);

	proto_register_field_array(proto_blip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_register_field_array(expert_blip, ei, array_length(ei));

	blip_handle = register_dissector("blip", dissect_blip, proto_blip);

#ifdef HAVE_ZLIB
	module_t *blip_module = prefs_register_protocol(proto_blip, NULL);
	prefs_register_uint_preference(blip_module, "max_uncompressed_size",
						"Maximum uncompressed message size (Kb)",
						"The maximum size of the buffer for uncompressed messages. "
						"If a message is larger than this, then the packet containing "
						"the message, as well as subsequent packets, will fail to "
						"decompress", 10, &max_uncompressed_size);
#endif
}

void
proto_reg_handoff_blip(void)
{

	// Register the blip dissector as a subprotocol dissector of "ws.protocol",
	// matching any packets with a Web-Sec-Protocol header of "BLIP_3+CBMobile_2"
	// or "BLIP_3+CBMobile_3"
	//
	// See https://github.com/couchbase/sync_gateway/issues/3356#issuecomment-370958321 for
	// more notes on how the websocket dissector routes packets down to subprotocol handlers.

	dissector_add_string("ws.protocol", "BLIP_3+CBMobile_3", blip_handle);
	dissector_add_string("ws.protocol", "BLIP_3+CBMobile_2", blip_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * ex: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
