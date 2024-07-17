/* packet-dbus.c
 * Routines for D-Bus dissection
 * Copyright 2012, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 * Copyright 2020, Simon Holesch <simon@holesch.de>
 *
 * Protocol specification available at http://dbus.freedesktop.org/doc/dbus-specification.html
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include <epan/ptvcursor.h>
#include <wsutil/ws_roundup.h>
#include <epan/conversation.h>
#include "packet-tcp.h"

#define DBUS_MAX_ARRAY_LEN (64 * 1024 * 1024)
#define DBUS_MAX_NAME_LENGTH 255
#define DBUS_MAX_SIGNATURE_LENGTH 255
#define DBUS_MAX_TYPE_NESTING_LEVEL 32
#define DBUS_MAX_TOTAL_NESTING_LEVEL (2 * DBUS_MAX_TYPE_NESTING_LEVEL)

#define SIG_CODE_BYTE ('y')
#define SIG_CODE_BOOLEAN ('b')
#define SIG_CODE_INT16 ('n')
#define SIG_CODE_UINT16 ('q')
#define SIG_CODE_INT32 ('i')
#define SIG_CODE_UINT32 ('u')
#define SIG_CODE_INT64 ('x')
#define SIG_CODE_UINT64 ('t')
#define SIG_CODE_DOUBLE ('d')
#define SIG_CODE_STRING ('s')
#define SIG_CODE_OBJECT_PATH ('o')
#define SIG_CODE_SIGNATURE ('g')
#define SIG_CODE_ARRAY ('a')
#define SIG_CODE_STRUCT_OPEN ('(')
#define SIG_CODE_STRUCT_CLOSE (')')
#define SIG_CODE_VARIANT ('v')
#define SIG_CODE_DICT_ENTRY_OPEN ('{')
#define SIG_CODE_DICT_ENTRY_CLOSE ('}')
#define SIG_CODE_UNIX_FD ('h')

void proto_register_dbus(void);
void proto_reg_handoff_dbus(void);

static int proto_dbus;
static bool dbus_desegment = true;
static bool dbus_resolve_names = true;

static dissector_handle_t dbus_handle;
static dissector_handle_t dbus_handle_tcp;

#define DBUS_MESSAGE_TYPE_INVALID 0
#define DBUS_MESSAGE_TYPE_METHOD_CALL 1
#define DBUS_MESSAGE_TYPE_METHOD_RETURN 2
#define DBUS_MESSAGE_TYPE_ERROR 3
#define DBUS_MESSAGE_TYPE_SIGNAL 4

static const value_string message_type_vals[] = {
	{ DBUS_MESSAGE_TYPE_INVALID, "Invalid" },
	{ DBUS_MESSAGE_TYPE_METHOD_CALL, "Method call" },
	{ DBUS_MESSAGE_TYPE_METHOD_RETURN, "Method reply" },
	{ DBUS_MESSAGE_TYPE_ERROR, "Error reply" },
	{ DBUS_MESSAGE_TYPE_SIGNAL, "Signal emission" },
	{ 0, NULL }
};

#define DBUS_HEADER_FIELD_INVALID        0
#define DBUS_HEADER_FIELD_PATH           1
#define DBUS_HEADER_FIELD_INTERFACE      2
#define DBUS_HEADER_FIELD_MEMBER         3
#define DBUS_HEADER_FIELD_ERROR_NAME     4
#define DBUS_HEADER_FIELD_REPLY_SERIAL   5
#define DBUS_HEADER_FIELD_DESTINATION    6
#define DBUS_HEADER_FIELD_SENDER         7
#define DBUS_HEADER_FIELD_SIGNATURE      8
#define DBUS_HEADER_FIELD_UNIX_FDS       9

static const value_string field_code_vals[] = {
	{ DBUS_HEADER_FIELD_INVALID, "Invalid" },
	{ DBUS_HEADER_FIELD_PATH, "Path" },
	{ DBUS_HEADER_FIELD_INTERFACE, "Interface" },
	{ DBUS_HEADER_FIELD_MEMBER, "Member" },
	{ DBUS_HEADER_FIELD_ERROR_NAME, "Error name" },
	{ DBUS_HEADER_FIELD_REPLY_SERIAL, "Reply serial" },
	{ DBUS_HEADER_FIELD_DESTINATION, "Destination" },
	{ DBUS_HEADER_FIELD_SENDER, "sender" },
	{ DBUS_HEADER_FIELD_SIGNATURE, "Signature" },
	{ DBUS_HEADER_FIELD_UNIX_FDS, "Unix FDs" },
	{ 0, NULL }
};

static const value_string endianness_vals[] = {
	{ 'l', "little-endian" },
	{ 'B', "big-endian" },
	{ 0, NULL }
};

#define DBUS_FLAGS_NO_REPLY_EXPECTED_MASK 0x01
#define DBUS_FLAGS_NO_AUTO_START_MASK 0x02
#define DBUS_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION_MASK 0x04

static const true_false_string allow_vals = { "Allow", "Don't allow" };
static const true_false_string no_start_vals = { "Don't start", "Start" };
static const true_false_string not_expected_vals = { "Not expected", "Expected" };

static int hf_dbus_endianness;
static int hf_dbus_message_type;
static int hf_dbus_flags;
static int hf_dbus_flags_no_reply_expected;
static int hf_dbus_flags_no_auto_start;
static int hf_dbus_flags_allow_interactive_authorization;
static int hf_dbus_version;
static int hf_dbus_body_length;
static int hf_dbus_serial;
static int hf_dbus_field_code;
static int hf_dbus_padding;
static int hf_dbus_path;
static int hf_dbus_interface;
static int hf_dbus_member;
static int hf_dbus_error_name;
static int hf_dbus_reply_serial;
static int hf_dbus_destination;
static int hf_dbus_sender;
static int hf_dbus_signature;
static int hf_dbus_unix_fds;
static int hf_dbus_body;
static int hf_dbus_type_byte;
static int hf_dbus_type_boolean;
static int hf_dbus_type_int16;
static int hf_dbus_type_uint16;
static int hf_dbus_type_int32;
static int hf_dbus_type_uint32;
static int hf_dbus_type_int64;
static int hf_dbus_type_uint64;
static int hf_dbus_type_double;
static int hf_dbus_type_string;
static int hf_dbus_type_object_path;
static int hf_dbus_type_signature;
static int hf_dbus_type_array;
static int hf_dbus_type_array_length;
static int hf_dbus_type_struct;
static int hf_dbus_type_variant;
static int hf_dbus_type_variant_signature;
static int hf_dbus_type_dict_entry;
static int hf_dbus_type_dict_entry_key;
static int hf_dbus_type_unix_fd;
static int hf_dbus_response_in;
static int hf_dbus_response_to;
static int hf_dbus_response_time;

static int ett_dbus;
static int ett_dbus_flags;
static int ett_dbus_header_field_array;
static int ett_dbus_header_field;
static int ett_dbus_body;
static int ett_dbus_type_array;
static int ett_dbus_type_struct;
static int ett_dbus_type_variant;
static int ett_dbus_type_dict_entry;

static expert_field ei_dbus_endianness_invalid;
static expert_field ei_dbus_message_type_invalid;
static expert_field ei_dbus_message_type_unknown;
static expert_field ei_dbus_version_invalid;
static expert_field ei_dbus_serial_invalid;
static expert_field ei_dbus_field_code_invalid;
static expert_field ei_dbus_required_header_field_missing;
static expert_field ei_dbus_padding_invalid;
static expert_field ei_dbus_field_signature_wrong;
static expert_field ei_dbus_interface_invalid;
static expert_field ei_dbus_member_invalid;
static expert_field ei_dbus_error_name_invalid;
static expert_field ei_dbus_bus_name_invalid;
static expert_field ei_dbus_type_boolean_invalid;
static expert_field ei_dbus_string_invalid;
static expert_field ei_dbus_type_signature_invalid;
static expert_field ei_dbus_type_array_too_long;
static expert_field ei_dbus_type_array_content_out_of_bounds;
static expert_field ei_dbus_type_object_path_invalid;
static expert_field ei_dbus_type_variant_signature_invalid;
static expert_field ei_dbus_nested_too_deeply;

typedef struct {
	ptvcursor_t *cursor;
	packet_info *pinfo;
	unsigned enc;
	uint32_t message_type;
	uint8_t flags;
	uint32_t body_len;
	uint32_t serial;

	proto_item *current_pi;
	const char *path;
	const char *interface;
	const char *member;
	const char *error_name;
	uint32_t reply_serial;
	const char *destination;
	const char *sender;
	const char *signature;
	uint32_t unix_fds;
} dbus_packet_t;

typedef struct _dbus_type_reader_t {
	dbus_packet_t *packet;
	const char *signature;
	uint32_t level;
	uint32_t array_level;
	uint32_t struct_level;
	uint32_t dict_entry_level;
	const char *array_type_start;
	int array_end_offset;
	bool is_in_variant;
	bool is_basic_variant;
	bool is_in_dict_entry;
	bool is_basic_dict_entry;
	proto_item *container;
	struct _dbus_type_reader_t *parent;
} dbus_type_reader_t;

typedef union {
	bool bool_;
	uint32_t uint;
	int32_t int_;
	uint64_t uint64;
	int64_t int64;
	double double_;
	const char *string;
} dbus_val_t;

typedef struct {
	uint32_t req_frame;
	uint32_t rep_frame;
	nstime_t req_time;
	const char *path;
	const char *interface;
	const char *member;
} dbus_transaction_t;

typedef struct {
	wmem_map_t *packets;
} dbus_conv_info_t;

static wmem_map_t *request_info_map;
static wmem_map_t *unique_name_map;

static bool
is_ascii_digit(char c) {
	return (unsigned)c - '0' < 10;
}

static bool
is_ascii_alpha(char c) {
	return ((unsigned)c | 0x20) - 'a' <= 'z' - 'a';
}

static bool
is_dbus_object_path_valid(const char *path) {
	// - The path may be of any length.
	// - The path must begin with an ASCII '/' (integer 47) character, and must consist of elements separated by
	//   slash characters.
	// - Each element must only contain the ASCII characters "[A-Z][a-z][0-9]_"
	// - No element may be the empty string.
	// - Multiple '/' characters cannot occur in sequence.
	// - A trailing '/' character is not allowed unless the path is the root path (a single '/' character).
	if (*path == '/' && *(path + 1) == '\0') {
		return true;
	}

	while (*path == '/') {
		path++;

		if (*path == '/') {
			return false;
		}

		while (is_ascii_alpha(*path) || is_ascii_digit(*path) || *path == '_') {
			path++;
		}

		if (*path == '\0') {
			return *(path - 1) != '/';
		}
	}

	return false;
}

static bool
is_dbus_interface_valid(const char *interface) {
	// - Interface names are composed of 2 or more elements separated by a period ('.') character. All elements
	//   must contain at least one character.
	// - Each element must only contain the ASCII characters "[A-Z][a-z][0-9]_" and must not begin with a digit.
	// - Interface names must not exceed the maximum name length.
	int elements = 0;
	const char *p = interface;
	do {
		if (!(is_ascii_alpha(*p) || *p == '_')) {
			return false;
		}
		p++;
		elements++;

		while (is_ascii_alpha(*p) || is_ascii_digit(*p) || *p == '_') {
			p++;
		}

		if (*p == '\0') {
			size_t length = p - interface;
			return elements >= 2 && length <= DBUS_MAX_NAME_LENGTH;
		}
	} while (*p++ == '.');

	return false;
}

static bool
is_dbus_member_name_valid(const char *member_name) {
	// - Must only contain the ASCII characters "[A-Z][a-z][0-9]_" and may not begin with a digit.
	// - Must not contain the '.' (period) character.
	// - Must not exceed the maximum name length.
	// - Must be at least 1 byte in length.
	const char *p = member_name;

	if (!(is_ascii_alpha(*p) || *p == '_')) {
		return false;
	}

	do {
		p++;
	} while (is_ascii_alpha(*p) || is_ascii_digit(*p) || *p == '_');

	if (*p == '\0') {
		size_t length = p - member_name;
		return length <= DBUS_MAX_NAME_LENGTH;
	}

	return false;
}

static bool
is_dbus_bus_name_valid(const char *bus_name) {
	// - Bus names that start with a colon (':') character are unique connection names. Other bus names are called
	//   well-known bus names.
	// - Bus names are composed of 1 or more elements separated by a period ('.') character. All elements must
	//   contain at least one character.
	// - Each element must only contain the ASCII characters "[A-Z][a-z][0-9]_-", with "-" discouraged in new bus
	//   names. Only elements that are part of a unique connection name may begin with a digit, elements in other
	//   bus names must not begin with a digit.
	// - Bus names must contain at least one '.' (period) character (and thus at least two elements).
	// - Bus names must not begin with a '.' (period) character.
	// - Bus names must not exceed the maximum name length.
	int elements = 0;
	const char *p = bus_name;
	bool is_unique_name = false;

	if (*p == ':') {
		is_unique_name = true;
		p++;
	}

	do {
		if (!(is_ascii_alpha(*p) || *p == '_' || *p == '-' || (is_unique_name && is_ascii_digit(*p)))) {
			return false;
		}
		p++;
		elements++;

		while (is_ascii_alpha(*p) || is_ascii_digit(*p) || *p == '_' || *p == '-') {
			p++;
		}

		if (*p == '\0') {
			size_t length = p - bus_name;
			return elements >= 2 && length <= DBUS_MAX_NAME_LENGTH;
		}
	} while (*p++ == '.');

	return false;
}

static bool
is_basic_type(char sig_code) {
	switch (sig_code) {
	case SIG_CODE_BYTE:
	case SIG_CODE_BOOLEAN:
	case SIG_CODE_INT16:
	case SIG_CODE_UINT16:
	case SIG_CODE_INT32:
	case SIG_CODE_UINT32:
	case SIG_CODE_INT64:
	case SIG_CODE_UINT64:
	case SIG_CODE_DOUBLE:
	case SIG_CODE_STRING:
	case SIG_CODE_OBJECT_PATH:
	case SIG_CODE_SIGNATURE:
	case SIG_CODE_UNIX_FD:
		return true;
	default:
		return false;
	}
}

static const char *
skip_enclosed_container(const char *signature, char open_bracket, char closed_bracket) {
	int nested = 0;
	for (char sig_code = *signature++; sig_code != '\0'; sig_code = *signature++) {
		if (sig_code == closed_bracket) {
			if (nested == 0) {
				return signature;
			}
			nested--;
		} else if (sig_code == open_bracket) {
			nested++;
		}
	}
	return NULL;
}

static const char *
skip_single_complete_type(const char *signature) {
	char sig_code;
	while (1) {
		sig_code = *signature++;
		switch (sig_code) {
		case SIG_CODE_BYTE:
		case SIG_CODE_BOOLEAN:
		case SIG_CODE_INT16:
		case SIG_CODE_UINT16:
		case SIG_CODE_INT32:
		case SIG_CODE_UINT32:
		case SIG_CODE_INT64:
		case SIG_CODE_UINT64:
		case SIG_CODE_DOUBLE:
		case SIG_CODE_STRING:
		case SIG_CODE_OBJECT_PATH:
		case SIG_CODE_SIGNATURE:
		case SIG_CODE_VARIANT:
		case SIG_CODE_UNIX_FD:
			return signature;
		case SIG_CODE_ARRAY:
			continue;
		case SIG_CODE_STRUCT_OPEN:
			return skip_enclosed_container(signature, SIG_CODE_STRUCT_OPEN, SIG_CODE_STRUCT_CLOSE);
		case SIG_CODE_DICT_ENTRY_OPEN:
			return skip_enclosed_container(signature, SIG_CODE_DICT_ENTRY_OPEN, SIG_CODE_DICT_ENTRY_CLOSE);
		default:
			return NULL;
		}
	}
}

static bool
is_dbus_signature_valid(const char *signature, dbus_packet_t *packet) {
	char sig_code;
	size_t length = 0;
	char prev_sig_code = '\0';
	wmem_stack_t *expected_chars = wmem_stack_new(packet->pinfo->pool);

	while ((sig_code = *signature++) != '\0') {
		if (++length >= DBUS_MAX_SIGNATURE_LENGTH) {
			return false;
		}

		switch (sig_code) {
		case SIG_CODE_BYTE:
		case SIG_CODE_SIGNATURE:
		case SIG_CODE_VARIANT:
		case SIG_CODE_INT16:
		case SIG_CODE_UINT16:
		case SIG_CODE_INT32:
		case SIG_CODE_UINT32:
		case SIG_CODE_BOOLEAN:
		case SIG_CODE_OBJECT_PATH:
		case SIG_CODE_STRING:
		case SIG_CODE_UNIX_FD:
		case SIG_CODE_INT64:
		case SIG_CODE_UINT64:
		case SIG_CODE_DOUBLE:
			break;
		case SIG_CODE_ARRAY:
			switch (*signature) {
			case '\0':
			case SIG_CODE_STRUCT_CLOSE:
			case SIG_CODE_DICT_ENTRY_CLOSE:
				// arrays must be followed by a single complete type
				return false;
			}
			// invalid signature codes are detected in the next iteration
			break;
		case SIG_CODE_STRUCT_OPEN:
			if (*signature == SIG_CODE_STRUCT_CLOSE) {
				// empty structures are not allowed
				return false;
			}
			wmem_stack_push(expected_chars, (void *)SIG_CODE_STRUCT_CLOSE);
			break;
		case SIG_CODE_DICT_ENTRY_OPEN: {
			// dict entries must be an array element type
			// the first single complete type (the "key") must be a basic type
			if (prev_sig_code != SIG_CODE_ARRAY || !is_basic_type(*signature)) {
				return false;
			}

			// dict entries must contain exactly two single complete types
			// + 1 can be used here, since the key is a basic type
			const char *sig_code_close = skip_single_complete_type(signature + 1);
			if (!sig_code_close || *sig_code_close != SIG_CODE_DICT_ENTRY_CLOSE) {
				return false;
			}
			wmem_stack_push(expected_chars, (void *)SIG_CODE_DICT_ENTRY_CLOSE);
			break;
		}
		case SIG_CODE_STRUCT_CLOSE:
		case SIG_CODE_DICT_ENTRY_CLOSE:
			if (wmem_stack_count(expected_chars) == 0 ||
				(char)(guintptr)wmem_stack_pop(expected_chars) != sig_code) {
				return false;
			}
			break;
		default:
			return false;
		}

		prev_sig_code = sig_code;
	}
	return wmem_stack_count(expected_chars) == 0;
}

static void
add_expert(dbus_packet_t *packet, expert_field *ei) {
	expert_add_info(packet->pinfo, packet->current_pi, ei);
}

static uint32_t
add_uint(dbus_packet_t *packet, int hf) {
	header_field_info *info = proto_registrar_get_nth(hf);
	int length;
	uint32_t value;
	switch (info->type) {
	case FT_UINT8:
		length = 1;
		break;
	case FT_UINT32:
		length = 4;
		break;
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
	}
	packet->current_pi = ptvcursor_add_ret_uint(packet->cursor, hf, length, packet->enc, &value);
	return value;
}

static const uint8_t *
add_dbus_string(dbus_packet_t *packet, int hf, int uint_length) {
	const uint8_t *string;
	int start_offset = ptvcursor_current_offset(packet->cursor);
	proto_item *pi = ptvcursor_add_ret_string(packet->cursor, hf, uint_length,
			packet->enc | ENC_UTF_8, packet->pinfo->pool, &string);
	int item_length = ptvcursor_current_offset(packet->cursor) - start_offset;
	uint8_t term_byte = tvb_get_uint8(ptvcursor_tvbuff(packet->cursor), ptvcursor_current_offset(packet->cursor));
	proto_item_set_len(pi, item_length + 1);
	ptvcursor_advance(packet->cursor, 1);
	packet->current_pi = pi;

	if ((strlen(string) != (size_t)(item_length - uint_length)) || (term_byte != '\0')) {
		return NULL;
	}
	return string;
}

static int
calculate_padding_len(int offset, char sig) {
	int alignment;
	switch (sig) {
	case SIG_CODE_BYTE:
	case SIG_CODE_SIGNATURE:
	case SIG_CODE_VARIANT:
	default:
		alignment = 1;
		break;
	case SIG_CODE_INT16:
	case SIG_CODE_UINT16:
		alignment = 2;
		break;
	case SIG_CODE_INT32:
	case SIG_CODE_UINT32:
	case SIG_CODE_BOOLEAN:
	case SIG_CODE_OBJECT_PATH:
	case SIG_CODE_ARRAY:
	case SIG_CODE_STRING:
	case SIG_CODE_UNIX_FD:
		alignment = 4;
		break;
	case SIG_CODE_INT64:
	case SIG_CODE_UINT64:
	case SIG_CODE_DOUBLE:
	case SIG_CODE_STRUCT_OPEN:
	case SIG_CODE_DICT_ENTRY_OPEN:
		alignment = 8;
		break;
	}
	return (alignment - (offset % alignment)) % alignment;
}

static int
add_padding(dbus_packet_t *packet, char sig) {
	uint8_t value;
	tvbuff_t *tvb = ptvcursor_tvbuff(packet->cursor);
	int offset = ptvcursor_current_offset(packet->cursor);
	int padding_len = calculate_padding_len(offset, sig);

	if (padding_len != 0) {
		packet->current_pi = ptvcursor_add(packet->cursor, hf_dbus_padding, padding_len, packet->enc);
		for (int i = offset; i < (offset + padding_len); i++) {
			value = tvb_get_uint8(tvb, i);
			if (value != 0) {
				add_expert(packet, &ei_dbus_padding_invalid);
				return 1;
			}
		}
		proto_item_set_hidden(packet->current_pi);
	}
	return 0;
}

static void
reader_cleanup(dbus_type_reader_t *reader) {
	for (dbus_type_reader_t *r = reader; r->parent; r = r->parent) {
		ptvcursor_pop_subtree(r->packet->cursor);
	}
}

static dbus_type_reader_t *
reader_next(dbus_type_reader_t *reader, int hf, int ett, dbus_val_t *value) {
	int err = 0;
	char sig_code = *reader->signature++;
	dbus_packet_t *packet = reader->packet;
	bool is_single_complete_type = true;
	add_padding(packet, sig_code);

	switch (sig_code) {
	case SIG_CODE_BYTE:
		packet->current_pi = ptvcursor_add_ret_uint(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_byte, 1, packet->enc, &value->uint);
		break;
	case SIG_CODE_BOOLEAN: {
		int offset = ptvcursor_current_offset(packet->cursor);
		tvbuff_t *tvb = ptvcursor_tvbuff(packet->cursor);
		uint8_t val = tvb_get_uint8(tvb, offset);
		packet->current_pi = ptvcursor_add_ret_boolean(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_boolean, 4, packet->enc, &value->bool_);
		if (val >= 2) {
			add_expert(packet, &ei_dbus_type_boolean_invalid);
			err = 1;
		}
		break;
	}
	case SIG_CODE_INT16:
		packet->current_pi = ptvcursor_add_ret_int(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_int16, 2, packet->enc, &value->int_);
		break;
	case SIG_CODE_UINT16:
		packet->current_pi = ptvcursor_add_ret_uint(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_uint16, 2, packet->enc, &value->uint);
		break;
	case SIG_CODE_INT32:
		packet->current_pi = ptvcursor_add_ret_int(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_int32, 4, packet->enc, &value->int_);
		break;
	case SIG_CODE_UINT32:
		packet->current_pi = ptvcursor_add_ret_uint(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_uint32, 4, packet->enc, &value->uint);
		break;
	case SIG_CODE_INT64: {
		int offset = ptvcursor_current_offset(packet->cursor);
		tvbuff_t *tvb = ptvcursor_tvbuff(packet->cursor);
		value->int64 = tvb_get_int64(tvb, offset, packet->enc);
		packet->current_pi = ptvcursor_add(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_int64, 8, packet->enc);
		break;
	}
	case SIG_CODE_UINT64: {
		int offset = ptvcursor_current_offset(packet->cursor);
		tvbuff_t *tvb = ptvcursor_tvbuff(packet->cursor);
		value->uint64 = tvb_get_uint64(tvb, offset, packet->enc);
		packet->current_pi = ptvcursor_add(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_uint64, 8, packet->enc);
		break;
	}
	case SIG_CODE_DOUBLE: {
		int offset = ptvcursor_current_offset(packet->cursor);
		tvbuff_t *tvb = ptvcursor_tvbuff(packet->cursor);
		value->double_ = tvb_get_ieee_double(tvb, offset, packet->enc);
		packet->current_pi = ptvcursor_add(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_double, 8, packet->enc);
		break;
	}
	case SIG_CODE_STRING: {
		const char *val = add_dbus_string(packet,
				hf != -1 ? hf : hf_dbus_type_string, 4);
		if (!val || !g_utf8_validate(val, -1, NULL)) {
			add_expert(packet, &ei_dbus_string_invalid);
			err = 1;
		}
		value->string = val;
		break;
	}
	case SIG_CODE_OBJECT_PATH: {
		const char *val = add_dbus_string(packet, hf != -1 ? hf : hf_dbus_type_object_path, 4);
		if (!val || !is_dbus_object_path_valid(val)) {
			add_expert(packet, &ei_dbus_type_object_path_invalid);
			err = 1;
		}
		value->string = val;
		break;
	}
	case SIG_CODE_SIGNATURE: {
		const char *val = add_dbus_string(packet, hf != -1 ? hf : hf_dbus_type_signature, 1);
		if (!val || !is_dbus_signature_valid(val, packet)) {
			add_expert(packet, &ei_dbus_type_signature_invalid);
			err = 1;
		}
		value->string = val;
		break;
	}
	case SIG_CODE_ARRAY: {
		is_single_complete_type = false;
		proto_item *array = ptvcursor_add_with_subtree(packet->cursor, hf != -1 ? hf : hf_dbus_type_array,
				SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett != -1 ? ett : ett_dbus_type_array);
		if (*reader->signature == SIG_CODE_DICT_ENTRY_OPEN) {
			proto_item_append_text(array, " (Dict)");
		}
		uint32_t array_len = add_uint(packet, hf_dbus_type_array_length);
		value->uint = array_len;
		add_padding(packet, *reader->signature);
		if (array_len == 0) {
			reader->signature = skip_single_complete_type(reader->signature);
			// all signatures are validated
			DISSECTOR_ASSERT(reader->signature);
			ptvcursor_pop_subtree(packet->cursor);
			is_single_complete_type = true;
		} else if (array_len <= DBUS_MAX_ARRAY_LEN) {
			int end_offset = ptvcursor_current_offset(packet->cursor) + array_len;
			dbus_type_reader_t *child = wmem_new(packet->pinfo->pool, dbus_type_reader_t);
			*child = (dbus_type_reader_t){
				.packet = reader->packet,
				.signature = reader->signature,
				.level = reader->level + 1,
				.array_level = reader->array_level + 1,
				.array_type_start = reader->signature,
				.array_end_offset = end_offset,
				.container = array,
				.parent = reader,
			};
			reader = child;
		} else {
			add_expert(packet, &ei_dbus_type_array_too_long);
			err = 1;
			ptvcursor_pop_subtree(packet->cursor);
		}
		break;
	}
	case SIG_CODE_STRUCT_OPEN: {
		is_single_complete_type = false;
		ptvcursor_add_with_subtree(packet->cursor, hf != -1 ? hf : hf_dbus_type_struct,
				SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett != -1 ? ett : ett_dbus_type_struct);
		dbus_type_reader_t *child = wmem_new(packet->pinfo->pool, dbus_type_reader_t);
		*child = (dbus_type_reader_t){
			.packet = reader->packet,
			.signature = reader->signature,
			.level = reader->level + 1,
			.struct_level = reader->struct_level + 1,
			.parent = reader,
		};
		reader = child;
		break;
	}
	case SIG_CODE_VARIANT: {
		is_single_complete_type = false;
		proto_item *variant = ptvcursor_add_with_subtree(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_variant,
				SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett != -1 ? ett : ett_dbus_type_variant);
		const char *variant_signature = add_dbus_string(packet, hf_dbus_type_variant_signature, 1);
		value->string = variant_signature;
		if (variant_signature && is_dbus_signature_valid(variant_signature, packet)) {
			if (variant_signature[0] != '\0') {
				dbus_type_reader_t *child = wmem_new(packet->pinfo->pool, dbus_type_reader_t);
				*child = (dbus_type_reader_t){
					.packet = reader->packet,
					.signature = variant_signature,
					.level = reader->level + 1,
					.is_in_variant = true,
					.is_basic_variant = is_basic_type(*variant_signature)
						&& *(variant_signature + 1) == '\0',
					.container = variant,
					.parent = reader,
				};
				if (reader->is_in_dict_entry && child->is_basic_variant) {
					reader->is_basic_dict_entry = true;
				}
				reader = child;
			} else {
				ptvcursor_pop_subtree(packet->cursor);
			}
		} else {
			add_expert(packet, &ei_dbus_type_variant_signature_invalid);
			err = 1;
			ptvcursor_pop_subtree(packet->cursor);
		}
		break;
	}
	case SIG_CODE_DICT_ENTRY_OPEN: {
		is_single_complete_type = false;
		proto_item *dict_entry = ptvcursor_add_with_subtree(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_dict_entry,
				SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett != -1 ? ett : ett_dbus_type_dict_entry);
		dbus_type_reader_t *child = wmem_new(packet->pinfo->pool, dbus_type_reader_t);
		*child = (dbus_type_reader_t){
			.packet = reader->packet,
			.signature = reader->signature,
			.level = reader->level + 1,
			.dict_entry_level = reader->dict_entry_level + 1,
			.is_in_dict_entry = true,
			.is_basic_dict_entry = is_basic_type(*(reader->signature + 1)),
			.container = dict_entry,
			.parent = reader,
		};
		reader = child;
		break;
	}
	case SIG_CODE_STRUCT_CLOSE:
	case SIG_CODE_DICT_ENTRY_CLOSE:
		ptvcursor_pop_subtree(packet->cursor);
		reader->parent->signature = reader->signature;
		reader = reader->parent;
		break;
	case SIG_CODE_UNIX_FD:
		packet->current_pi = ptvcursor_add_ret_uint(packet->cursor,
				hf != -1 ? hf : hf_dbus_type_unix_fd, 4, packet->enc, &value->uint);
		break;
	default:
		// all signatures are validated
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	if (reader->level > DBUS_MAX_TOTAL_NESTING_LEVEL ||
			reader->array_level > DBUS_MAX_TYPE_NESTING_LEVEL ||
			reader->struct_level > DBUS_MAX_TYPE_NESTING_LEVEL ||
			reader->dict_entry_level > DBUS_MAX_TYPE_NESTING_LEVEL) {
		add_expert(packet, &ei_dbus_nested_too_deeply);
		err= 1;
	} else if (is_single_complete_type) {
		// Arrays and variants don't have a closing signature code, but they end after a single complete type.
		// Close them here recursively, e.g. "aav"
		while (1) {
			if (reader->array_type_start) { // inside array
				int offset = ptvcursor_current_offset(packet->cursor);

				if (offset < reader->array_end_offset) {
					// parse next array element -> reset signature
					reader->signature = reader->array_type_start;
					break;
				} else if (offset == reader->array_end_offset) {
					// all array elements parsed
					ptvcursor_pop_subtree(packet->cursor);
					reader->parent->signature = reader->signature;
					reader = reader->parent;
				} else {
					// array elements don't fit into array
					expert_add_info(packet->pinfo, reader->container,
							&ei_dbus_type_array_content_out_of_bounds);
					err = 1;
					break;
				}
			} else if (reader->is_in_variant) {
				if (reader->is_basic_variant) {
					proto_item_append_text(reader->container, ": %s",
							proto_item_get_display_repr(packet->pinfo->pool, packet->current_pi));
				}
				ptvcursor_pop_subtree(packet->cursor);
				reader = reader->parent;
			} else {
				break;
			}
		}
		if (reader->is_in_dict_entry) {
			// add "key: value" to dict entry item to make it readable without expanding the tree
			if (*(reader->signature - 2) == SIG_CODE_DICT_ENTRY_OPEN) { // == key
				// key is always a basic type
				proto_item_append_text(reader->container, ", %s",
						proto_item_get_display_repr(packet->pinfo->pool, packet->current_pi));
			} else if (reader->is_basic_dict_entry) { // == value
				proto_item_append_text(reader->container, ": %s",
						proto_item_get_display_repr(packet->pinfo->pool, packet->current_pi));
			}
		}
	}

	if (err) {
		reader_cleanup(reader);
		return NULL;
	}
	return reader;
}

static bool
reader_is_finished(dbus_type_reader_t *reader) {
	return *reader->signature == '\0' && reader->parent == NULL;
}

static int
dissect_dbus_signature(dbus_packet_t *packet, const char *signature) {
	dbus_type_reader_t root_reader = {
		.packet = packet,
		.signature = signature,
	};
	dbus_type_reader_t *reader = &root_reader;
	dbus_val_t value;
	while (!reader_is_finished(reader)) {
		reader = reader_next(reader, -1, -1, &value);
		if (!reader) {
			return 1;
		}
	}
	return 0;
}

static int
dissect_dbus_body(dbus_packet_t *packet) {
	int err = 0;
	if (packet->signature[0]) {
		ptvcursor_add_with_subtree(packet->cursor, hf_dbus_body,
				SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett_dbus_body);
		err = dissect_dbus_signature(packet, packet->signature);
		ptvcursor_pop_subtree(packet->cursor);
	}
	return err;
}

static void
update_unique_name_map(const char *name1, const char *name2) {
	const char *unique_name;
	const char *well_known_name;

	if (!dbus_resolve_names) {
		return;
	}

	if (name1[0] == ':' && name2[0] != ':') {
		unique_name = name1;
		well_known_name = name2;
	} else if (name2[0] == ':' && name1[0] != ':') {
		unique_name = name2;
		well_known_name = name1;
	} else {
		// both are well-known or both are unique names
		return;
	}
	if (!wmem_map_contains(unique_name_map, unique_name)) {
		wmem_map_insert(unique_name_map,
				wmem_strdup(wmem_file_scope(), unique_name),
				wmem_strdup(wmem_file_scope(), well_known_name));
	}
}

static void
add_conversation(dbus_packet_t *packet, proto_tree *header_field_tree) {
	bool is_request;
	char *request_dest;
	char *key;

	if (!packet->sender || !packet->destination) {
		// in a peer-to-peer setup, sender and destination can be unset, in which case conversation tracking
		// doesn't make sense.
		return;
	}

	switch (packet->message_type) {
	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		if (packet->flags & DBUS_FLAGS_NO_REPLY_EXPECTED_MASK) {
			// there won't be a response, no need to track
			return;
		}
		is_request = true;

		// There are cases where the destination address of the request doesn't match the sender address of the
		// response, for example:
		// - The request is sent to the well-known bus name (e.g. org.freedesktop.PolicyKit1), but the reply is
		//   sent from the unique connection name (e.g. :1.10). Both names refer to the same connection and for
		//   every unique connection name, there can be multiple well-known names.
		// - The D-Bus daemon (org.freedesktop.DBus) sends the reply, instead of the recipient, e.g.
		//   org.freedesktop.DBus.Error.AccessDenied
		// To find the correct response, match the request sender + serial with the response destination +
		// reply serial.
		if (!PINFO_FD_VISITED(packet->pinfo)) {
			request_dest = wmem_strdup(wmem_file_scope(), packet->destination);
			key = wmem_strdup_printf(wmem_file_scope(), "%s %u", packet->sender, packet->serial);
			wmem_map_insert(request_info_map, key, request_dest);
		}
		break;
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
	case DBUS_MESSAGE_TYPE_ERROR:
		is_request = false;

		key = wmem_strdup_printf(packet->pinfo->pool, "%s %u", packet->destination, packet->reply_serial);
		request_dest = (char *)wmem_map_lookup(request_info_map, key);
		if (request_dest && !g_str_equal(request_dest, packet->sender)) {
			// Replace the sender address of the response with the destination address of the request, so
			// the conversation can be found.
			address sender_addr;
			set_address(&sender_addr, AT_STRINGZ, (int)strlen(request_dest)+1, request_dest);
			conversation_set_conv_addr_port_endpoints(packet->pinfo, &sender_addr, &packet->pinfo->dst,
					conversation_pt_to_endpoint_type(packet->pinfo->ptype),
					packet->pinfo->srcport, packet->pinfo->destport);

			if (!PINFO_FD_VISITED(packet->pinfo) && packet->message_type == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
				update_unique_name_map(request_dest, packet->sender);
			}
		}
		break;
	case DBUS_MESSAGE_TYPE_SIGNAL:
	default:
		// signals don't have a response, no need to track
		return;
	}

	conversation_t *conversation = find_or_create_conversation(packet->pinfo);
	dbus_conv_info_t *conv_info = (dbus_conv_info_t *)conversation_get_proto_data(conversation, proto_dbus);

	if (!conv_info) {
		conv_info = wmem_new(wmem_file_scope(), dbus_conv_info_t);
		conv_info->packets = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conversation_add_proto_data(conversation, proto_dbus, conv_info);
	}

	dbus_transaction_t *trans;
	if (!PINFO_FD_VISITED(packet->pinfo)) {
		if (is_request) {
			trans = wmem_new(wmem_file_scope(), dbus_transaction_t);
			*trans = (dbus_transaction_t){
				.req_frame = packet->pinfo->num,
				.req_time = packet->pinfo->fd->abs_ts,
				.path = wmem_strdup(wmem_file_scope(), packet->path),
				.interface = wmem_strdup(wmem_file_scope(), packet->interface),
				.member = wmem_strdup(wmem_file_scope(), packet->member),
			};
			wmem_map_insert(conv_info->packets, GUINT_TO_POINTER(packet->serial), (void *)trans);
		} else {
			trans = (dbus_transaction_t *)wmem_map_lookup(conv_info->packets, GUINT_TO_POINTER(packet->reply_serial));
			if (trans) {
				trans->rep_frame = packet->pinfo->num;
			}
		}
	} else {
		uint32_t request_serial = is_request ? packet->serial : packet->reply_serial;
		trans = (dbus_transaction_t *)wmem_map_lookup(conv_info->packets, GUINT_TO_POINTER(request_serial));
	}

	if (!trans) {
		return;
	}

	if (is_request) {
		proto_item *it = proto_tree_add_uint(header_field_tree, hf_dbus_response_in, ptvcursor_tvbuff(packet->cursor), 0, 0, trans->rep_frame);
		proto_item_set_generated(it);
	} else {
		nstime_t ns;
		proto_item *it;
		tvbuff_t *tvb = ptvcursor_tvbuff(packet->cursor);

		it = proto_tree_add_string(header_field_tree, hf_dbus_path, tvb, 0, 0, trans->path);
		proto_item_set_generated(it);
		packet->path = trans->path;

		it = proto_tree_add_string(header_field_tree, hf_dbus_interface, tvb, 0, 0, trans->interface);
		proto_item_set_generated(it);
		packet->interface = trans->interface;

		it = proto_tree_add_string(header_field_tree, hf_dbus_member, tvb, 0, 0, trans->member);
		proto_item_set_generated(it);
		packet->member = trans->member;

		it = proto_tree_add_uint(header_field_tree, hf_dbus_response_to, tvb, 0, 0, trans->req_frame);
		proto_item_set_generated(it);

		nstime_delta(&ns, &packet->pinfo->fd->abs_ts, &trans->req_time);
		it = proto_tree_add_time(header_field_tree, hf_dbus_response_time, tvb, 0, 0, &ns);
		proto_item_set_generated(it);
	}
}

static void
resolve_unique_name(dbus_packet_t *packet, proto_tree *header_field_tree) {
	proto_item *it;
	tvbuff_t *tvb = ptvcursor_tvbuff(packet->cursor);

	if (packet->sender) {
		const char *sender_well_known = (const char *)wmem_map_lookup(unique_name_map, packet->sender);
		if (sender_well_known) {
			set_address(&packet->pinfo->src, AT_STRINGZ, (int)strlen(sender_well_known)+1, sender_well_known);
			it = proto_tree_add_string(header_field_tree, hf_dbus_sender, tvb, 0, 0, sender_well_known);
			proto_item_set_generated(it);
		}
	}

	if (packet->destination) {
		const char *destination_well_known = (const char *)wmem_map_lookup(unique_name_map, packet->destination);
		if (destination_well_known) {
			set_address(&packet->pinfo->dst, AT_STRINGZ, (int)strlen(destination_well_known)+1, destination_well_known);
			it = proto_tree_add_string(header_field_tree, hf_dbus_destination, tvb, 0, 0, destination_well_known);
			proto_item_set_generated(it);
		}
	}
}

static int
dissect_dbus_header_fields(dbus_packet_t *packet) {
	dbus_type_reader_t root_reader = {
		.packet = packet,
		.signature = "a{yv}",
	};
	dbus_type_reader_t *reader = &root_reader;
	dbus_val_t value;
#define NEXT_OR_RETURN(hf, ett) if (!(reader = reader_next(reader, hf, ett, &value))) return 1;

	// Header Field Array
	NEXT_OR_RETURN(-1, ett_dbus_header_field_array);
	proto_item *header_field_array_pi = reader->container;
	proto_item_set_text(header_field_array_pi, "Header Field Array");
	while (reader->level > 0) {
		// Header Field (Dict)
		NEXT_OR_RETURN(-1, ett_dbus_header_field);
		// Field Code
		NEXT_OR_RETURN(hf_dbus_field_code, -1);
		uint32_t field_code = value.uint;
		const char *field_code_str = val_to_str_const(field_code, field_code_vals, "Unknown field code");
		proto_item_append_text(reader->container, ", %s", field_code_str);
		if (field_code == DBUS_HEADER_FIELD_INVALID) {
			add_expert(packet, &ei_dbus_field_code_invalid);
			reader_cleanup(reader);
			return 1;
		}

		// Header Field Value (Variant)
		NEXT_OR_RETURN(-1, -1);
		const char *header_field_signature = value.string;

		const char *expected_signature;
		switch (field_code) {
		case DBUS_HEADER_FIELD_PATH:
			expected_signature = "o";
			break;
		case DBUS_HEADER_FIELD_INTERFACE:
		case DBUS_HEADER_FIELD_MEMBER:
		case DBUS_HEADER_FIELD_ERROR_NAME:
		case DBUS_HEADER_FIELD_DESTINATION:
		case DBUS_HEADER_FIELD_SENDER:
			expected_signature = "s";
			break;
		case DBUS_HEADER_FIELD_REPLY_SERIAL:
			expected_signature = "u";
			break;
		case DBUS_HEADER_FIELD_UNIX_FDS:
			expected_signature = "u";
			break;
		case DBUS_HEADER_FIELD_SIGNATURE:
			expected_signature = "g";
			break;
		default:
			expected_signature = NULL;
		}

		if (expected_signature && strcmp(header_field_signature, expected_signature) != 0) {
			add_expert(packet, &ei_dbus_field_signature_wrong);
			reader_cleanup(reader);
			return 1;
		}

		// Variant Value
		switch (field_code) {
		case DBUS_HEADER_FIELD_PATH:
			NEXT_OR_RETURN(hf_dbus_path, -1);
			packet->path = value.string;
			break;
		case DBUS_HEADER_FIELD_INTERFACE:
			NEXT_OR_RETURN(hf_dbus_interface, -1);
			packet->interface = value.string;
			if (!is_dbus_interface_valid(packet->interface)) {
				add_expert(packet, &ei_dbus_interface_invalid);
				reader_cleanup(reader);
				return 1;
			}
			break;
		case DBUS_HEADER_FIELD_MEMBER:
			NEXT_OR_RETURN(hf_dbus_member, -1);
			packet->member = value.string;
			if (!is_dbus_member_name_valid(packet->member)) {
				add_expert(packet, &ei_dbus_member_invalid);
				reader_cleanup(reader);
				return 1;
			}
			break;
		case DBUS_HEADER_FIELD_ERROR_NAME:
			NEXT_OR_RETURN(hf_dbus_error_name, -1);
			packet->error_name = value.string;
			if (!is_dbus_interface_valid(packet->error_name)) {
				add_expert(packet, &ei_dbus_error_name_invalid);
				reader_cleanup(reader);
				return 1;
			}
			break;
		case DBUS_HEADER_FIELD_DESTINATION:
			NEXT_OR_RETURN(hf_dbus_destination, -1);
			packet->destination = value.string;
			if (!is_dbus_bus_name_valid(packet->destination)) {
				add_expert(packet, &ei_dbus_bus_name_invalid);
				reader_cleanup(reader);
				return 1;
			}
			set_address(&packet->pinfo->dst, AT_STRINGZ, (int)strlen(packet->destination)+1,
				wmem_strdup(packet->pinfo->pool, packet->destination));
			break;
		case DBUS_HEADER_FIELD_SENDER:
			NEXT_OR_RETURN(hf_dbus_sender, -1);
			packet->sender = value.string;
			if (!is_dbus_bus_name_valid(packet->sender)) {
				add_expert(packet, &ei_dbus_bus_name_invalid);
				reader_cleanup(reader);
				return 1;
			}
			set_address(&packet->pinfo->src, AT_STRINGZ, (int)strlen(packet->sender)+1,
				wmem_strdup(packet->pinfo->pool, packet->sender));
			break;
		case DBUS_HEADER_FIELD_SIGNATURE:
			NEXT_OR_RETURN(hf_dbus_signature, -1);
			packet->signature = value.string;
			break;
		case DBUS_HEADER_FIELD_REPLY_SERIAL:
			NEXT_OR_RETURN(hf_dbus_reply_serial, -1);
			packet->reply_serial = value.uint;
			if (packet->reply_serial == 0) {
				add_expert(packet, &ei_dbus_serial_invalid);
				reader_cleanup(reader);
				return 1;
			}
			break;
		case DBUS_HEADER_FIELD_UNIX_FDS:
			NEXT_OR_RETURN(hf_dbus_unix_fds, -1);
			packet->unix_fds = value.uint;
			break;
		default:
			// Unknown Field code must be skipped without error
			do {
				NEXT_OR_RETURN(-1, -1);
				// Skip while inside Header Field Array -> Header Field Dict -> Variant
			} while (reader->level >= 3);
		}
		// end of dict
		NEXT_OR_RETURN(-1, -1);
	}

	bool is_field_missing = false;
	switch (packet->message_type) {
	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		is_field_missing = !packet->path || !packet->member;
		break;
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
		is_field_missing = !packet->reply_serial;
		break;
	case DBUS_MESSAGE_TYPE_ERROR:
		is_field_missing = !packet->error_name || !packet->reply_serial;
		break;
	case DBUS_MESSAGE_TYPE_SIGNAL:
		is_field_missing = !packet->path || !packet->interface || !packet->member;
		break;
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		break;
	}
	if (is_field_missing) {
		expert_add_info(packet->pinfo, header_field_array_pi, &ei_dbus_required_header_field_missing);
		return 1;
	}

	add_conversation(packet, proto_item_get_subtree(header_field_array_pi));
	if (dbus_resolve_names) {
		resolve_unique_name(packet, proto_item_get_subtree(header_field_array_pi));
	}

	switch(packet->message_type) {
	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		col_add_fstr(packet->pinfo->cinfo, COL_INFO, "%s(%s) @ %s", packet->member, packet->signature, packet->path);
		break;
	case DBUS_MESSAGE_TYPE_SIGNAL:
		col_add_fstr(packet->pinfo->cinfo, COL_INFO, "* %s(%s) @ %s", packet->member, packet->signature, packet->path);
		break;
	case DBUS_MESSAGE_TYPE_ERROR:
		if (packet->member) {
			col_add_fstr(packet->pinfo->cinfo, COL_INFO, "! %s: %s", packet->member, packet->error_name);
		} else {
			col_add_fstr(packet->pinfo->cinfo, COL_INFO, "! %s", packet->error_name);
		}
		break;
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
		if (packet->member) {
			if (*packet->signature != '\0') {
				col_add_fstr(packet->pinfo->cinfo, COL_INFO, "-> %s: '%s'", packet->member, packet->signature);
			} else {
				col_add_fstr(packet->pinfo->cinfo, COL_INFO, "-> %s: OK", packet->member);

			}
		} else {
			col_add_fstr(packet->pinfo->cinfo, COL_INFO, "-> '%s'", packet->signature);
		}
		break;
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		break;
	}

	// Header length must be a multiple of 8 bytes
	return add_padding(packet, SIG_CODE_STRUCT_OPEN);
}

static int
dissect_dbus_header(dbus_packet_t *packet) {
	uint32_t val;

	// Endianness
	packet->current_pi = ptvcursor_add_ret_uint(packet->cursor, hf_dbus_endianness, 1, ENC_NA, &val);
	switch (val) {
		case 'l':
			packet->enc = ENC_LITTLE_ENDIAN;
			break;
		case 'B':
			packet->enc = ENC_BIG_ENDIAN;
			break;
		default:
			add_expert(packet, &ei_dbus_endianness_invalid);
			return 1;
	}

	// Message Type
	packet->message_type = add_uint(packet, hf_dbus_message_type);
	const char *info = try_val_to_str(packet->message_type, message_type_vals);
	if (packet->message_type == DBUS_MESSAGE_TYPE_INVALID) {
		col_set_str(packet->pinfo->cinfo, COL_INFO, info);
		add_expert(packet, &ei_dbus_message_type_invalid);
		return 1;
	} else if (!info) {
		col_set_str(packet->pinfo->cinfo, COL_INFO, "Unknown message type");
		add_expert(packet, &ei_dbus_message_type_unknown);
		return 1;
	}
	col_set_str(packet->pinfo->cinfo, COL_INFO, info);

	// Flags
	ptvcursor_add_with_subtree(packet->cursor, hf_dbus_flags, 1, packet->enc, ett_dbus_flags);
	ptvcursor_add_no_advance(packet->cursor, hf_dbus_flags_no_reply_expected, 1, packet->enc);
	ptvcursor_add_no_advance(packet->cursor, hf_dbus_flags_no_auto_start, 1, packet->enc);
	ptvcursor_add_no_advance(packet->cursor, hf_dbus_flags_allow_interactive_authorization, 1, packet->enc);
	packet->flags = tvb_get_uint8(ptvcursor_tvbuff(packet->cursor), ptvcursor_current_offset(packet->cursor));
	ptvcursor_advance(packet->cursor, 1);
	ptvcursor_pop_subtree(packet->cursor);

	// Version
	if (add_uint(packet, hf_dbus_version) != 1) {
		add_expert(packet, &ei_dbus_version_invalid);
		return 1;
	}

	// Body Length
	packet->body_len = add_uint(packet, hf_dbus_body_length);

	// Serial
	packet->serial = add_uint(packet, hf_dbus_serial);
	if (packet->serial == 0) {
		add_expert(packet, &ei_dbus_serial_invalid);
		return 1;
	}

	return 0;
}

static int
dissect_dbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	dbus_packet_t packet = { .pinfo = pinfo, .signature = "" };

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "D-Bus");
	col_set_str(pinfo->cinfo, COL_INFO, "D-Bus");

	proto_item *pi = proto_tree_add_protocol_format(tree, proto_dbus, tvb, 0, -1, "D-Bus");
	proto_tree *dbus_tree = proto_item_add_subtree(pi, ett_dbus);

	int offset = 0;
	packet.cursor = ptvcursor_new(pinfo->pool, dbus_tree, tvb, offset);

	(void)(dissect_dbus_header(&packet) ||
		dissect_dbus_header_fields(&packet) ||
		dissect_dbus_body(&packet));

	offset = ptvcursor_current_offset(packet.cursor);
	proto_item_set_end(pi, tvb, offset);
	ptvcursor_free(packet.cursor);
	return offset;
}

#define DBUS_HEADER_LEN 16

static unsigned
get_dbus_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_) {
	uint32_t (*get_guint32)(tvbuff_t *, const int);

	uint32_t len_body, len_hdr;

	switch (tvb_get_uint8(tvb, offset)) {
		case 'l':
			get_guint32 = tvb_get_letohl;
			break;
		case 'B':
		default:
			get_guint32 = tvb_get_ntohl;
			break;
	}

	len_hdr = DBUS_HEADER_LEN + get_guint32(tvb, offset + 12);
	len_hdr = WS_ROUNDUP_8(len_hdr);
	len_body = get_guint32(tvb, offset + 4);

	return len_hdr + len_body;
}

static int
dissect_dbus_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
	return dissect_dbus(tvb, pinfo, tree, data);
}

static int
dissect_dbus_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
	tcp_dissect_pdus(tvb, pinfo, tree, dbus_desegment, DBUS_HEADER_LEN,
			get_dbus_message_len, dissect_dbus_pdu, data);
	return tvb_reported_length(tvb);
}

void
proto_register_dbus(void) {
	static hf_register_info hf[] = {
		{ &hf_dbus_endianness, { "Endianness", "dbus.endianness",
			FT_UINT8, BASE_NONE, VALS(endianness_vals), 0x00, NULL, HFILL }},
		{ &hf_dbus_message_type, { "Message Type", "dbus.message_type",
			FT_UINT8, BASE_NONE, VALS(message_type_vals), 0x00, NULL, HFILL }},
		{ &hf_dbus_flags, { "Message Flags", "dbus.flags",
			FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_flags_no_reply_expected, { "No Reply Expected", "dbus.flags.no_reply_expected",
			FT_BOOLEAN, 8, TFS(&not_expected_vals),
			DBUS_FLAGS_NO_REPLY_EXPECTED_MASK, NULL, HFILL }},
		{ &hf_dbus_flags_no_auto_start, { "No Auto Start", "dbus.flags.no_auto_start",
			FT_BOOLEAN, 8, TFS(&no_start_vals),
			DBUS_FLAGS_NO_AUTO_START_MASK, NULL, HFILL }},
		{ &hf_dbus_flags_allow_interactive_authorization, { "Allow Interactive Authorization", "dbus.flags.allow_interactive_authorization",
			FT_BOOLEAN, 8, TFS(&allow_vals),
			DBUS_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION_MASK, NULL, HFILL }},
		{ &hf_dbus_version, { "Protocol Version", "dbus.version",
			FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_body_length, { "Message Body Length", "dbus.body_length",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_serial, { "Message Serial", "dbus.serial",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_field_code, { "Field Code", "dbus.field_code",
			FT_UINT8, BASE_DEC, VALS(field_code_vals), 0x00, NULL, HFILL }},
		{ &hf_dbus_padding, { "Padding", "dbus.padding",
			FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_path, { "Path", "dbus.path",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_interface, { "Interface", "dbus.interface",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_member, { "Member", "dbus.member",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_error_name, { "Error name", "dbus.error_name",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_reply_serial, { "Reply serial", "dbus.reply_serial",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_destination, { "Destination", "dbus.destination",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_sender, { "Sender", "dbus.sender",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_signature, { "Signature", "dbus.signature",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_unix_fds, { "Unix FDs", "dbus.unix_fds",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_body, { "Body", "dbus.body",
			FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_byte, { "Byte", "dbus.type.byte",
			FT_UINT8, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_boolean, { "Boolean", "dbus.type.boolean",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_int16, { "Int16", "dbus.type.int16",
			FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_uint16, { "Uint16", "dbus.type.uint16",
			FT_UINT16, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_int32, { "Int32", "dbus.type.int32",
			FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_uint32, { "Uint32", "dbus.type.uint32",
			FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_int64, { "Int64", "dbus.type.int64",
			FT_INT64, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_uint64, { "Uint64", "dbus.type.uint64",
			FT_UINT64, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_double, { "Double", "dbus.type.double",
			FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_string, { "String", "dbus.type.string",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_object_path, { "Object Path", "dbus.type.object_path",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_signature, { "Signature", "dbus.type.signature",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_array, { "Array", "dbus.type.array",
			FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_array_length, { "Array Length", "dbus.type.array.length",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_struct, { "Struct", "dbus.type.struct",
			FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_variant, { "Variant", "dbus.type.variant",
			FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_variant_signature, { "Variant Signature", "dbus.type.variant.signature",
			FT_UINT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_dict_entry, { "Dict Entry", "dbus.type.dict_entry",
			FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_dict_entry_key, { "Key", "dbus.type.dict_entry.key",
			FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_type_unix_fd, { "Unix FD", "dbus.type.unix_fd",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
		{ &hf_dbus_response_in, { "Response In", "dbus.response_in",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			"The response to this D-Bus call is in this frame", HFILL }},
		{ &hf_dbus_response_to, { "Response To", "dbus.response_to",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			"This is a response to the D-Bus call in this frame", HFILL }},
		{ &hf_dbus_response_time, { "Response Time", "dbus.response_time",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			"The time between the Call and the Reply", HFILL }},
	};

	static int *ett[] = {
		&ett_dbus,
		&ett_dbus_flags,
		&ett_dbus_header_field_array,
		&ett_dbus_header_field,
		&ett_dbus_body,
		&ett_dbus_type_array,
		&ett_dbus_type_struct,
		&ett_dbus_type_variant,
		&ett_dbus_type_dict_entry,
	};

	static ei_register_info ei[] = {
		{ &ei_dbus_endianness_invalid, { "dbus.endianness.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid endianness flag", EXPFILL }},
		{ &ei_dbus_message_type_invalid, { "dbus.message_type.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid message type", EXPFILL }},
		{ &ei_dbus_message_type_unknown, { "dbus.message_type.unknown",
			PI_PROTOCOL, PI_WARN, "Unknown message type", EXPFILL }},
		{ &ei_dbus_version_invalid, { "dbus.version.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid version", EXPFILL }},
		{ &ei_dbus_serial_invalid, { "dbus.serial.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid serial", EXPFILL }},
		{ &ei_dbus_field_code_invalid, { "dbus.field_code.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid field code", EXPFILL }},
		{ &ei_dbus_required_header_field_missing, { "dbus.required_header_field_missing",
			PI_PROTOCOL, PI_ERROR, "Required header field is missing", EXPFILL }},
		{ &ei_dbus_padding_invalid, { "dbus.padding.invalid",
			PI_PROTOCOL, PI_ERROR, "Padding bytes must be zero", EXPFILL }},
		{ &ei_dbus_field_signature_wrong, { "dbus.field_signature_wrong",
			PI_PROTOCOL, PI_ERROR, "Wrong header field variant signature", EXPFILL }},
		{ &ei_dbus_interface_invalid, { "dbus.interface.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid interface name", EXPFILL }},
		{ &ei_dbus_member_invalid, { "dbus.member.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid member name", EXPFILL }},
		{ &ei_dbus_error_name_invalid, { "dbus.error_name.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid error name", EXPFILL }},
		{ &ei_dbus_bus_name_invalid, { "dbus.bus_name.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid bus name", EXPFILL }},
		{ &ei_dbus_type_boolean_invalid, { "dbus.type.boolean.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid boolean value", EXPFILL }},
		{ &ei_dbus_string_invalid, { "dbus.type.string.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid string value", EXPFILL }},
		{ &ei_dbus_type_signature_invalid, { "dbus.type.signature.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid signature", EXPFILL }},
		{ &ei_dbus_type_array_too_long, { "dbus.type.array.too_long",
			PI_PROTOCOL, PI_ERROR, "Array too long", EXPFILL }},
		{ &ei_dbus_type_array_content_out_of_bounds, { "dbus.type.array.content_out_of_bounds",
			PI_PROTOCOL, PI_ERROR, "Array content is out of bounds", EXPFILL }},
		{ &ei_dbus_type_object_path_invalid, { "dbus.type.object_path.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid object path", EXPFILL }},
		{ &ei_dbus_type_variant_signature_invalid, { "dbus.type.variant.signature.invalid",
			PI_PROTOCOL, PI_ERROR, "Invalid variant signature", EXPFILL }},
		{ &ei_dbus_nested_too_deeply, { "dbus.nested_too_deeply",
			PI_PROTOCOL, PI_ERROR, "Containers nested too deeply", EXPFILL }},
	};

	expert_module_t *expert_dbus;
	module_t *dbus_module;

	proto_dbus = proto_register_protocol("D-Bus", "D-Bus", "dbus");
	proto_register_field_array(proto_dbus, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_dbus = expert_register_protocol(proto_dbus);
	expert_register_field_array(expert_dbus, ei, array_length(ei));

	dbus_handle = register_dissector("dbus", dissect_dbus, proto_dbus);
	dbus_handle_tcp = register_dissector("dbus.tcp", dissect_dbus_tcp, proto_dbus);

	dbus_module = prefs_register_protocol(proto_dbus, NULL);
	prefs_register_bool_preference(dbus_module, "resolve_names",
			"Resolve unique names into well-known names",
			"Show the first inferred well-known bus name (e.g. \"com.example.MusicPlayer1\") instead of the unique connection name (e.g. \":1.18\"). Might be confusing if a connection owns more than one well-known name.", &dbus_resolve_names);

	request_info_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), wmem_str_hash, g_str_equal);
	unique_name_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), wmem_str_hash, g_str_equal);
}

void
proto_reg_handoff_dbus(void) {
	dissector_add_uint("wtap_encap", WTAP_ENCAP_DBUS, dbus_handle);
	dissector_add_for_decode_as_with_preference("tcp.port", dbus_handle_tcp);
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
