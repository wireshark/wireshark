/* packet-spdy.c
 * Routines for SPDY packet disassembly
 * For now, the protocol spec can be found at
 * http://dev.chromium.org/spdy/spdy-protocol
 *
 * Copyright 2010, Google Inc.
 * Hasan Khalil <hkhalil@google.com>
 * Chris Bentzel <cbentzel@google.com>
 * Eric Shienbrood <ers@google.com>
 *
 * Copyright 2013-2014
 * Alexis La Goutte <alexis.lagoutte@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Originally based on packet-http.c
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

#include <ctype.h>

#include <glib.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/wmem/wmem.h>

#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-ssl.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tap.h>

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

void proto_register_spdy(void);
void proto_reg_handoff_spdy(void);

#define MIN_SPDY_VERSION 3

#define SPDY_STREAM_ID_MASK 0x7FFFFFFF

/*
 * Conversation data - used for assembling multi-data-frame
 * entities and for decompressing request & reply header blocks.
 */
typedef struct _spdy_conv_t {
#ifdef HAVE_LIBZ
  z_streamp rqst_decompressor;
  z_streamp rply_decompressor;
  uLong     dictionary_id;
#endif
  wmem_tree_t  *streams;
} spdy_conv_t;


/* The types of SPDY frames */
#define SPDY_DATA           0
#define SPDY_SYN_STREAM     1
#define SPDY_SYN_REPLY      2
#define SPDY_RST_STREAM     3
#define SPDY_SETTINGS       4
#define SPDY_PING           6
#define SPDY_GOAWAY         7
#define SPDY_HEADERS        8
#define SPDY_WINDOW_UPDATE  9
#define SPDY_CREDENTIAL    10
#define SPDY_INVALID       11

#define SPDY_FLAG_FIN  0x01
#define SPDY_FLAG_UNIDIRECTIONAL 0x02
#define SPDY_FLAG_SETTINGS_CLEAR_SETTINGS 0x01

/* Flags for each setting in a SETTINGS frame. */
#define SPDY_FLAG_SETTINGS_PERSIST_VALUE 0x01
#define SPDY_FLAG_SETTINGS_PERSISTED 0x02

#define TCP_PORT_SPDY 6121
#define SSL_PORT_SPDY 443

static const value_string frame_type_names[] = {
  { SPDY_DATA,          "DATA" },
  { SPDY_SYN_STREAM,    "SYN_STREAM" },
  { SPDY_SYN_REPLY,     "SYN_REPLY" },
  { SPDY_RST_STREAM,    "RST_STREAM" },
  { SPDY_SETTINGS,      "SETTINGS" },
  { SPDY_PING,          "PING" },
  { SPDY_GOAWAY,        "GOAWAY" },
  { SPDY_HEADERS,       "HEADERS" },
  { SPDY_WINDOW_UPDATE, "WINDOW_UPDATE" },
  { SPDY_CREDENTIAL,    "CREDENTIAL" },
  { SPDY_INVALID,       "INVALID" },
  { 0, NULL }
};

static const value_string rst_stream_status_names[] = {
  { 1,  "PROTOCOL_ERROR" },
  { 2,  "INVALID_STREAM" },
  { 3,  "REFUSED_STREAM" },
  { 4,  "UNSUPPORTED_VERSION" },
  { 5,  "CANCEL" },
  { 6,  "INTERNAL_ERROR" },
  { 7,  "FLOW_CONTROL_ERROR" },
  { 8,  "STREAM_IN_USE" },
  { 9,  "STREAM_ALREADY_CLOSED" },
  { 10, "INVALID_CREDENTIALS" },
  { 11, "FRAME_TOO_LARGE" },
  { 12, "INVALID" },
  { 0, NULL }
};

static const value_string setting_id_names[] = {
  { 1, "UPLOAD_BANDWIDTH" },
  { 2, "DOWNLOAD_BANDWIDTH" },
  { 3, "ROUND_TRIP_TIME" },
  { 4, "MAX_CONCURRENT_STREAMS" },
  { 5, "CURRENT_CWND" },
  { 6, "DOWNLOAD_RETRANS_RATE" },
  { 7, "INITIAL_WINDOW_SIZE" },
  { 0, NULL }
};

static const value_string goaway_status_names[] = {
  { 0,  "OK" },
  { 1,  "PROTOCOL_ERROR" },
  { 11, "INTERNAL_ERROR" },
  { 0, NULL }
};

/*
 * This structure will be tied to each SPDY frame and is used as an argument for
 * dissect_spdy_*_payload() functions.
 */
typedef struct _spdy_control_frame_info_t {
  gboolean control_bit;
  guint16  version;
  guint16  type;
  guint8   flags;
  guint32  length;  /* Actually only 24 bits. */
} spdy_control_frame_info_t;

/*
 * This structure will be tied to each SPDY header frame.
 * Only applies to frames containing headers: SYN_STREAM, SYN_REPLY, HEADERS
 * Note that there may be multiple SPDY frames in one packet.
 */
typedef struct _spdy_header_info_t {
  guint32 stream_id;
  guint8 *header_block;
  guint   header_block_len;
  guint16 frame_type;
} spdy_header_info_t;

static wmem_list_t *header_info_list;

/*
 * This structures keeps track of all the data frames
 * associated with a stream, so that they can be
 * reassembled into a single chunk.
 */
typedef struct _spdy_data_frame_t {
  guint8 *data;
  guint32 length;
  guint32 framenum;
} spdy_data_frame_t;

typedef struct _spdy_stream_info_t {
  gchar *content_type;
  gchar *content_type_parameters;
  gchar *content_encoding;
  wmem_list_t *data_frames;
  tvbuff_t *assembled_data;
  guint num_data_frames;
} spdy_stream_info_t;

/* Handles for metadata population. */

static int spdy_tap = -1;
static int spdy_eo_tap = -1;

static int proto_spdy = -1;
static int hf_spdy_data = -1;
static int hf_spdy_control_bit = -1;
static int hf_spdy_version = -1;
static int hf_spdy_type = -1;
static int hf_spdy_flags = -1;
static int hf_spdy_flags_fin = -1;
static int hf_spdy_flags_unidirectional = -1;
static int hf_spdy_flags_clear_settings = -1;
static int hf_spdy_flags_persist_value = -1;
static int hf_spdy_flags_persisted = -1;
static int hf_spdy_length = -1;
static int hf_spdy_header_block = -1;
static int hf_spdy_header = -1;
static int hf_spdy_header_name = -1;
static int hf_spdy_header_value = -1;
static int hf_spdy_streamid = -1;
static int hf_spdy_associated_streamid = -1;
static int hf_spdy_priority = -1;
static int hf_spdy_num_headers = -1;
static int hf_spdy_rst_stream_status = -1;
static int hf_spdy_num_settings = -1;
static int hf_spdy_setting = -1;
static int hf_spdy_setting_id = -1;
static int hf_spdy_setting_value = -1;
static int hf_spdy_ping_id = -1;
static int hf_spdy_goaway_last_good_stream_id = -1;
static int hf_spdy_goaway_status = -1;
static int hf_spdy_window_update_delta = -1;

static gint ett_spdy = -1;
static gint ett_spdy_flags = -1;
static gint ett_spdy_header_block = -1;
static gint ett_spdy_header = -1;
static gint ett_spdy_setting = -1;

static gint ett_spdy_encoded_entity = -1;

static expert_field ei_spdy_inflation_failed = EI_INIT;
static expert_field ei_spdy_mal_frame_data = EI_INIT;
static expert_field ei_spdy_mal_setting_frame = EI_INIT;
static expert_field ei_spdy_invalid_rst_stream = EI_INIT;
static expert_field ei_spdy_invalid_go_away = EI_INIT;
static expert_field ei_spdy_invalid_frame_type = EI_INIT;

static dissector_handle_t data_handle;
static dissector_handle_t media_handle;
static dissector_handle_t spdy_handle;
static dissector_table_t media_type_subdissector_table;
static dissector_table_t port_subdissector_table;

static gboolean spdy_assemble_entity_bodies = TRUE;

/*
 * Decompression of zlib encoded entities.
 */
#ifdef HAVE_LIBZ
static gboolean spdy_decompress_body = TRUE;
static gboolean spdy_decompress_headers = TRUE;
#else
static gboolean spdy_decompress_body = FALSE;
static gboolean spdy_decompress_headers = FALSE;
#endif

static const char spdy_dictionary[] = {
  0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69,  /* - - - - o p t i */
  0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68,  /* o n s - - - - h */
  0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70,  /* e a d - - - - p */
  0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70,  /* o s t - - - - p */
  0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65,  /* u t - - - - d e */
  0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05,  /* l e t e - - - - */
  0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00,  /* t r a c e - - - */
  0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00,  /* - a c c e p t - */
  0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70,  /* - - - a c c e p */
  0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,  /* t - c h a r s e */
  0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63,  /* t - - - - a c c */
  0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,  /* e p t - e n c o */
  0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f,  /* d i n g - - - - */
  0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c,  /* a c c e p t - l */
  0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00,  /* a n g u a g e - */
  0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70,  /* - - - a c c e p */
  0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73,  /* t - r a n g e s */
  0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00,  /* - - - - a g e - */
  0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77,  /* - - - a l l o w */
  0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68,  /* - - - - a u t h */
  0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,  /* o r i z a t i o */
  0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63,  /* n - - - - c a c */
  0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72,  /* h e - c o n t r */
  0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f,  /* o l - - - - c o */
  0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,  /* n n e c t i o n */
  0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74,  /* - - - - c o n t */
  0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65,  /* e n t - b a s e */
  0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74,  /* - - - - c o n t */
  0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,  /* e n t - e n c o */
  0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10,  /* d i n g - - - - */
  0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,  /* c o n t e n t - */
  0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,  /* l a n g u a g e */
  0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74,  /* - - - - c o n t */
  0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67,  /* e n t - l e n g */
  0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f,  /* t h - - - - c o */
  0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f,  /* n t e n t - l o */
  0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00,  /* c a t i o n - - */
  0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,  /* - - c o n t e n */
  0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00,  /* t - m d 5 - - - */
  0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,  /* - c o n t e n t */
  0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00,  /* - r a n g e - - */
  0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,  /* - - c o n t e n */
  0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00,  /* t - t y p e - - */
  0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00,  /* - - d a t e - - */
  0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00,  /* - - e t a g - - */
  0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74,  /* - - e x p e c t */
  0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69,  /* - - - - e x p i */
  0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66,  /* r e s - - - - f */
  0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68,  /* r o m - - - - h */
  0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69,  /* o s t - - - - i */
  0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00,  /* f - m a t c h - */
  0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f,  /* - - - i f - m o */
  0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73,  /* d i f i e d - s */
  0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d,  /* i n c e - - - - */
  0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d,  /* i f - n o n e - */
  0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00,  /* m a t c h - - - */
  0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67,  /* - i f - r a n g */
  0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d,  /* e - - - - i f - */
  0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69,  /* u n m o d i f i */
  0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65,  /* e d - s i n c e */
  0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74,  /* - - - - l a s t */
  0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,  /* - m o d i f i e */
  0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63,  /* d - - - - l o c */
  0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,  /* a t i o n - - - */
  0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72,  /* - m a x - f o r */
  0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00,  /* w a r d s - - - */
  0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00,  /* - p r a g m a - */
  0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79,  /* - - - p r o x y */
  0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,  /* - a u t h e n t */
  0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00,  /* i c a t e - - - */
  0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61,  /* - p r o x y - a */
  0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,  /* u t h o r i z a */
  0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05,  /* t i o n - - - - */
  0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00,  /* r a n g e - - - */
  0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72,  /* - r e f e r e r */
  0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72,  /* - - - - r e t r */
  0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00,  /* y - a f t e r - */
  0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,  /* - - - s e r v e */
  0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00,  /* r - - - - t e - */
  0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c,  /* - - - t r a i l */
  0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72,  /* e r - - - - t r */
  0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65,  /* a n s f e r - e */
  0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,  /* n c o d i n g - */
  0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61,  /* - - - u p g r a */
  0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73,  /* d e - - - - u s */
  0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,  /* e r - a g e n t */
  0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79,  /* - - - - v a r y */
  0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00,  /* - - - - v i a - */
  0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69,  /* - - - w a r n i */
  0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77,  /* n g - - - - w w */
  0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,  /* w - a u t h e n */
  0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00,  /* t i c a t e - - */
  0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,  /* - - m e t h o d */
  0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00,  /* - - - - g e t - */
  0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,  /* - - - s t a t u */
  0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30,  /* s - - - - 2 0 0 */
  0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76,  /* - O K - - - - v */
  0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00,  /* e r s i o n - - */
  0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,  /* - - H T T P - 1 */
  0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72,  /* - 1 - - - - u r */
  0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62,  /* l - - - - p u b */
  0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73,  /* l i c - - - - s */
  0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69,  /* e t - c o o k i */
  0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65,  /* e - - - - k e e */
  0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00,  /* p - a l i v e - */
  0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69,  /* - - - o r i g i */
  0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32,  /* n 1 0 0 1 0 1 2 */
  0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35,  /* 0 1 2 0 2 2 0 5 */
  0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30,  /* 2 0 6 3 0 0 3 0 */
  0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33,  /* 2 3 0 3 3 0 4 3 */
  0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37,  /* 0 5 3 0 6 3 0 7 */
  0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30,  /* 4 0 2 4 0 5 4 0 */
  0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34,  /* 6 4 0 7 4 0 8 4 */
  0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31,  /* 0 9 4 1 0 4 1 1 */
  0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31,  /* 4 1 2 4 1 3 4 1 */
  0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34,  /* 4 4 1 5 4 1 6 4 */
  0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34,  /* 1 7 5 0 2 5 0 4 */
  0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e,  /* 5 0 5 2 0 3 - N */
  0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f,  /* o n - A u t h o */
  0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65,  /* r i t a t i v e */
  0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61,  /* - I n f o r m a */
  0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20,  /* t i o n 2 0 4 - */
  0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65,  /* N o - C o n t e */
  0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f,  /* n t 3 0 1 - M o */
  0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d,  /* v e d - P e r m */
  0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34,  /* a n e n t l y 4 */
  0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52,  /* 0 0 - B a d - R */
  0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30,  /* e q u e s t 4 0 */
  0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68,  /* 1 - U n a u t h */
  0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30,  /* o r i z e d 4 0 */
  0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64,  /* 3 - F o r b i d */
  0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e,  /* d e n 4 0 4 - N */
  0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64,  /* o t - F o u n d */
  0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65,  /* 5 0 0 - I n t e */
  0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72,  /* r n a l - S e r */
  0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f,  /* v e r - E r r o */
  0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74,  /* r 5 0 1 - N o t */
  0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,  /* - I m p l e m e */
  0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20,  /* n t e d 5 0 3 - */
  0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20,  /* S e r v i c e - */
  0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61,  /* U n a v a i l a */
  0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46,  /* b l e J a n - F */
  0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41,  /* e b - M a r - A */
  0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a,  /* p r - M a y - J */
  0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41,  /* u n - J u l - A */
  0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20,  /* u g - S e p t - */
  0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20,  /* O c t - N o v - */
  0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30,  /* D e c - 0 0 - 0 */
  0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e,  /* 0 - 0 0 - M o n */
  0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57,  /* - - T u e - - W */
  0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c,  /* e d - - T h u - */
  0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61,  /* - F r i - - S a */
  0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,  /* t - - S u n - - */
  0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b,  /* G M T c h u n k */
  0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f,  /* e d - t e x t - */
  0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61,  /* h t m l - i m a */
  0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69,  /* g e - p n g - i */
  0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67,  /* m a g e - j p g */
  0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67,  /* - i m a g e - g */
  0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,  /* i f - a p p l i */
  0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,  /* c a t i o n - x */
  0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,  /* m l - a p p l i */
  0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,  /* c a t i o n - x */
  0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c,  /* h t m l - x m l */
  0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c,  /* - t e x t - p l */
  0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74,  /* a i n - t e x t */
  0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72,  /* - j a v a s c r */
  0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c,  /* i p t - p u b l */
  0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,  /* i c p r i v a t */
  0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65,  /* e m a x - a g e */
  0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65,  /* - g z i p - d e */
  0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64,  /* f l a t e - s d */
  0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,  /* c h c h a r s e */
  0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63,  /* t - u t f - 8 c */
  0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69,  /* h a r s e t - i */
  0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d,  /* s o - 8 8 5 9 - */
  0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a,  /* 1 - u t f - - - */
  0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e         /* - e n q - 0 -   */
};

#ifdef HAVE_LIBZ
/* callback function used at the end of file-scope to cleanup zlib's inflate
 * streams to avoid memory leaks.
 * XXX: can we be more aggressive and call this sooner for finished streams?
 */
static gboolean inflate_end_cb (wmem_allocator_t *allocator _U_,
    wmem_cb_event_t event _U_, void *user_data) {

  inflateEnd((z_streamp)user_data);

  return FALSE;
}
#endif

/*
 * Protocol initialization
 */
static void
spdy_init_protocol(void)
{
   header_info_list = NULL;
}

/*
 * Returns conversation data for a given packet. If conversation data can't be
 * found, creates and returns new conversation data.
 */
static spdy_conv_t * get_or_create_spdy_conversation_data(packet_info *pinfo) {
  conversation_t  *conversation;
  spdy_conv_t *conv_data;
#ifdef HAVE_LIBZ
  int retcode;
#endif

  conversation = find_or_create_conversation(pinfo);

  /* Retrieve information from conversation */
  conv_data = (spdy_conv_t *)conversation_get_proto_data(conversation, proto_spdy);
  if (!conv_data) {
    /* Set up the conversation structure itself */
    conv_data = wmem_new0(wmem_file_scope(), spdy_conv_t);

    conv_data->streams = NULL;
    if (spdy_decompress_headers) {
#ifdef HAVE_LIBZ
      conv_data->rqst_decompressor = wmem_new0(wmem_file_scope(), z_stream);
      conv_data->rply_decompressor = wmem_new0(wmem_file_scope(), z_stream);
      retcode = inflateInit(conv_data->rqst_decompressor);
      if (retcode == Z_OK) {
        wmem_register_callback(wmem_file_scope(), inflate_end_cb,
            conv_data->rqst_decompressor);
        retcode = inflateInit(conv_data->rply_decompressor);
        if (retcode == Z_OK) {
          wmem_register_callback(wmem_file_scope(), inflate_end_cb,
              conv_data->rply_decompressor);
        }
      }

      /* XXX - use wsutil/adler32.h? */
      conv_data->dictionary_id = adler32(0L, Z_NULL, 0);
      conv_data->dictionary_id = adler32(conv_data->dictionary_id,
                                         spdy_dictionary,
                                         (uInt)sizeof(spdy_dictionary));
#endif
    }

    conversation_add_proto_data(conversation, proto_spdy, conv_data);
  }

  return conv_data;
}

/*
 * Retains state on a given stream.
 */
static void spdy_save_stream_info(spdy_conv_t *conv_data,
                                  guint32 stream_id,
                                  gchar *content_type,
                                  gchar *content_type_params,
                                  gchar *content_encoding) {
  spdy_stream_info_t *si;

  if (conv_data->streams == NULL) {
    conv_data->streams = wmem_tree_new(wmem_file_scope());
  }

  si = (spdy_stream_info_t *)wmem_alloc(wmem_file_scope(), sizeof(spdy_stream_info_t));
  si->content_type = content_type;
  si->content_type_parameters = content_type_params;
  si->content_encoding = content_encoding;
  si->data_frames = wmem_list_new(wmem_file_scope());
  si->num_data_frames = 0;
  si->assembled_data = NULL;
  wmem_tree_insert32(conv_data->streams, stream_id, si);
}

/*
 * Retrieves previously saved state on a given stream.
 */
static spdy_stream_info_t* spdy_get_stream_info(spdy_conv_t *conv_data,
                                                guint32 stream_id)
{
  if (conv_data->streams == NULL)
    return NULL;

  return (spdy_stream_info_t*)wmem_tree_lookup32(conv_data->streams, stream_id);
}

/*
 * Adds a data chunk to a given SPDY converstaion/stream.
 */
static void spdy_add_data_chunk(spdy_conv_t *conv_data,
                                guint32 stream_id,
                                guint32 frame,
                                guint8 *data,
                                guint32 length)
{
  spdy_stream_info_t *si = spdy_get_stream_info(conv_data, stream_id);

  if (si != NULL) {
    spdy_data_frame_t *df = (spdy_data_frame_t *)wmem_new(wmem_file_scope(), spdy_data_frame_t);
    df->data = data;
    df->length = length;
    df->framenum = frame;
    wmem_list_append(si->data_frames, df);
    ++si->num_data_frames;
  }
}

/*
 * Increment the count of DATA frames found on a given stream.
 */
static void spdy_increment_data_chunk_count(spdy_conv_t *conv_data,
                                            guint32 stream_id) {
  spdy_stream_info_t *si = spdy_get_stream_info(conv_data, stream_id);
  if (si != NULL) {
    ++si->num_data_frames;
  }
}

/*
 * Return the number of data frames saved so far for the specified stream.
 */
static guint spdy_get_num_data_frames(spdy_conv_t *conv_data,
                                      guint32 stream_id) {
  spdy_stream_info_t *si = spdy_get_stream_info(conv_data, stream_id);

  return si == NULL ? 0 : si->num_data_frames;
}

/*
 * Reassembles DATA frames for a given stream into one tvb.
 */
static spdy_stream_info_t* spdy_assemble_data_frames(spdy_conv_t *conv_data,
                                                     guint32 stream_id) {
  spdy_stream_info_t *si = spdy_get_stream_info(conv_data, stream_id);
  tvbuff_t *tvb;

  if (si == NULL) {
    return NULL;
  }

  /*
   * Compute the total amount of data and concatenate the
   * data chunks, if it hasn't already been done.
   */
  if (si->assembled_data == NULL) {
    spdy_data_frame_t *df;
    guint8 *data;
    guint32 datalen;
    guint32 offset;
    wmem_list_t *dflist = si->data_frames;
    wmem_list_frame_t *frame;
    if (wmem_list_count(dflist) == 0) {
      return si;
    }
    datalen = 0;
    /*
     * It'd be nice to use a composite tvbuff here, but since
     * only a real-data tvbuff can be the child of another
     * tvb, we can't. It would be nice if this limitation
     * could be fixed.
     */
    frame = wmem_list_frame_next(wmem_list_head(dflist));
    while (frame != NULL) {
      df = (spdy_data_frame_t *)wmem_list_frame_data(frame);
      datalen += df->length;
      frame = wmem_list_frame_next(frame);
    }
    if (datalen != 0) {
      data = (guint8 *)wmem_alloc(wmem_file_scope(), datalen);
      dflist = si->data_frames;
      offset = 0;
      frame = wmem_list_frame_next(wmem_list_head(dflist));
      while (frame != NULL) {
        df = (spdy_data_frame_t *)wmem_list_frame_data(frame);
        memcpy(data+offset, df->data, df->length);
        offset += df->length;
        frame = wmem_list_frame_next(frame);
      }
      tvb = tvb_new_real_data(data, datalen, datalen);
      si->assembled_data = tvb;
    }
  }
  return si;
}

/*
 * Same as dissect_spdy_stream_id below, except with explicit field index.
 */
static void dissect_spdy_stream_id_field(tvbuff_t *tvb,
                                         int offset,
                                         packet_info *pinfo _U_,
                                         proto_tree *frame_tree,
                                         const int hfindex)
{
  guint32 stream_id = tvb_get_ntohl(tvb, offset) & SPDY_STREAM_ID_MASK;

  /* Add stream id to tree. */
  proto_tree_add_item(frame_tree, hfindex, tvb, offset, 4, ENC_BIG_ENDIAN);

  if (hfindex == hf_spdy_streamid) {
    proto_item_append_text(frame_tree, ", Stream: %u", stream_id);
  }
}

/*
 * Adds flag details to proto tree.
 */
static void dissect_spdy_flags(tvbuff_t *tvb,
                               int offset,
                               proto_tree *frame_tree,
                               const spdy_control_frame_info_t *frame) {
  proto_item *flags_ti;
  proto_tree *flags_tree;

  /* Create flags substree. */
  flags_ti = proto_tree_add_item(frame_tree, hf_spdy_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
  flags_tree = proto_item_add_subtree(flags_ti, ett_spdy_flags);

  /* Add FIN flag for appropriate frames. */
  if (frame->type == SPDY_DATA ||
      frame->type == SPDY_SYN_STREAM ||
      frame->type == SPDY_SYN_REPLY ||
      frame->type == SPDY_HEADERS) {
    /* Add FIN flag. */
    proto_tree_add_item(flags_tree, hf_spdy_flags_fin, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (frame->flags & SPDY_FLAG_FIN) {
      proto_item_append_text(frame_tree, " (FIN)");
      proto_item_append_text(flags_ti, " (FIN)");
    }
  }

  /* Add UNIDIRECTIONAL flag, only applicable for SYN_STREAM. */
  if (frame->type == SPDY_SYN_STREAM) {
    proto_tree_add_item(flags_tree, hf_spdy_flags_unidirectional, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    if (frame->flags & SPDY_FLAG_UNIDIRECTIONAL) {
      proto_item_append_text(flags_ti, " (UNIDIRECTIONAL)");
    }
  }

  /* Add CLEAR_SETTINGS flag, only applicable for SETTINGS. */
  if (frame->type == SPDY_SETTINGS) {
    proto_tree_add_item(flags_tree, hf_spdy_flags_clear_settings, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    if (frame->flags & SPDY_FLAG_SETTINGS_CLEAR_SETTINGS) {
      proto_item_append_text(flags_ti, " (CLEAR)");
    }
  }
}

/*
 * Performs DATA frame payload dissection.
 */
static int dissect_spdy_data_payload(tvbuff_t *tvb,
                                     int offset,
                                     packet_info *pinfo,
                                     proto_tree *top_level_tree _U_,
                                     proto_tree *spdy_tree,
                                     proto_item *spdy_proto,
                                     spdy_conv_t *conv_data,
                                     guint32 stream_id,
                                     const spdy_control_frame_info_t *frame)
{
  dissector_handle_t handle;
  guint num_data_frames;
  gboolean dissected;

  /* Add frame description. */
  proto_item_append_text(spdy_proto, ", Stream: %d, Length: %d",
                           stream_id,
                           frame->length);

  /* Add data. */
  proto_tree_add_item(spdy_tree, hf_spdy_data, tvb, offset, frame->length, ENC_NA);

  num_data_frames = spdy_get_num_data_frames(conv_data, stream_id);
  if (frame->length != 0 || num_data_frames != 0) {
    /*
     * There's stuff left over; process it.
     */
    tvbuff_t *next_tvb = NULL;
    tvbuff_t    *data_tvb = NULL;
    spdy_stream_info_t *si = NULL;
    void *save_private_data = NULL;
    guint8 *copied_data;
    gboolean private_data_changed = FALSE;
    gboolean is_single_chunk = FALSE;
    gboolean have_entire_body;

    /*
     * Create a tvbuff for the payload.
     */
    if (frame->length != 0) {
      next_tvb = tvb_new_subset_length(tvb, offset, frame->length);
      is_single_chunk = num_data_frames == 0 &&
          (frame->flags & SPDY_FLAG_FIN) != 0;
      if (!pinfo->fd->flags.visited) {
        if (!is_single_chunk) {
          if (spdy_assemble_entity_bodies) {
            copied_data = (guint8 *)tvb_memdup(wmem_file_scope(),next_tvb, 0, frame->length);
            spdy_add_data_chunk(conv_data, stream_id, pinfo->fd->num, copied_data, frame->length);
          } else {
            spdy_increment_data_chunk_count(conv_data, stream_id);
          }
        }
      }
    } else {
      is_single_chunk = (num_data_frames == 1);
    }

    if (!(frame->flags & SPDY_FLAG_FIN)) {
      col_set_fence(pinfo->cinfo, COL_INFO);
      proto_item_append_text(spdy_proto, " (partial entity body)");
      /* would like the proto item to say */
      /* " (entity body fragment N of M)" */
      goto body_dissected;
    }
    have_entire_body = is_single_chunk;
    /*
     * On seeing the last data frame in a stream, we can
     * reassemble the frames into one data block.
     */
    si = spdy_assemble_data_frames(conv_data, stream_id);
    if (si == NULL) {
      goto body_dissected;
    }
    data_tvb = si->assembled_data;
    if (spdy_assemble_entity_bodies) {
      have_entire_body = TRUE;
    }

    if (!have_entire_body) {
      goto body_dissected;
    }

    if (data_tvb == NULL) {
      data_tvb = next_tvb;
    } else {
      add_new_data_source(pinfo, data_tvb, "Assembled entity body");
    }

    if (have_entire_body && si->content_encoding != NULL &&
      g_ascii_strcasecmp(si->content_encoding, "identity") != 0) {
      /*
       * We currently can't handle, for example, "compress";
       * just handle them as data for now.
       *
       * After July 7, 2004 the LZW patent expires, so support
       * might be added then.  However, I don't think that
       * anybody ever really implemented "compress", due to
       * the aforementioned patent.
       */
      tvbuff_t *uncomp_tvb = NULL;
      proto_item *e_ti = NULL;
      proto_item *ce_ti = NULL;
      proto_tree *e_tree = NULL;

      if (spdy_decompress_body &&
          (g_ascii_strcasecmp(si->content_encoding, "gzip") == 0 ||
           g_ascii_strcasecmp(si->content_encoding, "deflate") == 0)) {
        uncomp_tvb = tvb_child_uncompress(tvb, data_tvb, 0,
                                               tvb_reported_length(data_tvb));
      }
      /*
       * Add the encoded entity to the protocol tree
       */
      e_ti = proto_tree_add_text(spdy_tree, data_tvb,
                                 0, tvb_reported_length(data_tvb),
                                 "Content-encoded entity body (%s): %u bytes",
                                 si->content_encoding,
                                 tvb_reported_length(data_tvb));
      e_tree = proto_item_add_subtree(e_ti, ett_spdy_encoded_entity);
      if (si->num_data_frames > 1) {
        wmem_list_t *dflist = si->data_frames;
        wmem_list_frame_t *frame_item;
        spdy_data_frame_t *df;
        guint32 framenum;
        ce_ti = proto_tree_add_text(e_tree, data_tvb, 0,
                                    tvb_reported_length(data_tvb),
                                    "Assembled from %d frames in packet(s)",
                                    si->num_data_frames);
        framenum = 0;
        frame_item = wmem_list_frame_next(wmem_list_head(dflist));
        while (frame_item != NULL) {
          df = (spdy_data_frame_t *)wmem_list_frame_data(frame_item);
          if (framenum != df->framenum) {
            proto_item_append_text(ce_ti, " #%u", df->framenum);
            framenum = df->framenum;
          }
          frame_item = wmem_list_frame_next(frame_item);
        }
      }

      if (uncomp_tvb != NULL) {
        /*
         * Decompression worked
         */

        /* XXX - Don't free this, since it's possible
         * that the data was only partially
         * decompressed, such as when desegmentation
         * isn't enabled.
         *
         tvb_free(next_tvb);
         */
        proto_item_append_text(e_ti, " -> %u bytes", tvb_reported_length(uncomp_tvb));
        data_tvb = uncomp_tvb;
        add_new_data_source(pinfo, data_tvb, "Uncompressed entity body");
      } else {
        if (spdy_decompress_body) {
          proto_item_append_text(e_ti, " [Error: Decompression failed]");
        }
        call_dissector(data_handle, data_tvb, pinfo, e_tree);

        goto body_dissected;
      }
    }

    /*
     * Do subdissector checks.
     *
     * First, check whether some subdissector asked that they
     * be called if something was on some particular port.
     */

    if (have_entire_body && port_subdissector_table != NULL) {
      handle = dissector_get_uint_handle(port_subdissector_table,
                                         pinfo->match_uint);
    } else {
      handle = NULL;
    }
    if (handle == NULL && have_entire_body && si->content_type != NULL &&
      media_type_subdissector_table != NULL) {
      /*
       * We didn't find any subdissector that
       * registered for the port, and we have a
       * Content-Type value.  Is there any subdissector
       * for that content type?
       */
      save_private_data = pinfo->private_data;
      private_data_changed = TRUE;

      if (si->content_type_parameters) {
        pinfo->private_data = wmem_strdup(wmem_packet_scope(), si->content_type_parameters);
      } else {
        pinfo->private_data = NULL;
      }
      /*
       * Calling the string handle for the media type
       * dissector table will set pinfo->match_string
       * to si->content_type for us.
       */
      pinfo->match_string = si->content_type;
      handle = dissector_get_string_handle(media_type_subdissector_table,
                                           si->content_type);
    }
    if (handle != NULL) {
      /*
       * We have a subdissector - call it.
       */
      dissected = call_dissector(handle, data_tvb, pinfo, spdy_tree);
    } else {
      dissected = FALSE;
    }

    if (!dissected && have_entire_body && si->content_type != NULL) {
      /*
       * Calling the default media handle if there is a content-type that
       * wasn't handled above.
       */
      call_dissector(media_handle, next_tvb, pinfo, spdy_tree);
    } else {
      /* Call the default data dissector */
      call_dissector(data_handle, next_tvb, pinfo, spdy_tree);
    }

body_dissected:
    /*
     * Do *not* attempt at freeing the private data;
     * it may be in use by subdissectors.
     */
    if (private_data_changed) { /*restore even NULL value*/
      pinfo->private_data = save_private_data;
    }
    /*
     * We've processed frame->length bytes worth of data
     * (which may be no data at all); advance the
     * offset past whatever data we've processed.
     */
  }
  return frame->length;
}

#ifdef HAVE_LIBZ
/*
 * Performs header decompression.
 *
 * The returned buffer is automatically scoped to the lifetime of the capture
 * (via se_memdup()).
 */
#define DECOMPRESS_BUFSIZE	16384

static guint8* spdy_decompress_header_block(tvbuff_t *tvb,
                                            z_streamp decomp,
                                            uLong dictionary_id,
                                            int offset,
                                            guint32 length,
                                            guint *uncomp_length) {
  int retcode;
  const guint8 *hptr = tvb_get_ptr(tvb, offset, length);
  guint8 *uncomp_block = (guint8 *)wmem_alloc(wmem_packet_scope(), DECOMPRESS_BUFSIZE);

  decomp->next_in = (Bytef *)hptr;
  decomp->avail_in = length;
  decomp->next_out = uncomp_block;
  decomp->avail_out = DECOMPRESS_BUFSIZE;
  retcode = inflate(decomp, Z_SYNC_FLUSH);
  if (retcode == Z_NEED_DICT) {
    if (decomp->adler == dictionary_id) {
      retcode = inflateSetDictionary(decomp,
                                     spdy_dictionary,
                                     sizeof(spdy_dictionary));
      if (retcode == Z_OK) {
        retcode = inflate(decomp, Z_SYNC_FLUSH);
      }
    }
  }

  /* Handle errors. */
  if (retcode != Z_OK) {
    return NULL;
  }

  /* Handle successful inflation. */
  *uncomp_length = DECOMPRESS_BUFSIZE - decomp->avail_out;

  return (guint8 *)wmem_memdup(wmem_file_scope(), uncomp_block, *uncomp_length);
}
#endif


/*
 * Saves state on header data for a given stream.
 */
static spdy_header_info_t* spdy_save_header_block(packet_info *pinfo _U_,
                                                  guint32 stream_id,
                                                  guint16 frame_type,
                                                  guint8 *header,
                                                  guint length) {
  spdy_header_info_t *header_info;

  if (header_info_list == NULL)
    header_info_list = wmem_list_new(wmem_file_scope());

  header_info = wmem_new(wmem_file_scope(), spdy_header_info_t);
  header_info->stream_id = stream_id;
  header_info->header_block = header;
  header_info->header_block_len = length;
  header_info->frame_type = frame_type;
  wmem_list_append(header_info_list, header_info);
  return header_info;
}

/*
 * Retrieves saved state for a given stream.
 */
static spdy_header_info_t* spdy_find_saved_header_block(packet_info *pinfo _U_,
                                                        guint32 stream_id,
                                                        guint16 frame_type) {
  wmem_list_frame_t *frame;

  if ((header_info_list == NULL) || (wmem_list_head(header_info_list) == NULL))
      return NULL;

  frame = wmem_list_frame_next(wmem_list_head(header_info_list));
  while (frame != NULL) {
      spdy_header_info_t *hi = (spdy_header_info_t *)wmem_list_frame_data(frame);
      if (hi->stream_id == stream_id && hi->frame_type == frame_type)
          return hi;
      frame = wmem_list_frame_next(frame);
  }
  return NULL;
}

/*
 * Given a content type string that may contain optional parameters,
 * return the parameter string, if any, otherwise return NULL. This
 * also has the side effect of null terminating the content type
 * part of the original string.
 */
static gchar* spdy_parse_content_type(gchar *content_type) {
  gchar *cp = content_type;

  while (*cp != '\0' && *cp != ';' && !isspace(*cp)) {
    *cp = tolower(*cp);
    ++cp;
  }
  if (*cp == '\0') {
    cp = NULL;
  }

  if (cp != NULL) {
    *cp++ = '\0';
    while (*cp == ';' || isspace(*cp)) {
      ++cp;
    }
    if (*cp != '\0') {
      return cp;
    }
  }
  return NULL;
}

static int dissect_spdy_header_payload(
  tvbuff_t *tvb,
  int offset,
  packet_info *pinfo,
  proto_tree *frame_tree,
  const spdy_control_frame_info_t *frame,
  spdy_conv_t *conv_data) {
  guint32 stream_id;
  int header_block_length = frame->length;
  int hdr_offset = 0;
  tvbuff_t *header_tvb = NULL;
  const gchar *hdr_method = NULL;
  const gchar *hdr_path = NULL;
  const gchar *hdr_version = NULL;
  const gchar *hdr_host = NULL;
  const gchar *hdr_scheme = NULL;
  const gchar *hdr_status = NULL;
  gchar *content_type = NULL;
  gchar *content_encoding = NULL;
  guint32 num_headers = 0;
  proto_item *header_block_item;
  proto_tree *header_block_tree;

  /* Get stream id, which is present in all types of header frames. */
  stream_id = tvb_get_ntohl(tvb, offset) & SPDY_STREAM_ID_MASK;
  dissect_spdy_stream_id_field(tvb, offset, pinfo, frame_tree, hf_spdy_streamid);
  offset += 4;

  /* Get SYN_STREAM-only fields. */
  if (frame->type == SPDY_SYN_STREAM) {
    /* Get associated stream ID. */
    dissect_spdy_stream_id_field(tvb, offset, pinfo, frame_tree, hf_spdy_associated_streamid);
    offset += 4;

    /* Get priority */
    proto_tree_add_item(frame_tree, hf_spdy_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;
  }


  /* Get our header block length. */
  switch (frame->type) {
    case SPDY_SYN_STREAM:
      header_block_length -= 10;
      break;
    case SPDY_SYN_REPLY:
    case SPDY_HEADERS:
      header_block_length -= 4;
      break;
    default:
      /* Unhandled case. This should never happen. */
      DISSECTOR_ASSERT_NOT_REACHED();
  }

  /* Add the header block. */
  header_block_item = proto_tree_add_item(frame_tree,
                                            hf_spdy_header_block,
                                            tvb,
                                            offset,
                                            header_block_length,
                                            ENC_NA);
  header_block_tree = proto_item_add_subtree(header_block_item,
                                               ett_spdy_header_block);

  /* Decompress header block as necessary. */
  if (!spdy_decompress_headers) {
    header_tvb = tvb;
    hdr_offset = offset;
  } else {
    spdy_header_info_t *header_info;

    /* First attempt to find previously decompressed data.
     * This will not work correctly for lower-level frames that contain more
     * than one SPDY frame of the same type. We assume this to never be the
     * case, though. */
    header_info = spdy_find_saved_header_block(pinfo,
                                               stream_id,
                                               frame->type);

    /* Generate decompressed data and store it, since none was found. */
    if (header_info == NULL) {
      guint8 *uncomp_ptr = NULL;
      guint uncomp_length = 0;
#ifdef HAVE_LIBZ
      z_streamp decomp;

      /* Get our decompressor. */
      if (stream_id % 2 == 0) {
        /* Even streams are server-initiated and should never get a
         * client-initiated header block. Use reply decompressor. */
        decomp = conv_data->rply_decompressor;
      } else if (frame->type == SPDY_HEADERS) {
        /* Odd streams are client-initiated, but may have HEADERS from either
         * side. Currently, no known clients send HEADERS so we assume they are
         * all from the server. */
        decomp = conv_data->rply_decompressor;
      } else if (frame->type == SPDY_SYN_STREAM) {
        decomp = conv_data->rqst_decompressor;
      } else if (frame->type == SPDY_SYN_REPLY) {
        decomp = conv_data->rply_decompressor;
      } else {
        /* Unhandled case. This should never happen. */
        DISSECTOR_ASSERT_NOT_REACHED();
      }

      /* Decompress. */
      uncomp_ptr = spdy_decompress_header_block(tvb,
                                                decomp,
                                                conv_data->dictionary_id,
                                                offset,
                                                header_block_length,
                                                &uncomp_length);

      /* Catch decompression failures. */
      if (uncomp_ptr == NULL) {
        expert_add_info(pinfo, frame_tree, &ei_spdy_inflation_failed);

        proto_item_append_text(frame_tree, " [Error: Header decompression failed]");
        return -1;
      }
#endif

      /* Store decompressed data. */
      header_info = spdy_save_header_block(pinfo, stream_id, frame->type, uncomp_ptr, uncomp_length);
    }

    /* Create a tvb containing the uncompressed data. */
    header_tvb = tvb_new_child_real_data(tvb, header_info->header_block,
                                         header_info->header_block_len,
                                         header_info->header_block_len);
    add_new_data_source(pinfo, header_tvb, "Uncompressed headers");
    hdr_offset = 0;
  }

  /* Get header block details. */
  if (header_tvb == NULL || !spdy_decompress_headers) {
    num_headers = 0;
  } else {
    num_headers = tvb_get_ntohl(header_tvb, hdr_offset);
    /*ti = */ proto_tree_add_item(header_block_tree,
                             hf_spdy_num_headers,
                             header_tvb,
                             hdr_offset,
                             4,
                             ENC_BIG_ENDIAN);
  }
  hdr_offset += 4;

  /* Process headers. */
  while (num_headers--) {
    gchar *header_name;
    const gchar *header_value;
    proto_tree *header_tree;
    proto_item *header;
    int header_name_offset;
    int header_value_offset;
    int header_name_length;
    int header_value_length;

    /* Get header name details. */
    if (tvb_reported_length_remaining(header_tvb, hdr_offset) < 4) {
      expert_add_info_format(pinfo, frame_tree, &ei_spdy_mal_frame_data,
                             "Not enough frame data for header name size.");
      break;
    }
    header_name_offset = hdr_offset;
    header_name_length = tvb_get_ntohl(header_tvb, hdr_offset);
    hdr_offset += 4;
    if (tvb_reported_length_remaining(header_tvb, hdr_offset) < header_name_length) {
      expert_add_info_format(pinfo, frame_tree, &ei_spdy_mal_frame_data,
                             "Not enough frame data for header name.");
      break;
    }
    header_name = (gchar *)tvb_get_string_enc(wmem_packet_scope(), header_tvb,
                                                    hdr_offset,
                                                    header_name_length, ENC_ASCII|ENC_NA);
    hdr_offset += header_name_length;

    /* Get header value details. */
    if (tvb_reported_length_remaining(header_tvb, hdr_offset) < 4) {
      expert_add_info_format(pinfo, frame_tree, &ei_spdy_mal_frame_data,
                             "Not enough frame data for header value size.");
      break;
    }
    header_value_offset = hdr_offset;
    header_value_length = tvb_get_ntohl(header_tvb, hdr_offset);
    hdr_offset += 4;
    if (tvb_reported_length_remaining(header_tvb, hdr_offset) < header_value_length) {
      expert_add_info_format(pinfo, frame_tree, &ei_spdy_mal_frame_data,
                             "Not enough frame data for header value.");
      break;
    }
    header_value = (gchar *)tvb_get_string_enc(wmem_packet_scope(),header_tvb,
                                                     hdr_offset,
                                                     header_value_length, ENC_ASCII|ENC_NA);
    hdr_offset += header_value_length;

    /* Populate tree with header name/value details. */
    if (frame_tree) {
      /* Add 'Header' subtree with description. */
      header = proto_tree_add_item(frame_tree,
                                   hf_spdy_header,
                                   header_tvb,
                                   header_name_offset,
                                   hdr_offset - header_name_offset,
                                   ENC_NA);
      proto_item_append_text(header, ": %s: %s", header_name, header_value);
      header_tree = proto_item_add_subtree(header, ett_spdy_header);

      /* Add header name. */
      proto_tree_add_item(header_tree, hf_spdy_header_name, header_tvb,
                          header_name_offset, 4, ENC_NA);

      /* Add header value. */
      proto_tree_add_item(header_tree, hf_spdy_header_value, header_tvb,
                          header_value_offset, 4, ENC_NA);
    }

    /*
     * TODO(ers) check that the header name contains only legal characters.
     */
    /* TODO(hkhalil): Make sure that prohibited headers aren't sent. */
    if (g_strcmp0(header_name, ":method") == 0) {
      hdr_method = header_value;
    } else if (g_strcmp0(header_name, ":path") == 0) {
      hdr_path = header_value;
    } else if (g_strcmp0(header_name, ":version") == 0) {
      hdr_version = header_value;
    } else if (g_strcmp0(header_name, ":host") == 0) {
      hdr_host = header_value;
    } else if (g_strcmp0(header_name, ":scheme") == 0) {
      hdr_scheme = header_value;
    } else if (g_strcmp0(header_name, ":status") == 0) {
      hdr_status = header_value;
    } else if (g_strcmp0(header_name, "content-type") == 0) {
      content_type = wmem_strdup(wmem_file_scope(), header_value);
    } else if (g_strcmp0(header_name, "content-encoding") == 0) {
      content_encoding = wmem_strdup(wmem_file_scope(), header_value);
    }
  }

  /* Set Info column. */
  if (hdr_version != NULL) {
    if (hdr_status == NULL) {
      proto_item_append_text(frame_tree, ", Request: %s %s://%s%s %s",
                      hdr_method, hdr_scheme, hdr_host, hdr_path, hdr_version);
    } else {
      proto_item_append_text(frame_tree, ", Response: %s %s",
                      hdr_status, hdr_version);
    }
  }

  /*
   * If we expect data on this stream, we need to remember the content
   * type and content encoding.
   */
  if (content_type != NULL && !pinfo->fd->flags.visited) {
    gchar *content_type_params = spdy_parse_content_type(content_type);
    spdy_save_stream_info(conv_data, stream_id, content_type,
                          content_type_params, content_encoding);
  }

  return frame->length;
}

static int dissect_spdy_rst_stream_payload(
  tvbuff_t *tvb,
  int offset,
  packet_info *pinfo,
  proto_tree *frame_tree,
  const spdy_control_frame_info_t *frame) {
  guint32 rst_status;
  proto_item *ti;
  const char* str;

  /* Get stream ID and add to info column and tree. */
  dissect_spdy_stream_id_field(tvb, offset, pinfo, frame_tree, hf_spdy_streamid);
  offset += 4;

  /* Get status. */

  ti = proto_tree_add_item(frame_tree, hf_spdy_rst_stream_status, tvb, offset, 4, ENC_BIG_ENDIAN);
  rst_status = tvb_get_ntohl(tvb, offset);
  if (try_val_to_str(rst_status, rst_stream_status_names) == NULL) {
    /* Handle boundary conditions. */
    expert_add_info_format(pinfo, ti, &ei_spdy_invalid_rst_stream,
                           "Invalid status code for RST_STREAM: %u", rst_status);
  }

  str = val_to_str(rst_status, rst_stream_status_names, "Unknown (%d)");

  proto_item_append_text(frame_tree, ", Status: %s", str);

  return frame->length;
}

static int dissect_spdy_settings_payload(
  tvbuff_t *tvb,
  int offset,
  packet_info *pinfo,
  proto_tree *frame_tree,
  const spdy_control_frame_info_t *frame) {
  guint32 num_entries;
  proto_item *ti, *ti_setting;
  proto_tree *setting_tree;
  proto_tree *flags_tree;

  /* Make sure that we have enough room for our number of entries field. */
  if (frame->length < 4) {
    expert_add_info(pinfo, frame_tree, &ei_spdy_mal_setting_frame);
    return -1;
  }

  /* Get number of entries, and make sure we have enough room for them. */
  num_entries = tvb_get_ntohl(tvb, offset);
  if (frame->length < num_entries * 8) {
    expert_add_info_format(pinfo, frame_tree, &ei_spdy_mal_setting_frame,
        "SETTINGS frame too small [num_entries=%d]", num_entries);
    return -1;
  }

  proto_tree_add_item(frame_tree, hf_spdy_num_settings, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* Dissect each entry. */
  while (num_entries > 0) {
    const gchar *setting_id_str;
    guint32 setting_value;

    /* Create key/value pair subtree. */
    ti_setting = proto_tree_add_item(frame_tree, hf_spdy_setting, tvb, offset, 8, ENC_NA);
    setting_tree = proto_item_add_subtree(ti_setting, ett_spdy_setting);

    /* Set flags. */
    if (setting_tree) {
      ti = proto_tree_add_item(setting_tree, hf_spdy_flags, tvb, offset, 1, ENC_NA);

      /* TODO(hkhalil): Prettier output for flags sub-tree description. */
      flags_tree = proto_item_add_subtree(ti, ett_spdy_flags);
      proto_tree_add_item(flags_tree, hf_spdy_flags_persist_value, tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(flags_tree, hf_spdy_flags_persisted, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;

    /* Set ID. */
    setting_id_str = val_to_str(tvb_get_ntoh24(tvb, offset), setting_id_names, "Unknown(%d)");

    proto_tree_add_item(setting_tree, hf_spdy_setting_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Set Value. */
    setting_value = tvb_get_ntohl(tvb, offset);

    proto_tree_add_item(setting_tree, hf_spdy_setting_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_setting, ", %s: %u", setting_id_str, setting_value);
    proto_item_append_text(frame_tree, ", %s: %u", setting_id_str, setting_value);
    offset += 4;

    /* Increment. */
    --num_entries;
  }

  return frame->length;
}

static int dissect_spdy_ping_payload(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                                     proto_tree *frame_tree, const spdy_control_frame_info_t *frame)
{
  /* Get ping ID. */
  guint32 ping_id = tvb_get_ntohl(tvb, offset);

  /* Add proto item for ping ID. */
  proto_tree_add_item(frame_tree, hf_spdy_ping_id, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_item_append_text(frame_tree, ", ID: %u", ping_id);

  return frame->length;
}

static int dissect_spdy_goaway_payload(tvbuff_t *tvb,
                                       int offset,
                                       packet_info *pinfo,
                                       proto_tree *frame_tree,
                                       const spdy_control_frame_info_t *frame) {
  guint32 goaway_status;
  proto_item* ti;

  /* Get last good stream ID and add to info column and tree. */
  dissect_spdy_stream_id_field(tvb, offset, pinfo, frame_tree, hf_spdy_goaway_last_good_stream_id);
  offset += 4;

  /* Add proto item for goaway_status. */
  ti = proto_tree_add_item(frame_tree, hf_spdy_goaway_status, tvb, offset, 4, ENC_BIG_ENDIAN);
  goaway_status = tvb_get_ntohl(tvb, offset);

  if (try_val_to_str(goaway_status, goaway_status_names) == NULL) {
    /* Handle boundary conditions. */
    expert_add_info_format(pinfo, ti, &ei_spdy_invalid_go_away,
                           "Invalid status code for GOAWAY: %u", goaway_status);
  }

  /* Add status to info column. */
  proto_item_append_text(frame_tree, " Status=%s)",
                  val_to_str(goaway_status, rst_stream_status_names, "Unknown (%d)"));

  return frame->length;
}

static int dissect_spdy_window_update_payload(
    tvbuff_t *tvb,
    int offset,
    packet_info *pinfo,
    proto_tree *frame_tree,
    const spdy_control_frame_info_t *frame)
{
  guint32             window_update_delta;

  /* Get stream ID. */
  dissect_spdy_stream_id_field(tvb, offset, pinfo, frame_tree, hf_spdy_streamid);
  offset += 4;

  /* Get window update delta. */
  window_update_delta = tvb_get_ntohl(tvb, offset) & 0x7FFFFFFF;

  /* Add proto item for window update delta. */
  proto_tree_add_item(frame_tree, hf_spdy_window_update_delta, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_item_append_text(frame_tree, ", Delta: %u", window_update_delta);

  return frame->length;
}

/*
 * Performs SPDY frame dissection.
 */
int dissect_spdy_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint8              control_bit;
  spdy_control_frame_info_t frame;
  guint32             stream_id = 0;
  const gchar         *frame_type_name;
  proto_tree          *spdy_tree;
  proto_item          *spdy_item, *type_item = NULL;
  int                 offset = 0;
  spdy_conv_t         *conv_data;

  conv_data = get_or_create_spdy_conversation_data(pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPDY");

  /* Create frame root. */
  spdy_item = proto_tree_add_item(tree, proto_spdy, tvb, offset, -1, ENC_NA);
  spdy_tree = proto_item_add_subtree(spdy_item, ett_spdy);

  /* Add control bit. */
  control_bit = tvb_get_guint8(tvb, offset) & 0x80;
  proto_tree_add_item(spdy_tree, hf_spdy_control_bit, tvb, offset, 1, ENC_NA);

  /* Process first four bytes of frame, formatted depending on control bit. */
  if (control_bit) {
    /* Add version. */
    frame.version = tvb_get_ntohs(tvb, offset) & 0x7FFF;
    proto_tree_add_item(spdy_tree, hf_spdy_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Add control frame type. */
    type_item = proto_tree_add_item(spdy_tree, hf_spdy_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    frame.type = tvb_get_ntohs(tvb, offset);
    if (frame.type >= SPDY_INVALID) {
      expert_add_info_format(pinfo, type_item, &ei_spdy_invalid_frame_type,
                             "Invalid SPDY control frame type: %d", frame.type);
      return -1;
    }
    offset += 2;

  } else {
    frame.type = SPDY_DATA;
    frame.version = 0; /* Version doesn't apply to DATA. */

    /* Add stream ID. */
    stream_id = tvb_get_ntohl(tvb, offset) & SPDY_STREAM_ID_MASK;
    proto_tree_add_item(spdy_tree, hf_spdy_streamid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
  }

  /* Add frame info. */
  frame_type_name = val_to_str(frame.type, frame_type_names, "Unknown(%d)");
  col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", frame_type_name);

  proto_item_append_text(spdy_tree, ": %s", frame_type_name);

  /* Add flags. */
  frame.flags = tvb_get_guint8(tvb, offset);
  if (spdy_tree) {
    dissect_spdy_flags(tvb, offset, spdy_tree, &frame);
  }
  offset += 1;

  /* Add length. */
  frame.length = tvb_get_ntoh24(tvb, offset);

  proto_item_set_len(spdy_item, frame.length + 8);
  proto_tree_add_item(spdy_tree, hf_spdy_length, tvb, offset, 3, ENC_BIG_ENDIAN);
  offset += 3;

  /*
   * Make sure there's as much data as the frame header says there is.
   */
  if ((guint)tvb_reported_length_remaining(tvb, offset) < frame.length) {
    expert_add_info_format(pinfo, tree, &ei_spdy_mal_frame_data,
                           "Not enough frame data: %d vs. %d",
                           frame.length, tvb_reported_length_remaining(tvb, offset));
    return -1;
  }

  /* Dissect DATA payload as necessary. */
  if (!control_bit) {
    return offset + dissect_spdy_data_payload(tvb, offset, pinfo, tree, spdy_tree,
                                              spdy_item, conv_data, stream_id, &frame);
  }

  /* Abort here if the version is too low. */
  if (frame.version < MIN_SPDY_VERSION) {
    proto_item_append_text(spdy_item, " [Unsupported Version]");
    return frame.length + 8;
  }

  switch (frame.type) {
    case SPDY_SYN_STREAM:
    case SPDY_SYN_REPLY:
    case SPDY_HEADERS:
      dissect_spdy_header_payload(tvb, offset, pinfo, spdy_tree, &frame, conv_data);
      break;

    case SPDY_RST_STREAM:
      dissect_spdy_rst_stream_payload(tvb, offset, pinfo, spdy_tree, &frame);
      break;

    case SPDY_SETTINGS:
      dissect_spdy_settings_payload(tvb, offset, pinfo, spdy_tree, &frame);
      break;

    case SPDY_PING:
      dissect_spdy_ping_payload(tvb, offset, pinfo, spdy_tree, &frame);
      break;

    case SPDY_GOAWAY:
      dissect_spdy_goaway_payload(tvb, offset, pinfo, spdy_tree, &frame);
      break;

    case SPDY_WINDOW_UPDATE:
      dissect_spdy_window_update_payload(tvb, offset, pinfo, spdy_tree, &frame);
      break;

    case SPDY_CREDENTIAL:
      /* TODO(hkhalil): Show something meaningful. */
      break;

    default:
      expert_add_info_format(pinfo, type_item, &ei_spdy_invalid_frame_type,
                             "Unhandled SPDY frame type: %d", frame.type);
      break;
  }

  /*
   * OK, we've set the Protocol and Info columns for the
   * first SPDY message; set a fence so that subsequent
   * SPDY messages don't overwrite the Info column.
   */
  col_set_fence(pinfo->cinfo, COL_INFO);

  /* Assume that we've consumed the whole frame. */
  return 8 + frame.length;
}

static guint get_spdy_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                  int offset)
{
  return (guint)tvb_get_ntoh24(tvb, offset + 5) + 8;
}

/*
 * Wrapper for dissect_spdy_frame, sets fencing and desegments as necessary.
 */
static int dissect_spdy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 8, get_spdy_message_len, dissect_spdy_frame, data);
   return tvb_captured_length(tvb);
}

#if 0 /* heuristic too weak */
/*
 * Looks for SPDY frame at tvb start.
 * If not enough data for either, requests more via desegment struct.
 */
gboolean dissect_spdy_heur(tvbuff_t *tvb,
                                  packet_info *pinfo,
                                  proto_tree *tree,
                                   void *data _U_)
{
  /*
   * The first byte of a SPDY frame must be either 0 or
   * 0x80. If it's not, assume that this is not SPDY.
   * (In theory, a data frame could have a stream ID
   * >= 2^24, in which case it won't have 0 for a first
   * byte, but this is a pretty reliable heuristic for
   * now.)
   */
  guint8 first_byte = tvb_get_guint8(tvb, 0);
  if (first_byte != 0x80 && first_byte != 0x0) {
    return FALSE;
  }

  /* Attempt dissection. */
  if (dissect_spdy(tvb, pinfo, tree, NULL) != 0) {
    return TRUE;
  }

  return FALSE;
}
#endif

/*
 * Performs plugin registration.
 */
void proto_register_spdy(void)
{
  static hf_register_info hf[] = {
    { &hf_spdy_data,
      { "Data",           "spdy.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_spdy_control_bit,
      { "Control frame",    "spdy.control_bit",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
        "TRUE if SPDY control frame", HFILL
      }
    },
    { &hf_spdy_version,
      { "Version",        "spdy.version",
        FT_UINT16, BASE_DEC, NULL, 0x7FFF,
        NULL, HFILL
      }
    },
    { &hf_spdy_type,
      { "Type",           "spdy.type",
        FT_UINT16, BASE_DEC,
        VALS(frame_type_names), 0x0,
        NULL, HFILL
      }
    },
    { &hf_spdy_flags,
      { "Flags",          "spdy.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_spdy_flags_fin,
      { "FIN",            "spdy.flags.fin",
        FT_BOOLEAN, 8,
        TFS(&tfs_set_notset), SPDY_FLAG_FIN,
        NULL, HFILL
      }
    },
    { &hf_spdy_flags_unidirectional,
      { "Unidirectional", "spdy.flags.fin",
        FT_BOOLEAN, 8,
        TFS(&tfs_set_notset), SPDY_FLAG_UNIDIRECTIONAL,
        NULL, HFILL
      }
    },
    { &hf_spdy_flags_clear_settings,
      { "Persist Value",  "spdy.flags.clear_settings",
        FT_BOOLEAN, 8,
        TFS(&tfs_set_notset), SPDY_FLAG_SETTINGS_CLEAR_SETTINGS,
        NULL, HFILL
      }
    },
    { &hf_spdy_flags_persist_value,
      { "Persist Value",  "spdy.flags.persist_value",
        FT_BOOLEAN, 8,
        TFS(&tfs_set_notset), SPDY_FLAG_SETTINGS_PERSIST_VALUE,
        NULL, HFILL
      }
    },
    { &hf_spdy_flags_persisted,
      { "Persisted",      "spdy.flags.persisted",
        FT_BOOLEAN, 8,
        TFS(&tfs_set_notset), SPDY_FLAG_SETTINGS_PERSISTED,
        NULL, HFILL
      }
    },
    { &hf_spdy_length,
      { "Length",         "spdy.length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_spdy_header_block,
      { "Header block", "spdy.header_block",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_header,
      { "Header",         "spdy.header",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_spdy_header_name,
      { "Name",           "spdy.header.name",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_header_value,
      { "Value",          "spdy.header.value",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_streamid,
      { "Stream ID",      "spdy.streamid",
          FT_UINT32, BASE_DEC, NULL, SPDY_STREAM_ID_MASK,
          NULL, HFILL
      }
    },
    { &hf_spdy_associated_streamid,
      { "Associated Stream ID",   "spdy.associated.streamid",
          FT_UINT32, BASE_DEC, NULL, SPDY_STREAM_ID_MASK,
          NULL, HFILL
      }
    },
    { &hf_spdy_priority,
      { "Priority",       "spdy.priority",
          FT_UINT8, BASE_DEC, NULL, 0x07,
          NULL, HFILL
      }
    },
    { &hf_spdy_num_headers,
      { "Number of headers", "spdy.numheaders",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_rst_stream_status,
      { "Reset Status",   "spdy.rst_stream_status",
          FT_UINT32, BASE_DEC, VALS(rst_stream_status_names), 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_num_settings,
      { "Number of Settings", "spdy.num_settings",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_setting,
      { "Setting",        "spdy.setting",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_setting_id,
      { "ID",             "spdy.setting.id",
          FT_UINT24, BASE_DEC, VALS(setting_id_names), 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_setting_value,
      { "Value",          "spdy.setting.value",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_ping_id,
      { "Ping ID",        "spdy.ping_id",
          FT_UINT24, BASE_DEC, NULL, 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_goaway_last_good_stream_id,
      { "Last Good Stream ID", "spdy.goaway_last_good_stream_id",
          FT_UINT32, BASE_DEC, NULL, SPDY_STREAM_ID_MASK,
          NULL, HFILL
      }
    },
    { &hf_spdy_goaway_status,
      { "Go Away Status", "spdy.goaway_status",
          FT_UINT32, BASE_DEC, VALS(goaway_status_names), 0x0,
          NULL, HFILL
      }
    },
    { &hf_spdy_window_update_delta,
      { "Window Update Delta", "spdy.window_update_delta",
          FT_UINT32, BASE_DEC, NULL, 0x7FFFFFFF,
          NULL, HFILL
      }
    },
  };
  static gint *ett[] = {
    &ett_spdy,
    &ett_spdy_flags,
    &ett_spdy_header_block,
    &ett_spdy_header,
    &ett_spdy_setting,
    &ett_spdy_encoded_entity,
  };

  static ei_register_info ei[] = {
    { &ei_spdy_inflation_failed, { "spdy.inflation_failed", PI_UNDECODED, PI_ERROR, "Inflation failed. Aborting.", EXPFILL }},
    { &ei_spdy_mal_frame_data, { "spdy.malformed.frame_data", PI_MALFORMED, PI_ERROR, "Not enough frame data", EXPFILL }},
    { &ei_spdy_mal_setting_frame, { "spdy.malformed.setting_frame", PI_MALFORMED, PI_ERROR, "SETTINGS frame too small for number of entries field.", EXPFILL }},
    { &ei_spdy_invalid_rst_stream, { "spdy.rst_stream.invalid", PI_PROTOCOL, PI_WARN, "Invalid status code for RST_STREAM", EXPFILL }},
    { &ei_spdy_invalid_go_away, { "spdy.goaway.invalid", PI_PROTOCOL, PI_WARN, "Invalid status code for GOAWAY", EXPFILL }},
    { &ei_spdy_invalid_frame_type, { "spdy.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid SPDY frame type", EXPFILL }},
  };

  module_t *spdy_module;
  expert_module_t* expert_spdy;

  proto_spdy = proto_register_protocol("SPDY", "SPDY", "spdy");
  proto_register_field_array(proto_spdy, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_spdy = expert_register_protocol(proto_spdy);
  expert_register_field_array(expert_spdy, ei, array_length(ei));

  new_register_dissector("spdy", dissect_spdy, proto_spdy);

  spdy_module = prefs_register_protocol(proto_spdy, NULL);
  prefs_register_bool_preference(spdy_module, "assemble_data_frames",
                                 "Assemble SPDY bodies that consist of multiple DATA frames",
                                 "Whether the SPDY dissector should reassemble multiple "
                                 "data frames into an entity body.",
                                 &spdy_assemble_entity_bodies);

  prefs_register_bool_preference(spdy_module, "decompress_headers",
                                 "Uncompress SPDY headers",
                                 "Whether to uncompress SPDY headers.",
                                 &spdy_decompress_headers);
  prefs_register_bool_preference(spdy_module, "decompress_body",
                                 "Uncompress entity bodies",
                                 "Whether to uncompress entity bodies that are compressed "
                                 "using \"Content-Encoding: \"",
                                 &spdy_decompress_body);

  /** Create dissector handle and register for dissection. */
  spdy_handle = new_create_dissector_handle(dissect_spdy, proto_spdy);

  register_init_routine(&spdy_init_protocol);

  /*
   * Register for tapping
   */
  spdy_tap = register_tap("spdy"); /* SPDY statistics tap */
  spdy_eo_tap = register_tap("spdy_eo"); /* SPDY Export Object tap */
}

void proto_reg_handoff_spdy(void) {

  dissector_add_uint("tcp.port", TCP_PORT_SPDY, spdy_handle);
  ssl_dissector_add(SSL_PORT_SPDY, "spdy", TRUE);

  data_handle = find_dissector("data");
  media_handle = find_dissector("media");
  port_subdissector_table = find_dissector_table("http.port");
  media_type_subdissector_table = find_dissector_table("media_type");

#if 0 /* heuristic too weak */
  heur_dissector_add("tcp", dissect_spdy_heur, proto_spdy);
#endif
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
