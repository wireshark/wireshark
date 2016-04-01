/* packet-spice.c
 * Routines for Spice protocol dissection
 * Copyright 2011, Yaniv Kaul <ykaul@redhat.com>
 * Copyright 2013, Jonathon Jongsma <jjongsma@redhat.com>
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
 *
 * This code is based on the protocol specification:
 *   http://www.spice-space.org/docs/spice_protocol.pdf
 *   and the source - git://cgit.freedesktop.org/spice/spice-protocol
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
/* NOTE:
 * packet-spice.h is auto-generated from a Spice protocol definition by a tool
 * included in the spice-common repository
 * (http://cgit.freedesktop.org/spice/spice-common/)
 * To re-generate this file, run the following command from the root of the
 * spice-common tree:
 *      python ./spice_codegen.py --generate-wireshark-dissector \
 *              spice.proto packet-spice.h
 */
#include "packet-spice.h"

void proto_register_spice(void);
void proto_reg_handoff_spice(void);

#define SPICE_MAGIC 0x52454451 /* = "REDQ" */

#define SPICE_VERSION_MAJOR_1 1
#define SPICE_VERSION_MINOR_0 0
#define SPICE_VERSION_MAJOR_UNSTABLE 0xfffe
#define SPICE_VERSION_MINOR_UNSTABLE 0xffff

#define SPICE_TICKET_PUBKEY_BYTES 162

#define SPICE_ALIGN(a, size) (((a) + ((size) - 1)) & ~((size) - 1))

typedef enum {
    SPICE_LINK_CLIENT,
    SPICE_LINK_SERVER,

    SPICE_TICKET_CLIENT,
    SPICE_TICKET_SERVER,

    SPICE_CLIENT_AUTH_SELECT,
    SPICE_SASL_INIT_FROM_SERVER,
    SPICE_SASL_START_TO_SERVER,
    SPICE_SASL_START_FROM_SERVER,
    SPICE_SASL_START_FROM_SERVER_CONT,
    SPICE_SASL_STEP_TO_SERVER,
    SPICE_SASL_STEP_FROM_SERVER,
    SPICE_SASL_STEP_FROM_SERVER_CONT,
    SPICE_SASL_DATA,
    SPICE_DATA
} spice_session_state_e;

static const value_string state_name_vs[] = {
    { SPICE_LINK_CLIENT, "Client link message" },
    { SPICE_LINK_SERVER, "Server link message" },
    { SPICE_TICKET_CLIENT, "Client ticket" },
    { SPICE_TICKET_SERVER, "Server ticket" },
    { SPICE_CLIENT_AUTH_SELECT, "Client authentication method selection" },
    { SPICE_SASL_INIT_FROM_SERVER, "SASL supported authentication mechanisms (init from server)" },
    { SPICE_SASL_START_TO_SERVER, "SASL authentication (start to server)" },
    { SPICE_SASL_START_FROM_SERVER, "SASL authentication (start from server)" },
    { SPICE_SASL_START_FROM_SERVER_CONT, "SASL authentication - result from server" },
    { SPICE_SASL_STEP_TO_SERVER, "SASL authentication from client (step to server)" },
    { SPICE_SASL_STEP_FROM_SERVER, "SASL authentication (step from server)" },
    { SPICE_SASL_STEP_FROM_SERVER_CONT, "SASL authentication - result from server" },
    { SPICE_SASL_DATA, "SASL wrapped Spice message" },
    { SPICE_DATA, "" }, /* Intentionally "blank" to help col_append_sep_str() logic */
    { 0, NULL }
};

static dissector_handle_t spice_handle;

#define SPICE_CHANNEL_NONE      0

#define SPICE_FIRST_AVAIL_MESSAGE 101

#define sizeof_SpiceLinkHeader  16
#define sizeof_SpiceDataHeader  18
#define sizeof_SpiceMiniDataHeader  6

static const value_string playback_mode_vals[] = {
    { SPICE_AUDIO_DATA_MODE_INVALID,    "INVALID" },
    { SPICE_AUDIO_DATA_MODE_RAW,        "RAW" },
    { SPICE_AUDIO_DATA_MODE_CELT_0_5_1, "CELT_0_5_1" },
    { 0, NULL }
};

enum {
    SPICE_PLAYBACK_CAP_CELT_0_5_1,
    SPICE_PLAYBACK_CAP_VOLUME
};

enum {
    SPICE_PLAYBACK_CAP_CELT_0_5_1_MASK = (1 << SPICE_PLAYBACK_CAP_CELT_0_5_1),
    SPICE_PLAYBACK_CAP_VOLUME_MASK = (1 << SPICE_PLAYBACK_CAP_VOLUME)
};

/* main channel */

enum {
    SPICE_MAIN_CAP_SEMI_SEAMLESS_MIGRATE,
    SPICE_MAIN_CAP_VM_NAME_UUID,
    SPICE_MAIN_CAP_AGENT_CONNECTED_TOKENS,
    SPICE_MAIN_CAP_SEAMLESS_MIGRATE
};

enum
{
    SPICE_MAIN_CAP_SEMI_SEAMLESS_MIGRATE_MASK = (1 << SPICE_MAIN_CAP_SEMI_SEAMLESS_MIGRATE),
    SPICE_MAIN_CAP_VM_NAME_UUID_MASK = (1 << SPICE_MAIN_CAP_VM_NAME_UUID),
    SPICE_MAIN_CAP_AGENT_CONNECTED_TOKENS_MASK = (1 << SPICE_MAIN_CAP_AGENT_CONNECTED_TOKENS),
    SPICE_MAIN_CAP_SEAMLESS_MIGRATE_MASK = (1 << SPICE_MAIN_CAP_SEAMLESS_MIGRATE)
};

enum {
    VD_AGENT_MOUSE_STATE = 1,
    VD_AGENT_MONITORS_CONFIG,
    VD_AGENT_REPLY,
    VD_AGENT_CLIPBOARD,
    VD_AGENT_DISPLAY_CONFIG,
    VD_AGENT_ANNOUNCE_CAPABILITIES,
    VD_AGENT_CLIPBOARD_GRAB,
    VD_AGENT_CLIPBOARD_REQUEST,
    VD_AGENT_CLIPBOARD_RELEASE,
    VD_AGENT_FILE_XFER_START,
    VD_AGENT_FILE_XFER_STATUS,
    VD_AGENT_FILE_XFER_DATA,
    VD_AGENT_CLIENT_DISCONNECTED,
    VD_AGENT_END_MESSAGE
};

static const value_string agent_message_type_vs[] = {
    { VD_AGENT_MOUSE_STATE, "VD_AGENT_MOUSE_STATE" },
    { VD_AGENT_MONITORS_CONFIG, "VD_AGENT_MONITORS_CONFIG" },
    { VD_AGENT_REPLY, "VD_AGENT_REPLY" },
    { VD_AGENT_CLIPBOARD, "VD_AGENT_CLIPBOARD" },
    { VD_AGENT_DISPLAY_CONFIG, "VD_AGENT_DISPLAY_CONFIG" },
    { VD_AGENT_ANNOUNCE_CAPABILITIES, "VD_AGENT_ANNOUNCE_CAPABILITIES" },
    { VD_AGENT_CLIPBOARD_GRAB, "VD_AGENT_CLIPBOARD_GRAB" },
    { VD_AGENT_CLIPBOARD_REQUEST, "VD_AGENT_CLIPBOARD_REQUEST" },
    { VD_AGENT_CLIPBOARD_RELEASE, "VD_AGENT_CLIPBOARD_RELEASE" },
    { VD_AGENT_FILE_XFER_START, "VD_AGENT_FILE_XFER_START" },
    { VD_AGENT_FILE_XFER_STATUS, "VD_AGENT_FILE_XFER_STATUS" },
    { VD_AGENT_FILE_XFER_DATA, "VD_AGENT_FILE_XFER_DATA" },
    { VD_AGENT_CLIENT_DISCONNECTED, "VD_AGENT_CLIENT_DISCONNECTED" },
    { VD_AGENT_END_MESSAGE, "VD_AGENT_END_MESSAGE" },
    { 0, NULL }
};

enum {
    VD_AGENT_CLIPBOARD_NONE,
    VD_AGENT_CLIPBOARD_UTF8_TEXT,
    VD_AGENT_CLIPBOARD_IMAGE_PNG,
    VD_AGENT_CLIPBOARD_IMAGE_BMP,
    VD_AGENT_CLIPBOARD_IMAGE_TIFF,
    VD_AGENT_CLIPBOARD_IMAGE_JPG
};

static const value_string agent_clipboard_type[] = {
    { VD_AGENT_CLIPBOARD_NONE,      "NONE" },
    { VD_AGENT_CLIPBOARD_UTF8_TEXT, "UTF8_TEXT" },
    { VD_AGENT_CLIPBOARD_IMAGE_PNG, "IMAGE_PNG" },
    { VD_AGENT_CLIPBOARD_IMAGE_BMP, "IMAGE_BMP" },
    { VD_AGENT_CLIPBOARD_IMAGE_TIFF,"IMAGE_TIFF" },
    { VD_AGENT_CLIPBOARD_IMAGE_JPG, "IMAGE_JPG" },
    { 0, NULL }
};

enum {
    VD_AGENT_CAP_MOUSE_STATE = (1 << 0),
    VD_AGENT_CAP_MONITORS_CONFIG = (1 << 1),
    VD_AGENT_CAP_REPLY = (1 << 2),
    VD_AGENT_CAP_CLIPBOARD = (1 << 3),
    VD_AGENT_CAP_DISPLAY_CONFIG = (1 << 4),
    VD_AGENT_CAP_CLIPBOARD_BY_DEMAND = (1 << 5),
    VD_AGENT_CAP_CLIPBOARD_SELECTION = (1 << 6),
    VD_AGENT_CAP_SPARSE_MONITORS_CONFIG = (1 << 7),
    VD_AGENT_CAP_GUEST_LINEEND_LF = (1 << 8),
    VD_AGENT_CAP_GUEST_LINEEND_CRLF = (1 << 9)
};

#if 0
static const value_string vd_agent_cap_vs[] = {
    { VD_AGENT_CAP_MOUSE_STATE, "VD_AGENT_CAP_MOUSE_STATE" },
    { VD_AGENT_CAP_MONITORS_CONFIG, "VD_AGENT_CAP_MONITORS_CONFIG" },
    { VD_AGENT_CAP_REPLY, "VD_AGENT_CAP_REPLY" },
    { VD_AGENT_CAP_CLIPBOARD, "VD_AGENT_CAP_CLIPBOARD" },
    { VD_AGENT_CAP_DISPLAY_CONFIG, "VD_AGENT_CAP_DISPLAY_CONFIG" },
    { VD_AGENT_CAP_CLIPBOARD_BY_DEMAND, "VD_AGENT_CAP_CLIPBOARD_BY_DEMAND" },
    { VD_AGENT_CAP_CLIPBOARD_SELECTION, "VD_AGENT_CAP_CLIPBOARD_SELECTION" },
    { VD_AGENT_CAP_SPARSE_MONITORS_CONFIG, "VD_AGENT_CAP_SPARSE_MONITORS_CONFIG" },
    { VD_AGENT_CAP_GUEST_LINEEND_LF, "VD_AGENT_CAP_GUEST_LINEEND_LF" },
    { VD_AGENT_CAP_GUEST_LINEEND_CRLF, "VD_AGENT_CAP_GUEST_LINEEND_CRLF" },
    { 0, NULL }
};
#endif

enum {
    VD_AGENT_CONFIG_MONITORS_FLAG_USE_POS = (1 << 0)
};

#if 0
static const value_string vd_agent_monitors_config_flag_vs[] = {
    { VD_AGENT_CONFIG_MONITORS_FLAG_USE_POS, "VD_AGENT_CONFIG_MONITORS_FLAG_USE_POS"},
    { 0, NULL }
};
#endif

enum {
    VD_AGENT_SUCCESS = 1,
    VD_AGENT_ERROR
};

static const value_string vd_agent_reply_error_vs[] = {
    { VD_AGENT_SUCCESS, "SUCCESS"},
    { VD_AGENT_ERROR, "ERROR"},
    { 0, NULL }
};

/* record channel capabilities - same as playback */
enum {
    SPICE_RECORD_CAP_CELT_0_5_1,
    SPICE_RECORD_CAP_VOLUME
};

enum {
    SPICE_RECORD_CAP_CELT_0_5_1_MASK = (1 << SPICE_RECORD_CAP_CELT_0_5_1),
    SPICE_RECORD_CAP_VOLUME_MASK = (1 << SPICE_RECORD_CAP_VOLUME)
};

/* display channel */
enum {
    SPICE_DISPLAY_CAP_SIZED_STREAM,
    SPICE_DISPLAY_CAP_MONITORS_CONFIG,
    SPICE_DISPLAY_CAP_COMPOSITE,
    SPICE_DISPLAY_CAP_A8_SURFACE
};

enum {
    SPICE_DISPLAY_CAP_SIZED_STREAM_MASK = (1 << SPICE_DISPLAY_CAP_SIZED_STREAM),
    SPICE_DISPLAY_CAP_MONITORS_CONFIG_MASK = (1 << SPICE_DISPLAY_CAP_MONITORS_CONFIG),
    SPICE_DISPLAY_CAP_COMPOSITE_MASK = (1 << SPICE_DISPLAY_CAP_COMPOSITE),
    SPICE_DISPLAY_CAP_A8_SURFACE_MASK = (1 << SPICE_DISPLAY_CAP_A8_SURFACE)
};

/* display channel */

#define sizeof_RedcDisplayInit 14

/* cursor channel */
static const value_string cursor_visible_vs[] = {
    { 1, "Visible" },
    { 0, "Invisible" },
    { 0, NULL }
};

typedef struct {
    guint64 unique;
    guint8  type;
    guint16 width;
    guint16 height;
    guint16 hot_spot_x;
    guint16 hot_spot_y;
} CursorHeader;

#define sizeof_CursorHeader 17

static const value_string spice_agent_vs[] = {
    { 0, "Disconnected" },
    { 1, "Connected" },
    { 0, NULL }
};

/* This structure will be tied to each conversation. */
typedef struct {
    guint32  connection_id;
    guint32  num_channel_caps;
    guint32  destport;
    guint32  client_auth;
    guint32  server_auth;
    guint32  auth_selected;
    spice_session_state_e next_state;
    guint16  playback_mode;
    guint8   channel_type;
    guint8   channel_id;
    gboolean client_mini_header;
    gboolean server_mini_header;
} spice_conversation_t;

typedef struct {
    spice_session_state_e state;
} spice_packet_t;

typedef struct {
    gint32 left;
    gint32 top;
    gint32 right;
    gint32 bottom;
} SpiceRect;

#define sizeof_SpiceRect 16

typedef struct {
    guint8 type;
} Clip;
#define sizeof_Clip 1 /* This is correct only if the type is none. If it is RECTS, this is followed by: */

typedef struct {
    guint32 num_rects; /* this is followed by RECT rects[num_rects] */
} ClipRects;


typedef struct {
    guint32   surface_id;
    SpiceRect bounding_box;
    Clip      clip;
} DisplayBase;

#define sizeof_DisplayBase 21 /* size without a rect list in the Clip */

typedef struct {
    gint32 x;
    gint32 y;
} point32_t;

typedef struct {
    gint16 x;
    gint16 y;
} point16_t;

#define sizeof_Mask 13

#define sizeof_ImageDescriptor 18

enum {
    QUIC_IMAGE_TYPE_INVALID,
    QUIC_IMAGE_TYPE_GRAY,
    QUIC_IMAGE_TYPE_RGB16,
    QUIC_IMAGE_TYPE_RGB24,
    QUIC_IMAGE_TYPE_RGB32,
    QUIC_IMAGE_TYPE_RGBA
};

static const value_string quic_type_vs[] = {
    { QUIC_IMAGE_TYPE_INVALID, "INVALID" },
    { QUIC_IMAGE_TYPE_GRAY,    "GRAY" },
    { QUIC_IMAGE_TYPE_RGB16,   "RGB16" },
    { QUIC_IMAGE_TYPE_RGB24,   "RGB24" },
    { QUIC_IMAGE_TYPE_RGB32,   "RGB32" },
    { QUIC_IMAGE_TYPE_RGBA,    "RGBA" },
    { 0, NULL }
};

enum {
    LZ_IMAGE_TYPE_INVALID,
    LZ_IMAGE_TYPE_PLT1_LE,
    LZ_IMAGE_TYPE_PLT1_BE,
    LZ_IMAGE_TYPE_PLT4_LE,
    LZ_IMAGE_TYPE_PLT4_BE,
    LZ_IMAGE_TYPE_PLT8,
    LZ_IMAGE_TYPE_RGB16,
    LZ_IMAGE_TYPE_RGB24,
    LZ_IMAGE_TYPE_RGB32,
    LZ_IMAGE_TYPE_RGBA,
    LZ_IMAGE_TYPE_XXXA
};

static const value_string LzImage_type_vs[] = {
    { LZ_IMAGE_TYPE_INVALID, "INVALID" },
    { LZ_IMAGE_TYPE_PLT1_LE, "PLT1_LE" },
    { LZ_IMAGE_TYPE_PLT1_BE, "PLT1_BE" },
    { LZ_IMAGE_TYPE_PLT4_LE, "PLT4_LE" },
    { LZ_IMAGE_TYPE_PLT4_BE, "PLT4_BE" },
    { LZ_IMAGE_TYPE_PLT8,    "PLT8" },
    { LZ_IMAGE_TYPE_RGB16,   "RGB16" },
    { LZ_IMAGE_TYPE_RGB24,   "RGB24" },
    { LZ_IMAGE_TYPE_RGB32,   "RGB32" },
    { LZ_IMAGE_TYPE_RGBA,    "RGBA" },
    { LZ_IMAGE_TYPE_XXXA,    "RGB JPEG (w/ Alpha LZ)" },
    { 0, NULL }
};

#define sizeof_SpiceHead 28

enum {
    SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION,
    SPICE_COMMON_CAP_AUTH_SPICE,
    SPICE_COMMON_CAP_AUTH_SASL,
    SPICE_COMMON_CAP_MINI_HEADER
};

enum {
    SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION_MASK = (1 << SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION),
    SPICE_COMMON_CAP_AUTH_SPICE_MASK = (1 << SPICE_COMMON_CAP_AUTH_SPICE),
    SPICE_COMMON_CAP_AUTH_SASL_MASK = (1 << SPICE_COMMON_CAP_AUTH_SASL),
    SPICE_COMMON_CAP_MINI_HEADER_MASK = (1 << SPICE_COMMON_CAP_MINI_HEADER)
};

static const value_string spice_auth_select_vs[] = {
    { SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION, "Auth Selection" },
    { SPICE_COMMON_CAP_AUTH_SPICE,              "Spice" },
    { SPICE_COMMON_CAP_AUTH_SASL,               "SASL" },
    { SPICE_COMMON_CAP_MINI_HEADER,             "Mini header" },
    { 0, NULL }
};

static const value_string spice_sasl_auth_result_vs[] = {
    { 0, "CONTINUE" },
    { 1, "DONE" },
    { 0, NULL }
};

#define GET_PDU_FROM_OFFSET(OFFSET) if (avail < pdu_len) { \
                                       pinfo->desegment_offset = OFFSET; \
                                       pinfo->desegment_len = pdu_len - avail; \
                                       return avail; \
                                   }

static gint ett_spice = -1;
static gint ett_link_client = -1;
static gint ett_link_server = -1;
static gint ett_link_caps = -1;
static gint ett_data = -1;
static gint ett_message = -1;
static gint ett_ticket_client = -1;
static gint ett_auth_select_client = -1;
static gint ett_ticket_server = -1;
static gint ett_playback = -1;
static gint ett_display_client = -1;
static gint ett_display_server = -1;
static gint ett_common_server_message = -1;
static gint ett_common_client_message = -1;
static gint ett_point = -1;
static gint ett_point16 = -1;
static gint ett_cursor = -1;
static gint ett_spice_main = -1;
static gint ett_rect = -1;
static gint ett_DisplayBase = -1;
static gint ett_Clip = -1;
static gint ett_Mask = -1;
static gint ett_imagedesc = -1;
static gint ett_imageQuic = -1;
static gint ett_GLZ_RGB = -1;
static gint ett_LZ_RGB = -1;
static gint ett_LZ_PLT = -1;
static gint ett_ZLIB_GLZ = -1;
static gint ett_Uncomp_tree = -1;
static gint ett_LZ_JPEG = -1;
static gint ett_JPEG = -1;
static gint ett_cursor_header = -1;
static gint ett_RedCursor = -1;
static gint ett_pattern = -1;
static gint ett_brush = -1;
static gint ett_Pixmap = -1;
static gint ett_SpiceHead = -1;
static gint ett_inputs_client = -1;
static gint ett_rectlist = -1;
static gint ett_inputs_server = -1;
static gint ett_record_client = -1;
static gint ett_record_server = -1;
static gint ett_main_client = -1;
static gint ett_spice_agent = -1;
static gint ett_cap_tree = -1;
static int proto_spice = -1;
static int hf_spice_magic  = -1;
static int hf_major_version  = -1;
static int hf_minor_version  = -1;
static int hf_message_size  = -1;
static int hf_message_type  = -1;
static int hf_conn_id  = -1;
static int hf_channel_type  = -1;
static int hf_channel_id  = -1;
static int hf_num_common_caps  = -1;
static int hf_num_channel_caps  = -1;
static int hf_caps_offset  = -1;
static int hf_error_code  = -1;
static int hf_data = -1;
static int hf_serial = -1;
static int hf_data_size = -1;
static int hf_data_sublist = -1;
static int hf_link_client = -1;
static int hf_link_server = -1;
static int hf_ticket_client = -1;
static int hf_auth_select_client = -1;
static int hf_ticket_server = -1;
static int hf_main_num_channels = -1;
static int hf_main_cap_semi_migrate = -1;
static int hf_main_cap_vm_name_uuid = -1;
static int hf_main_cap_agent_connected_tokens = -1;
static int hf_main_cap_seamless_migrate = -1;
static int hf_inputs_cap = -1;
static int hf_cursor_cap = -1;
static int hf_common_cap_auth_select = -1;
static int hf_common_cap_auth_spice = -1;
static int hf_common_cap_auth_sasl = -1;
static int hf_common_cap_mini_header = -1;
static int hf_audio_timestamp = -1;
static int hf_audio_mode = -1;
static int hf_audio_channels = -1;
static int hf_audio_format = -1;
static int hf_audio_frequency = -1;
static int hf_audio_volume = -1;
static int hf_audio_mute = -1;
static int hf_audio_latency = -1;
static int hf_red_set_ack_generation = -1;
static int hf_red_set_ack_window = -1;
static int hf_Clip_type = -1;
static int hf_Mask_flag = -1;
static int hf_display_rop_descriptor = -1;
static int hf_display_scale_mode = -1;
static int hf_display_stream_id = -1;
static int hf_display_stream_report_unique_id = -1;
static int hf_display_stream_report_max_window_size = -1;
static int hf_display_stream_report_timeout = -1;
static int hf_display_stream_width = -1;
static int hf_display_stream_height = -1;
static int hf_display_stream_src_width = -1;
static int hf_display_stream_src_height = -1;
static int hf_display_stream_data_size = -1;
static int hf_display_stream_codec_type = -1;
static int hf_display_stream_stamp = -1;
static int hf_display_stream_flags = -1;
static int hf_red_ping_id = -1;
static int hf_red_timestamp = -1;
static int hf_spice_display_mode_width = -1;
static int hf_spice_display_mode_height = -1;
static int hf_spice_display_mode_depth = -1;
static int hf_image_desc_id = -1;
static int hf_image_desc_type = -1;
static int hf_image_desc_flags = -1;
static int hf_image_desc_width = -1;
static int hf_image_desc_height = -1;
static int hf_quic_width = -1;
static int hf_quic_height = -1;
static int hf_quic_major_version  = -1;
static int hf_quic_minor_version  = -1;
static int hf_quic_type = -1;
static int hf_LZ_width = -1;
static int hf_LZ_height = -1;
static int hf_LZ_major_version  = -1;
static int hf_LZ_minor_version  = -1;
static int hf_LZ_PLT_type = -1;
static int hf_LZ_RGB_type = -1;
static int hf_LZ_stride = -1;
static int hf_LZ_RGB_dict_id = -1;
static int hf_cursor_trail_len = -1;
static int hf_cursor_trail_freq = -1;
static int hf_cursor_trail_visible = -1;
static int hf_cursor_unique = -1;
static int hf_cursor_type = -1;
static int hf_cursor_width = -1;
static int hf_cursor_height = -1;
static int hf_cursor_hotspot_x = -1;
static int hf_cursor_hotspot_y = -1;
static int hf_cursor_flags = -1;
static int hf_cursor_id = -1;
static int hf_spice_display_init_cache_id = -1;
static int hf_spice_display_init_cache_size = -1;
static int hf_spice_display_init_glz_dict_id = -1;
static int hf_spice_display_init_dict_window_size = -1;
static int hf_brush_type = -1;
static int hf_brush_rgb = -1;
static int hf_pixmap_width = -1;
static int hf_pixmap_height = -1;
static int hf_pixmap_stride = -1;
static int hf_pixmap_address = -1;
static int hf_pixmap_format = -1;
static int hf_pixmap_flags = -1;
static int hf_keyboard_modifiers = -1;
static int hf_keyboard_modifier_scroll_lock = -1;
static int hf_keyboard_modifier_num_lock = -1;
static int hf_keyboard_modifier_caps_lock = -1;
static int hf_keyboard_code = -1;
static int hf_rectlist_size = -1;
static int hf_migrate_dest_port = -1;
static int hf_migrate_dest_sport = -1;
static int hf_migrate_src_mig_version = -1;
static int hf_session_id = -1;
static int hf_display_channels_hint = -1;
static int hf_supported_mouse_modes = -1;
static int hf_current_mouse_mode = -1;
static int hf_supported_mouse_modes_flags = -1;
static int hf_supported_mouse_modes_flag_client = -1;
static int hf_supported_mouse_modes_flag_server = -1;
static int hf_current_mouse_mode_flags = -1;
static int hf_agent_connected = -1;
static int hf_agent_tokens = -1;
static int hf_agent_protocol = -1;
static int hf_agent_type = -1;
static int hf_agent_opaque = -1;
static int hf_agent_size = -1;
static int hf_agent_token = -1;
static int hf_agent_clipboard_selection = -1;
static int hf_agent_clipboard_type = -1;
static int hf_agent_num_monitors = -1;
static int hf_agent_monitor_height = -1;
static int hf_agent_monitor_width = -1;
static int hf_agent_monitor_depth = -1;
static int hf_agent_monitor_x = -1;
static int hf_agent_monitor_y = -1;
static int hf_multi_media_time = -1;
static int hf_ram_hint = -1;
static int hf_button_state = -1;
static int hf_mouse_display_id = -1;
static int hf_display_text_fore_mode = -1;
static int hf_display_text_back_mode = -1;
static int hf_display_surface_id = -1;
static int hf_display_surface_width = -1;
static int hf_display_surface_height = -1;
static int hf_display_surface_format = -1;
static int hf_display_surface_flags = -1;
static int hf_main_client_agent_tokens = -1;
static int hf_tranparent_src_color = -1;
static int hf_tranparent_true_color = -1;
static int hf_spice_sasl_auth_result = -1;
static int hf_record_cap_volume = -1;
static int hf_record_cap_celt = -1;
static int hf_display_cap_sized_stream = -1;
static int hf_display_cap_monitors_config = -1;
static int hf_display_cap_composite = -1;
static int hf_display_cap_a8_surface = -1;
static int hf_main_uuid = -1;
static int hf_main_name = -1;
static int hf_main_name_len = -1;
static int hf_display_monitor_config_count = -1;
static int hf_display_monitor_config_max_allowed = -1;
static int hf_display_head_id = -1;
static int hf_display_head_surface_id = -1;
static int hf_display_head_width = -1;
static int hf_display_head_height = -1;
static int hf_display_head_x = -1;
static int hf_display_head_y = -1;
static int hf_display_head_flags = -1;
static int hf_zlib_uncompress_size = -1;
static int hf_zlib_compress_size = -1;
static int hf_rect_left = -1;
static int hf_rect_top = -1;
static int hf_rect_right = -1;
static int hf_rect_bottom = -1;
static int hf_point32_x = -1;
static int hf_point32_y = -1;
static int hf_point16_x = -1;
static int hf_point16_y = -1;
static int hf_severity = -1;
static int hf_visibility = -1;
static int hf_notify_code = -1;
static int hf_notify_message_len = -1;
static int hf_notify_message = -1;
static int hf_num_glyphs = -1;
static int hf_port_opened = -1;
static int hf_port_event = -1;
static int hf_raw_data = -1;
static int hf_display_inval_list_count = -1;
static int hf_resource_type = -1;
static int hf_resource_id = -1;
static int hf_ref_image = -1;
static int hf_ref_string = -1;
static int hf_vd_agent_caps_request = -1;
static int hf_vd_agent_cap_mouse_state = -1;
static int hf_vd_agent_cap_monitors_config = -1;
static int hf_vd_agent_cap_reply = -1;
static int hf_vd_agent_cap_clipboard = -1;
static int hf_vd_agent_cap_display_config = -1;
static int hf_vd_agent_cap_clipboard_by_demand = -1;
static int hf_vd_agent_cap_clipboard_selection = -1;
static int hf_vd_agent_cap_sparse_monitors_config = -1;
static int hf_vd_agent_cap_guest_lineend_lf = -1;
static int hf_vd_agent_cap_guest_lineend_crlf = -1;
static int hf_vd_agent_monitors_config_flag_use_pos = -1;
static int hf_vd_agent_reply_type = -1;
static int hf_vd_agent_reply_error = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_spice_supported_authentication_mechanisms_list = -1;
static int hf_spice_selected_client_out_mechanism = -1;
static int hf_spice_scale_mode = -1;
static int hf_spice_supported_authentication_mechanisms_list_length = -1;
static int hf_spice_rop3 = -1;
static int hf_spice_x509_subjectpublickeyinfo = -1;
static int hf_spice_glz_rgb_image_size = -1;
static int hf_spice_vd_agent_display_config_message = -1;
static int hf_spice_stream_data = -1;
static int hf_spice_client_out_mechanism_length = -1;
static int hf_spice_vd_agent_clipboard_message = -1;
static int hf_spice_image_from_cache = -1;
static int hf_spice_lz_rgb_compressed_image_data = -1;
static int hf_spice_unknown_bytes = -1;
static int hf_spice_sasl_data = -1;
static int hf_spice_name_length = -1;
static int hf_spice_zlib_stream = -1;
static int hf_spice_lz_plt_image_size = -1;
static int hf_spice_reserved = -1;
static int hf_spice_sasl_authentication_data = -1;
static int hf_spice_image_from_cache_lossless = -1;
static int hf_spice_quic_magic = -1;
static int hf_spice_surface_id = -1;
static int hf_spice_ping_data = -1;
static int hf_spice_display_mark_message = -1;
static int hf_spice_pixmap_pixels = -1;
static int hf_spice_vd_agent_clipboard_release_message = -1;
static int hf_spice_clientout_list = -1;
static int hf_spice_server_inputs_mouse_motion_ack_message = -1;
static int hf_spice_cursor_data = -1;
static int hf_spice_clientout_length = -1;
static int hf_spice_lz_magic = -1;
static int hf_spice_lz_rgb_image_size = -1;
static int hf_spice_lz_plt_data = -1;
static int hf_spice_glyph_flags = -1;
static int hf_spice_pallete_offset = -1;
#if 0
static int hf_spice_lz_jpeg_image_size = -1;
#endif
static int hf_spice_pallete = -1;
static int hf_spice_selected_authentication_mechanism_length = -1;
static int hf_spice_display_reset_message = -1;
static int hf_spice_topdown_flag = -1;
static int hf_spice_quic_image_size = -1;
static int hf_spice_sasl_message_length = -1;
static int hf_spice_selected_authentication_mechanism = -1;
static int hf_spice_lz_plt_flag = -1;
static int hf_spice_quic_compressed_image_data = -1;

static expert_field ei_spice_decompress_error = EI_INIT;
static expert_field ei_spice_unknown_message = EI_INIT;
static expert_field ei_spice_not_dissected = EI_INIT;
static expert_field ei_spice_auth_unknown = EI_INIT;
static expert_field ei_spice_sasl_auth_result = EI_INIT;
static expert_field ei_spice_expected_from_client = EI_INIT;
/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_spice_brush_type = EI_INIT;
static expert_field ei_spice_unknown_image_type = EI_INIT;
static expert_field ei_spice_Mask_flag = EI_INIT;
static expert_field ei_spice_Mask_point = EI_INIT;
static expert_field ei_spice_common_cap_unknown = EI_INIT;
static expert_field ei_spice_unknown_channel = EI_INIT;


static dissector_handle_t jpeg_handle;

static guint32
dissect_SpiceHead(tvbuff_t *tvb, proto_tree *tree, guint32 offset, const guint16 num)
{
    proto_tree *SpiceHead_tree;

    SpiceHead_tree = proto_tree_add_subtree_format(tree, tvb, offset, sizeof_SpiceHead,
                                    ett_SpiceHead, NULL, "Display Head #%u", num);
    proto_tree_add_item(SpiceHead_tree, hf_display_head_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(SpiceHead_tree, hf_display_head_surface_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(SpiceHead_tree, hf_display_head_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(SpiceHead_tree, hf_display_head_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(SpiceHead_tree, hf_display_head_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(SpiceHead_tree, hf_display_head_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(SpiceHead_tree, hf_display_head_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

#define sizeof_AgentMonitorConfig 20
static guint32
dissect_AgentMonitorConfig(tvbuff_t *tvb, proto_tree *tree, guint32 offset, const guint16 num)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree_format(tree, tvb, offset, sizeof_AgentMonitorConfig,
                            ett_SpiceHead, NULL, "Monitor Config #%u", num);
    proto_tree_add_item(subtree, hf_agent_monitor_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_agent_monitor_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_agent_monitor_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_agent_monitor_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_agent_monitor_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

/* returns the pixmap size in bytes */
static guint32
dissect_Pixmap(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item *ti;
    proto_tree *Pixmap_tree;
    guint32     PixmapSize;
    guint32     strides, height, pallete_ptr;

    Pixmap_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_Pixmap, &ti, "Pixmap"); /* size is fixed later */
    proto_tree_add_item(Pixmap_tree, hf_pixmap_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(Pixmap_tree, hf_pixmap_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(Pixmap_tree, hf_pixmap_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    height = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(Pixmap_tree, hf_pixmap_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    strides = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(Pixmap_tree, hf_pixmap_stride, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    pallete_ptr = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(Pixmap_tree, hf_pixmap_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    PixmapSize = height * strides;
    proto_item_set_len(ti, 18 + PixmapSize);
    proto_tree_add_bytes_format(Pixmap_tree, hf_spice_pixmap_pixels, tvb, offset, PixmapSize, NULL,
                                "Pixmap pixels (%d bytes)", PixmapSize);
    offset += PixmapSize;
    /* FIXME: compute pallete size */
    proto_tree_add_bytes_format(Pixmap_tree, hf_spice_pallete, tvb, offset, 0, NULL, "Pallete (offset from message start - %u)", pallete_ptr);
    /*TODO: complete pixmap dissection */

    return PixmapSize + 18;
}

/* returns the type of cursor */
static guint8
dissect_CursorHeader(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint16 *width, guint16 *height)
{
    const guint8 type = tvb_get_guint8(tvb, offset + 8);

    *width  = tvb_get_letohs(tvb, offset + 8 + 1);
    *height = tvb_get_letohs(tvb, offset + 8 + 1 + 2);

    if (tree) {
        proto_tree *CursorHeader_tree;

        CursorHeader_tree = proto_tree_add_subtree(tree, tvb, offset, sizeof_CursorHeader, ett_cursor_header, NULL, "Cursor Header");
        proto_tree_add_item(CursorHeader_tree, hf_cursor_unique,    tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(CursorHeader_tree, hf_cursor_type,      tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(CursorHeader_tree, hf_cursor_width,     tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(CursorHeader_tree, hf_cursor_height,    tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(CursorHeader_tree, hf_cursor_hotspot_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(CursorHeader_tree, hf_cursor_hotspot_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }

    return type;
}

/* returns the size of RedCursor */
static guint32
dissect_RedCursor(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item *ti;
    proto_tree    *RedCursor_tree;
    guint8         type;
    guint16        height, width;
    guint32        init_offset = offset;
    const guint16  flags       = tvb_get_letohs(tvb, offset);
    guint32        data_size   = 0;

    RedCursor_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_RedCursor, &ti, "RedCursor"); /* FIXME - fix size if flag is not NONE */

    proto_tree_add_item(RedCursor_tree, hf_cursor_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    if (flags == SPICE_CURSOR_FLAGS_NONE) {
        return 2;
    }

    offset += 2;

    type = dissect_CursorHeader(tvb, RedCursor_tree, offset, &width, &height);
    offset += (int)sizeof_CursorHeader;


    if (((width == 0) || (height == 0)) || (flags == SPICE_CURSOR_FLAGS_FROM_CACHE)) {
        proto_item_set_len(ti, offset - init_offset);
        return (offset - init_offset);
    }

    switch (type) {
        case SPICE_CURSOR_TYPE_ALPHA:
            data_size = (width << 2) * height;
            break;
        case SPICE_CURSOR_TYPE_MONO:
            data_size = (SPICE_ALIGN(width, 8) >> 2) * height;
            break;
        /* TODO: fix all size calculations for below cursor types, using SPICE_ALIGN */
        case SPICE_CURSOR_TYPE_COLOR4:
        case SPICE_CURSOR_TYPE_COLOR8:
        case SPICE_CURSOR_TYPE_COLOR16:
        case SPICE_CURSOR_TYPE_COLOR24:
        case SPICE_CURSOR_TYPE_COLOR32:
            break;
        default:
            data_size = 0;
            break;
    }
    if (data_size != 0) {
        proto_tree_add_item(RedCursor_tree, hf_spice_cursor_data, tvb, offset, data_size, ENC_NA);
    } else {
        proto_tree_add_item(RedCursor_tree, hf_spice_cursor_data, tvb, offset, -1, ENC_NA);
    }
    offset += data_size;


    return (offset - init_offset);
}

/* returns the image type, needed for later */
static guint8
dissect_ImageDescriptor(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    const guint8  type = tvb_get_guint8(tvb, offset + 8);

    if (tree) {
        proto_tree *ImageDescriptor_tree;

        ImageDescriptor_tree = proto_tree_add_subtree(tree, tvb, offset, sizeof_ImageDescriptor, ett_imagedesc, NULL, "Image Descriptor");

        proto_tree_add_item(ImageDescriptor_tree, hf_image_desc_id,     tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_item(ImageDescriptor_tree, hf_image_desc_type,   tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(ImageDescriptor_tree, hf_image_desc_flags,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(ImageDescriptor_tree, hf_image_desc_width,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(ImageDescriptor_tree, hf_image_desc_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }

    return type;
}

static guint32
dissect_ImageQuic(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    const guint32  QuicSize = tvb_get_letohl(tvb, offset);

    if (tree) {
        proto_tree *ImageQuic_tree;

        ImageQuic_tree = proto_tree_add_subtree(tree, tvb, offset, QuicSize + 4, ett_imageQuic, NULL, "QUIC Image");

        proto_tree_add_uint_format_value(ImageQuic_tree, hf_spice_quic_image_size, tvb, offset, 4, QuicSize, "%u bytes", QuicSize);
        offset += 4;
        proto_tree_add_item(ImageQuic_tree, hf_spice_quic_magic, tvb, offset, 4, ENC_ASCII|ENC_NA);
        offset += 4;
        proto_tree_add_item(ImageQuic_tree, hf_quic_major_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(ImageQuic_tree, hf_quic_minor_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(ImageQuic_tree, hf_quic_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(ImageQuic_tree, hf_quic_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(ImageQuic_tree, hf_quic_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_bytes_format(ImageQuic_tree, hf_spice_quic_compressed_image_data, tvb, offset, QuicSize - 20, NULL, "QUIC compressed image data (%u bytes)", QuicSize);
    }

    return QuicSize + 4;
}

static guint32
dissect_ImageLZ_common_header(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{

    proto_tree_add_item(tree, hf_spice_lz_magic, tvb, offset, 4, ENC_ASCII|ENC_NA);
    proto_tree_add_item(tree, hf_LZ_major_version, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_LZ_minor_version, tvb, offset + 6, 2, ENC_BIG_ENDIAN);

    return 8;
}

static guint32
dissect_ImageLZ_common(tvbuff_t *tvb, proto_tree *tree, guint32 offset, const gboolean IsLZ, const guint32 size)
{

    guint8 type;

    offset += dissect_ImageLZ_common_header(tvb, tree, offset);

    if (IsLZ)
       offset +=3; /* alignment in LZ? Does not exist in GLZ?*/

    proto_tree_add_item(tree, hf_LZ_RGB_type, tvb, offset, 1, ENC_NA);
    type = tvb_get_guint8(tvb, offset);
    offset += 1;
    switch (type & 0xf) { /* 0xf is the MASK */
        case LZ_IMAGE_TYPE_RGB16:
        case LZ_IMAGE_TYPE_RGB24:
        case LZ_IMAGE_TYPE_RGB32:
            proto_tree_add_item(tree, hf_LZ_width, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_height, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_stride, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_RGB_dict_id, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            proto_tree_add_bytes_format(tree, hf_spice_lz_rgb_compressed_image_data, tvb, offset , size - 29, NULL, "LZ_RGB compressed image data (%u bytes)", size - 29);
            break;
        case LZ_IMAGE_TYPE_RGBA:
            offset += 2;
            break;
        case LZ_IMAGE_TYPE_XXXA:
            proto_tree_add_item(tree, hf_LZ_width, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_height, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_stride, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_spice_topdown_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_spice_unknown_bytes, tvb, offset, 12, ENC_NA);
            offset += 8;
            break;
        default:
            proto_tree_add_item(tree, hf_LZ_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_stride, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_RGB_dict_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_bytes_format(tree, hf_spice_lz_rgb_compressed_image_data, tvb, offset , size - 30, NULL, "LZ_RGB compressed image data (%u bytes)", size - 30);
            break;
    }
    return offset;
}

#if 0
static guint32
dissect_ImageLZ_JPEG(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_tree    *LZ_JPEG_tree;
    const guint32  LZ_JPEGSize = tvb_get_letohl(tvb, offset);

    LZ_JPEG_tree = proto_tree_add_subtree(tree, tvb, offset, LZ_JPEGSize + 4, ett_LZ_JPEG, NULL, "LZ_JPEG Image");
    proto_tree_add_uint_format_value(LZ_JPEG_tree, hf_spice_lz_jpeg_image_size, tvb, offset, 4, LZ_JPEGSize, "%u bytes", LZ_JPEGSize);
    offset += 4;
    offset += dissect_ImageLZ_common_header(tvb, LZ_JPEG_tree, offset);

    return offset;
}
#endif

static guint32
dissect_ImageGLZ_RGB(tvbuff_t *tvb, proto_tree *tree, guint32 offset, const guint32 size)
{
    proto_tree *GLZ_RGB_tree;
    guint32     GLZ_RGBSize;

    if (size == 0) { /* if no size was passed to us, need to fetch it. Otherwise, we already have it from the callee */
        GLZ_RGBSize = tvb_get_letohl(tvb, offset);
        GLZ_RGB_tree = proto_tree_add_subtree(tree, tvb, offset, GLZ_RGBSize + 4, ett_GLZ_RGB, NULL, "GLZ_RGB Image");
        proto_tree_add_uint_format_value(GLZ_RGB_tree, hf_spice_glz_rgb_image_size, tvb, offset, 4, GLZ_RGBSize, "%u bytes", GLZ_RGBSize);
        offset += 4;
    } else {
        GLZ_RGBSize = size;
        GLZ_RGB_tree = proto_tree_add_subtree(tree, tvb, offset, GLZ_RGBSize, ett_GLZ_RGB, NULL, "GLZ_RGB Image");
    }

    dissect_ImageLZ_common(tvb, GLZ_RGB_tree, offset, FALSE, GLZ_RGBSize);

    return GLZ_RGBSize + 4;
}

static guint32
dissect_ImageLZ_RGB(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_tree    *LZ_RGB_tree;
    const guint32  LZ_RGBSize = tvb_get_letohl(tvb, offset);

    LZ_RGB_tree = proto_tree_add_subtree(tree, tvb, offset, LZ_RGBSize + 4, ett_LZ_RGB, NULL, "LZ_RGB Image");
    proto_tree_add_uint_format_value(LZ_RGB_tree, hf_spice_lz_rgb_image_size, tvb, offset, 4, LZ_RGBSize, "%u bytes", LZ_RGBSize);
    offset += 4;

    dissect_ImageLZ_common(tvb, LZ_RGB_tree, offset, TRUE, LZ_RGBSize);

    return LZ_RGBSize + 4;
}

static guint32
dissect_ImageLZ_PLT(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_tree *LZ_PLT_tree;
    guint32     LZ_PLTSize, pal_size;

    const guint32 current_offset = offset;

    LZ_PLTSize = tvb_get_letohl(tvb, offset + 1); /* for some reason, it reports two extra bytes */
    LZ_PLT_tree = proto_tree_add_subtree(tree, tvb, offset, (LZ_PLTSize - 2)+ 1 + 4 + 4 + 8 + 4 + 4 + 4 + 4 + 4, ett_LZ_PLT, NULL, "LZ_PLT Image");

    proto_tree_add_item(LZ_PLT_tree, hf_spice_lz_plt_flag, tvb, offset, 1, ENC_NA); /* TODO: dissect */
    offset += 1;
    proto_tree_add_uint_format_value(LZ_PLT_tree, hf_spice_lz_plt_image_size, tvb, offset, 4, LZ_PLTSize, "%u bytes (2 extra bytes?)", LZ_PLTSize);
    offset += 4;

    pal_size = tvb_get_letohl(tvb, offset);
    proto_tree_add_uint_format_value(LZ_PLT_tree, hf_spice_pallete_offset, tvb, offset, 4, pal_size, "%u bytes", pal_size); /* TODO: not sure it's correct */
    offset += 4;

    dissect_ImageLZ_common_header(tvb, LZ_PLT_tree, offset);
    offset += 8;

    proto_tree_add_item(LZ_PLT_tree, hf_LZ_PLT_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(LZ_PLT_tree, hf_LZ_width, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(LZ_PLT_tree, hf_LZ_height, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(LZ_PLT_tree, hf_LZ_stride, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(LZ_PLT_tree, hf_spice_topdown_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_bytes_format(LZ_PLT_tree, hf_spice_lz_plt_data, tvb, offset, (LZ_PLTSize - 2), NULL, "LZ_PLT data (%u bytes)", (LZ_PLTSize - 2));
    offset += (LZ_PLTSize - 2);
    /* TODO:
    * proto_tree_add_bytes_format(LZ_PLT_tree, tvb, offset, pal_size, "palette (%u bytes)" , pal_size);
    *  offset += pal_size;
    */
    return offset - current_offset;
}



static guint32
dissect_ImageJPEG_Alpha(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset)
{
    proto_tree *JPEG_tree;
    tvbuff_t   *jpeg_tvb;
    guint32     JPEG_Size, Data_Size;

    /*TODO: const guint8 flags = tvb_get_guint8(tvb, offset); dissect and present */
    offset += 1;

    JPEG_Size = tvb_get_letohl(tvb, offset);
    offset += 4;

    Data_Size = tvb_get_letohl(tvb, offset);
    offset += 4;

    JPEG_tree = proto_tree_add_subtree_format(tree, tvb, offset - 9, Data_Size + 9,
            ett_JPEG, NULL, "RGB JPEG Image, Alpha channel (%u bytes)", Data_Size);

    jpeg_tvb = tvb_new_subset_length(tvb, offset, JPEG_Size);
    call_dissector(jpeg_handle, jpeg_tvb, pinfo, JPEG_tree);
    offset += JPEG_Size;

    dissect_ImageLZ_common(tvb, tree, offset, TRUE, JPEG_Size);

    return Data_Size + 9;
}

static guint32
dissect_ImageJPEG(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, const guint32 offset)
{
    proto_tree *JPEG_tree;
    tvbuff_t   *jpeg_tvb;

    const guint32 JPEG_Size = tvb_get_letohl(tvb, offset);
    JPEG_tree = proto_tree_add_subtree_format(tree, tvb, offset, JPEG_Size + 4, ett_JPEG, NULL, "JPEG Image (%u bytes)", JPEG_Size);

    jpeg_tvb = tvb_new_subset_length(tvb, offset + 4, JPEG_Size);
    call_dissector(jpeg_handle, jpeg_tvb, pinfo, JPEG_tree);

    return JPEG_Size + 4;
}

#ifdef HAVE_ZLIB
static void
dissect_ImageZLIB_GLZ_stream(tvbuff_t *tvb, proto_tree *ZLIB_GLZ_tree, packet_info *pinfo,
                             guint32 offset, guint32 ZLIB_GLZSize, guint32 ZLIB_uncompSize)
{
    proto_item *ti;
    proto_tree *Uncomp_tree;
    tvbuff_t   *uncompressed_tvb;

    Uncomp_tree = proto_tree_add_subtree_format(ZLIB_GLZ_tree, tvb, offset, ZLIB_GLZSize, ett_Uncomp_tree, &ti, "ZLIB stream (%u bytes)", ZLIB_GLZSize);
    uncompressed_tvb = tvb_child_uncompress(tvb, tvb, offset, ZLIB_GLZSize);
    if (uncompressed_tvb != NULL) {
        add_new_data_source(pinfo, uncompressed_tvb, "Uncompressed GLZ stream");
        dissect_ImageGLZ_RGB(uncompressed_tvb, Uncomp_tree, 0, ZLIB_uncompSize);
    } else {
        expert_add_info(pinfo, ti, &ei_spice_decompress_error);
    }
}
#else
static void
dissect_ImageZLIB_GLZ_stream(tvbuff_t *tvb, proto_tree *ZLIB_GLZ_tree, packet_info *pinfo _U_,
                             guint32 offset, guint32 ZLIB_GLZSize, guint32 ZLIB_uncompSize _U_)
{
    proto_tree_add_bytes_format(ZLIB_GLZ_tree, hf_spice_zlib_stream, tvb, offset, ZLIB_GLZSize, NULL, "ZLIB stream (%u bytes)", ZLIB_GLZSize);
}
#endif

static guint32
dissect_ImageZLIB_GLZ(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset)
{
    proto_item *ti;
    proto_tree *ZLIB_GLZ_tree;
    guint32     ZLIB_GLZSize, ZLIB_uncompSize;

    ZLIB_uncompSize = tvb_get_letohl(tvb, offset);
    ZLIB_GLZSize    = tvb_get_letohl(tvb, offset + 4); /* compressed size */
    if (tree) {
        ZLIB_GLZ_tree = proto_tree_add_subtree(tree, tvb, offset, ZLIB_GLZSize + 8, ett_ZLIB_GLZ, NULL, "ZLIB over GLZ Image");

        ti = proto_tree_add_item(ZLIB_GLZ_tree, hf_zlib_uncompress_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_item_append_text(ti, " bytes");
        offset += 4;
        ti = proto_tree_add_item(ZLIB_GLZ_tree, hf_zlib_compress_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_item_append_text(ti, " bytes");
        offset += 4;
        dissect_ImageZLIB_GLZ_stream(tvb, ZLIB_GLZ_tree, pinfo, offset, ZLIB_GLZSize, ZLIB_uncompSize);
    }

    return ZLIB_GLZSize + 8;
}

/* returns the size of an image, not offset */
static guint32
dissect_Image(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset)
{
    guint32      ImageSize = 0;
    const guint8 type      = dissect_ImageDescriptor(tvb, tree, offset);

    offset += (int)sizeof_ImageDescriptor;

    switch (type) {
        case SPICE_IMAGE_TYPE_BITMAP:
            ImageSize = dissect_Pixmap(tvb, tree, offset);
            break;
        case SPICE_IMAGE_TYPE_QUIC:
            ImageSize = dissect_ImageQuic(tvb, tree, offset);
            break;
        case SPICE_IMAGE_TYPE_LZ_PLT:
            ImageSize = dissect_ImageLZ_PLT(tvb, tree, offset);
            break;
        case SPICE_IMAGE_TYPE_LZ_RGB:
            ImageSize = dissect_ImageLZ_RGB(tvb, tree, offset);
            break;
        case SPICE_IMAGE_TYPE_GLZ_RGB:
            ImageSize = dissect_ImageGLZ_RGB(tvb, tree, offset, 0);
            break;
        case SPICE_IMAGE_TYPE_FROM_CACHE:
            proto_tree_add_item(tree, hf_spice_image_from_cache, tvb, offset, 0, ENC_NA);
            break;
        case SPICE_IMAGE_TYPE_SURFACE:
            ImageSize = 4; /* surface ID */
            proto_tree_add_item(tree, hf_spice_surface_id, tvb, offset, ImageSize, ENC_LITTLE_ENDIAN);
            break;
        case SPICE_IMAGE_TYPE_JPEG:
            ImageSize = dissect_ImageJPEG(tvb, tree, pinfo, offset);
            break;
        case SPICE_IMAGE_TYPE_FROM_CACHE_LOSSLESS:
            proto_tree_add_item(tree, hf_spice_image_from_cache_lossless, tvb, offset, 0, ENC_NA);
            break;
        case SPICE_IMAGE_TYPE_ZLIB_GLZ_RGB:
            ImageSize = dissect_ImageZLIB_GLZ(tvb, tree, pinfo, offset);
            break;
        case SPICE_IMAGE_TYPE_JPEG_ALPHA:
            ImageSize = dissect_ImageJPEG_Alpha(tvb, tree, pinfo, offset);
            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_spice_unknown_image_type, tvb, offset, -1);
    }

    return sizeof_ImageDescriptor + ImageSize;
}

static SpiceRect
dissect_SpiceRect(tvbuff_t *tvb, proto_tree *tree, const guint32 offset, const gint32 id)
{
    proto_tree *rect_tree;
    SpiceRect   rect;

    rect.left   = tvb_get_letohl(tvb, offset);
    rect.top    = tvb_get_letohl(tvb, offset + 4);
    rect.right  = tvb_get_letohl(tvb, offset + 8);
    rect.bottom = tvb_get_letohl(tvb, offset + 12);

    if (tree) {
        if (id != -1) {
            rect_tree = proto_tree_add_subtree_format(tree, tvb, offset, sizeof_SpiceRect, ett_rect, NULL,
                                     "RECT %u: (%u-%u, %u-%u)", id, rect.left, rect.top, rect.right, rect.bottom);
        } else { /* single rectangle */
            rect_tree = proto_tree_add_subtree_format(tree, tvb, offset, sizeof_SpiceRect, ett_rect, NULL,
                                     "RECT: (%u-%u, %u-%u)", rect.left, rect.top, rect.right, rect.bottom);
        }

        proto_tree_add_item(rect_tree, hf_rect_left, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rect_tree, hf_rect_top, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rect_tree, hf_rect_right, tvb, offset + 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(rect_tree, hf_rect_bottom, tvb, offset + 12, 4, ENC_LITTLE_ENDIAN);
    }

    return rect;
}

static guint32
rect_is_empty(const SpiceRect r)
{
    return r.top == r.bottom || r.left == r.right;
}

static guint32
dissect_RectList(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_tree    *rectlist_tree;
    guint32        i;
    const guint32  rectlist_size = tvb_get_letohl(tvb, offset);

    if (tree) {
        rectlist_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + (rectlist_size * sizeof_SpiceRect),
                                 ett_rectlist, NULL, "RectList (%d rects)", rectlist_size);

        proto_tree_add_item(rectlist_tree, hf_rectlist_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        for (i = 0; i < rectlist_size; i++ ) {
            dissect_SpiceRect(tvb, rectlist_tree, offset, i);
            offset += (int)sizeof_SpiceRect;
        }
    }

    return (4 + (rectlist_size * sizeof_SpiceRect));
}

/* returns clip type */
static guint8
dissect_Clip(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{
    proto_tree   *Clip_tree;
    const guint8  type = tvb_get_guint8(tvb, offset);

    if (tree) {
        Clip_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_Clip, NULL, "SpiceClip");
        proto_tree_add_item(Clip_tree, hf_Clip_type, tvb, offset, sizeof_Clip, ENC_LITTLE_ENDIAN);
    }

    return type;
}

static proto_item*
dissect_POINT32(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{
    proto_tree *point_tree;
    proto_item *ret_item;
    point32_t   point;

    point.x = tvb_get_letohl(tvb, offset);
    point.y = tvb_get_letohl(tvb, offset + 4);

    point_tree = proto_tree_add_subtree_format(tree, tvb, offset, sizeof(point32_t), ett_point, &ret_item, "POINT (%u, %u)", point.x, point.y);

    proto_tree_add_item(point_tree, hf_point32_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(point_tree, hf_point32_y, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);

    return ret_item;
}

static point16_t
dissect_POINT16(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{
    proto_tree *point16_tree;
    point16_t   point16;

    point16.x = tvb_get_letohs(tvb, offset);
    point16.y = tvb_get_letohs(tvb, offset + 2);

    if (tree) {
        point16_tree = proto_tree_add_subtree_format(tree, tvb, offset, sizeof(point16_t), ett_point16, NULL, "POINT16 (%u, %u)", point16.x, point16.y);

        proto_tree_add_item(point16_tree, hf_point16_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(point16_tree, hf_point16_y, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
    }

    return point16;
}

static guint32
dissect_Mask(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset)
{
    proto_item *ti, *mask_item, *point_item;
    proto_tree *Mask_tree;
    guint32     bitmap;

    Mask_tree = proto_tree_add_subtree(tree, tvb, offset, sizeof_Mask, ett_Mask, &ti, "Mask");
    mask_item = proto_tree_add_item(Mask_tree, hf_Mask_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    point_item = dissect_POINT32(tvb, Mask_tree, offset);
    offset += (int)sizeof(point32_t);
    bitmap = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(Mask_tree, hf_ref_image, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    if (bitmap != 0) {
        proto_item_set_len(ti, sizeof_Mask + sizeof_ImageDescriptor);
        dissect_ImageDescriptor(tvb, Mask_tree, offset);
        return sizeof_Mask + sizeof_ImageDescriptor;
    }

    expert_add_info(pinfo, mask_item, &ei_spice_Mask_flag);
    expert_add_info(pinfo, point_item, &ei_spice_Mask_point);
    return sizeof_Mask;
}

/* returns brush size */
static guint32
dissect_Brush(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset)
{
    proto_tree   *brush_tree;
    proto_item   *ti;
    const guint8  type = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_item(tree, hf_brush_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    switch (type) {
        case SPICE_BRUSH_TYPE_SOLID:
            proto_item_set_len(ti, 5);
            brush_tree = proto_item_add_subtree(ti, ett_brush);
            offset += 1;
            proto_tree_add_item(brush_tree, hf_brush_rgb, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            return 5;
        case SPICE_BRUSH_TYPE_PATTERN:
            proto_item_set_len(ti, 17);
            brush_tree = proto_item_add_subtree(ti, ett_brush);
            proto_tree_add_item(brush_tree, hf_brush_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* FIXME: this is supposed to be the offset to the image to be used as the pattern.        */
            /* For now the hack is that callers check if the returned size was not 5 (therefore SOLID, */
            /* it's a pattern and later on dissect the image. That's bad. Really. */
            proto_tree_add_item(brush_tree, hf_ref_image, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_POINT32(tvb, brush_tree, offset);
            return (1 + 4 + 8);
        case SPICE_BRUSH_TYPE_NONE:
            return 1;
        default:
            expert_add_info(pinfo, ti, &ei_spice_brush_type);
            return 0;
    }

    return 0;
}

static guint32
dissect_DisplayBase(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item *ti;
    proto_tree *DisplayBase_tree;
    SpiceRect   rect;
    guint8      clip_type;
    guint32     clip_size = 0;

    DisplayBase_tree = proto_tree_add_subtree(tree, tvb, offset, sizeof_DisplayBase, ett_DisplayBase, &ti, "SpiceMsgDisplayBase");
    proto_tree_add_item(DisplayBase_tree, hf_display_surface_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    rect = dissect_SpiceRect(tvb, DisplayBase_tree, offset, -1);
    proto_item_append_text(ti, " - SpiceRect box (%u-%u, %u-%u)",rect.left, rect.top, rect.right, rect.bottom);
    offset += (int)sizeof_SpiceRect;
    clip_type = dissect_Clip(tvb, DisplayBase_tree, offset);
    offset += (int)sizeof_Clip;
    if (clip_type == SPICE_CLIP_TYPE_RECTS) {
        clip_size = dissect_RectList(tvb, DisplayBase_tree, offset);
        proto_item_set_len(ti, sizeof_DisplayBase + clip_size);
        return sizeof_DisplayBase + clip_size;
    }
    return sizeof_DisplayBase;
}


#define sizeof_ResourceId 9
static guint32
dissect_SpiceResourceId(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint16 count)
{
    proto_tree *resource_tree;

    resource_tree = proto_tree_add_subtree_format(tree, tvb, offset, sizeof_ResourceId,
                            ett_cursor_header, NULL, "Resource #%d", count);
    proto_tree_add_item(resource_tree, hf_resource_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(resource_tree, hf_resource_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);

    return sizeof_ResourceId;
}


static const gchar* get_message_type_string(const guint16 message_type, const spice_conversation_t *spice_info,
                                            const gboolean client_message)
{

    if (message_type < SPICE_FIRST_AVAIL_MESSAGE) { /* this is a common message */
        if (client_message) {
            return val_to_str_const(message_type, spice_msgc_vs, "Unknown client message");
        } else {
            return val_to_str_const(message_type, spice_msg_vs, "Unknown server message");
        }
    }

    switch (spice_info->channel_type) {
        case SPICE_CHANNEL_MAIN:
            if (client_message) {
                return val_to_str_const(message_type, spice_msgc_main_vs, "Unknown main channel client message");
            } else {
                return val_to_str_const(message_type, spice_msg_main_vs, "Unknown main channel server message");
            }
            break;
        case SPICE_CHANNEL_DISPLAY:
            if (client_message) {
                return val_to_str_const(message_type, spice_msgc_display_vs, "Unknown display channel client message");
            } else {
                return val_to_str_const(message_type, spice_msg_display_vs, "Unknown display channel server message");
            }
            break;
        case SPICE_CHANNEL_INPUTS:
            if (client_message) {
                return val_to_str_const(message_type, spice_msgc_inputs_vs, "Unknown inputs channel client message");
            } else {
                return val_to_str_const(message_type, spice_msg_inputs_vs, "Unknown inputs channel server message");
            }
            break;
        case SPICE_CHANNEL_CURSOR:
            if (client_message) {
                return val_to_str_const(message_type, NULL, "Unknown cursor channel client message");
            } else {
                return val_to_str_const(message_type, spice_msg_cursor_vs, "Unknown cursor channel server message");
            }
            break;
        case SPICE_CHANNEL_PLAYBACK:
            return val_to_str_const(message_type, spice_msg_playback_vs, "Unknown playback channel server message");
            break;
        case SPICE_CHANNEL_RECORD:
            if (client_message) {
                return val_to_str_const(message_type, spice_msgc_record_vs, "Unknown record channel client message");
            } else {
                return val_to_str_const(message_type, spice_msg_record_vs, "Unknown record channel server message");
            }
            break;
        case SPICE_CHANNEL_TUNNEL:
            if (client_message) {
                return val_to_str_const(message_type, spice_msgc_tunnel_vs, "Unknown tunnel channel client message");
            } else {
                return val_to_str_const(message_type, spice_msg_tunnel_vs, "Unknown tunnel channel server message");
            }
            break;
        case SPICE_CHANNEL_SMARTCARD:
            if (client_message) {
                return val_to_str_const(message_type, spice_msgc_smartcard_vs, "Unknown smartcard channel client message");
            } else {
                return val_to_str_const(message_type, spice_msg_smartcard_vs, "Unknown smartcard channel server message");
            }
            break;
        case SPICE_CHANNEL_USBREDIR:
            if (client_message) {
                const value_string *values = NULL;
                if (message_type < SPICE_MSG_END_SPICEVMC)
                    values = spice_msg_spicevmc_vs;
                return val_to_str_const(message_type, values, "Unknown usbredir channel client message");
            } else {
                const value_string *values = NULL;
                if (message_type < SPICE_MSGC_END_SPICEVMC)
                    values = spice_msgc_spicevmc_vs;
                return val_to_str_const(message_type, values, "Unknown usbredir channel server message");
            }
            break;
        default:
            break;
    }
    return "Unknown message";
}
static void
dissect_spice_mini_data_header(tvbuff_t *tvb, proto_tree *tree, const spice_conversation_t *spice_info,
                               const gboolean client_message, const guint16 message_type, guint32 offset)
{
    proto_tree* subtree;

    if (tree) {
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 2, ett_common_client_message, NULL,
                    "Message type: %s (%d)", get_message_type_string(message_type, spice_info, client_message), message_type);
        proto_tree_add_item(subtree, hf_message_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_spice_data_header(tvbuff_t *tvb, proto_tree *tree, const spice_conversation_t *spice_info,
                          const gboolean client_message, const guint16 message_type, proto_item** msgtype_item, guint32 *sublist_size, guint32 offset)
{
    proto_tree* subtree;
    *sublist_size = tvb_get_letohl(tvb, offset + 14);

    if (tree) {
        proto_tree_add_item(tree, hf_serial, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 2, ett_common_client_message, NULL,
            "Message type: %s (%d)", get_message_type_string(message_type, spice_info, client_message), message_type);
        *msgtype_item = proto_tree_add_item(subtree, hf_message_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_data_sublist, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}


static guint32
dissect_spice_common_client_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    switch (message_type) {
        case SPICE_MSGC_ACK_SYNC:
            proto_tree_add_item(tree, hf_red_set_ack_generation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSGC_ACK:
            break;
        case SPICE_MSGC_PONG:
            proto_tree_add_item(tree, hf_red_ping_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_red_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        /*
        case SPICE_MSGC_MIGRATE_FLUSH_MARK:
        case SPICE_MSGC_MIGRATE_DATA:
        case SPICE_MSGC_DISCONNECTING:
        */
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown common client message - cannot dissect");
            break;
    }

    return offset;
}

static guint32
dissect_spice_common_server_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item,
                                     guint32 offset, const guint32 total_message_size)
{
    guint32     message_len;

    switch (message_type) {
        /*
        case SPICE_MSG_MIGRATE:
        case SPICE_MSG_MIGRATE_DATA:
        case SPICE_MSG_WAIT_FOR_CHANNELS:
        case SPICE_MSG_DISCONNECTING:
        */
        case SPICE_MSG_SET_ACK:
            proto_tree_add_item(tree, hf_red_set_ack_generation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_red_set_ack_window, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_PING:
            proto_tree_add_item(tree, hf_red_ping_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_red_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            if (total_message_size > 12) {
                proto_tree_add_bytes_format(tree, hf_spice_ping_data, tvb, offset, total_message_size - 12,
                                    NULL, "PING DATA (%d bytes)", total_message_size - 12);
                offset += (total_message_size - 12);
            }
            break;
        case SPICE_MSG_NOTIFY:
            proto_tree_add_item(tree, hf_red_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_severity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_visibility, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /*TODO: based on severity, dissect the error code */
            proto_tree_add_item(tree, hf_notify_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            message_len = tvb_get_letohl(tvb, offset);
            proto_tree_add_item(tree, hf_notify_message_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_notify_message, tvb, offset, message_len + 1, ENC_ASCII|ENC_NA);
            offset += (message_len + 1);
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown common server message - cannot dissect");
            break;
    }

    return offset;
}
static guint32
dissect_spice_record_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    proto_tree *record_tree;

    switch (message_type) {
        case SPICE_MSGC_RECORD_MODE:
            record_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_record_client, NULL, "Client RECORD_MODE message"); /* size is incorrect, fixed later */
            proto_tree_add_item(record_tree, hf_audio_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(record_tree, hf_audio_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* TODO - mode dependant, there may be more data here */
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown record client message - cannot dissect");
            break;
    }

    return offset;
}

static guint32
dissect_spice_display_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    switch (message_type) {
        case SPICE_MSGC_DISPLAY_INIT:
            proto_tree_add_item(tree, hf_spice_display_init_cache_id, tvb, offset,  1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(tree, hf_spice_display_init_cache_size, tvb, offset,  8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_spice_display_init_glz_dict_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(tree, hf_spice_display_init_dict_window_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown display client message - cannot dissect");
            break;
    }

    return offset;
}

static guint32
dissect_spice_display_server(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    guint32    data_size, displayBaseLen;
    guint8     clip_type;
    guint16    count, i;
    SpiceRect  r;
    tvbuff_t  *jpeg_tvb;

    switch (message_type) {
        case SPICE_MSG_DISPLAY_MODE:
            proto_tree_add_item(tree, hf_spice_display_mode_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_spice_display_mode_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_spice_display_mode_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_DISPLAY_MARK:
            proto_tree_add_item(tree, hf_spice_display_mark_message, tvb, offset, 0, ENC_NA);
            break;
        case SPICE_MSG_DISPLAY_RESET:
            proto_tree_add_item(tree, hf_spice_display_reset_message, tvb, offset, 0, ENC_NA);
            break;
        case SPICE_MSG_DISPLAY_INVAL_LIST:
            proto_tree_add_item(tree, hf_display_inval_list_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            count = tvb_get_letohs(tvb, offset);
            offset += 2;
            for (i = 0; i < count; i++) {
                offset += dissect_SpiceResourceId(tvb, tree, offset, i + 1);
            }
            break;
        case SPICE_MSG_DISPLAY_DRAW_ALPHA_BLEND:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            /* TODO: Flag 1 byte, Alpha 1 byte dissection*/
            offset += 2;
            proto_tree_add_item(tree, hf_ref_image, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += (int)sizeof_SpiceRect;
            data_size = dissect_Image(tvb, tree, pinfo, offset);
            offset += data_size;
            break;
        case SPICE_MSG_DISPLAY_DRAW_BLACKNESS:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            offset += dissect_Mask(tvb, pinfo, tree, offset);
            break;
        case SPICE_MSG_DISPLAY_COPY_BITS:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            dissect_POINT32(tvb, tree, offset);
            offset += (int)sizeof(point32_t);
            break;
        case SPICE_MSG_DISPLAY_DRAW_WHITENESS:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            offset += dissect_Mask(tvb, pinfo, tree, offset);
            break;
        case SPICE_MSG_DISPLAY_DRAW_INVERS:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            offset += dissect_Mask(tvb, pinfo, tree, offset);
            break;
        case SPICE_MSG_DISPLAY_DRAW_FILL:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            data_size = dissect_Brush(tvb, pinfo, tree, offset);
            offset += data_size;

            proto_tree_add_item(tree, hf_display_rop_descriptor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            offset += dissect_Mask(tvb, pinfo, tree, offset);

            if (data_size != 5) { /* if it's not a SOLID brush, it's a PATTERN, dissect its image descriptor */
                offset += dissect_Image(tvb, tree, pinfo, offset);
            }
            break;
        case SPICE_MSG_DISPLAY_DRAW_TRANSPARENT:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            proto_tree_add_item(tree, hf_ref_image, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* source area */
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += (int)sizeof_SpiceRect;
            proto_tree_add_item(tree, hf_tranparent_src_color, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_tranparent_true_color, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            data_size = dissect_Image(tvb, tree, pinfo, offset);
            offset += data_size;
            break;
        case SPICE_MSG_DISPLAY_DRAW_BLEND:
        case SPICE_MSG_DISPLAY_DRAW_COPY:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            /* SpiceImage *src_bitmap */
            proto_tree_add_item(tree, hf_ref_image, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            /* source area */
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += (int)sizeof_SpiceRect;

            proto_tree_add_item(tree, hf_display_rop_descriptor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_display_scale_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset += dissect_Mask(tvb, pinfo, tree, offset);

            data_size = dissect_Image(tvb, tree, pinfo, offset);
            offset += data_size;
            break;
        case SPICE_MSG_DISPLAY_DRAW_ROP3:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            /* SpiceImage *src_bitmap */
            proto_tree_add_item(tree, hf_ref_image, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            /* source area */
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += (int)sizeof_SpiceRect;

            data_size = dissect_Brush(tvb, pinfo, tree, offset);
            offset += data_size;

            proto_tree_add_item(tree, hf_spice_rop3, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_spice_scale_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset += dissect_Mask(tvb, pinfo, tree, offset);
            /*FIXME - need to understand what the rest of the message contains. */
            data_size = dissect_Image(tvb, tree, pinfo, offset);
            offset += data_size;
            break;
        case SPICE_MSG_DISPLAY_INVAL_ALL_PALETTES:
            break;
        case SPICE_MSG_DISPLAY_DRAW_TEXT:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            proto_tree_add_item(tree, hf_ref_string, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            r = dissect_SpiceRect(tvb, tree, offset, -1);
            offset += (int)sizeof_SpiceRect;
            if (!rect_is_empty(r)) {
                data_size = dissect_Brush(tvb, pinfo, tree, offset);
                offset += data_size;
            }
            proto_tree_add_item(tree, hf_display_text_fore_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_display_text_back_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_num_glyphs, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_spice_glyph_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
            /*TODO finish dissecting glyph list */
            break;
        case SPICE_MSG_DISPLAY_DRAW_STROKE:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset  += displayBaseLen;
            /*TODO: complete and correct dissection */

            break;
        case SPICE_MSG_DISPLAY_STREAM_CLIP:
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            clip_type = dissect_Clip(tvb, tree, offset);
            offset += (int)sizeof_Clip;
            if (clip_type == SPICE_CLIP_TYPE_RECTS) {
                offset += dissect_RectList(tvb, tree, offset);
            }
            break;
        case SPICE_MSG_DISPLAY_STREAM_CREATE:
            proto_tree_add_item(tree, hf_display_surface_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(tree, hf_display_stream_codec_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(tree, hf_display_stream_stamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_display_stream_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_src_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_src_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += (int)sizeof_SpiceRect;
            clip_type = dissect_Clip(tvb, tree, offset);
            offset += (int)sizeof_Clip;
            if (clip_type == SPICE_CLIP_TYPE_RECTS) {
                offset += dissect_RectList(tvb, tree, offset);
            }
            break;
        case SPICE_MSG_DISPLAY_STREAM_DATA:
            data_size = tvb_get_letohl(tvb, offset + 8);
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_multi_media_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_bytes_format(tree, hf_spice_stream_data, tvb, offset, data_size, NULL, "Stream data");
            jpeg_tvb = tvb_new_subset_length(tvb, offset, data_size);
            call_dissector(jpeg_handle, jpeg_tvb, pinfo, tree);
            offset += data_size;
            break;
        case SPICE_MSG_DISPLAY_STREAM_DESTROY:
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_DISPLAY_STREAM_DATA_SIZED:
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_multi_media_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += (int)sizeof_SpiceRect;
            proto_tree_add_item(tree, hf_display_stream_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_DISPLAY_STREAM_DESTROY_ALL:
            break;
        case SPICE_MSG_DISPLAY_SURFACE_CREATE:
            proto_tree_add_item(tree, hf_display_surface_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_surface_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_surface_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_surface_format, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_surface_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_DISPLAY_SURFACE_DESTROY:
            proto_tree_add_item(tree, hf_display_surface_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_DISPLAY_MONITORS_CONFIG:
            proto_tree_add_item(tree, hf_display_monitor_config_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            count = tvb_get_letohs(tvb, offset);
            offset += 2;
            proto_tree_add_item(tree, hf_display_monitor_config_max_allowed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            for (i = 0; i < count; i++) {
                offset = dissect_SpiceHead(tvb, tree, offset, i);
            }
            break;
        case SPICE_MSG_DISPLAY_DRAW_COMPOSITE:
            break;
        case SPICE_MSG_DISPLAY_STREAM_ACTIVATE_REPORT:
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_report_unique_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_report_max_window_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_report_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown display server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_playback_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item,
                              guint32 message_size, spice_conversation_t *spice_info, guint32 offset)
{
    guint8 num_channels, i;
    proto_tree* subtree;

    switch (message_type) {
        case SPICE_MSG_PLAYBACK_DATA:
            proto_tree_add_item(tree, hf_audio_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_raw_data, tvb, offset, message_size - 4, ENC_NA);
            offset += (message_size - 4);
            break;
        case SPICE_MSG_PLAYBACK_MODE:
            proto_tree_add_item(tree, hf_audio_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            spice_info->playback_mode = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(tree, hf_audio_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* TODO - mode dependent, there may be more data here */
            break;
        case SPICE_MSG_PLAYBACK_START:
            proto_tree_add_item(tree, hf_audio_channels, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_audio_format, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_audio_frequency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_audio_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_PLAYBACK_STOP:
            break;
        case SPICE_MSG_PLAYBACK_VOLUME:
            num_channels = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_audio_channels, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 * num_channels, ett_record_server, NULL, "Channel volume array");
            for (i = 0; i < num_channels; i++) {
                proto_tree_add_item(subtree, hf_audio_volume, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            break;
        case SPICE_MSG_PLAYBACK_MUTE:
            proto_tree_add_item(tree, hf_audio_mute, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        case SPICE_MSG_PLAYBACK_LATENCY:
            proto_tree_add_item(tree, hf_audio_latency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown playback server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_cursor_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    guint32 RedCursorSize;

    switch (message_type) {
        case SPICE_MSG_CURSOR_INIT:
            dissect_POINT16(tvb, tree, offset);
            offset += (int)sizeof(point16_t);
            proto_tree_add_item(tree, hf_cursor_trail_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_cursor_trail_freq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_cursor_trail_visible, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            RedCursorSize = dissect_RedCursor(tvb, tree, offset);
            offset += RedCursorSize;
            break;
        case SPICE_MSG_CURSOR_RESET:
            break;
        case SPICE_MSG_CURSOR_SET:
            dissect_POINT16(tvb, tree, offset);
            offset += (int)sizeof(point16_t);
            offset +=1; /*TODO flags */
            RedCursorSize = dissect_RedCursor(tvb, tree, offset);
            offset += RedCursorSize;
            break;
        case SPICE_MSG_CURSOR_MOVE:
            dissect_POINT16(tvb, tree, offset);
            offset += (int)sizeof(point16_t);
            break;
        case SPICE_MSG_CURSOR_HIDE:
            break;
        case SPICE_MSG_CURSOR_TRAIL:
            proto_tree_add_item(tree, hf_cursor_trail_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_cursor_trail_freq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICE_MSG_CURSOR_INVAL_ONE:
            proto_tree_add_item(tree, hf_cursor_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case SPICE_MSG_CURSOR_INVAL_ALL:
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown cursor server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_record_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    guint8 num_channels, i;
    proto_tree* subtree;

    switch (message_type) {
        case SPICE_MSG_RECORD_STOP:
            break;
        case SPICE_MSG_RECORD_VOLUME:
            num_channels = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_audio_channels, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 * num_channels, ett_record_server, NULL, "Volume Array");
            for (i = 0; i < num_channels; i++) {
                proto_tree_add_item(subtree, hf_audio_volume, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
            break;
        case SPICE_MSG_RECORD_MUTE:
            proto_tree_add_item(tree, hf_audio_mute, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown record server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_agent_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint32 message_type, proto_item* msgtype_item, guint32 message_len, guint32 offset)
{
    proto_tree *agent_tree;
    guint32 n_monitors = 0, i;

    switch (message_type) {
        case VD_AGENT_MOUSE_STATE:
            dissect_POINT32(tvb, tree, offset);
            offset += (int)sizeof(point32_t);
            proto_tree_add_item(tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_mouse_display_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case VD_AGENT_MONITORS_CONFIG:
            n_monitors = tvb_get_letohl(tvb, offset);
            proto_tree_add_item(tree, hf_agent_num_monitors, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_vd_agent_monitors_config_flag_use_pos, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            for (i = 0; i < n_monitors; i++) {
                offset = dissect_AgentMonitorConfig(tvb, tree, offset, i);
            }
            break;
        case VD_AGENT_REPLY:
            proto_tree_add_item(tree, hf_vd_agent_reply_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_vd_agent_reply_error, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case VD_AGENT_CLIPBOARD:
            /*ti = */proto_tree_add_item(tree, hf_spice_vd_agent_clipboard_message, tvb, offset, message_len, ENC_NA);
            /* TODO: display string
            agent_tree = proto_item_add_subtree(ti, ett_spice_agent);
            */
            offset += message_len;
            break;
        case VD_AGENT_DISPLAY_CONFIG:
            proto_tree_add_item(tree, hf_spice_vd_agent_display_config_message, tvb, offset, 4, ENC_NA);
            offset += 4;
            break;
        case VD_AGENT_ANNOUNCE_CAPABILITIES:
            proto_tree_add_item(tree, hf_vd_agent_caps_request, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_vd_agent_cap_mouse_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_monitors_config, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_reply, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_clipboard, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_display_config, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_clipboard_by_demand, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_clipboard_selection, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_sparse_monitors_config, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_guest_lineend_lf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_vd_agent_cap_guest_lineend_crlf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case VD_AGENT_CLIPBOARD_GRAB:
            agent_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_spice_agent, NULL, "VD_AGENT_CLIPBOARD_GRAB message");
            proto_tree_add_item(agent_tree, hf_agent_clipboard_selection, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(agent_tree, hf_spice_reserved, tvb, offset, 3, ENC_NA);
            offset += 3;
            break;
        case VD_AGENT_CLIPBOARD_REQUEST:
            agent_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_spice_agent, NULL, "VD_AGENT_CLIPBOARD_REQUEST message");
            proto_tree_add_item(agent_tree, hf_agent_clipboard_selection, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(agent_tree, hf_spice_reserved, tvb, offset, 3, ENC_NA);
            offset += 3;
            proto_tree_add_item(agent_tree, hf_agent_clipboard_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case VD_AGENT_CLIPBOARD_RELEASE:
            proto_tree_add_item(tree, hf_spice_vd_agent_clipboard_release_message, tvb, offset, 0, ENC_NA);
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown agent message (%u) - cannot dissect", message_type);
            break;
    }
    return offset;
}

/* note that the size property is necessary here because the protocol uses
 * uint32 in the INIT message, and flags16 in the MOUSE_MODE message
 */
static guint32
dissect_supported_mouse_modes(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 size)
{
    proto_item* ti;
    proto_tree *sub_tree;
    int hf = hf_supported_mouse_modes;

    if (size == 2)
        hf = hf_supported_mouse_modes_flags;

    ti = proto_tree_add_item(tree, hf, tvb, offset, size, ENC_LITTLE_ENDIAN);
    sub_tree = proto_item_add_subtree(ti, ett_main_client);

    proto_tree_add_item(sub_tree, hf_supported_mouse_modes_flag_client, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(sub_tree, hf_supported_mouse_modes_flag_server, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    return offset + size;
}

static guint32
dissect_spice_main_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    guint32 num_channels, i, agent_msg_type, agent_msg_len, name_len, data_size;
    proto_tree *subtree = NULL;

    switch (message_type) {
        case SPICE_MSG_MAIN_MIGRATE_BEGIN:
        case SPICE_MSG_MAIN_MIGRATE_SWITCH_HOST:
        case SPICE_MSG_MAIN_MIGRATE_BEGIN_SEAMLESS:
            proto_tree_add_item(tree, hf_migrate_dest_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_migrate_dest_sport, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            data_size = tvb_get_letohl(tvb, offset);
            offset += 4;
            proto_tree_add_item(tree, hf_raw_data, tvb, offset, data_size, ENC_NA);
            offset += data_size;
            data_size = tvb_get_letohl(tvb, offset);
            offset += 4;
            proto_tree_add_item(tree, hf_raw_data, tvb, offset, data_size, ENC_NA);
            offset += data_size;
            if (message_type == SPICE_MSG_MAIN_MIGRATE_BEGIN_SEAMLESS) {
                proto_tree_add_item(tree, hf_migrate_src_mig_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }
            break;
        case SPICE_MSG_MAIN_MIGRATE_CANCEL:
            break;
        case SPICE_MSG_MAIN_INIT:
            proto_tree_add_item(tree, hf_session_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_channels_hint, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_supported_mouse_modes(tvb, tree, offset, 4);
            offset += 4;
            proto_tree_add_item(tree, hf_current_mouse_mode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_agent_connected, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_agent_tokens, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_multi_media_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_ram_hint, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_MAIN_CHANNELS_LIST:
            num_channels = tvb_get_letohl(tvb, offset);
            proto_tree_add_item(tree, hf_main_num_channels, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 * num_channels, ett_main_client, NULL, "Channel Array");
            for (i = 0; i < num_channels; i++ ) {
                proto_tree *subsubtree;

                subsubtree = proto_tree_add_subtree_format(subtree, tvb, offset, 2, ett_main_client, NULL, "channels[%u]", i);

                proto_tree_add_item(subsubtree, hf_channel_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                proto_tree_add_item(subsubtree, hf_channel_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
            }
            break;
        case SPICE_MSG_MAIN_MOUSE_MODE:
            dissect_supported_mouse_modes(tvb, tree, offset, 2);
            offset += 2;
            proto_tree_add_item(tree, hf_current_mouse_mode_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICE_MSG_MAIN_MULTI_MEDIA_TIME:
            proto_tree_add_item(tree, hf_multi_media_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_MAIN_AGENT_DISCONNECTED:
            proto_tree_add_item(tree, hf_error_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_MAIN_AGENT_DATA:
            proto_tree_add_item(tree, hf_agent_protocol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_agent_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            agent_msg_type = tvb_get_letohl(tvb, offset);
            offset += 4;
            proto_tree_add_item(tree, hf_agent_opaque, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(tree, hf_agent_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            agent_msg_len = tvb_get_letohl(tvb, offset);
            offset += 4;
            offset = dissect_spice_agent_message(tvb, pinfo, tree, agent_msg_type, msgtype_item, agent_msg_len, offset);
            break;
        case SPICE_MSG_MAIN_AGENT_TOKEN:
        case SPICE_MSG_MAIN_AGENT_CONNECTED_TOKENS:
            proto_tree_add_item(tree, hf_agent_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSG_MAIN_NAME:
            name_len = tvb_get_letohl(tvb, offset);
            proto_tree_add_item(tree, hf_main_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_main_name, tvb, offset, name_len, ENC_ASCII|ENC_NA);
            offset += name_len;
            break;
        case SPICE_MSG_MAIN_UUID:
            proto_tree_add_item(tree, hf_main_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
            offset += 16;
            break;
        case SPICE_MSG_MAIN_MIGRATE_END:
            break;
        case SPICE_MSG_MAIN_MIGRATE_DST_SEAMLESS_ACK:
            break;
        case SPICE_MSG_MAIN_MIGRATE_DST_SEAMLESS_NACK:
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown main server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_main_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    proto_tree *main_tree;
    guint32     agent_msg_type, agent_msg_len;

    switch (message_type) {
        case SPICE_MSGC_MAIN_MOUSE_MODE_REQUEST:
            proto_tree_add_item(tree, hf_current_mouse_mode_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICE_MSGC_MAIN_ATTACH_CHANNELS:
            break;
        case SPICE_MSGC_MAIN_AGENT_START:
            main_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_main_client, NULL, "Client AGENT_START message");
            proto_tree_add_item(main_tree, hf_main_client_agent_tokens, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSGC_MAIN_AGENT_DATA:
            main_tree = proto_tree_add_subtree(tree, tvb, offset, 24, ett_main_client, NULL, "Client AGENT_DATA message");
            proto_tree_add_item(main_tree, hf_agent_protocol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(main_tree, hf_agent_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            agent_msg_type = tvb_get_letohl(tvb, offset);
            offset += 4;
            proto_tree_add_item(main_tree, hf_agent_opaque, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(main_tree, hf_agent_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            agent_msg_len = tvb_get_letohl(tvb, offset);
            offset += 4;
            offset = dissect_spice_agent_message(tvb, pinfo, main_tree, agent_msg_type, msgtype_item, agent_msg_len, offset);
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown main client message - cannot dissect");
            break;
    }
    return offset;
}

static int
dissect_spice_keyboard_modifiers(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item *ti;
    proto_tree *subtree;

    ti = proto_tree_add_item(tree, hf_keyboard_modifiers, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(ti, ett_link_caps);

    proto_tree_add_item(subtree, hf_keyboard_modifier_scroll_lock, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_keyboard_modifier_num_lock, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_keyboard_modifier_caps_lock, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    return 2;
}

static guint32
dissect_spice_inputs_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    proto_tree *inputs_tree;

    switch (message_type) {
        case SPICE_MSGC_INPUTS_KEY_DOWN:
            inputs_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_inputs_client, NULL, "Client KEY_DOWN message");
            proto_tree_add_item(inputs_tree, hf_keyboard_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSGC_INPUTS_KEY_UP:
            inputs_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_inputs_client, NULL, "Client KEY_UP message");
            proto_tree_add_item(inputs_tree, hf_keyboard_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MSGC_INPUTS_KEY_MODIFIERS:
            offset += dissect_spice_keyboard_modifiers(tvb, tree, offset);
            break;
        case SPICE_MSGC_INPUTS_MOUSE_POSITION:
            inputs_tree = proto_tree_add_subtree(tree, tvb, offset, sizeof(point32_t) + 3, ett_inputs_client, NULL, "Client MOUSE_POSITION message");
            dissect_POINT32(tvb, inputs_tree, offset);
            offset += (int)sizeof(point32_t);
            proto_tree_add_item(inputs_tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(inputs_tree, hf_mouse_display_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        case SPICE_MSGC_INPUTS_MOUSE_MOTION:
            inputs_tree = proto_tree_add_subtree(tree, tvb, offset, sizeof(point32_t) + 4, ett_inputs_client, NULL, "Client MOUSE_MOTION message");
            dissect_POINT32(tvb, inputs_tree, offset);
            offset += (int)sizeof(point32_t);
            proto_tree_add_item(inputs_tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICE_MSGC_INPUTS_MOUSE_PRESS:
            inputs_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_inputs_client, NULL, "Client MOUSE_PRESS message");
            proto_tree_add_item(inputs_tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(inputs_tree, hf_mouse_display_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case SPICE_MSGC_INPUTS_MOUSE_RELEASE:
            inputs_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_inputs_client, NULL, "Client MOUSE_RELEASE message");
            proto_tree_add_item(inputs_tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(inputs_tree, hf_mouse_display_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown inputs client message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_inputs_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    switch (message_type) {
        case SPICE_MSG_INPUTS_INIT:
            offset += dissect_spice_keyboard_modifiers(tvb, tree, offset);
            break;
        case SPICE_MSG_INPUTS_KEY_MODIFIERS:
            offset += dissect_spice_keyboard_modifiers(tvb, tree, offset);
            break;
        case SPICE_MSG_INPUTS_MOUSE_MOTION_ACK:
            proto_tree_add_item(tree, hf_spice_server_inputs_mouse_motion_ack_message, tvb, offset, 0, ENC_NA);
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown inputs server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_tunnel_client(packet_info *pinfo, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    /* TODO: Not implemented yet */
    switch (message_type) {
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_tunnel_server(packet_info *pinfo, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    /* TODO: Not implemented yet */
    switch (message_type) {
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_smartcard_client(packet_info *pinfo, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    /* TODO: Not implemented yet */
    switch (message_type) {
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_smartcard_server(packet_info *pinfo, const guint16 message_type, proto_item* msgtype_item, guint32 offset)
{
    /* TODO: Not implemented yet */
    switch (message_type) {
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_usbredir_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 message_size, guint32 offset)
{
    switch (message_type) {
        case SPICE_MSGC_SPICEVMC_DATA:
            proto_tree_add_item(tree, hf_raw_data, tvb, offset, message_size, ENC_NA);
            offset += message_size;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_usbredir_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 message_size, guint32 offset)
{
    switch (message_type) {
        case SPICE_MSG_SPICEVMC_DATA:
            proto_tree_add_item(tree, hf_raw_data, tvb, offset, message_size, ENC_NA);
            offset += message_size;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_port_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 message_size, guint32 offset)
{
    switch (message_type) {
        case SPICE_MSGC_SPICEVMC_DATA:
            proto_tree_add_item(tree, hf_raw_data, tvb, offset, message_size, ENC_NA);
            offset += message_size;
            break;
        case SPICE_MSGC_PORT_EVENT:
            proto_tree_add_item(tree, hf_port_event, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_port_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const guint16 message_type, proto_item* msgtype_item, guint32 message_size, guint32 offset)
{
    switch (message_type) {
        case SPICE_MSG_SPICEVMC_DATA:
            proto_tree_add_item(tree, hf_raw_data, tvb, offset, message_size, ENC_NA);
            offset += message_size;
            break;
        case SPICE_MSG_PORT_INIT:
            {
                guint32 size = tvb_get_letohl(tvb, offset);
                proto_tree_add_item(tree, hf_spice_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(tree, hf_main_name, tvb, offset, size, ENC_ASCII|ENC_NA);
                offset += size;
                proto_tree_add_item(tree, hf_port_opened, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
            }
            break;
        case SPICE_MSG_PORT_EVENT:
            proto_tree_add_item(tree, hf_port_event, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        default:
            expert_add_info_format(pinfo, msgtype_item, &ei_spice_unknown_message, "Unknown message - cannot dissect");
            break;
    }
    return offset;
}


static guint32
dissect_spice_data_server_pdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, spice_conversation_t *spice_info, guint32 offset, const guint32 total_message_size)
{
    proto_item *ti = NULL, *msg_ti=NULL, *msgtype_ti=NULL;
    proto_tree *data_header_tree, *message_tree;
    guint16     message_type;
    guint32     message_size, sublist_size, old_offset;
    guint32     header_size;

    if (spice_info->client_mini_header && spice_info->server_mini_header) {
        header_size  = sizeof_SpiceMiniDataHeader;
        message_type = tvb_get_letohs(tvb, offset);
        message_size = tvb_get_letohl(tvb, offset +2);
        message_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0,
                                     ett_message, &msg_ti, "%s (%d bytes)",
                                     get_message_type_string(message_type, spice_info, FALSE),
                                     message_size + header_size);
        ti = proto_tree_add_item(message_tree, hf_data, tvb, offset, header_size, ENC_NA);
        data_header_tree = proto_item_add_subtree(ti, ett_data);
        dissect_spice_mini_data_header(tvb, data_header_tree, spice_info, FALSE, message_type, offset);
        proto_item_set_len(msg_ti, message_size + header_size);
    } else {
        header_size  = sizeof_SpiceDataHeader;
        message_type = tvb_get_letohs(tvb, offset + 8);
        message_size = tvb_get_letohl(tvb, offset + 10);
        message_tree = proto_tree_add_subtree_format(tree, tvb, offset, 0,
                                     ett_message, &msg_ti, "%s (%d bytes)",
                                     get_message_type_string(message_type, spice_info, FALSE),
                                     message_size + header_size);
        ti = proto_tree_add_item(message_tree, hf_data, tvb, offset, header_size, ENC_NA);
        data_header_tree = proto_item_add_subtree(ti, ett_data);
        dissect_spice_data_header(tvb, data_header_tree, spice_info, FALSE, message_type, &msgtype_ti, &sublist_size, offset);
    }
    proto_item_set_len(msg_ti, message_size + header_size);
    offset    += header_size;
    old_offset = offset;

    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", get_message_type_string(message_type, spice_info, FALSE));
    if (message_type < SPICE_FIRST_AVAIL_MESSAGE) { /* this is a common message */
        offset = dissect_spice_common_server_messages(tvb, pinfo, message_tree, message_type, msgtype_ti, offset, total_message_size - header_size);
        return offset;
    }

    switch (spice_info->channel_type) {
        case SPICE_CHANNEL_PLAYBACK:
            offset = dissect_spice_playback_server(tvb, pinfo, message_tree, message_type, msgtype_ti, message_size, spice_info, offset);
            break;
        case SPICE_CHANNEL_RECORD:
            offset = dissect_spice_record_server(tvb, pinfo, message_tree, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_MAIN:
            offset = dissect_spice_main_server(tvb, pinfo, message_tree, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_CURSOR:
            offset = dissect_spice_cursor_server(tvb, pinfo, message_tree, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_DISPLAY:
            offset = dissect_spice_display_server(tvb, message_tree, pinfo, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_INPUTS:
            offset = dissect_spice_inputs_server(tvb, pinfo, message_tree, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_TUNNEL:
            offset = dissect_spice_tunnel_server(pinfo, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_SMARTCARD:
            offset = dissect_spice_smartcard_server(pinfo, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_USBREDIR:
            offset = dissect_spice_usbredir_server(tvb, pinfo, message_tree, message_type, msgtype_ti, message_size, offset);
            break;
        case SPICE_CHANNEL_PORT:
            offset = dissect_spice_port_server(tvb, pinfo, message_tree, message_type, msgtype_ti, message_size, offset);
            break;
        default:
            expert_add_info_format(pinfo, msgtype_ti, &ei_spice_unknown_message, "Unknown server PDU - cannot dissect");
    }

    if ((offset - old_offset) != message_size) {
        proto_tree_add_expert_format(tree, pinfo, &ei_spice_not_dissected, tvb, offset, -1,
            "message type %s (%u) not fully dissected", get_message_type_string(message_type, spice_info, FALSE), message_type);
        offset = old_offset + message_size;
    }

    return offset;
}

static guint32
dissect_spice_data_client_pdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, spice_conversation_t *spice_info, guint32 offset)
{
    proto_item *ti = NULL, *msgtype_ti = NULL;
    proto_tree *data_header_tree;
    guint16     message_type;
    guint32     message_size = 0, sublist_size;
    guint32     header_size;

    if (spice_info->client_mini_header && spice_info->server_mini_header) {
        header_size = sizeof_SpiceMiniDataHeader;
        ti = proto_tree_add_item(tree, hf_data, tvb, offset, header_size, ENC_NA);
        data_header_tree = proto_item_add_subtree(ti, ett_data);
        message_type = tvb_get_letohs(tvb, offset);
        message_size = tvb_get_letohl(tvb, offset + 2);
        dissect_spice_mini_data_header(tvb, data_header_tree, spice_info, TRUE, message_type, offset);
    } else {
        header_size = sizeof_SpiceDataHeader;
        ti = proto_tree_add_item(tree, hf_data, tvb, offset, header_size, ENC_NA);
        data_header_tree = proto_item_add_subtree(ti, ett_data);
        message_type = tvb_get_letohs(tvb, offset + 8);
        message_size = tvb_get_letohl(tvb, offset + 10);
        dissect_spice_data_header(tvb, data_header_tree, spice_info, TRUE, message_type, &msgtype_ti, &sublist_size, offset);
    }
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", get_message_type_string(message_type, spice_info, TRUE));
    offset += header_size;
        /* TODO: deal with sub-messages list first. As implementation does not uses sub-messages list yet, */
        /*       it cannot be implemented in the dissector yet. */

    if (message_type < SPICE_FIRST_AVAIL_MESSAGE) { /* this is a common message */
        return dissect_spice_common_client_messages(tvb, pinfo, tree, message_type, msgtype_ti, offset);
    }

    switch (spice_info->channel_type) {
        case SPICE_CHANNEL_PLAYBACK:
            break;
        case SPICE_CHANNEL_RECORD:
            offset = dissect_spice_record_client(tvb, pinfo, tree, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_MAIN:
            offset = dissect_spice_main_client(tvb, pinfo, tree, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_DISPLAY:
            offset = dissect_spice_display_client(tvb, pinfo, tree, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_INPUTS:
            offset = dissect_spice_inputs_client(tvb, pinfo, tree, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_TUNNEL:
            offset = dissect_spice_tunnel_client(pinfo, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_SMARTCARD:
            offset = dissect_spice_smartcard_client(pinfo, message_type, msgtype_ti, offset);
            break;
        case SPICE_CHANNEL_USBREDIR:
            offset = dissect_spice_usbredir_client(tvb, pinfo, tree, message_type, msgtype_ti, message_size, offset);
            break;
        case SPICE_CHANNEL_PORT:
            offset = dissect_spice_port_client(tvb, pinfo, tree, message_type, msgtype_ti, message_size, offset);
            break;
        default:
            expert_add_info_format(pinfo, msgtype_ti, &ei_spice_unknown_message, "Unknown client PDU - cannot dissect");
            break;
    }

    return offset;
}

static void
dissect_spice_link_common_header(tvbuff_t *tvb, proto_tree *tree)
{
     if (tree) {
        /* dissect common header */
        proto_tree_add_item(tree, hf_spice_magic,   tvb,  0, 4, ENC_ASCII|ENC_NA);
        proto_tree_add_item(tree, hf_major_version, tvb,  4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_minor_version, tvb,  8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_message_size,  tvb, 12, 4, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_spice_common_capabilities(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, const guint caps_len, spice_conversation_t *spice_info, gboolean is_client)
{
/* TODO: save common and per-channel capabilities in spice_info ? */
    guint   i;
    guint32 val;
    static const int * caps[] = {
        &hf_common_cap_auth_select,
        &hf_common_cap_auth_spice,
        &hf_common_cap_auth_sasl,
        &hf_common_cap_mini_header,
        NULL
    };

    for(i = 0; i < caps_len; i++) {
        val = tvb_get_letohl(tvb, offset);
        switch (i) {
            case 0:
                if (is_client) {
                    spice_info->client_auth = val;
                } else {
                    spice_info->server_auth = val;
                }

                proto_tree_add_bitmask_list(tree, tvb, offset, 4, caps, ENC_LITTLE_ENDIAN);
                if (val & SPICE_COMMON_CAP_MINI_HEADER_MASK) {
                    if (is_client) {
                        spice_info->client_mini_header = TRUE;
                    } else {
                        spice_info->server_mini_header = TRUE;
                    }
                }
                offset += 4;
                break;
            default:
                proto_tree_add_expert(tree, pinfo, &ei_spice_common_cap_unknown, tvb, offset, 4);
                offset += 4;
                break;
        }
    }
}

static void
dissect_spice_link_capabilities(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint32 offset, const guint caps_len, const spice_conversation_t *spice_info)
{
/* TODO: save common and per-channel capabilities in spice_info ? */
    guint   i;

    for(i = 0; i < caps_len; i++) {
        switch (spice_info->channel_type) {
            case SPICE_CHANNEL_PLAYBACK:
                {
                const int * playback[] = {
                    &hf_common_cap_auth_select,
                    &hf_common_cap_auth_spice,
                    NULL
                };

                if (i != 0)
                    return;

                proto_tree_add_bitmask_list(tree, tvb, offset, 4, playback, ENC_LITTLE_ENDIAN);
                }
                break;
            case SPICE_CHANNEL_MAIN:
                {
                const int * main_cap[] = {
                    &hf_main_cap_semi_migrate,
                    &hf_main_cap_vm_name_uuid, /*Note: only relevant for client. TODO: dissect only for client */
                    &hf_main_cap_agent_connected_tokens,
                    &hf_main_cap_seamless_migrate,
                    NULL
                };

                if (i != 0)
                    return;

                proto_tree_add_bitmask_list(tree, tvb, offset, 4, main_cap, ENC_LITTLE_ENDIAN);
                }
                break;
            case SPICE_CHANNEL_DISPLAY:
                {
                const int * display_cap[] = {
                    &hf_display_cap_sized_stream,
                    &hf_display_cap_monitors_config,
                    &hf_display_cap_composite,
                    &hf_display_cap_a8_surface,
                    NULL
                };

                if (i != 0)
                    return;

                proto_tree_add_bitmask_list(tree, tvb, offset, 4, display_cap, ENC_LITTLE_ENDIAN);
                }
                break;
            case SPICE_CHANNEL_INPUTS:
                proto_tree_add_item(tree, hf_inputs_cap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            case SPICE_CHANNEL_CURSOR:
                proto_tree_add_item(tree, hf_cursor_cap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            case SPICE_CHANNEL_RECORD:
                {
                const int * record_cap[] = {
                    &hf_record_cap_celt,
                    &hf_record_cap_volume,
                    NULL
                };

                if (i != 0)
                    return;

                proto_tree_add_bitmask_list(tree, tvb, offset, 4, record_cap, ENC_LITTLE_ENDIAN);
                }
                break;
            default:
                proto_tree_add_expert(tree, pinfo, &ei_spice_unknown_channel, tvb, offset, -1);
                return;
        }
        offset += 4;
    }
}

static void
dissect_spice_link_client_pdu(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, spice_conversation_t *spice_info)
{
    guint32     offset;
    guint32     common_caps_len, channel_caps_len;
    proto_item *ti               = NULL;
    proto_tree *link_header_tree = NULL;
    proto_tree *caps_tree        = NULL;

     if (tree) {
        ti = proto_tree_add_item(tree, hf_link_client, tvb, 0, sizeof_SpiceLinkHeader, ENC_NA);
        link_header_tree = proto_item_add_subtree(ti, ett_link_client);

        dissect_spice_link_common_header(tvb, link_header_tree);
    }
    offset = sizeof_SpiceLinkHeader;

    if (spice_info->channel_type == SPICE_CHANNEL_NONE) {
        spice_info->channel_type = tvb_get_guint8(tvb, offset + 4);
    }
    common_caps_len  = tvb_get_letohl(tvb, offset + 6);
    channel_caps_len = tvb_get_letohl(tvb, offset + 10);
    proto_tree_add_item(tree, hf_conn_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_channel_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_channel_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_num_common_caps, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_num_channel_caps, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_caps_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    if (common_caps_len > 0) {
        caps_tree = proto_tree_add_subtree_format(tree, tvb, offset, common_caps_len * 4,
                                 ett_link_caps, NULL, "Client Common Capabilities (%d bytes)",
                                 common_caps_len * 4); /* caps_len multiplied by 4 as length is in UINT32 units   */
        dissect_spice_common_capabilities(tvb, pinfo, caps_tree, offset, common_caps_len, spice_info, TRUE);
        offset += (common_caps_len * 4);
    }
    if (channel_caps_len > 0) {
        caps_tree = proto_tree_add_subtree_format(tree, tvb, offset, channel_caps_len * 4,
                                 ett_link_caps, NULL, "Client Channel-specific Capabilities (%d bytes)",
                                 channel_caps_len * 4); /* caps_len multiplied by 4 as length is in UINT32 units    */
        dissect_spice_link_capabilities(tvb, pinfo, caps_tree, offset, channel_caps_len, spice_info);
    }
}

static void
dissect_spice_link_server_pdu(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, spice_conversation_t *spice_info)
{
    guint32     offset;
    guint32     common_caps_len, channel_caps_len;
    proto_item *ti        = NULL;
    proto_tree *link_tree = NULL;
    proto_tree *caps_tree = NULL;

     if (tree) {
        ti = proto_tree_add_item(tree, hf_link_server, tvb, 0, sizeof_SpiceLinkHeader, ENC_NA);
        link_tree = proto_item_add_subtree(ti, ett_link_server);

        dissect_spice_link_common_header(tvb, link_tree);
    }

    offset = sizeof_SpiceLinkHeader;

    if (tree) {
        proto_tree_add_item(tree, hf_error_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_bytes_format(tree, hf_spice_x509_subjectpublickeyinfo, tvb, offset + 4, SPICE_TICKET_PUBKEY_BYTES, NULL, "X.509 SubjectPublicKeyInfo (ASN.1)");
        proto_tree_add_item(tree, hf_num_common_caps, tvb, offset + 4 + SPICE_TICKET_PUBKEY_BYTES, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_num_channel_caps, tvb, offset + 8 + SPICE_TICKET_PUBKEY_BYTES, 4, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(tree, hf_caps_offset, tvb, offset + 12 + SPICE_TICKET_PUBKEY_BYTES, 4, ENC_LITTLE_ENDIAN);
    }

    common_caps_len  = tvb_get_letohl(tvb, offset + 4 + SPICE_TICKET_PUBKEY_BYTES);
    channel_caps_len = tvb_get_letohl(tvb, offset + 8 + SPICE_TICKET_PUBKEY_BYTES);
    offset += (int)sizeof_SpiceLinkHeader + SPICE_TICKET_PUBKEY_BYTES;

    if (common_caps_len > 0) {
        caps_tree = proto_tree_add_subtree_format(tree, tvb, offset, common_caps_len * 4,
                                 ett_link_caps, NULL, "Common Capabilities (%d bytes)",
                                 common_caps_len * 4); /* caps_len multiplied by 4 as length is in UINT32 units */
        dissect_spice_common_capabilities(tvb, pinfo, caps_tree, offset, common_caps_len, spice_info, FALSE);
        offset += (common_caps_len * 4);
    }
    if (channel_caps_len > 0) {
        caps_tree = proto_tree_add_subtree_format(tree, tvb, offset, channel_caps_len * 4,
                                 ett_link_caps, NULL, "Channel Capabilities (%d bytes)",
                                 channel_caps_len * 4); /* caps_len multiplied by 4 as length is in UINT32 units */
        dissect_spice_link_capabilities(tvb, pinfo, caps_tree, offset, channel_caps_len, spice_info);
    }
}

static int
dissect_spice(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    conversation_t       *conversation;
    spice_conversation_t *spice_info;
    spice_packet_t       *per_packet_info;
    guint32               avail;
    guint32               pdu_len          = 0;
    guint32               offset;
    proto_item           *ti, *auth_item;
    proto_tree           *spice_tree;
    gboolean              client_sasl_list = FALSE;
    guint8                sasl_auth_result;

    conversation = find_or_create_conversation(pinfo);

    spice_info = (spice_conversation_t*)conversation_get_proto_data(conversation, proto_spice);
    if (!spice_info) {
        spice_info = wmem_new0(wmem_file_scope(), spice_conversation_t);
        spice_info->destport           = pinfo->destport;
        spice_info->channel_type       = SPICE_CHANNEL_NONE;
        spice_info->next_state         = SPICE_LINK_CLIENT;
        spice_info->client_auth        = 0;
        spice_info->server_auth        = 0;
        spice_info->playback_mode      = SPICE_AUDIO_DATA_MODE_INVALID;
        spice_info->client_mini_header = FALSE;
        spice_info->server_mini_header = FALSE;
        conversation_add_proto_data(conversation, proto_spice, spice_info);
        conversation_set_dissector(conversation, spice_handle);
    }

    per_packet_info = (spice_packet_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_spice, 0);
    if (!per_packet_info) {
        per_packet_info = wmem_new(wmem_file_scope(), spice_packet_t);
        per_packet_info->state = spice_info->next_state;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_spice, 0, per_packet_info);
    }

    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(per_packet_info->state, state_name_vs, ""));

    ti = proto_tree_add_item(tree, proto_spice, tvb, 0, -1, ENC_NA);
    spice_tree = proto_item_add_subtree(ti, ett_spice);

    switch (per_packet_info->state) {
        case SPICE_LINK_CLIENT:
            avail   = tvb_reported_length(tvb);
            pdu_len = sizeof_SpiceLinkHeader;
            GET_PDU_FROM_OFFSET(0)
            pdu_len = tvb_get_letohl(tvb, 12) + sizeof_SpiceLinkHeader;
            GET_PDU_FROM_OFFSET(0)
            proto_item_set_len(ti, pdu_len);
            dissect_spice_link_client_pdu(tvb, pinfo, spice_tree, spice_info);
            col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                         "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
            spice_info->next_state = SPICE_LINK_SERVER;
            return pdu_len;
            break;
        case SPICE_LINK_SERVER:
            avail = tvb_reported_length(tvb);
            pdu_len = sizeof_SpiceLinkHeader;
            GET_PDU_FROM_OFFSET(0)
            pdu_len = tvb_get_letohl(tvb, 12) + sizeof_SpiceLinkHeader;
            GET_PDU_FROM_OFFSET(0)
            proto_item_set_len(ti, pdu_len);
            dissect_spice_link_server_pdu(tvb, pinfo, spice_tree, spice_info);
            if (!(spice_info->server_auth & SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION_MASK) ||
                !(spice_info->client_auth & SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION_MASK)) {
                /* Server or clients support spice ticket auth only */
                spice_info->next_state = SPICE_TICKET_CLIENT;
            } else { /* Protocol selection between client and server */
                spice_info->next_state = SPICE_CLIENT_AUTH_SELECT;
            }
            return pdu_len;
            break;
        case SPICE_CLIENT_AUTH_SELECT:
            if (spice_info->destport != pinfo->destport) { /* ignore anything from the server, wait for data from client */
                expert_add_info(pinfo, ti, &ei_spice_expected_from_client);
                break;
            }

            avail = tvb_reported_length(tvb);
            pdu_len = 4;
            GET_PDU_FROM_OFFSET(0)
            proto_item_set_len(ti, 4);

            auth_item = proto_tree_add_item(spice_tree, hf_auth_select_client, tvb, 0, 4, ENC_LITTLE_ENDIAN);
            spice_info->auth_selected = tvb_get_letohl(tvb, 0);
            switch (spice_info->auth_selected) {
                case SPICE_COMMON_CAP_AUTH_SPICE:
                    spice_info->next_state = SPICE_TICKET_CLIENT;
                    break;
                case SPICE_COMMON_CAP_AUTH_SASL:
                    spice_info->next_state = SPICE_SASL_INIT_FROM_SERVER;
                    break;
                default:
                    expert_add_info(pinfo, auth_item, &ei_spice_auth_unknown);
                    break;
            }
            return 4;
            break;
        case SPICE_SASL_INIT_FROM_SERVER:
            offset = 0;
            avail = tvb_reported_length_remaining(tvb, offset);
            pdu_len = 4;
            GET_PDU_FROM_OFFSET(offset)
            pdu_len = tvb_get_letohl(tvb, offset); /* the length of the following messages */
            proto_item_set_len(ti, 4);
            proto_tree_add_item(spice_tree, hf_spice_sasl_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            pdu_len += 4;
            GET_PDU_FROM_OFFSET(offset)
            proto_item_set_len(ti, pdu_len);
            proto_tree_add_uint(spice_tree, hf_spice_supported_authentication_mechanisms_list_length, tvb, offset, 4, pdu_len - 4);
            offset += 4;
            proto_tree_add_item(spice_tree, hf_spice_supported_authentication_mechanisms_list, tvb, offset, pdu_len - 4, ENC_NA|ENC_ASCII);
            offset += (pdu_len - 4);
            spice_info->next_state = SPICE_SASL_START_TO_SERVER;
            return offset;
        case SPICE_SASL_START_TO_SERVER:
            offset = 0;
            while (offset < tvb_reported_length(tvb)) {
                avail = tvb_reported_length_remaining(tvb, offset);
                pdu_len = 4;
                GET_PDU_FROM_OFFSET(offset)
                pdu_len = tvb_get_letohl(tvb, offset); /* the length of the following messages */
                proto_item_set_len(ti, 4);
                proto_tree_add_item(spice_tree, hf_spice_sasl_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (pdu_len == 0) {
                    /* meaning, empty PDU - assuming the client_out_list, which may be empty*/
                    spice_info->next_state = SPICE_SASL_START_FROM_SERVER;
                    pdu_len = 4; /* only the size field.*/
                    offset += pdu_len;
                } else {
                    pdu_len += 4;
                    GET_PDU_FROM_OFFSET(offset)
                    proto_item_set_len(ti, pdu_len);
                    if (client_sasl_list == FALSE) {
                        client_sasl_list = TRUE;
                        col_set_str(pinfo->cinfo, COL_INFO, "Client selected SASL authentication mechanism (start to server)");
                        proto_tree_add_uint(spice_tree, hf_spice_selected_authentication_mechanism_length, tvb, offset, 4, pdu_len - 4);
                        offset += 4;
                        proto_tree_add_item(spice_tree, hf_spice_selected_authentication_mechanism, tvb, offset, pdu_len - 4, ENC_NA|ENC_ASCII);
                    } else {
                        /* this is the client out list, ending the start from client message */
                         col_set_str(pinfo->cinfo, COL_INFO, "Client out mechanism (start to server)");
                         proto_tree_add_uint(spice_tree, hf_spice_client_out_mechanism_length, tvb, offset, 4, pdu_len - 4);
                         offset += 4;
                         proto_tree_add_item(spice_tree, hf_spice_selected_client_out_mechanism, tvb, offset, pdu_len - 4, ENC_NA|ENC_ASCII);
                         spice_info->next_state = SPICE_SASL_START_FROM_SERVER;
                    }
                    offset += (pdu_len - 4);
                }
            }
            return pdu_len;
            break;
        case SPICE_SASL_START_FROM_SERVER:
        case SPICE_SASL_STEP_FROM_SERVER:
            offset = 0;
            while (offset < tvb_reported_length(tvb)) {
                avail = tvb_reported_length_remaining(tvb, offset);
                pdu_len = 4;
                GET_PDU_FROM_OFFSET(offset)
                pdu_len = tvb_get_letohl(tvb, offset); /* the length of the following messages */
                proto_item_set_len(ti, 4 + pdu_len);
                proto_tree_add_item(spice_tree, hf_spice_sasl_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (pdu_len == 0) { /* meaning, empty PDU */
                offset += 4; /* only the size field.*/
                } else {
                    pdu_len += 4;
                    GET_PDU_FROM_OFFSET(offset)
                    offset += 4;
                    proto_tree_add_item(spice_tree, hf_spice_sasl_authentication_data, tvb, offset, pdu_len - 4, ENC_ASCII|ENC_NA);
                    offset += (pdu_len - 4);
                }
            }
            if (per_packet_info->state == SPICE_SASL_START_FROM_SERVER) {
                spice_info->next_state = SPICE_SASL_START_FROM_SERVER_CONT;
            } else {
                spice_info->next_state = SPICE_SASL_STEP_FROM_SERVER_CONT;
            }
            return pdu_len;
            break;
        case SPICE_SASL_START_FROM_SERVER_CONT:
        case SPICE_SASL_STEP_FROM_SERVER_CONT:
            offset = 0;
            avail = tvb_reported_length_remaining(tvb, offset);
            if (avail >= 1) {
                proto_item_set_len(ti, 1);
                sasl_auth_result = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(spice_tree, hf_spice_sasl_auth_result, tvb, offset, 1, ENC_NA);

                if (per_packet_info->state == SPICE_SASL_START_FROM_SERVER_CONT) {
                    /* if we are in the sasl start, and can continue */
                    if (sasl_auth_result == 0) { /* 0 = continue */
                        spice_info->next_state = SPICE_SASL_STEP_TO_SERVER;
                    } else {
                        expert_add_info_format(pinfo, ti, &ei_spice_sasl_auth_result, "SPICE_SASL_START_FROM_SERVER_CONT and sasl_auth_result is %d",
                                  sasl_auth_result);
                    }
                } else { /* SPICE_SASL_STEP_FROM_SERVER_CONT state. */
                        spice_info->next_state = SPICE_TICKET_SERVER;
                }
            }
            return 1;
            break;
        case SPICE_SASL_STEP_TO_SERVER:
            offset = 0;
            while (offset < tvb_reported_length(tvb)) {
                avail = tvb_reported_length_remaining(tvb, offset);
                pdu_len = 4;
                GET_PDU_FROM_OFFSET(offset)
                pdu_len = tvb_get_letohl(tvb, offset); /* the length of the following messages */
                proto_item_set_len(ti, 4);
                proto_tree_add_item(spice_tree, hf_spice_sasl_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (pdu_len == 0) {
                    /* meaning, empty PDU - assuming the client_out_list, which may be empty*/
                    col_set_str(pinfo->cinfo, COL_INFO, "SASL authentication from client (step to server)");
                    spice_info->next_state = SPICE_SASL_STEP_FROM_SERVER;
                    pdu_len = 4; /* only the size field.*/
                    offset += pdu_len;
                } else {
                    pdu_len += 4;
                    GET_PDU_FROM_OFFSET(offset)
                    proto_item_set_len(ti, pdu_len);
                    col_set_str(pinfo->cinfo, COL_INFO, "Clientout (step to server)");
                    proto_tree_add_uint(spice_tree, hf_spice_clientout_length, tvb, offset, 4, pdu_len - 4);
                    offset += 4;
                    proto_tree_add_item(spice_tree, hf_spice_clientout_list, tvb, offset, pdu_len - 4, ENC_NA|ENC_ASCII);
                    spice_info->next_state = SPICE_SASL_STEP_FROM_SERVER;
                    offset += (pdu_len - 4);
                }
            }
            return pdu_len;
            break;
        case SPICE_SASL_DATA:
            offset = 0;
            while (offset < tvb_reported_length(tvb)) {
                avail = tvb_reported_length_remaining(tvb, offset);
                pdu_len = 4;
                GET_PDU_FROM_OFFSET(offset)
                pdu_len = tvb_get_ntohl(tvb, offset); /* the length of the following messages */
                proto_item_set_len(ti, pdu_len);
                proto_tree_add_item(spice_tree, hf_spice_sasl_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                if (pdu_len == 0) { /* meaning, empty PDU */
                    return 4; /* only the size field.*/
                } else {
                    pdu_len += 4;
                }
                GET_PDU_FROM_OFFSET(offset)
                proto_item_set_len(ti, pdu_len);
                col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                             "Spice %s (SASL wrapped)", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));

                offset += 4;
                proto_tree_add_bytes_format(spice_tree, hf_spice_sasl_data, tvb, offset, pdu_len - 4, NULL, "SASL data (%u bytes)", pdu_len - 4);
                offset += (pdu_len - 4);
            }
            return pdu_len;
            break;
        case SPICE_DATA:
            offset = 0;
            while (offset < tvb_reported_length(tvb)) {
                avail = tvb_reported_length_remaining(tvb, offset);
                if (spice_info->client_mini_header && spice_info->server_mini_header) {
                    pdu_len = sizeof_SpiceMiniDataHeader;
                    GET_PDU_FROM_OFFSET(offset)
                    pdu_len = tvb_get_letohl(tvb, offset + 2);
                    pdu_len += sizeof_SpiceMiniDataHeader;
                } else {
                    pdu_len = sizeof_SpiceDataHeader;
                    GET_PDU_FROM_OFFSET(offset)
                    /* if there are no sub-messages, get the usual message body size.   */
                    /* Note that we do not dissect properly yet sub-messages - but they */
                    /* are not used in the protcol either */
                    pdu_len = tvb_get_letohl(tvb, offset + 10);
                    pdu_len += sizeof_SpiceDataHeader; /* +sizeof_SpiceDataHeader since you need to exclude the SPICE   */
                                                   /* data header, which is sizeof_SpiceDataHeader (18) bytes long) */
                }
                GET_PDU_FROM_OFFSET(offset)
                proto_item_set_len(ti, pdu_len);

                if (spice_info->destport == pinfo->destport) { /* client to server traffic */
                     offset = dissect_spice_data_client_pdu(tvb, spice_tree, pinfo, spice_info, offset);
                 } else { /* server to client traffic */
                     offset = dissect_spice_data_server_pdu(tvb, spice_tree, pinfo, spice_info, offset, pdu_len);
                 }
             }
             return offset;
            break;
        case SPICE_TICKET_CLIENT:
            if (spice_info->destport != pinfo->destport) /* ignore anything from the server, wait for ticket from client */
                break;
            avail = tvb_reported_length(tvb);
            pdu_len = 128;
            GET_PDU_FROM_OFFSET(0)
            proto_item_set_len(ti, 128);
            proto_tree_add_item(spice_tree, hf_ticket_client, tvb, 0, 128, ENC_NA);
            spice_info->next_state = SPICE_TICKET_SERVER;
            return 128;
            break;
        case SPICE_TICKET_SERVER:
            if (spice_info->destport != pinfo->srcport) /* ignore anything from the client, wait for ticket from server */
                break;
            avail = tvb_reported_length(tvb);
            pdu_len = 4;
            GET_PDU_FROM_OFFSET(0)
            proto_item_set_len(ti, 4);
            proto_tree_add_item(spice_tree, hf_ticket_server, tvb, 0, 4, ENC_LITTLE_ENDIAN);
            if (spice_info->auth_selected == SPICE_COMMON_CAP_AUTH_SASL) {
               spice_info->next_state = SPICE_SASL_DATA;
            } else {
                spice_info->next_state = SPICE_DATA;
            }
            return pdu_len;
            break;
        default:
            break;
    }
    return 0;
}

static gboolean
test_spice_protocol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    if ((tvb_reported_length(tvb) >= 4) && (tvb_get_ntohl(tvb, 0) == SPICE_MAGIC)) {
        dissect_spice(tvb, pinfo, tree, data);
        return TRUE;
    }
    return FALSE;
}

/* Register the protocol with Wireshark */
void
proto_register_spice(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_link_client,
          { "Link client header", "spice.link_client",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_link_server,
          { "Link server header", "spice.link_server",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spice_magic,
          { "SPICE MAGIC", "spice.magic",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_major_version,
          { "Protocol major version", "spice.major_version",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_minor_version,
          { "Protocol minor version", "spice.minor_version",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_message_size,
          { "Message size", "spice.message_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_message_type,
          { "Message type", "spice.message_type",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_conn_id,
          { "Session ID", "spice.conn_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_channel_type,
          { "Channel type", "spice.channel_type",
            FT_UINT8, BASE_DEC, VALS(channel_types_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_channel_id,
          { "Channel ID", "spice.channel_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_num_common_caps,
          { "Number of common capabilities", "spice.num_common_caps",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_num_channel_caps,
          { "Number of channel capabilities", "spice.num_channel_caps",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_caps_offset,
          { "Capabilities offset (bytes)", "spice.caps_offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_error_code,
          { "spice ERROR", "spice.error_code",
            FT_UINT32, BASE_DEC, VALS(spice_link_err_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_serial,
          { "Message serial number", "spice.serial",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data,
          { "Message header", "spice.message_header",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data_size,
          { "Message body size (bytes)", "spice.message_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data_sublist,
          { "Sub-list offset (bytes)", "spice.message_sublist",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ticket_client,
          { "Ticket - client", "spice.ticket_client",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ticket_server,
          { "Link result", "spice.ticket_server",
            FT_UINT32, BASE_DEC, VALS(spice_link_err_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_auth_select_client,
          { "Authentication selected by client", "spice.auth_select_client",
            FT_UINT32, BASE_DEC, VALS(spice_auth_select_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_common_cap_auth_select,
          { "Auth Selection", "spice.common_cap_auth_select",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION_MASK,
            NULL, HFILL }
        },
        { &hf_common_cap_auth_spice,
          { "Auth Spice", "spice.common_cap_auth_spice",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_COMMON_CAP_AUTH_SPICE_MASK,
            NULL, HFILL }
        },
        { &hf_common_cap_auth_sasl,
          { "Auth SASL", "spice.common_cap_auth_sasl",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_COMMON_CAP_AUTH_SASL_MASK,
            NULL, HFILL }
        },
        { &hf_common_cap_mini_header,
          { "Mini Header", "spice.common_cap_mini_header",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_COMMON_CAP_MINI_HEADER_MASK,
            NULL, HFILL }
        },
        { &hf_record_cap_volume,
          { "Volume record channel support", "spice.record_cap_volume",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_RECORD_CAP_VOLUME_MASK,
            NULL, HFILL }
        },
        { &hf_record_cap_celt,
          { "CELT 0.5.1 record channel support", "spice.record_cap_celt",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_RECORD_CAP_CELT_0_5_1_MASK,
            NULL, HFILL }
        },
        { &hf_display_cap_sized_stream,
          { "Sized stream display channel support", "spice.display_cap_sized_stream",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_DISPLAY_CAP_SIZED_STREAM_MASK,
            NULL, HFILL }
        },
        { &hf_display_cap_monitors_config,
          { "Monitors configuration display channel support", "spice.display_cap_monitors_config",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_DISPLAY_CAP_MONITORS_CONFIG_MASK,
            NULL, HFILL }
        },
        { &hf_display_cap_composite,
          { "Composite capability display channel support", "spice.display_cap_composite",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_DISPLAY_CAP_COMPOSITE_MASK,
            NULL, HFILL }
        },
        { &hf_display_cap_a8_surface,
          { "A8 bitmap display channel support", "spice.display_cap_a8_surface",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_DISPLAY_CAP_A8_SURFACE_MASK,
            NULL, HFILL }
        },
        { &hf_cursor_cap,
          { "Cursor channel capability", "spice.cursor_cap",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_inputs_cap,
          { "Inputs channel capability", "spice.inputs_cap",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_main_num_channels,
          { "Number of Channels", "spice.main_num_channels",
            FT_UINT32, 4, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_main_cap_semi_migrate,
          { "Semi-seamless migration capability", "spice.main_cap_semi_migrate",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_MAIN_CAP_SEMI_SEAMLESS_MIGRATE_MASK,
            NULL, HFILL }
        },
        { &hf_main_cap_vm_name_uuid,
          { "VM name and UUID messages capability", "spice.main_cap_vm_name_uuid",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_MAIN_CAP_VM_NAME_UUID_MASK,
            NULL, HFILL }
        },
        { &hf_main_cap_agent_connected_tokens,
          { "Agent connected tokens capability", "spice.main_cap_agent_connected_tokens",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_MAIN_CAP_AGENT_CONNECTED_TOKENS_MASK,
            NULL, HFILL }
        },
        { &hf_main_cap_seamless_migrate,
          { "Seamless migration capability", "spice.main_cap_seamless_migrate",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_MAIN_CAP_SEAMLESS_MIGRATE_MASK,
            NULL, HFILL }
        },
        { &hf_audio_timestamp,
          { "Timestamp", "spice.audio_timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_audio_mode,
          { "Mode", "spice.audio_mode",
            FT_UINT16, BASE_DEC, VALS(playback_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_audio_channels,
          { "Channels", "spice.audio_channels",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_audio_format,
          { "Format", "spice.audio_format",
            FT_UINT16, BASE_DEC, VALS(spice_audio_fmt_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_audio_frequency,
          { "Frequency", "spice.audio_frequency",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_audio_volume,
          { "Volume", "spice.audio_volume",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_audio_mute,
          { "Mute", "spice.audio_mute",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_audio_latency,
          { "Latency (ms)", "spice.audio_latency",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_red_set_ack_generation,
          { "Set ACK generation", "spice.red_set_ack_generation",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_red_set_ack_window,
          { "Set ACK window (messages)", "spice.red_set_ack_window",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_Clip_type,
          { "Clip type", "spice.clip_type",
            FT_UINT8, BASE_DEC, VALS(spice_clip_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_Mask_flag,
          { "Mask flag", "spice.mask_flag",
            FT_UINT8, BASE_DEC, VALS(spice_mask_flags_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_display_rop_descriptor,
          { "ROP descriptor", "spice.display_rop_descriptor",
            FT_UINT16, BASE_HEX, VALS(spice_ropd_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_display_scale_mode,
          { "Scale mode", "spice.scale_mode",
            FT_UINT8, BASE_DEC, VALS(spice_image_scale_mode_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_red_ping_id,
          { "Ping ID", "spice.ping_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_red_timestamp,
          { "timestamp", "spice.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spice_display_mode_width,
          { "Display Width", "spice.display_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spice_display_mode_height,
          { "Display Height", "spice.display_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spice_display_mode_depth,
          { "Color depth", "spice.display_depth",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_image_desc_id,
          { "Image ID", "spice.image_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_image_desc_type,
          { "Image type", "spice.image_type",
            FT_UINT8, BASE_DEC, VALS(spice_image_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_image_desc_flags,
          { "Flags", "spice.image_flags",
            FT_UINT8, BASE_HEX, VALS(spice_image_flags_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_image_desc_width,
          { "Width", "spice.image_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_image_desc_height,
          { "Height", "spice.image_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_width,
          { "Width", "spice.quic_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_type,
          { "QUIC image type", "spice.quic_type",
            FT_UINT32, BASE_DEC, VALS(quic_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_quic_height,
          { "Height", "spice.quic_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_major_version,
          { "QUIC major version", "spice.quic_major_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_minor_version,
          { "QUIC minor version", "spice.quic_minor_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_LZ_width,
          { "Width", "spice.LZ_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_LZ_height,
          { "Height", "spice.LZ_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_LZ_RGB_type,
          { "Image type", "spice.LZ_RGB_type",
            FT_UINT8, BASE_DEC, VALS(LzImage_type_vs), 0xf,
            NULL, HFILL }
        },
        { &hf_LZ_major_version,
          { "LZ major version", "spice.LZ_major_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_LZ_minor_version,
          { "LZ minor version", "spice.LZ_minor_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_LZ_stride,
          { "Stride", "spice.LZ_stride",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_LZ_RGB_dict_id,
          { "LZ RGB Dictionary ID", "spice.LZ_RGB_dict_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_trail_len,
          { "Cursor trail length", "spice.cursor_trail_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_trail_freq,
          { "Cursor trail frequency", "spice.cursor_trail_freq",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_trail_visible,
          { "Cursor trail visibility", "spice.cursor_trail_visible",
            FT_UINT8, BASE_DEC, VALS(cursor_visible_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_unique,
          { "Cursor unique ID", "spice.cursor_unique",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_type,
          { "Cursor type", "spice.cursor_type",
            FT_UINT8, BASE_HEX, VALS(spice_cursor_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_width,
          { "Cursor width", "spice.cursor_width",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_height,
          { "Cursor height", "spice.cursor_height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_hotspot_x,
          { "Cursor hotspot X", "spice.cursor_hotspot_x",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_hotspot_y,
          { "Cursor hotspot Y", "spice.cursor_hotspot_y",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_flags, /*FIXME - those are flags */
          { "Cursor flags", "spice.cursor_flags",
            FT_UINT16, BASE_HEX, VALS(spice_cursor_flags_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_id,
          { "Cursor ID", "spice.cursor_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spice_display_init_cache_id,
          { "Cache ID", "spice.display_init_cache_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spice_display_init_cache_size,
          { "Cache size (pixels)", "spice.display_init_cache_size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spice_display_init_glz_dict_id,
          { "GLZ Dictionary ID", "spice.display_init_glz_dict_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spice_display_init_dict_window_size,
          { "Dictionary window size", "spice.display_init_dict_window_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_brush_type,
          { "Brush type", "spice.brush_type",
            FT_UINT8, BASE_DEC, VALS(spice_brush_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_brush_rgb,
          { "Brush color", "spice.brush_rgb",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pixmap_width,
          { "Pixmap width", "spice.pixmap_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pixmap_height,
          { "Pixmap height", "spice.pixmap_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pixmap_stride,
          { "Pixmap stride", "spice.pixmap_stride",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pixmap_address,
          { "Pixmap palette pointer", "spice.pixmap_palette_address",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pixmap_format,
          { "Pixmap format", "spice.pixmap_format",
            FT_UINT8, BASE_DEC, VALS(spice_bitmap_fmt_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_pixmap_flags,
          { "Pixmap flags", "spice.pixmap_flags",
            FT_UINT8, BASE_HEX, VALS(spice_bitmap_flags_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_keyboard_modifiers,
          { "Keyboard modifiers", "spice.keyboard_modifiers",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_keyboard_modifier_scroll_lock,
          { "Scroll Lock", "spice.keyboard_modifier_scroll_lock",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), SPICE_KEYBOARD_MODIFIER_FLAGS_SCROLL_LOCK,
            NULL, HFILL }
        },
        { &hf_keyboard_modifier_num_lock,
          { "Num Lock", "spice.keyboard_modifier_num_lock",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), SPICE_KEYBOARD_MODIFIER_FLAGS_NUM_LOCK,
            NULL, HFILL }
        },
        { &hf_keyboard_modifier_caps_lock,
          { "Caps Lock", "spice.keyboard_modifier_caps_lock",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), SPICE_KEYBOARD_MODIFIER_FLAGS_CAPS_LOCK,
            NULL, HFILL }
        },
        { &hf_keyboard_code,
          { "Key scan code", "spice.keyboard_key_code",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rectlist_size,
          { "RectList size", "spice.rectlist_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_migrate_dest_port,
          { "Migrate Dest Port", "spice.migrate_dest_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_migrate_dest_sport,
          { "Migrate Dest Secure Port", "spice.migrate_dest_sport",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_migrate_src_mig_version,
          { "Migrate Source Migration Version", "spice.migrate_src_version",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_session_id,
          { "Session ID", "spice.main_session_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_channels_hint,
          { "Number of display channels", "spice.display_channels_hint",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_supported_mouse_modes,
          { "Supported mouse modes", "spice.supported_mouse_modes",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_supported_mouse_modes_flags,
          { "Supported mouse modes", "spice.supported_mouse_modes_flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_current_mouse_mode,
          { "Current mouse mode", "spice.current_mouse_mode",
            FT_UINT32, BASE_HEX, VALS(spice_mouse_mode_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_supported_mouse_modes_flag_client,
          { "Client mode", "spice.supported_mouse_modes_flag_client",
            FT_BOOLEAN, 2, TFS(&tfs_set_notset), SPICE_MOUSE_MODE_CLIENT,
            NULL, HFILL }
        },
        { &hf_supported_mouse_modes_flag_server,
          { "Server mode", "spice.supported_mouse_modes_flags_server",
            FT_BOOLEAN, 2, TFS(&tfs_set_notset), SPICE_MOUSE_MODE_SERVER,
            NULL, HFILL }
        },
        { &hf_current_mouse_mode_flags,
          { "Current mouse mode", "spice.current_mouse_mode_flags",
            FT_UINT16, BASE_HEX, VALS(spice_mouse_mode_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_agent_connected,
          { "Agent", "spice.agent",
            FT_UINT32, BASE_DEC, VALS(spice_agent_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_agent_tokens,
          { "Agent tokens", "spice.agent_tokens",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_multi_media_time,
          { "Current server multimedia time", "spice.multimedia_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ram_hint,
          { "RAM hint", "spice.ram_hint",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_button_state, /*FIXME - bitmask */
          { "Mouse button state", "spice.button_state",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mouse_display_id,
          { "Mouse display ID", "spice.mouse_display_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_text_fore_mode,
          { "Text foreground mode", "spice.draw_text_fore_mode",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_text_back_mode,
          { "Text background mode", "spice.draw_text_back_mode",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_monitor_config_count,
          { "Monitor count", "spice.monitor_config_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_monitor_config_max_allowed,
          { "Max.allowed monitors", "spice.monitor_config_max_allowed",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_id,
          { "Stream ID", "spice.display_stream_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_report_unique_id,
          { "Unique ID", "spice.display_stream_report_unique_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_report_max_window_size,
          { "Max window size", "spice.display_stream_report_max_window_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_report_timeout,
          { "Timeout (ms)", "spice.display_stream_report_timeout",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_flags,
          { "Stream flags", "spice.display_stream_flags",
            FT_UINT8, BASE_DEC, VALS(spice_stream_flags_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_codec_type,
          { "Stream codec type", "spice.display_stream_codec_type",
            FT_UINT32, BASE_DEC, VALS(spice_video_codec_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_stamp,
          { "Stream stamp", "spice.display_stream_stamp",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_data_size,
          { "Stream data size", "spice.display_stream_data_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_width,
          { "Stream width", "spice.stream_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_height,
          { "Stream height", "spice.stream_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_src_width,
          { "Stream source width", "spice.stream_src_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_src_height,
          { "Stream source height", "spice.stream_src_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_surface_id,
          { "Surface ID", "spice.surface_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_surface_width,
          { "Surface width", "spice.surface_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_surface_height,
          { "Surface height", "spice.surface_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_surface_format,
          { "Surface format", "spice.surface_format",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_surface_flags,
          { "Surface flags", "spice.surface_flags",
            FT_UINT32, BASE_DEC, VALS(spice_surface_flags_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_tranparent_src_color,
          { "Transparent source color", "spice.display_transparent_src_color",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_tranparent_true_color,
          { "Transparent true color", "spice.display_transparent_true_color",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_main_client_agent_tokens,
          { "Agent tokens", "spice.main_agent_tokens",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_protocol,
          { "Agent Protocol version", "spice.main_agent_protocol",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_type,
          { "Agent message type", "spice.agent_message_type",
            FT_UINT32, BASE_DEC, VALS(agent_message_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_agent_opaque,
          { "Agent Opaque", "spice.main_agent_opaque",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_size,
          { "Agent message size", "spice.main_agent_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_token,
          { "Agent token", "spice.main_agent_token",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_clipboard_selection,
          { "Agent clipboard selection", "spice.main_agent_clipboard_selection",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_clipboard_type,
          { "Agent clipboard type", "spice.main_agent_clipboard_type",
            FT_UINT32, BASE_DEC, VALS(agent_clipboard_type), 0x0,
            NULL, HFILL }
        },
       { &hf_LZ_PLT_type,
          { "LZ_PLT image type", "spice.LZ_PLT_type",
            FT_UINT32, BASE_DEC, VALS(LzImage_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_spice_sasl_auth_result,
          { "Authentication result", "spice.sasl_auth_result",
            FT_UINT8, BASE_DEC, VALS(spice_sasl_auth_result_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_main_uuid,
          { "UUID", "spice.main_uuid",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_main_name_len,
          { "Name length", "spice.main_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_main_name,
          { "Name", "spice.main_name",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_head_id,
          { "Head ID", "spice.display_head_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_head_surface_id,
          { "Head surface ID", "spice.display_head_surface_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_head_width,
          { "Head width", "spice.display_head_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_head_height,
          { "Head height", "spice.display_head_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_head_x,
          { "Head X coordinate", "spice.display_head_x",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_head_y,
          { "Head Y coordinate", "spice.display_head_y",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_head_flags,
          { "Head flags", "spice.display_head_flags",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zlib_uncompress_size,
          { "ZLIB stream uncompressed size", "spice.zlib_uncompress_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zlib_compress_size,
          { "ZLIB stream compressed size", "spice.zlib_compress_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rect_left,
          { "left", "spice.rect.left",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rect_top,
          { "top", "spice.rect.top",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rect_right,
          { "right", "spice.rect.right",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rect_bottom,
          { "bottom", "spice.rect.bottom",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_point32_x,
          { "x", "spice.point32.x",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_point32_y,
          { "y", "spice.point32.y",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_point16_x,
          { "x", "spice.point16.x",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_point16_y,
          { "y", "spice.point16.y",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_severity,
          { "Severity", "spice.notify_severity",
            FT_UINT32, BASE_DEC, VALS(spice_notify_severity_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_visibility,
          { "Visibility", "spice.notify_visibility",
            FT_UINT32, BASE_DEC, VALS(spice_notify_visibility_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_notify_code,
          { "error/warn/info code", "spice.notify_code",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_notify_message_len,
          { "Message length", "spice.notify_message_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_notify_message,
          { "Message", "spice.notify_message",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_num_glyphs,
          { "Number of glyphs", "spice.num_glyphs",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_port_opened,
          { "Opened", "spice.port_opened",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_port_event,
          { "Event", "spice.port_event",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_raw_data,
          { "data", "spice.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_inval_list_count,
          { "count", "spice.display_inval_list_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_resource_type,
          { "Type", "spice.resource_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_resource_id,
          { "id", "spice.resource_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ref_image,
          { "Image address", "spice.ref_image",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ref_string,
          { "String address", "spice.ref_string",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_num_monitors,
          { "Number of monitors", "spice.agent_num_monitors",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_monitor_height,
          { "Height", "spice.agent_monitor_height",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_monitor_width,
          { "Width", "spice.agent_monitor_width",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_monitor_depth,
          { "Depth", "spice.agent_monitor_depth",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_monitor_x,
          { "x", "spice.agent_monitor_x",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_monitor_y,
          { "y", "spice.agent_monitor_y",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vd_agent_caps_request,
          { "Request", "spice.vd_agent_caps_request",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_mouse_state,
          { "Mouse State", "spice.vd_agent_cap_mouse_state",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_MOUSE_STATE,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_monitors_config,
          { "Monitors config", "spice.vd_agent_cap_monitors_config",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_MONITORS_CONFIG,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_reply,
          { "Reply", "spice.vd_agent_cap_reply",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_REPLY,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_clipboard,
          { "Clipboard", "spice.vd_agent_cap_clipboard",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_CLIPBOARD,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_display_config,
          { "Display config", "spice.vd_agent_cap_display_config",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_DISPLAY_CONFIG,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_clipboard_by_demand,
          { "Clipboard by demand", "spice.vd_agent_cap_clipboard_by_demand",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_CLIPBOARD_BY_DEMAND,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_clipboard_selection,
          { "Clipboard selection", "spice.vd_agent_cap_clipboard_selection",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_CLIPBOARD_SELECTION,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_sparse_monitors_config,
          { "Sparse monitors config", "spice.vd_agent_cap_sparse_monitors_config",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_SPARSE_MONITORS_CONFIG,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_guest_lineend_lf,
          { "Guest line-end LF", "spice.vd_agent_cap_guest_lineend_lf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_GUEST_LINEEND_LF,
            NULL, HFILL }
        },
        { &hf_vd_agent_cap_guest_lineend_crlf,
          { "Guest line-end CRLF", "spice.vd_agent_cap_guest_lineend_crlf",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CAP_GUEST_LINEEND_CRLF,
            NULL, HFILL }
        },
        { &hf_vd_agent_monitors_config_flag_use_pos,
          { "Use position", "spice.vd_agent_monitors_config_flag_use_pos",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), VD_AGENT_CONFIG_MONITORS_FLAG_USE_POS,
            NULL, HFILL }
        },
        { &hf_vd_agent_reply_type,
          { "Type", "spice.vd_agent_reply_type",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vd_agent_reply_error,
          { "Error", "spice.vd_agent_reply_error",
            FT_UINT32, BASE_DEC, VALS(vd_agent_reply_error_vs), 0x0,
            NULL, HFILL }
        },
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_spice_pixmap_pixels, { "Pixmap pixels", "spice.pixmap_pixels", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_pallete, { "Pallete", "spice.pallete", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_cursor_data, { "Cursor data", "spice.cursor_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_quic_image_size, { "QUIC image size", "spice.quic_image_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_quic_magic, { "QUIC magic", "spice.quic_magic", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_quic_compressed_image_data, { "QUIC compressed image data", "spice.quic_compressed_image_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_lz_magic, { "LZ magic", "spice.lz_magic", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_lz_rgb_compressed_image_data, { "LZ_RGB compressed image data", "spice.lz_rgb_compressed_image_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_topdown_flag, { "Topdown flag", "spice.topdown_flag", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_unknown_bytes, { "Unknown bytes", "spice.unknown_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
#if 0
      { &hf_spice_lz_jpeg_image_size, { "LZ JPEG image size", "spice.lz_jpeg_image_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
#endif
      { &hf_spice_glz_rgb_image_size, { "GLZ RGB image size", "spice.glz_rgb_image_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_lz_rgb_image_size, { "LZ RGB image size", "spice.lz_rgb_image_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_lz_plt_flag, { "LZ_PLT Flag", "spice.lz_plt_flag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_lz_plt_image_size, { "LZ PLT image size", "spice.lz_plt_image_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_pallete_offset, { "pallete offset", "spice.pallete_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_lz_plt_data, { "LZ_PLT data", "spice.lz_plt_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_zlib_stream, { "ZLIB stream", "spice.zlib_stream", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_image_from_cache, { "Image from Cache", "spice.image_from_cache", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_surface_id, { "Surface ID", "spice.surface_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_image_from_cache_lossless, { "Image from Cache - lossless", "spice.image_from_cache_lossless", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_ping_data, { "PING DATA", "spice.ping_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_display_mark_message, { "DISPLAY_MARK message", "spice.display_mark_message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_display_reset_message, { "DISPLAY_RESET message", "spice.display_reset_message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_rop3, { "ROP3", "spice.rop3", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_scale_mode, { "scale mode", "spice.scale_mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_glyph_flags, { "Glyph flags", "spice.glyph_flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_stream_data, { "Stream data", "spice.stream_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_vd_agent_clipboard_message, { "VD_AGENT_CLIPBOARD message", "spice.vd_agent_clipboard_message", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_vd_agent_display_config_message, { "VD_AGENT_DISPLAY_CONFIG message", "spice.vd_agent_display_config_message", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_reserved, { "Reserved", "spice.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_vd_agent_clipboard_release_message, { "VD_AGENT_CLIPBOARD_RELEASE message", "spice.vd_agent_clipboard_release_message", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_server_inputs_mouse_motion_ack_message, { "Server INPUTS_MOUSE_MOTION_ACK message", "spice.server_inputs_mouse_motion_ack_message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_name_length, { "Name length (bytes)", "spice.name_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_x509_subjectpublickeyinfo, { "X.509 SubjectPublicKeyInfo (ASN.1)", "spice.x509_subjectpublickeyinfo", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_sasl_message_length, { "SASL message length", "spice.sasl_message_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_supported_authentication_mechanisms_list_length, { "Supported authentication mechanisms list length", "spice.supported_authentication_mechanisms_list_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_supported_authentication_mechanisms_list, { "Supported authentication mechanisms list", "spice.supported_authentication_mechanisms_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_selected_authentication_mechanism_length, { "Selected authentication mechanism length", "spice.selected_authentication_mechanism_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_selected_authentication_mechanism, { "Selected authentication mechanism", "spice.selected_authentication_mechanism", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_client_out_mechanism_length, { "Client out mechanism length", "spice.client_out_mechanism_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_selected_client_out_mechanism, { "Selected client out mechanism", "spice.selected_client_out_mechanism", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_sasl_authentication_data, { "SASL authentication data", "spice.sasl_authentication_data", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_clientout_length, { "clientout length", "spice.clientout_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_clientout_list, { "clientout list", "spice.clientout_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_spice_sasl_data, { "SASL data", "spice.sasl_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    /* Setup protocol subtree arrays */
    static gint *ett[] = {
        &ett_spice,
        &ett_link_client,
        &ett_link_server,
        &ett_link_caps,
        &ett_ticket_client,
        &ett_auth_select_client,
        &ett_ticket_server,
        &ett_data,
        &ett_message,
        &ett_playback,
        &ett_common_server_message,
        &ett_common_client_message,
        &ett_display_client,
        &ett_display_server,
        &ett_point,
        &ett_point16,
        &ett_rect,
        &ett_DisplayBase,
        &ett_Clip,
        &ett_Mask,
        &ett_imagedesc,
        &ett_imageQuic,
        &ett_GLZ_RGB,
        &ett_LZ_RGB,
        &ett_ZLIB_GLZ,
        &ett_Uncomp_tree,
        &ett_LZ_JPEG,
        &ett_LZ_PLT,
        &ett_JPEG,
        &ett_cursor_header,
        &ett_RedCursor,
        &ett_cursor,
        &ett_spice_main,
        &ett_brush,
        &ett_pattern,
        &ett_Pixmap,
        &ett_SpiceHead,
        &ett_inputs_client,
        &ett_rectlist,
        &ett_inputs_server,
        &ett_record_client,
        &ett_record_server,
        &ett_main_client,
        &ett_spice_agent,
        &ett_cap_tree
    };

    static ei_register_info ei[] = {
        { &ei_spice_decompress_error, { "spice.decompress_error", PI_PROTOCOL, PI_WARN, "Error: Unable to decompress content", EXPFILL }},
        { &ei_spice_unknown_message, { "spice.unknown_message", PI_UNDECODED, PI_WARN, "Unknown message - cannot dissect", EXPFILL }},
        { &ei_spice_not_dissected, { "spice.not_dissected", PI_UNDECODED, PI_WARN, "Message not dissected", EXPFILL }},
        { &ei_spice_auth_unknown, { "spice.auth_unknown", PI_PROTOCOL, PI_WARN, "Unknown authentication selected", EXPFILL }},
        { &ei_spice_sasl_auth_result, { "spice.sasl_auth_result.expert", PI_PROTOCOL, PI_WARN, "Bad sasl_auth_result", EXPFILL }},
        { &ei_spice_expected_from_client, { "spice.expected_from_client", PI_PROTOCOL, PI_WARN, "SPICE_CLIENT_AUTH_SELECT: packet from server - expected from client", EXPFILL }},
        /* Generated from convert_proto_tree_add_text.pl */
        { &ei_spice_unknown_image_type, { "spice.unknown_image_type", PI_UNDECODED, PI_WARN, "Unknown image type - cannot dissect", EXPFILL }},
        { &ei_spice_brush_type, { "spice.brush_type.invalid", PI_PROTOCOL, PI_WARN, "Invalid Brush type", EXPFILL }},
        { &ei_spice_Mask_flag, { "spice.mask_flag.irrelevant", PI_PROTOCOL, PI_NOTE, "value irrelevant as bitmap address is 0", EXPFILL }},
        { &ei_spice_Mask_point, { "spice.mask_point.irrelevant", PI_PROTOCOL, PI_NOTE, "value irrelevant as bitmap address is 0", EXPFILL }},
        { &ei_spice_unknown_channel, { "spice.unknown_channel", PI_UNDECODED, PI_WARN, "Unknown channel - cannot dissect", EXPFILL }},
        { &ei_spice_common_cap_unknown, { "spice.common_cap.unknown", PI_PROTOCOL, PI_WARN, "Unknown common capability", EXPFILL }},
    };

    expert_module_t* expert_spice;

    /* Register the protocol name and description */
    proto_spice = proto_register_protocol("Spice protocol", "Spice", "spice");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_spice, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_spice = expert_register_protocol(proto_spice);
    expert_register_field_array(expert_spice, ei, array_length(ei));

}

void
proto_reg_handoff_spice(void)
{
    spice_handle = create_dissector_handle(dissect_spice, proto_spice);
    dissector_add_for_decode_as("tcp.port", spice_handle);
    heur_dissector_add("tcp", test_spice_protocol, "Spice over TCP", "spice_tcp", proto_spice, HEURISTIC_ENABLE);
    jpeg_handle  = find_dissector_add_dependency("image-jfif", proto_spice);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
