/* packet-spice.c
 * Routines for Spice protocol dissection
 * Copyright 2011, Yaniv Kaul <ykaul@redhat.com>
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
 *
 * This code is based on the protocol specification:
 *   http://www.spice-space.org/docs/spice_protocol.pdf
 *   and the source - git://cgit.freedesktop.org/spice/spice-protocol
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>

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

static dissector_handle_t spice_handle;

#define SPICE_CHANNEL_NONE      0
#define SPICE_CHANNEL_MAIN      1
#define SPICE_CHANNEL_DISPLAY   2
#define SPICE_CHANNEL_INPUTS    3
#define SPICE_CHANNEL_CURSOR    4
#define SPICE_CHANNEL_PLAYBACK  5
#define SPICE_CHANNEL_RECORD    6
#define SPICE_CHANNEL_TUNNEL    7
#define SPICE_CHANNEL_SMARTCARD 8

static const value_string channel_types_vs[] = {
    { SPICE_CHANNEL_NONE,      "Invalid" },
    { SPICE_CHANNEL_MAIN,      "Main" },
    { SPICE_CHANNEL_DISPLAY,   "Display" },
    { SPICE_CHANNEL_INPUTS,    "Inputs" },
    { SPICE_CHANNEL_CURSOR,    "Cursor" },
    { SPICE_CHANNEL_PLAYBACK,  "Playback" },
    { SPICE_CHANNEL_RECORD,    "Record" },
    { SPICE_CHANNEL_TUNNEL,    "Tunnel" },
    { SPICE_CHANNEL_SMARTCARD, "Smart Card" },
    { 0,  NULL }
};

/* common server messages */
#define SPICE_MIGRATE             1
#define SPICE_MIGRATE_DATA        2
#define SPICE_SET_ACK             3
#define SPICE_PING                4
#define SPICE_WAIT_FOR_CHANNELS   5
#define SPICE_DISCONNECTING       6
#define SPICE_NOTIFY              7

/* common client messages */

#define SPICEC_ACK_SYNC           1
#define SPICEC_ACK                2
#define SPICEC_PONG               3
#define SPICEC_MIGRATE_FLUSH_MARK 4
#define SPICEC_MIGRATE_DATA       5
#define SPICEC_DISCONNECTING      6

#define SPICE_FIRST_AVAIL_MESSAGE 101

static const value_string common_server_message_types[] = {
    { SPICE_MIGRATE,             "Server MIGRATE" },
    { SPICE_MIGRATE_DATA,        "Server MIGRATE_DATA" },
    { SPICE_SET_ACK,             "Server SET_ACK" },
    { SPICE_PING,                "Server PING" },
    { SPICE_WAIT_FOR_CHANNELS,   "Server WAIT_FOR_CHANNELS" },
    { SPICE_DISCONNECTING,       "Server DISCONNECTING" },
    { SPICE_NOTIFY,              "Server NOTIFY" },
    { 0, NULL }
};

static const value_string common_client_message_types[] = {
    { SPICEC_ACK_SYNC,           "Client ACK_SYNC" },
    { SPICEC_ACK,                "Client ACK" },
    { SPICEC_PONG,               "Client PONG" },
    { SPICEC_MIGRATE_FLUSH_MARK, "Client MIGRATE_FLUSH_MARK" },
    { SPICEC_MIGRATE_DATA,       "Client MIGRATE_DATA" },
    { SPICEC_DISCONNECTING,      "Client DISCONNECTING" },
    { 0, NULL }
};

#define sizeof_SpiceLinkHeader  16
#define sizeof_SpiceDataHeader  18
#define sizeof_SpiceMiniDataHeader  6

/* playback server channel messages */
#define SPICE_PLAYBACK_DATA    101
#define SPICE_PLAYBACK_MODE    102
#define SPICE_PLAYBACK_START   103
#define SPICE_PLAYBACK_STOP    104
#define SPICE_PLAYBACK_VOLUME  105
#define SPICE_PLAYBACK_MUTE    106

static const value_string playback_server_message_types[] = {
    { SPICE_PLAYBACK_DATA,       "Server PLAYBACK_DATA" },
    { SPICE_PLAYBACK_MODE,       "Server PLAYBACK_MODE" },
    { SPICE_PLAYBACK_START,      "Server PLAYBACK_START" },
    { SPICE_PLAYBACK_STOP,       "Server PLAYBACK_STOP" },
    { SPICE_PLAYBACK_VOLUME,     "Server PLAYBACK_VOLUME" },
    { SPICE_PLAYBACK_MUTE,       "Server PLAYBACK_MUTE" },
    { 0, NULL }
};

static const value_string playback_mode_vals[] = {
    { 0, "INVALID" },
    { 1, "RAW" },
    { 2, "CELT_0_5_1" },
    { 0, NULL }
};

#define SPICE_PLAYBACK_CAP_CELT_0_5_1 0
#define SPICE_PLAYBACK_CAP_VOLUME 1

#define SPICE_PLAYBACK_CAP_CELT_0_5_1_MASK (1 << SPICE_PLAYBACK_CAP_CELT_0_5_1)
#define SPICE_PLAYBACK_CAP_VOLUME_MASK (1 << SPICE_PLAYBACK_CAP_VOLUME) /* 0x2 */

/* main channel */

#define SPICE_MAIN_CAP_SEMI_SEAMLESS_MIGRATE 0
#define SPICE_MAIN_CAP_VM_NAME_UUID 1
#define SPICE_MAIN_CAP_SEMI_SEAMLESS_MIGRATE_MASK (1 << SPICE_MAIN_CAP_SEMI_SEAMLESS_MIGRATE)
#define SPICE_MAIN_CAP_VM_NAME_UUID_MASK (1 << SPICE_MAIN_CAP_VM_NAME_UUID)

/* main channel server messages */
#define SPICE_MAIN_MIGRATE_BEGIN        101
#define SPICE_MAIN_MIGRATE_CANCEL       102
#define SPICE_MAIN_INIT                 103
#define SPICE_MAIN_CHANNELS_LIST        104
#define SPICE_MAIN_MOUSE_MODE           105
#define SPICE_MAIN_MULTI_MEDIA_TIME     106
#define SPICE_MAIN_AGENT_CONNECTED      107
#define SPICE_MAIN_AGENT_DISCONNECTED   108
#define SPICE_MAIN_AGENT_DATA           109
#define SPICE_MAIN_AGENT_TOKEN          110
#define SPICE_MAIN_MIGRATE_SWITCH_HOST  111
#define SPICE_MAIN_MIGRATE_END          112
#define SPICE_MAIN_NAME                 113
#define SPICE_MAIN_UUID                 114

static const value_string main_server_message_types[] = {
    { SPICE_MAIN_MIGRATE_BEGIN,       "Server MIGRATE_BEGIN" },
    { SPICE_MAIN_MIGRATE_CANCEL,      "Server MIGRATE_CANCEL" },
    { SPICE_MAIN_INIT,                "Server INIT" },
    { SPICE_MAIN_CHANNELS_LIST,       "Server CHANNELS_LIST" },
    { SPICE_MAIN_MOUSE_MODE,          "Server MOUSE_MODE" },
    { SPICE_MAIN_MULTI_MEDIA_TIME,    "Server MULTI_MEDIA_TIME" },
    { SPICE_MAIN_AGENT_CONNECTED,     "Server AGENT_CONNECTED" },
    { SPICE_MAIN_AGENT_DISCONNECTED,  "Server AGENT_DISCONNECTED" },
    { SPICE_MAIN_AGENT_DATA,          "Server AGENT_DATA" },
    { SPICE_MAIN_AGENT_TOKEN,         "Server AGENT_TOKEN" },
    { SPICE_MAIN_MIGRATE_SWITCH_HOST, "Server MIGRATE_SWITCH_HOST" },
    { SPICE_MAIN_MIGRATE_END,         "Server MIGRATE_END" },
    { SPICE_MAIN_NAME,                "Server VM_NAME" },
    { SPICE_MAIN_UUID,                "Server VM_UUID" },
    { 0, NULL }
};

/* main channel client messages */
#define SPICEC_MAIN_RESERVED            101
#define SPICEC_MAIN_MIGRATE_READY       102
#define SPICEC_MAIN_MIGRATE_ERROR       103
#define SPICEC_MAIN_ATTACH_CHANNELS     104
#define SPICEC_MAIN_MOUSE_MODE_REQUEST  105
#define SPICEC_MAIN_AGENT_START         106
#define SPICEC_MAIN_AGENT_DATA          107
#define SPICEC_MAIN_AGENT_TOKEN         108

static const value_string main_client_message_types[] = {
    { SPICEC_MAIN_RESERVED,           "Client RESERVED" },
    { SPICEC_MAIN_MIGRATE_READY,      "Client MIGRATE_READY" },
    { SPICEC_MAIN_MIGRATE_ERROR,      "Client MIGRATE_ERROR" },
    { SPICEC_MAIN_ATTACH_CHANNELS,    "Client ATTACH_CHANNELS" },
    { SPICEC_MAIN_MOUSE_MODE_REQUEST, "Client MOUSE_MODE_REQUEST" },
    { SPICEC_MAIN_AGENT_START,        "Client AGENT_START" },
    { SPICEC_MAIN_AGENT_DATA,         "Client AGENT_DATA" },
    { SPICEC_MAIN_AGENT_TOKEN,        "Client AGENT_TOKEN" },
    { 0, NULL }
};

#define VD_AGENT_MOUSE_STATE            1
#define VD_AGENT_MONITORS_CONFIG        2
#define VD_AGENT_REPLY                  3
#define VD_AGENT_CLIPBOARD              4
#define VD_AGENT_DISPLAY_CONFIG         5
#define VD_AGENT_ANNOUNCE_CAPABILITIES  6
#define VD_AGENT_CLIPBOARD_GRAB         7
#define VD_AGENT_CLIPBOARD_REQUEST      8
#define VD_AGENT_CLIPBOARD_RELEASE      9

static const value_string agent_message_type[] = {
    { VD_AGENT_MOUSE_STATE,           "VD_AGENT_MOUSE_STATE" },
    { VD_AGENT_MONITORS_CONFIG,       "VD_AGENT_MONITORS_CONFIG" },
    { VD_AGENT_REPLY,                 "VD_AGENT_REPLY" },
    { VD_AGENT_CLIPBOARD,             "VD_AGENT_CLIPBOARD" },
    { VD_AGENT_DISPLAY_CONFIG,        "VD_AGENT_DISPLAY_CONFIG" },
    { VD_AGENT_ANNOUNCE_CAPABILITIES, "VD_AGENT_ANNOUNCE_CAPABILITIES" },
    { VD_AGENT_CLIPBOARD_GRAB,        "VD_AGENT_CLIPBOARD_GRAB" },
    { VD_AGENT_CLIPBOARD_REQUEST,     "VD_AGENT_CLIPBOARD_REQUEST" },
    { VD_AGENT_CLIPBOARD_RELEASE,     "VD_AGENT_CLIPBOARD_RELEASE" },
    { 0, NULL }
};

#define VD_AGENT_CLIPBOARD_NONE         0
#define VD_AGENT_CLIPBOARD_UTF8_TEXT    1
#define VD_AGENT_CLIPBOARD_IMAGE_PNG    2
#define VD_AGENT_CLIPBOARD_IMAGE_BMP    3
#define VD_AGENT_CLIPBOARD_IMAGE_TIFF   4
#define VD_AGENT_CLIPBOARD_IMAGE_JPG    5

static const value_string agent_clipboard_type[] = {
    { VD_AGENT_CLIPBOARD_NONE,      "NONE" },
    { VD_AGENT_CLIPBOARD_UTF8_TEXT, "UTF8_TEXT" },
    { VD_AGENT_CLIPBOARD_IMAGE_PNG, "IMAGE_PNG" },
    { VD_AGENT_CLIPBOARD_IMAGE_PNG, "IMAGE_BMP" },
    { VD_AGENT_CLIPBOARD_IMAGE_PNG, "IMAGE_TIFF" },
    { VD_AGENT_CLIPBOARD_IMAGE_PNG, "IMAGE_JPG" },
    { 0, NULL }
};
/* record channel */
/* record channel server messages */
#define SPICE_RECORD_START            101
#define SPICE_RECORD_STOP             102

static const value_string record_server_message_types[] = {
    { SPICE_RECORD_START, "Server RECORD_START" },
    { SPICE_RECORD_STOP,  "Server RECORD_STOP" },
    { 0, NULL }
};

/* record channel client messages */
#define SPICEC_RECORD_DATA        101
#define SPICEC_RECORD_MODE        102
#define SPICEC_RECORD_START_MARK  103

static const value_string record_client_message_types[] = {
    { SPICEC_RECORD_DATA,       "Client RECORD_DATA" },
    { SPICEC_RECORD_MODE,       "Client RECORD_MODE" },
    { SPICEC_RECORD_START_MARK, "Client RECORD_START_MARK" },
    { 0, NULL }
};

/* record channel capabilities - same as playback */
#define SPICE_RECORD_CAP_CELT_0_5_1 0

#define SPICE_RECORD_CAP_CELT_0_5_1_MASK (1 << SPICE_RECORD_CAP_CELT_0_5_1)

/* display channel */
/* display channel server messages */
#define SPICE_DISPLAY_MODE                  101
#define SPICE_DISPLAY_MARK                  102
#define SPICE_DISPLAY_RESET                 103
#define SPICE_DISPLAY_COPY_BITS             104
#define SPICE_DISPLAY_INVAL_LIST            105
#define SPICE_DISPLAY_INVAL_ALL_PIXMAPS     106
#define SPICE_DISPLAY_INVAL_PALETTE         107
#define SPICE_DISPLAY_INVAL_ALL_PALETTES    108
#define SPICE_DISPLAY_STREAM_CREATE         122
#define SPICE_DISPLAY_STREAM_DATA           123
#define SPICE_DISPLAY_STREAM_CLIP           124
#define SPICE_DISPLAY_STREAM_DESTROY        125
#define SPICE_DISPLAY_STREAM_DESTROY_ALL    126
#define SPICE_DISPLAY_DRAW_FILL             302
#define SPICE_DISPLAY_DRAW_OPAQUE           303
#define SPICE_DISPLAY_DRAW_COPY             304
#define SPICE_DISPLAY_DRAW_BLEND            305
#define SPICE_DISPLAY_DRAW_BLACKNESS        306
#define SPICE_DISPLAY_DRAW_WHITENESS        307
#define SPICE_DISPLAY_DRAW_INVERS           308
#define SPICE_DISPLAY_DRAW_ROP3             309
#define SPICE_DISPLAY_DRAW_STROKE           310
#define SPICE_DISPLAY_DRAW_TEXT             311
#define SPICE_DISPLAY_DRAW_TRANSPARENT      312
#define SPICE_DISPLAY_DRAW_ALPHA_BLEND      313
#define SPICE_DISPLAY_DRAW_SURFACE_CREATE   314
#define SPICE_DISPLAY_DRAW_SURFACE_DESTROY  315

static const value_string display_server_message_types[] = {
    { SPICE_DISPLAY_MODE,                 "MODE" },
    { SPICE_DISPLAY_MARK,                 "MARK" },
    { SPICE_DISPLAY_RESET,                "RESET" },
    { SPICE_DISPLAY_COPY_BITS,            "COPY_BITS" },
    { SPICE_DISPLAY_INVAL_LIST,           "INVAL_LIST" },
    { SPICE_DISPLAY_INVAL_ALL_PIXMAPS,    "INVAL_ALL_PIXMAPS" },
    { SPICE_DISPLAY_INVAL_PALETTE,        "INVAL_PALETTE" },
    { SPICE_DISPLAY_INVAL_ALL_PALETTES,   "INVAL_ALL_PALETTES" },
    { SPICE_DISPLAY_STREAM_CREATE,        "STREAM_CREATE" },
    { SPICE_DISPLAY_STREAM_DATA,          "STREAM_DATA"    },
    { SPICE_DISPLAY_STREAM_CLIP,          "STREAM_CLIP"    },
    { SPICE_DISPLAY_STREAM_DESTROY,       "STREAM_DESTROY"    },
    { SPICE_DISPLAY_STREAM_DESTROY_ALL,   "STREAM_DESTROY_ALL"    },
    { SPICE_DISPLAY_DRAW_FILL,            "DRAW_FILL"    },
    { SPICE_DISPLAY_DRAW_OPAQUE,          "DRAW_OPAQUE" },
    { SPICE_DISPLAY_DRAW_COPY,            "DRAW_COPY" },
    { SPICE_DISPLAY_DRAW_BLEND,           "DRAW_BLEND" },
    { SPICE_DISPLAY_DRAW_BLACKNESS,       "DRAW_BLACKNESS" },
    { SPICE_DISPLAY_DRAW_WHITENESS,       "DRAW_WHITENESS" },
    { SPICE_DISPLAY_DRAW_INVERS,          "DRAW_INVERS" },
    { SPICE_DISPLAY_DRAW_ROP3,            "DRAW_ROP3" },
    { SPICE_DISPLAY_DRAW_STROKE,          "DRAW_STROKE" },
    { SPICE_DISPLAY_DRAW_TEXT,            "DRAW_TEXT" },
    { SPICE_DISPLAY_DRAW_TRANSPARENT,     "DRAW_TRANSPARENT" },
    { SPICE_DISPLAY_DRAW_ALPHA_BLEND,     "DRAW_ALPHA_BLEND" },
    { SPICE_DISPLAY_DRAW_SURFACE_CREATE,  "DRAW_SURFACE_CREATE" },
    { SPICE_DISPLAY_DRAW_SURFACE_DESTROY, "DRAW_SURFACE_DESTROY" },
    { 0, NULL }
};


#define TOP_DOWN    1
static const value_string stream_flags[] = {
    { 0,        "None" },
    { TOP_DOWN, "TOP DOWN" },
    { 0, NULL }
};

#define MJPEG    1
static const value_string stream_codec_types[] = {
    { MJPEG, "MJPEG" },
    { 0, NULL }
};


/* display channel client messages */
#define SPICEC_DISPLAY_INIT    101
static const value_string display_client_message_types[] = {
    { SPICEC_DISPLAY_INIT, "Client DISPLAY INIT" },
    { 0, NULL }
};

#define sizeof_RedcDisplayInit 14

/* cursor channel */
/* cursor channel server messages */
#define SPICE_CURSOR_INIT         101
#define SPICE_CURSOR_RESET        102
#define SPICE_CURSOR_SET          103
#define SPICE_CURSOR_MOVE         104
#define SPICE_CURSOR_HIDE         105
#define SPICE_CURSOR_TRAIL        106
#define SPICE_CURSOR_INVAL_ONE    107
#define SPICE_CURSOR_INVAL_ALL    108

static const value_string cursor_visible_vs[] = {
    { 1, "Visible" },
    { 0, "Invisible" },
    { 0, NULL }
};

static const value_string cursor_server_message_types[] = {
    { SPICE_CURSOR_INIT,      "Server CURSOR_INIT" },
    { SPICE_CURSOR_RESET,     "Server CURSOR_RESET" },
    { SPICE_CURSOR_SET,       "Server CURSOR_SET" },
    { SPICE_CURSOR_MOVE,      "Server CURSOR_MOVE" },
    { SPICE_CURSOR_HIDE,      "Server CURSOR_HIDE" },
    { SPICE_CURSOR_TRAIL,     "Server CURSOR_TRAIL" },
    { SPICE_CURSOR_INVAL_ONE, "Server CURSOR_INVAL_ONE" },
    { SPICE_CURSOR_INVAL_ALL, "Server CURSOR_INVAL_ALL" },
    { 0, NULL }
};

/* cursor channel client messages */
static const value_string cursor_client_message_types[] = {
    { 0, NULL }
};

#define    SPICE_CURSOR_FLAGS_NONE       1
#define    SPICE_CURSOR_FLAGS_CACHE_ME   2
#define    SPICE_CURSOR_FLAGS_FROM_CACHE 4

static const value_string cursor_flags_vs[] = {
    { SPICE_CURSOR_FLAGS_NONE,       "NONE" },
    { SPICE_CURSOR_FLAGS_CACHE_ME,   "CACHE_ME" },
    { SPICE_CURSOR_FLAGS_FROM_CACHE, "FROM_CACHE" },
    { 0, NULL }
};

#define SPICE_CURSOR_TYPE_ALPHA   0
#define SPICE_CURSOR_TYPE_MONO    1
#define SPICE_CURSOR_TYPE_COLOR4  2
#define SPICE_CURSOR_TYPE_COLOR8  3
#define SPICE_CURSOR_TYPE_COLOR16 4
#define SPICE_CURSOR_TYPE_COLOR24 5
#define SPICE_CURSOR_TYPE_COLOR32 6

static const value_string cursor_type_vs[] = {
    { SPICE_CURSOR_TYPE_ALPHA,   "CURSOR_TYPE_ALPHA" },
    { SPICE_CURSOR_TYPE_MONO,    "CURSOR_TYPE_MONO" },
    { SPICE_CURSOR_TYPE_COLOR4,  "CURSOR_TYPE_COLOR4" },
    { SPICE_CURSOR_TYPE_COLOR8,  "CURSOR_TYPE_COLOR8" },
    { SPICE_CURSOR_TYPE_COLOR16, "CURSOR_TYPE_COLOR16" },
    { SPICE_CURSOR_TYPE_COLOR24, "CURSOR_TYPE_COLOR24" },
    { SPICE_CURSOR_TYPE_COLOR32, "CURSOR_TYPE_COLOR32" },
    { 0, NULL }
};

typedef struct {
    guint64 unique;
    guint8 type;
    guint16 width;
    guint16 height;
    guint16 hot_spot_x;
    guint16 hot_spot_y;
} CursorHeader;

#define sizeof_CursorHeader 17

#define SPICE_MOUSE_MODE_SERVER 1
#define SPICE_MOUSE_MODE_CLIENT 2

static const value_string spice_mouse_modes_vs[] = {
    { SPICE_MOUSE_MODE_SERVER, "Server mouse" },
    { SPICE_MOUSE_MODE_CLIENT, "Client mouse" },
    { 0, NULL }
};

static const value_string spice_agent_vs[] = {
    { 0, "Disconnected" },
    { 1, "Connected" },
    { 0, NULL }
};

#define SPICE_NOTIFY_SEVERITY_INFO  0
#define SPICE_NOTIFY_SEVERITY_WARN  1
#define SPICE_NOTIFY_SEVERITY_ERROR 2

static const value_string spice_severity_vs[] = {
    { SPICE_NOTIFY_SEVERITY_INFO,  "Info" },
    { SPICE_NOTIFY_SEVERITY_WARN,  "Warning" },
    { SPICE_NOTIFY_SEVERITY_ERROR, "Error" },
    { 0, NULL }
};

#define SPICE_NOTIFY_VISIBILITY_LOW    0
#define SPICE_NOTIFY_VISIBILITY_MEDIUM 1
#define SPICE_NOTIFY_VISIBILITY_HIGH   2

static const value_string spice_visibility_vs[] = {
    { SPICE_NOTIFY_VISIBILITY_LOW,    "Low visibility" },
    { SPICE_NOTIFY_VISIBILITY_MEDIUM, "Medium visibility" },
    { SPICE_NOTIFY_VISIBILITY_HIGH,   "High visibility" },
    { 0, NULL }
};

static const value_string spice_error_codes_vs[] = {
    { 0, "OK"                     },
    { 1, "ERROR"                  },
    { 2, "INVALID_MAGIC"          },
    { 3, "INVALID_DATA"           },
    { 4, "VERSION_MISMATCH"       },
    { 5, "NEED_SECURED"           },
    { 6, "NEED_UNSECURED"         },
    { 7, "PERMISSION_DENIED"      },
    { 8, "BAD_CONNECTION_ID"      },
    { 9, "CHANNEL_NOT_AVAILABLE"  },
    { 0,  NULL }
};

/* Inputs channel */
#define SPICEC_INPUTS_KEY_DOWN        101
#define SPICEC_INPUTS_KEY_UP          102
#define SPICEC_INPUTS_KEY_MODIFIERS   103
#define SPICEC_INPUTS_MOUSE_MOTION    111
#define SPICEC_INPUTS_MOUSE_POSITION  112
#define SPICEC_INPUTS_MOUSE_PRESS     113
#define SPICEC_INPUTS_MOUSE_RELEASE   114
#define SPICE_INPUTS_INIT             101
#define SPICE_INPUTS_KEY_MODIFIERS    102
#define SPICE_INPUTS_MOUSE_MOTION_ACK 111

static const value_string inputs_client_message_types[] = {
    { SPICEC_INPUTS_KEY_DOWN,        "Client KEY_DOWN" },
    { SPICEC_INPUTS_KEY_UP,          "Client INPUTS_KEY_UP" },
    { SPICEC_INPUTS_KEY_MODIFIERS,   "Client KEY_MODIFIERS" },
    { SPICEC_INPUTS_MOUSE_MOTION,    "Client MOUSE_MOTION" },
    { SPICEC_INPUTS_MOUSE_POSITION,  "Client MOUSE_POSITION" },
    { SPICEC_INPUTS_MOUSE_PRESS,     "Client MOUSE_PRESS" },
    { SPICEC_INPUTS_MOUSE_RELEASE,   "Client MOUSE_RELEASE" },
    { 0, NULL }
};

static const value_string inputs_server_message_types[] = {
    { SPICE_INPUTS_INIT,             "Server INPUTS_INIT" },
    { SPICE_INPUTS_KEY_MODIFIERS,    "Server KEY_MODIFIERS" },
    { SPICE_INPUTS_MOUSE_MOTION_ACK, "Server MOUSE_MOTION_ACK" },
    { 0, NULL }
};

#define SPICE_SCROLL_LOCK_MODIFIER 1
#define SPICE_NUM_LOCK_MODIFIER    2
#define SPICE_CAPS_LOCK_MODIFIER   4

static const value_string input_modifiers_types[] = {
    { 0, "None" },
    { SPICE_SCROLL_LOCK_MODIFIER, "Scroll lock" },
    { SPICE_NUM_LOCK_MODIFIER,    "Num lock" },
    { SPICE_CAPS_LOCK_MODIFIER,   "CAPS lock" },
    { 0, NULL }
};

/* This structure will be tied to each conversation. */
typedef struct {
    guint32 connection_id;
    guint32 num_channel_caps;
    guint32 destport;
    guint32 client_auth;
    guint32 server_auth;
    guint32 auth_selected;
    spice_session_state_e next_state;
    guint8 channel_type;
    guint8 channel_id;
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
#define CLIP_TYPE_NONE    0
#define CLIP_TYPE_RECTS   1

static const value_string clip_types_vs[] = {
    { CLIP_TYPE_NONE,  "NONE" },
    { CLIP_TYPE_RECTS, "RECTS" },
    { 0, NULL }
};

typedef struct {
    guint8 type;
} Clip;
#define sizeof_Clip 1 /* This is correct only if the type is none. If it is RECTS, this is followed by: */

typedef struct {
    guint32 num_rects; /* this is followed by RECT rects[num_rects] */
} ClipRects;


typedef struct {
    guint32 surface_id;
    SpiceRect bounding_box;
    Clip clip;
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

#define    SPICE_BRUSH_TYPE_NONE    0
#define    SPICE_BRUSH_TYPE_SOLID   1
#define    SPICE_BRUSH_TYPE_PATTERN 2

static const value_string brush_types_vs[] = {
    { SPICE_BRUSH_TYPE_NONE,    "NONE" },
    { SPICE_BRUSH_TYPE_SOLID,   "SOLID" },
    { SPICE_BRUSH_TYPE_PATTERN, "PATTERN" },
    { 0, NULL }
};

typedef struct {
    guint64 image;
    point32_t position;
} Pattern;

#define sizeof_Pattern 16

typedef struct {
    guint8 type;
    union {
        guint32 color;
        Pattern patten;
    };
} Brush;

#define sizeof_Brush 17 /* for pattern */

static const value_string Mask_flags_vs[] = {
    { 0, "MASK_FLAG_INVERS" },
    { 0, NULL }
};

typedef struct {
    guint8 flags;
    point32_t position;
    guint32 bitmap;
} Mask;

#define sizeof_Mask 13

static const value_string scale_mode_vs[] = {
    { 0, "IMAGE_SCALE_INTERPOLATE" },
    { 1, "IMAGE_SCALE_NEAREST" },
    { 0, NULL }
};

typedef struct {
    guint64 id;
    guint8    type;
    guint8    flag;
    guint32    width;
    guint32 height;
} ImageDescriptor;

#define sizeof_ImageDescriptor 18

#define IMAGE_TYPE_BITMAP                 0
#define IMAGE_TYPE_QUIC                   1
#define IMAGE_TYPE_RESERVED               2
#define IMAGE_TYPE_LZ_PLT               100
#define IMAGE_TYPE_LZ_RGB               101
#define IMAGE_TYPE_GLZ_RGB              102
#define IMAGE_TYPE_FROM_CACHE           103
#define IMAGE_TYPE_SURFACE              104
#define IMAGE_TYPE_JPEG                 105
#define IMAGE_TYPE_FROM_CACHE_LOSSLESS  106
#define IMAGE_TYPE_ZLIB_GLZ_RGB         107
#define IMAGE_TYPE_JPEG_ALPHA           108

static const value_string image_type_vs[] = {
    { IMAGE_TYPE_BITMAP,              "BITMAP" },
    { IMAGE_TYPE_QUIC,                "QUIC" },
    { IMAGE_TYPE_LZ_PLT,              "LZ_PLT" },
    { IMAGE_TYPE_LZ_RGB,              "LZ_RGB" },
    { IMAGE_TYPE_GLZ_RGB,             "GLZ_RGB" },
    { IMAGE_TYPE_FROM_CACHE,          "FROM_CACHE" },
    { IMAGE_TYPE_SURFACE,             "SURFACE" },
    { IMAGE_TYPE_JPEG,                "JPEG" },
    { IMAGE_TYPE_FROM_CACHE_LOSSLESS, "FROM_CACHE_LOSSLESS" },
    { IMAGE_TYPE_ZLIB_GLZ_RGB,        "ZLIB_GLZ_RGB" },
    { IMAGE_TYPE_JPEG_ALPHA,          "JPEG_ALPHA" },
    { 0, NULL }
};

/* FIXME - those flags should be bit-wise, I guess! */
#define IMAGE_FLAGS_CACHE_ME      (1 << 0)
#define IMAGE_FLAGS_HIGH_BITS_SET (1 << 1)
#define IMAGE_FLAGS_REPLACE_ME    (1 << 2)
static const value_string image_flags_vs[] = {
    { 0,                         "None" },
    { IMAGE_FLAGS_CACHE_ME,      "CACHE_ME" },
    { IMAGE_FLAGS_HIGH_BITS_SET, "HIGH_BITS_SET" },
    { IMAGE_FLAGS_REPLACE_ME,    "REPLACE_ME" },
    { 0, NULL }
};

static const value_string rop_descriptor_vs[] = {
    { (1 << 0), "SPICE_ROPD_INVERS_SRC" },
    { (1 << 1), "SPICE_ROPD_INVERS_BRUSH" },
    { (1 << 2), "SPICE_ROPD_INVERS_DEST" },
    { (1 << 3), "SPICE_ROPD_OP_PUT" },
    { (1 << 4), "SPICE_ROPD_OP_OR" },
    { (1 << 5), "SPICE_ROPD_OP_AND" },
    { (1 << 6), "SPICE_ROPD_OP_XOR" },
    { (1 << 7), "SPICE_ROPD_OP_BLACKNESS" },
    { (1 << 8), "SPICE_ROPD_OP_WHITENESS" },
    { (1 << 9), "SPICE_ROPD_OP_INVERS" },
    { (1 << 10), "SPICE_ROPD_INVERS_RES" },
    { 0, NULL }
};

#define QUIC_IMAGE_TYPE_INVALID 0
#define QUIC_IMAGE_TYPE_GRAY    1
#define QUIC_IMAGE_TYPE_RGB16   2
#define QUIC_IMAGE_TYPE_RGB24   3
#define QUIC_IMAGE_TYPE_RGB32   4
#define QUIC_IMAGE_TYPE_RGBA    5

static const value_string quic_type_vs[] = {
    { QUIC_IMAGE_TYPE_INVALID, "INVALID" },
    { QUIC_IMAGE_TYPE_GRAY,    "GRAY" },
    { QUIC_IMAGE_TYPE_RGB16,   "RGB16" },
    { QUIC_IMAGE_TYPE_RGB24,   "RGB24" },
    { QUIC_IMAGE_TYPE_RGB32,   "RGB32" },
    { QUIC_IMAGE_TYPE_RGBA,    "RGBA" },
    { 0, NULL }
};

#define LZ_IMAGE_TYPE_INVALID  0
#define LZ_IMAGE_TYPE_PLT1_LE  1
#define LZ_IMAGE_TYPE_PLT1_BE  2      /* PLT stands for palette */
#define LZ_IMAGE_TYPE_PLT4_LE  3
#define LZ_IMAGE_TYPE_PLT4_BE  4
#define LZ_IMAGE_TYPE_PLT8     5
#define LZ_IMAGE_TYPE_RGB16    6
#define LZ_IMAGE_TYPE_RGB24    7
#define LZ_IMAGE_TYPE_RGB32    8
#define LZ_IMAGE_TYPE_RGBA     9
#define LZ_IMAGE_TYPE_XXXA    10
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

#define PIXMAP_FORMAT_1BIT_LE 1
#define PIXMAP_FORMAT_1BIT_BE 2
#define PIXMAP_FORMAT_4BIT_LE 3
#define PIXMAP_FORMAT_4BIT_BE 4
#define PIXMAP_FORMAT_8BIT    5
#define PIXMAP_FORMAT_16BIT   6
#define PIXMAP_FORMAT_24BIT   7
#define PIXMAP_FORMAT_32BIT   8
#define PIXMAP_FORMAT_RGBA    9

static const value_string Pixmap_types_vs[] = {
    { PIXMAP_FORMAT_1BIT_LE, "1BIT_LE" },
    { PIXMAP_FORMAT_1BIT_BE, "1BIT_BE" },
    { PIXMAP_FORMAT_4BIT_LE, "4BIT_LE" },
    { PIXMAP_FORMAT_4BIT_BE, "4BIT_BE" },
    { PIXMAP_FORMAT_8BIT,    "8BIT" },
    { PIXMAP_FORMAT_16BIT,   "16BIT" },
    { PIXMAP_FORMAT_24BIT,   "24BIT" },
    { PIXMAP_FORMAT_32BIT,   "32BIT" },
    { PIXMAP_FORMAT_RGBA,    "RGBA" },
    { 0, NULL }
};


#define SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION 0
#define SPICE_COMMON_CAP_AUTH_SPICE              1
#define SPICE_COMMON_CAP_AUTH_SASL               2
#define SPICE_COMMON_CAP_MINI_HEADER             3

#define SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION_MASK (1 << SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION) /* 0x1 */
#define SPICE_COMMON_CAP_AUTH_SPICE_MASK              (1 << SPICE_COMMON_CAP_AUTH_SPICE)              /* 0x2 */
#define SPICE_COMMON_CAP_AUTH_SASL_MASK               (1 << SPICE_COMMON_CAP_AUTH_SASL)               /* 0x4 */
#define SPICE_COMMON_CAP_MINI_HEADER_MASK             (1 << SPICE_COMMON_CAP_MINI_HEADER)

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
static gint ett_inputs_client = -1;
static gint ett_rectlist = -1;
static gint ett_inputs_server = -1;
static gint ett_record_client = -1;
static gint ett_main_client = -1;
static gint ett_spice_agent = -1;
static gint ett_auth_tree = -1;
static gint ett_cap_tree = -1;
static int proto_spice = -1;
static int hf_spice_magic  = -1;
static int hf_major_version  = -1;
static int hf_minor_version  = -1;
static int hf_message_size  = -1;
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
static int hf_main_cap_semi_migrate = -1;
static int hf_main_cap_vm_name_uuid = -1;
static int hf_display_cap = -1;
static int hf_inputs_cap = -1;
static int hf_cursor_cap = -1;
static int hf_common_cap_byte1 = -1;
static int hf_common_cap_auth_select = -1;
static int hf_common_cap_auth_spice = -1;
static int hf_common_cap_auth_sasl = -1;
static int hf_common_cap_mini_header = -1;
static int hf_playback_record_mode_timstamp = -1;
static int hf_playback_record_mode = -1;
static int hf_red_set_ack_generation = -1;
static int hf_red_set_ack_window = -1;
static int hf_Clip_type = -1;
static int hf_Mask_flag = -1;
static int hf_Mask_bitmap = -1;
static int hf_display_rop_descriptor = -1;
static int hf_display_scale_mode = -1;
static int hf_display_stream_id = -1;
static int hf_display_stream_width = -1;
static int hf_display_stream_height = -1;
static int hf_display_stream_src_width = -1;
static int hf_display_stream_src_height = -1;
static int hf_display_stream_data_size = -1;
static int hf_display_stream_codec_type = -1;
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
static int hf_keyboard_bits = -1;
static int hf_rectlist_size = -1;
static int hf_session_id = -1;
static int hf_display_channels_hint = -1;
static int hf_supported_mouse_modes = -1;
static int hf_current_mouse_mode = -1;
static int hf_agent_connected = -1;
static int hf_agent_tokens = -1;
static int hf_agent_protocol = -1;
static int hf_agent_type = -1;
static int hf_agent_opaque = -1;
static int hf_agent_size = -1;
static int hf_agent_token = -1;
static int hf_agent_clipboard_selection = -1;
static int hf_agent_clipboard_type = -1;
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
static int hf_playback_cap_celt = -1;
static int hf_playback_cap_volume = -1;
static int hf_record_cap_celt = -1;
static int hf_vm_uuid = -1;
static int hf_vm_name = -1;

static dissector_handle_t jpeg_handle;

static guint32
dissect_ID(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{
    const guint32 id = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "ID: %u (0x%x)", id, id);
    return id;
}

/* returns the pixmap size in bytes */
static guint32
dissect_Pixmap(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *Pixmap_tree;
    guint32     PixmapSize;
    guint32     strides, height, pallete_ptr;

    ti = proto_tree_add_text(tree, tvb, offset, 0, "Pixmap"); /* size is fixed later */
    Pixmap_tree = proto_item_add_subtree(ti, ett_Pixmap);
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
    proto_tree_add_text(Pixmap_tree, tvb, offset, PixmapSize, "Pixmap pixels (%d bytes)", PixmapSize);
    offset += PixmapSize;
    /* FIXME: compute pallete size */
    proto_tree_add_text(Pixmap_tree, tvb, offset, 0, "Pallete (offset from message start - %u)", pallete_ptr);
    /*TODO: complete pixmap dissection */

    return PixmapSize + 18;
}

/* returns the type of cursor */
static guint8
dissect_CursorHeader(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint16 *width, guint16 *height)
{
    proto_item   *ti   = NULL;
    proto_tree   *CursorHeader_tree;
    const guint8  type = tvb_get_guint8(tvb, offset + 8);

    *width  = tvb_get_letohs(tvb, offset + 8 + 1);
    *height = tvb_get_letohs(tvb, offset + 8 + 1 + 2);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof_CursorHeader, "Cursor Header");
        CursorHeader_tree = proto_item_add_subtree(ti, ett_cursor_header);
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
    proto_item    *ti          = NULL;
    proto_tree    *RedCursor_tree;
    guint8         type;
    guint16        height, width;
    guint32        init_offset = offset, data_size = 0;
    const guint16  flags       = tvb_get_letohs(tvb, offset);

    ti = proto_tree_add_text(tree, tvb, offset, 2, "RedCursor"); /* FIXME - fix size if flag is not NONE */
    RedCursor_tree = proto_item_add_subtree(ti, ett_RedCursor);

    proto_tree_add_item(RedCursor_tree, hf_cursor_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    if (flags == SPICE_CURSOR_FLAGS_NONE) {
        return 2;
    }

    offset += 2;

    type = dissect_CursorHeader(tvb, RedCursor_tree, offset, &width, &height);
    offset += sizeof_CursorHeader;


    if ((width == 0 || height == 0) || flags == SPICE_CURSOR_FLAGS_FROM_CACHE) {
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
        proto_tree_add_text(RedCursor_tree, tvb, offset, data_size, "Cursor data (%u bytes)", data_size);
    } else {
        proto_tree_add_text(RedCursor_tree, tvb, offset, -1, "Cursor data");
    }
    offset += data_size;


    return (offset - init_offset);
}

/* returns the image type, needed for later */
static guint8
dissect_ImageDescriptor(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item   *ti   = NULL;
    proto_tree   *ImageDescriptor_tree;
    const guint8  type = tvb_get_guint8(tvb, offset + 8);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof_ImageDescriptor, "Image Descriptor");
        ImageDescriptor_tree = proto_item_add_subtree(ti, ett_imagedesc);

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
    proto_item    *ti       = NULL;
    proto_tree    *ImageQuic_tree;
    const guint32  QuicSize = tvb_get_letohl(tvb, offset);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, QuicSize + 4, "QUIC Image");
        ImageQuic_tree = proto_item_add_subtree(ti, ett_imageQuic);

        proto_tree_add_text(ImageQuic_tree, tvb, offset, 4, "QUIC image size: %u bytes", QuicSize);
        offset += 4;
        proto_tree_add_text(ImageQuic_tree, tvb, offset, 4, "QUIC magic (QUIC)");
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
        proto_tree_add_text(ImageQuic_tree, tvb, offset, QuicSize - 20, "QUIC compressed image data (%u bytes)", QuicSize);
    }

    return QuicSize + 4;
}

static guint32
dissect_ImageLZ_common_header(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{

    proto_tree_add_text(tree, tvb, offset, 4, "LZ magic (\"  ZL\")");
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
            proto_tree_add_text(tree, tvb, offset , size - 29, "LZ_RGB compressed image data (%u bytes)", size - 29);
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
            proto_tree_add_text(tree, tvb, offset, 4, "topdown flag: %d", tvb_get_ntohl(tvb, offset));
            offset += 4;
            proto_tree_add_text(tree, tvb, offset, 12, "FIXME: 12 unknown bytes");
            offset += 8;
            break;
        default:
            g_warning("dissecting default LZ image. type & 0xf: %d", type & 0xf);
            proto_tree_add_item(tree, hf_LZ_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_stride, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_LZ_RGB_dict_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_text(tree, tvb, offset , size - 30, "LZ_RGB compressed image data (%u bytes)", size - 30);
            break;
    }
    return offset;
}

#if 0
static guint32
dissect_ImageLZ_JPEG(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item    *ti          = NULL;
    proto_tree    *LZ_JPEG_tree;
    const guint32  LZ_JPEGSize = tvb_get_letohl(tvb, offset);

    ti = proto_tree_add_text(tree, tvb, offset, LZ_JPEGSize + 4, "LZ_JPEG Image");
    LZ_JPEG_tree = proto_item_add_subtree(ti, ett_LZ_JPEG);
    proto_tree_add_text(LZ_JPEG_tree, tvb, offset, 4, "LZ JPEG image size: %u bytes", LZ_JPEGSize);
    offset += 4;
    offset += dissect_ImageLZ_common_header(tvb, LZ_JPEG_tree, offset);

    return offset;
}
#endif

static guint32
dissect_ImageGLZ_RGB(tvbuff_t *tvb, proto_tree *tree, guint32 offset, const guint32 size)
{
    proto_item *ti = NULL;
    proto_tree *GLZ_RGB_tree;
    guint32     GLZ_RGBSize;

    if (size == 0) { /* if no size was passed to us, need to fetch it. Otherwise, we already have it from the callee */
        GLZ_RGBSize = tvb_get_letohl(tvb, offset);
        ti = proto_tree_add_text(tree, tvb, offset, GLZ_RGBSize + 4, "GLZ_RGB Image");
        GLZ_RGB_tree = proto_item_add_subtree(ti, ett_GLZ_RGB);
        proto_tree_add_text(GLZ_RGB_tree, tvb, offset, 4, "GLZ RGB image size: %u bytes", GLZ_RGBSize);
        offset += 4;
    } else {
        GLZ_RGBSize = size;
        ti = proto_tree_add_text(tree, tvb, offset, GLZ_RGBSize, "GLZ_RGB Image");
        GLZ_RGB_tree = proto_item_add_subtree(ti, ett_GLZ_RGB);
    }

    dissect_ImageLZ_common(tvb, GLZ_RGB_tree, offset, FALSE, GLZ_RGBSize);

    return GLZ_RGBSize + 4;
}

static guint32
dissect_ImageLZ_RGB(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item    *ti         = NULL;
    proto_tree    *LZ_RGB_tree;
    const guint32  LZ_RGBSize = tvb_get_letohl(tvb, offset);

    ti = proto_tree_add_text(tree, tvb, offset, LZ_RGBSize + 4, "LZ_RGB Image");
    LZ_RGB_tree = proto_item_add_subtree(ti, ett_LZ_RGB);
    proto_tree_add_text(LZ_RGB_tree, tvb, offset, 4, "LZ RGB image size: %u bytes", LZ_RGBSize);
    offset += 4;

    dissect_ImageLZ_common(tvb, LZ_RGB_tree, offset, TRUE, LZ_RGBSize);

    return LZ_RGBSize + 4;
}

static guint32
dissect_ImageLZ_PLT(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *LZ_PLT_tree;
    guint32     LZ_PLTSize, pal_size;

    const guint32 current_offset = offset;

    LZ_PLTSize = tvb_get_letohl(tvb, offset + 1); /* for some reason, it reports two extra bytes */
    ti = proto_tree_add_text(tree, tvb, offset, (LZ_PLTSize - 2)+ 1 + 4 + 4 + 8 + 4 + 4 + 4 + 4 + 4, "LZ_PLT Image");
    LZ_PLT_tree = proto_item_add_subtree(ti, ett_LZ_PLT);

    proto_tree_add_text(LZ_PLT_tree, tvb, offset, 1, "LZ_PLT Flag"); /* TODO: dissect */
    offset += 1;
    proto_tree_add_text(LZ_PLT_tree, tvb, offset, 4, "LZ PLT image size: %u bytes (2 extra bytes?)", LZ_PLTSize);
    offset += 4;

    pal_size = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(LZ_PLT_tree, tvb, offset, 4, "pallete offset: %u bytes", pal_size); /* TODO: not sure it's correct */
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
    proto_tree_add_text(LZ_PLT_tree, tvb, offset, 4, "topdown flag: %d", tvb_get_ntohl(tvb, offset));
    offset += 4;
    proto_tree_add_text(LZ_PLT_tree, tvb, offset, (LZ_PLTSize - 2), "LZ_PLT data (%u bytes)", (LZ_PLTSize - 2));
    offset += (LZ_PLTSize - 2);
    /* TODO:
    * proto_tree_add_text(LZ_PLT_tree, tvb, offset, pal_size, "palette (%u bytes)" , pal_size);
    *  offset += pal_size;
    */
    return offset - current_offset;
}



static guint32
dissect_ImageJPEG_Alpha(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *JPEG_tree;
    tvbuff_t   *jpeg_tvb;
    guint32     JPEG_Size, Data_Size;

    /*TODO: const guint8 flags = tvb_get_guint8(tvb, offset); dissect and present */
    offset += 1;

    JPEG_Size = tvb_get_letohl(tvb, offset);
    offset += 4;

    Data_Size = tvb_get_letohl(tvb, offset);
    offset += 4;

    ti = proto_tree_add_text(tree, tvb, offset - 9, Data_Size + 9, "RGB JPEG Image, Alpha channel (%u bytes)", Data_Size);
    JPEG_tree = proto_item_add_subtree(ti, ett_JPEG);

    jpeg_tvb = tvb_new_subset(tvb, offset, JPEG_Size, JPEG_Size);
    call_dissector(jpeg_handle, jpeg_tvb, pinfo, JPEG_tree);
    offset += JPEG_Size;

    dissect_ImageLZ_common(tvb, tree, offset, TRUE, JPEG_Size);

    return Data_Size + 9;
}

static guint32
dissect_ImageJPEG(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, const guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *JPEG_tree;
    tvbuff_t   *jpeg_tvb;

    const guint32 JPEG_Size = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, JPEG_Size + 4, "JPEG Image (%u bytes)", JPEG_Size);
    JPEG_tree = proto_item_add_subtree(ti, ett_JPEG);

    jpeg_tvb = tvb_new_subset(tvb, offset + 4, JPEG_Size, JPEG_Size);
    call_dissector(jpeg_handle, jpeg_tvb, pinfo, JPEG_tree);

    return JPEG_Size + 4;
}

#ifdef HAVE_LIBZ
static void
dissect_ImageZLIB_GLZ_stream(tvbuff_t *tvb, proto_tree *ZLIB_GLZ_tree, packet_info *pinfo,
                             guint32 offset, guint32 ZLIB_GLZSize, guint32 ZLIB_uncompSize)
{
    proto_item *ti;
    proto_tree *Uncomp_tree;
    tvbuff_t   *uncompressed_tvb;

    ti = proto_tree_add_text(ZLIB_GLZ_tree, tvb, offset, ZLIB_GLZSize, "ZLIB stream (%u bytes)", ZLIB_GLZSize);
    uncompressed_tvb = tvb_child_uncompress(tvb, tvb, offset, ZLIB_GLZSize);
    if (uncompressed_tvb != NULL) {
        add_new_data_source(pinfo, uncompressed_tvb, "Uncompressed GLZ stream");
        Uncomp_tree = proto_item_add_subtree(ti, ett_Uncomp_tree);
        dissect_ImageGLZ_RGB(uncompressed_tvb, Uncomp_tree, 0, ZLIB_uncompSize);
    } else {
        proto_tree_add_text(ZLIB_GLZ_tree, tvb, offset, -1, "Error: Unable to decompress content");
    }
}
#else
static void
dissect_ImageZLIB_GLZ_stream(tvbuff_t *tvb, proto_tree *ZLIB_GLZ_tree, packet_info *pinfo _U_,
                             guint32 offset, guint32 ZLIB_GLZSize, guint32 ZLIB_uncompSize _U_)
{
    proto_tree_add_text(ZLIB_GLZ_tree, tvb, offset, ZLIB_GLZSize, "ZLIB stream (%u bytes)", ZLIB_GLZSize);
}
#endif

static guint32
dissect_ImageZLIB_GLZ(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *ZLIB_GLZ_tree;
    guint32     ZLIB_GLZSize, ZLIB_uncompSize;

    ZLIB_uncompSize = tvb_get_letohl(tvb, offset);
    ZLIB_GLZSize = tvb_get_letohl(tvb, offset + 4); /* compressed size */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, ZLIB_GLZSize + 8, "ZLIB over GLZ Image");
        ZLIB_GLZ_tree = proto_item_add_subtree(ti, ett_ZLIB_GLZ);

        proto_tree_add_text(ZLIB_GLZ_tree, tvb, offset, 4, "ZLIB stream uncompressed size: %u bytes", ZLIB_uncompSize);
        offset += 4;
        proto_tree_add_text(ZLIB_GLZ_tree, tvb, offset, 4, "ZLIB stream compressed size: %u bytes", ZLIB_GLZSize);
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
    const guint8 type      = dissect_ImageDescriptor(tvb, tree, offset);;

    offset += sizeof_ImageDescriptor;

    switch(type) {
        case IMAGE_TYPE_QUIC:
            ImageSize = dissect_ImageQuic(tvb, tree, offset);
            break;
        case IMAGE_TYPE_GLZ_RGB:
            ImageSize = dissect_ImageGLZ_RGB(tvb, tree, offset, 0);
            break;
        case IMAGE_TYPE_LZ_RGB:
            ImageSize = dissect_ImageLZ_RGB(tvb, tree, offset);
            break;
        case IMAGE_TYPE_BITMAP:
            ImageSize = dissect_Pixmap(tvb, tree, offset);
            break;
        case IMAGE_TYPE_FROM_CACHE:
            proto_tree_add_text(tree, tvb, offset, 0, "Image from Cache");
            break;
        case IMAGE_TYPE_FROM_CACHE_LOSSLESS:
            proto_tree_add_text(tree, tvb, offset, 0, "Image from Cache - lossless");
            break;
        case IMAGE_TYPE_ZLIB_GLZ_RGB:
            ImageSize = dissect_ImageZLIB_GLZ(tvb, tree, pinfo, offset);
            break;
        case IMAGE_TYPE_JPEG:
            ImageSize = dissect_ImageJPEG(tvb, tree, pinfo, offset);
            break;
        case IMAGE_TYPE_JPEG_ALPHA:
            ImageSize = dissect_ImageJPEG_Alpha(tvb, tree, pinfo, offset);
            break;
        case IMAGE_TYPE_LZ_PLT:
            ImageSize = dissect_ImageLZ_PLT(tvb, tree, offset);
            break;
        case IMAGE_TYPE_SURFACE:
            ImageSize = 4; /* surface ID */
            proto_tree_add_text(tree, tvb, offset, ImageSize, "Surface ID: %u", tvb_get_letohl(tvb, offset));
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown image type - cannot dissect");
    }

    return sizeof_ImageDescriptor + ImageSize;
}

static SpiceRect
dissect_SpiceRect(tvbuff_t *tvb, proto_tree *tree, const guint32 offset, const gint32 id)
{
    proto_item *ti = NULL;
    proto_tree *rect_tree;
    SpiceRect   rect;

    rect.left   = tvb_get_letohl(tvb, offset);
    rect.top    = tvb_get_letohl(tvb, offset + 4);
    rect.right  = tvb_get_letohl(tvb, offset + 8);
    rect.bottom = tvb_get_letohl(tvb, offset + 12);

    if (tree) {
        if (id != -1) {
            ti = proto_tree_add_text(tree, tvb, offset, sizeof_SpiceRect,
                                     "RECT %u: (%u-%u, %u-%u)", id, rect.left, rect.top, rect.right, rect.bottom);
        } else { /* single rectangle */
            ti = proto_tree_add_text(tree, tvb, offset, sizeof_SpiceRect,
                                     "RECT: (%u-%u, %u-%u)", rect.left, rect.top, rect.right, rect.bottom);
        }
        rect_tree = proto_item_add_subtree(ti, ett_rect);

        proto_tree_add_text(rect_tree, tvb, offset,      4, "left: %u", rect.left);
        proto_tree_add_text(rect_tree, tvb, offset + 4,  4, "top: %u", rect.top);
        proto_tree_add_text(rect_tree, tvb, offset + 8,  4, "right: %u", rect.right);
        proto_tree_add_text(rect_tree, tvb, offset + 12, 4, "bottom: %u", rect.bottom);
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
    proto_item    *ti            = NULL;
    proto_tree    *rectlist_tree;
    guint32        i;
    const guint32  rectlist_size = tvb_get_letohl(tvb, offset);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, 4 + (rectlist_size * sizeof_SpiceRect),
                                 "RectList (%d rects)", rectlist_size);
        rectlist_tree = proto_item_add_subtree(ti, ett_rectlist);

        proto_tree_add_item(rectlist_tree, hf_rectlist_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        for (i = 0; i != rectlist_size; i++ ) {
            dissect_SpiceRect(tvb, rectlist_tree, offset, i);
            offset += sizeof_SpiceRect;
        }
    }

    return (4 + (rectlist_size * sizeof_SpiceRect));
}

/* returns clip type */
static guint8
dissect_Clip(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{
    proto_item   *ti   = NULL;
    proto_tree   *Clip_tree;
    const guint8  type = tvb_get_guint8(tvb, offset);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, 1, "SpiceClip");
        Clip_tree = proto_item_add_subtree(ti, ett_Clip);
        proto_tree_add_item(Clip_tree, hf_Clip_type, tvb, offset, sizeof_Clip, ENC_LITTLE_ENDIAN);
    }

    return type;
}

static point32_t
dissect_POINT32(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *point_tree;
    point32_t   point;

    point.x = tvb_get_letohl(tvb, offset);
    point.y = tvb_get_letohl(tvb, offset + 4);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof(point32_t), "POINT (%u, %u)", point.x, point.y);
        point_tree = proto_item_add_subtree(ti, ett_point);

        proto_tree_add_text(point_tree, tvb, offset,     4, "x: %u", point.x);
        proto_tree_add_text(point_tree, tvb, offset + 4, 4, "y: %u", point.y);
    }

    return point;
}

static point16_t
dissect_POINT16(tvbuff_t *tvb, proto_tree *tree, const guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *point16_tree;
    point16_t   point16;

    point16.x = tvb_get_letohs(tvb, offset);
    point16.y = tvb_get_letohs(tvb, offset + 2);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, sizeof(point16_t), "POINT16 (%u, %u)", point16.x, point16.y);
        point16_tree = proto_item_add_subtree(ti, ett_point16);

        proto_tree_add_text(point16_tree, tvb, offset,     2, "x: %u", point16.x);
        proto_tree_add_text(point16_tree, tvb, offset + 2, 2, "y: %u", point16.y);
    }

    return point16;
}

static guint32
dissect_Mask(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *Mask_tree;
    guint32     bitmap;

    ti = proto_tree_add_text(tree, tvb, offset, sizeof_Mask, "Mask");
    Mask_tree = proto_item_add_subtree(ti, ett_Mask);

    bitmap = tvb_get_letohl(tvb, offset + sizeof(point32_t) + 1);
    if (bitmap != 0) {
        proto_tree_add_item(Mask_tree, hf_Mask_flag, tvb, offset, 1, ENC_NA);
        offset += 1;
        dissect_POINT32(tvb, Mask_tree, offset);
        offset += sizeof(point32_t);
        proto_tree_add_item(Mask_tree, hf_Mask_bitmap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_item_set_len(ti, sizeof_Mask + sizeof_ImageDescriptor);
        dissect_ImageDescriptor(tvb, Mask_tree, offset);
        return sizeof_Mask + sizeof_ImageDescriptor;
    } else {
        proto_tree_add_text(Mask_tree, tvb, offset, 1, "Mask flag - value irrelevant as bitmap address is 0");
        offset += 1;
        proto_tree_add_text(Mask_tree, tvb, offset, sizeof(point32_t), "Point - value irrelevant as bitmap address is 0");
        offset += sizeof(point32_t);
        proto_tree_add_item(Mask_tree, hf_Mask_bitmap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
    return sizeof_Mask;
}

/* returns brush size */
static guint32
dissect_Brush(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item   *ti   = NULL;
    proto_tree   *brush_tree;
    const guint8  type = tvb_get_guint8(tvb, offset);

    switch(type) {
        case SPICE_BRUSH_TYPE_SOLID:
            ti = proto_tree_add_text(tree, tvb, offset, 5, "Brush - SOLID");
            brush_tree = proto_item_add_subtree(ti, ett_brush);
            proto_tree_add_item(brush_tree, hf_brush_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(brush_tree, hf_brush_rgb, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            return 5;
            break;
        case SPICE_BRUSH_TYPE_PATTERN:
            ti = proto_tree_add_text(tree, tvb, offset, 17, "Brush - PATTERN");
            brush_tree = proto_item_add_subtree(ti, ett_brush);
            proto_tree_add_item(brush_tree, hf_brush_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* FIXME: this is supposed to be the offset to the image to be used as the pattern.        */
            /* For now the hack is that callers check if the returned size was not 5 (therefore SOLID, */
            /* it's a pattern and later on dissect the image. That's bad. Really. */
            dissect_ID(tvb, brush_tree, offset);
            offset += 4;
            dissect_POINT32(tvb, brush_tree, offset);
            return (1 + 4 + 8);
            break;
        case SPICE_BRUSH_TYPE_NONE:
            proto_tree_add_text(tree, tvb, offset, 1, "Brush - NONE");
            return 1;
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Invalid Brush type");
            return 0;
            break;
    }

    return 0;
}

static guint32
dissect_DisplayBase(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    proto_item *ti        = NULL;
    proto_tree *DisplayBase_tree;
    SpiceRect   rect;
    guint8      clip_type;
    guint32     clip_size = 0;

    ti = proto_tree_add_text(tree, tvb, offset, sizeof_DisplayBase, "SpiceMsgDisplayBase");
    DisplayBase_tree = proto_item_add_subtree(ti, ett_DisplayBase);
    proto_tree_add_item(DisplayBase_tree, hf_display_surface_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    rect = dissect_SpiceRect(tvb, DisplayBase_tree, offset, -1);
    proto_item_append_text(ti, " - SpiceRect box (%u-%u, %u-%u)",rect.left, rect.top, rect.right, rect.bottom);
    offset += sizeof_SpiceRect;
    clip_type = dissect_Clip(tvb, DisplayBase_tree, offset);
    offset += sizeof_Clip;
    if (clip_type == CLIP_TYPE_RECTS) {
        clip_size = dissect_RectList(tvb, DisplayBase_tree, offset);
        proto_item_set_len(ti, sizeof_DisplayBase + clip_size);
        return sizeof_DisplayBase + clip_size;
    }
    return sizeof_DisplayBase;
}

static const gchar* get_message_type_string(const guint16 message_type, const spice_conversation_t *spice_info,
                                            const gboolean client_message)
{

    if (message_type < SPICE_FIRST_AVAIL_MESSAGE) { /* this is a common message */
        if (client_message) {
            return val_to_str_const(message_type, common_client_message_types, "Unknown client message");
        } else {
            return val_to_str_const(message_type, common_server_message_types, "Unknown server message");
        }
    }

    switch (spice_info->channel_type) {
        case SPICE_CHANNEL_PLAYBACK:
            return val_to_str_const(message_type, playback_server_message_types, "Unknown playback channel server message");
            break;
        case SPICE_CHANNEL_RECORD:
            if (client_message) {
                return val_to_str_const(message_type, record_client_message_types, "Unknown record channel client message");
            } else {
                return val_to_str_const(message_type, record_server_message_types, "Unknown record channel server message");
            }
            break;
        case SPICE_CHANNEL_MAIN:
            if (client_message) {
                return val_to_str_const(message_type, main_client_message_types, "Unknown main channel client message");
            } else {
                return val_to_str_const(message_type, main_server_message_types, "Unknown main channel server message");
            }
            break;
        case SPICE_CHANNEL_CURSOR:
            if (client_message) {
                return val_to_str_const(message_type, cursor_client_message_types, "Unknown cursor channel client message");
            } else {
                return val_to_str_const(message_type, cursor_server_message_types, "Unknown cursor channel server message");
            }
            break;
        case SPICE_CHANNEL_DISPLAY:
            if (client_message) {
                return val_to_str_const(message_type, display_client_message_types, "Unknown display channel client message");
            } else {
                return val_to_str_const(message_type, display_server_message_types, "Unknown display channel server message");
            }
            break;
        case SPICE_CHANNEL_INPUTS:
            if (client_message) {
                return val_to_str_const(message_type, inputs_client_message_types, "Unknown inputs channel client message");
            } else {
                return val_to_str_const(message_type, inputs_server_message_types, "Unknown inputs channel server message");
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
    if (tree) {
        proto_tree_add_text(tree, tvb, offset, 2, "Message type: %s (%d)", get_message_type_string(message_type, spice_info, client_message), message_type);
        offset += 2;
        proto_tree_add_item(tree, hf_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_spice_data_header(tvbuff_t *tvb, proto_tree *tree, const spice_conversation_t *spice_info,
                          const gboolean client_message, const guint16 message_type, guint32 *sublist_size, guint32 offset)
{
    *sublist_size = tvb_get_letohl(tvb, offset + 14);

    if (tree) {
        proto_tree_add_item(tree, hf_serial, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        proto_tree_add_text(tree, tvb, offset, 2, "Message type: %s (%d)", get_message_type_string(message_type, spice_info, client_message), message_type);
        offset += 2;
        proto_tree_add_item(tree, hf_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_data_sublist, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }
}


static guint32
dissect_spice_common_client_messages(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    proto_item *ti=NULL;
    proto_tree *client_message_tree;

    switch(message_type) {
        case SPICEC_ACK_SYNC:
            ti = proto_tree_add_text(tree, tvb, offset, 4, "Client ACK_SYNC message");
            client_message_tree = proto_item_add_subtree(ti, ett_common_client_message);
            proto_tree_add_item(client_message_tree, hf_red_set_ack_generation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICEC_ACK:
            proto_tree_add_text(tree, tvb, offset, 0, "Client ACK message");
            break;
        case SPICEC_PONG:
            ti = proto_tree_add_text(tree, tvb, offset, 12, "Client PONG message");
            client_message_tree = proto_item_add_subtree(ti, ett_common_client_message);
            proto_tree_add_item(client_message_tree, hf_red_ping_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(client_message_tree, hf_red_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        /*
        case SPICEC_MIGRATE_FLUSH_MARK:
        case SPICEC_MIGRATE_DATA:
        case SPICEC_DISCONNECTING:
        */
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown common client message - cannot dissect");
            break;
    }

    return offset;
}

static guint32
dissect_spice_common_server_messages(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset, const guint32 total_message_size)
{
    proto_item *ti = NULL;
    proto_tree *server_message_tree;
    guint32     message_len, severity, visibility;

    switch(message_type) {
        /*
        case SPICE_MIGRATE:
        case SPICE_MIGRATE_DATA:
        case SPICE_WAIT_FOR_CHANNELS:
        case SPICE_DISCONNECTING:
        */
        case SPICE_SET_ACK:
            ti = proto_tree_add_text(tree, tvb, offset, 8, "Server SET_ACK message");
            server_message_tree = proto_item_add_subtree(ti, ett_common_server_message);
            proto_tree_add_item(server_message_tree, hf_red_set_ack_generation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(server_message_tree, hf_red_set_ack_window, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_PING:
            ti = proto_tree_add_text(tree, tvb, offset, 12, "Server PING message");
            server_message_tree = proto_item_add_subtree(ti, ett_common_server_message);
            proto_tree_add_item(server_message_tree, hf_red_ping_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(server_message_tree, hf_red_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            if (total_message_size > 12) {
                proto_tree_add_text(server_message_tree, tvb, offset, total_message_size - 12,
                                    "PING DATA (%d bytes)", total_message_size - 12);
                offset += (total_message_size - 12);
            }
            break;
        case SPICE_NOTIFY:
            ti = proto_tree_add_text(tree, tvb, offset, 12, "Server NOTIFY message");
            server_message_tree = proto_item_add_subtree(ti, ett_common_server_message);
            proto_tree_add_item(server_message_tree, hf_red_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            /* TODO: properly dissect severity and visibility flags, using hf_ and proto_tree_add_item */
            severity = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(server_message_tree, tvb, offset, 4,
                                "Severity: %s (%d)", val_to_str_const(severity, spice_severity_vs, "unknown severity"), severity);
            offset += 4;
            visibility = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(server_message_tree, tvb, offset, 4,
                                "Visibility: %s (%d)", val_to_str_const(visibility, spice_visibility_vs, "unknown visibility"), visibility);
            offset += 4;
            /*TODO: based on severity, dissect the error code */
            proto_tree_add_text(server_message_tree, tvb, offset, 4, "error/warning/info code: %d", tvb_get_letohl(tvb, offset));
            offset += 4;
            message_len = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(server_message_tree, tvb, offset, 4, "message length: %d", message_len);
            offset += 4;
            /*TODO use proto_tree_add_string and get the stringz using tvb_get_ephemeral_stringz() */
            proto_tree_add_text(server_message_tree, tvb, offset, message_len + 1, "Message content");
            offset += (message_len + 1);
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown common server message - cannot dissect");
            break;
    }

    return offset;
}
static guint32
dissect_spice_record_client(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    proto_item *ti=NULL;
    proto_tree *record_tree;

    switch(message_type) {
        case SPICEC_RECORD_MODE:
            ti = proto_tree_add_text(tree, tvb, offset, 8, "Client RECORD_MODE message"); /* size is incorrect, fixed later */
            record_tree = proto_item_add_subtree(ti, ett_record_client);
            proto_tree_add_item(record_tree, hf_playback_record_mode_timstamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(record_tree, hf_playback_record_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* TODO - mode dependant, there may be more data here */
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown record client message - cannot dissect");
            break;
    }

    return offset;
}

static guint32
dissect_spice_display_client(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    proto_item *ti=NULL;
    proto_tree *display_tree;

    switch(message_type) {
        case SPICEC_DISPLAY_INIT:
            ti = proto_tree_add_text(tree, tvb, offset, sizeof_RedcDisplayInit, "Client INIT message");
            display_tree = proto_item_add_subtree(ti, ett_display_client);
            proto_tree_add_item(display_tree, hf_spice_display_init_cache_id, tvb, offset,  1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(display_tree, hf_spice_display_init_cache_size, tvb, offset,  8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(display_tree, hf_spice_display_init_glz_dict_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(display_tree, hf_spice_display_init_dict_window_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown display client message - cannot dissect");
            break;
    }

    return offset;
}

static guint32
dissect_spice_display_server(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, const guint16 message_type, guint32 offset)
{
    guint32    data_size, displayBaseLen;
    guint8     clip_type;
    guint16    glyphs;
    SpiceRect  r;
    tvbuff_t  *jpeg_tvb;

    switch(message_type) {
        case SPICE_DISPLAY_MODE:
            proto_tree_add_item(tree, hf_spice_display_mode_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_spice_display_mode_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_spice_display_mode_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_DISPLAY_MARK:
            proto_tree_add_text(tree, tvb, offset, 0, "DISPLAY_MARK message");
            break;
        case SPICE_DISPLAY_RESET:
            proto_tree_add_text(tree, tvb, offset, 0, "DISPLAY_RESET message");
            break;
        case SPICE_DISPLAY_DRAW_ALPHA_BLEND:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            /* TODO: Flag 1 byte, Alpha 1 byte dissection*/
            offset += 2;
            dissect_ID(tvb, tree, offset);
            offset += 4;
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += sizeof_SpiceRect;
            data_size = dissect_Image(tvb, tree, pinfo, offset);
            offset += data_size;
            break;
        case SPICE_DISPLAY_DRAW_BLACKNESS:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            offset += dissect_Mask(tvb, tree, offset);
            break;
        case SPICE_DISPLAY_COPY_BITS:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            dissect_POINT32(tvb, tree, offset);
            offset += sizeof(point32_t);
            break;
        case SPICE_DISPLAY_DRAW_WHITENESS:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            offset += dissect_Mask(tvb, tree, offset);
            break;
        case SPICE_DISPLAY_DRAW_INVERS:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            offset += dissect_Mask(tvb, tree, offset);
            break;
        case SPICE_DISPLAY_DRAW_FILL:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            data_size = dissect_Brush(tvb, tree, offset);
            offset += data_size;

            proto_tree_add_item(tree, hf_display_rop_descriptor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            offset += dissect_Mask(tvb, tree, offset);

            if (data_size != 5) { /* if it's not a SOLID brush, it's a PATTERN, dissect its image descriptior */
                offset += dissect_Image(tvb, tree, pinfo, offset);
            }
            break;
        case SPICE_DISPLAY_DRAW_TRANSPARENT:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            dissect_ID(tvb, tree, offset);
            offset += 4;
            /* source area */
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += sizeof_SpiceRect;
            proto_tree_add_item(tree, hf_tranparent_src_color, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_tranparent_true_color, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            data_size = dissect_Image(tvb, tree, pinfo, offset);
            offset += data_size;
            break;
        case SPICE_DISPLAY_DRAW_BLEND:
        case SPICE_DISPLAY_DRAW_COPY:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            /* SpiceImage *src_bitmap */
            dissect_ID(tvb, tree, offset);
            offset += 4;

            /* source area */
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += sizeof_SpiceRect;

            proto_tree_add_item(tree, hf_display_rop_descriptor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_display_scale_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            offset += dissect_Mask(tvb, tree, offset);

            data_size = dissect_Image(tvb, tree, pinfo, offset);
            offset += data_size;
            break;
        case SPICE_DISPLAY_DRAW_ROP3:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            /* SpiceImage *src_bitmap */
            dissect_ID(tvb, tree, offset);
            offset += 4;

            /* source area */
            dissect_SpiceRect(tvb, tree, offset, -1);
            offset += sizeof_SpiceRect;

            data_size = dissect_Brush(tvb, tree, offset);
            offset += data_size;

            proto_tree_add_text(tree, tvb, offset, 1, "ROP3");
            offset += 1;
            proto_tree_add_text(tree, tvb, offset, 1, "scale mode");
            offset += 1;

            offset += dissect_Mask(tvb, tree, offset);
            /*FIXME - need to understand what the rest of the message contains. */
            data_size = dissect_Image(tvb, tree, pinfo, offset);
            offset += data_size;
            break;
        case SPICE_DISPLAY_INVAL_ALL_PALETTES:
            proto_tree_add_text(tree, tvb, offset, 0, "DISPLAY_INVAL_ALL_PALETTES message");
            break;
        case SPICE_DISPLAY_DRAW_TEXT:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset += displayBaseLen;
            dissect_ID(tvb, tree, offset);
            offset += 4;

            r = dissect_SpiceRect(tvb, tree, offset, -1);
            offset += sizeof_SpiceRect;
            if (!rect_is_empty(r)) {
                data_size = dissect_Brush(tvb, tree, offset);
                offset += data_size;
            }
            proto_tree_add_item(tree, hf_display_text_fore_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_display_text_back_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            glyphs = tvb_get_letohs(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 2, "Number of glyphs: %u", glyphs);
            offset += 2;
            proto_tree_add_text(tree, tvb, offset, 2, "Glyph flags");
            /*TODO finish dissecting glyph list */
            break;
        case SPICE_DISPLAY_DRAW_STROKE:
            displayBaseLen = dissect_DisplayBase(tvb, tree, offset);
            offset  += displayBaseLen;
            /*TODO: complete and correct dissection */

            break;
        case SPICE_DISPLAY_STREAM_CLIP:
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            clip_type = dissect_Clip(tvb, tree, offset);
            offset += sizeof_Clip;
            if (clip_type == CLIP_TYPE_RECTS) {
                offset += dissect_RectList(tvb, tree, offset);
            }
            break;
        case SPICE_DISPLAY_STREAM_CREATE:
            proto_tree_add_item(tree, hf_display_surface_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(tree, hf_display_stream_codec_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_text(tree, tvb, offset, 8, "stamp");
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
            offset += sizeof_SpiceRect;
            clip_type = dissect_Clip(tvb, tree, offset);
            offset += sizeof_Clip;
            if (clip_type == CLIP_TYPE_RECTS) {
                offset += dissect_RectList(tvb, tree, offset);
            }
            break;
        case SPICE_DISPLAY_STREAM_DATA:
            data_size = tvb_get_letohl(tvb, offset + 8);
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_multi_media_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_stream_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_text(tree, tvb, offset, data_size, "Stream data");
            jpeg_tvb = tvb_new_subset(tvb, offset, data_size, data_size);
            call_dissector(jpeg_handle, jpeg_tvb, pinfo, tree);
            offset += data_size;
            break;
        case SPICE_DISPLAY_STREAM_DESTROY:
            proto_tree_add_item(tree, hf_display_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_DISPLAY_STREAM_DESTROY_ALL:
            proto_tree_add_text(tree, tvb, offset, 0, "DISPLAY_STREAM_DESTROY_ALL message");
            break;
        case SPICE_DISPLAY_DRAW_SURFACE_CREATE:
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
        case SPICE_DISPLAY_DRAW_SURFACE_DESTROY:
            proto_tree_add_item(tree, hf_display_surface_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown display server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_playback_server(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    switch(message_type) {
        case SPICE_PLAYBACK_DATA:
            proto_tree_add_item(tree, hf_playback_record_mode_timstamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* TODO - mode dependent, there may be more data here */
            break;
            break;
        case SPICE_PLAYBACK_MODE:
            proto_tree_add_item(tree, hf_playback_record_mode_timstamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_playback_record_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            /* TODO - mode dependent, there may be more data here */
            break;
        case SPICE_PLAYBACK_START:
            /*TODO: no. channels (UINT32), format (UINT16), frequency (UINT32), time (UINT32)*/
            offset += 14;
            break;
        case SPICE_PLAYBACK_STOP:
            proto_tree_add_text(tree, tvb, offset, 0, "PLAYBACK_STOP message");
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown playback server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_cursor_server(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    guint32 RedCursorSize;

    switch(message_type) {
        case SPICE_CURSOR_INIT:
            dissect_POINT16(tvb, tree, offset);
            offset += sizeof(point16_t);
            proto_tree_add_item(tree, hf_cursor_trail_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_cursor_trail_freq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_cursor_trail_visible, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            RedCursorSize = dissect_RedCursor(tvb, tree, offset);
            offset += RedCursorSize;
            break;
        case SPICE_CURSOR_RESET:
            proto_tree_add_text(tree, tvb, offset, 0, "CURSOR_RESET message");
            break;
        case SPICE_CURSOR_SET:
            dissect_POINT16(tvb, tree, offset);
            offset += sizeof(point16_t);
            offset +=1; /*TODO flags */
            RedCursorSize = dissect_RedCursor(tvb, tree, offset);
            offset += RedCursorSize;
            break;
        case SPICE_CURSOR_MOVE:
            dissect_POINT16(tvb, tree, offset);
            offset += sizeof(point16_t);
            break;
        case SPICE_CURSOR_HIDE:
            proto_tree_add_text(tree, tvb, offset, 0, "CURSOR_HIDE message");
            break;
        case SPICE_CURSOR_TRAIL:
            proto_tree_add_item(tree, hf_cursor_trail_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_cursor_trail_freq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICE_CURSOR_INVAL_ONE:
            proto_tree_add_item(tree, hf_cursor_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        case SPICE_CURSOR_INVAL_ALL:
            proto_tree_add_text(tree, tvb, offset, 0, "CURSOR_INVAL_ALL message");
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown cursor server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_record_server(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, const guint32 offset)
{
    switch(message_type) {
        case SPICE_RECORD_STOP:
            proto_tree_add_text(tree, tvb, offset, 0, "RECORD_STOP message");
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown record server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_agent_message(tvbuff_t *tvb, proto_tree *tree, const guint32 message_type, guint32 message_len, guint32 offset)
{
    proto_item *ti=NULL;
    proto_tree *agent_tree;

    switch (message_type) {
        case VD_AGENT_MOUSE_STATE:
            proto_tree_add_text(tree, tvb, offset, 4, "VD_AGENT_MOUSE_STATE message");
            offset += 4;
            break;
        case VD_AGENT_MONITORS_CONFIG:
            proto_tree_add_text(tree, tvb, offset, 4, "VD_AGENT_MONITORS_CONFIG message");
            offset += 4;
            break;
        case VD_AGENT_REPLY:
            /*ti = */proto_tree_add_text(tree, tvb, offset, message_len, "VD_AGENT_REPLY message");
            /* TODO: complete dissection
            agent_tree = proto_item_add_subtree(ti, ett_spice_agent);
            */
            offset += message_len;
            break;
        case VD_AGENT_CLIPBOARD:
            /*ti = */proto_tree_add_text(tree, tvb, offset, message_len, "VD_AGENT_CLIPBOARD message");
            /* TODO: display string
            agent_tree = proto_item_add_subtree(ti, ett_spice_agent);
            */
            offset += message_len;
            break;
        case VD_AGENT_DISPLAY_CONFIG:
            proto_tree_add_text(tree, tvb, offset, 4, "VD_AGENT_DISPLAY_CONFIG message");
            offset += 4;
            break;
        case VD_AGENT_ANNOUNCE_CAPABILITIES:
            /*ti = */proto_tree_add_text(tree, tvb, offset, message_len, "VD_AGENT_ANNOUNCE_CAPABILITIES message");
            /* TODO: complete dissection
            agent_tree = proto_item_add_subtree(ti, ett_spice_agent);
            */
            offset += message_len;
            break;
        case VD_AGENT_CLIPBOARD_GRAB:
            ti = proto_tree_add_text(tree, tvb, offset, 4, "VD_AGENT_CLIPBOARD_GRAB message");
            agent_tree = proto_item_add_subtree(ti, ett_spice_agent);
            proto_tree_add_item(agent_tree, hf_agent_clipboard_selection, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_text(agent_tree, tvb, offset, 3, "reserverd");
            offset += 3;
            break;
        case VD_AGENT_CLIPBOARD_REQUEST:
            ti = proto_tree_add_text(tree, tvb, offset, 8, "VD_AGENT_CLIPBOARD_REQUEST message");
            agent_tree = proto_item_add_subtree(ti, ett_spice_agent);
            proto_tree_add_item(agent_tree, hf_agent_clipboard_selection, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_text(agent_tree, tvb, offset, 3, "reserverd");
            offset += 3;
            proto_tree_add_item(agent_tree, hf_agent_clipboard_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case VD_AGENT_CLIPBOARD_RELEASE:
            proto_tree_add_text(tree, tvb, offset, 0, "VD_AGENT_CLIPBOARD_RELEASE message");
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown agent message (%u) - cannot dissect", message_type);
            break;
    }
    return offset;
}

static guint32
dissect_spice_main_server(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    guint32 num_channels, i, agent_msg_type, agent_msg_len, name_len;
    guint8  channel_type;

    switch(message_type) {
        case SPICE_MAIN_INIT:
            proto_tree_add_item(tree, hf_session_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_display_channels_hint, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_supported_mouse_modes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
        case SPICE_MAIN_NAME:
            name_len = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 4, "Name length (bytes): %u", name_len);
            offset += 4;
            proto_tree_add_item(tree, hf_vm_name, tvb, offset, name_len, ENC_NA);
            offset += name_len;
            break;
        case SPICE_MAIN_UUID:
            proto_tree_add_item(tree, hf_vm_uuid, tvb, offset, 16, ENC_BIG_ENDIAN);
            offset += 16;
            break;
        case SPICE_MAIN_CHANNELS_LIST:
            num_channels = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 4, "Number of channels: %u", num_channels);
            offset += 4;
            for (i = 1; i <= num_channels; i++ ) {
                channel_type = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, 1,
                                    "Type: %s [%d]", val_to_str_const(channel_type, channel_types_vs, "Unknown"), channel_type);
                offset += 1;
                proto_tree_add_text(tree, tvb, offset, 1, "\tID: %d", tvb_get_guint8(tvb, offset));
                offset += 1;
            }
            break;
        case SPICE_MAIN_MULTI_MEDIA_TIME:
            proto_tree_add_item(tree, hf_multi_media_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICE_MAIN_MOUSE_MODE:
            proto_tree_add_text(tree, tvb, offset, 4, "MOUSE_MODE message");
            /* TODO:
                mouse_mode supported_modes;
                mouse_mode current_mode;
            */
            offset += 4;
            break;
        case SPICE_MAIN_AGENT_DATA:
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
            offset = dissect_spice_agent_message(tvb, tree, agent_msg_type, agent_msg_len, offset);
            break;
        case SPICE_MAIN_AGENT_TOKEN:
            proto_tree_add_item(tree, hf_agent_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown main server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_main_client(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *main_tree;
    guint32     agent_msg_type, agent_msg_len;

    switch(message_type) {
        case SPICEC_MAIN_MOUSE_MODE_REQUEST:
            /*ti = */proto_tree_add_text(tree, tvb, offset, 4, "Client MOUSE_MODE_REQUEST message");
            /* TODO: complete dissection - mouse_mode, 2 bytes
            main_tree = proto_item_add_subtree(ti, ett_main_client);
            */
            offset += 2;
            break;
        case SPICEC_MAIN_ATTACH_CHANNELS:
            /*ti = */proto_tree_add_text(tree, tvb, offset, 4, "Client MAIN_ATTACH_CHANNEL message");
            /* TODO: complete dissection
            main_tree = proto_item_add_subtree(ti, ett_main_client);
            */
            break;
        case SPICEC_MAIN_AGENT_START:
            ti = proto_tree_add_text(tree, tvb, offset, 4, "Client AGENT_START message");
            main_tree = proto_item_add_subtree(ti, ett_main_client);
            proto_tree_add_item(main_tree, hf_main_client_agent_tokens, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case SPICEC_MAIN_AGENT_DATA:
            ti = proto_tree_add_text(tree, tvb, offset, 24, "Client AGENT_DATA message");
            main_tree = proto_item_add_subtree(ti, ett_main_client);
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
            offset = dissect_spice_agent_message(tvb, main_tree, agent_msg_type, agent_msg_len, offset);
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown main client message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_inputs_client(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    proto_item *ti=NULL;
    proto_tree *inputs_tree;

    switch(message_type) {
        case SPICEC_INPUTS_KEY_DOWN:
            /*ti = */proto_tree_add_text(tree, tvb, offset, 4, "Client KEY_DOWN message");
            /* TODO: complete dissection
            inputs_tree = proto_item_add_subtree(ti, ett_inputs_client);
            */
            offset += 4;
            break;
        case SPICEC_INPUTS_KEY_UP:
            /*ti = */proto_tree_add_text(tree, tvb, offset, 4, "Client KEY_UP message");
            /* TODO: complete dissection
            inputs_tree = proto_item_add_subtree(ti, ett_inputs_client);
            */
            offset += 4;
            break;
        case SPICEC_INPUTS_KEY_MODIFIERS:
            ti = proto_tree_add_text(tree, tvb, offset, 2, "Client KEY_MODIFIERS message");
            inputs_tree = proto_item_add_subtree(ti, ett_inputs_client);
            proto_tree_add_item(inputs_tree, hf_keyboard_bits, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICEC_INPUTS_MOUSE_POSITION:
            ti = proto_tree_add_text(tree, tvb, offset, sizeof(point32_t) + 3, "Client MOUSE_POSITION message");
            inputs_tree = proto_item_add_subtree(ti, ett_inputs_client);
            dissect_POINT32(tvb, inputs_tree, offset);
            offset += sizeof(point32_t);
            proto_tree_add_item(inputs_tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(inputs_tree, hf_mouse_display_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        case SPICEC_INPUTS_MOUSE_MOTION:
            ti = proto_tree_add_text(tree, tvb, offset, sizeof(point32_t) + 4, "Client MOUSE_MOTION message");
            inputs_tree = proto_item_add_subtree(ti, ett_inputs_client);
            dissect_POINT32(tvb, inputs_tree, offset);
            offset += sizeof(point32_t);
            proto_tree_add_item(inputs_tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICEC_INPUTS_MOUSE_PRESS:
            ti = proto_tree_add_text(tree, tvb, offset, 3, "Client MOUSE_PRESS message");
            inputs_tree = proto_item_add_subtree(ti, ett_inputs_client);
            proto_tree_add_item(inputs_tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(inputs_tree, hf_mouse_display_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case SPICEC_INPUTS_MOUSE_RELEASE:
            ti = proto_tree_add_text(tree, tvb, offset, 3, "Client MOUSE_RELEASE message");
            inputs_tree = proto_item_add_subtree(ti, ett_inputs_client);
            proto_tree_add_item(inputs_tree, hf_button_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(inputs_tree, hf_mouse_display_id, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown inputs client message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_inputs_server(tvbuff_t *tvb, proto_tree *tree, const guint16 message_type, guint32 offset)
{
    switch(message_type) {
        case SPICE_INPUTS_INIT:
            proto_tree_add_item(tree, hf_keyboard_bits, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICE_INPUTS_KEY_MODIFIERS:
            proto_tree_add_item(tree, hf_keyboard_bits, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case SPICE_INPUTS_MOUSE_MOTION_ACK:
            proto_tree_add_text(tree, tvb, offset, 0, "Server INPUTS_MOUSE_MOTION_ACK message");
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown inputs server message - cannot dissect");
            break;
    }
    return offset;
}

static guint32
dissect_spice_data_server_pdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, spice_conversation_t *spice_info, guint32 offset, const guint32 total_message_size)
{
    proto_item *ti = NULL, *msg_ti=NULL;
    proto_tree *data_header_tree, *message_tree;
    guint16     message_type;
    guint32     message_size, sublist_size, old_offset;
    guint32     header_size;

    if (spice_info->client_mini_header && spice_info->server_mini_header) {
        header_size = sizeof_SpiceMiniDataHeader;
        message_type = tvb_get_letohs(tvb, offset);
        message_size = tvb_get_letohl(tvb, offset +2);
        msg_ti = proto_tree_add_text(tree, tvb, offset, 0,
                                     "%s (%d bytes)",
                                     get_message_type_string(message_type, spice_info, FALSE),
                                     message_size + header_size);
        message_tree = proto_item_add_subtree(msg_ti, ett_message);
        ti = proto_tree_add_item(message_tree, hf_data, tvb, offset, header_size, ENC_NA);
        data_header_tree = proto_item_add_subtree(ti, ett_data);
        dissect_spice_mini_data_header(tvb, data_header_tree, spice_info, FALSE, message_type, offset);
        proto_item_set_len(msg_ti, message_size + header_size);
    } else {
        header_size = sizeof_SpiceDataHeader;
        message_type = tvb_get_letohs(tvb, offset + 8);
        message_size = tvb_get_letohl(tvb, offset + 10);
        msg_ti = proto_tree_add_text(tree, tvb, offset, 0,
                                     "%s (%d bytes)",
                                     get_message_type_string(message_type, spice_info, FALSE),
                                     message_size + header_size);
        message_tree = proto_item_add_subtree(msg_ti, ett_message);
        ti = proto_tree_add_item(message_tree, hf_data, tvb, offset, header_size, ENC_NA);
        data_header_tree = proto_item_add_subtree(ti, ett_data);
        dissect_spice_data_header(tvb, data_header_tree, spice_info, FALSE, message_type, &sublist_size, offset);
    }
    proto_item_set_len(msg_ti, message_size + header_size);
    offset += header_size;
    old_offset = offset;

    col_append_str(pinfo->cinfo, COL_INFO, get_message_type_string(message_type, spice_info, FALSE));
    if (message_type < SPICE_FIRST_AVAIL_MESSAGE) { /* this is a common message */
        offset = dissect_spice_common_server_messages(tvb, message_tree, message_type, offset, total_message_size - header_size);
        return offset;
    }

    switch (spice_info->channel_type) {
        case SPICE_CHANNEL_PLAYBACK:
            offset = dissect_spice_playback_server(tvb, message_tree, message_type, offset);
            break;
        case SPICE_CHANNEL_RECORD:
            offset = dissect_spice_record_server(tvb, message_tree, message_type, offset);
            break;
        case SPICE_CHANNEL_MAIN:
            offset = dissect_spice_main_server(tvb, message_tree, message_type, offset);
            break;
        case SPICE_CHANNEL_CURSOR:
            offset = dissect_spice_cursor_server(tvb, message_tree, message_type, offset);
            break;
        case SPICE_CHANNEL_DISPLAY:
            offset = dissect_spice_display_server(tvb, message_tree, pinfo, message_type, offset);
            break;
        case SPICE_CHANNEL_INPUTS:
            offset = dissect_spice_inputs_server(tvb, message_tree, message_type, offset);
            break;
        case SPICE_CHANNEL_TUNNEL:
            /* TODO: Not implemented yet */
        case SPICE_CHANNEL_SMARTCARD:
            /* TODO: Not implemented yet */
        default:
            proto_tree_add_text(message_tree, tvb, offset, 0, "Unknown server PDU - cannot dissect");
    }

    if((offset - old_offset) != message_size) {
        g_warning("dissect_spice_data_server_pdu() - FIXME:message type %s (%u) in packet %d was not fully dissected"
                  " - dissected %d (offset %d [0x%x]), total message size: %d.\r\n",
                  get_message_type_string(message_type, spice_info, FALSE),
                  message_type, pinfo->fd->num, offset - old_offset, offset, offset, message_size + header_size);
        offset = old_offset + message_size;
    }

    return offset;
}

static guint32
dissect_spice_data_client_pdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, spice_conversation_t *spice_info, guint32 offset)
{
    proto_item *ti = NULL;
    proto_tree *data_header_tree;
    guint16     message_type;
    guint32 /** message_size,**/ sublist_size;
    guint32     header_size;

    if (spice_info->client_mini_header && spice_info->server_mini_header) {
        header_size = sizeof_SpiceMiniDataHeader;
        ti = proto_tree_add_item(tree, hf_data, tvb, offset, header_size, ENC_NA);
        data_header_tree = proto_item_add_subtree(ti, ett_data);
        message_type = tvb_get_letohs(tvb, offset);
        dissect_spice_mini_data_header(tvb, data_header_tree, spice_info, TRUE, message_type, offset);
    } else {
        header_size = sizeof_SpiceDataHeader;
        ti = proto_tree_add_item(tree, hf_data, tvb, offset, header_size, ENC_NA);
        data_header_tree = proto_item_add_subtree(ti, ett_data);
        message_type = tvb_get_letohs(tvb, offset + 8);
        /** message_size = tvb_get_letohl(tvb, offset + 10);  **/
        dissect_spice_data_header(tvb, data_header_tree, spice_info, TRUE, message_type, &sublist_size, offset);
    }
    col_append_str(pinfo->cinfo, COL_INFO, get_message_type_string(message_type, spice_info, TRUE));
    offset += header_size;
        /* TODO: deal with sub-messages list first. As implementation does not uses sub-messsages list yet, */
        /*       it cannot be implemented in the dissector yet. */

    if (message_type < SPICE_FIRST_AVAIL_MESSAGE) { /* this is a common message */
        return dissect_spice_common_client_messages(tvb, tree, message_type, offset);
    }

    switch (spice_info->channel_type) {
        case SPICE_CHANNEL_PLAYBACK:
            break;
        case SPICE_CHANNEL_RECORD:
            offset = dissect_spice_record_client(tvb, tree, message_type, offset);
            break;
        case SPICE_CHANNEL_MAIN:
            offset = dissect_spice_main_client(tvb, tree, message_type, offset);
            break;
        case SPICE_CHANNEL_DISPLAY:
            offset = dissect_spice_display_client(tvb, tree, message_type, offset);
            break;
        case SPICE_CHANNEL_INPUTS:
            offset = dissect_spice_inputs_client(tvb, tree, message_type, offset);
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 0, "Unknown client PDU - cannot dissect");
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
dissect_spice_common_capabilities(tvbuff_t *tvb, proto_tree *tree, guint32 offset, const int caps_len, spice_conversation_t *spice_info, gboolean is_client)
{
/* TODO: save common and per-channel capabilities in spice_info ? */
    int         i;
    guint32     val;
    proto_item *ti = NULL;
    proto_tree *auth_tree;

    for(i = 0; i != caps_len ; i++) {
        val = tvb_get_letohl(tvb, offset);
        switch (i) {
            case 0:
                if (is_client) {
                    spice_info->client_auth = val;
                } else {
                    spice_info->server_auth = val;
                }
                ti = proto_tree_add_item(tree, hf_common_cap_byte1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                auth_tree = proto_item_add_subtree(ti, ett_auth_tree);
                proto_tree_add_boolean(auth_tree, hf_common_cap_auth_select, tvb, offset, 4, val);
                proto_tree_add_boolean(auth_tree, hf_common_cap_auth_spice, tvb, offset, 4, val);
                proto_tree_add_boolean(auth_tree, hf_common_cap_auth_sasl, tvb, offset, 4, val);

                proto_tree_add_boolean(tree, hf_common_cap_mini_header, tvb, offset, 4, val);
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
                proto_tree_add_text(tree, tvb, offset, 4, "Unknown common capability");
                offset += 4;
                break;
        }
    }
}

static void
dissect_spice_link_capabilities(tvbuff_t *tvb, proto_tree *tree, guint32 offset, const int caps_len, const spice_conversation_t *spice_info)
{
/* TODO: save common and per-channel capabilities in spice_info ? */
    int         i;
    guint32     val;
    proto_item *ti = NULL;
    proto_tree *cap_tree;

    for(i = 0; i != caps_len ; i++) {
        val = tvb_get_letohl(tvb, offset);
        switch (spice_info->channel_type) {
            case SPICE_CHANNEL_PLAYBACK:
                switch (i) {
                    case 0:
                        ti = proto_tree_add_item(tree, hf_common_cap_byte1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                        cap_tree = proto_item_add_subtree(ti, ett_cap_tree);
                        proto_tree_add_boolean(cap_tree, hf_playback_cap_celt, tvb, offset, 4, val);
                        proto_tree_add_boolean(cap_tree, hf_playback_cap_volume, tvb, offset, 4, val);
                        break;
                    default:
                        break;
                }
                break;
            case SPICE_CHANNEL_MAIN:
                switch (i) {
                    case 0:
                        ti = proto_tree_add_item(tree, hf_common_cap_byte1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                        cap_tree = proto_item_add_subtree(ti, ett_cap_tree);
                        proto_tree_add_boolean(cap_tree, hf_main_cap_semi_migrate, tvb, offset, 4, val);
                        proto_tree_add_boolean(cap_tree, hf_main_cap_vm_name_uuid, tvb, offset, 4, val); /*Note: only relevant for client. TODO: dissect only for client */
                        break;
                    default:
                        break;
                }
                break;
            case SPICE_CHANNEL_DISPLAY:
                proto_tree_add_item(tree, hf_display_cap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            case SPICE_CHANNEL_INPUTS:
                proto_tree_add_item(tree, hf_inputs_cap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            case SPICE_CHANNEL_CURSOR:
                proto_tree_add_item(tree, hf_cursor_cap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                break;
            case SPICE_CHANNEL_RECORD:
                switch (i) {
                    case 0:
                        ti = proto_tree_add_item(tree, hf_common_cap_byte1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                        cap_tree = proto_item_add_subtree(ti, ett_cap_tree);
                        proto_tree_add_boolean(cap_tree, hf_record_cap_celt, tvb, offset, 4, val);
                        break;
                    default:
                        break;
                }
                break;
            default:
                proto_tree_add_text(tree, tvb, offset, 0, "Unknown channel - cannot dissect");
                break;
        }
        offset += 4;
    }
}

static void
dissect_spice_link_client_pdu(tvbuff_t *tvb, proto_tree *tree, spice_conversation_t *spice_info)
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
    common_caps_len = tvb_get_letohl(tvb, offset + 6);
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
        ti = proto_tree_add_text(tree, tvb, offset, common_caps_len * 4,
                                 "Client Common Capabilities (%d bytes)",
                                 common_caps_len * 4); /* caps_len multiplied by 4 as length is in UINT32 units   */
        caps_tree = proto_item_add_subtree(ti, ett_link_caps);
        dissect_spice_common_capabilities(tvb, caps_tree, offset, common_caps_len, spice_info, TRUE);
        offset += (common_caps_len * 4);
    }
    if (channel_caps_len > 0) {
        ti = proto_tree_add_text(tree, tvb, offset, channel_caps_len * 4,
                                 "Client Channel-specific Capabilities (%d bytes)",
                                 channel_caps_len * 4); /* caps_len multiplied by 4 as length is in UINT32 units    */
        caps_tree = proto_item_add_subtree(ti, ett_link_caps);
        dissect_spice_link_capabilities(tvb, caps_tree, offset, channel_caps_len, spice_info);
    }
}

static void
dissect_spice_link_server_pdu(tvbuff_t *tvb, proto_tree *tree, spice_conversation_t *spice_info)
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
        proto_tree_add_text(tree, tvb, offset + 4, SPICE_TICKET_PUBKEY_BYTES, "X.509 SubjectPublicKeyInfo (ASN.1)");
        proto_tree_add_item(tree, hf_num_common_caps, tvb, offset + 4 + SPICE_TICKET_PUBKEY_BYTES, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_num_channel_caps, tvb, offset + 8 + SPICE_TICKET_PUBKEY_BYTES, 4, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(tree, hf_caps_offset, tvb, offset + 12 + SPICE_TICKET_PUBKEY_BYTES, 4, ENC_LITTLE_ENDIAN);
    }

    common_caps_len = tvb_get_letohl(tvb, offset + 4 + SPICE_TICKET_PUBKEY_BYTES);
    channel_caps_len = tvb_get_letohl(tvb, offset + 8 + SPICE_TICKET_PUBKEY_BYTES);
    offset += sizeof_SpiceLinkHeader + SPICE_TICKET_PUBKEY_BYTES;

    if (common_caps_len > 0) {
        ti = proto_tree_add_text(tree, tvb, offset, common_caps_len * 4,
                                 "Common Capabilities (%d bytes)",
                                 common_caps_len * 4); /* caps_len multiplied by 4 as length is in UINT32 units */
        caps_tree = proto_item_add_subtree(ti, ett_link_caps);
        dissect_spice_common_capabilities(tvb, caps_tree, offset, common_caps_len, spice_info, FALSE);
        offset += (common_caps_len * 4);
    }
    if (channel_caps_len > 0) {
        ti = proto_tree_add_text(tree, tvb, offset, channel_caps_len * 4,
                                 "Channel Capabilities (%d bytes)",
                                 channel_caps_len * 4); /* caps_len multiplied by 4 as length is in UINT32 units */
        caps_tree = proto_item_add_subtree(ti, ett_link_caps);
        dissect_spice_link_capabilities(tvb, caps_tree, offset, channel_caps_len, spice_info);
    }
}

static int
dissect_spice(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    conversation_t       *conversation;
    spice_conversation_t *spice_info;
    spice_packet_t       *per_packet_info;
    guint32               avail;
    guint32               pdu_len          = 0;
    guint32               offset;
    proto_item           *ti               = NULL;
    proto_tree           *spice_tree       = NULL;
    proto_tree           *spice_data_tree  = NULL;
    gboolean              client_sasl_list = FALSE;
    gboolean              first_record_in_frame;
    guint8                sasl_auth_result;

    conversation = find_or_create_conversation(pinfo);

    spice_info = (spice_conversation_t*)conversation_get_proto_data(conversation, proto_spice);
    if(!spice_info) {
        spice_info = se_alloc0(sizeof(spice_conversation_t));
        spice_info->destport = pinfo->destport;
        spice_info->channel_type = SPICE_CHANNEL_NONE;
        spice_info->next_state = SPICE_LINK_CLIENT;
        spice_info->client_auth = 0;
        spice_info->server_auth = 0;
        spice_info->client_mini_header = FALSE;
        spice_info->server_mini_header = FALSE;
        conversation_add_proto_data(conversation, proto_spice, spice_info);
        conversation_set_dissector(conversation, spice_handle);
    }

    per_packet_info = p_get_proto_data(pinfo->fd, proto_spice);
    if(!per_packet_info) {
        per_packet_info = se_alloc(sizeof(spice_packet_t));
        per_packet_info->state = spice_info->next_state;
        p_add_proto_data(pinfo->fd, proto_spice, per_packet_info);
    }

    col_clear(pinfo->cinfo, COL_INFO);
    first_record_in_frame = TRUE;

    switch (per_packet_info->state) {
        case SPICE_LINK_CLIENT:
            avail = tvb_reported_length(tvb);
            pdu_len = sizeof_SpiceLinkHeader;
            GET_PDU_FROM_OFFSET(0)
            pdu_len = tvb_get_letohl(tvb, 12) + sizeof_SpiceLinkHeader;
            GET_PDU_FROM_OFFSET(0)
            col_set_str(pinfo->cinfo, COL_INFO, "Client link message");
            if (tree) {
                ti = proto_tree_add_item(tree, proto_spice, tvb, 0, pdu_len, ENC_NA);
                spice_tree = proto_item_add_subtree(ti, ett_spice);
            }
            dissect_spice_link_client_pdu(tvb, spice_tree, spice_info);
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
            col_set_str(pinfo->cinfo, COL_INFO, "Server link message");
            col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                         "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
            if (tree) {
                ti = proto_tree_add_item(tree, proto_spice, tvb, 0, pdu_len, ENC_NA);
                spice_tree = proto_item_add_subtree(ti, ett_spice);
            }
            dissect_spice_link_server_pdu(tvb, spice_tree, spice_info);
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
                g_warning("SPICE_CLIENT_AUTH_SELECT: packet from server - expected from client. Packet: %d", pinfo->fd->num);
                break;
            }
            avail = tvb_reported_length(tvb);
            pdu_len = 4;
            GET_PDU_FROM_OFFSET(0)
            col_set_str(pinfo->cinfo, COL_INFO, "Client authentication method selection");
            col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                         "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
            if (tree) {
                ti = proto_tree_add_item(tree, proto_spice, tvb, 0, 4, ENC_NA);
                spice_tree = proto_item_add_subtree(ti, ett_auth_select_client);
                proto_tree_add_item(spice_tree, hf_auth_select_client, tvb, 0, 4, ENC_LITTLE_ENDIAN);
            }
            spice_info->auth_selected = tvb_get_letohl(tvb, 0);
            switch(spice_info->auth_selected) {
                case SPICE_COMMON_CAP_AUTH_SPICE:
                    spice_info->next_state = SPICE_TICKET_CLIENT;
                    break;
                case SPICE_COMMON_CAP_AUTH_SASL:
                    spice_info->next_state = SPICE_SASL_INIT_FROM_SERVER;
                    break;
                default:
                    g_warning("unknown authentication selected");
                    break;
            }
            return 4;
            break;
        case SPICE_SASL_INIT_FROM_SERVER:
            offset = 0;
            avail = tvb_length_remaining(tvb, offset);
            pdu_len = 4;
            GET_PDU_FROM_OFFSET(offset)
            pdu_len = tvb_get_letohl(tvb, offset); /* the length of the following messages */
            if (tree && spice_tree == NULL) {
                ti = proto_tree_add_item(tree, proto_spice, tvb, offset, 4, ENC_NA);
                spice_tree = proto_item_add_subtree(ti, ett_spice);
            }
            col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                         "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
            proto_tree_add_text(spice_tree, tvb, offset, 4, "SASL message length: %u", pdu_len);
            pdu_len += 4;
            GET_PDU_FROM_OFFSET(offset)
            proto_item_set_len(ti, pdu_len);
            col_set_str(pinfo->cinfo, COL_INFO, "SASL supported authentication mechanisms (init from server)");
            proto_tree_add_text(spice_tree, tvb, offset, 4, "Supported authentication mechanisms list length: %u", pdu_len - 4);
            offset += 4;
            proto_tree_add_text(spice_tree, tvb, offset, pdu_len - 4,
                                "Supported authentication mechanisms list: %s", tvb_format_text(tvb, offset, pdu_len - 4));
            offset += (pdu_len - 4);
            spice_info->next_state = SPICE_SASL_START_TO_SERVER;
            return offset;
        case SPICE_SASL_START_TO_SERVER:
            offset = 0;
            while (offset < tvb_reported_length(tvb)) {
                avail = tvb_length_remaining(tvb, offset);
                pdu_len = 4;
                GET_PDU_FROM_OFFSET(offset)
                pdu_len = tvb_get_letohl(tvb, offset); /* the length of the following messages */
                if (tree && spice_tree == NULL) {
                    ti = proto_tree_add_item(tree, proto_spice, tvb, offset, 4, ENC_NA);
                    spice_tree = proto_item_add_subtree(ti, ett_spice);
                }
                col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                             "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
                proto_tree_add_text(spice_tree, tvb, offset, 4, "SASL message length: %u", pdu_len);
                if (pdu_len == 0) {
                    /* meaning, empty PDU - assuming the client_out_list, which may be empty*/
                    col_set_str(pinfo->cinfo, COL_INFO, "SASL authentication (start to server)");
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
                        proto_tree_add_text(spice_tree, tvb, offset, 4, "Selected authentication mechanism length: %u", pdu_len - 4);
                        offset += 4;
                        proto_tree_add_text(spice_tree, tvb, offset, pdu_len - 4,
                                            "Selected authentication mechanism: %s", tvb_format_text(tvb, offset, pdu_len - 4));
                    } else {
                        /* this is the client out list, ending the start from client message */
                         col_set_str(pinfo->cinfo, COL_INFO, "Client out mechanism (start to server)");
                         proto_tree_add_text(spice_tree, tvb, offset, 4, "Client out mechanism length: %u", pdu_len - 4);
                         offset += 4;
                         proto_tree_add_text(spice_tree, tvb, offset, pdu_len - 4,
                                             "Selected client out mechanism: %s", tvb_format_text(tvb, offset, pdu_len - 4));
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
                avail = tvb_length_remaining(tvb, offset);
                pdu_len = 4;
                GET_PDU_FROM_OFFSET(offset)
                pdu_len = tvb_get_letohl(tvb, offset); /* the length of the following messages */
                if (tree && spice_tree == NULL) {
                    ti = proto_tree_add_item(tree, proto_spice, tvb, offset, pdu_len + 4, ENC_NA);
                    spice_tree = proto_item_add_subtree(ti, ett_spice);
                }
                col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                             "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
                if (per_packet_info->state == SPICE_SASL_START_FROM_SERVER) {
                    col_set_str(pinfo->cinfo, COL_INFO, "SASL authentication (start from server)");
                } else {
                    col_set_str(pinfo->cinfo, COL_INFO, "SASL authentication (step from server)");
                }
                proto_tree_add_text(spice_tree, tvb, offset, 4, "SASL message length: %u", pdu_len);
                if (pdu_len == 0) { /* meaning, empty PDU */
                offset += 4; /* only the size field.*/
                } else {
                    pdu_len += 4;
                    GET_PDU_FROM_OFFSET(offset)
                    offset += 4;
                    proto_tree_add_text(spice_tree, tvb, offset, pdu_len - 4, "SASL authentication data (%u bytes): %s", pdu_len - 4, tvb_format_stringzpad(tvb, offset, pdu_len - 4));
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
            avail = tvb_length_remaining(tvb, offset);
            if (avail >= 1) {
                if (tree && spice_tree == NULL) {
                    ti = proto_tree_add_item(tree, proto_spice, tvb, offset, 1, ENC_NA);
                    spice_tree = proto_item_add_subtree(ti, ett_spice);
                }
                col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                             "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
                col_set_str(pinfo->cinfo, COL_INFO, "SASL authentication - result from server");
                sasl_auth_result = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(spice_tree, hf_spice_sasl_auth_result, tvb, offset, 1, ENC_NA);

                if (per_packet_info->state == SPICE_SASL_START_FROM_SERVER_CONT) {
                    /* if we are in the sasl start, and can continue */
                    if (sasl_auth_result == 0) { /* 0 = continue */
                        spice_info->next_state = SPICE_SASL_STEP_TO_SERVER;
                    } else {
                        g_warning("SPICE_SASL_START_FROM_SERVER_CONT and sasl_auth_result is %d, packet %d",
                                  sasl_auth_result, pinfo->fd->num);
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
                avail = tvb_length_remaining(tvb, offset);
                pdu_len = 4;
                GET_PDU_FROM_OFFSET(offset)
                pdu_len = tvb_get_letohl(tvb, offset); /* the length of the following messages */
                if (tree && spice_tree == NULL) {
                    ti = proto_tree_add_item(tree, proto_spice, tvb, offset, 4, ENC_NA);
                    spice_tree = proto_item_add_subtree(ti, ett_spice);
                }
                col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                             "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
                proto_tree_add_text(spice_tree, tvb, offset, 4, "SASL message length: %u", pdu_len);
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
                    proto_tree_add_text(spice_tree, tvb, offset, 4, "clientout length: %u", pdu_len - 4);
                    offset += 4;
                    proto_tree_add_text(spice_tree, tvb, offset, pdu_len - 4,
                                        "clientout list: %s", tvb_format_text(tvb, offset, pdu_len - 4));
                    spice_info->next_state = SPICE_SASL_STEP_FROM_SERVER;
                    offset += (pdu_len - 4);
                }
            }
            return pdu_len;
            break;
        case SPICE_SASL_DATA:
            offset = 0;
            while (offset < tvb_reported_length(tvb)) {
                avail = tvb_length_remaining(tvb, offset);
                pdu_len = 4;
                GET_PDU_FROM_OFFSET(offset)
                pdu_len = tvb_get_ntohl(tvb, offset); /* the length of the following messages */
                if (tree && spice_tree == NULL) {
                    ti = proto_tree_add_item(tree, proto_spice, tvb, offset, pdu_len, ENC_NA);
                    spice_tree = proto_item_add_subtree(ti, ett_spice);
                }
                proto_tree_add_text(spice_tree, tvb, offset, 4, "SASL message length: %u", pdu_len);
                if (pdu_len == 0) { /* meaning, empty PDU */
                    return 4; /* only the size field.*/
                } else {
                    pdu_len += 4;
                }
                GET_PDU_FROM_OFFSET(offset)
                proto_item_set_len(ti, pdu_len);
                col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                             "Spice %s (SASL wrapped)", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
                col_set_str(pinfo->cinfo, COL_INFO, "SASL wrapped Spice message");

                offset += 4;
                proto_tree_add_text(spice_tree, tvb, offset, pdu_len - 4, "SASL data (%u bytes)", pdu_len - 4);
                offset += (pdu_len - 4);
            }
            return pdu_len;
            break;
        case SPICE_DATA:
            offset = 0;
            while (offset < tvb_reported_length(tvb)) {
                avail = tvb_length_remaining(tvb, offset);
                if (spice_info->client_mini_header && spice_info->server_mini_header) {
                    pdu_len = sizeof_SpiceMiniDataHeader;
                    GET_PDU_FROM_OFFSET(offset)
                    pdu_len = tvb_get_letohl(tvb, offset + 2);
                    pdu_len += sizeof_SpiceMiniDataHeader;
                } else {
                    pdu_len = sizeof_SpiceDataHeader;
                    GET_PDU_FROM_OFFSET(offset)
                    pdu_len = tvb_get_letohl(tvb, offset + 14); /* this is actually the sub-message list size */
                    if (pdu_len == 0) {
                        /* if there are no sub-messages, get the usual message body size.   */
                        /* Note that we do not dissect properly yet sub-messages - but they */
                        /* are not used in the protcol either */
                        pdu_len = tvb_get_letohl(tvb, offset + 10);
                    } else {
                        pdu_len = tvb_get_letohl(tvb, offset + 10);
                    }
                    pdu_len += sizeof_SpiceDataHeader; /* +sizeof_SpiceDataHeader since you need to exclude the SPICE   */
                                                   /* data header, which is sizeof_SpiceDataHeader (18) bytes long) */
                }
                GET_PDU_FROM_OFFSET(offset)
                col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                             "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
                if (!first_record_in_frame) {
                    /* if it's not the first dissected PDU, we want in COL_INFO to have: "PDU_type_A, PDU_typeB, PDU_typeC, etc. */
                    col_append_str(pinfo->cinfo, COL_INFO, ", ");
                }
                if (tree && spice_data_tree == NULL) {
                    ti = proto_tree_add_item(tree, proto_spice, tvb, offset, pdu_len, ENC_NA);
                    spice_data_tree = proto_item_add_subtree(ti, ett_data);
                }
                if (spice_info->destport == pinfo->destport) { /* client to server traffic */
                     offset = dissect_spice_data_client_pdu(tvb, spice_data_tree, pinfo, spice_info, offset);
                 } else { /* server to client traffic */
                     offset = dissect_spice_data_server_pdu(tvb, spice_data_tree, pinfo, spice_info, offset, pdu_len);
                 }
                first_record_in_frame = FALSE;
             }
             return offset;
            break;
        case SPICE_TICKET_CLIENT:
            if (spice_info->destport != pinfo->destport) /* ignore anything from the server, wait for ticket from client */
                break;
            avail = tvb_reported_length(tvb);
            pdu_len = 128;
            GET_PDU_FROM_OFFSET(0)
            col_set_str(pinfo->cinfo, COL_INFO, "Client ticket");
            col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                         "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
            if (tree) {
                ti = proto_tree_add_item(tree, proto_spice, tvb, 0, 128, ENC_NA);
                spice_tree = proto_item_add_subtree(ti, ett_ticket_client);
                proto_tree_add_item(spice_tree, hf_ticket_client, tvb, 0, 128, ENC_NA);
            }
            spice_info->next_state = SPICE_TICKET_SERVER;
            return 128;
            break;
        case SPICE_TICKET_SERVER:
            if (spice_info->destport != pinfo->srcport) /* ignore anything from the client, wait for ticket from server */
                break;
            avail = tvb_reported_length(tvb);
            pdu_len = 4;
            GET_PDU_FROM_OFFSET(0)
            col_set_str(pinfo->cinfo, COL_INFO, "Server ticket");
            col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
                         "Spice %s", val_to_str_const(spice_info->channel_type,channel_types_vs, "Unknown"));
            if (tree) {
                ti = proto_tree_add_item(tree, proto_spice, tvb, 0, 4, ENC_NA);
                spice_tree = proto_item_add_subtree(ti, ett_ticket_server);
                proto_tree_add_item(spice_tree, hf_ticket_server, tvb, 0, 4, ENC_LITTLE_ENDIAN);
            }
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
test_spice_protocol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    if (tvb_reported_length(tvb) >= 4 && tvb_get_ntohl(tvb, 0) == SPICE_MAGIC) {
        dissect_spice(tvb, pinfo, tree);
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
            FT_UINT32, BASE_DEC, VALS(spice_error_codes_vs), 0x0,
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
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ticket_server,
          { "Link result", "spice.ticket_server",
            FT_UINT32, BASE_DEC, VALS(spice_error_codes_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_auth_select_client,
          { "Authentication selected by client", "spice.auth_select_client",
            FT_UINT32, BASE_DEC, VALS(spice_auth_select_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_common_cap_byte1,
          { "Capabilitities", "spice.common_cap_byte1",
            FT_NONE, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_common_cap_auth_select,
          { "Auth Selection", "spice.common_cap_auth_select",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_COMMON_CAP_PROTOCOL_AUTH_SELECTION_MASK,
            NULL, HFILL }
        },
        { &hf_common_cap_auth_spice,
          { "Auth Spice", "spice.common_cap_auth_spice",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_COMMON_CAP_AUTH_SPICE_MASK,
            NULL, HFILL }
        },
        { &hf_common_cap_auth_sasl,
          { "Auth SASL", "spice.common_cap_auth_sasl",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_COMMON_CAP_AUTH_SASL_MASK,
            NULL, HFILL }
        },
        { &hf_common_cap_mini_header,
          { "Mini Header", "spice.common_cap_mini_header",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), SPICE_COMMON_CAP_MINI_HEADER_MASK,
            NULL, HFILL }
        },
        { &hf_playback_cap_celt,
          { "CELT 0.5.1 playback channel support", "spice.playback_cap_celt",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_PLAYBACK_CAP_CELT_0_5_1_MASK,
            NULL, HFILL }
        },
        { &hf_playback_cap_volume,
          { "Volume playback channel support", "spice.playback_cap_volume",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_PLAYBACK_CAP_VOLUME_MASK,
            NULL, HFILL }
        },
        { &hf_record_cap_celt,
          { "CELT 0.5.1 record channel support", "spice.record_cap_celt",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_RECORD_CAP_CELT_0_5_1_MASK,
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
        { &hf_main_cap_semi_migrate,
          { "Semi-seamless migratation capability", "spice.main_cap_semi_migrate",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_MAIN_CAP_SEMI_SEAMLESS_MIGRATE_MASK,
            NULL, HFILL }
        },
        { &hf_main_cap_vm_name_uuid,
          { "VM name and UUID messages capability", "spice.main_cap_vm_name_uuid",
            FT_BOOLEAN, 3, TFS(&tfs_set_notset), SPICE_MAIN_CAP_VM_NAME_UUID_MASK,
            NULL, HFILL }
        },
        { &hf_display_cap,
          { "Display channelcapability", "spice.display_cap",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_playback_record_mode_timstamp,
          { "Timestamp", "spice.timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_playback_record_mode,
          { "Mode", "spice.mode",
            FT_UINT16, BASE_DEC, VALS(playback_mode_vals), 0x0,
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
            FT_UINT8, BASE_DEC, VALS(clip_types_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_Mask_flag,
          { "Mask flag", "spice.mask_flag",
            FT_UINT8, BASE_DEC, VALS(Mask_flags_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_Mask_bitmap,
          { "Bitmap address", "spice.mask_bitmap",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_rop_descriptor,
          { "ROP descriptor", "spice.display_rop_descriptor",
            FT_UINT16, BASE_HEX, VALS(rop_descriptor_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_display_scale_mode,
          { "Scale mode", "spice.scale_mode",
            FT_UINT8, BASE_DEC, VALS(scale_mode_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_red_ping_id,
          { "Ping ID", "spice.ping_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_red_timestamp,
          { "timestamp", "spice.timestamp",
            FT_UINT64, BASE_HEX, NULL, 0x0,
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
            FT_UINT8, BASE_DEC, VALS(image_type_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_image_desc_flags,
          { "Flags", "spice.image_flags",
            FT_UINT8, BASE_HEX, VALS(image_flags_vs), 0x0,
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
          { "Cursor trail visiblity", "spice.cursor_trail_visible",
            FT_UINT8, BASE_DEC, VALS(cursor_visible_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_unique,
          { "Cursor unique ID", "spice._cursor_unique",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cursor_type,
          { "Cursor type", "spice.cursor_type",
            FT_UINT8, BASE_HEX, VALS(cursor_type_vs), 0x0,
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
            FT_UINT16, BASE_HEX, VALS(cursor_flags_vs), 0x0,
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
            FT_UINT8, BASE_DEC, VALS(brush_types_vs), 0x0,
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
          { "Pixmap palettte pointer", "spice.pixmap_palette_address",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pixmap_format,
          { "Pixmap format", "spice.pixmap_format",
            FT_UINT8, BASE_DEC, VALS(Pixmap_types_vs), 0x0,
            NULL, HFILL }
        },
        { &hf_pixmap_flags,
          { "Pixmap flags", "spice.pixmap_flags",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_keyboard_bits, /* FIXME - flags */
          { "Keyboard led bits", "spice.keyboard_bits",
            FT_UINT16, BASE_HEX, VALS(input_modifiers_types), 0x0,
            NULL, HFILL }
        },
        { &hf_rectlist_size,
          { "RectList size", "spice.rectlist_size",
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
        { &hf_supported_mouse_modes, /* FIXME: bitmask */
          { "Supported mouse modes", "spice.supported_mouse_modes",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_current_mouse_mode,
          { "Current mouse mode", "spice.current_mouse_mode",
            FT_UINT32, BASE_DEC, VALS(spice_mouse_modes_vs), 0x0,
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
            FT_UINT32, BASE_HEX, NULL, 0x0,
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
        { &hf_display_stream_id,
          { "Stream ID", "spice.display_stream_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_flags,
          { "Stream flags", "spice.display_stream_flags",
            FT_UINT8, BASE_DEC, VALS(stream_flags), 0x0,
            NULL, HFILL }
        },
        { &hf_display_stream_codec_type,
          { "Stream codec type", "spice.display_stream_codec_type",
            FT_UINT32, BASE_DEC, VALS(stream_codec_types), 0x0,
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
            FT_UINT32, BASE_DEC, NULL, 0x0,
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
          { "Agent Tokes", "spice.main_agent_tokens",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_protocol,
          { "Agent Protocol version", "spice.main_agent_protocol",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_agent_type,
          { "Agent Type", "spice.main_agent_type",
            FT_UINT32, BASE_DEC, VALS(agent_message_type), 0x0,
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
        { &hf_vm_uuid,
          { "VM UUID", "spice.vm_uuid",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vm_name,
          { "VM Name", "spice.vm_name",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
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
        &ett_inputs_client,
        &ett_rectlist,
        &ett_inputs_server,
        &ett_record_client,
        &ett_main_client,
        &ett_spice_agent,
        &ett_auth_tree,
        &ett_cap_tree
    };

    /* Register the protocol name and description */
    proto_spice = proto_register_protocol("Spice protocol",
                                          "Spice", "spice");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_spice, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_spice(void)
{
    spice_handle = new_create_dissector_handle(dissect_spice, proto_spice);
    dissector_add_handle("tcp.port", spice_handle);   /* for "decode as" */
    heur_dissector_add("tcp", test_spice_protocol, proto_spice);
    jpeg_handle = find_dissector("image-jfif");
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

