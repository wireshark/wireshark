/* packet-websocket.c
 * Routines for WebSocket dissection
 * Copyright 2012, Alexis La Goutte <alexis.lagoutte@gmail.com>
 *           2015, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <wsutil/strtoi.h>

#include "packet-http.h"
#include "packet-tcp.h"

#ifdef HAVE_ZLIB
#define ZLIB_CONST
#include <zlib.h>
#endif

/*
 * The information used comes from:
 * RFC6455: The WebSocket Protocol
 * http://www.iana.org/assignments/websocket (last updated 2012-04-12)
 */

void proto_register_websocket(void);
void proto_reg_handoff_websocket(void);

static dissector_handle_t websocket_handle;
static dissector_handle_t text_lines_handle;
static dissector_handle_t json_handle;
static dissector_handle_t sip_handle;

#define WEBSOCKET_NONE 0
#define WEBSOCKET_TEXT 1
#define WEBSOCKET_JSON 2
#define WEBSOCKET_SIP 3

static gint  pref_text_type             = WEBSOCKET_NONE;
static gboolean pref_decompress         = TRUE;

typedef struct {
  const char   *subprotocol;
  guint16       server_port;
  gboolean      permessage_deflate;
#ifdef HAVE_ZLIB
  gboolean      permessage_deflate_ok;
  gint8         server_wbits;
  gint8         client_wbits;
  z_streamp     server_take_over_context;
  z_streamp     client_take_over_context;
#endif
} websocket_conv_t;

#ifdef HAVE_ZLIB
typedef struct {
  guint8 *decompr_payload;
  guint decompr_len;
} websocket_packet_t;
#endif

/* Initialize the protocol and registered fields */
static int proto_websocket = -1;
static int proto_http = -1;

static int hf_ws_fin = -1;
static int hf_ws_reserved = -1;
static int hf_ws_pmc = -1;
static int hf_ws_opcode = -1;
static int hf_ws_mask = -1;
static int hf_ws_payload_length = -1;
static int hf_ws_payload_length_ext_16 = -1;
static int hf_ws_payload_length_ext_64 = -1;
static int hf_ws_masking_key = -1;
static int hf_ws_payload = -1;
static int hf_ws_masked_payload = -1;
static int hf_ws_payload_continue = -1;
static int hf_ws_payload_close = -1;
static int hf_ws_payload_close_status_code = -1;
static int hf_ws_payload_close_reason = -1;
static int hf_ws_payload_ping = -1;
static int hf_ws_payload_pong = -1;
static int hf_ws_payload_unknown = -1;

static gint ett_ws = -1;
static gint ett_ws_pl = -1;
static gint ett_ws_mask = -1;
static gint ett_ws_control_close = -1;

static expert_field ei_ws_payload_unknown = EI_INIT;
static expert_field ei_ws_decompression_failed = EI_INIT;

#define WS_CONTINUE 0x0
#define WS_TEXT     0x1
#define WS_BINARY   0x2
#define WS_CLOSE    0x8
#define WS_PING     0x9
#define WS_PONG     0xA

static const value_string ws_opcode_vals[] = {
  { WS_CONTINUE, "Continuation" },
  { WS_TEXT, "Text" },
  { WS_BINARY, "Binary" },
  { WS_CLOSE, "Connection Close" },
  { WS_PING, "Ping" },
  { WS_PONG, "Pong" },
  { 0, NULL}
};

#define MASK_WS_FIN 0x80
#define MASK_WS_RSV 0x70
#define MASK_WS_RSV1 0x40
#define MASK_WS_OPCODE 0x0F
#define MASK_WS_MASK 0x80
#define MASK_WS_PAYLOAD_LEN 0x7F

static const value_string ws_close_status_code_vals[] = {
  { 1000, "Normal Closure" },
  { 1001, "Going Away" },
  { 1002, "Protocol error" },
  { 1003, "Unsupported Data" },
  { 1004, "---Reserved----" },
  { 1005, "No Status Rcvd" },
  { 1006, "Abnormal Closure" },
  { 1007, "Invalid frame payload data" },
  { 1008, "Policy Violation" },
  { 1009, "Message Too Big" },
  { 1010, "Mandatory Ext." },
  { 1011, "Internal Server" },
  { 1015, "TLS handshake" },
  { 0,    NULL}
};

static dissector_table_t port_subdissector_table;
static dissector_table_t protocol_subdissector_table;
static heur_dissector_list_t heur_subdissector_list;

#define MAX_UNMASKED_LEN (1024 * 256)
static tvbuff_t *
tvb_unmasked(tvbuff_t *tvb, packet_info *pinfo, const guint offset, guint payload_length, const guint8 *masking_key)
{

  gchar        *data_unmask;
  guint         i;
  const guint8 *data_mask;
  guint         unmasked_length = payload_length > MAX_UNMASKED_LEN ? MAX_UNMASKED_LEN : payload_length;

  data_unmask = (gchar *)wmem_alloc(pinfo->pool, unmasked_length);
  data_mask   = tvb_get_ptr(tvb, offset, unmasked_length);
  /* Unmasked(XOR) Data... */
  for(i=0; i < unmasked_length; i++) {
    data_unmask[i] = data_mask[i] ^ masking_key[i%4];
  }

  return tvb_new_real_data(data_unmask, unmasked_length, payload_length);
}

#ifdef HAVE_ZLIB
static gint8
websocket_extract_wbits(const gchar *str)
{
  guint8 wbits;
  const gchar *end;

  if (str && ws_strtou8(str, &end, &wbits) &&
      (*end == '\0' || strchr(";\t ", *end))) {
    if (wbits < 8) {
      wbits = 8;
    } else if (wbits > 15) {
      wbits = 15;
    }
  } else {
    wbits = 15;
  }
  return -wbits;
}

static void *
websocket_zalloc(void *opaque _U_, unsigned int items, unsigned int size)
{
  return wmem_alloc(wmem_file_scope(), items*size);
}

static void
websocket_zfree(void *opaque _U_, void *addr)
{
  wmem_free(wmem_file_scope(), addr);
}

static z_streamp
websocket_init_z_stream_context(gint8 wbits)
{
  z_streamp z_strm = wmem_new0(wmem_file_scope(), z_stream);

  z_strm->zalloc = websocket_zalloc;
  z_strm->zfree = websocket_zfree;

  if (inflateInit2(z_strm, wbits) != Z_OK) {
    inflateEnd(z_strm);
    wmem_free(wmem_file_scope(), z_strm);
    return NULL;
  }
  return z_strm;
}

/*
 * Decompress the given buffer using the given zlib context. On success, the
 * (possibly empty) buffer is stored as "proto data" and TRUE is returned.
 * Otherwise FALSE is returned.
 */
static gboolean
websocket_uncompress(tvbuff_t *tvb, packet_info *pinfo, z_streamp z_strm, tvbuff_t **uncompressed_tvb, guint32 key)
{
  /*
   * Decompression a message: append "0x00 0x00 0xff 0xff" to the end of
   * message, then apply DEFLATE to the result.
   * https://tools.ietf.org/html/rfc7692#section-7.2.2
   */
  guint8   *decompr_payload = NULL;
  guint     decompr_len = 0;
  guint     compr_len, decompr_buf_len;
  guint8   *compr_payload, *decompr_buf;
  gint      err;

  compr_len = tvb_captured_length(tvb) + 4;
  compr_payload = (guint8 *)wmem_alloc(wmem_packet_scope(), compr_len);
  tvb_memcpy(tvb, compr_payload, 0, compr_len-4);
  compr_payload[compr_len-4] = compr_payload[compr_len-3] = 0x00;
  compr_payload[compr_len-2] = compr_payload[compr_len-1] = 0xff;
  decompr_buf_len = 2*compr_len;
  decompr_buf = (guint8 *)wmem_alloc(wmem_packet_scope(), decompr_buf_len);

  z_strm->next_in = compr_payload;
  z_strm->avail_in = compr_len;
  /* Decompress all available data. */
  do {
    z_strm->next_out = decompr_buf;
    z_strm->avail_out = decompr_buf_len;

    err = inflate(z_strm, Z_SYNC_FLUSH);

    if (err == Z_OK || err == Z_STREAM_END || err == Z_BUF_ERROR) {
      guint avail_bytes = decompr_buf_len - z_strm->avail_out;
      if (avail_bytes) {
        decompr_payload = (guint8 *)wmem_realloc(wmem_file_scope(), decompr_payload,
                                                 decompr_len + avail_bytes);
        memcpy(&decompr_payload[decompr_len], decompr_buf, avail_bytes);
        decompr_len += avail_bytes;
      }
    }
  } while (err == Z_OK);

  if (err == Z_STREAM_END || err == Z_BUF_ERROR) {
    /* Data was (partially) uncompressed. */
    websocket_packet_t *pkt_info = wmem_new0(wmem_file_scope(), websocket_packet_t);
    if (decompr_len > 0) {
      pkt_info->decompr_payload = decompr_payload;
      pkt_info->decompr_len = decompr_len;
      *uncompressed_tvb = tvb_new_real_data(decompr_payload, decompr_len, decompr_len);
    }
    p_add_proto_data(wmem_file_scope(), pinfo, proto_websocket, key, pkt_info);
    return TRUE;
  } else {
    /* decompression failed */
    wmem_free(wmem_file_scope(), decompr_payload);
    return FALSE;
  }
}
#endif

static void
dissect_websocket_control_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 opcode)
{
  proto_item         *ti;
  proto_tree         *subtree;
  const guint         offset = 0, length = tvb_reported_length(tvb);

  switch (opcode) {
    case WS_CLOSE: /* Close */
      ti = proto_tree_add_item(tree, hf_ws_payload_close, tvb, offset, length, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_ws_control_close);
      /* Close frame MAY contain a body. */
      if (length >= 2) {
        proto_tree_add_item(subtree, hf_ws_payload_close_status_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        if (length > 2)
          proto_tree_add_item(subtree, hf_ws_payload_close_reason, tvb, offset+2, length-2, ENC_UTF_8|ENC_NA);
      }
      break;

    case WS_PING: /* Ping */
      proto_tree_add_item(tree, hf_ws_payload_ping, tvb, offset, length, ENC_NA);
      break;

    case WS_PONG: /* Pong */
      proto_tree_add_item(tree, hf_ws_payload_pong, tvb, offset, length, ENC_NA);
      break;

    default: /* Unknown */
      ti = proto_tree_add_item(tree, hf_ws_payload_unknown, tvb, offset, length, ENC_NA);
      expert_add_info_format(pinfo, ti, &ei_ws_payload_unknown, "Dissector for Websocket Opcode (%d)"
        " code not implemented, Contact Wireshark developers"
        " if you want this supported", opcode);
      break;
  }
}

static void
dissect_websocket_data_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *pl_tree, guint8 opcode, websocket_conv_t *websocket_conv, gboolean pmc _U_, gint raw_offset _U_)
{
  proto_item         *ti;
  dissector_handle_t  handle = NULL;
  heur_dtbl_entry_t  *hdtbl_entry;

  /* try to find a dissector which accepts the data. */
  if (websocket_conv->subprotocol) {
    handle = dissector_get_string_handle(protocol_subdissector_table, websocket_conv->subprotocol);
  } else if (websocket_conv->server_port) {
    handle = dissector_get_uint_handle(port_subdissector_table, websocket_conv->server_port);
  }

#ifdef HAVE_ZLIB
  if (websocket_conv->permessage_deflate_ok && pmc) {
    tvbuff_t   *uncompressed = NULL;
    gboolean    uncompress_ok = FALSE;

    if (!PINFO_FD_VISITED(pinfo)) {
      z_streamp z_strm;
      gint8 wbits;

      if (pinfo->destport == websocket_conv->server_port) {
        z_strm = websocket_conv->server_take_over_context;
        wbits = websocket_conv->server_wbits;
      } else {
        z_strm = websocket_conv->client_take_over_context;
        wbits = websocket_conv->client_wbits;
      }

      if (z_strm) {
        uncompress_ok = websocket_uncompress(tvb, pinfo, z_strm, &uncompressed, raw_offset);
      } else {
        /* no context take over, initialize a new context */
        z_strm = wmem_new0(wmem_packet_scope(), z_stream);
        if (inflateInit2(z_strm, wbits) == Z_OK) {
          uncompress_ok = websocket_uncompress(tvb, pinfo, z_strm, &uncompressed, raw_offset);
        }
        inflateEnd(z_strm);
      }
    } else {
      websocket_packet_t *pkt_info =
          (websocket_packet_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_websocket, raw_offset);
      if (pkt_info) {
        uncompress_ok = TRUE;
        if (pkt_info->decompr_len > 0) {
          uncompressed = tvb_new_real_data(pkt_info->decompr_payload, pkt_info->decompr_len, pkt_info->decompr_len);
        }
      }
    }

    if (!uncompress_ok) {
      proto_tree_add_expert(tree, pinfo, &ei_ws_decompression_failed, tvb, 0, -1);
      return;
    }
    if (uncompressed) {
      add_new_data_source(pinfo, uncompressed, "Decompressed payload");
      tvb = uncompressed;
    }
  }
#endif

  if (handle) {
    call_dissector_only(handle, tvb, pinfo, tree, NULL);
    return; /* handle found, assume dissector took care of it. */
  } else if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, NULL)) {
    return; /* heuristics dissector handled it. */
  }

  /* no dissector wanted it, try to print something appropriate. */
  switch (opcode) {
    case WS_TEXT: /* Text */
    {
      const gchar  *saved_match_string = pinfo->match_string;

      pinfo->match_string = NULL;
      switch (pref_text_type) {
      case WEBSOCKET_TEXT:
      case WEBSOCKET_NONE:
      default:
        /* Assume that most text protocols are line-based. */
        call_dissector(text_lines_handle, tvb, pinfo, tree);
        break;
      case WEBSOCKET_JSON:
        call_dissector(json_handle, tvb, pinfo, tree);
        break;
      case WEBSOCKET_SIP:
        call_dissector(sip_handle, tvb, pinfo, tree);
        break;
      }
      pinfo->match_string = saved_match_string;
    }
    break;

    case WS_BINARY: /* Binary */
      call_data_dissector(tvb, pinfo, tree);
      break;

    default: /* Unknown */
      ti = proto_tree_add_item(pl_tree, hf_ws_payload_unknown, tvb, 0, -1, ENC_NA);
      expert_add_info_format(pinfo, ti, &ei_ws_payload_unknown, "Dissector for Websocket Opcode (%d)"
        " code not implemented, Contact Wireshark developers"
        " if you want this supported", opcode);
      break;
  }
}

static void
websocket_parse_extensions(websocket_conv_t *websocket_conv, const char *str)
{
  /*
   * Grammar for the header:
   *
   *    Sec-WebSocket-Extensions = extension-list
   *    extension-list = 1#extension
   *    extension = extension-token *( ";" extension-param )
   *    extension-token = registered-token
   *    registered-token = token
   *    extension-param = token [ "=" (token | quoted-string) ]
   */

  /*
   * RFC 7692 permessage-deflate parsing.
   */

  websocket_conv->permessage_deflate = !!strstr(str, "permessage-deflate");
#ifdef HAVE_ZLIB
  websocket_conv->permessage_deflate_ok = pref_decompress &&
       websocket_conv->permessage_deflate;
  if (websocket_conv->permessage_deflate_ok) {
    websocket_conv->server_wbits =
        websocket_extract_wbits(strstr(str, "server_max_window_bits="));
    if (!strstr(str, "server_no_context_takeover")) {
      websocket_conv->server_take_over_context =
          websocket_init_z_stream_context(websocket_conv->server_wbits);
    }
    websocket_conv->client_wbits =
        websocket_extract_wbits(strstr(str, "client_max_window_bits="));
    if (!strstr(str, "client_no_context_takeover")) {
      websocket_conv->client_take_over_context =
          websocket_init_z_stream_context(websocket_conv->client_wbits);
    }
  }
#endif
}

static void
dissect_websocket_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ws_tree, guint8 opcode, websocket_conv_t *websocket_conv, gboolean pmc, gint raw_offset)
{
  const guint         offset = 0, length = tvb_reported_length(tvb);
  proto_item         *ti;
  proto_tree         *pl_tree;
  tvbuff_t           *tvb_appdata;

  /* Payload */
  ti = proto_tree_add_item(ws_tree, hf_ws_payload, tvb, offset, length, ENC_NA);
  pl_tree = proto_item_add_subtree(ti, ett_ws_pl);

  /* Extension Data */
  /* TODO: Add dissector of Extension (not extension available for the moment...) */


  /* Application Data */
  if (opcode == WS_CONTINUE) {
    proto_tree_add_item(tree, hf_ws_payload_continue, tvb, offset, length, ENC_NA);
    /* TODO: Add Fragmentation support (needs FIN bit)
     * https://tools.ietf.org/html/rfc6455#section-5.4 */
    return;
  }
  /* Right now this is exactly the same, this may change when exts. are added.
  tvb_appdata = tvb_new_subset_length_caplen(tvb, offset, length, length);
  */
  tvb_appdata = tvb;

  if (opcode & 8) { /* Control frames have MSB set. */
    dissect_websocket_control_frame(tvb_appdata, pinfo, pl_tree, opcode);
  } else {
    dissect_websocket_data_frame(tvb_appdata, pinfo, tree, pl_tree, opcode, websocket_conv, pmc, raw_offset);
  }
}


static int
dissect_websocket_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item   *ti, *ti_len;
  guint8        fin, opcode;
  gboolean      mask;
  guint         short_length, payload_length;
  guint         payload_offset, mask_offset;
  proto_tree   *ws_tree;
  const guint8 *masking_key = NULL;
  tvbuff_t     *tvb_payload;
  conversation_t *conv;
  websocket_conv_t *websocket_conv;
  gboolean      pmc = FALSE;

  /*
   * If this is a new Websocket session, try to parse HTTP Sec-Websocket-*
   * headers once.
   */
  conv = find_or_create_conversation(pinfo);
  websocket_conv = (websocket_conv_t *)conversation_get_proto_data(conv, proto_websocket);
  if (!websocket_conv) {
    websocket_conv = wmem_new0(wmem_file_scope(), websocket_conv_t);

    http_conv_t *http_conv = (http_conv_t *)conversation_get_proto_data(conv, proto_http);
    if (http_conv) {
      websocket_conv->subprotocol = http_conv->websocket_protocol;
      websocket_conv->server_port = http_conv->server_port;
      if ( http_conv->websocket_extensions) {
        websocket_parse_extensions(websocket_conv, http_conv->websocket_extensions);
      }
    }

    conversation_add_proto_data(conv, proto_websocket, websocket_conv);
  }

  short_length = tvb_get_guint8(tvb, 1) & MASK_WS_PAYLOAD_LEN;
  mask_offset = 2;
  if (short_length == 126) {
    payload_length = tvb_get_ntohs(tvb, 2);
    mask_offset += 2;
  } else if (short_length == 127) {
    /* warning C4244: '=' : conversion from 'guint64' to 'guint ', possible loss of data */
    payload_length = (guint)tvb_get_ntoh64(tvb, 2);
    mask_offset += 8;
  } else {
    payload_length = short_length;
  }

  /* Mask */
  mask = (tvb_get_guint8(tvb, 1) & MASK_WS_MASK) != 0;
  payload_offset = mask_offset + (mask ? 4 : 0);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "WebSocket");
  col_set_str(pinfo->cinfo, COL_INFO, "WebSocket");

  ti = proto_tree_add_item(tree, proto_websocket, tvb, 0, payload_offset, ENC_NA);
  ws_tree = proto_item_add_subtree(ti, ett_ws);

  /* Flags */
  proto_tree_add_item(ws_tree, hf_ws_fin, tvb, 0, 1, ENC_NA);
  fin = (tvb_get_guint8(tvb, 0) & MASK_WS_FIN) >> 4;
  proto_tree_add_item(ws_tree, hf_ws_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);
  if (websocket_conv->permessage_deflate) {
    /* RSV1 is Per-Message Compressed bit (RFC 7692). */
    pmc = !!(tvb_get_guint8(tvb, 0) & MASK_WS_RSV1);
    proto_tree_add_item(ws_tree, hf_ws_pmc, tvb, 0, 1, ENC_BIG_ENDIAN);
  }

  /* Opcode */
  proto_tree_add_item(ws_tree, hf_ws_opcode, tvb, 0, 1, ENC_BIG_ENDIAN);
  opcode = tvb_get_guint8(tvb, 0) & MASK_WS_OPCODE;
  col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str_const(opcode, ws_opcode_vals, "Unknown Opcode"));
  col_append_str(pinfo->cinfo, COL_INFO, fin ? " [FIN]" : " ");

  /* Add Mask bit to the tree */
  proto_tree_add_item(ws_tree, hf_ws_mask, tvb, 1, 1, ENC_NA);
  col_append_str(pinfo->cinfo, COL_INFO, mask ? " [MASKED]" : " ");

  /* (Extended) Payload Length */
  ti_len = proto_tree_add_item(ws_tree, hf_ws_payload_length, tvb, 1, 1, ENC_BIG_ENDIAN);
  if (short_length == 126) {
    proto_item_append_text(ti_len, " Extended Payload Length (16 bits)");
    proto_tree_add_item(ws_tree, hf_ws_payload_length_ext_16, tvb, 2, 2, ENC_BIG_ENDIAN);
  }
  else if (short_length == 127) {
    proto_item_append_text(ti_len, " Extended Payload Length (64 bits)");
    proto_tree_add_item(ws_tree, hf_ws_payload_length_ext_64, tvb, 2, 8, ENC_BIG_ENDIAN);
  }

  /* Masking-key */
  if (mask) {
    proto_tree_add_item(ws_tree, hf_ws_masking_key, tvb, mask_offset, 4, ENC_NA);
    masking_key = tvb_get_ptr(tvb, mask_offset, 4);
  }

  if (payload_length > 0) {
    /* Always unmask payload data before analysing it. */
    if (mask) {
      proto_tree_add_item(ws_tree, hf_ws_masked_payload, tvb, payload_offset, payload_length, ENC_NA);
      tvb_payload = tvb_unmasked(tvb, pinfo, payload_offset, payload_length, masking_key);
      tvb_set_child_real_data_tvbuff(tvb, tvb_payload);
      add_new_data_source(pinfo, tvb_payload, "Unmasked data");
    } else {
      tvb_payload = tvb_new_subset_length_caplen(tvb, payload_offset, payload_length, payload_length);
    }
    dissect_websocket_payload(tvb_payload, pinfo, tree, ws_tree, opcode, websocket_conv, pmc, tvb_raw_offset(tvb));
  }

  return tvb_captured_length(tvb);
}

static guint
get_websocket_frame_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  guint         frame_length, payload_length;
  gboolean      mask;

  frame_length = 2;                 /* flags, opcode and Payload length */
  mask = tvb_get_guint8(tvb, offset + 1) & MASK_WS_MASK;

  payload_length = tvb_get_guint8(tvb, offset + 1) & MASK_WS_PAYLOAD_LEN;
  offset += 2; /* Skip flags, opcode and Payload length */

  /* Check for Extended Payload Length. */
  if (payload_length == 126) {
    if (tvb_reported_length_remaining(tvb, offset) < 2)
      return 0; /* Need more data. */

    payload_length = tvb_get_ntohs(tvb, offset);
    frame_length += 2;              /* Extended payload length */
  } else if (payload_length == 127) {
    if (tvb_reported_length_remaining(tvb, offset) < 8)
      return 0; /* Need more data. */

    payload_length = (guint)tvb_get_ntoh64(tvb, offset);
    frame_length += 8;              /* Extended payload length */
  }

  if (mask)
    frame_length += 4;              /* Masking-key */
  frame_length += payload_length;   /* Payload data */
  return frame_length;
}

static int
dissect_websocket(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  /* Need at least two bytes for flags, opcode and Payload length. */
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2,
                   get_websocket_frame_length, dissect_websocket_frame, data);
  return tvb_captured_length(tvb);
}


void
proto_register_websocket(void)
{

  static hf_register_info hf[] = {
    { &hf_ws_fin,
      { "Fin", "websocket.fin",
      FT_BOOLEAN, 8, NULL, MASK_WS_FIN,
      "Indicates that this is the final fragment in a message", HFILL }
    },
    { &hf_ws_reserved,
      { "Reserved", "websocket.rsv",
      FT_UINT8, BASE_HEX, NULL, MASK_WS_RSV,
      "Must be zero", HFILL }
    },
    { &hf_ws_pmc,
      { "Per-Message Compressed", "websocket.pmc",
      FT_BOOLEAN, 8, NULL, MASK_WS_RSV1,
      "Whether a message is compressed or not", HFILL }
    },
    { &hf_ws_opcode,
      { "Opcode", "websocket.opcode",
      FT_UINT8, BASE_DEC, VALS(ws_opcode_vals), MASK_WS_OPCODE,
      "Defines the interpretation of the Payload data", HFILL }
    },
    { &hf_ws_mask,
      { "Mask", "websocket.mask",
      FT_BOOLEAN, 8, NULL, MASK_WS_MASK,
      "Defines whether the Payload data is masked", HFILL }
    },
    { &hf_ws_payload_length,
      { "Payload length", "websocket.payload_length",
      FT_UINT8, BASE_DEC, NULL, MASK_WS_PAYLOAD_LEN,
      "The length of the Payload data", HFILL }
    },
    { &hf_ws_payload_length_ext_16,
      { "Extended Payload length (16 bits)", "websocket.payload_length_ext_16",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "The length (16 bits) of the Payload data", HFILL }
    },
    { &hf_ws_payload_length_ext_64,
      { "Extended Payload length (64 bits)", "websocket.payload_length_ext_64",
      FT_UINT64, BASE_DEC, NULL, 0x0,
      "The length (64 bits) of the Payload data", HFILL }
    },
    { &hf_ws_masking_key,
      { "Masking-Key", "websocket.masking_key",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "All frames sent from the client to the server are masked by a 32-bit value that is contained within the frame", HFILL }
    },
    { &hf_ws_payload,
      { "Payload", "websocket.payload",
      FT_NONE, BASE_NONE, NULL, 0x0,
      "Payload (after unmasking)", HFILL }
    },
    { &hf_ws_masked_payload,
      { "Masked payload", "websocket.masked_payload",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_ws_payload_continue,
      { "Continue", "websocket.payload.continue",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_ws_payload_close,
      { "Close", "websocket.payload.close",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_ws_payload_close_status_code,
      { "Status code", "websocket.payload.close.status_code",
      FT_UINT16, BASE_DEC, VALS(ws_close_status_code_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_ws_payload_close_reason,
      { "Reason", "websocket.payload.close.reason",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_ws_payload_ping,
      { "Ping", "websocket.payload.ping",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_ws_payload_pong,
      { "Pong", "websocket.payload.pong",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_ws_payload_unknown,
      { "Unknown", "websocket.payload.unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
  };


  static gint *ett[] = {
    &ett_ws,
    &ett_ws_pl,
    &ett_ws_mask,
    &ett_ws_control_close,
  };

  static ei_register_info ei[] = {
    { &ei_ws_payload_unknown, { "websocket.payload.unknown.expert", PI_UNDECODED, PI_NOTE, "Dissector for Websocket Opcode", EXPFILL }},
    { &ei_ws_decompression_failed, { "websocket.decompression.failed.expert", PI_PROTOCOL, PI_WARN, "Decompression failed", EXPFILL }},
  };

  static const enum_val_t text_types[] = {
      {"None",            "No subdissection", WEBSOCKET_NONE},
      {"Line based text", "Line based text",  WEBSOCKET_TEXT},
      {"As JSON",         "As json",          WEBSOCKET_JSON},
      {"As SIP",         "As SIP",          WEBSOCKET_SIP},
      {NULL, NULL, -1}
  };

  module_t *websocket_module;
  expert_module_t* expert_websocket;

  proto_websocket = proto_register_protocol("WebSocket",
      "WebSocket", "websocket");

  /*
   * Heuristic dissectors SHOULD register themselves in
   * this table using the standard heur_dissector_add()
   * function.
   */
  heur_subdissector_list = register_heur_dissector_list("ws", proto_websocket);

  port_subdissector_table = register_dissector_table("ws.port",
      "TCP port for protocols using WebSocket", proto_websocket, FT_UINT16, BASE_DEC);

  protocol_subdissector_table = register_dissector_table("ws.protocol",
      "Negotiated WebSocket protocol", proto_websocket, FT_STRING, BASE_NONE);

  proto_register_field_array(proto_websocket, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_websocket = expert_register_protocol(proto_websocket);
  expert_register_field_array(expert_websocket, ei, array_length(ei));

  websocket_handle = register_dissector("websocket", dissect_websocket, proto_websocket);

  websocket_module = prefs_register_protocol(proto_websocket, proto_reg_handoff_websocket);

  prefs_register_enum_preference(websocket_module, "text_type",
        "Dissect websocket text as",
        "Select dissector for websocket text",
        &pref_text_type, text_types, WEBSOCKET_NONE);
  prefs_register_bool_preference(websocket_module, "decompress",
        "Try to decompress permessage-deflate payload", NULL, &pref_decompress);
}

void
proto_reg_handoff_websocket(void)
{
  dissector_add_string("http.upgrade", "websocket", websocket_handle);

  text_lines_handle = find_dissector_add_dependency("data-text-lines", proto_websocket);
  json_handle = find_dissector_add_dependency("json", proto_websocket);
  sip_handle = find_dissector_add_dependency("sip", proto_websocket);

  proto_http = proto_get_id_by_filter_name("http");
}
/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
