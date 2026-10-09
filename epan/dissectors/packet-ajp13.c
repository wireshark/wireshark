/* packet-ajp13.c
 * Routines for AJP13 dissection
 * Copyright 2002, Christopher K. St. John <cks@distributopia.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/export_object.h>
#include "packet-tcp.h"

#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>

void proto_register_ajp13(void);
void proto_reg_handoff_ajp13(void);

static dissector_handle_t ajp13_handle;

#define AJP13_TCP_PORT 8009 /* Not IANA registered */

/* IMPORTANT IMPLEMENTATION NOTES
 *
 * You need to be looking at:
 *
 *     http://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
 *
 * If you're a wireshark dissector guru, then you can skip the rest of
 * this. I'm writing it all down because I've written 3 dissectors so
 * far and every time I've forgotten it all and had to re-learn it
 * from scratch. Not this time, damnit.
 *
 * Dissector routines get called in two phases:
 *
 * The first phase is an in-order traversal of every incoming
 * frame. Since we know it's in-order, we can set up a "conversational
 * state" that records context-sensitive stuff like "was there a
 * content-length in the previous request". During this first pass
 * through the data, the "tree" parameter might be null, or not. For
 * the regular gui-based Wireshark, it's null, which means we don't
 * actually display the dissected data in the gui quite yet. For the
 * text based interface, we might do the parsing and display both in
 * this first pass.
 *
 * The second phase happens when the data is actually displayed. In
 * this pase the "tree" param is non-null, so you've got a hook to
 * hang the parsed-out display data on. Since there might be gigabytes
 * worth of capture data, the display code only calls the dissector
 * for the stuff the user actually clicks on. So you have to assume
 * the dissector is getting called on random frames, you can't depend
 * on ordering anymore.
 *
 * But some parts of the AJP13 capture stream are context sensitive.
 * That's no big deal during the first in-order pass, but the second
 * phase requires us to display any random frame correctly. So during
 * the first in-order phase we create a per-frame user data structure
 * and attach it to the frame using p_add_proto_data.
 *
 * Since AJP13 is a TCP/IP based protocol, writing a dissector for it
 * requires addressing several other issues:
 *
 * 1) TCP/IP segments can get retransmitted or be sent out of
 * order. Users don't normally care, because the low-level kernel
 * networking code takes care of reassembling them properly. But we're
 * looking at raw network packets, aren't we? The stuff on the
 * wire. Wireshark has been getting better and better at helping
 * dissectors with this. I'm a little fuzzy on the details, but my
 * understanding is that wireshark now contains a fairly substantial
 * user-space TCP/IP stack so it can re-assemble the data. But I might
 * be wrong. Since AJP13 is going to be used either on the loopback
 * interface or on a LAN, it isn't likely to be a big issues anyway.
 *
 * 2) AJP13 packets (PDU's or protocol data unit's in
 * networking-speak) don't necessarily line up with TCP segments. That
 * is, one TCP segment can have more than one AJP13 PDU, or one AJP13
 * PDU can stretch across multiple TCP segments. Assembling them is
 * obviously possible, but a royal pain. During the "phase one"
 * in-order pass you have to keep track of a bunch of offsets and
 * store which PDU goes with which TCP segment. Luckily, recent
 * (0.9.4+) versions of wireshark provide the "tcp_dissect_pdus()"
 * function that takes care of much of the work. See the comments in
 * packet-tcp.c, the example code in packet-dns.c, or check the
 * wireshark-dev archives for details.
 *
 * 3) Wireshark isn't guaranteed to see all the data. I'm a little
 * unclear on all the possible failure modes, but it comes down to: a)
 * Not your fault: it's an imperfect world, we're eavesdroppers, and
 * stuff happens. We might totally miss packets or get garbled
 * data. Or b) Totally your fault: you turn on the capture during the
 * middle of an AJP13 conversation and the capture starts out with
 * half an AJP13 PDU. This code doesn't currently handle either case
 * very well, but you can get arbitrarily clever. Like: put in tests
 * to see if this packet has reasonable field values, and if it
 * doesn't, walk the offset ahead until we see a matching magic number
 * field, then re-test. But we don't do that now, and since we're
 * using tcp_dissect_pdu's, I'm not sure how to do it.
 *
 */



#define MTYPE_FORWARD_REQUEST   2
#define MTYPE_SEND_BODY_CHUNK   3
#define MTYPE_SEND_HEADERS      4
#define MTYPE_END_RESPONSE      5
#define MTYPE_GET_BODY_CHUNK    6
#define MTYPE_SHUTDOWN          7
#define MTYPE_CPONG             9
#define MTYPE_CPING             10

static const value_string mtype_codes[] = {
  { MTYPE_FORWARD_REQUEST, "FORWARD REQUEST" },
  { MTYPE_SEND_BODY_CHUNK, "SEND BODY CHUNK" },
  { MTYPE_SEND_HEADERS,    "SEND HEADERS" },
  { MTYPE_END_RESPONSE,    "END RESPONSE" },
  { MTYPE_GET_BODY_CHUNK,  "GET BODY CHUNK" },
  { MTYPE_SHUTDOWN,        "SHUTDOWN" },
  { MTYPE_CPONG,           "CPONG" },
  { MTYPE_CPING,           "CPING" },
  { 0, NULL }
};


static const value_string http_method_codes[] = {
  { 1, "OPTIONS" },
  { 2, "GET" },
  { 3, "HEAD" },
  { 4, "POST" },
  { 5, "PUT" },
  { 6, "DELETE" },
  { 7, "TRACE" },
  { 8, "PROPFIND" },
  { 9, "PROPPATCH" },
  { 10, "MKCOL" },
  { 11, "COPY" },
  { 12, "MOVE" },
  { 13, "LOCK" },
  { 14, "UNLOCK" },
  { 15, "ACL" },
  { 16, "REPORT" },
  { 17, "VERSION-CONTROL" },
  { 18, "CHECKIN" },
  { 19, "CHECKOUT" },
  { 20, "UNCHECKOUT" },
  { 21, "SEARCH" },
  { 0, NULL }
};



static int proto_ajp13;
static int hf_ajp13_magic;
static int hf_ajp13_len;
static int hf_ajp13_code;
static int hf_ajp13_method;
static int hf_ajp13_ver;
static int hf_ajp13_uri;
static int hf_ajp13_raddr;
static int hf_ajp13_rhost;
static int hf_ajp13_srv;
static int hf_ajp13_port;
static int hf_ajp13_sslp;
static int hf_ajp13_nhdr;

/* response headers */
static int hf_ajp13_unknown_header;
static int hf_ajp13_content_type;
static int hf_ajp13_content_language;
static int hf_ajp13_content_length;
static int hf_ajp13_date;
static int hf_ajp13_last_modified;
static int hf_ajp13_location;
static int hf_ajp13_set_cookie;
static int hf_ajp13_set_cookie2;
static int hf_ajp13_servlet_engine;
static int hf_ajp13_status;
static int hf_ajp13_www_authenticate;

/* request headers */
static int hf_ajp13_accept;
static int hf_ajp13_accept_charset;
static int hf_ajp13_accept_encoding;
static int hf_ajp13_accept_language;
static int hf_ajp13_authorization;
static int hf_ajp13_connection;
                 /* content_type   */
                 /* content_length */
static int hf_ajp13_cookie;
static int hf_ajp13_cookie2;
static int hf_ajp13_host;
static int hf_ajp13_pragma;
static int hf_ajp13_referer;
static int hf_ajp13_user_agent;

/* request attributes */
static int hf_ajp13_unknown_attribute;
static int hf_ajp13_req_attribute;
static int hf_ajp13_context;
static int hf_ajp13_servlet_path;
static int hf_ajp13_remote_user;
static int hf_ajp13_auth_type;
static int hf_ajp13_query_string;
static int hf_ajp13_route;
static int hf_ajp13_ssl_cert;
static int hf_ajp13_ssl_cipher;
static int hf_ajp13_ssl_session;
static int hf_ajp13_ssl_key_size;
static int hf_ajp13_secret;
static int hf_ajp13_stored_method;

static int hf_ajp13_rlen;
static int hf_ajp13_reusep;
static int hf_ajp13_rstatus;
static int hf_ajp13_rsmsg;
static int hf_ajp13_data;

/* body reassembly */
static int hf_ajp13_body_fragments;
static int hf_ajp13_body_fragment;
static int hf_ajp13_body_fragment_overlap;
static int hf_ajp13_body_fragment_overlap_conflicts;
static int hf_ajp13_body_fragment_multiple_tails;
static int hf_ajp13_body_fragment_too_long_fragment;
static int hf_ajp13_body_fragment_error;
static int hf_ajp13_body_fragment_count;
static int hf_ajp13_body_reassembled_in;
static int hf_ajp13_body_reassembled_length;

static int ett_ajp13;
static int ett_ajp13_body_fragment;
static int ett_ajp13_body_fragments;

static expert_field ei_ajp13_content_length_invalid;

static const fragment_items ajp13_body_fragment_items = {
  &ett_ajp13_body_fragment,
  &ett_ajp13_body_fragments,
  &hf_ajp13_body_fragments,
  &hf_ajp13_body_fragment,
  &hf_ajp13_body_fragment_overlap,
  &hf_ajp13_body_fragment_overlap_conflicts,
  &hf_ajp13_body_fragment_multiple_tails,
  &hf_ajp13_body_fragment_too_long_fragment,
  &hf_ajp13_body_fragment_error,
  &hf_ajp13_body_fragment_count,
  &hf_ajp13_body_reassembled_in,
  &hf_ajp13_body_reassembled_length,
  NULL,
  "Body fragments"
};

static reassembly_table ajp13_body_reassembly_table;

static int ajp13_eo_tap;

/* Reassemble request and response bodies (needed for Export Objects) */
static bool ajp13_reassemble_body = true;

/*
 * Request/response header codes. Common headers are stored as ints in
 * an effort to improve performance. Why can't we just have one big
 * list?
 */
static int * const rsp_headers[] = {
  &hf_ajp13_unknown_header,
  &hf_ajp13_content_type,
  &hf_ajp13_content_language,
  &hf_ajp13_content_length,
  &hf_ajp13_date,
  &hf_ajp13_last_modified,
  &hf_ajp13_location,
  &hf_ajp13_set_cookie,
  &hf_ajp13_set_cookie2,
  &hf_ajp13_servlet_engine,
  &hf_ajp13_status,
  &hf_ajp13_www_authenticate
};

static int * const req_headers[] = {
  &hf_ajp13_unknown_header,
  &hf_ajp13_accept,
  &hf_ajp13_accept_charset,
  &hf_ajp13_accept_encoding,
  &hf_ajp13_accept_language,
  &hf_ajp13_authorization,
  &hf_ajp13_connection,
  &hf_ajp13_content_type,
  &hf_ajp13_content_length,
  &hf_ajp13_cookie,
  &hf_ajp13_cookie2,
  &hf_ajp13_host,
  &hf_ajp13_pragma,
  &hf_ajp13_referer,
  &hf_ajp13_user_agent
};

static int * const req_attributes[] = {
  &hf_ajp13_unknown_attribute,
  &hf_ajp13_context,
  &hf_ajp13_servlet_path,
  &hf_ajp13_remote_user,
  &hf_ajp13_auth_type,
  &hf_ajp13_query_string,
  &hf_ajp13_route,
  &hf_ajp13_ssl_cert,
  &hf_ajp13_ssl_cipher,
  &hf_ajp13_ssl_session,
  &hf_ajp13_req_attribute, /* 0x0A - name and value follows */
  &hf_ajp13_ssl_key_size,
  &hf_ajp13_secret,
  &hf_ajp13_stored_method
};

/* A request and its response, whose bodies are reassembled and exported */
typedef struct ajp13_trans_info {
  uint32_t body_id;              /* reassembly ID of the bodies */
  const char *host;              /* Host header, or else server name */
  const char *uri;               /* request URI, including the query string */
  const char *req_content_type;  /* media type of the request body */
  const char *rsp_content_type;  /* media type of the response body */
} ajp13_trans_info;

typedef struct ajp13_conv_data {
  uint32_t content_length;  /* remaining length of the request body */
  bool was_get_body_chunk;  /* the next request packet is a body chunk */
  ajp13_trans_info *trans;      /* current request */
  ajp13_trans_info *rsp_trans;  /* request whose response is being sent */
} ajp13_conv_data;

typedef struct ajp13_frame_data {
  bool is_request_body;
  bool is_request_body_end;  /* last packet of the request body */
  ajp13_trans_info *trans;   /* request that the body packet belongs to */
} ajp13_frame_data;

/* Used for the Export Objects feature */
typedef struct ajp13_eo_t {
  const char *hostname;
  const char *filename;
  const char *content_type;
  tvbuff_t *payload;
} ajp13_eo_t;

static tap_packet_status
ajp13_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
  export_object_list_t *object_list = (export_object_list_t *)tapdata;
  const ajp13_eo_t *eo_info = (const ajp13_eo_t *)data;
  export_object_entry_t *entry;

  if (!eo_info)
    return TAP_PACKET_DONT_REDRAW;

  /* These values will be freed when the Export Object window is closed. */
  entry = g_new(export_object_entry_t, 1);

  entry->pkt_num = pinfo->num;
  entry->hostname = g_strdup(eo_info->hostname);
  entry->content_type = g_strdup(eo_info->content_type);
  /* Like HTTP, use the final part of the URI */
  entry->filename = eo_info->filename ? g_path_get_basename(eo_info->filename) : NULL;
  entry->payload_len = tvb_captured_length(eo_info->payload);
  entry->payload_data = (uint8_t *)tvb_memdup(NULL, eo_info->payload, 0, entry->payload_len);

  object_list->add_entry(object_list->gui_data, entry);

  return TAP_PACKET_REDRAW;
}

/* Returns the media type of a Content-Type header value, i.e. without
 * any parameters and in lower case, like the HTTP dissector.
 */
static const char *
ajp13_get_media_type(wmem_allocator_t *scope, const char *content_type)
{
  return wmem_ascii_strdown(scope, content_type, strcspn(content_type, "; \t"));
}

/* Adds the data of a request or response body packet to the reassembly
 * of the body. If the packet ends the body, adds the reassembled body to
 * the tree and sends it to Export Objects.
 */
static void
ajp13_reassemble_body_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ajp13_tree,
                           int offset, uint16_t length, bool is_end,
                           const ajp13_trans_info *trans, const char *content_type)
{
  fragment_head *fd_head = NULL;
  tvbuff_t *body_tvb;

  if (!ajp13_reassemble_body)
    return;

  if (length != 0 && tvb_bytes_exist(tvb, offset, length)) {
    fd_head = fragment_add_seq_next(&ajp13_body_reassembly_table, tvb, offset,
                                    pinfo, trans->body_id, NULL, length, true);
  }

  if (!is_end) {
    /* We know where the body was reassembled after the first pass. The
     * last packet can be in the same frame as this one, so don't use
     * process_reassembled_data(), which would show the body here too.
     */
    if (fd_head) {
      proto_item *ti = proto_tree_add_uint(ajp13_tree, hf_ajp13_body_reassembled_in,
                                           tvb, 0, 0, fd_head->reassembled_in);
      proto_item_set_generated(ti);
    }
    return;
  }

  fd_head = fragment_end_seq_next(&ajp13_body_reassembly_table, pinfo, trans->body_id, NULL);
  body_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled body", fd_head,
                                      &ajp13_body_fragment_items, NULL, ajp13_tree);

  if (body_tvb && have_tap_listener(ajp13_eo_tap)) {
    ajp13_eo_t *eo_info = wmem_new0(pinfo->pool, ajp13_eo_t);

    eo_info->hostname = trans->host;
    eo_info->filename = trans->uri;
    eo_info->content_type = content_type;
    eo_info->payload = body_tvb;

    tap_queue_packet(ajp13_eo_tap, pinfo, eo_info);
  }
}

/* ajp13, in sort of a belt-and-suspenders move, encodes strings with
 * both a leading length field, and a trailing null. Mostly, see
 * ajpv13a.html. The returned length _includes_ the trailing null, if
 * there is one.
 *
 * XXX - is there a tvbuff routine to handle this?
 */
static const char *
ajp13_get_nstring(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, uint16_t* ret_len)
{
  uint16_t len;

  len = tvb_get_ntohs(tvb, offset);

  if (ret_len)
    *ret_len = len+1;

  /* a size of 0xFFFF indicates a null string - no data follows */
  if (len == 0xFFFF)
    len = 0;

  return tvb_format_text(scope, tvb, offset+2, len);
}



/* dissect a response. more work to do here.
 */
static void
display_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ajp13_tree,
            ajp13_conv_data* cd, ajp13_frame_data* fd)
{
  int pos = 0;
  uint32_t mcode = 0;
  int i;

  /* MAGIC
   */
  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_magic, tvb, pos, 2, ENC_NA);
  pos+=2;

  /* PDU LENGTH
   */
  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_len,   tvb, pos, 2, ENC_BIG_ENDIAN);
  pos+=2;

  /* MESSAGE TYPE CODE
   */
  proto_tree_add_item_ret_uint(ajp13_tree, hf_ajp13_code, tvb, pos, 1, ENC_BIG_ENDIAN, &mcode);
  col_append_str(pinfo->cinfo, COL_INFO, val_to_str(pinfo->pool, mcode, mtype_codes, "Unknown message code %u"));
  pos+=1;

  switch (mcode) {

  case MTYPE_END_RESPONSE:
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_reusep, tvb, pos, 1, ENC_BIG_ENDIAN);
    /*pos+=1;*/
    /* This ends the request handling cycle, the container won't read
     * any more of the request body.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
      cd->content_length = 0;
      cd->was_get_body_chunk = false;
      fd->trans = cd->rsp_trans;
      cd->trans = NULL;
      cd->rsp_trans = NULL;
    }
    /* This also ends the response body
     */
    if (fd->trans)
      ajp13_reassemble_body_data(tvb, pinfo, ajp13_tree, pos, 0, true,
                                 fd->trans, fd->trans->rsp_content_type);
    break;

  case MTYPE_SEND_BODY_CHUNK:
  {
    uint16_t chunk_len;

    /* MESSAGE DATA
     */
    chunk_len = tvb_get_ntohs(tvb, pos);
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_data, tvb, pos+2, -1, ENC_UTF_8);

    if (!PINFO_FD_VISITED(pinfo))
      fd->trans = cd->rsp_trans;
    if (fd->trans)
      ajp13_reassemble_body_data(tvb, pinfo, ajp13_tree, pos+2, chunk_len, false,
                                 fd->trans, NULL);
    break;
  }

  case MTYPE_SEND_HEADERS:
  {
    const char *rsmsg;
    uint16_t rsmsg_len;
    uint16_t nhdr;
    uint16_t rcode_num;
    const char *content_type = NULL;

    /* HTTP RESPONSE STATUS CODE
     */
    rcode_num = tvb_get_ntohs(tvb, pos);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%d", rcode_num);
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_rstatus, tvb, pos, 2, ENC_BIG_ENDIAN);
    pos+=2;

    /* HTTP RESPONSE STATUS MESSAGE
     */
    rsmsg = ajp13_get_nstring(pinfo->pool, tvb, pos, &rsmsg_len);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", rsmsg);
    if (ajp13_tree)
      proto_tree_add_string(ajp13_tree, hf_ajp13_rsmsg, tvb, pos, rsmsg_len+2, rsmsg);
    pos+=rsmsg_len+2;

    /* NUMBER OF HEADERS
     */
    nhdr = tvb_get_ntohs(tvb, pos);
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_nhdr, tvb, pos, 2, ENC_BIG_ENDIAN);
    pos+=2;

    /* The response (body) starts here. We only reassemble bodies that
     * we've seen the start of.
     */
    if (!PINFO_FD_VISITED(pinfo)) {
      if (!cd->trans) {
        /* we haven't seen the request */
        cd->trans = wmem_new0(wmem_file_scope(), ajp13_trans_info);
        cd->trans->body_id = pinfo->num;
      }
      cd->rsp_trans = cd->trans;
    }

    /* HEADERS
     */
    for(i=0; i<nhdr; i++) {

      uint8_t hcd;
      uint8_t hid;
      const char *hval;
      uint16_t hval_len, hname_len;
      const char* hname = NULL;
      int hpos = pos;
      /* int cl = 0; TODO: Content-Length header (encoded by 0x08) is special */

      /* HEADER CODE/NAME
       */
      hcd = tvb_get_uint8(tvb, pos);

      if (hcd == 0xA0) {
        pos+=1;
        hid = tvb_get_uint8(tvb, pos);
        pos+=1;

        if (hid >= array_length(rsp_headers))
          hid = 0;

        hval = ajp13_get_nstring(pinfo->pool, tvb, pos, &hval_len);

        proto_tree_add_string(ajp13_tree, *rsp_headers[hid],
                              tvb, hpos, 2+hval_len+2, hval);
        pos+=hval_len+2;

        if (hid == 0x01)  /* Content-Type */
          content_type = hval;
#if 0
        /* TODO: Content-Length header (encoded by 0x08) is special */
        if (hid == 0x08)
          cl = 1;
#endif
      } else {
        hname = ajp13_get_nstring(pinfo->pool, tvb, pos, &hname_len);
        pos+=hname_len+2;

        hval = ajp13_get_nstring(pinfo->pool, tvb, pos, &hval_len);

        if (hcd >= array_length(rsp_headers)) {
          hcd = 0;
        }

        proto_tree_add_string_format(ajp13_tree, *rsp_headers[hcd],
                                tvb, hpos, hname_len+2+hval_len+2,
                                wmem_strdup_printf(pinfo->pool, "%s: %s", hname, hval),
                                "%s: %s", hname, hval);
        pos+=hval_len+2;
      }
    }

    if (!PINFO_FD_VISITED(pinfo) && content_type)
      cd->rsp_trans->rsp_content_type = ajp13_get_media_type(wmem_file_scope(), content_type);
    break;
  }

  case MTYPE_GET_BODY_CHUNK:
  {
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_rlen, tvb, pos, 2, ENC_BIG_ENDIAN);
    /*pos+=2;*/
    /* The web server answers with a request body packet, which may be
     * shorter than the requested length.
     */
    if (!PINFO_FD_VISITED(pinfo))
      cd->was_get_body_chunk = true;
    break;
  }

  case MTYPE_CPONG:
    break;

  default:
    /* MESSAGE DATA (COPOUT)
     */
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_data,  tvb, pos+2, -1, ENC_UTF_8);
    break;
  }
}



/* dissect a request body. see AJPv13.html, but the idea is that these
 * packets, unlike all other packets, have no type field. you just
 * sort of have to know that they're coming based on the previous
 * packets.
 */
static void
display_req_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ajp13_tree,
                 ajp13_conv_data* cd, ajp13_frame_data* fd)
{
  /*printf("ajp13:display_req_body()\n");*/
  uint16_t content_length = 0;
  uint16_t packet_length;

  int pos = 0;

  /* MAGIC
   */
  proto_tree_add_item(ajp13_tree, hf_ajp13_magic, tvb, pos, 2, ENC_NA);
  pos+=2;

  /* PACKET LENGTH
   */
  packet_length = tvb_get_ntohs(tvb, pos);
  proto_tree_add_item(ajp13_tree, hf_ajp13_len, tvb, pos, 2, ENC_BIG_ENDIAN);
  pos+=2;

  /*
   * An empty packet:
   * 0x12 0x34 0x00 0x00
   * or zero length content signals that there is no more data in the body
   */
  if (packet_length != 0) {
    content_length = tvb_get_ntohs(tvb, pos);
    pos+=2;
  }

  if (!PINFO_FD_VISITED(pinfo)) {
    cd->was_get_body_chunk = false;
    if (content_length == 0) {
      cd->content_length = 0;
      fd->is_request_body_end = true;
    } else if (cd->content_length != 0) {
      /* the body has the length given by the Content-Length header,
       * otherwise it ends with an empty packet.
       */
      cd->content_length -= MIN(content_length, cd->content_length);
      fd->is_request_body_end = (cd->content_length == 0);
    }
    fd->trans = cd->trans;
  }

  /* BODY (AS STRING)
   */
  if (content_length != 0)
    proto_tree_add_item(ajp13_tree, hf_ajp13_data, tvb, pos, content_length, ENC_UTF_8);

  if (fd->trans)
    ajp13_reassemble_body_data(tvb, pinfo, ajp13_tree, pos, content_length,
                               fd->is_request_body_end, fd->trans,
                               fd->trans->req_content_type);
}



/* note that even if ajp13_tree is null on the first pass, we still
 * need to dissect the packet in order to determine if there is a
 * content-length, and thus if there is a subsequent automatic
 * request-body transmitted in the next request packet. if there is a
 * content-length, we record the fact in the conversation context.
 * ref the top of this file for comments explaining the multi-pass
 * thing.
*/
static void
display_req_forward(tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *ajp13_tree,
                    ajp13_conv_data* cd)
{
  int pos = 0;
  uint32_t meth;
  uint8_t cod;
  const char *ver;
  uint16_t ver_len;
  const char *uri;
  uint16_t uri_len;
  const char *raddr;
  uint16_t raddr_len;
  const char *rhost;
  uint16_t rhost_len;
  const char *srv;
  uint16_t srv_len;
  unsigned nhdr;
  unsigned i;
  ajp13_trans_info *trans = NULL;

  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_magic, tvb, pos, 2, ENC_NA);
  pos+=2;

  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_len, tvb, pos, 2, ENC_BIG_ENDIAN);
  pos+=2;

  /* PACKET CODE
   */
  cod = tvb_get_uint8(tvb, 4);
  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_code, tvb, pos, 1, ENC_BIG_ENDIAN);
  pos+=1;
  if ( cod == MTYPE_CPING ) {
    col_append_str(pinfo->cinfo, COL_INFO, "CPING" );
    return;
  }

  /* HTTP METHOD (ENCODED AS INTEGER)
   */
  proto_tree_add_item_ret_uint(ajp13_tree, hf_ajp13_method, tvb, pos, 1, ENC_BIG_ENDIAN, &meth);
  col_append_str(pinfo->cinfo, COL_INFO, val_to_str(pinfo->pool, meth, http_method_codes, "Unknown method %u"));
  pos+=1;

  /* HTTP VERSION STRING
   */
  ver = ajp13_get_nstring(pinfo->pool, tvb, pos, &ver_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_ver, tvb, pos, ver_len+2, ver);
  pos=pos+ver_len+2;  /* skip over size + chars + trailing null */

  /* URI
   */
  uri = ajp13_get_nstring(pinfo->pool, tvb, pos, &uri_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_uri, tvb, pos, uri_len+2, uri);
  pos=pos+uri_len+2;  /* skip over size + chars + trailing null */


  col_append_fstr(pinfo->cinfo, COL_INFO, " %s %s", uri, ver);


  /* REMOTE ADDRESS
   */
  raddr = ajp13_get_nstring(pinfo->pool, tvb, pos, &raddr_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_raddr, tvb, pos, raddr_len+2, raddr);
  pos=pos+raddr_len+2;  /* skip over size + chars + trailing null */

  /* REMOTE HOST
   */
  rhost = ajp13_get_nstring(pinfo->pool, tvb, pos, &rhost_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_rhost, tvb, pos, rhost_len+2, rhost);
  pos=pos+rhost_len+2;  /* skip over size + chars + trailing null */

  /* SERVER NAME
   */
  srv = ajp13_get_nstring(pinfo->pool, tvb, pos, &srv_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_srv, tvb, pos, srv_len+2, srv);
  pos=pos+srv_len+2;  /* skip over size + chars + trailing null */

  /* SERVER PORT
   */
  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_port, tvb, pos, 2, ENC_BIG_ENDIAN);
  pos+=2;

  /* IS SSL?
   */
  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_sslp, tvb, pos, 1, ENC_NA);
  pos+=1;

  /* NUM HEADERS
   */
  nhdr = tvb_get_ntohs(tvb, pos);

  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_nhdr, tvb, pos, 2, ENC_BIG_ENDIAN);
  pos+=2;
  if (!PINFO_FD_VISITED(pinfo)) {
    cd->content_length = 0;
    if (cod == MTYPE_FORWARD_REQUEST) {
      /* a new request, for the bodies */
      trans = wmem_new0(wmem_file_scope(), ajp13_trans_info);
      trans->body_id = pinfo->num;
      trans->host = wmem_strdup(wmem_file_scope(), srv);
      trans->uri = wmem_strdup(wmem_file_scope(), uri);
      cd->trans = trans;
    }
  }

  /* HEADERS
   */
  for(i=0; i<nhdr; i++) {

    uint8_t hcd;
    uint8_t hid = 0;
    const char* hname = NULL;
    int hpos = pos;
    const char *hval;
    uint16_t hval_len, hname_len;

    /* HEADER CODE/NAME
     */
    hcd = tvb_get_uint8(tvb, pos);

    if (hcd == 0xA0) {
      proto_item* pi;

      pos+=1;
      hid = tvb_get_uint8(tvb, pos);
      pos+=1;

      if (hid >= array_length(req_headers))
        hid = 0;

      hval = ajp13_get_nstring(pinfo->pool, tvb, pos, &hval_len);


      pi = proto_tree_add_string(ajp13_tree, *req_headers[hid],
                                 tvb, hpos, 2+hval_len+2, hval);

      if (hid == 0x08) {
        uint32_t content_length;

        if (!ws_strtou32(hval, NULL, &content_length))
          expert_add_info(pinfo, pi, &ei_ajp13_content_length_invalid);
        if (!PINFO_FD_VISITED(pinfo))
          cd->content_length = content_length;
      }

      if (trans && hid == 0x07)  /* Content-Type */
        trans->req_content_type = ajp13_get_media_type(wmem_file_scope(), hval);
      if (trans && hid == 0x0B)  /* Host */
        trans->host = wmem_strdup(wmem_file_scope(), hval);

      pos+=hval_len+2;
    } else {
      hname = ajp13_get_nstring(pinfo->pool, tvb, pos, &hname_len);
      pos+=hname_len+2;

      if (hcd >= array_length(req_headers)) {
        hcd = 0;
      }

      hval = ajp13_get_nstring(pinfo->pool, tvb, pos, &hval_len);

      proto_tree_add_string_format(ajp13_tree, *req_headers[hcd],
                                     tvb, hpos, hname_len+2+hval_len+2,
                                     wmem_strdup_printf(pinfo->pool, "%s: %s", hname, hval),
                                     "%s: %s", hname, hval);
      pos+=hval_len+2;
    }
  }

  /* ATTRIBUTES
   */
  while(tvb_reported_length_remaining(tvb, pos) > 0) {
    uint8_t aid;
    const char* aname = NULL;
    const char* aval;
    uint16_t aval_len, aname_len, key_len;

    int apos = pos;

    /* ATTRIBUTE CODE/NAME
     */
    aid = tvb_get_uint8(tvb, pos);
    pos+=1;

    if (aid == 0xFF) {
      /* request terminator */
      break;
    }
    if (aid == 0x0A) {
      /* req_attribute - name and value follow */

      aname = ajp13_get_nstring(pinfo->pool, tvb, pos, &aname_len);
      pos+=aname_len+2;

      aval = ajp13_get_nstring(pinfo->pool, tvb, pos, &aval_len);
      pos+=aval_len+2;

      proto_tree_add_string_format(ajp13_tree, hf_ajp13_req_attribute,
                                     tvb, apos, 1+aname_len+2+aval_len+2,
                                     wmem_strdup_printf(pinfo->pool, "%s: %s", aname, aval),
                                     "%s: %s", aname, aval);
    } else if (aid == 0x0B ) {
      /* ssl_key_length */
      key_len = tvb_get_ntohs(tvb, pos);
      proto_tree_add_uint(ajp13_tree, hf_ajp13_ssl_key_size,
                            tvb, apos, 1+2, key_len);
      pos+=2;
    } else {

      if (aid >= array_length(req_attributes))
        aid = 0;

      aval = ajp13_get_nstring(pinfo->pool, tvb, pos, &aval_len);
      pos+=aval_len+2;

      proto_tree_add_string(ajp13_tree, *req_attributes[aid],
                            tvb, apos, 1+aval_len+2, aval);

      if (trans && aid == 0x05)  /* query_string */
        trans->uri = wmem_strdup_printf(wmem_file_scope(), "%s?%s", trans->uri, aval);
    }
  }
}



/* main dissector function. wireshark calls it for segments in both
 * directions.
 */
static int
dissect_ajp13_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  uint16_t mag;
  /* uint16_t len; */
  conversation_t *conv = NULL;
  ajp13_conv_data *cd = NULL;
  proto_tree *ajp13_tree = NULL;
  ajp13_frame_data* fd = NULL;
  unsigned pdu_num;

  /* conversational state really only does us good during the first
   * in-order traversal
   */
  conv = find_or_create_conversation(pinfo);

  cd = (ajp13_conv_data*)conversation_get_proto_data(conv, proto_ajp13);
  if (!cd) {
    cd = wmem_new0(wmem_file_scope(), ajp13_conv_data);
    conversation_add_proto_data(conv, proto_ajp13, cd);
  }

  /* we use the per segment user data to record the conversational
   * state for use later on when we're called out of order (see
   * comments at top of this file). a segment can contain more than
   * one PDU, so the data is keyed by the PDU's position in the frame.
   */
  pdu_num = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_ajp13, 0));
  p_set_proto_data(pinfo->pool, pinfo, proto_ajp13, 0, GUINT_TO_POINTER(pdu_num + 1));

  fd = (ajp13_frame_data*)p_get_proto_data(wmem_file_scope(), pinfo, proto_ajp13, pdu_num);
  if (!fd) {
    /*printf("ajp13:dissect_ajp13_common():no frame data, adding");*/
    /* since there's no per-packet user data, this must be the first
     * time we've see the packet, and it must be the first "in order"
     * pass through the data.
     */
    fd = wmem_new0(wmem_file_scope(), ajp13_frame_data);
    p_add_proto_data(wmem_file_scope(), pinfo, proto_ajp13, pdu_num, fd);
    if (cd->content_length || cd->was_get_body_chunk) {
      /* this is screwy, see AJPv13.html. the idea is that if the
       * request has a body (as determined by the content-length
       * header), then there's always an immediate follow-up PDU with
       * no GET_BODY_CHUNK from the container. the following parts
       * of the body are sent in reply to GET_BODY_CHUNK.
       */
      fd->is_request_body = true;
    }
  }

  col_clear(pinfo->cinfo, COL_INFO);

  mag = tvb_get_ntohs(tvb, 0);
  /*  len = tvb_get_ntohs(tvb, 2); */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AJP13");

  if (mag == 0x1234 && !fd->is_request_body)
    col_append_fstr(pinfo->cinfo, COL_INFO, "%d:REQ:", conv->conv_index);
  else if (mag == 0x1234 && fd->is_request_body)
    col_append_fstr(pinfo->cinfo, COL_INFO, "%d:REQ:Body", conv->conv_index);
  else if (mag == 0x4142)
    col_append_fstr(pinfo->cinfo, COL_INFO, "%d:RSP:", conv->conv_index);
  else
    col_set_str(pinfo->cinfo, COL_INFO, "AJP13 Error?");

  if (tree) {
    proto_item *ti;
    ti = proto_tree_add_item(tree, proto_ajp13, tvb, 0, -1, ENC_NA);
    ajp13_tree = proto_item_add_subtree(ti, ett_ajp13);
  }

  if (mag == 0x1234) {

    if (fd->is_request_body)
      display_req_body(tvb, pinfo, ajp13_tree, cd, fd);
    else
      display_req_forward(tvb, pinfo, ajp13_tree, cd);

  } else if (mag == 0x4142) {

    display_rsp(tvb, pinfo, ajp13_tree, cd, fd);

  }

  return tvb_reported_length(tvb);
}



/* given the first chunk of the AJP13 pdu, extract out and return the
 * packet length. see comments in packet-tcp.c:tcp_dissect_pdus().
 */
static unsigned
get_ajp13_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  /*uint16_t magic;*/
  uint16_t plen;
  /*magic = tvb_get_ntohs(tvb, offset); */
  plen = tvb_get_ntohs(tvb, offset+2);
  plen += 4;
  return plen;
}



/* Code to actually dissect the packets.
 */
static int
dissect_ajp13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  /* Set up structures needed to add the protocol subtree and manage it
   */
  tcp_dissect_pdus(tvb, pinfo, tree,
                   true,                   /* desegment or not   */
                   4,                      /* magic + length */
                   get_ajp13_pdu_len,      /* use first 4, calc data len */
                   dissect_ajp13_tcp_pdu, data); /* the naive dissector */

  return tvb_reported_length(tvb);
}



void
proto_register_ajp13(void)
{
  module_t *ajp13_module;
  expert_module_t* expert_ajp13;

  static hf_register_info hf[] = {
    { &hf_ajp13_magic,
      { "Magic",  "ajp13.magic", FT_BYTES, BASE_NONE, NULL, 0x0, "Magic Number",
        HFILL }
    },
    { &hf_ajp13_len,
      { "Length",  "ajp13.len", FT_UINT16, BASE_DEC, NULL, 0x0, "Data Length",
        HFILL }
    },
    { &hf_ajp13_code,
      { "Code",  "ajp13.code", FT_UINT32, BASE_DEC, VALS(mtype_codes), 0x0, "Type Code",
         HFILL }
    },
    { &hf_ajp13_method,
      { "Method",  "ajp13.method", FT_UINT8, BASE_DEC, VALS(http_method_codes), 0x0, "HTTP Method",
        HFILL }
    },
    { &hf_ajp13_ver,
      { "Version",  "ajp13.ver", FT_STRING, BASE_NONE, NULL, 0x0, "HTTP Version",
        HFILL }
    },
    { &hf_ajp13_uri,
      { "URI",  "ajp13.uri", FT_STRING, BASE_NONE, NULL, 0x0, "HTTP URI",
        HFILL }
    },
    { &hf_ajp13_raddr,
      { "RADDR",  "ajp13.raddr", FT_STRING, BASE_NONE, NULL, 0x0, "Remote Address",
        HFILL }
    },
    { &hf_ajp13_rhost,
      { "RHOST",  "ajp13.rhost", FT_STRING, BASE_NONE, NULL, 0x0, "Remote Host",
        HFILL }
    },
    { &hf_ajp13_srv,
      { "SRV",  "ajp13.srv", FT_STRING, BASE_NONE, NULL, 0x0, "Server",
        HFILL }
    },
    { &hf_ajp13_port,
      { "PORT",  "ajp13.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_sslp,
      { "SSLP",  "ajp13.sslp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Is SSL?",
        HFILL }
    },
    { &hf_ajp13_nhdr,
      { "NHDR",  "ajp13.nhdr", FT_UINT16, BASE_DEC, NULL, 0x0, "Num Headers",
        HFILL }
    },
/* response headers */
    { &hf_ajp13_unknown_header,
      { "unknown_header",  "ajp13.unknown_header", FT_STRING, BASE_NONE, NULL, 0x0, "Unknown Header Type",
        HFILL }
    },
    { &hf_ajp13_content_type,
      { "Content-Type",  "ajp13.content_type", FT_STRING, BASE_NONE, NULL, 0x0, "Content-Type Header",
        HFILL }
    },
    { &hf_ajp13_content_language,
      { "Content-Language",  "ajp13.content_language", FT_STRING, BASE_NONE, NULL, 0x0, "Content-Language Header",
        HFILL }
    },
    { &hf_ajp13_content_length,
      { "Content-Length",  "ajp13.content_length", FT_STRING, BASE_NONE, NULL, 0x0, "Content-Length header",
        HFILL }
    },
    { &hf_ajp13_date,
      { "Date",  "ajp13.date", FT_STRING, BASE_NONE, NULL, 0x0, "Date Header",
        HFILL }
    },
    { &hf_ajp13_last_modified,
      { "Last-Modified",  "ajp13.last_modified", FT_STRING, BASE_NONE, NULL, 0x0, "Last Modified Header",
        HFILL }
    },
    { &hf_ajp13_location,
      { "Location",  "ajp13.location", FT_STRING, BASE_NONE, NULL, 0x0, "Location Header",
        HFILL }
    },
    { &hf_ajp13_set_cookie,
      { "Set-Cookie",  "ajp13.set_cookie", FT_STRING, BASE_NONE, NULL, 0x0, "Set-Cookie Header",
        HFILL }
    },
    { &hf_ajp13_set_cookie2,
      { "Set-Cookie2",  "ajp13.set_cookie2", FT_STRING, BASE_NONE, NULL, 0x0, "Set-Cookie2 Header",
        HFILL }
    },
    { &hf_ajp13_servlet_engine,
      { "Servlet-Engine",  "ajp13.servlet_engine", FT_STRING, BASE_NONE, NULL, 0x0, "Servlet-Engine Header",
        HFILL }
    },
    { &hf_ajp13_status,
      { "Status",  "ajp13.status", FT_STRING, BASE_NONE, NULL, 0x0, "Status Header",
        HFILL }
    },
    { &hf_ajp13_www_authenticate,
      { "WWW-Authenticate",  "ajp13.www_authenticate", FT_STRING, BASE_NONE, NULL, 0x0, "WWW-Authenticate Header",
        HFILL }
    },
/* request headers */
    { &hf_ajp13_accept,
      { "Accept",  "ajp13.accept", FT_STRING, BASE_NONE, NULL, 0x0, "Accept Header",
        HFILL }
    },
    { &hf_ajp13_accept_charset,
      { "Accept-Charset",  "ajp13.accept_charset", FT_STRING, BASE_NONE, NULL, 0x0, "Accept-Charset Header",
        HFILL }
    },
    { &hf_ajp13_accept_encoding,
      { "Accept-Encoding",  "ajp13.accept_encoding", FT_STRING, BASE_NONE, NULL, 0x0, "Accept-Encoding Header",
        HFILL }
    },
    { &hf_ajp13_accept_language,
      { "Accept-Language",  "ajp13.accept_language", FT_STRING, BASE_NONE, NULL, 0x0, "Accept-Language Header",
        HFILL }
    },
    { &hf_ajp13_authorization,
      { "Authorization",  "ajp13.authorization", FT_STRING, BASE_NONE, NULL, 0x0, "Authorization Header",
        HFILL }
    },
    { &hf_ajp13_connection,
      { "Connection",  "ajp13.connection", FT_STRING, BASE_NONE, NULL, 0x0, "Connection Header",
        HFILL }
    },
    { &hf_ajp13_cookie,
      { "Cookie",  "ajp13.cookie", FT_STRING, BASE_NONE, NULL, 0x0, "Cookie Header",
        HFILL }
    },
    { &hf_ajp13_cookie2,
      { "Cookie2",  "ajp13.cookie2", FT_STRING, BASE_NONE, NULL, 0x0, "Cookie2 Header",
        HFILL }
    },
    { &hf_ajp13_host,
      { "Host",  "ajp13.host", FT_STRING, BASE_NONE, NULL, 0x0, "Host Header",
        HFILL }
    },
    { &hf_ajp13_pragma,
      { "Pragma",  "ajp13.pragma", FT_STRING, BASE_NONE, NULL, 0x0, "Pragma Header",
        HFILL }
    },
    { &hf_ajp13_referer,
      { "Referer",  "ajp13.referer", FT_STRING, BASE_NONE, NULL, 0x0, "Referer Header",
        HFILL }
    },
    { &hf_ajp13_user_agent,
      { "User-Agent",  "ajp13.user_agent", FT_STRING, BASE_NONE, NULL, 0x0, "User-Agent Header",
        HFILL }
    },
/* request attributes */
    { &hf_ajp13_unknown_attribute,
      { "unknown_attribute",  "ajp13.unknown_attribute", FT_STRING, BASE_NONE, NULL, 0x0, "Unknown Attribute Type",
        HFILL }
    },
    { &hf_ajp13_req_attribute,
      { "req_attribute",  "ajp13.req_attribute", FT_STRING, BASE_NONE, NULL, 0x0, "Additional Attribute Type",
        HFILL }
    },
    { &hf_ajp13_context,
      { "Context",  "ajp13.context", FT_STRING, BASE_NONE, NULL, 0x0, "Context Attribute",
        HFILL }
    },
    { &hf_ajp13_servlet_path,
      { "Servlet-Path",  "ajp13.servlet_path", FT_STRING, BASE_NONE, NULL, 0x0, "Servlet-Path Attribute",
        HFILL }
    },
    { &hf_ajp13_remote_user,
      { "Remote-User",  "ajp13.remote_user", FT_STRING, BASE_NONE, NULL, 0x0, "Remote-User Attribute",
        HFILL }
    },
    { &hf_ajp13_auth_type,
      { "Auth-Type",  "ajp13.auth_type", FT_STRING, BASE_NONE, NULL, 0x0, "Auth-Type Attribute",
        HFILL }
    },
    { &hf_ajp13_query_string,
      { "Query-String",  "ajp13.query_string", FT_STRING, BASE_NONE, NULL, 0x0, "Query-String Attribute",
        HFILL }
    },
    { &hf_ajp13_route,
      { "Route",  "ajp13.route", FT_STRING, BASE_NONE, NULL, 0x0, "Route Attribute",
        HFILL }
    },
    { &hf_ajp13_ssl_cert,
      { "SSL-Cert",  "ajp13.ssl_cert", FT_STRING, BASE_NONE, NULL, 0x0, "SSL-Cert Attribute",
        HFILL }
    },
    { &hf_ajp13_ssl_cipher,
      { "SSL-Cipher",  "ajp13.ssl_cipher", FT_STRING, BASE_NONE, NULL, 0x0, "SSL-Cipher Attribute",
        HFILL }
    },
    { &hf_ajp13_ssl_session,
      { "SSL-Session",  "ajp13.ssl_session", FT_STRING, BASE_NONE, NULL, 0x0, "SSL-Session Attribute",
        HFILL }
    },
    { &hf_ajp13_ssl_key_size,
      { "SSL-Key-Size",  "ajp13.ssl_key_size", FT_UINT16, BASE_DEC, NULL, 0x0, "SSL-Key-Size Attribute",
        HFILL }
    },
    { &hf_ajp13_secret,
      { "Secret",  "ajp13.secret", FT_STRING, BASE_NONE, NULL, 0x0, "Secret Attribute",
        HFILL }
    },
    { &hf_ajp13_stored_method,
      { "Stored-Method",  "ajp13.stored_method", FT_STRING, BASE_NONE, NULL, 0x0, "Stored-Method Attribute",
        HFILL }
    },

    { &hf_ajp13_rlen,
      { "RLEN",  "ajp13.rlen", FT_UINT16, BASE_DEC, NULL, 0x0, "Requested Length",
        HFILL }
    },
    { &hf_ajp13_reusep,
      { "REUSEP",  "ajp13.reusep", FT_UINT8, BASE_DEC, NULL, 0x0, "Reuse Connection?",
        HFILL }
    },
    { &hf_ajp13_rstatus,
      { "RSTATUS",  "ajp13.rstatus", FT_UINT16, BASE_DEC, NULL, 0x0, "HTTP Status Code",
        HFILL }
    },
    { &hf_ajp13_rsmsg,
      { "RSMSG",  "ajp13.rsmsg", FT_STRING, BASE_NONE, NULL, 0x0, "HTTP Status Message",
        HFILL }
    },
    { &hf_ajp13_data,
      { "Data",  "ajp13.data", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
/* body reassembly */
    { &hf_ajp13_body_fragments,
      { "Body fragments", "ajp13.body.fragments", FT_NONE, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_fragment,
      { "Body fragment", "ajp13.body.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_fragment_overlap,
      { "Body fragment overlap", "ajp13.body.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_fragment_overlap_conflicts,
      { "Body fragment overlapping with conflicting data", "ajp13.body.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_fragment_multiple_tails,
      { "Body has multiple tail fragments", "ajp13.body.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_fragment_too_long_fragment,
      { "Body fragment too long", "ajp13.body.fragment.too_long_fragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_fragment_error,
      { "Body defragmentation error", "ajp13.body.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_fragment_count,
      { "Body fragment count", "ajp13.body.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_reassembled_in,
      { "Reassembled body in frame", "ajp13.body.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ajp13_body_reassembled_length,
      { "Reassembled body length", "ajp13.body.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
        HFILL }
    },
  };

  static ei_register_info ei[] = {
    { &ei_ajp13_content_length_invalid, { "ajp13.content_length.invalid", PI_MALFORMED, PI_ERROR,
      "Content-Length must be a string containing an integer", EXPFILL }}
  };

  static int *ett[] = {
    &ett_ajp13,
    &ett_ajp13_body_fragment,
    &ett_ajp13_body_fragments,
  };

  /* Register the protocol name and description
   */
  proto_ajp13 = proto_register_protocol("Apache JServ Protocol v1.3", "AJP13", "ajp13");

  proto_register_field_array(proto_ajp13, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_ajp13 = expert_register_protocol(proto_ajp13);
  expert_register_field_array(expert_ajp13, ei, array_length(ei));

  ajp13_module = prefs_register_protocol(proto_ajp13, NULL);
  prefs_register_bool_preference(ajp13_module, "reassemble_body",
                                 "Reassemble bodies spanning multiple AJP13 packets",
                                 "Whether the AJP13 dissector should reassemble request "
                                 "and response bodies spanning multiple AJP13 packets. "
                                 "This is needed to export the bodies with Export Objects.",
                                 &ajp13_reassemble_body);

  reassembly_table_register(&ajp13_body_reassembly_table,
                            &addresses_ports_reassembly_table_functions);

  ajp13_handle = register_dissector("ajp13", dissect_ajp13, proto_ajp13);

  ajp13_eo_tap = register_export_object(proto_ajp13, ajp13_eo_packet, NULL);
}



void
proto_reg_handoff_ajp13(void)
{
  dissector_add_uint_with_preference("tcp.port", AJP13_TCP_PORT, ajp13_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
