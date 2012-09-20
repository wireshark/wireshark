/* packet-ajp13.c
 * Routines for AJP13 dissection
 * Copyright 2002, Christopher K. St. John <cks@distributopia.com>
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

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include "packet-tcp.h"



/* IMPORTANT IMPLEMENTATION NOTES
 *
 * You need to be looking at:
 *
 *	http://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
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
 * uderstanding is that wireshark now contains a fairly substantial
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
 * store which PDU goes with which TCP segment. Luckly, recent
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



#define MTYPE_FORWARD_REQUEST	2
#define MTYPE_SEND_BODY_CHUNK	3
#define MTYPE_SEND_HEADERS	4
#define MTYPE_END_RESPONSE	5
#define MTYPE_GET_BODY_CHUNK	6
#define MTYPE_SHUTDOWN		7
#define MTYPE_CPONG		9
#define MTYPE_CPING		10

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



static int proto_ajp13     = -1;
static int hf_ajp13_magic  = -1;
static int hf_ajp13_len    = -1;
static int hf_ajp13_code   = -1;
static int hf_ajp13_method = -1;
static int hf_ajp13_ver    = -1;
static int hf_ajp13_uri    = -1;
static int hf_ajp13_raddr  = -1;
static int hf_ajp13_rhost  = -1;
static int hf_ajp13_srv    = -1;
static int hf_ajp13_port   = -1;
static int hf_ajp13_sslp   = -1;
static int hf_ajp13_nhdr   = -1;

/* response headers */
static int hf_ajp13_unknown_header    = -1;
static int hf_ajp13_additional_header = -1;
static int hf_ajp13_content_type      = -1;
static int hf_ajp13_content_language  = -1;
static int hf_ajp13_content_length    = -1;
static int hf_ajp13_date              = -1;
static int hf_ajp13_last_modified     = -1;
static int hf_ajp13_location          = -1;
static int hf_ajp13_set_cookie        = -1;
static int hf_ajp13_set_cookie2       = -1;
static int hf_ajp13_servlet_engine    = -1;
static int hf_ajp13_status            = -1;
static int hf_ajp13_www_authenticate  = -1;

/* request headers */
static int hf_ajp13_accept            = -1;
static int hf_ajp13_accept_charset    = -1;
static int hf_ajp13_accept_encoding   = -1;
static int hf_ajp13_accept_language   = -1;
static int hf_ajp13_authorization     = -1;
static int hf_ajp13_connection        = -1;
                 /* content_type   */
                 /* content_length */
static int hf_ajp13_cookie            = -1;
static int hf_ajp13_cookie2           = -1;
static int hf_ajp13_host              = -1;
static int hf_ajp13_pragma            = -1;
static int hf_ajp13_referer           = -1;
static int hf_ajp13_user_agent        = -1;

/* request attributes */
static int hf_ajp13_unknown_attribute     = -1;
static int hf_ajp13_req_attribute         = -1;
static int hf_ajp13_context               = -1;
static int hf_ajp13_servlet_path          = -1;
static int hf_ajp13_remote_user           = -1;
static int hf_ajp13_auth_type             = -1;
static int hf_ajp13_query_string          = -1;
static int hf_ajp13_route                 = -1;
static int hf_ajp13_ssl_cert              = -1;
static int hf_ajp13_ssl_cipher            = -1;
static int hf_ajp13_ssl_session           = -1;
static int hf_ajp13_ssl_key_size          = -1;
static int hf_ajp13_secret                = -1;
static int hf_ajp13_stored_method         = -1;

static int hf_ajp13_rlen   = -1;
static int hf_ajp13_reusep = -1;
static int hf_ajp13_rstatus= -1;
static int hf_ajp13_rsmsg  = -1;
static int hf_ajp13_data   = -1;
static gint ett_ajp13 = -1;

/*
 * Request/response header codes. Common headers are stored as ints in
 * an effort to improve performance. Why can't we just have one big
 * list?
 */
static const int* rsp_headers[] = {
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

static const int* req_headers[] = {
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

static const int* req_attributes[] = {
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

typedef struct ajp13_conv_data {
  int content_length;
  gboolean was_get_body_chunk;  /* XXX - not used */
} ajp13_conv_data;

typedef struct ajp13_frame_data {
  gboolean is_request_body;
} ajp13_frame_data;

/* ajp13, in sort of a belt-and-suspenders move, encodes strings with
 * both a leading length field, and a trailing null. Mostly, see
 * ajpv13a.html. The returned length _includes_ the trailing null, if
 * there is one.
 *
 * XXX - is there a tvbuff routine to handle this?
 */
static const gchar *
ajp13_get_nstring(tvbuff_t *tvb, gint offset, guint16* ret_len)
{
  guint16 len;

  len = tvb_get_ntohs(tvb, offset);

  if (ret_len)
    *ret_len = len+1;

  /* a size of 0xFFFF indicates a null string - no data follows */
  if (len == 0xFFFF)
    len = 0;

  return tvb_format_text(tvb, offset+2, MIN(len, ITEM_LABEL_LENGTH));
}



/* dissect a response. more work to do here.
 */
static void
display_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ajp13_tree, ajp13_conv_data* cd)
{
  int pos = 0;
  guint8 mcode = 0;
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
  mcode = tvb_get_guint8(tvb, pos);
  col_append_str(pinfo->cinfo, COL_INFO, val_to_str(mcode, mtype_codes, "Unknown message code %u"));
  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_code, tvb, pos, 1, ENC_BIG_ENDIAN);
  pos+=1;

  switch (mcode) {

  case MTYPE_END_RESPONSE:
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_reusep, tvb, pos, 1, ENC_BIG_ENDIAN);
    /*pos+=1;*/
    break;

  case MTYPE_SEND_HEADERS:
  {
    const gchar *rsmsg;
    guint16 rsmsg_len;
    guint16 nhdr;
    guint16 rcode_num;

    /* HTTP RESPONSE STATUS CODE
     */
    rcode_num = tvb_get_ntohs(tvb, pos);
    col_append_fstr(pinfo->cinfo, COL_INFO, ":%d", rcode_num);
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_rstatus, tvb, pos, 2, ENC_BIG_ENDIAN);
    pos+=2;

    /* HTTP RESPONSE STATUS MESSAGE
     */
    rsmsg = ajp13_get_nstring(tvb, pos, &rsmsg_len);
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

    /* HEADERS
     */
    for(i=0; i<nhdr; i++) {

      guint8 hcd;
      guint8 hid;
      const gchar *hval;
      guint16 hval_len, hname_len;
      const gchar* hname = NULL;
      header_field_info *hfinfo;
      int hpos = pos;
      /* int cl = 0; TODO: Content-Length header (encoded by 0x08) is special */

      /* HEADER CODE/NAME
       */
      hcd = tvb_get_guint8(tvb, pos);

      if (hcd == 0xA0) {
        pos+=1;
        hid = tvb_get_guint8(tvb, pos);
        pos+=1;

        if (hid >= array_length(rsp_headers))
          hid = 0;

        hval = ajp13_get_nstring(tvb, pos, &hval_len);

        if (ajp13_tree) {
          hfinfo = proto_registrar_get_nth(*rsp_headers[hid]);
          proto_tree_add_string_format(ajp13_tree, *rsp_headers[hid],
                                       tvb, hpos, 2+hval_len+2, hval,
                                       "%s: %s", hfinfo->name, hval);
        }
        pos+=hval_len+2;
#if 0
        /* TODO: Content-Length header (encoded by 0x08) is special */
        if (hid == 0x08)
          cl = 1;
#endif
      } else {
        hname = ajp13_get_nstring(tvb, pos, &hname_len);
        pos+=hname_len+2;

        hval = ajp13_get_nstring(tvb, pos, &hval_len);

        if (ajp13_tree) {
          proto_tree_add_string_format(ajp13_tree, hf_ajp13_additional_header,
                                tvb, hpos, hname_len+2+hval_len+2,
                                ep_strdup_printf("%s: %s", hname, hval),
                                "%s: %s", hname, hval);
        }
        pos+=hval_len+2;
      }
    }
    break;
  }

  case MTYPE_GET_BODY_CHUNK:
  {
    guint16 rlen;
    rlen = tvb_get_ntohs(tvb, pos);
    cd->content_length = rlen;
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_rlen, tvb, pos, 2, ENC_BIG_ENDIAN);
    /*pos+=2;*/
    break;
  }

  case MTYPE_CPONG:
    break;

  default:
    /* MESSAGE DATA (COPOUT)
     */
    if (ajp13_tree)
      proto_tree_add_item(ajp13_tree, hf_ajp13_data,  tvb, pos+2, -1, ENC_UTF_8|ENC_NA);
    break;
  }
}



/* dissect a request body. see AJPv13.html, but the idea is that these
 * packets, unlike all other packets, have no type field. you just
 * sort of have to know that they're coming based on the previous
 * packets.
 */
static void
display_req_body(tvbuff_t *tvb, proto_tree *ajp13_tree, ajp13_conv_data* cd)
{
  /*printf("ajp13:display_req_body()\n");*/
  /*
   * In a resued connection this is never reset.
   */
  guint16 content_length;
  guint16 packet_length;

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

  if (packet_length == 0)
  {
    /*
     * We've got an empty packet:
     * 0x12 0x34 0x00 0x00
     * It signals that there is no more data in the body
     */
    cd->content_length = 0;
    return;
  }

  /* BODY (AS STRING)
   */
  content_length = tvb_get_ntohs( tvb, pos);
  if (content_length == 0) {
    /* zero length content also signals no more body data */
    cd->content_length = 0;
    return;
  }
  cd->content_length -= content_length;
  proto_tree_add_item(ajp13_tree, hf_ajp13_data, tvb, pos+2, content_length, ENC_UTF_8|ENC_NA);
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
  guint8 meth;
  guint8 cod;
  const gchar *ver;
  guint16 ver_len;
  const gchar *uri;
  guint16 uri_len;
  const gchar *raddr;
  guint16 raddr_len;
  const gchar *rhost;
  guint16 rhost_len;
  const gchar *srv;
  guint16 srv_len;
  guint nhdr;
  guint i;

  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_magic, tvb, pos, 2, ENC_NA);
  pos+=2;

  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_len, tvb, pos, 2, ENC_BIG_ENDIAN);
  pos+=2;

  /* PACKET CODE
   */
  cod = tvb_get_guint8(tvb, 4);
  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_code, tvb, pos, 1, ENC_BIG_ENDIAN);
  pos+=1;
  if ( cod == MTYPE_CPING ) {
    col_append_str(pinfo->cinfo, COL_INFO, "CPING" );
    return;
  }

  /* HTTP METHOD (ENCODED AS INTEGER)
   */
  meth = tvb_get_guint8(tvb, pos);
  col_append_str(pinfo->cinfo, COL_INFO, val_to_str(meth, http_method_codes, "Unknown method %u"));
  if (ajp13_tree)
    proto_tree_add_item(ajp13_tree, hf_ajp13_method, tvb, pos, 1, ENC_BIG_ENDIAN);
  pos+=1;

  /* HTTP VERSION STRING
   */
  ver = ajp13_get_nstring(tvb, pos, &ver_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_ver, tvb, pos, ver_len+2, ver);
  pos=pos+ver_len+2;  /* skip over size + chars + trailing null */

  /* URI
   */
  uri = ajp13_get_nstring(tvb, pos, &uri_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_uri, tvb, pos, uri_len+2, uri);
  pos=pos+uri_len+2;  /* skip over size + chars + trailing null */


  col_append_fstr(pinfo->cinfo, COL_INFO, " %s %s", uri, ver);


  /* REMOTE ADDRESS
   */
  raddr = ajp13_get_nstring(tvb, pos, &raddr_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_raddr, tvb, pos, raddr_len+2, raddr);
  pos=pos+raddr_len+2;  /* skip over size + chars + trailing null */

  /* REMOTE HOST
   */
  rhost = ajp13_get_nstring(tvb, pos, &rhost_len);
  if (ajp13_tree)
    proto_tree_add_string(ajp13_tree, hf_ajp13_rhost, tvb, pos, rhost_len+2, rhost);
  pos=pos+rhost_len+2;  /* skip over size + chars + trailing null */

  /* SERVER NAME
   */
  srv = ajp13_get_nstring(tvb, pos, &srv_len);
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
  cd->content_length = 0;

  /* HEADERS
   */
  for(i=0; i<nhdr; i++) {

    guint8 hcd;
    guint8 hid;
    const gchar* hname = NULL;
    header_field_info *hfinfo;
    int hpos = pos;
    int cl = 0;
    const gchar *hval;
    guint16 hval_len, hname_len;

    /* HEADER CODE/NAME
     */
    hcd = tvb_get_guint8(tvb, pos);

    if (hcd == 0xA0) {
      pos+=1;
      hid = tvb_get_guint8(tvb, pos);
      pos+=1;

      if (hid >= array_length(req_headers))
        hid = 0;

      hval = ajp13_get_nstring(tvb, pos, &hval_len);

      if (ajp13_tree) {
        hfinfo = proto_registrar_get_nth(*req_headers[hid]);
        proto_tree_add_string_format(ajp13_tree, *req_headers[hid],
                                     tvb, hpos, 2+hval_len+2, hval,
                                     "%s: %s", hfinfo->name, hval);
      }
      pos+=hval_len+2;

      if (hid == 0x08)
        cl = 1;
    } else {
      hname = ajp13_get_nstring(tvb, pos, &hname_len);
      pos+=hname_len+2;

      hval = ajp13_get_nstring(tvb, pos, &hval_len);

      if (ajp13_tree) {
        proto_tree_add_string_format(ajp13_tree, hf_ajp13_additional_header,
                                     tvb, hpos, hname_len+2+hval_len+2,
                                     ep_strdup_printf("%s: %s", hname, hval),
                                     "%s: %s", hname, hval);
      }
      pos+=hval_len+2;
    }

    if (cl) {
      cl = atoi(hval);
      cd->content_length = cl;
    }
  }

  /* ATTRIBUTES
   */
  while(tvb_reported_length_remaining(tvb, pos) > 0) {
    guint8 aid;
    const gchar* aname = NULL;
    const gchar* aval;
    guint16 aval_len, aname_len;

    header_field_info *hfinfo;
    int apos = pos;

    /* ATTRIBUTE CODE/NAME
     */
    aid = tvb_get_guint8(tvb, pos);
    pos+=1;

    if (aid == 0xFF) {
      /* request terminator */
      break;
    }
    if (aid == 0x0A) {
      /* req_attribute - name and value follow */

      aname = ajp13_get_nstring(tvb, pos, &aname_len);
      pos+=aname_len+2;

      aval = ajp13_get_nstring(tvb, pos, &aval_len);
      pos+=aval_len+2;

      if (ajp13_tree) {
        proto_tree_add_string_format(ajp13_tree, hf_ajp13_req_attribute,
                                     tvb, apos, 1+aname_len+2+aval_len+2,
                                     ep_strdup_printf("%s: %s", aname, aval),
                                     "%s: %s", aname, aval);
      }
    } else if (aid == 0x0B ) {
      /* ssl_key_length */
      if (ajp13_tree) {
        proto_tree_add_uint(ajp13_tree, hf_ajp13_ssl_key_size,
                            tvb, apos, 1+2, tvb_get_ntohs(tvb, pos));
      }
      pos+=2;
    } else {

      if (aid >= array_length(req_attributes))
        aid = 0;

      hfinfo = proto_registrar_get_nth(*req_attributes[aid]);
      aval = ajp13_get_nstring(tvb, pos, &aval_len);
      pos+=aval_len+2;

      if (ajp13_tree) {
        proto_tree_add_string_format(ajp13_tree, *req_attributes[aid],
                                     tvb, apos, 1+aval_len+2, aval,
                                     "%s: %s", hfinfo->name, aval);
      }
    }
  }
}



/* main dissector function. wireshark calls it for segments in both
 * directions.
 */
static void
dissect_ajp13_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16 mag;
  /* guint16 len; */
  conversation_t *conv = NULL;
  ajp13_conv_data *cd = NULL;
  proto_tree *ajp13_tree = NULL;
  ajp13_frame_data* fd = NULL;

  /* conversational state really only does us good during the first
   * in-order traversal
   */
  conv = find_or_create_conversation(pinfo);

  cd = (ajp13_conv_data*)conversation_get_proto_data(conv, proto_ajp13);
  if (!cd) {
    cd = se_new(ajp13_conv_data);
    cd->content_length = 0;
    cd->was_get_body_chunk = FALSE;
    conversation_add_proto_data(conv, proto_ajp13, cd);
  }

  /* we use the per segment user data to record the conversational
   * state for use later on when we're called out of order (see
   * comments at top of this file)
   */
  fd = (ajp13_frame_data*)p_get_proto_data(pinfo->fd, proto_ajp13);
  if (!fd) {
    /*printf("ajp13:dissect_ajp13_common():no frame data, adding");*/
    /* since there's no per-packet user data, this must be the first
     * time we've see the packet, and it must be the first "in order"
     * pass through the data.
     */
    fd = se_new(ajp13_frame_data);
    p_add_proto_data(pinfo->fd, proto_ajp13, fd);
    fd->is_request_body = FALSE;
    if (cd->content_length) {
      /* this is screwy, see AJPv13.html. the idea is that if the
       * request has a body (as determined by the content-length
       * header), then there's always an immediate follow-up PDU with
       * no GET_BODY_CHUNK from the container.
       */
      fd->is_request_body = TRUE;
    }
  }

  col_clear(pinfo->cinfo, COL_INFO);

  mag = tvb_get_ntohs(tvb, 0);
  /*  len = tvb_get_ntohs(tvb, 2); */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AJP13");

  if (mag == 0x1234 && !fd->is_request_body)
    col_append_fstr(pinfo->cinfo, COL_INFO, "%d:REQ:", conv->index);
  else if (mag == 0x1234 && fd->is_request_body)
    col_append_fstr(pinfo->cinfo, COL_INFO, "%d:REQ:Body", conv->index);
  else if (mag == 0x4142)
    col_append_fstr(pinfo->cinfo, COL_INFO, "%d:RSP:", conv->index);
  else
    col_set_str(pinfo->cinfo, COL_INFO, "AJP13 Error?");

  if (tree) {
    proto_item *ti;
    ti = proto_tree_add_item(tree, proto_ajp13, tvb, 0, -1, ENC_NA);
    ajp13_tree = proto_item_add_subtree(ti, ett_ajp13);
  }

  if (mag == 0x1234) {

    if (fd->is_request_body)
      display_req_body(tvb, ajp13_tree, cd);
    else
      display_req_forward(tvb, pinfo, ajp13_tree, cd);

  } else if (mag == 0x4142) {

    display_rsp(tvb, pinfo, ajp13_tree, cd);

  }
}



/* given the first chunk of the AJP13 pdu, extract out and return the
 * packet length. see comments in packet-tcp.c:tcp_dissect_pdus().
 */
static guint
get_ajp13_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  /*guint16 magic;*/
  guint16 plen;
  /*magic = tvb_get_ntohs(tvb, offset); */
  plen = tvb_get_ntohs(tvb, offset+2);
  plen += 4;
  return plen;
}



/* Code to actually dissect the packets.
 */
static void
dissect_ajp13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* Set up structures needed to add the protocol subtree and manage it
   */
  tcp_dissect_pdus(tvb, pinfo, tree,
                   TRUE,                   /* desegment or not   */
                   4,                      /* magic + length */
                   get_ajp13_pdu_len,      /* use first 4, calc data len */
                   dissect_ajp13_tcp_pdu); /* the naive dissector */
}



void
proto_register_ajp13(void)
{
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
    { &hf_ajp13_additional_header,
      { "additional_header",  "ajp13.additional_header", FT_STRING, BASE_NONE, NULL, 0x0, "Additional Header Type",
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
      { "RSMSG",  "ajp13.rmsg", FT_STRING, BASE_NONE, NULL, 0x0, "HTTP Status Message",
        HFILL }
    },
    { &hf_ajp13_data,
      { "Data",  "ajp13.data", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
        HFILL }
    },
  };

  static gint *ett[] = {
    &ett_ajp13,
  };

  /* Register the protocol name and description
   */
  proto_ajp13 = proto_register_protocol("Apache JServ Protocol v1.3", "AJP13", "ajp13");

  proto_register_field_array(proto_ajp13, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}



void
proto_reg_handoff_ajp13(void)
{
  dissector_handle_t ajp13_handle;
  ajp13_handle = create_dissector_handle(dissect_ajp13, proto_ajp13);
  dissector_add_uint("tcp.port", 8009, ajp13_handle);
}
