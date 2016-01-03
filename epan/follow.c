/* follow.c
 *
 * Copyright 1998 Mike Hall <mlh@io.com>
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
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-udp.h>
#include "follow.h"
#include <epan/conversation.h>
#include <epan/tap.h>

#define MAX_IPADDR_LEN  16

typedef struct _tcp_frag {
  guint32             seq;
  guint32             len;
  guint32             data_len;
  gchar              *data;
  struct _tcp_frag   *next;
} tcp_frag;

WS_DLL_PUBLIC_DEF
FILE* data_out_file = NULL;

gboolean empty_tcp_stream;
gboolean incomplete_tcp_stream;

static guint32 stream_to_follow[MAX_STREAM] = {0};
static gboolean find_addr[MAX_STREAM] = {FALSE};
static gboolean find_index[MAX_STREAM] = {FALSE};
static address tcp_addr[2];
static guint8  ip_address[2][MAX_IPADDR_LEN];
static guint   port[2];
static guint   bytes_written[2];
static gboolean is_ipv6 = FALSE;

void
follow_stats(follow_stats_t* stats)
{
  int i;

  for (i = 0; i < 2 ; i++) {
    memcpy(stats->ip_address[i], ip_address[i], MAX_IPADDR_LEN);
    stats->port[i] = port[i];
    stats->bytes_written[i] = bytes_written[i];
    stats->is_ipv6 = is_ipv6;
  }
}

/* This will build a display filter text that will only
   pass the packets related to the stream. There is a
   chance that two streams could intersect, but not a
   very good one */
gchar*
build_follow_conv_filter( packet_info *pi, const char* append_filter ) {
  char* buf;
  int len;
  conversation_t *conv=NULL;
  struct tcp_analysis *tcpd;
  struct udp_analysis *udpd;
  wmem_list_frame_t* protos;
  int proto_id;
  const char* proto_name;
  gboolean is_tcp = FALSE, is_udp = FALSE;

  protos = wmem_list_head(pi->layers);

  /* walk the list of a available protocols in the packet to
      figure out if any of them affect context sensitivity */
  while (protos != NULL)
  {
    proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
    proto_name = proto_get_protocol_filter_name(proto_id);

    if (!strcmp(proto_name, "tcp")) {
        is_tcp = TRUE;
    } else if (!strcmp(proto_name, "udp")) {
        is_udp = TRUE;
    }

    protos = wmem_list_frame_next(protos);
  }

  if( ((pi->net_src.type == AT_IPv4 && pi->net_dst.type == AT_IPv4) ||
       (pi->net_src.type == AT_IPv6 && pi->net_dst.type == AT_IPv6))
       && is_tcp && (conv=find_conversation(pi->fd->num, &pi->src, &pi->dst, pi->ptype,
              pi->srcport, pi->destport, 0)) != NULL ) {
    /* TCP over IPv4/6 */
    tcpd=get_tcp_conversation_data(conv, pi);
    if (tcpd) {
      if (append_filter == NULL) {
        buf = g_strdup_printf("tcp.stream eq %d", tcpd->stream);
      } else {
        buf = g_strdup_printf("((tcp.stream eq %d) && (%s))", tcpd->stream, append_filter);
      }
      stream_to_follow[TCP_STREAM] = tcpd->stream;
      if (pi->net_src.type == AT_IPv4) {
        len = 4;
        is_ipv6 = FALSE;
      } else {
        len = 16;
        is_ipv6 = TRUE;
      }
    } else {
      return NULL;
    }
  }
  else if( ((pi->net_src.type == AT_IPv4 && pi->net_dst.type == AT_IPv4) ||
            (pi->net_src.type == AT_IPv6 && pi->net_dst.type == AT_IPv6))
          && is_udp && (conv=find_conversation(pi->fd->num, &pi->src, &pi->dst, pi->ptype,
              pi->srcport, pi->destport, 0)) != NULL ) {
    /* UDP over IPv4/6 */
    udpd=get_udp_conversation_data(conv, pi);
    if (udpd) {
      if (append_filter == NULL) {
        buf = g_strdup_printf("udp.stream eq %d", udpd->stream);
      } else {
        buf = g_strdup_printf("((udp.stream eq %d) && (%s))", udpd->stream, append_filter);
      }
      stream_to_follow[UDP_STREAM] = udpd->stream;
      if (pi->net_src.type == AT_IPv4) {
        len = 4;
        is_ipv6 = FALSE;
      } else {
        len = 16;
        is_ipv6 = TRUE;
      }
    } else {
      return NULL;
    }
  }
  else {
    return NULL;
  }
  memcpy(ip_address[0], pi->net_src.data, len);
  memcpy(ip_address[1], pi->net_dst.data, len);
  port[0] = pi->srcport;
  port[1] = pi->destport;
  return buf;
}

static gboolean
udp_follow_packet(void *tapdata _U_, packet_info *pinfo,
                  epan_dissect_t *edt _U_, const void *data _U_)
{
  if (find_addr[UDP_STREAM]) {
    if (pinfo->net_src.type == AT_IPv6) {
      is_ipv6 = TRUE;
    } else {
      is_ipv6 = FALSE;
    }
    memcpy(ip_address[0], pinfo->net_src.data, pinfo->net_src.len);
    memcpy(ip_address[1], pinfo->net_dst.data, pinfo->net_dst.len);
    port[0] = pinfo->srcport;
    port[1] = pinfo->destport;
    find_addr[UDP_STREAM] = FALSE;
  }

  return FALSE;
}


/* here we are going to try and reconstruct the data portion of a TCP
   session. We will try and handle duplicates, TCP fragments, and out
   of order packets in a smart way. */

static tcp_frag *frags[2] = { 0, 0 };
static guint32 seq[2];
static guint8 src_addr[2][MAX_IPADDR_LEN];
static guint src_port[2] = { 0, 0 };

void
reset_stream_follow(stream_type stream) {
  tcp_frag *current, *next;
  int i;

  remove_tap_listener(&stream_to_follow[stream]);
  find_addr[stream] = FALSE;
  find_index[stream] = FALSE;
  if (stream == TCP_STREAM) {
    empty_tcp_stream = TRUE;
    incomplete_tcp_stream = FALSE;

    for( i=0; i<2; i++ ) {
      seq[i] = 0;
      memset(src_addr[i], '\0', MAX_IPADDR_LEN);
      src_port[i] = 0;
      memset(ip_address[i], '\0', MAX_IPADDR_LEN);
      port[i] = 0;
      bytes_written[i] = 0;
      current = frags[i];
      while( current ) {
        next = current->next;
        g_free( current->data );
        g_free( current );
        current = next;
      }
      frags[i] = NULL;
    }
  }
}

gchar*
build_follow_index_filter(stream_type stream) {
  gchar *buf;

  find_addr[stream] = TRUE;
  if (stream == TCP_STREAM) {
    buf = g_strdup_printf("tcp.stream eq %d", stream_to_follow[TCP_STREAM]);
  } else {
    GString * error_string;
    buf = g_strdup_printf("udp.stream eq %d", stream_to_follow[UDP_STREAM]);
    error_string = register_tap_listener("udp_follow", &stream_to_follow[UDP_STREAM], buf, 0, NULL, udp_follow_packet, NULL);
    if (error_string) {
      g_string_free(error_string, TRUE);
    }
  }
  return buf;
}

/* select a tcp stream to follow via it's address/port pairs */
gboolean
follow_addr(stream_type stream, const address *addr0, guint port0,
            const address *addr1, guint port1)
{
  if (addr0 == NULL || addr1 == NULL || addr0->type != addr1->type ||
      port0 > G_MAXUINT16 || port1 > G_MAXUINT16 )  {
    return FALSE;
  }

  if (find_index[stream] || find_addr[stream]) {
    return FALSE;
  }

  switch (addr0->type) {
  default:
    return FALSE;
  case AT_IPv4:
  case AT_IPv6:
    is_ipv6 = addr0->type == AT_IPv6;
    break;
  }


  memcpy(ip_address[0], addr0->data, addr0->len);
  port[0] = port0;

  memcpy(ip_address[1], addr1->data, addr1->len);
  port[1] = port1;

  if (stream == TCP_STREAM) {
    find_index[TCP_STREAM] = TRUE;
    set_address(&tcp_addr[0], addr0->type, addr0->len, ip_address[0]);
    set_address(&tcp_addr[1], addr1->type, addr1->len, ip_address[1]);
  }

  return TRUE;
}

/* select a stream to follow via its index */
gboolean
follow_index(stream_type stream, guint32 indx)
{
  if (find_index[stream] || find_addr[stream]) {
    return FALSE;
  }

  find_addr[stream] = TRUE;
  stream_to_follow[stream] = indx;
  memset(ip_address, 0, sizeof ip_address);
  port[0] = port[1] = 0;

  return TRUE;
}

guint32
get_follow_index(stream_type stream) {
  return stream_to_follow[stream];
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
