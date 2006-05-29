/* follow.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>
#include <epan/packet.h>
#include "follow.h"

#define MAX_IPADDR_LEN  16

typedef struct _tcp_frag {
  gulong              seq;
  gulong              len;
  gulong              data_len;
  gchar              *data;
  struct _tcp_frag   *next;
} tcp_frag;

FILE* data_out_file = NULL;

gboolean incomplete_tcp_stream = FALSE;

static guint8  ip_address[2][MAX_IPADDR_LEN];
static guint   tcp_port[2];
static guint   bytes_written[2];
static gboolean is_ipv6 = FALSE;

static int check_fragments( int, tcp_stream_chunk * );
static void write_packet_data( int, tcp_stream_chunk *, const char * );

void
follow_tcp_stats(follow_tcp_stats_t* stats)
{
	int i;

	for (i = 0; i < 2 ; i++) {
		memcpy(stats->ip_address[i], ip_address[i], MAX_IPADDR_LEN);
		stats->tcp_port[i] = tcp_port[i];
		stats->bytes_written[i] = bytes_written[i];
		stats->is_ipv6 = is_ipv6;
	}
}

/* this will build libpcap filter text that will only
   pass the packets related to the stream. There is a
   chance that two streams could intersect, but not a
   very good one */
char*
build_follow_filter( packet_info *pi ) {
  char* buf;
  int len;
  if( pi->net_src.type == AT_IPv4 && pi->net_dst.type == AT_IPv4
	&& pi->ipproto == 6 ) {
    /* TCP over IPv4 */
    buf = g_strdup_printf(
	     "(ip.addr eq %s and ip.addr eq %s) and (tcp.port eq %d and tcp.port eq %d)",
	     ip_to_str( pi->net_src.data),
	     ip_to_str( pi->net_dst.data),
	     pi->srcport, pi->destport );
    len = 4;
    is_ipv6 = FALSE;
  }
  else if( pi->net_src.type == AT_IPv6 && pi->net_dst.type == AT_IPv6
	&& pi->ipproto == 6 ) {
    /* TCP over IPv6 */
    buf = g_strdup_printf(
	     "(ipv6.addr eq %s and ipv6.addr eq %s) and (tcp.port eq %d and tcp.port eq %d)",
	     ip6_to_str((const struct e_in6_addr *)pi->net_src.data),
	     ip6_to_str((const struct e_in6_addr *)pi->net_dst.data),
	     pi->srcport, pi->destport );
    len = 16;
    is_ipv6 = TRUE;
  }
  else {
    return NULL;
  }
  memcpy(ip_address[0], pi->net_src.data, len);
  memcpy(ip_address[1], pi->net_dst.data, len);
  tcp_port[0] = pi->srcport;
  tcp_port[1] = pi->destport;
  return buf;
}

/* here we are going to try and reconstruct the data portion of a TCP
   session. We will try and handle duplicates, TCP fragments, and out
   of order packets in a smart way. */

static tcp_frag *frags[2] = { 0, 0 };
static gulong seq[2];
static guint8 src_addr[2][MAX_IPADDR_LEN];
static guint src_port[2] = { 0, 0 };

void
reassemble_tcp( gulong sequence, gulong length, const char* data,
		gulong data_length, int synflag, address *net_src,
		address *net_dst, guint srcport, guint dstport) {
  guint8 srcx[MAX_IPADDR_LEN], dstx[MAX_IPADDR_LEN];
  int src_index, j, first = 0, len;
  gulong newseq;
  tcp_frag *tmp_frag;
  tcp_stream_chunk sc;

  src_index = -1;

  /* First, check if this packet should be processed. */

  if ((net_src->type != AT_IPv4 && net_src->type != AT_IPv6) ||
      (net_dst->type != AT_IPv4 && net_dst->type != AT_IPv6))
    return;

  if (net_src->type == AT_IPv4)
    len = 4;
  else
    len = 16;

  /* Now check if the packet is for this connection. */
  memcpy(srcx, net_src->data, len);
  memcpy(dstx, net_dst->data, len);
  if (
      ! (
	 memcmp(srcx, ip_address[0], len) == 0 &&
	 memcmp(dstx, ip_address[1], len) == 0 &&
	 srcport == tcp_port[0] &&
	 dstport == tcp_port[1]
	) &&
      ! (
	 memcmp(srcx, ip_address[1], len) == 0 &&
	 memcmp(dstx, ip_address[0], len) == 0 &&
	 srcport == tcp_port[1] &&
	 dstport == tcp_port[0]
	)
     )
    return;

  /* Initialize our stream chunk.  This data gets written to disk. */
  memcpy(sc.src_addr, srcx, len);
  sc.src_port = srcport;
  sc.dlen     = data_length;

  /* Check to see if we have seen this source IP and port before.
     (Yes, we have to check both source IP and port; the connection
     might be between two different ports on the same machine.) */
  for( j=0; j<2; j++ ) {
    if (memcmp(src_addr[j], srcx, len) == 0 && src_port[j] == srcport ) {
      src_index = j;
    }
  }
  /* we didn't find it if src_index == -1 */
  if( src_index < 0 ) {
    /* assign it to a src_index and get going */
    for( j=0; j<2; j++ ) {
      if( src_port[j] == 0 ) {
	memcpy(src_addr[j], srcx, len);
	src_port[j] = srcport;
	src_index = j;
	first = 1;
	break;
      }
    }
  }
  if( src_index < 0 ) {
    fprintf( stderr, "ERROR in reassemble_tcp: Too many addresses!\n");
    return;
  }

  if( data_length < length ) {
    incomplete_tcp_stream = TRUE;
  }

  /* now that we have filed away the srcs, lets get the sequence number stuff
     figured out */
  if( first ) {
    /* this is the first time we have seen this src's sequence number */
    seq[src_index] = sequence + length;
    if( synflag ) {
      seq[src_index]++;
    }
    /* write out the packet data */
    write_packet_data( src_index, &sc, data );
    return;
  }
  /* if we are here, we have already seen this src, let's
     try and figure out if this packet is in the right place */
  if( sequence < seq[src_index] ) {
    /* this sequence number seems dated, but
       check the end to make sure it has no more
       info than we have already seen */
    newseq = sequence + length;
    if( newseq > seq[src_index] ) {
      gulong new_len;

      /* this one has more than we have seen. let's get the
	 payload that we have not seen. */

      new_len = seq[src_index] - sequence;

      if ( data_length <= new_len ) {
	data = NULL;
	data_length = 0;
	incomplete_tcp_stream = TRUE;
      } else {
	data += new_len;
	data_length -= new_len;
      }
      sc.dlen = data_length;
      sequence = seq[src_index];
      length = newseq - seq[src_index];

      /* this will now appear to be right on time :) */
    }
  }
  if ( sequence == seq[src_index] ) {
    /* right on time */
    seq[src_index] += length;
    if( synflag ) seq[src_index]++;
    if( data ) {
      write_packet_data( src_index, &sc, data );
    }
    /* done with the packet, see if it caused a fragment to fit */
    while( check_fragments( src_index, &sc ) )
      ;
  }
  else {
    /* out of order packet */
    if(data_length > 0 && sequence > seq[src_index] ) {
      tmp_frag = (tcp_frag *)g_malloc( sizeof( tcp_frag ) );
      tmp_frag->data = (guchar *)g_malloc( data_length );
      tmp_frag->seq = sequence;
      tmp_frag->len = length;
      tmp_frag->data_len = data_length;
      memcpy( tmp_frag->data, data, data_length );
      if( frags[src_index] ) {
	tmp_frag->next = frags[src_index];
      } else {
	tmp_frag->next = NULL;
      }
      frags[src_index] = tmp_frag;
    }
  }
} /* end reassemble_tcp */

/* here we search through all the frag we have collected to see if
   one fits */
static int
check_fragments( int index, tcp_stream_chunk *sc ) {
  tcp_frag *prev = NULL;
  tcp_frag *current;
  current = frags[index];
  while( current ) {
    if( current->seq == seq[index] ) {
      /* this fragment fits the stream */
      if( current->data ) {
        sc->dlen = current->data_len;
	write_packet_data( index, sc, current->data );
      }
      seq[index] += current->len;
      if( prev ) {
	prev->next = current->next;
      } else {
	frags[index] = current->next;
      }
      g_free( current->data );
      g_free( current );
      return 1;
    }
    prev = current;
    current = current->next;
  }
  return 0;
}

/* this should always be called before we start to reassemble a stream */
void
reset_tcp_reassembly() {
  tcp_frag *current, *next;
  int i;
  incomplete_tcp_stream = FALSE;
  for( i=0; i<2; i++ ) {
    seq[i] = 0;
    memset(src_addr[i], '\0', MAX_IPADDR_LEN);
    src_port[i] = 0;
    memset(ip_address[i], '\0', MAX_IPADDR_LEN);
    tcp_port[i] = 0;
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

static void
write_packet_data( int index, tcp_stream_chunk *sc, const char *data )
{
  fwrite( sc, 1, sizeof(tcp_stream_chunk), data_out_file );
  fwrite( data, 1, sc->dlen, data_out_file );
  bytes_written[index] += sc->dlen;
}
