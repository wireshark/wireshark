/* follow.c
 *
 * $Id: follow.c,v 1.18 1999/11/28 03:35:09 gerald Exp $
 *
 * Copyright 1998 Mike Hall <mlh@io.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "gtk/main.h"
#include "packet.h"
#include "follow.h"

extern FILE* data_out_file;

gboolean incomplete_tcp_stream = FALSE;

static guint32 ip_address[2];
static u_int   tcp_port[2];

static int check_fragments( int, tcp_stream_chunk * );
static void write_packet_data( tcp_stream_chunk *, const char * );

/* this will build libpcap filter text that will only 
   pass the packets related to the stream. There is a 
   chance that two streams could intersect, but not a 
   very good one */
char* 
build_follow_filter( packet_info *pi ) {
  char* buf = malloc(1024);
  if( pi->net_src.type == AT_IPv4 && pi->net_dst.type == AT_IPv4
	&& pi->ipproto == 6 ) {
    /* TCP over IPv4 */
    sprintf( buf, 
	     "(ip.addr eq %s and ip.addr eq %s) and (tcp.port eq %d and tcp.port eq %d)",
	     ip_to_str( pi->net_src.data), 
	     ip_to_str( pi->net_dst.data), 
	     pi->srcport, pi->destport );
  }
  else { 
    free( buf );
    return NULL;
  }
  memcpy(&ip_address[0], pi->net_src.data, sizeof ip_address[0]);
  memcpy(&ip_address[1], pi->net_dst.data, sizeof ip_address[1]);
  tcp_port[0] = pi->srcport;
  tcp_port[1] = pi->destport;
  return buf;
}

/* here we are going to try and reconstruct the data portion of a TCP
   session. We will try and handle duplicates, TCP fragments, and out 
   of order packets in a smart way. */

static tcp_frag *frags[2] = { 0, 0};
static u_long seq[2];
static guint32 src[2] = { 0, 0 };

void 
reassemble_tcp( u_long sequence, u_long length, const char* data,
		u_long data_length, int synflag, address *net_src,
		address *net_dst, u_int srcport, u_int dstport,
                guint32 secs, guint32 usecs) {
  guint32 srcx, dstx;
  int src_index, j, first = 0;
  u_long newseq;
  tcp_frag *tmp_frag;
  tcp_stream_chunk sc;
  
  src_index = -1;
  
  /* first check if this packet should be processed */
  if (net_src->type != AT_IPv4 || net_dst->type != AT_IPv4)
    return;
  memcpy(&srcx, net_src->data, sizeof srcx);
  memcpy(&dstx, net_dst->data, sizeof dstx);
  if ((srcx != ip_address[0] && srcx != ip_address[1]) ||
      (dstx != ip_address[0] && dstx != ip_address[1]) ||
      (srcport != tcp_port[0] && srcport != tcp_port[1]) ||
      (dstport != tcp_port[0] && dstport != tcp_port[1]))
    return;

  /* Initialize our stream chunk.  This data gets written to disk. */
  sc.src_addr = srcx;
  sc.src_port = srcport;
  sc.secs     = secs;
  sc.usecs    = usecs;
  sc.dlen     = data_length;

  /* first we check to see if we have seen this src ip before. */
  for( j=0; j<2; j++ ) {
    if( src[j] == srcx ) {
      src_index = j;
    }
  }
  /* we didn't find it if src_index == -1 */
  if( src_index < 0 ) {
    /* assign it to a src_index and get going */
    for( j=0; j<2; j++ ) {
      if( src[j] == 0 ) {
	src[j] = srcx;
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
    write_packet_data( &sc, data );
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
      u_long new_len;

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
      write_packet_data( &sc, data );
    }
    /* done with the packet, see if it caused a fragment to fit */
    while( check_fragments( src_index, &sc ) )
      ;
  }
  else {
    /* out of order packet */
    if( sequence > seq[src_index] ) {
      tmp_frag = (tcp_frag *)malloc( sizeof( tcp_frag ) );
      tmp_frag->data = (u_char *)malloc( data_length );
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
	write_packet_data( sc, current->data );
      }
      seq[index] += current->len;
      if( prev ) {
	prev->next = current->next;
      } else {
	frags[index] = current->next;
      }
      free( current->data );
      free( current );
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
    src[i] = 0;
    ip_address[i] = 0;
    tcp_port[i] = 0;
    current = frags[i];
    while( current ) {
      next = current->next;
      free( current->data ); 
      free( current );
      current = next;
    }
    frags[i] = NULL;
  }
}

static void 
write_packet_data( tcp_stream_chunk *sc, const char *data ) {
  if (sc->dlen == 0)
    return;
  fwrite( sc, 1, sizeof(tcp_stream_chunk), data_out_file );
  fwrite( data, 1, sc->dlen, data_out_file );
}
  
