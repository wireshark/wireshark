/* follow.c
 *
 * $Id: follow.c,v 1.4 1998/10/28 01:29:16 guy Exp $
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
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "follow.h"

extern FILE* data_out_file;

/* this will build libpcap filter text that will only 
   pass the packets related to the stream. There is a 
   chance that two streams could intersect, but not a 
   very good one */
char* 
build_follow_filter( packet_info *pi ) {
  char* buf = malloc(1024);
  if( pi->ipproto == 6 ) {
    /* TCP */
    sprintf( buf, "host %s and host %s and (ip proto \\tcp) and (port %d and port %d)",
	     pi->srcip, pi->destip, pi->srcport, pi->destport );
  }
  else { 
    free( buf );
    return NULL;
  }
  return buf;
}

/* here we are going to try and reconstruct the data portion of a TCP
   session. We will try and handle duplicates, TCP fragments, and out 
   of order packets in a smart way. */

static tcp_frag *frags[2] = { 0, 0};
static u_long seq[2];
static u_long src[2] = { 0, 0 };

void 
reassemble_tcp( u_long sequence, u_long length, const char* data, int synflag, u_long srcx ) {
  int src_index, j, first = 0;
  u_long newseq;
  tcp_frag *tmp_frag;
  src_index = -1;
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
  /* now that we have filed away the srcs, lets get the sequence number stuff 
     figured out */
  if( first ) {
    /* this is the first time we have seen this src's sequence number */
    seq[src_index] = sequence + length;
    if( synflag ) {
      seq[src_index]++;
    }
    /* write out the packet data */
    write_packet_data( data, length );
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
      /* this one has more than we have seen. let's get the 
	 payload that we have not seen. */
      data += ( seq[src_index] - sequence );
      sequence = seq[src_index];
      length = newseq - seq[src_index];
      /* this will now appear to be right on time :) */
    }
  }
  if ( sequence == seq[src_index] ) {
    /* right on time */
    seq[src_index] += length;
    if( synflag ) seq[src_index]++;
    write_packet_data( data, length );
    /* done with the packet, see if it caused a fragment to fit */
    while( check_fragments( src_index ) )
      ;
  }
  else {
    /* out of order packet */
    if( sequence > seq[src_index] ) {
      tmp_frag = (tcp_frag *)malloc( sizeof( tcp_frag ) );
      tmp_frag->data = (u_char *)malloc( length );
      tmp_frag->seq = sequence;
      tmp_frag->len = length;
      memcpy( tmp_frag->data, data, length );
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
int 
check_fragments( int index ) {
  tcp_frag *prev = NULL;
  tcp_frag *current;
  current = frags[index];
  while( current ) {
    if( current->seq == seq[index] ) {
      /* this fragment fits the stream */
      write_packet_data( current->data, current->len );
      seq[index] += current->len;
      if( prev ) {
	prev->next = current->next;
      } else {
	src[index] = current->next;
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
  for( i=0; i<2; i++ ) {
    seq[i] = 0;
    src[i] = 0;
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

void 
write_packet_data( const u_char* data, int length ) {
  fwrite( data, 1, length, data_out_file );
}
  
