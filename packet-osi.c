/* packet-osi.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 * Main entrance point and common functions
 *
 * $Id: packet-osi.c,v 1.39 2001/01/09 06:31:39 guy Exp $
 * Laurent Deniel <deniel@worldnet.fr>
 * Ralf Schneider <Ralf.Schneider@t-online.de>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include "packet.h"
#include "llcsaps.h"
#include "aftypes.h"
#include "nlpid.h"
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-esis.h"


gchar *print_system_id( const u_char *buffer, int length ) {
  int           tmp;
  u_char       *cur; 
  static gchar  str[MAX_SYSTEMID_LEN * 3 + 5]; /* Don't trust exact matching */  
 
  if ( ( length <= 0 ) || ( length > MAX_SYSTEMID_LEN ) ) {
    sprintf( str, "<Invalid length of SYSTEM ID>");
    return( str );
  }  
 
  cur = str;
  if ( ( 6 == length ) || ( 7 == length ) ) { /* Special case, print as MAC */
    cur += sprintf(str, "[%02x:%02x:%02x_%02x:%02x:%02x]", buffer[0], buffer[1],
                    buffer[2], buffer[3], buffer[4], buffer[5] );
    if ( 7 == length ) {
      sprintf( cur, "-%02x", buffer[6] );
    }
  }
  else {
    tmp = 0;
    while ( tmp < length / 4 ) { /* 16 / 4 == 4 > four Octets left to print */
      cur += sprintf( str, "%02x%02x%02x%02x.", buffer[tmp++], buffer[tmp++],
                      buffer[tmp++], buffer[tmp++] );
    }
    if ( 1 == tmp ) {   /* Special case for Designated IS */
      sprintf( --cur, "-%02x", buffer[tmp] );
    }
    else {
      for ( ; tmp < length; ) {  /* print the rest without dot */
        cur += sprintf( cur, "%02x", buffer[tmp++] );
      }
    }
  }
  return( str );
}

gchar *print_area(const u_char *buffer, int length)
{
  /* to do : all real area decoding now: NET is assumed if id len is 1 more byte
   * and take away all these stupid resource consuming local statics
   */
  
  static gchar  str[MAX_AREA_LEN * 3 + 20]; /* reserve space for nice layout */
  gchar *cur;
  u_int  tmp  = 0;

  cur = str;

  if (length <= 0 || length > MAX_AREA_LEN) {
    sprintf( str, "<Invalid length of AREA>");
    return( str );
  }
  
  if ( (  ( NSAP_IDI_ISODCC          == *buffer )      
       || ( NSAP_IDI_GOSIP2          == *buffer )
       )
       && 
       (  ( RFC1237_FULLAREA_LEN     ==  length ) 
       || ( RFC1237_FULLAREA_LEN + 1 ==  length )
       ) 
     ) {    /* AFI is good and length is long enough  */
  
    if ( length > RFC1237_FULLAREA_LEN + 1 ) {  /* Special Case Designated IS */
      sprintf( str, "<Invalid length of AREA for DCC / GOSIP AFI>");
      return( str );
    }
 
    cur += sprintf( cur, "[%02x|%02x:%02x][%02x|%02x:%02x:%02x|%02x:%02x]", 
                    buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], 
                    buffer[5], buffer[6], buffer[7], buffer[8] );
    cur += sprintf( cur, "[%02x:%02x|%02x:%02x]",
                    buffer[9], buffer[10],  buffer[11], buffer[12] );
    if ( RFC1237_FULLAREA_LEN + 1 == length ) {
      sprintf( cur, "-[%02x]", buffer[20] );
    }
    return str;
  }
  else { /* print standard format */
    if ( 4 < length ) { 
      while ( tmp < length / 4 ) {      /* 16/4==4  four Octets left to print */
        cur += sprintf( str, "%02x%02x%02x%02x.", buffer[tmp++], buffer[tmp++],
                        buffer[tmp++], buffer[tmp++] );
      }
      if ( 1 == tmp ) {                     /* Special case for Designated IS */
        sprintf( --cur, "-%02x", buffer[tmp] );
      }
      else {
        for ( ; tmp < length; ) {  /* print the rest without dot */ 
          cur += sprintf( cur, "%02x", buffer[tmp++] );
        }
      } 
    }
    return( str );
  }
} /* print_area */


gchar *print_nsap_net( const u_char *buffer, int length)
{
  /* to do : NSAP / NET decoding */

  static gchar  str[MAX_NSAP_LEN * 3 + 50]; /* reserve space for nice layout */
  gchar *cur;

  cur = str;

  if ( (length <= 0 ) || ( length > MAX_NSAP_LEN ) ) {
    sprintf( str, "<Invalid length of NSAP>");
    return( str );
  }
  if ( ( length == RFC1237_NSAP_LEN ) || ( length == RFC1237_NSAP_LEN + 1 ) ) {
    cur += sprintf( cur, "%s", print_area( buffer, RFC1237_FULLAREA_LEN ) );
    cur += sprintf( cur, "%s", print_system_id( buffer + RFC1237_FULLAREA_LEN, 
                    RFC1237_SYSTEMID_LEN ) );
    cur += sprintf( cur, "[%02x]", 
                    buffer[ RFC1237_FULLAREA_LEN + RFC1237_SYSTEMID_LEN ] );
    if ( length == RFC1237_NSAP_LEN + 1 ) {
      cur += sprintf( cur, "-%02x", buffer[ length -1 ] );
    }
    return ( str );
  }
  else {    /* probably format as standard */
    return( print_area( buffer, length ) );
  }
} /* print_nsap */


gchar *calc_checksum( tvbuff_t *tvb, int offset, u_int len, u_int checksum) {
  u_int   calc_sum = 0;
  u_int   count    = 0;
  const gchar *buffer;
  guint   available_len;

  if ( 0 == checksum )
    return( "Not Used" );

  available_len = tvb_length_remaining( tvb, offset );
  if ( available_len < len )
    return( "Not checkable - not all of packet was captured" );

  buffer = tvb_get_ptr( tvb, offset, len );
  for ( count = 0; count < len; count++ ) {
    calc_sum += (u_int) buffer[count];
  }
  calc_sum %= 255;  /* modulo 255 divison */
  
  if ( 0 == calc_sum )
    return( "Is good" );
  else
    return( "Is wrong" );	/* XXX - what should the checksum be? */
}


/* main entry point */

const value_string nlpid_vals[] = {
	{ NLPID_NULL,            "NULL" },
	{ NLPID_T_70,            "T.70" },
	{ NLPID_X_633,           "X.633" },
	{ NLPID_Q_931,           "Q.931" },
	{ NLPID_Q_2931,          "Q.2931" },
	{ NLPID_Q_2119,          "Q.2119" },
	{ NLPID_SNAP,            "SNAP" },
	{ NLPID_ISO8473_CLNP,    "CLNP" },
	{ NLPID_ISO9542_ESIS,    "ESIS" },
	{ NLPID_ISO10589_ISIS,   "ISIS" },
	{ NLPID_ISO10747_IDRP,   "IDRP" },
	{ NLPID_ISO9542X25_ESIS, "ESIS (X.25)" },
	{ NLPID_ISO10030,        "ISO 10030" },
	{ NLPID_ISO11577,        "ISO 11577" },
	{ NLPID_IP,              "IP" },
	{ NLPID_PPP,             "PPP" },
	{ 0,                     NULL },
};

static dissector_table_t subdissector_table;

void dissect_osi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
  guint8 nlpid;

  pinfo->current_proto = "OSI";

  nlpid = tvb_get_guint8(tvb, 0);

  /* do lookup with the subdissector table */
  if (dissector_try_port(subdissector_table, nlpid, tvb, pinfo, tree))
      return;

  switch (nlpid) {

    /* ESIS (X.25) is not currently decoded */

    case NLPID_ISO9542X25_ESIS:
      if (check_col(pinfo->fd, COL_PROTOCOL)) {
	col_set_str(pinfo->fd, COL_PROTOCOL, "ESIS (X.25)");
      }
      dissect_data(tvb, 0, pinfo, tree);
      break;
    case NLPID_ISO10747_IDRP:
      if (check_col(pinfo->fd, COL_PROTOCOL)) {
        col_set_str(pinfo->fd, COL_PROTOCOL, "IDRP");
      }
      dissect_data(tvb, 0, pinfo, tree);
      break;
    default:
      if (check_col(pinfo->fd, COL_PROTOCOL)) {
	col_set_str(pinfo->fd, COL_PROTOCOL, "ISO");
      }
      if (check_col(pinfo->fd, COL_INFO)) {
	col_add_fstr(pinfo->fd, COL_INFO, "Unknown ISO protocol (%02x)", nlpid);
      }
      dissect_data(tvb, 0, pinfo, tree);
      break;
  }
} /* dissect_osi */

void
proto_register_osi(void)
{
	/* There's no "OSI" protocol *per se*, but we do register a
	   dissector table so various protocols running at the
	   network layer can register themselves. */
	subdissector_table = register_dissector_table("osinl");
}

void
proto_reg_handoff_osi(void)
{
	dissector_add("llc.dsap", SAP_OSINL, dissect_osi, -1);
	dissector_add("null.type", BSD_AF_ISO, dissect_osi, -1);
}
