/* osi-utils.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 * Main entrance point and common functions
 *
 * $Id: osi-utils.c,v 1.3 2001/04/16 10:04:33 guy Exp $
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <stdio.h>
#include <glib.h>

#include "osi-utils.h"

gchar *print_nsap_net( const guint8 *buffer, int length)
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


gchar *print_system_id( const guint8 *buffer, int length ) {
  int           tmp;
  gchar        *cur; 
  static gchar  str[MAX_SYSTEMID_LEN * 3 + 5]; /* Don't trust exact matching */  
 
  if ( ( length <= 0 ) || ( length > MAX_SYSTEMID_LEN ) ) {
    sprintf( str, "<Invalid length of SYSTEM ID>");
    return( str );
  }  
 
  cur = str;
  if ( ( 6 == length ) || ( 7 == length ) ) { /* Special case, print as MAC */
    cur += sprintf(str, "%02x%02x.%02x%02x.%02x%02x", buffer[0], buffer[1],
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

gchar *print_area(const guint8 *buffer, int length)
{
  /* to do : all real area decoding now: NET is assumed if id len is 1 more byte
   * and take away all these stupid resource consuming local statics
   */
  
  static gchar  str[MAX_AREA_LEN * 3 + 20]; /* reserve space for nice layout */
  gchar *cur;
  int  tmp  = 0;

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
    if ( length == RFC1237_AREA_LEN ) {
	sprintf( str, "%02x.%02x%02x", buffer[0], buffer[1],
			buffer[2] );
			return( str );
       }
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

