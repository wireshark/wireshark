%{
/* ascend-grammar.y
 *
 * $Id: ascend-grammar.y,v 1.17 2000/11/12 04:57:39 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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

/*
   Example 'wandsess' output data:
   
RECV-iguana:241:(task: B02614C0, time: 1975432.85) 49 octets @ 8003BD94
  [0000]: FF 03 00 3D C0 06 CA 22 2F 45 00 00 28 6A 3B 40 
  [0010]: 00 3F 03 D7 37 CE 41 62 12 CF 00 FB 08 20 27 00 
  [0020]: 50 E4 08 DD D7 7C 4C 71 92 50 10 7D 78 67 C8 00 
  [0030]: 00 
XMIT-iguana:241:(task: B04E12C0, time: 1975432.85) 53 octets @ 8009EB16
  [0000]: FF 03 00 3D C0 09 1E 31 21 45 00 00 2C 2D BD 40 
  [0010]: 00 7A 06 D8 B1 CF 00 FB 08 CE 41 62 12 00 50 20 
  [0020]: 29 7C 4C 71 9C 9A 6A 93 A4 60 12 22 38 3F 10 00 
  [0030]: 00 02 04 05 B4 

    Example 'wdd' output data:

Date: 01/12/1990.  Time: 12:22:33
Cause an attempt to place call to 14082750382
WD_DIALOUT_DISP: chunk 2515EE type IP.
(task: 251790, time: 994953.28) 44 octets @ 2782B8
  [0000]: 00 C0 7B 71 45 6C 00 60 08 16 AA 51 08 00 45 00
  [0010]: 00 2C 66 1C 40 00 80 06 53 F6 AC 14 00 18 CC 47
  [0020]: C8 45 0A 31 00 50 3B D9 5B 75 00 00
 

 */

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap-int.h"
#include "buffer.h"
#include "ascend.h"
#include "ascend-int.h"

#define NFH_PATH "/dev/null"

extern int at_eof;

int yyparse(void);
void yyerror(char *);

int bcur = 0, bcount;
guint32 start_time, secs, usecs, caplen, wirelen;
ascend_pkthdr *header;
struct ascend_phdr *pseudo_header;
char *pkt_data;
FILE *nfh = NULL;

%}
 
%union {
gchar  *s;
guint32 d;
char    b;
}

%token <s> STRING KEYWORD WDD_DATE WDD_CHUNK COUNTER
%token <d> WDS_PREFIX DECNUM HEXNUM
%token <b> HEXBYTE

%type <s> string dataln datagroup
%type <d> wds_prefix decnum hexnum
%type <b> byte bytegroup

%%

data_packet:
  | wds_hdr datagroup
  | wdd_date wdd_hdr datagroup
  | wdd_hdr datagroup
;

wds_prefix: WDS_PREFIX;

string: STRING;

decnum: DECNUM;

hexnum: HEXNUM;

/*            1        2      3      4       5      6       7      8      9      10     11 */
wds_hdr: wds_prefix string decnum KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  wirelen = $9;
  caplen = ($9 < ASCEND_MAX_PKT_LEN) ? $9 : ASCEND_MAX_PKT_LEN;
  /* If we don't have as many bytes of data as the octet count in
     the header, make the capture length the number of bytes we
     actually have. */
  if (bcount > 0 && bcount <= caplen)
    caplen = bcount;
  secs = $7;
  usecs = $8;
  if (pseudo_header != NULL) {
    /* pseudo_header->user is set in ascend-scanner.l */
    pseudo_header->type = $1;
    pseudo_header->sess = $3;
    pseudo_header->call_num[0] = '\0';
    pseudo_header->chunk = 0;
    pseudo_header->task = $5;
  }
  
  bcur = 0;
}
;

/*
Date: 01/12/1990.  Time: 12:22:33
Cause an attempt to place call to 14082750382
*/
/*           1        2      3      4      5       6      7      8      9      10*/
wdd_date: WDD_DATE decnum decnum decnum KEYWORD decnum decnum decnum KEYWORD string {
  /*
   * Supply the date/time value to the code above us; it will use the
   * first date/time value supplied as the capture start date/time.
   */
  struct tm wddt;

  wddt.tm_sec  = $8;
  wddt.tm_min  = $7;
  wddt.tm_hour = $6;
  wddt.tm_mday = $3;
  wddt.tm_mon  = $2 - 1;
  wddt.tm_year = ($4 > 1970) ? $4 - 1900 : 70;
  wddt.tm_isdst = -1;
  
  start_time = mktime(&wddt);
}
;
 
/*
WD_DIALOUT_DISP: chunk 2515EE type IP.
(task: 251790, time: 994953.28) 44 octets @ 2782B8
*/
/*           1        2      3       4       5      6       7      8      9      10     11*/
wdd_hdr: WDD_CHUNK hexnum KEYWORD KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  wirelen = $9;
  caplen = ($9 < ASCEND_MAX_PKT_LEN) ? $9 : ASCEND_MAX_PKT_LEN;
  /* If we don't have as many bytes of data as the octet count in
     the header, make the capture length the number of bytes we
     actually have. */
  if (bcount > 0 && bcount <= caplen)
    caplen = bcount;
  secs = $7;
  usecs = $8;
  if (pseudo_header != NULL) {
    /* pseudo_header->call_num is set in ascend-scanner.l */
    pseudo_header->type = ASCEND_PFX_WDD;
    pseudo_header->user[0] = '\0';
    pseudo_header->sess = 0;
    pseudo_header->chunk = $2;
    pseudo_header->task = $5;
  }
  
  bcur = 0;
}
;
 
byte: HEXBYTE {
  if (bcur < caplen) {
    pkt_data[bcur] = $1;
    bcur++;
  }

  if (bcur >= caplen) {
    if (header != NULL) {
      header->start_time = start_time;
      header->secs = secs;
      header->usecs = usecs;
      header->caplen = caplen;
      header->len = wirelen;
    }
    YYACCEPT;
  }
} 
;

/* XXX  There must be a better way to do this... */
bytegroup: byte
  | byte byte
  | byte byte byte
  | byte byte byte byte
  | byte byte byte byte byte
  | byte byte byte byte byte byte
  | byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte byte byte byte
  | byte byte byte byte byte byte byte byte byte byte byte byte byte byte byte byte
;

dataln: COUNTER bytegroup;

datagroup: dataln
  | dataln dataln
  | dataln dataln dataln
  | dataln dataln dataln dataln
  | dataln dataln dataln dataln dataln
  | dataln dataln dataln dataln dataln dataln
  | dataln dataln dataln dataln dataln dataln dataln
  | dataln dataln dataln dataln dataln dataln dataln dataln
;

%%

void
init_parse_ascend()
{
  bcur = 0;
  at_eof = 0;
  start_time = 0;	/* we haven't see a date/time yet */
  
  /* In order to keep flex from printing a lot of newlines while reading
     the capture data, we open up /dev/null and point yyout at the null
     file handle. */
  if (! nfh) {
    nfh = fopen(NFH_PATH, "r");
  }
}

/* Parse the capture file.  Return the offset of the next packet, or zero
   if there is none. */
int
parse_ascend(FILE_T fh, void *pd, struct ascend_phdr *phdr,
		ascend_pkthdr *hdr, int len)
{
  /* yydebug = 1; */
 
  ascend_init_lexer(fh, nfh);
  pkt_data = pd;
  pseudo_header = phdr;
  header = hdr;
  bcount = len;
  
  /*
   * Not all packets in a "wdd" dump necessarily have a "Cause an
   * attempt to place call to" header (I presume this can happen if
   * there was a call in progress when the packet was sent or
   * received), so we won't necessarily have the phone number for
   * the packet.
   *
   * XXX - we could assume, in the sequential pass, that it's the
   * phone number from the last call, and remember that for use
   * when doing random access.
   */
  pseudo_header->call_num[0] = '\0';

  if (yyparse())
    return 0;
  else
    return 1;
}

void
yyerror (char *s)
{
  /* fprintf (stderr, "%s\n", s); */
}
