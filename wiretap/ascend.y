/*
 * We want a reentrant parser.
 */
%pure-parser

/*
 * We also want a reentrant scanner, so we have to pass the
 * handle for the reentrant scanner to the parser, and the
 * parser has to pass it to the lexical analyzer.
 *
 * We use void * rather than yyscan_t because, at least with some
 * versions of Flex and Bison, if you use yyscan_t in %parse-param and
 * %lex-param, you have to include the ascend_lex_scanner.h before
 * ascend.h to get yyscan_t declared, and you have to include ascend.h
 * before ascend_lex_scanner.h to get YYSTYPE declared.  Using void *
 * breaks the cycle; the Flex documentation says yyscan_t is just a void *.
 */
%parse-param {void *yyscanner}
%lex-param {void *yyscanner}

/*
 * And we need to pass the parser/scanner state to the parser.
 */
%parse-param {ascend_state_t *parser_state}

%{
/* ascend.y
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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

/*
    Example 'pridisp' output data - one paragraph/frame:

PRI-XMIT-27: (task "l1Task" at 0x10216fe0, time: 560194.01) 4 octets @ 0x1027c5b0
  [0000]: 00 01 01 a9                                         ....
PRI-RCV-27: (task "idle task" at 0x10123570, time: 560194.01) 4 octets @ 0x1027fb00
  [0000]: 00 01 01 dd

    Example 'pridisp' output data - two paragraphs/frame for XMIT case only:

PRI-XMIT-19/1:  (task "l1Task" at 0x10216840, time: 274759.98) 4 octets @ 0x1027f230
  [0000]: 00 01 30 d8                                         ..0.
PRI-XMIT-19/2 (task "l1Task" at 0x10216840, time: 274759.98) 11 octets @ 0x1027f234
  [0000]: 08 02 8c bf 02 18 04 e9  82 83 8f                   ........ ...

    Example 'ether-disp' output data:

ETHER3ND RECV: (task "_sarTask" at 0x802c6eb0, time: 259848.03) 775 octets @ 0xa8fb2020
  [0000]: 00 d0 52 04 e7 1e 08 00  20 ae 51 b5 08 00 45 00    ..R..... .Q...E.
  [0010]: 02 f9 05 e6 40 00 3f 11  6e 39 87 fe c4 95 3c 3c    ....@.?.  n9....<<
  [0020]: 3c 05 13 c4 13 c4 02 e5  ef ed 49 4e 56 49 54 45    <.......  ..INVITE
  [0030]: 20 73 69 70 3a 35 32 30  37 33 40 36 30 2e 36 30     sip:520 73@60.60
  [0040]: 2e 36 30 2e 35 20 53 49  50 2f 32 2e 30 0d 0a 56    .60.5 SI P/2.0..V
  [0050]: 69 61 3a 20 53 49 50 2f  32 2e 30 2f 55 44 50 20    ia: SIP/ 2.0/UDP
  [0060]: 31 33 35 2e                                         135.

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

    The following output comes from a MAX with Software 7.2.3:

RECV-187:(task: B050B480, time: 18042248.03) 100 octets @ 800012C0
  [0000]: FF 03 00 21 45 00 00 60 E3 49 00 00 7F 11 FD 7B
  [0010]: C0 A8 F7 05 8A C8 18 51 00 89 00 89 00 4C C7 C1
  [0020]: CC 8E 40 00 00 01 00 00 00 00 00 01 20 45 4A 45
  [0030]: 42 45 43 45 48 43 4E 46 43 46 41 43 41 43 41 43
  [0040]: 41 43 41 43 41 43 41 43 41 43 41 42 4E 00 00 20
  [0050]: 00 01 C0 0C 00 20 00 01 00 04 93 E0 00 06 60 00
  [0060]: C0 A8 F7 05
XMIT-187:(task: B0292CA0, time: 18042248.04) 60 octets @ 800AD576
  [0000]: FF 03 00 21 45 00 00 38 D7 EE 00 00 0F 01 11 2B
  [0010]: 0A FF FF FE C0 A8 F7 05 03 0D 33 D3 00 00 00 00
  [0020]: 45 00 00 60 E3 49 00 00 7E 11 FE 7B C0 A8 F7 05
  [0030]: 8A C8 18 51 00 89 00 89 00 4C C7 C1
RECV-187:(task: B0292CA0, time: 18042251.92) 16 octets @ 800018E8
  [0000]: FF 03 C0 21 09 01 00 0C DE 61 96 4B 00 30 94 92

  In TAOS 8.0, Lucent slightly changed the format as follows:

    Example 'wandisp' output data (TAOS 8.0.3): (same format is used
    for 'wanopen' and 'wannext' command)

RECV-14: (task "idle task" at 0xb05e6e00, time: 1279.01) 29 octets @ 0x8000e0fc
  [0000]: ff 03 c0 21 01 01 00 19  01 04 05 f4 11 04 05 f4    ...!.... ........
  [0010]: 13 09 03 00 c0 7b 9a 9f  2d 17 04 10 00             .....{.. -....
XMIT-14: (task "idle task" at 0xb05e6e00, time: 1279.02) 38 octets @ 0x8007fd56
  [0000]: ff 03 c0 21 01 01 00 22  00 04 00 00 01 04 05 f4    ...!..." ........
  [0010]: 03 05 c2 23 05 11 04 05  f4 13 09 03 00 c0 7b 80    ...#.... ......{.
  [0020]: 7c ef 17 04 0e 00                                   |.....
XMIT-14: (task "idle task" at 0xb05e6e00, time: 1279.02) 29 octets @ 0x8007fa36
  [0000]: ff 03 c0 21 02 01 00 19  01 04 05 f4 11 04 05 f4    ...!.... ........
  [0010]: 13 09 03 00 c0 7b 9a 9f  2d 17 04 10 00             .....{.. -....

    Example 'wandsess' output data (TAOS 8.0.3):

RECV-Max7:20: (task "_brouterControlTask" at 0xb094ac20, time: 1481.50) 20 octets @ 0x8000d198
  [0000]: ff 03 00 3d c0 00 00 04  80 fd 02 01 00 0a 11 06    ...=.... ........
  [0010]: 00 01 01 03                                         ....
XMIT-Max7:20: (task "_brouterControlTask" at 0xb094ac20, time: 1481.51) 26 octets @ 0x800806b6
  [0000]: ff 03 00 3d c0 00 00 00  80 21 01 01 00 10 02 06    ...=.... .!......
  [0010]: 00 2d 0f 01 03 06 89 64  03 08                      .-.....d ..
XMIT-Max7:20: (task "_brouterControlTask" at 0xb094ac20, time: 1481.51) 20 octets @ 0x8007f716
  [0000]: ff 03 00 3d c0 00 00 01  80 fd 01 01 00 0a 11 06    ...=.... ........
  [0010]: 00 01 01 03                                         ....

  The changes since TAOS 7.X are:

    1) White space is added before "(task".
    2) Task has a name, indicated by a subsequent string surrounded by a
       double-quote.
    3) Address expressed in hex number has a preceeding "0x".
    4) Hex numbers are in lower case.
    5) There is a character display corresponding to hex data in each line.

 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "wtap-int.h"
#include <wsutil/buffer.h>
#include "ascendtext.h"
#include "ascend-int.h"
#include "ascend.h"
#include "ascend_scanner_lex.h"
#include "file_wrappers.h"

#define NO_USER "<none>"

extern void yyerror (void *yyscanner, ascend_state_t *state, FILE_T fh _U_, const char *s);
%}

%union {
gchar  *s;
guint32 d;
guint8  b;
}

%token <s> STRING KEYWORD WDD_DATE WDD_CHUNK COUNTER SLASH_SUFFIX
%token <d> WDS_PREFIX ISDN_PREFIX ETHER_PREFIX DECNUM HEXNUM
%token <b> HEXBYTE

%type <s> string dataln datagroup
%type <d> wds_prefix isdn_prefix ether_prefix decnum hexnum
%type <b> byte bytegroup

%parse-param { FILE_T fh }

%%

data_packet:
  | ether_hdr datagroup
  | deferred_isdn_hdr datagroup deferred_isdn_hdr datagroup
  | isdn_hdr datagroup
  | wds_hdr datagroup
  | wds8_hdr datagroup
  | wdp7_hdr datagroup
  | wdp8_hdr datagroup
  | wdd_date wdd_hdr datagroup
  | wdd_hdr datagroup
;

isdn_prefix: ISDN_PREFIX;

ether_prefix: ETHER_PREFIX;

wds_prefix: WDS_PREFIX;

string: STRING;

decnum: DECNUM;

hexnum: HEXNUM;

/*
  pridisp special case - I-frame header printed separately from contents,
  one frame across two messages.

PRI-XMIT-0/1:  (task "l1Task" at 0x80152b20, time: 283529.65) 4 octets @
0x80128220
  [0000]: 00 01 ae b2                                         ....
PRI-XMIT-0/2 (task "l1Task" at 0x80152b20, time: 283529.65) 10 octets @
0x80128224
  [0000]: 08 02 d7 e3 02 18 03 a9  83 8a                      ........

*/
deferred_isdn_hdr: isdn_prefix decnum SLASH_SUFFIX KEYWORD string KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  parser_state->wirelen += $11;
  parser_state->secs = $9;
  parser_state->usecs = $10;
  if (parser_state->pseudo_header != NULL) {
    parser_state->pseudo_header->type = $1;
    parser_state->pseudo_header->sess = $2;
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = $7;
  }
  /* because we have two data groups */
  parser_state->first_hexbyte = 0;
}
;

/*
PRI-XMIT-19:  (task "l1Task" at 0x10216840, time: 274758.67) 4 octets @ 0x1027c1c0
 ... or ...
PRI-RCV-27:  (task "idle task" at 0x10123570, time: 560194.01) 4 octets @ 0x1027fb00
*/
isdn_hdr: isdn_prefix decnum KEYWORD string KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  parser_state->wirelen = $10;
  parser_state->secs = $8;
  parser_state->usecs = $9;
  if (parser_state->pseudo_header != NULL) {
    parser_state->pseudo_header->type = $1;
    parser_state->pseudo_header->sess = $2;
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = $6;
  }
  parser_state->first_hexbyte = 0;
}
;

/*
ETHER3ND XMIT: (task "_sarTask" at 0x802c6eb0, time: 259848.11) 414 octets @ 0xa
885f80e
*/
ether_hdr: ether_prefix string KEYWORD string KEYWORD hexnum KEYWORD decnum decnum
 decnum KEYWORD HEXNUM {
  parser_state->wirelen = $10;
  parser_state->secs = $8;
  parser_state->usecs = $9;
  if (parser_state->pseudo_header != NULL) {
    parser_state->pseudo_header->type = $1;
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = $6;
  }
}
;

/* RECV-iguana:241:(task: B02614C0, time: 1975432.85) 49 octets @ 8003BD94 */
/*            1        2      3      4       5      6       7      8      9      10     11 */
wds_hdr: wds_prefix string decnum KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  parser_state->wirelen = $9;
  parser_state->secs = $7;
  parser_state->usecs = $8;
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->user is set in ascend_scanner.l */
    parser_state->pseudo_header->type = $1;
    parser_state->pseudo_header->sess = $3;
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = $5;
  }
}
;

/* RECV-Max7:20: (task "_brouterControlTask" at 0xb094ac20, time: 1481.50) 20 octets @ 0x8000d198 */
/*                1       2       3     4       5       6      7       8      9      10     11     12      13 */
wds8_hdr: wds_prefix string decnum KEYWORD string KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  parser_state->wirelen = $11;
  parser_state->secs = $9;
  parser_state->usecs = $10;
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->user is set in ascend_scanner.l */
    parser_state->pseudo_header->type = $1;
    parser_state->pseudo_header->sess = $3;
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = $7;
  }
}
;

/* RECV-187:(task: B050B480, time: 18042248.03) 100 octets @ 800012C0 */
/*            1        2       3      4       5       6      7      8      9      10    */
wdp7_hdr: wds_prefix decnum KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  parser_state->wirelen = $8;
  parser_state->secs = $6;
  parser_state->usecs = $7;
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->user is set in ascend_scanner.l */
    parser_state->pseudo_header->type = $1;
    parser_state->pseudo_header->sess = $2;
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = $4;
  }
}
;

/* XMIT-44: (task "freedm_task" at 0xe051fd10, time: 6258.66) 29 octets @ 0x606d1f00 */
/*              1        2       3      4       5      6      7       8      9      10     11      12 */
wdp8_hdr: wds_prefix decnum KEYWORD string KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  parser_state->wirelen = $10;
  parser_state->secs = $8;
  parser_state->usecs = $9;
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->user is set in ascend_scanner.l */
    parser_state->pseudo_header->type = $1;
    parser_state->pseudo_header->sess = $2;
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = $6;
  }
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

  parser_state->timestamp = (guint32) mktime(&wddt);
  parser_state->saw_timestamp = TRUE;
}
;

/*
WD_DIALOUT_DISP: chunk 2515EE type IP.
(task: 251790, time: 994953.28) 44 octets @ 2782B8
*/
/*           1        2      3       4       5      6       7      8      9      10     11*/
wdd_hdr: WDD_CHUNK hexnum KEYWORD KEYWORD hexnum KEYWORD decnum decnum decnum KEYWORD HEXNUM {
  parser_state->wirelen = $9;
  parser_state->secs = $7;
  parser_state->usecs = $8;
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->call_num is set in ascend_scanner.l */
    parser_state->pseudo_header->type = ASCEND_PFX_WDD;
    parser_state->pseudo_header->user[0] = '\0';
    parser_state->pseudo_header->sess = 0;
    parser_state->pseudo_header->chunk = $2;
    parser_state->pseudo_header->task = $5;
  }
}
;

byte: HEXBYTE {
  /* remember the position of the data group in the trace, to tip
     off ascend_seek() as to where to look for the next header. */
  if (parser_state->first_hexbyte == 0)
    parser_state->first_hexbyte = file_tell(fh);

  /* XXX - if this test fails, it means that we parsed more bytes than
     the header claimed there were. */
  if (parser_state->caplen < parser_state->wirelen) {
    parser_state->pkt_data[parser_state->caplen] = $1;
    parser_state->caplen++;
  }

  /* arbitrary safety maximum... */
  if (parser_state->caplen >= ASCEND_MAX_PKT_LEN)
    YYACCEPT;
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

/* Run the parser. */
int
run_ascend_parser(FILE_T fh, struct wtap_pkthdr *phdr, guint8 *pd,
                  ascend_state_t *parser_state, int *err, gchar **err_info)
{
  yyscan_t scanner = NULL;
  int status;

  if (ascendlex_init(&scanner) != 0) {
    /* errno is set if this fails */
    *err = errno;
    *err_info = NULL;
    return 1;
  }
  /* Associate the parser state with the lexical analyzer state */
  ascendset_extra(parser_state, scanner);
  parser_state->fh = fh;
  parser_state->ascend_parse_error = NULL;
  parser_state->err = 0;
  parser_state->err_info = NULL;
  parser_state->pseudo_header = &phdr->pseudo_header.ascend;
  parser_state->pkt_data = pd;

  /*
   * We haven't seen a time stamp yet.
   */
  parser_state->saw_timestamp = FALSE;
  parser_state->timestamp = 0;

  parser_state->first_hexbyte = 0;
  parser_state->caplen = 0;
  parser_state->wirelen = 0;

  parser_state->secs = 0;
  parser_state->usecs = 0;

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
  parser_state->pseudo_header->call_num[0] = '\0';

  status = yyparse(scanner, parser_state, fh);
  *err = parser_state->err;
  *err_info = parser_state->err_info;
  return status;
}

void
yyerror (void *yyscanner, ascend_state_t *state _U_, FILE_T fh _U_, const char *s)
{
  ascendget_extra(yyscanner)->ascend_parse_error = s;
}
