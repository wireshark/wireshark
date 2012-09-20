/*
 * We don't read from the terminal.
 */
%option never-interactive

/*
 * Prefix scanner routines with "ascend" rather than "yy", so this scanner
 * can coexist with other scanners.
 */
%option prefix="ascend"

%{
/* ascend_scanner.l
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_IO_H
#include <io.h> 	/* for isatty() on win32 */
#endif

#include "wtap-int.h"
#include "ascendtext.h"
#include "ascend.h"
#include "ascend-int.h"
#include "file_wrappers.h"
#include "ascend_scanner_lex.h"

FILE_T yy_fh;
extern char *ascend_ra_ptr;
extern char *ascend_ra_last;
#define YY_INPUT(buf,result,max_size) { int c = file_getc(yy_fh);  \
result = (c==EOF) ? YY_NULL : (buf[0] = c, 1); }

int at_eof;
int mul, scratch;

#define NO_USER "<none>"

#ifndef HAVE_UNISTD_H
#define YY_NO_UNISTD_H
#endif


%}

D [0-9]
H [A-Fa-f0-9]

PPP_XPFX PPP-OUT
PPP_RPFX PPP-IN
ISDN_XPFX PRI-XMIT-
ISDN_RPFX PRI-RCV-
WAN_XPFX XMIT[\-:]*
WAN_RPFX RECV[\-:]*
ETHER_PFX ETHER

WDD_DATE    "Date:"
WDD_TIME    "Time:"
WDD_CAUSE   "Cause an attempt to place call to "
WDD_CALLNUM [^\n\r\t ]+
WDD_CHUNK   "WD_DIALOUT_DISP: chunk"
WDD_TYPE    "type "[^\n\r\t ]+

%s sc_gen_task
%s sc_gen_time_s
%s sc_gen_time_u
%s sc_gen_octets
%s sc_gen_counter
%s sc_gen_byte

%s sc_wds_user
%s sc_wds_sess

%s sc_wdd_date_d
%s sc_wdd_date_m
%s sc_wdd_date_y
%s sc_wdd_time
%s sc_wdd_time_h
%s sc_wdd_time_m
%s sc_wdd_time_s
%s sc_wdd_cause
%s sc_wdd_callnum
%s sc_wdd_chunk
%s sc_wdd_chunknum
%s sc_wdd_type

%s sc_chardisp

%s sc_isdn_call
%s sc_ether_direction

%%

<INITIAL,sc_gen_byte>{ETHER_PFX} {
  BEGIN(sc_ether_direction);
  ascendlval.d = ASCEND_PFX_ETHER;
  return ETHER_PREFIX;
}

<INITIAL,sc_gen_byte>{ISDN_XPFX} {
  BEGIN(sc_isdn_call);
  ascendlval.d = ASCEND_PFX_ISDN_X;
  return ISDN_PREFIX;
}

<INITIAL,sc_gen_byte>{ISDN_RPFX} {
  BEGIN(sc_isdn_call);
  ascendlval.d = ASCEND_PFX_ISDN_R;
  return ISDN_PREFIX;
}

<INITIAL,sc_gen_byte>{WAN_XPFX} {
  BEGIN(sc_wds_user);
  ascendlval.d = ASCEND_PFX_WDS_X;
  return WDS_PREFIX;
}

<INITIAL,sc_gen_byte>{WAN_RPFX} {
  BEGIN(sc_wds_user);
  ascendlval.d = ASCEND_PFX_WDS_R;
  return WDS_PREFIX;
}

<INITIAL,sc_gen_byte>{PPP_XPFX} {
  BEGIN(sc_wds_user);
  ascendlval.d = ASCEND_PFX_WDS_X;
  return WDS_PREFIX;
}

<INITIAL,sc_gen_byte>{PPP_RPFX} {
  BEGIN(sc_wds_user);
  ascendlval.d = ASCEND_PFX_WDS_R;
  return WDS_PREFIX;
}

<sc_ether_direction>[^\(]{2,20} {
  BEGIN(sc_gen_task);
  return STRING;
}

<sc_isdn_call>[^\/\(:]{2,20} {
  BEGIN(sc_gen_task);
  return DECNUM;
}

<sc_wds_user>[^:]{2,20} {
  char *atcopy = g_strdup(ascendtext);
  char colon = input();
  char after = input();
  int retval = STRING;

  unput(after); unput(colon);

  if (after != '(' && after != ' ') {
    BEGIN(sc_wds_sess);
    if (pseudo_header != NULL) {
      g_strlcpy(pseudo_header->user, atcopy, ASCEND_MAX_STR_LEN);
    }
  } else {	/* We have a version 7 file */
    BEGIN(sc_gen_task);
    if (pseudo_header != NULL) {
      g_strlcpy(pseudo_header->user, NO_USER, ASCEND_MAX_STR_LEN);
    }
    ascendlval.d = strtol(ascendtext, NULL, 10);
    retval = DECNUM;
  }
  g_free (atcopy);
  return retval;
}

<sc_wds_sess>{D}* {
  BEGIN(sc_gen_task);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_gen_task>(0x|0X)?{H}{2,8} {
  BEGIN(sc_gen_time_s);
  ascendlval.d = strtoul(ascendtext, NULL, 16);
  return HEXNUM;
}

<sc_gen_task>\"[A-Za-z0-9_ ]+\" {
  return STRING;
}

<sc_gen_time_s>{D}{1,10} {
  BEGIN(sc_gen_time_u);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_gen_time_u>{D}{1,6} {
  char *atcopy = g_strdup(ascendtext);
  BEGIN(sc_gen_octets);
  /* only want the most significant 2 digits. convert to usecs */
  if (strlen(atcopy) > 2)
    atcopy[2] = '\0';
  ascendlval.d = strtol(atcopy, NULL, 10) * 10000;
  g_free(atcopy);
  return DECNUM;
}

<sc_gen_octets>{D}{1,10} {
  BEGIN(sc_gen_counter);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_gen_counter,sc_gen_byte>"["{H}{4}"]:" {
  BEGIN(sc_gen_byte);
  return COUNTER;
}

<sc_gen_byte>{H}{2} {
  ascendlval.b = (guint8)strtol(ascendtext, NULL, 16);
  return HEXBYTE;
}

<sc_gen_byte>" "{4} {
  BEGIN(sc_chardisp);
}

<sc_chardisp>.*	{
  BEGIN(sc_gen_byte);
}

<INITIAL,sc_gen_byte>{WDD_DATE} {
  BEGIN(sc_wdd_date_d);
  return WDD_DATE;
}

<sc_wdd_date_d>{D}{2} {
  BEGIN(sc_wdd_date_m);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_wdd_date_m>{D}{2} {
  BEGIN(sc_wdd_date_y);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_wdd_date_y>{D}{4} {
  BEGIN(sc_wdd_time);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_wdd_time>{WDD_TIME} {
  BEGIN(sc_wdd_time_h);
  return KEYWORD;
}

<sc_wdd_time_h>{D}{2} {
  BEGIN(sc_wdd_time_m);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_wdd_time_m>{D}{2} {
  BEGIN(sc_wdd_time_s);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_wdd_time_s>{D}{2} {
  BEGIN(sc_wdd_cause);
  ascendlval.d = strtol(ascendtext, NULL, 10);
  return DECNUM;
}

<sc_wdd_cause>{WDD_CAUSE} {
  BEGIN(sc_wdd_callnum);
  return KEYWORD;
}

<sc_wdd_callnum>{WDD_CALLNUM} {
  BEGIN(sc_wdd_chunk);
  if (pseudo_header != NULL) {
    g_strlcpy(pseudo_header->call_num, ascendtext, ASCEND_MAX_STR_LEN);
  }
  return STRING;
}

<INITIAL,sc_wdd_chunk,sc_gen_byte>{WDD_CHUNK} {
  BEGIN(sc_wdd_chunknum);
  return WDD_CHUNK;
}

<sc_wdd_chunknum>{H}{1,8} {
  BEGIN(sc_wdd_type);
  ascendlval.d = strtoul(ascendtext, NULL, 16);
  return HEXNUM;
}

<sc_wdd_type>{WDD_TYPE} {
  BEGIN(sc_gen_task);
  return KEYWORD;
}

<sc_gen_task>\/{D}+ {
  return SLASH_SUFFIX;
}

(0x|0X)?{H}+ { return HEXNUM; }

task:|task|at|time:|octets { return KEYWORD; }

<<EOF>> { at_eof++; yyterminate(); }

(.|\n) ;

%%

void ascend_init_lexer(FILE_T fh)
{
  yyrestart(0);
  yy_fh = fh;
  BEGIN(INITIAL);
}

/*
 * We want to stop processing when we get to the end of the input.
 * (%option noyywrap is not used because if used then
 * some flex versions (eg: 2.5.35) generate code which causes
 * warnings by the Windows VC compiler).
 */

int yywrap(void) {
    return 1;
}
