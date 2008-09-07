/*
 * We don't use unput, so don't generate code for it.
 */
%option nounput

/*
 * We don't read from the terminal.
 */
%option never-interactive

/*
 * Prefix scanner routines with "K12Text_" rather than "yy", so this scanner
 * can coexist with other scanners.
 */
%option prefix="K12Text_"

%option outfile="k12text.c"

%{
/* k12text.l
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

 /*
  * TODO:
  *   - fix timestamps after midnight
  *   - verify encapsulations
  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "wtap-int.h"
#include "wtap.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "k12.h"
#include "k12text_lex.h"

#ifndef HAVE_UNISTD_H
#define YY_NO_UNISTD_H
#endif

static guint h;
static guint m;
static guint s;
static guint ms;
static guint ns;
static gint encap;
static guint8 b[65536];
static guint i;
static gboolean is_k12text;
static gboolean at_eof;
static guint junk_chars = 0;
static void finalize_frame(void);
static gchar* error_str;
static gint64 cum_offset;
static gboolean ok_frame;
static FILE_T yy_fh;

#define RESET() do { ok_frame = FALSE; h=0; m=0; s=0; ns=0; ms=0; i=0; is_k12text=FALSE; junk_chars = 0; error_str = NULL; } while(0)

#define KERROR(text) do { error_str = g_strdup(text); yyterminate(); } while(0)
#define START_PACKET RESET
#define SET_HOURS(text) h = strtoul(text,NULL,10)
#define SET_MINUTES(text) m = strtoul(text,NULL,10)
#define SET_SECONDS(text) s = strtoul(text,NULL,10)
#define SET_MS(text) ms = strtoul(text,NULL,10)
#define SET_NS(text) ns = strtoul(text,NULL,10)
#define SET_ENCAP(text) set_encap(text)
#define ADD_BYTE(text) do {if (i >= 65536) {KERROR("frame too large");} b[i++] = (guint8)strtoul(text,NULL,16); } while(0)
#define FINALIZE_FRAME() finalize_frame()
/*~ #define ECHO*/
#define YY_USER_ACTION cum_offset += yyleng;
#define YY_INPUT(buf,result,max_size) { int c = file_getc(yy_fh);  result = (c==EOF) ? YY_NULL : (buf[0] = c, 1); }

#define MAX_JUNK 400000
#define ECHO
%}
start_timestamp \053[\055]{9}\053[\055]{15,100}\053[\055]{10,100}\053
oneormoredigits [0-9]+:
twodigits [0-9][0-9]
colon :
comma ,
threedigits [0-9][0-9][0-9]
start_bytes \174\060\040\040\040\174
bytes_junk \174[A-F0-9][A-F0-9\040][A-F0-9\040][A-F0-9\040]\174
byte [a-f0-9][a-f0-9]\174
end_bytes \015\012\015\012
eth ETHER
mtp2 MTP-L2
sscop SSCOP
sscfnni SSCF
hdlc HDLC

%START NEXT_FRAME HOURS H2M MINUTES M2S S2M MS M2N NS ENCAP STARTBYTES BYTE ENDBYTES MAGIC SECONDS
%%
<MAGIC>{start_timestamp}  { is_k12text = TRUE; yyterminate(); }

<MAGIC>. { if (++ junk_chars > MAX_JUNK) { is_k12text = FALSE;  yyterminate(); } }

<NEXT_FRAME>{start_timestamp} { START_PACKET(); BEGIN(HOURS); }
<HOURS>{oneormoredigits} { SET_HOURS(yytext); BEGIN(MINUTES); }
<MINUTES>{twodigits} { SET_MINUTES(yytext); BEGIN(M2S);}
<M2S>{colon} { BEGIN(SECONDS);}
<SECONDS>{twodigits} { SET_SECONDS(yytext); BEGIN(S2M); }
<S2M>{comma}  { BEGIN(MS); }
<MS>{threedigits} { SET_MS(yytext); BEGIN(M2N);  }
<M2N>{comma}  { BEGIN(NS); }
<NS>{threedigits} { SET_NS(yytext); BEGIN(ENCAP);}
<ENCAP>{eth} {encap = WTAP_ENCAP_ETHERNET; BEGIN(STARTBYTES); }
<ENCAP>{mtp2} {encap = WTAP_ENCAP_MTP2; BEGIN(STARTBYTES); }
<ENCAP>{sscop} {encap = WTAP_ENCAP_ATM_PDUS; BEGIN(STARTBYTES); }
<ENCAP>{sscfnni} {encap = WTAP_ENCAP_MTP3; BEGIN(STARTBYTES); }
<ENCAP>{hdlc} {encap = WTAP_ENCAP_CHDLC; BEGIN(STARTBYTES); }
<ENCAP,STARTBYTES>{start_bytes} { BEGIN(BYTE); }
<BYTE>{byte} { ADD_BYTE(yytext); }
<BYTE>{bytes_junk} ;
<BYTE>{end_bytes} { FINALIZE_FRAME(); yyterminate(); }

. {  if (++junk_chars > MAX_JUNK) { KERROR("too much junk");  } }
<<EOF>> { at_eof = TRUE; yyterminate(); }

%%

static void finalize_frame(void) {
	ok_frame = TRUE;
}

static gboolean k12text_read(wtap *wth, int *err, char ** err_info _U_, gint64 *data_offset) {
	gint64 start_offset = cum_offset;

	encap = WTAP_ENCAP_UNKNOWN;
	ok_frame = FALSE;

	BEGIN(NEXT_FRAME);
	yylex();

	if (ok_frame == FALSE) {
		if (at_eof) {
			*err_info = NULL;
			*err = 0;
		} else {
			*err_info = error_str;
			*err = WTAP_ERR_BAD_RECORD;
		}
		return FALSE;
	}

	wth->data_offset = *data_offset = start_offset ;


	wth->phdr.ts.secs = 946681200 + (3600*h) + (60*m) + s;
	wth->phdr.ts.nsecs = 1000000*ms + 1000*ns;

	wth->phdr.caplen = wth->phdr.len = i;

	wth->phdr.pkt_encap = encap;

	buffer_assure_space(wth->frame_buffer, wth->phdr.caplen);
	memcpy(buffer_start_ptr(wth->frame_buffer), b, wth->phdr.caplen);

	return TRUE;
}

static gboolean k12text_seek_read(wtap *wth, gint64 seek_off, union wtap_pseudo_header *pseudo_header _U_, guint8 *pd, int length, int *err, char **err_info) {
	gint64 save_offset = cum_offset;

	ok_frame = FALSE;
	RESET();

	yy_fh = wth->random_fh;


	if ( file_seek(yy_fh, seek_off, SEEK_SET, err) == -1) {
		return FALSE;
	}

	BEGIN(NEXT_FRAME);
	yylex();

	if (ok_frame == FALSE) {
		*err_info = error_str;
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	memcpy(pd, b, length);

	cum_offset = save_offset ;
	return TRUE;
}

static void k12text_close(wtap *wth _U_) {
	(void)0;
}

int k12text_open(wtap *wth, int *err, gchar **err_info _U_) {

	cum_offset = 0;

	RESET();
	yy_fh = wth->fh;
	BEGIN(MAGIC);
	yylex();

	if (! is_k12text) return 0;

	if ( file_seek(yy_fh, 0, SEEK_SET, err) == -1) {
		return -1;
	}

	cum_offset = 0;

	wth->data_offset = 0;
	wth->file_type = WTAP_FILE_K12TEXT;
	wth->file_encap = WTAP_ENCAP_PER_PACKET;
	wth->snapshot_length = 0;
	wth->subtype_read = k12text_read;
	wth->subtype_seek_read = k12text_seek_read;
	wth->subtype_close = k12text_close;
	wth->capture.generic  = NULL;
	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

	return 1;
}


static const struct { int e; const char* s; } encaps[] = {
	{ WTAP_ENCAP_ETHERNET, "ETHER" },
	{ WTAP_ENCAP_MTP2, "MTP-L2" },
	{ WTAP_ENCAP_ATM_PDUS, "SSCOP" },
	{ WTAP_ENCAP_MTP3, "SSCF" },
	{ WTAP_ENCAP_CHDLC, "HDLC" },
	/* ... */
	{ WTAP_ENCAP_UNKNOWN, "UNKNOWN" },
	{ 0, NULL }
};

static gboolean k12text_dump(wtap_dumper *wdh _U_, const struct wtap_pkthdr *phdr,
                         const union wtap_pseudo_header *pseudo_header _U_,
                         const guchar *pd, int *err _U_) {
	char buf[196808];
	size_t left = 196808;
	gint wl;
	char* p=buf;
	const char* str_enc = "";
	guint i;
	guint ns;
	guint ms;

	ms = phdr->ts.nsecs / 1000000;
	ns = (phdr->ts.nsecs - (1000000*ms))/1000;

	for(i=0; encaps[i].s; i++) {
		str_enc = encaps[i].s;
		if (phdr->pkt_encap == encaps[i].e) break;
	}

	strftime(p,90,"+---------+---------------+----------+\r\n%H:%M:%S,",gmtime(&phdr->ts.secs));
       wl = strlen(p);
       p += wl;
       left -= wl;
       
       wl = g_snprintf(p,left,"%.3d,%.3d   %s\r\n|0   |",ms,ns,str_enc);
       p+= wl;
       left -= wl;

       for(i=0;i < phdr->caplen && left > 2; i++) {
               wl = g_snprintf(p,left,"%.2x|",pd[i]);
               p += wl;
               left -= wl;
		}

       wl = g_snprintf(p,left,"\r\n\r\n");
       p+= wl;
       left -= wl;
       
	fwrite(buf, 1, strlen(buf), wdh->fh);

	return TRUE;
}


static gboolean k12text_dump_close(wtap_dumper *wdh _U_ , int *err _U_) {
	return TRUE;
}

gboolean k12text_dump_open(wtap_dumper *wdh, gboolean cant_seek, int *err) {

    if (cant_seek) {
        *err = WTAP_ERR_CANT_WRITE_TO_PIPE;
        return FALSE;
    }

    wdh->subtype_write = k12text_dump;
    wdh->subtype_close = k12text_dump_close;

    return TRUE;
}

int k12text_dump_can_write_encap(int encap) {
    switch (encap) {
	case WTAP_ENCAP_PER_PACKET:
	case WTAP_ENCAP_ETHERNET:
	case WTAP_ENCAP_MTP2:
	case WTAP_ENCAP_ATM_PDUS:
	case WTAP_ENCAP_MTP3:
	case WTAP_ENCAP_CHDLC:
	case WTAP_ENCAP_UNKNOWN:
		return 0;
	default:
		return WTAP_ERR_UNSUPPORTED_ENCAP;
    }
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
