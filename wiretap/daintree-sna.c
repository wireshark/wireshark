/* daintree_sna.c
 * Routines for opening .dcf capture files created by Daintree's
 * Sensor Network Analyzer for 802.15.4 radios
 * Copyright 2009, Exegin Technologies Limited <fff@exegin.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Started with packetlogger.c as a template, but little packetlogger code 
 * remains. Borrowed many snippets from dbs-etherwatch.c, the 
 * daintree_sna_hex_char function having the largest chunk.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/* This module reads capture files saved by Daintree's Sensor Network Analyzer. 
 * Daintree captures are plain text files with a two line header,
 * followed by packet records, one per line, with whitespace separated fields
 * consisting of: packet number, time, bytes of capture data, capture data,
 * unknown, unknown, signal strength?, unknown, etc, and terminated with CRLF.
 */

/* Example capture file:
 
#Format=4
# SNA v2.2.0.4 SUS:20090709 ACT:819705
1 1233783799.326400 10 030809ffffffff07ffff 42 1 -69 25 2 0 1 32767
2 1233783799.477440 5 02000bffff 110 1 -44 25 6 0 1 32767
3 1233783799.809920 5 020013ffff 107 1 -45 25 43 0 1 3276

*/

#include "config.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "wtap.h"
#include "wtap-int.h"
#include "buffer.h"
#include "file_wrappers.h"
#include "daintree-sna.h"

typedef struct daintree_sna_header {
	guint32 len;
	guint64 ts;
} daintree_sna_header_t;

#define DAINTREE_SNA_HEADER_SIZE 2
#define FCS_LENGTH 2

static const char daintree_magic_text[] =
{ '#', 'F', 'o', 'r', 'm', 'a', 't', '=' };

#define DAINTREE_MAGIC_TEXT_SIZE (sizeof daintree_magic_text)
#define DAINTREE_MAX_LINE_SIZE 512
#define READDATA_BUF_SIZE (DAINTREE_MAX_LINE_SIZE/2)
#define READDATA_MAX_FIELD_SIZE "255"  /* DAINTREE_MAX_LINE_SIZE/2 -1 */

#define COMMENT_LINE daintree_magic_text[0]

static gboolean daintree_sna_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);

static gboolean daintree_sna_seek_read(wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header _U_,
	guint8 *pd, int len, int *err,
	gchar **err_info);

static guint daintree_sna_hex_char(guchar *str, int *err);

/* Open a file and determine if it's a Daintree file */
int daintree_sna_open(wtap *wth, int *err _U_, gchar **err_info _U_)
{
	char readLine[DAINTREE_MAX_LINE_SIZE];
	guint i; 

	/* get first line of file header */
	if (file_gets(readLine, DAINTREE_MAX_LINE_SIZE, wth->fh)==NULL) return 0;

	/* check magic text */
	i = 0;
	while (i < DAINTREE_MAGIC_TEXT_SIZE) {
		if (readLine[i] != daintree_magic_text[i]) return 0; /* not daintree format */
		i++;
	} 

	/* read second header line */
	if (file_gets(readLine, DAINTREE_MAX_LINE_SIZE, wth->fh)==NULL) return 0;
	if (readLine[0] != COMMENT_LINE) return 0; /* daintree files have a two line header */

	/* set up the pointers to the handlers for this file type */
	wth->subtype_read = daintree_sna_read;
	wth->subtype_seek_read = daintree_sna_seek_read;

	/* set up for file type */
	wth->file_type = WTAP_FILE_DAINTREE_SNA;
	wth->file_encap = WTAP_ENCAP_IEEE802_15_4_NOFCS;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;
	wth->snapshot_length = 0; /* not available in header */

	return 1; /* it's a Daintree file */
}

/* Read the capture file sequentially
 * Wireshark scans the file with sequential reads during preview and initial display. */
static gboolean
daintree_sna_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	char readLine[DAINTREE_MAX_LINE_SIZE];
	guint64 seconds;
	char readData[READDATA_BUF_SIZE];

	*data_offset = file_tell(wth->fh);

	/* we've only seen file header lines starting with '#', but
	 * if others appear in the file, they are tossed */
	do {
		if (file_gets(readLine, DAINTREE_MAX_LINE_SIZE, wth->fh) == NULL) {
			*err = file_error(wth->fh, err_info);
			return FALSE; /* all done */
		}
	} while (readLine[0] == COMMENT_LINE);

	wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	/* parse one line of capture data */
	if (sscanf(readLine, "%*s %18" G_GINT64_MODIFIER "u.%9d %9u %" READDATA_MAX_FIELD_SIZE "s",
	    &seconds, &wth->phdr.ts.nsecs, &wth->phdr.len, readData) != 4) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("daintree_sna: invalid read record");
		return FALSE;
	}

	/* Daintree doesn't store the FCS, but pads end of packet with 0xffff, which we toss */
	if (wth->phdr.len <= FCS_LENGTH) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("daintree_sna: packet length <= %u bytes, no frame data present",
		    FCS_LENGTH);
		return FALSE;
	}
	wth->phdr.len -= FCS_LENGTH;

	wth->phdr.ts.secs = (time_t) seconds;
	wth->phdr.ts.nsecs *= 1000; /* convert mS to nS */

	/* convert packet data from ASCII string to hex, sanity-check its length against what we assume is the
	 * packet length field, write data to frame buffer */
	if ((wth->phdr.caplen = daintree_sna_hex_char(readData, err)) > FCS_LENGTH) {
		/* Daintree doesn't store the FCS, but pads end of packet with 0xffff, which we toss */
		wth->phdr.caplen -= FCS_LENGTH;
		if (wth->phdr.caplen <= wth->phdr.len) {
			buffer_assure_space(wth->frame_buffer, wth->phdr.caplen);
			memcpy(buffer_start_ptr(wth->frame_buffer), readData, wth->phdr.caplen);
		} else {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("daintree_sna: capture length (%u) > packet length (%u)",
				wth->phdr.caplen, wth->phdr.len);
			return FALSE;
		}
	} else {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("daintree_sna: invalid packet data");
		return FALSE;
	}

	return TRUE;
}

/* Read the capture file randomly 
 * Wireshark opens the capture file for random access when displaying user-selected packets */
static gboolean
daintree_sna_seek_read(wtap *wth, gint64 seek_off, union wtap_pseudo_header
	*pseudo_header _U_, guint8 *pd, int len, int *err,
	gchar **err_info)
{
	char readLine[DAINTREE_MAX_LINE_SIZE];
	guint pkt_len;
	char readData[READDATA_BUF_SIZE];

	if(file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* It appears only file header lines start with '#', but
	 * if we find any others, we toss them */
	do {
		if (file_gets(readLine, DAINTREE_MAX_LINE_SIZE, wth->random_fh) == NULL) {
			*err = file_error(wth->random_fh, err_info);
			return FALSE; /* all done */
		}
	} while (readLine[0] == COMMENT_LINE);

	/* ignore all but packet data, since the sequential read pass stored everything else */
	if (sscanf(readLine, "%*s %*u.%*u %*u %" READDATA_MAX_FIELD_SIZE "s", readData) != 1) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("daintree_sna: corrupted seek record");
		return FALSE;
	}

	/* convert packet data from ASCII hex string to guchar */
	if ((pkt_len = daintree_sna_hex_char(readData, err)) <= FCS_LENGTH) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("daintree_sna: corrupted packet data");
		return FALSE;
	}

	pkt_len -= FCS_LENGTH; /* remove padded bytes that Daintree stores instead of FCS */

	if (pkt_len == (guint) len) {
		/* move to frame buffer for dissection */
		memcpy(pd, readData, pkt_len);
	} else {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("daintree-sna: corrupted frame");
		return FALSE;
	} 

	return TRUE;
}

/* Convert an ASCII hex string to guint8 */
static guint
daintree_sna_hex_char(guchar *str, int *err _U_) {
	guint bytes;
	guint8 *p;

	p = str; /* overlay source buffer */
	bytes = 0;
	/* convert hex string to guint8 */
	while(*str) {
		if (!isxdigit((guchar)*str)) return 0;
		/* most significant nibble */
		if(isdigit((guchar)*str)) {
			*p = (*str - '0') << 4;
		} else {
			*p = ((tolower(*str) - 'a') + 10) << 4;
		}
		str++;

		if (!isxdigit((guchar)*str)) return 0;
		/* least significant nibble */
		if(isdigit((guchar)*str)) {
			*p += *str - '0';
		} else {
			*p += (tolower(*str) - 'a') + 10;
		}
		str++;

		/* next byte in buffer */
		p++;
		bytes++;
	}

	return bytes;
}
