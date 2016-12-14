/* daintree_sna.c
 * Routines for opening .dcf capture files created by Daintree's
 * Sensor Network Analyzer for 802.15.4 radios
 * Copyright 2009, Exegin Technologies Limited <fff@exegin.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Started with packetlogger.c as a template, but little packetlogger code
 * remains. Borrowed many snippets from dbs-etherwatch.c, the
 * daintree_sna_process_hex_data function having the largest chunk.
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

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "daintree-sna.h"

typedef struct daintree_sna_header {
	guint32 len;
	guint64 ts;
} daintree_sna_header_t;

#define DAINTREE_SNA_HEADER_SIZE 2
#define FCS_LENGTH 2

static const char daintree_magic_text[] = "#Format=";

#define DAINTREE_MAGIC_TEXT_SIZE (sizeof daintree_magic_text - 1)
#define DAINTREE_MAX_LINE_SIZE 512
#define READDATA_BUF_SIZE (DAINTREE_MAX_LINE_SIZE/2)
#define READDATA_MAX_FIELD_SIZE "255"  /* DAINTREE_MAX_LINE_SIZE/2 -1 */

#define COMMENT_LINE daintree_magic_text[0]

static gboolean daintree_sna_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);

static gboolean daintree_sna_seek_read(wtap *wth, gint64 seek_off,
	struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);

static gboolean daintree_sna_read_packet(FILE_T fh, struct wtap_pkthdr *phdr,
	Buffer *buf, int *err, gchar **err_info);

/* Open a file and determine if it's a Daintree file */
wtap_open_return_val daintree_sna_open(wtap *wth, int *err, gchar **err_info)
{
	char readLine[DAINTREE_MAX_LINE_SIZE];

	/* get first line of file header */
	if (file_gets(readLine, DAINTREE_MAX_LINE_SIZE, wth->fh)==NULL) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/* check magic text */
	if (strncmp(readLine, daintree_magic_text, DAINTREE_MAGIC_TEXT_SIZE) != 0)
		return WTAP_OPEN_NOT_MINE; /* not daintree format */

	/* read second header line */
	if (file_gets(readLine, DAINTREE_MAX_LINE_SIZE, wth->fh)==NULL) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}
	if (readLine[0] != COMMENT_LINE)
		return WTAP_OPEN_NOT_MINE; /* daintree files have a two line header */

	/* set up the pointers to the handlers for this file type */
	wth->subtype_read = daintree_sna_read;
	wth->subtype_seek_read = daintree_sna_seek_read;

	/* set up for file type */
	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_DAINTREE_SNA;
	wth->file_encap = WTAP_ENCAP_IEEE802_15_4_NOFCS;
	wth->file_tsprec = WTAP_TSPREC_USEC;
	wth->snapshot_length = 0; /* not available in header */

	return WTAP_OPEN_MINE; /* it's a Daintree file */
}

/* Read the capture file sequentially
 * Wireshark scans the file with sequential reads during preview and initial display. */
static gboolean
daintree_sna_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	*data_offset = file_tell(wth->fh);

	/* parse that line and the following packet data */
	return daintree_sna_read_packet(wth->fh, &wth->phdr,
	    wth->frame_buffer, err, err_info);
}

/* Read the capture file randomly
 * Wireshark opens the capture file for random access when displaying user-selected packets */
static gboolean
daintree_sna_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
	Buffer *buf, int *err, gchar **err_info)
{
	if(file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* parse that line and the following packet data */
	return daintree_sna_read_packet(wth->random_fh, phdr, buf, err,
	    err_info);
}

/* Read a header line, scan it, and fill in a struct wtap_pkthdr.
 * Then convert packet data from ASCII hex string to binary in place,
 * sanity-check its length against what we assume is the packet length field,
 * and copy it into a Buffer. */
static gboolean
daintree_sna_read_packet(FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
	guint64 seconds;
	int useconds;
	char readLine[DAINTREE_MAX_LINE_SIZE];
	char readData[READDATA_BUF_SIZE];
	guchar *str = (guchar *)readData;
	guint bytes;
	guint8 *p;

	/* we've only seen file header lines starting with '#', but
	 * if others appear in the file, they are tossed */
	do {
		if (file_gets(readLine, DAINTREE_MAX_LINE_SIZE, fh) == NULL) {
			*err = file_error(fh, err_info);
			return FALSE; /* all done */
		}
	} while (readLine[0] == COMMENT_LINE);

	phdr->rec_type = REC_TYPE_PACKET;
	phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	if (sscanf(readLine, "%*s %18" G_GINT64_MODIFIER "u.%9d %9u %" READDATA_MAX_FIELD_SIZE "s",
	    &seconds, &useconds, &phdr->len, readData) != 4) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("daintree_sna: invalid read record");
		return FALSE;
	}

	/* Daintree doesn't store the FCS, but pads end of packet with 0xffff, which we toss */
	if (phdr->len <= FCS_LENGTH) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("daintree_sna: packet length <= %u bytes, no frame data present",
		    FCS_LENGTH);
		return FALSE;
	}
	phdr->len -= FCS_LENGTH;

	phdr->ts.secs = (time_t) seconds;
	phdr->ts.nsecs = useconds * 1000; /* convert mS to nS */

	/*
	 * READDATA_BUF_SIZE is < WTAP_MAX_PACKET_SIZE, and is the maximum
	 * number of bytes of packet data we can generate, so we don't
	 * need to check the packet length.
	 */
	p = str; /* overlay source buffer */
	bytes = 0;
	/* convert hex string to guint8 */
	while(*str) {
		/* most significant nibble */
		if (!g_ascii_isxdigit(*str)) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("daintree_sna: non-hex digit in hex data");
			return FALSE;
		}
		if(g_ascii_isdigit(*str)) {
			*p = (*str - '0') << 4;
		} else {
			*p = ((g_ascii_tolower(*str) - 'a') + 10) << 4;
		}
		str++;

		/* least significant nibble */
		if (!g_ascii_isxdigit(*str)) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("daintree_sna: non-hex digit in hex data");
			return FALSE;
		}
		if(g_ascii_isdigit(*str)) {
			*p += *str - '0';
		} else {
			*p += (g_ascii_tolower(*str) - 'a') + 10;
		}
		str++;

		/* next byte in buffer */
		p++;
		bytes++;
	}

	/* Daintree doesn't store the FCS, but pads end of packet with 0xffff, which we toss */
	if (bytes <= FCS_LENGTH) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("daintree_sna: Only %u bytes of packet data",
		    bytes);
		return FALSE;
	}
	bytes -= FCS_LENGTH;
	if (bytes > phdr->len) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("daintree_sna: capture length (%u) > packet length (%u)",
		    bytes, phdr->len);
		return FALSE;
	}

	phdr->caplen = bytes;

	ws_buffer_assure_space(buf, bytes);
	memcpy(ws_buffer_start_ptr(buf), readData, bytes);
	return TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
