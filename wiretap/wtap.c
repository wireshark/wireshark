/* wtap.c
 *
 * $Id: wtap.c,v 1.36 2000/01/13 07:09:20 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@verdict.uthscsa.edu>
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
#include <string.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "ascend.h"
#include "toshiba.h"

FILE* wtap_file(wtap *wth)
{
	return wth->fh;
}

int wtap_fd(wtap *wth)
{
	return wth->fd;
}

int wtap_file_type(wtap *wth)
{
	return wth->file_type;
}

int wtap_snapshot_length(wtap *wth)
{
	return wth->snapshot_length;
}

int wtap_file_encap(wtap *wth)
{
	return wth->file_encap;
}

/* Table of the encapsulation types we know about. */
const static struct encap_type_info {
	const char *name;
	const char *short_name;
} encap_table[WTAP_NUM_ENCAP_TYPES] = {
	/* WTAP_ENCAP_UNKNOWN */
	{ "Unknown", NULL },

	/* WTAP_ENCAP_ETHERNET */
	{ "Ethernet", "ether" },

	/* WTAP_ENCAP_TR */
	{ "Token Ring", "tr" },

	/* WTAP_ENCAP_SLIP */
	{ "SLIP", "slip" },

	/* WTAP_ENCAP_PPP */
	{ "PPP", "ppp" },

	/* WTAP_ENCAP_FDDI */
	{ "FDDI", "fddi" },

	/* WTAP_ENCAP_FDDI_BITSWAPPED */
	{ "FDDI with bit-swapped MAC addresses", "fddi-swapped" },

	/* WTAP_ENCAP_RAW_IP */
	{ "Raw IP", "rawip" },

	/* WTAP_ENCAP_ARCNET */
	{ "ARCNET", "arcnet" },

	/* WTAP_ENCAP_ATM_RFC1483 */
	{ "RFC 1483 ATM", "atm-rfc1483" },

	/* WTAP_ENCAP_LINUX_ATM_CLIP */
	{ "Linux ATM CLIP", "linux-atm-clip" },

	/* WTAP_ENCAP_LAPB */
	{ "LAPB", "lapb" },

	/* WTAP_ENCAP_ATM_SNIFFER */
	{ "ATM Sniffer", "atm-sniffer" },

	/* WTAP_ENCAP_NULL */
	{ "NULL", "null" },

	/* WTAP_ENCAP_ASCEND */
	{ "Lucent/Ascend access equipment", "ascend" },

	/* WTAP_ENCAP_LAPD */
	{ "LAPD", "lapd" },

	/* WTAP_ENCAP_V120 */
	{ "V.120", "v120" },
};

/* Name that should be somewhat descriptive. */
const char *wtap_encap_string(int encap)
{
	if (encap < 0 || encap >= WTAP_NUM_ENCAP_TYPES)
		return NULL;
	else
		return encap_table[encap].name;
}

/* Name to use in, say, a command-line flag specifying the type. */
const char *wtap_encap_short_string(int encap)
{
	if (encap < 0 || encap >= WTAP_NUM_ENCAP_TYPES)
		return NULL;
	else
		return encap_table[encap].short_name;
}

/* Translate a short name to a capture file type. */
int wtap_short_string_to_encap(const char *short_name)
{
	int encap;

	for (encap = 0; encap < WTAP_NUM_ENCAP_TYPES; encap++) {
		if (encap_table[encap].short_name != NULL &&
		    strcmp(short_name, encap_table[encap].short_name) == 0)
			return encap;
	}
	return -1;	/* no such encapsulation type */
}

static const char *wtap_errlist[] = {
	"The file isn't a plain file",
	"The file isn't a capture file in a known format",
	"File contains record data we don't support",
	NULL,
	"Files can't be saved in that format",
	"Files from that network type can't be saved in that format",
	"That format doesn't support per-packet encapsulations",
	NULL,
	NULL,
	"Less data was read than was expected",
	"File contains a record that's not valid",
	"Less data was written than was requested"
};
#define	WTAP_ERRLIST_SIZE	(sizeof wtap_errlist / sizeof wtap_errlist[0])

const char *wtap_strerror(int err)
{
	static char errbuf[6+11+1];	/* "Error %d" */
	int wtap_errlist_index;

	if (err < 0) {
#ifdef HAVE_LIBZ
		if (err >= WTAP_ERR_ZLIB_MIN && err <= WTAP_ERR_ZLIB_MAX) {
			/* Assume it's a zlib error. */
			sprintf(errbuf, "Uncompression error: %s",
			    zError(err - WTAP_ERR_ZLIB));
			return errbuf;
		}
#endif
		wtap_errlist_index = -1 - err;
		if (wtap_errlist_index >= WTAP_ERRLIST_SIZE) {
			sprintf(errbuf, "Error %d", err);
			return errbuf;
		}
		if (wtap_errlist[wtap_errlist_index] == NULL)
			return "Unknown reason";
		return wtap_errlist[wtap_errlist_index];
	} else
		return strerror(err);
}

void wtap_close(wtap *wth)
{
	/* free up memory. If any capture structure ever allocates
	 * its own memory, it would be better to make a *close() function
	 * for each filetype, like pcap_close(0, lanalyzer_close(), etc.
	 * But for now this will work. */
	switch(wth->file_type) {
		case WTAP_FILE_PCAP:
		case WTAP_FILE_PCAP_MODIFIED:
			g_free(wth->capture.pcap);
			break;

		case WTAP_FILE_LANALYZER:
			g_free(wth->capture.lanalyzer);
			break;

		case WTAP_FILE_NGSNIFFER:
			g_free(wth->capture.ngsniffer);
			break;

		case WTAP_FILE_RADCOM:
			g_free(wth->capture.radcom);
			break;

		case WTAP_FILE_NETMON_1_x:
		case WTAP_FILE_NETMON_2_x:
			g_free(wth->capture.netmon);
			break;

		case WTAP_FILE_NETXRAY_1_0:
		case WTAP_FILE_NETXRAY_1_1:
		case WTAP_FILE_NETXRAY_2_001:
			g_free(wth->capture.netxray);
			break;

		case WTAP_FILE_ASCEND:
			g_free(wth->capture.ascend);
			break;

		case WTAP_FILE_NETTL:
			g_free(wth->capture.nettl);
			break;

		/* default:
			 nothing */
	}

	file_close(wth->fh);

	if (wth->frame_buffer) {
		buffer_free(wth->frame_buffer);
		g_free(wth->frame_buffer);
	}

	g_free(wth);
}

int wtap_loop(wtap *wth, int count, wtap_handler callback, u_char* user,
	int *err)
{
	int data_offset, loop = 0;

	while ((data_offset = wth->subtype_read(wth, err)) > 0) {
		callback(user, &wth->phdr, data_offset,
		    buffer_start_ptr(wth->frame_buffer));
		if (count > 0 && ++loop >= count)
			break;
	}
	if (data_offset < 0)
		return FALSE;	/* failure */
	else
		return TRUE;	/* success */
}

int wtap_seek_read(int file_type, FILE *fh, int seek_off, guint8 *pd, int len)
{
	switch (file_type) {

	case WTAP_FILE_ASCEND:
		return ascend_seek_read(fh, seek_off, pd, len);

	case WTAP_FILE_TOSHIBA:
		return toshiba_seek_read(fh, seek_off, pd, len);

	default:
		return wtap_def_seek_read(fh, seek_off, pd, len);
	}
}
