/* wtap.c
 *
 * $Id: wtap.c,v 1.58 2001/11/30 07:14:22 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
#include <string.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"

int
wtap_fd(wtap *wth)
{
	return wth->fd;
}

int
wtap_file_type(wtap *wth)
{
	return wth->file_type;
}

int
wtap_snapshot_length(wtap *wth)
{
	return wth->snapshot_length;
}

int
wtap_file_encap(wtap *wth)
{
	return wth->file_encap;
}

/* Table of the encapsulation types we know about. */
static const struct encap_type_info {
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

	/* WTAP_ENCAP_PPP_WITH_PHDR */
	{ "PPP with Directional Info", "ppp-with-direction" },

	/* WTAP_ENCAP_IEEE_802_11 */
	{ "IEEE 802.11 Wireless LAN", "ieee-802-11" },

	/* WTAP_ENCAP_SLL */
	{ "Linux cooked-mode capture", "linux-sll" },

	/* WTAP_ENCAP_FRELAY */
	{ "Frame Relay", "frelay" },

	/* WTAP_ENCAP_CHDLC */
	{ "Cisco HDLC", "chdlc" },

	/* WTAP_ENCAP_CISCO_IOS */
	{ "Cisco IOS internal", "ios" },

	/* WTAP_ENCAP_LOCALTALK */
	{ "Localtalk", "ltalk" },

	/* WTAP_ENCAP_PRISM_HEADER */
	{ "IEEE 802.11 plus Prism II monitor mode header", "prism" },
};

/* Name that should be somewhat descriptive. */
const char
*wtap_encap_string(int encap)
{
	if (encap < 0 || encap >= WTAP_NUM_ENCAP_TYPES)
		return NULL;
	else
		return encap_table[encap].name;
}

/* Name to use in, say, a command-line flag specifying the type. */
const char
*wtap_encap_short_string(int encap)
{
	if (encap < 0 || encap >= WTAP_NUM_ENCAP_TYPES)
		return NULL;
	else
		return encap_table[encap].short_name;
}

/* Translate a short name to a capture file type. */
int
wtap_short_string_to_encap(const char *short_name)
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
	"Less data was written than was requested",
	"Uncompression error: data oddly truncated",
	"Uncompression error: data would overflow buffer",
	"Uncompression error: bad LZ77 offset",
};
#define	WTAP_ERRLIST_SIZE	(sizeof wtap_errlist / sizeof wtap_errlist[0])

const char
*wtap_strerror(int err)
{
	static char errbuf[128];
	unsigned int wtap_errlist_index;

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

/* Close only the sequential side, freeing up memory it uses.

   Note that we do *not* want to call the subtype's close function,
   as it would free any per-subtype data, and that data may be
   needed by the random-access side.
   
   Instead, if the subtype has a "sequential close" function, we call it,
   to free up stuff used only by the sequential side. */
void
wtap_sequential_close(wtap *wth)
{
	if (wth->subtype_sequential_close != NULL)
		(*wth->subtype_sequential_close)(wth);

	if (wth->fh != NULL) {
		file_close(wth->fh);
		wth->fh = NULL;
	}

	if (wth->frame_buffer) {
		buffer_free(wth->frame_buffer);
		g_free(wth->frame_buffer);
		wth->frame_buffer = NULL;
	}
}

void
wtap_close(wtap *wth)
{
	wtap_sequential_close(wth);

	if (wth->subtype_close != NULL)
		(*wth->subtype_close)(wth);

	if (wth->random_fh != NULL)
		file_close(wth->random_fh);

	g_free(wth);
}

gboolean
wtap_read(wtap *wth, int *err, long *data_offset)
{
	return wth->subtype_read(wth, err, data_offset);
}

struct wtap_pkthdr*
wtap_phdr(wtap *wth)
{
	return &wth->phdr;
}

union wtap_pseudo_header*
wtap_pseudoheader(wtap *wth)
{
	return &wth->pseudo_header;
}

guint8*
wtap_buf_ptr(wtap *wth)
{
	return buffer_start_ptr(wth->frame_buffer);
}

gboolean
wtap_loop(wtap *wth, int count, wtap_handler callback, u_char* user, int *err)
{
	long		data_offset;
	int		loop = 0;

	/* Start by clearing error flag */
	*err = 0;

	while ( (wtap_read(wth, err, &data_offset)) ) {
		callback(user, &wth->phdr, data_offset,
		    &wth->pseudo_header, buffer_start_ptr(wth->frame_buffer));
		if (count > 0 && ++loop >= count)
			break;
	}

	if (*err == 0)
		return TRUE;	/* success */
	else
		return FALSE;	/* failure */
}

int
wtap_seek_read(wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len)
{
	return wth->subtype_seek_read(wth, seek_off, pseudo_header, pd, len);
}
