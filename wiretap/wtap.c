/* wtap.c
 *
 * $Id: wtap.c,v 1.21 1999/09/23 04:39:00 ashokn Exp $
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
#include "file.h"
#include "wtap.h"
#include "buffer.h"
#include "ascend.h"

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

const char *wtap_file_type_string(wtap *wth)
{
	switch (wth->file_type) {
		case WTAP_FILE_WTAP:
			return "wiretap";

		case WTAP_FILE_PCAP:
			return "pcap";

		case WTAP_FILE_LANALYZER:
			return "Novell LANalyzer";

		case WTAP_FILE_NGSNIFFER:
			return "Network Associates Sniffer (DOS-based)";

		case WTAP_FILE_SNOOP:
			return "snoop";

		case WTAP_FILE_IPTRACE:
			return "iptrace";

		case WTAP_FILE_NETMON_1_x:
			return "Microsoft Network Monitor 1.x";

		case WTAP_FILE_NETMON_2_x:
			return "Microsoft Network Monitor 2.x";

		case WTAP_FILE_NETXRAY_1_0:
			return "Cinco Networks NetXRay";

		case WTAP_FILE_NETXRAY_1_1:
			return "Network Associates Sniffer (Windows-based) 1.1";

		case WTAP_FILE_NETXRAY_2_001:
			return "Network Associates Sniffer (Windows-based) 2.001";

		case WTAP_FILE_RADCOM:
			return "RADCOM WAN/LAN analyzer";

		case WTAP_FILE_ASCEND:
			return "Lucent/Ascend access server trace";

		default:
			g_error("Unknown capture file type %d", wth->file_type);
			return NULL;
	}
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

		/* default:
			 nothing */
	}

	file_close(wth->fh);
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

int wtap_seek_read(int encaps, FILE *fh, int seek_off, guint8 *pd, int len)
{
	switch (encaps) {

	case WTAP_ENCAP_ASCEND:
		return ascend_seek_read(fh, seek_off, pd, len);

	default:
		return wtap_def_seek_read(fh, seek_off, pd, len);
	}
}
