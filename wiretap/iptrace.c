/* iptrace.c
 *
 * $Id: iptrace.c,v 1.12 1999/09/24 05:49:50 guy Exp $
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include "wtap.h"
#include "file.h"
#include "buffer.h"
#include "iptrace.h"

static int iptrace_read(wtap *wth, int *err);

int iptrace_open(wtap *wth, int *err)
{
	int bytes_read;
	char name[12];

	file_seek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(name, 1, 11, wth->fh);
	if (bytes_read != 11) {
		if (file_error(wth->fh)) {
			*err = errno;
			return -1;
		}
		return 0;
	}
	wth->data_offset += 11;
	name[11] = 0;
	if (strcmp(name, "iptrace 2.0") != 0) {
		return 0;
	}

	wth->file_type = WTAP_FILE_IPTRACE;
	wth->subtype_read = iptrace_read;
	return 1;
}

/* Read the next packet */
static int iptrace_read(wtap *wth, int *err)
{
	int bytes_read;
	int data_offset;
	guint16 packet_size;
	guint8 header[40];
	char if_name1, if_name2;

	/* Read the descriptor data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(header, 1, 40, wth->fh);
	if (bytes_read != 40) {
		if (file_error(wth->fh)) {
			*err = errno;
			return -1;
		}
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	wth->data_offset += 40;

	packet_size = pntohs(&header[2]) - 32;

	/* Read the packet data */
	buffer_assure_space(wth->frame_buffer, packet_size);
	data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer), 1,
		packet_size, wth->fh);

	if (bytes_read != packet_size) {
		if (file_error(wth->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	wth->data_offset += packet_size;

	wth->phdr.len = packet_size;
	wth->phdr.caplen = packet_size;
	wth->phdr.ts.tv_sec = pntohl(&header[32]);
	/* AIX saves time in nsec, not usec. It's easier to make iptrace
	 * files more Unix-compliant here than try to get the calling
	 * program to know when to use nsec or usec */
	wth->phdr.ts.tv_usec = pntohl(&header[36]) / 1000;

	if_name1 = header[12];
	if_name2 = header[13];
	if (if_name1 == 't' && if_name2 == 'r') {
		wth->phdr.pkt_encap = WTAP_ENCAP_TR;
	}
	else if (if_name1 == 'e' && if_name2 == 'n') {
		wth->phdr.pkt_encap = WTAP_ENCAP_ETHERNET;
	}
	else if (if_name1 == 'f' && if_name2 == 'd') {
		wth->phdr.pkt_encap = WTAP_ENCAP_FDDI_BITSWAPPED;
	}
	else if (if_name1 == 'l' && if_name2 == 'o') { /* loopback */
		wth->phdr.pkt_encap = WTAP_ENCAP_RAW_IP;
	}
	else if (if_name1 == 'x' && if_name2 == 'd') { /* X.25 */
		wth->phdr.pkt_encap = WTAP_ENCAP_RAW_IP;
	}
	else {
		g_message("iptrace: interface type %c%c unknown or unsupported",
		    if_name1, if_name2);
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}
	return data_offset;
}
