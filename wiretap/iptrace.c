/* iptrace.c
 *
 * $Id: iptrace.c,v 1.2 1999/01/07 16:15:35 gram Exp $
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
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "wtap.h"
#include "iptrace.h"

int iptrace_open(wtap *wth)
{
	int bytes_read;
	char name[12];

	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(name, 1, 11, wth->fh);

	if (bytes_read != 11) {
		return WTAP_FILE_UNKNOWN;
	}
	name[11] = 0;
	if (strcmp(name, "iptrace 2.0") != 0) {
		return WTAP_FILE_UNKNOWN;
	}
	wth->subtype_read = iptrace_read;

	return WTAP_FILE_IPTRACE;
}

/* Read the next packet */
int iptrace_read(wtap *wth)
{
	int bytes_read;
	int data_offset;
	guint16 packet_size;
	guint8 header[40];
	char if_name1, if_name2;

	/* Read the descriptor data */
	bytes_read = fread(header, 1, 40, wth->fh);
	if (bytes_read != 40) {
		/* because of the way we have to kill the iptrace command,
		 * the existence of a partial header or packet is probable,
		 * and we should not complain about it. Simply return
		 * quietly and pretend that the trace file ended on
		 * a packet boundary
		 */
		return 0;
	}

	packet_size = pntohs(&header[2]) - 32;

	/* Read the packet data */
	buffer_assure_space(&wth->frame_buffer, packet_size);
	data_offset = ftell(wth->fh);
	bytes_read = fread(buffer_start_ptr(&wth->frame_buffer), 1,
		packet_size, wth->fh);

	if (bytes_read != packet_size) {
		/* don't complain about a partial packet. Just
		 * pretend that we reached the end of the file
		 * normally. If, however, there was a read error
		 * because of some other reason, complain
		 */
		if (ferror(wth->fh)) {
			g_print("iptrace_read: fread for data: read error\n");
		}
		return -1;
	}

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
		wth->phdr.pkt_encap = WTAP_ENCAP_FDDI;
	}
	else {
		wth->phdr.pkt_encap = WTAP_ENCAP_NONE;
	}
	return data_offset;
}
