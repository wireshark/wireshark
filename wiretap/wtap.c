/* wtap.c
 *
 * $Id: wtap.c,v 1.2 1998/11/12 06:01:26 gram Exp $
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

#include "wtap.h"

static
void pcap_callback_wrapper(u_char *user, const struct pcap_pkthdr *phdr,
		const u_char *buf);

wtap_handler wtap_callback = NULL;

FILE* wtap_file(wtap *wth)
{
	if (wth->file_type == WTAP_FILE_PCAP) {
		return pcap_file(wth->capture.pcap);
	}
	else
		return wth->fh;
}

int wtap_file_type(wtap *wth)
{
	return wth->file_type;
}

int wtap_encapsulation(wtap *wth)
{
	return wth->encapsulation;
}


int wtap_snapshot_length(wtap *wth)
{
	if (wth->file_type == WTAP_FILE_PCAP)
		return pcap_snapshot(wth->capture.pcap);
	else
		/* this is obviously *very* temporary :-) */
		return 5000;
}

void wtap_close(wtap *wth)
{
	if (wth->file_type == WTAP_FILE_PCAP)
		pcap_close(wth->capture.pcap);
	else
		fclose(wth->fh);
}

void wtap_loop(wtap *wth, int count, wtap_handler callback, u_char* user)
{
	int i = 0;

	if (wth->file_type == WTAP_FILE_PCAP) {
		wtap_callback = callback;
		pcap_loop(wth->capture.pcap, count, pcap_callback_wrapper, user);
	}
	else {
		/*while (ngsniffer_read(wth)) {*/
		while (wth->subtype_read(wth)) {
			i++;
			/*g_message("Parsing packet %d", i);*/
			callback(user, &wth->phdr, buffer_start_ptr(&wth->frame_buffer));
		}
	}
}

static
void pcap_callback_wrapper(u_char *user, const struct pcap_pkthdr *phdr,
		const u_char *buf)
{
/*	struct wtap_pkthdr whdr;
	memcpy(&whdr, phdr, sizeof(struct wtap_pkthdr));*/
	wtap_callback(user, (struct wtap_pkthdr*) phdr, buf);
}
