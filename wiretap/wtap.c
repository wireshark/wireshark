/* wtap.c
 *
 * $Id: wtap.c,v 1.5 1999/01/08 17:24:01 gram Exp $
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

FILE* wtap_file(wtap *wth)
{
	return wth->fh;
}

int wtap_file_type(wtap *wth)
{
	return wth->file_type;
}


int wtap_snapshot_length(wtap *wth)
{
	return wth->snapshot_length;
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

		default:
			/* nothing */
	}

	fclose(wth->fh);
}

void wtap_loop(wtap *wth, int count, wtap_handler callback, u_char* user)
{
	int i = 0;
	int data_offset;

	while ((data_offset = wth->subtype_read(wth)) > 0) {
		i++;
		/*g_message("Parsing packet %d", i);*/
		callback(user, &wth->phdr, data_offset,
		    buffer_start_ptr(&wth->frame_buffer));
	}
}
