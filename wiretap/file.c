/* file.c
 *
 * $Id: file.c,v 1.5 1999/01/02 06:10:55 gram Exp $
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wtap.h"
#include "lanalyzer.h"
#include "ngsniffer.h"
#include "libpcap.h"
#include "snoop.h"
#include "iptrace.h"

/* The open_file_* routines should return the WTAP_FILE_* type
 * that they are checking for if the file is successfully recognized
 * as such. If the file is not of that type, the routine should return
 * WTAP_FILE_UNKNOWN */

/* Opens a file and prepares a wtap struct */
wtap* wtap_open_offline(char *filename, int filetype)
{
	wtap	*wth;

	wth = (wtap*)malloc(sizeof(wtap));

	/* Open the file */
	if (!(wth->fh = fopen(filename, "rb"))) {
		return NULL;
	}

	/* If the filetype is unknown, try all my file types */
	if (filetype == WTAP_FILE_UNKNOWN) {
		/* WTAP_FILE_PCAP */
		if ((wth->file_type = libpcap_open(wth)) != WTAP_FILE_UNKNOWN) {
			goto success;
		}
		/* WTAP_FILE_NGSNIFFER */
		if ((wth->file_type = ngsniffer_open(wth)) != WTAP_FILE_UNKNOWN) {
			goto success;
		}
		/* WTAP_FILE_LANALYZER */
		if ((wth->file_type = lanalyzer_open(wth)) != WTAP_FILE_UNKNOWN) {
			goto success;
		}
		/* WTAP_FILE_SNOOP */
		if ((wth->file_type = snoop_open(wth)) != WTAP_FILE_UNKNOWN) {
			goto success;
		}
		/* WTAP_FILE_IPTRACE */
		if ((wth->file_type = iptrace_open(wth)) != WTAP_FILE_UNKNOWN) {
			goto success;
		}

		printf("failed\n");
		/* WTAP_FILE_UNKNOWN */
		goto failure;
	}

	/* If the user tells us what the file is supposed to be, check it */
	switch (filetype) {
		case WTAP_FILE_PCAP:
			if ((wth->file_type = libpcap_open(wth)) != WTAP_FILE_UNKNOWN) {
				goto success;
			}
			break;
		case WTAP_FILE_NGSNIFFER:
			if ((wth->file_type = ngsniffer_open(wth)) != WTAP_FILE_UNKNOWN) {
				goto success;
			}
			break;
		case WTAP_FILE_LANALYZER:
			if ((wth->file_type = lanalyzer_open(wth)) != WTAP_FILE_UNKNOWN) {
				goto success;
			}
			break;
		case WTAP_FILE_SNOOP:
			if ((wth->file_type = snoop_open(wth)) != WTAP_FILE_UNKNOWN) {
				goto success;
			}
			break;
		case WTAP_FILE_IPTRACE:
			if ((wth->file_type = iptrace_open(wth)) != WTAP_FILE_UNKNOWN) {
				goto success;
			}
			break;
		default:
			goto failure;
	}

	/* If we made it through the switch() statement w/o going to "success",
	 * then we failed. */
	goto failure;

failure:
	fclose(wth->fh);
	free(wth);
	wth = NULL;
	return wth;

success:
	buffer_init(&wth->frame_buffer, 1500);
	wth->frame_number = 0;
	wth->file_byte_offset = 0;
	return wth;
}
