/* file.c
 *
 * $Id: file.c,v 1.2 1998/11/12 06:01:21 gram Exp $
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
#include "wtap.h"
#include "lanalyzer.h"
#include "ngsniffer.h"

/* The open_file_* routines should return the WTAP_FILE_* type
 * that they are checking for if the file is successfully recognized
 * as such. If the file is not of that type, the routine should return
 * WTAP_FILE_UNKNOWN */
static int open_file_pcap(wtap *wth, char *filename);
static int convert_dlt_to_wtap_encap(int dlt);

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
		if (wth->file_type = open_file_pcap(wth, filename)) {
			goto success;
		}
		/* WTAP_FILE_NGSNIFFER */
		if (wth->file_type = ngsniffer_open(wth)) {
			goto success;
		}
		/* WTAP_FILE_LANALYZER */
		if (wth->file_type = lanalyzer_open(wth)) {
			goto success;
		}

		printf("failed\n");
		/* WTAP_FILE_UNKNOWN */
		goto failure;
	}

	/* If the user tells us what the file is supposed to be, check it */
	switch (filetype) {
		case WTAP_FILE_PCAP:
			if (wth->file_type = open_file_pcap(wth, filename)) {
				goto success;
			}
			break;
		case WTAP_FILE_NGSNIFFER:
			if (wth->file_type = ngsniffer_open(wth)) {
				goto success;
			}
			break;
		case WTAP_FILE_LANALYZER:
			if (wth->file_type = lanalyzer_open(wth)) {
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


/* libpcap/tcpdump files */
static
int open_file_pcap(wtap *wth, char *filename)
{
	int bytes_read, dlt;
	struct pcap_file_header	file_hdr;

	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread((char*)&file_hdr, 1,
			sizeof(struct pcap_file_header), wth->fh);

	if (bytes_read != sizeof(struct pcap_file_header)) {
		return WTAP_FILE_UNKNOWN;
	}

	if (file_hdr.magic != 0xa1b2c3d4) {
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a pcap file */
	wth->capture.pcap = pcap_open_offline(filename, wth->err_str);
	dlt = pcap_datalink(wth->capture.pcap);
	wth->encapsulation =  convert_dlt_to_wtap_encap(dlt);
	wth->subtype_read = NULL;

	/* For most file types I don't fclose my handle, but for pcap I'm
	 * letting libpcap handle the file, so I don't need an open file
	 * handle. Libpcap already has the file open with the above
	 * pcap_open_offline() */
	fclose(wth->fh);

	return WTAP_FILE_PCAP;
}


static
int convert_dlt_to_wtap_encap(dlt)
{
	int encap[] = {
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_TR,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_SLIP,
		WTAP_ENCAP_PPP,
		WTAP_ENCAP_FDDI,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_RAW_IP,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE,
		WTAP_ENCAP_NONE
	};

	return encap[dlt];
}

