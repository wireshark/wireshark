/* ngsniffer.c
 *
 * $Id: ngsniffer.c,v 1.2 1998/11/12 06:01:24 gram Exp $
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
#include "ngsniffer.h"

/* Returns WTAP_FILE_NGSNIFFER on success, WTAP_FILE_UNKNOWN on failure */
int ngsniffer_open(wtap *wth)
{
	int bytes_read;
	char magic[33];

	fseek(wth->fh, 0, SEEK_SET);
	bytes_read = fread(magic, 1, 32, wth->fh);

	if (bytes_read != 32) {
		return WTAP_FILE_UNKNOWN;
	}

	magic[16] = 0;

	if (strcmp(magic, "TRSNIFF data    ")) {
		return WTAP_FILE_UNKNOWN;
	}

	/* This is a ngsniffer file */
	wth->frame_number = 0;
	wth->file_byte_offset = 0x10b;
	wth->subtype_read = ngsniffer_read;

	/* I think this is link type */
	if (magic[30] == 0x25) {
		wth->encapsulation = WTAP_ENCAP_ETHERNET;
	}
	else if (magic[30] == 0x24) {
		wth->encapsulation = WTAP_ENCAP_TR;
	}
	else {
		g_error("The magic byte that I think tells DLT is 0x%02X\n", magic[30]);
		exit(-1);
	}

	if (fseek(wth->fh, 0x10b, SEEK_SET) < 0) {
		return WTAP_FILE_UNKNOWN; /* I should exit(-1) here */
	}
	return WTAP_FILE_NGSNIFFER;
}

/* Read the next packet */
int ngsniffer_read(wtap *wth)
{
	struct ngsniffer_hdr frame_hdr;
	int	bytes_read, packet_size;

	bytes_read = fread(&frame_hdr, 1, sizeof(struct ngsniffer_hdr), wth->fh);

	if (bytes_read == sizeof(struct ngsniffer_hdr)) {
		wth->frame_number++;
		packet_size = frame_hdr.bytes;
		buffer_assure_space(&wth->frame_buffer, packet_size);

		bytes_read = fread(buffer_start_ptr(&wth->frame_buffer), 1,
						frame_hdr.bytes, wth->fh);

		if (bytes_read != packet_size) {
			g_error("ngsniffer_read: fread for data: %d bytes out of %d read\n",
				bytes_read, packet_size);
			return 0;
		}

		wth->file_byte_offset += sizeof(struct ngsniffer_hdr) + packet_size;

		wth->phdr.ts.tv_sec = 0;
		wth->phdr.ts.tv_usec = 0;
		wth->phdr.caplen = packet_size;
		wth->phdr.len = packet_size;

		return 1;
	}

	return 0;
}
