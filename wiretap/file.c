/* file.c
 *
 * $Id: file.c,v 1.13 1999/08/15 06:59:13 guy Exp $
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include "wtap.h"
#include "buffer.h"
#include "lanalyzer.h"
#include "ngsniffer.h"
#include "radcom.h"
#include "libpcap.h"
#include "snoop.h"
#include "iptrace.h"
#include "netmon.h"
#include "netxray.h"

/* The open_file_* routines should return the WTAP_FILE_* type
 * that they are checking for if the file is successfully recognized
 * as such. If the file is not of that type, the routine should return
 * WTAP_FILE_UNKNOWN */

/* Opens a file and prepares a wtap struct */
wtap* wtap_open_offline(const char *filename, int *err)
{
	struct stat statb;
	wtap	*wth;

	/* First, make sure the file is valid */
	if (stat(filename, &statb)) {
		*err = errno;
		return NULL;
	}
#ifndef WIN32
	if (! S_ISREG(statb.st_mode) && ! S_ISFIFO(statb.st_mode)) {
		*err = WTAP_ERR_NOT_REGULAR_FILE;
		return NULL;
	}
#endif

	wth = (wtap*)malloc(sizeof(wtap));

	/* Open the file */
	if (!(wth->fh = fopen(filename, "rb"))) {
		*err = errno;
		free(wth);
		return NULL;
	}

	/* initialization */
	wth->file_encap = WTAP_ENCAP_NONE;

	/* Try all file types */

	/* WTAP_FILE_PCAP */
	if ((wth->file_type = libpcap_open(wth)) != WTAP_FILE_UNKNOWN) {
		goto success;
	}
	/* WTAP_FILE_NGSNIFFER */
	if ((wth->file_type = ngsniffer_open(wth)) != WTAP_FILE_UNKNOWN) {
		goto success;
	}
	/* WTAP_FILE_RADCOM */
	if ((wth->file_type = radcom_open(wth)) != WTAP_FILE_UNKNOWN) {
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
	/* WTAP_FILE_NETMON */
	if ((wth->file_type = netmon_open(wth)) != WTAP_FILE_UNKNOWN) {
		goto success;
	}
	/* WTAP_FILE_NETXRAY */
	if ((wth->file_type = netxray_open(wth)) != WTAP_FILE_UNKNOWN) {
		goto success;
	}


/* failure: */
	fclose(wth->fh);
	free(wth);
	*err = WTAP_ERR_FILE_UNKNOWN_FORMAT;
	return NULL;

success:
	wth->frame_buffer = g_malloc(sizeof(struct Buffer));
	buffer_init(wth->frame_buffer, 1500);
	return wth;
}
