/* file.c
 *
 * $Id: file.c,v 1.22 1999/09/23 04:39:00 ashokn Exp $
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
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include "file.h"
#include "wtap.h"
#include "buffer.h"
#include "lanalyzer.h"
#include "ngsniffer.h"
#include "radcom.h"
#include "ascend.h"
#include "libpcap.h"
#include "snoop.h"
#include "iptrace.h"
#include "netmon.h"
#include "netxray.h"

/* The open_file_* routines should return:
 *
 *	-1 on an I/O error;
 *
 *	1 if the file they're reading is one of the types it handles;
 *
 *	0 if the file they're reading isn't the type they're checking for.
 *
 * If the routine handles this type of file, it should set the "file_type"
 * field in the "struct wtap" to the type of the file.
 *
 * XXX - I need to drag my damn ANSI C spec in to figure out how to
 * declare a "const" array of pointers to functions; putting "const"
 * right after "static" isn't the right answer, at least according
 * to GCC, which whines if I do that.
 */

static int (*open_routines[])(wtap *, int *) = {
	libpcap_open,
	lanalyzer_open,
	ngsniffer_open,
	snoop_open,
	iptrace_open,
	netmon_open,
	netxray_open,
	radcom_open,
	ascend_open
};

int wtap_def_seek_read (FILE *fh, int seek_off, guint8 *pd, int len)
{
	file_seek(fh, seek_off, SEEK_SET);
	return file_read(pd, sizeof(guint8), len, fh);
}

#define	N_FILE_TYPES	(sizeof open_routines / sizeof open_routines[0])

/* Opens a file and prepares a wtap struct */
wtap* wtap_open_offline(const char *filename, int *err)
{
	struct stat statb;
	wtap	*wth;
	int	i;

	/* First, make sure the file is valid */
	if (stat(filename, &statb) < 0) {
		*err = errno;
		return NULL;
	}
#ifndef WIN32
	if (! S_ISREG(statb.st_mode) && ! S_ISFIFO(statb.st_mode)) {
		*err = WTAP_ERR_NOT_REGULAR_FILE;
		return NULL;
	}
#endif

	errno = ENOMEM;
	wth = (wtap*)malloc(sizeof(wtap));
	if (wth == NULL) {
		*err = errno;
		return NULL;
	}

	/* Open the file */
	errno = WTAP_ERR_CANT_OPEN;
	if (!(wth->fd = open(filename, O_RDONLY))) {
		*err = errno;
		free(wth);
		return NULL;
	}
	if (!(wth->fh = filed_open(wth->fd, "rb"))) {
		*err = errno;
		free(wth);
		return NULL;
	}

	/* initialization */
	wth->file_encap = WTAP_ENCAP_UNKNOWN;
	wth->data_offset = 0;

	/* Try all file types */
	for (i = 0; i < N_FILE_TYPES; i++) {
		switch ((*open_routines[i])(wth, err)) {

		case -1:
			/* I/O error - give up */
			*err = errno;
			file_close(wth->fh);
			close(wth->fd);
			free(wth);
			return NULL;

		case 0:
			/* No I/O error, but not that type of file */
			break;

		case 1:
			/* We found the file type */
			goto success;
		}
	}

	/* Well, it's not one of the types of file we know about. */
	file_close(wth->fh);
	free(wth);
	*err = WTAP_ERR_FILE_UNKNOWN_FORMAT;
	return NULL;

success:
	wth->frame_buffer = g_malloc(sizeof(struct Buffer));
	buffer_init(wth->frame_buffer, 1500);
	return wth;
}


static wtap_dumper* wtap_dump_open_common(FILE *fh, int filetype,
    int encap, int snaplen, int *err);

wtap_dumper* wtap_dump_open(const char *filename, int filetype, int encap,
				int snaplen, int *err)
{
	FILE *fh;

	/* In case "file_open()" fails but doesn't set "errno", set "errno"
	   to a generic "the open failed" error. */
	errno = WTAP_ERR_CANT_OPEN;
	fh = file_open(filename, "w");
	if (fh == NULL) {
		*err = errno;
		return NULL;	/* can't create file */
	}
	return wtap_dump_open_common(fh, filetype, encap, snaplen, err);
}

wtap_dumper* wtap_dump_fdopen(int fd, int filetype, int encap, int snaplen,
				int *err)
{
	FILE *fh;

	/* In case "file_open()" fails but doesn't set "errno", set "errno"
	   to a generic "the open failed" error. */
	errno = WTAP_ERR_CANT_OPEN;
	fh = filed_open(fd, "w");
	if (fh == NULL) {
		*err = errno;
		return NULL;	/* can't create standard I/O stream */
	}
	return wtap_dump_open_common(fh, filetype, encap, snaplen, err);
}

static wtap_dumper* wtap_dump_open_common(FILE *fh, int filetype, int encap,
					int snaplen, int *err)
{
	wtap_dumper *wdh;

	wdh = malloc(sizeof (wtap_dumper));
	if (wdh == NULL) {
		*err = errno;
		/* NOTE: this means the FD handed to "wtap_dump_fdopen()"
		   will be closed if the malloc fails. */
		file_close(fh);
		return NULL;
	}
	wdh->fh = fh;
	wdh->file_type = filetype;
	wdh->snaplen = snaplen;
	wdh->encap = encap;

	switch (filetype) {

	case WTAP_FILE_PCAP:
		if (!libpcap_dump_open(wdh, err))
			goto fail;
		break;

	default:
		/* We currently only support dumping "libpcap" files */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		goto fail;
	}
	return wdh;

fail:
	free(wdh);
	file_close(fh);
	return NULL;	/* XXX - provide a reason why we failed */
}

FILE* wtap_dump_file(wtap_dumper *wdh)
{
	return wdh->fh;
}

int wtap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const u_char *pd, int *err)
{
	return (wdh->subtype_write)(wdh, phdr, pd, err);
}

int wtap_dump_close(wtap_dumper *wdh, int *err)
{
	int ret = 1;

	if (!(wdh->subtype_close)(wdh, err))
		ret = 0;
	errno = WTAP_ERR_CANT_CLOSE;
	if (file_close(wdh->fh) == EOF) {
		if (ret) {
			/* The per-format close function succeeded,
			   but the file_close didn't.  Save the reason
			   why, if our caller asked for it. */
			if (err != NULL)
				*err = errno;
		}
		ret = 0;
	}
	free(wdh);
	return ret;
}

