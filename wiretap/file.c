/* file.c
 *
 * $Id: file.c,v 1.32 1999/12/04 05:37:36 guy Exp $
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
#include "wtap.h"
#include "file.h"
#include "buffer.h"
#include "lanalyzer.h"
#include "ngsniffer.h"
#include "radcom.h"
#include "ascend.h"
#include "nettl.h"
#include "libpcap.h"
#include "snoop.h"
#include "iptrace.h"
#include "netmon.h"
#include "netxray.h"
#include "toshiba.h"

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
 *
 * Put the trace files that are merely saved telnet-sessions last, since it's
 * possible that you could have captured someone a router telnet-session
 * using another tool. So, a libpcap trace of an toshiba "snoop" session
 * should be discovered as a libpcap file, not a toshiba file.
 */

static int (*open_routines[])(wtap *, int *) = {
	/* Files that have magic bytes in fixed locations. These
	 * are easy to identify.
	 */
	libpcap_open,
	lanalyzer_open,
	ngsniffer_open,
	snoop_open,
	iptrace_open,
	netmon_open,
	netxray_open,
	radcom_open,
	nettl_open,

	/* Files whose magic headers are in text *somewhere* in the
	 * file (usually because the trace is just a saved copy of
	 * the telnet session). 
	 */
	ascend_open,
	toshiba_open,
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
	wth = g_malloc(sizeof(wtap));
	if (wth == NULL) {
		*err = errno;
		return NULL;
	}

	/* Open the file */
	errno = WTAP_ERR_CANT_OPEN;
	if (!(wth->fd = open(filename, O_RDONLY))) {
		*err = errno;
		g_free(wth);
		return NULL;
	}
	if (!(wth->fh = filed_open(wth->fd, "rb"))) {
		*err = errno;
		g_free(wth);
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
			file_close(wth->fh);
			g_free(wth);
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
	g_free(wth);
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

	/* In case "fopen()" fails but doesn't set "errno", set "errno"
	   to a generic "the open failed" error. */
	errno = WTAP_ERR_CANT_OPEN;
	fh = fopen(filename, "w");
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

	/* In case "fopen()" fails but doesn't set "errno", set "errno"
	   to a generic "the open failed" error. */
	errno = WTAP_ERR_CANT_OPEN;
	fh = fdopen(fd, "w");
	if (fh == NULL) {
		*err = errno;
		return NULL;	/* can't create standard I/O stream */
	}
	return wtap_dump_open_common(fh, filetype, encap, snaplen, err);
}

const static struct dump_type {
	guint	type;
	int	(*dump_open)(wtap_dumper *, int *);
} dump_open_table[] = {
	{ WTAP_FILE_PCAP,		libpcap_dump_open },
	{ WTAP_FILE_SNOOP,		snoop_dump_open },
	{ WTAP_FILE_NETMON_1_x,		netmon_dump_open },
	{ 0,				NULL }
};

static wtap_dumper* wtap_dump_open_common(FILE *fh, int filetype, int encap,
					int snaplen, int *err)
{
	wtap_dumper *wdh;
	const struct dump_type *dtp;

	wdh = g_malloc(sizeof (wtap_dumper));
	if (wdh == NULL) {
		*err = errno;
		/* NOTE: this means the FD handed to "wtap_dump_fdopen()"
		   will be closed if the malloc fails. */
		fclose(fh);
		return NULL;
	}
	wdh->fh = fh;
	wdh->file_type = filetype;
	wdh->snaplen = snaplen;
	wdh->encap = encap;

	wdh->private.opaque = NULL;
	for (dtp = &dump_open_table[0]; dtp->dump_open != NULL; dtp++) {
		if (filetype == dtp->type) {
			if (!(*dtp->dump_open)(wdh, err)) {
				/* The attempt failed. */
				g_free(wdh);
				fclose(fh);
				return NULL;
			}
			return wdh;	/* success! */
		}
	}

	*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
	g_free(wdh);
	fclose(fh);
	return NULL;
}

FILE* wtap_dump_file(wtap_dumper *wdh)
{
	return wdh->fh;
}

gboolean wtap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const u_char *pd, int *err)
{
	return (wdh->subtype_write)(wdh, phdr, pd, err);
}

gboolean wtap_dump_close(wtap_dumper *wdh, int *err)
{
	gboolean ret = TRUE;

	if (!(wdh->subtype_close)(wdh, err))
		ret = FALSE;
	errno = WTAP_ERR_CANT_CLOSE;
	if (fclose(wdh->fh) == EOF) {
		if (ret) {
			/* The per-format close function succeeded,
			   but the fclose didn't.  Save the reason
			   why, if our caller asked for it. */
			if (err != NULL)
				*err = errno;
		}
		ret = FALSE;
	}
	if (wdh->private.opaque != NULL)
		g_free(wdh->private.opaque);
	g_free(wdh);
	return ret;
}

/*
 * Routine to return a Wiretap error code (0 for no error, an errno
 * for a file error, or a WTAP_ERR_ code for other errors) for an
 * I/O stream.
 */
#ifdef HAVE_LIBZ
int
file_error(void *fh)
{
	int errnum;

	gzerror(fh, &errnum);
	switch (errnum) {

	case Z_OK:		/* no error */
		return 0;

	case Z_STREAM_END:	/* EOF - not an error */
		return 0;

	case Z_ERRNO:		/* file I/O error */
		return errno;

	default:
		return WTAP_ERR_ZLIB + errnum;
	}
}
#else /* HAVE_LIBZ */
int
file_error(FILE *fh)
{
	if (ferror(fh))
		return errno;
	else
		return 0;
}
#endif /* HAVE_LIBZ */
