/* file.c
 *
 * $Id: file.c,v 1.46 2000/01/22 06:22:36 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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

#ifdef HAVE_IO_H
#include <io.h>	/* open/close on win32 */
#endif

#include "wtap.h"
#include "file_wrappers.h"
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
#include "i4btrace.h"

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
	i4btrace_open,
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

/* Table of the file types we know about. */
const static struct file_type_info {
	const char *name;
	const char *short_name;
	int	(*can_write_encap)(int, int);
	int	(*dump_open)(wtap_dumper *, int *);
} dump_open_table[WTAP_NUM_FILE_TYPES] = {
	/* WTAP_FILE_UNKNOWN */
	{ NULL, NULL,
	  NULL, NULL },

	/* WTAP_FILE_WTAP */
	{ "Wiretap (Ethereal)", NULL,
	  NULL, NULL },

	/* WTAP_FILE_PCAP */
	{ "libpcap (tcpdump, Ethereal, etc.)", "libpcap",
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_MODIFIED */
	{ "modified libpcap (tcpdump)", "modlibpcap",
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_RH_6_1 */
	{ "Red Hat Linux 6.1 libpcap (tcpdump)", "rh6_1libpcap",
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_LANALYZER */
	{ "Novell LANalyzer", NULL,
	  NULL, NULL },

	/* WTAP_FILE_NGSNIFFER */
	{ "Network Associates Sniffer (DOS-based)", "ngsniffer",
	  ngsniffer_dump_can_write_encap, ngsniffer_dump_open },

	/* WTAP_FILE_SNOOP */
	{ "Sun snoop", "snoop",
	  snoop_dump_can_write_encap, snoop_dump_open },

	/* WTAP_FILE_IPTRACE_1_0 */
	{ "AIX iptrace 1.0", NULL,
	  NULL, NULL },

	/* WTAP_FILE_IPTRACE_2_0 */
	{ "AIX iptrace 2.0", NULL,
	  NULL, NULL },

	/* WTAP_FILE_NETMON_1_x */
	{ "Microsoft Network Monitor 1.x", "netmon1",
	  netmon_dump_can_write_encap, netmon_dump_open },

	/* WTAP_FILE_NETMON_2_x */
	{ "Microsoft Network Monitor 2.x", NULL,
	  NULL, NULL },

	/* WTAP_FILE_NETXRAY_1_0 */
	{ "Cinco Networks NetXRay", NULL,
	  NULL, NULL },

	/* WTAP_FILE_NETXRAY_1_1 */
	{ "Network Associates Sniffer (Windows-based) 1.1", "ngwsniffer_1_1",
	  netxray_dump_can_write_encap, netxray_dump_open_1_1 },

	/* WTAP_FILE_NETXRAY_2_001 */
	{ "Network Associates Sniffer (Windows-based) 2.001", NULL,
	  NULL, NULL },

	/* WTAP_FILE_RADCOM */
	{ "RADCOM WAN/LAN analyzer", NULL,
	  NULL, NULL },

	/* WTAP_FILE_ASCEND */
	{ "Lucent/Ascend access server trace", NULL,
	  NULL, NULL },

	/* WTAP_FILE_NETTL */
	{ "HP-UX nettl trace", NULL,
	  NULL, NULL },

	/* WTAP_FILE_TOSHIBA */
	{ "Toshiba Compact ISDN Router snoop trace", NULL,
	  NULL, NULL },

	/* WTAP_FILE_I4BTRACE */
	{ "I4B ISDN trace", NULL,
	  NULL, NULL },

};

/* Name that should be somewhat descriptive. */
const char *wtap_file_type_string(int filetype)
{
	if (filetype < 0 || filetype >= WTAP_NUM_FILE_TYPES) {
		g_error("Unknown capture file type %d", filetype);
		return NULL;
	} else
		return dump_open_table[filetype].name;
}

/* Name to use in, say, a command-line flag specifying the type. */
const char *wtap_file_type_short_string(int filetype)
{
	if (filetype < 0 || filetype >= WTAP_NUM_FILE_TYPES)
		return NULL;
	else
		return dump_open_table[filetype].short_name;
}

/* Translate a short name to a capture file type. */
int wtap_short_string_to_file_type(const char *short_name)
{
	int filetype;

	for (filetype = 0; filetype < WTAP_NUM_FILE_TYPES; filetype++) {
		if (dump_open_table[filetype].short_name != NULL &&
		    strcmp(short_name, dump_open_table[filetype].short_name) == 0)
			return filetype;
	}
	return -1;	/* no such file type, or we can't write it */
}

gboolean wtap_dump_can_open(int filetype)
{
	if (filetype < 0 || filetype >= WTAP_NUM_FILE_TYPES
	    || dump_open_table[filetype].dump_open == NULL)
		return FALSE;

	return TRUE;
}

gboolean wtap_dump_can_write_encap(int filetype, int encap)
{
	if (filetype < 0 || filetype >= WTAP_NUM_FILE_TYPES
	    || dump_open_table[filetype].can_write_encap == NULL)
		return FALSE;

	if ((*dump_open_table[filetype].can_write_encap)(filetype, encap) != 0)
		return FALSE;

	return TRUE;
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

static wtap_dumper* wtap_dump_open_common(FILE *fh, int filetype, int encap,
					int snaplen, int *err)
{
	wtap_dumper *wdh;

	if (filetype < 0 || filetype >= WTAP_NUM_FILE_TYPES
	    || dump_open_table[filetype].dump_open == NULL) {
		/* Invalid type, or type we don't know how to write. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		/* NOTE: this means the FD handed to "wtap_dump_fdopen()"
		   will be closed if we can't write that file type. */
		fclose(fh);
		return NULL;
	}

	/* OK, we know how to write that type; can we write the specified
	   encapsulation type? */
	*err = (*dump_open_table[filetype].can_write_encap)(filetype, encap);
	if (*err != 0) {
		/* NOTE: this means the FD handed to "wtap_dump_fdopen()"
		   will be closed if we can't write that encapsulation type. */
		fclose(fh);
		return NULL;
	}

	/* OK, we can write the specified encapsulation type.  Allocate
	   a data structure for the output stream. */
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
	wdh->subtype_write = NULL;
	wdh->subtype_close = NULL;

	/* Now try to open the file for writing. */
	if (!(*dump_open_table[filetype].dump_open)(wdh, err)) {
		/* The attempt failed. */
		g_free(wdh);
		/* NOTE: this means the FD handed to "wtap_dump_fdopen()"
		   will be closed if the open fails. */
		fclose(fh);
		return NULL;
	}

	return wdh;	/* success! */
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

	if (wdh->subtype_close != NULL) {
		/* There's a close routine for this dump stream. */
		if (!(wdh->subtype_close)(wdh, err))
			ret = FALSE;
	}
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
