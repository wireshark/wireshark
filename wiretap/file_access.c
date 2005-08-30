/* file_access.c
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_IO_H
#include <io.h>	/* open/close on win32 */
#endif

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "lanalyzer.h"
#include "airopeek9.h"
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
#include "eyesdn.h"
#include "i4btrace.h"
#include "csids.h"
#include "pppdump.h"
#include "etherpeek.h"
#include "vms.h"
#include "dbs-etherwatch.h"
#include "visual.h"
#include "cosine.h"
#include "5views.h"
#include "erf.h"
#include "hcidump.h"
#include "network_instruments.h"
#include "k12.h"

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
 * Put the trace files that are merely saved telnet-sessions last, since it's
 * possible that you could have captured someone a router telnet-session
 * using another tool. So, a libpcap trace of an toshiba "snoop" session
 * should be discovered as a libpcap file, not a toshiba file.
 */

static int (*const open_routines[])(wtap *, int *, char **) = {
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
	visual_open,
	_5views_open,
	network_instruments_open,
	airopeek9_open,
	dbs_etherwatch_open,
	k12_open,
	
	/* Files that don't have magic bytes at a fixed location,
	 * but that instead require a heuristic of some sort to
	 * identify them.  This includes the ASCII trace files that
	 * would be, for example, saved copies of a Telnet session
	 * to some box.
	 */
	etherpeek_open,
	pppdump_open,
	ascend_open,
	eyesdn_open,
	toshiba_open,
	i4btrace_open,
	csids_open,
	vms_open,
	cosine_open,
	erf_open,
	hcidump_open,
};

#define	N_FILE_TYPES	(sizeof open_routines / sizeof open_routines[0])

/*
 * Visual C++ on Win32 systems doesn't define these.  (Old UNIX systems don't
 * define them either.)
 *
 * Visual C++ on Win32 systems doesn't define S_IFIFO, it defines _S_IFIFO.
 */
#ifndef S_ISREG
#define S_ISREG(mode)   (((mode) & S_IFMT) == S_IFREG)
#endif
#ifndef S_IFIFO
#define S_IFIFO	_S_IFIFO
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(mode)  (((mode) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode)   (((mode) & S_IFMT) == S_IFDIR)
#endif

/* Opens a file and prepares a wtap struct.
   If "do_random" is TRUE, it opens the file twice; the second open
   allows the application to do random-access I/O without moving
   the seek offset for sequential I/O, which is used by Ethereal
   so that it can do sequential I/O to a capture file that's being
   written to as new packets arrive independently of random I/O done
   to display protocol trees for packets when they're selected. */
wtap* wtap_open_offline(const char *filename, int *err, char **err_info,
    gboolean do_random)
{
	struct stat statb;
	wtap	*wth;
	unsigned int	i;
	gboolean use_stdin = FALSE;

	/* open standard input if filename is '-' */
	if (strcmp(filename, "-") == 0)
		use_stdin = TRUE;

	/* First, make sure the file is valid */
	if (use_stdin) {
		if (fstat(0, &statb) < 0) {
			*err = errno;
			return NULL;
		}
	} else {
		if (stat(filename, &statb) < 0) {
			*err = errno;
			return NULL;
		}
	}
	if (S_ISFIFO(statb.st_mode)) {
		/*
		 * Opens of FIFOs are allowed only when not opening
		 * for random access.
		 *
		 * XXX - currently, we do seeking when trying to find
		 * out the file type, so we don't actually support
		 * opening FIFOs.  However, we may eventually
		 * do buffering that allows us to do at least some
		 * file type determination even on pipes, so we
		 * allow FIFO opens and let things fail later when
		 * we try to seek.
		 */
		if (do_random) {
			*err = WTAP_ERR_RANDOM_OPEN_PIPE;
			return NULL;
		}
	} else if (S_ISDIR(statb.st_mode)) {
		/*
		 * Return different errors for "this is a directory"
		 * and "this is some random special file type", so
		 * the user can get a potentially more helpful error.
		 */
		*err = EISDIR;
		return NULL;
	} else if (! S_ISREG(statb.st_mode)) {
		*err = WTAP_ERR_NOT_REGULAR_FILE;
		return NULL;
	}

	/*
	 * We need two independent descriptors for random access, so
	 * they have different file positions.  If we're opening the
	 * standard input, we can only dup it to get additional
	 * descriptors, so we can't have two independent descriptors,
	 * and thus can't do random access.
	 */
	if (use_stdin && do_random) {
		*err = WTAP_ERR_RANDOM_OPEN_STDIN;
		return NULL;
	}

	errno = ENOMEM;
	wth = g_malloc(sizeof(wtap));
	if (wth == NULL) {
		*err = errno;
		return NULL;
	}

/* Win32 needs the O_BINARY flag for open() */
#ifndef O_BINARY
#define O_BINARY	0
#endif

	/* Open the file */
	errno = WTAP_ERR_CANT_OPEN;
	if (use_stdin) {
		/*
		 * We dup FD 0, so that we don't have to worry about
		 * an fclose or gzclose of wth->fh closing the standard
		 * input of the process.
		 */
		wth->fd = dup(0);
#ifdef _WIN32
		_setmode(wth->fd, O_BINARY);
#endif
	} else
		wth->fd = open(filename, O_RDONLY|O_BINARY);
	if (wth->fd < 0) {
		*err = errno;
		g_free(wth);
		return NULL;
	}
	if (!(wth->fh = filed_open(wth->fd, "rb"))) {
		*err = errno;
		close(wth->fd);
		g_free(wth);
		return NULL;
	}

	if (do_random) {
		if (!(wth->random_fh = file_open(filename, "rb"))) {
			*err = errno;
			file_close(wth->fh);
			g_free(wth);
			return NULL;
		}
	} else
		wth->random_fh = NULL;

	/* initialization */
	wth->file_encap = WTAP_ENCAP_UNKNOWN;
	wth->data_offset = 0;
	wth->subtype_sequential_close = NULL;
	wth->subtype_close = NULL;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

	/* Try all file types */
	for (i = 0; i < N_FILE_TYPES; i++) {
		/* Seek back to the beginning of the file; the open routine
		   for the previous file type may have left the file
		   position somewhere other than the beginning, and the
		   open routine for this file type will probably want
		   to start reading at the beginning.

		   Initialize the data offset while we're at it. */
		if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
			/* I/O error - give up */
			if (wth->random_fh != NULL)
				file_close(wth->random_fh);
			file_close(wth->fh);
			g_free(wth);
			return NULL;
		}
		wth->data_offset = 0;
		
		switch ((*open_routines[i])(wth, err, err_info)) {

		case -1:
			/* I/O error - give up */
			if (wth->random_fh != NULL)
				file_close(wth->random_fh);
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
	if (wth->random_fh != NULL)
		file_close(wth->random_fh);
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
static const struct file_type_info {
	const char *name;
	const char *short_name;
	int	(*can_write_encap)(int);
	int	(*dump_open)(wtap_dumper *, gboolean, int *);
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

	/* WTAP_FILE_PCAP_SS990417 */
	{ "RedHat Linux 6.1 libpcap (tcpdump)", "rh6_1libpcap",
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_SS990915 */
	{ "SuSE Linux 6.3 libpcap (tcpdump)", "suse6_3libpcap",
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_SS991029 */
	{ "modified libpcap (tcpdump)", "modlibpcap",
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_NOKIA */
	{ "Nokia libpcap (tcpdump)", "nokialibpcap",
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_AIX */
	{ "AIX libpcap (tcpdump)", NULL,
	  NULL, NULL },

	/* WTAP_FILE_PCAP_NSEC */
	{ "Nanosecond libpcap (Ethereal)", "nseclibpcap",
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_LANALYZER */
	{ "Novell LANalyzer","lanalyzer",
	  lanalyzer_dump_can_write_encap, lanalyzer_dump_open },

	/* WTAP_FILE_NGSNIFFER_UNCOMPRESSED */
	{ "Network Associates Sniffer (DOS-based)", "ngsniffer",
	  ngsniffer_dump_can_write_encap, ngsniffer_dump_open },

	/* WTAP_FILE_NGSNIFFER_COMPRESSED */
	{ "Network Associates Sniffer (DOS-based), compressed", "ngsniffer_comp",
	  NULL, NULL },

	/* WTAP_FILE_SNOOP */
	{ "Sun snoop", "snoop",
	  snoop_dump_can_write_encap, snoop_dump_open },

	/* WTAP_FILE_SHOMITI */
	{ "Shomiti/Finisar Surveyor", "shomiti",
	  NULL, NULL },

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
	{ "Microsoft Network Monitor 2.x", "netmon2",
	  netmon_dump_can_write_encap, netmon_dump_open },

	/* WTAP_FILE_NETXRAY_OLD */
	{ "Cinco Networks NetXRay 1.x", NULL,
	  NULL, NULL },

	/* WTAP_FILE_NETXRAY_1_0 */
	{ "Cinco Networks NetXRay 2.0 or later", NULL,
	  NULL, NULL },

	/* WTAP_FILE_NETXRAY_1_1 */
	{ "Network Associates Sniffer (Windows-based) 1.1", "ngwsniffer_1_1",
	  netxray_dump_can_write_encap_1_1, netxray_dump_open_1_1 },

	/* WTAP_FILE_NETXRAY_2_00x */
	{ "Network Associates Sniffer (Windows-based) 2.00x", "ngwsniffer_2_0",
	  netxray_dump_can_write_encap_2_0, netxray_dump_open_2_0 },

	/* WTAP_FILE_RADCOM */
	{ "RADCOM WAN/LAN analyzer", NULL,
	  NULL, NULL },

	/* WTAP_FILE_ASCEND */
	{ "Lucent/Ascend access server trace", NULL,
	  NULL, NULL },

	/* WTAP_FILE_NETTL */
	{ "HP-UX nettl trace", "nettl",
	  nettl_dump_can_write_encap, nettl_dump_open },

	/* WTAP_FILE_TOSHIBA */
	{ "Toshiba Compact ISDN Router snoop trace", NULL,
	  NULL, NULL },

	/* WTAP_FILE_I4BTRACE */
	{ "I4B ISDN trace", NULL,
	  NULL, NULL },

        /* WTAP_FILE_CSIDS */
        { "CSIDS IPLog", NULL,
          NULL, NULL },

        /* WTAP_FILE_PPPDUMP */
        { "pppd log (pppdump format)", NULL,
          NULL, NULL },

	/* WTAP_FILE_ETHERPEEK_V56 */
	{ "EtherPeek/TokenPeek trace (V5 & V6 file format)", NULL,
	  NULL, NULL },

	/* WTAP_FILE_ETHERPEEK_V7 */
	{ "EtherPeek/TokenPeek/AiroPeek trace (V7 file format)", NULL,
	  NULL, NULL },

	/* WTAP_FILE_VMS */
	{ "TCPIPtrace (VMS)", NULL,
	  NULL, NULL},

	/* WTAP_FILE_DBS_ETHERWATCH */
	{ "DBS Etherwatch (VMS)", NULL,
	  NULL, NULL},

	/* WTAP_FILE_VISUAL_NETWORKS */
	{ "Visual Networks traffic capture", "visual",
	  visual_dump_can_write_encap, visual_dump_open },

	/* WTAP_FILE_COSINE */
	{ "CoSine IPSX L2 capture", "cosine",
	  NULL, NULL },

	/* WTAP_FILE_5VIEWS */
	{ "Accellent 5Views capture", "5views",
	  _5views_dump_can_write_encap, _5views_dump_open },

	/* WTAP_FILE_ERF */
	{ "Endace DAG capture", "erf",
	  NULL, NULL },

	/* WTAP_FILE_HCIDUMP */
	{ "Bluetooth HCI dump", "hcidump",
	  NULL, NULL },

	/* WTAP_FILE_NETWORK_INSTRUMENTS_V9 */
	{ "Network Instruments Observer version 9", "niobserverv9",
	  network_instruments_dump_can_write_encap, network_instruments_dump_open },

	/* WTAP_FILE_AIROPEEK_V9 */
	{ "EtherPeek/AiroPeek trace (V9 file format)", NULL,
	  NULL, NULL },
    
	/* WTAP_FILE_EYESDN */
	{ "EyeSDN USB S0/E1 ISDN trace format", NULL,
		NULL, NULL },
    
	/* WTAP_FILE_K12 */
	{ "Tektronix K12xx 32-bit .rf5 format", "rf5",
		k12_dump_can_write_encap, k12_dump_open },
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

	if ((*dump_open_table[filetype].can_write_encap)(encap) != 0)
		return FALSE;

	return TRUE;
}

static gboolean wtap_dump_open_check(int filetype, int encap, int *err);
static wtap_dumper* wtap_dump_alloc_wdh(int filetype, int encap, int snaplen,
    int *err);
static gboolean wtap_dump_open_finish(wtap_dumper *wdh, int filetype, int *err);

wtap_dumper* wtap_dump_open(const char *filename, int filetype, int encap,
				int snaplen, int *err)
{
	wtap_dumper *wdh;
	FILE *fh;

	/* Check whether we can open a capture file with that file type
	   and that encapsulation. */
	if (!wtap_dump_open_check(filetype, encap, err))
		return NULL;

	/* Allocate a data structure for the output stream. */
	wdh = wtap_dump_alloc_wdh(filetype, encap, snaplen, err);
	if (wdh == NULL)
		return NULL;	/* couldn't allocate it */

	/* Empty filename means stdout */
	if (*filename == '\0') {
#ifdef _WIN32
		setmode(fileno(stdout), O_BINARY);
#endif
		wdh->fh = stdout;
	} else {
		/* In case "fopen()" fails but doesn't set "errno", set "errno"
		   to a generic "the open failed" error. */
		errno = WTAP_ERR_CANT_OPEN;
		fh = fopen(filename, "wb");
		if (fh == NULL) {
			*err = errno;
			return NULL;	/* can't create file */
		}
		wdh->fh = fh;
	}

	if (!wtap_dump_open_finish(wdh, filetype, err)) {
		/* Get rid of the file we created; we couldn't finish
		   opening it. */
		if (wdh->fh != stdout)
			unlink(filename);
		return NULL;
	}
	return wdh;
}

wtap_dumper* wtap_dump_fdopen(int fd, int filetype, int encap, int snaplen,
				int *err)
{
	wtap_dumper *wdh;
	FILE *fh;

	/* Check whether we can open a capture file with that file type
	   and that encapsulation. */
	if (!wtap_dump_open_check(filetype, encap, err))
		return NULL;

	/* Allocate a data structure for the output stream. */
	wdh = wtap_dump_alloc_wdh(filetype, encap, snaplen, err);
	if (wdh == NULL)
		return NULL;	/* couldn't allocate it */

	/* In case "fopen()" fails but doesn't set "errno", set "errno"
	   to a generic "the open failed" error. */
	errno = WTAP_ERR_CANT_OPEN;
	fh = fdopen(fd, "wb");
	if (fh == NULL) {
		*err = errno;
		return NULL;	/* can't create standard I/O stream */
	}
	wdh->fh = fh;

	if (!wtap_dump_open_finish(wdh, filetype, err))
		return NULL;
	return wdh;
}

static gboolean wtap_dump_open_check(int filetype, int encap, int *err)
{
	if (!wtap_dump_can_open(filetype)) {
		/* Invalid type, or type we don't know how to write. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	/* OK, we know how to write that type; can we write the specified
	   encapsulation type? */
	*err = (*dump_open_table[filetype].can_write_encap)(encap);
	if (*err != 0)
		return FALSE;

	/* All systems go! */
	return TRUE;
}

static wtap_dumper* wtap_dump_alloc_wdh(int filetype, int encap, int snaplen,
					int *err)
{
	wtap_dumper *wdh;

	wdh = g_malloc(sizeof (wtap_dumper));
	if (wdh == NULL) {
		*err = errno;
		return NULL;
	}
	wdh->fh = NULL;
	wdh->file_type = filetype;
	wdh->snaplen = snaplen;
	wdh->encap = encap;
	wdh->bytes_dumped = 0;
	wdh->dump.opaque = NULL;
	wdh->subtype_write = NULL;
	wdh->subtype_close = NULL;
	return wdh;
}

static gboolean wtap_dump_open_finish(wtap_dumper *wdh, int filetype, int *err)
{
	int fd;
	gboolean cant_seek;

	/* Can we do a seek on the file descriptor?
	   If not, note that fact. */
	fd = fileno(wdh->fh);
	if (lseek(fd, 1, SEEK_CUR) == -1)
	  cant_seek = TRUE;
	else {
	  /* Undo the seek. */
	  lseek(fd, 0, SEEK_SET);
	  cant_seek = FALSE;
	}

	/* Now try to open the file for writing. */
	if (!(*dump_open_table[filetype].dump_open)(wdh, cant_seek, err)) {
		/* The attempt failed.  Close the stream for the file.
		   NOTE: this means the FD handed to "wtap_dump_fdopen()"
		   will be closed if the open fails. */
		if (wdh->fh != stdout)
			fclose(wdh->fh);

		/* Now free up the dumper handle. */
		g_free(wdh);
		return FALSE;
	}

	return TRUE;	/* success! */
}

FILE* wtap_dump_file(wtap_dumper *wdh)
{
	return wdh->fh;
}

gboolean wtap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err)
{
	return (wdh->subtype_write)(wdh, phdr, pseudo_header, pd, err);
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
	/* Don't close stdout */
	if (wdh->fh != stdout) {
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
	}
	if (wdh->dump.opaque != NULL)
		g_free(wdh->dump.opaque);
	g_free(wdh);
	return ret;
}

long wtap_get_bytes_dumped(wtap_dumper *wdh)
{
	return wdh->bytes_dumped;
}

void wtap_set_bytes_dumped(wtap_dumper *wdh, long bytes_dumped)
{
	wdh->bytes_dumped = bytes_dumped;
}

