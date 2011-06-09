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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#include <wsutil/file_util.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "lanalyzer.h"
#include "airopeek9.h"
#include "ngsniffer.h"
#include "radcom.h"
#include "ascendtext.h"
#include "nettl.h"
#include "libpcap.h"
#include "snoop.h"
#include "iptrace.h"
#include "iseries.h"
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
#include "ber.h"
#include "catapult_dct2000.h"
#include "mpeg.h"
#include "netscreen.h"
#include "commview.h"
#include "pcapng.h"
#include "btsnoop.h"
#include "tnef.h"
#include "dct3trace.h"
#include "packetlogger.h"
#include "daintree-sna.h"
#include "netscaler.h"
#include "mime_file.h"
#include "ipfix.h"


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


static wtap_open_routine_t open_routines_base[] = {
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
	catapult_dct2000_open,
	ber_open,
	pcapng_open,
	btsnoop_open,
	packetlogger_open, /* This type does not have a magic number, but its
			    * files are sometimes grabbed by mpeg_open. */
	mpeg_open,
	tnef_open,
	dct3trace_open,
	daintree_sna_open,
	mime_file_open,
	/* Files that don't have magic bytes at a fixed location,
	 * but that instead require a heuristic of some sort to
	 * identify them.  This includes the ASCII trace files that
	 * would be, for example, saved copies of a Telnet session
	 * to some box.
	 */

	/* I put NetScreen *before* erf, because there were some
	 * false positives with my test-files (Sake Blok, July 2007)
	 */
	netscreen_open,
	erf_open,
	ipfix_open,
	k12text_open,
	etherpeek_open,
	pppdump_open,
	iseries_open,
	ascend_open,
	eyesdn_open,
	toshiba_open,
	i4btrace_open,
	csids_open,
	vms_open,
	cosine_open,
	hcidump_open,
	commview_open,
	nstrace_open
};

#define	N_FILE_TYPES	(sizeof open_routines_base / sizeof open_routines_base[0])

static wtap_open_routine_t* open_routines = NULL;

static GArray* open_routines_arr = NULL;


/* initialize the open routines array if it has not been initialized yet */
static void init_open_routines(void) {

	if (open_routines_arr) return;

	open_routines_arr = g_array_new(FALSE,TRUE,sizeof(wtap_open_routine_t));

	g_array_append_vals(open_routines_arr,open_routines_base,N_FILE_TYPES);

	open_routines = (wtap_open_routine_t*)(void *)open_routines_arr->data;
}

void wtap_register_open_routine(wtap_open_routine_t open_routine, gboolean has_magic) {
	init_open_routines();

	if (has_magic)
		g_array_prepend_val(open_routines_arr,open_routine);
	else
		g_array_append_val(open_routines_arr,open_routine);

	open_routines = (wtap_open_routine_t*)(void *)open_routines_arr->data;
}

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
   the seek offset for sequential I/O, which is used by Wireshark
   so that it can do sequential I/O to a capture file that's being
   written to as new packets arrive independently of random I/O done
   to display protocol trees for packets when they're selected. */
wtap* wtap_open_offline(const char *filename, int *err, char **err_info,
			gboolean do_random)
{
	int	fd;
	ws_statb64 statb;
	wtap	*wth;
	unsigned int	i;
	gboolean use_stdin = FALSE;

	/* open standard input if filename is '-' */
	if (strcmp(filename, "-") == 0)
		use_stdin = TRUE;

	/* First, make sure the file is valid */
	if (use_stdin) {
		if (ws_fstat64(0, &statb) < 0) {
			*err = errno;
			return NULL;
		}
	} else {
		if (ws_stat64(filename, &statb) < 0) {
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
	wth = (wtap *)g_malloc0(sizeof(wtap));

	/* Open the file */
	errno = WTAP_ERR_CANT_OPEN;
	if (use_stdin) {
		/*
		 * We dup FD 0, so that we don't have to worry about
		 * a file_close of wth->fh closing the standard
		 * input of the process.
		 */
		fd = ws_dup(0);
		if (fd < 0) {
			*err = errno;
			g_free(wth);
			return NULL;
		}
#ifdef _WIN32
		if (_setmode(fd, O_BINARY) == -1) {
			/* "Shouldn't happen" */
			*err = errno;
			g_free(wth);
			return NULL;
		}
#endif
		if (!(wth->fh = filed_open(fd))) {
			*err = errno;
			ws_close(fd);
			g_free(wth);
			return NULL;
		}
	} else {
		if (!(wth->fh = file_open(filename))) {
			*err = errno;
			g_free(wth);
			return NULL;
		}
	}

	if (do_random) {
		if (!(wth->random_fh = file_open(filename))) {
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
	wth->priv = NULL;

	init_open_routines();
	if (wth->random_fh) {
		wth->fast_seek = g_ptr_array_new();

		file_set_random_access(wth->fh, FALSE, wth->fast_seek);
		file_set_random_access(wth->random_fh, TRUE, wth->fast_seek);
	}

	/* Try all file types */
	for (i = 0; i < open_routines_arr->len; i++) {
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
	wtap_close(wth);
	*err = WTAP_ERR_FILE_UNKNOWN_FORMAT;
	return NULL;

success:
	wth->frame_buffer = (struct Buffer *)g_malloc(sizeof(struct Buffer));
	buffer_init(wth->frame_buffer, 1500);
	return wth;
}

/* Table of the file types we know about. */
static const struct file_type_info dump_open_table_base[] = {
	/* WTAP_FILE_UNKNOWN (only used internally for initialization) */
	{ NULL, NULL, NULL, NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_WTAP (only used internally while capturing) */
	{ NULL, NULL, NULL, NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_PCAP */
	{ "Wireshark/tcpdump/... - libpcap", "libpcap", "*.pcap;*.cap", ".pcap", FALSE, FALSE,
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_NSEC */
	{ "Wireshark - nanosecond libpcap", "nseclibpcap", "*.pcap;*.cap", ".pcap", FALSE, FALSE,
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_AIX */
	{ "AIX tcpdump - libpcap", "aixlibpcap", "*.pcap;*.cap", ".pcap", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_PCAP_SS991029 */
	{ "Modified tcpdump - libpcap", "modlibpcap", "*.pcap;*.cap", ".pcap", FALSE, FALSE,
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_NOKIA */
	{ "Nokia tcpdump - libpcap ", "nokialibpcap", "*.pcap;*.cap", ".pcap", FALSE, FALSE,
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_SS990417 */
	{ "RedHat 6.1 tcpdump - libpcap", "rh6_1libpcap", "*.pcap;*.cap", ".pcap", FALSE, FALSE,
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_PCAP_SS990915 */
	{ "SuSE 6.3 tcpdump - libpcap", "suse6_3libpcap", "*.pcap;*.cap", ".pcap", FALSE, FALSE,
	  libpcap_dump_can_write_encap, libpcap_dump_open },

	/* WTAP_FILE_5VIEWS */
	{ "Accellent 5Views capture", "5views", "*.5vw", ".5vw", TRUE, FALSE,
	  _5views_dump_can_write_encap, _5views_dump_open },

	/* WTAP_FILE_IPTRACE_1_0 */
	{ "AIX iptrace 1.0", "iptrace_1", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_IPTRACE_2_0 */
	{ "AIX iptrace 2.0", "iptrace_2", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_BER */
	{ "ASN.1 Basic Encoding Rules", "ber", "*.*", NULL, FALSE, FALSE,
		NULL, NULL },

	/* WTAP_FILE_HCIDUMP */
	{ "Bluetooth HCI dump", "hcidump", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_CATAPULT_DCT2000 */
	{ "Catapult DCT2000 trace (.out format)", "dct2000", "*.out", ".out", FALSE, FALSE,
	  catapult_dct2000_dump_can_write_encap, catapult_dct2000_dump_open },

	/* WTAP_FILE_NETXRAY_OLD */
	{ "Cinco Networks NetXRay 1.x", "netxray1", "*.cap", ".cap", TRUE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_NETXRAY_1_0 */
	{ "Cinco Networks NetXRay 2.0 or later", "netxray2", "*.cap", ".cap", TRUE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_COSINE */
	{ "CoSine IPSX L2 capture", "cosine", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_CSIDS */
	{ "CSIDS IPLog", "csids", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_DBS_ETHERWATCH */
	{ "DBS Etherwatch (VMS)", "etherwatch", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL},

	/* WTAP_FILE_ERF */
	{ "Endace ERF capture", "erf", "*.erf", ".erf", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_EYESDN */
	{ "EyeSDN USB S0/E1 ISDN trace format", "eyesdn", "*.trc", ".trc", FALSE, FALSE,
	   eyesdn_dump_can_write_encap, eyesdn_dump_open },

	/* WTAP_FILE_NETTL */
	{ "HP-UX nettl trace", "nettl", "*.TRC0;*.TRC1", ".TRC0", FALSE, FALSE,
	  nettl_dump_can_write_encap, nettl_dump_open },

	/* WTAP_FILE_ISERIES */
	{ "IBM iSeries comm. trace (ASCII)", "iseries_ascii", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_ISERIES_UNICODE */
	{ "IBM iSeries comm. trace (UNICODE)", "iseries_unicode", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_I4BTRACE */
	{ "I4B ISDN trace", "i4btrace", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_ASCEND */
	{ "Lucent/Ascend access server trace", "ascend", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_NETMON_1_x */
	{ "Microsoft NetMon 1.x", "netmon1", "*.cap", ".cap", TRUE, FALSE,
	  netmon_dump_can_write_encap, netmon_dump_open },

	/* WTAP_FILE_NETMON_2_x */
	{ "Microsoft NetMon 2.x", "netmon2", "*.cap", ".cap", TRUE, FALSE,
	  netmon_dump_can_write_encap, netmon_dump_open },

	/* WTAP_FILE_NGSNIFFER_UNCOMPRESSED */
	{ "NA Sniffer (DOS)", "ngsniffer", "*.cap;*.enc;*.trc;*.fdc;*.syc", ".cap", FALSE, FALSE,
	  ngsniffer_dump_can_write_encap, ngsniffer_dump_open },

	/* WTAP_FILE_NGSNIFFER_COMPRESSED */
	{ "NA Sniffer (DOS), compressed", "ngsniffer_comp", "*.caz", ".caz", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_NETXRAY_1_1 */
	{ "NA Sniffer (Windows) 1.1", "ngwsniffer_1_1", "*.cap", ".cap", TRUE, FALSE,
	  netxray_dump_can_write_encap_1_1, netxray_dump_open_1_1 },

	/* WTAP_FILE_NETXRAY_2_00x */
	{ "NA Sniffer (Windows) 2.00x", "ngwsniffer_2_0", "*.cap", ".cap", TRUE, FALSE,
	  netxray_dump_can_write_encap_2_0, netxray_dump_open_2_0 },

	/* WTAP_FILE_NETWORK_INSTRUMENTS */
	{ "Network Instruments Observer", "niobserverv", "*.bfr", ".bfr", FALSE, FALSE,
	  network_instruments_dump_can_write_encap, network_instruments_dump_open },

	/* WTAP_FILE_LANALYZER */
	{ "Novell LANalyzer","lanalyzer", "*.tr1", ".tr1", TRUE, FALSE,
	  lanalyzer_dump_can_write_encap, lanalyzer_dump_open },

	/* WTAP_FILE_PPPDUMP */
	{ "pppd log (pppdump format)", "pppd", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_RADCOM */
	{ "RADCOM WAN/LAN analyzer", "radcom", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_SNOOP */
	{ "Sun snoop", "snoop", "*.snoop;*.cap", ".snoop", FALSE, FALSE,
	  snoop_dump_can_write_encap, snoop_dump_open },

	/* WTAP_FILE_SHOMITI */
	{ "Shomiti/Finisar Surveyor", "shomiti", "*.cap", ".cap", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_VMS */
	{ "TCPIPtrace (VMS)", "tcpiptrace", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL},

	/* WTAP_FILE_K12 */
	{ "Tektronix K12xx 32-bit .rf5 format", "rf5", "*.rf5", ".rf5", TRUE, FALSE,
		k12_dump_can_write_encap, k12_dump_open },

	/* WTAP_FILE_TOSHIBA */
	{ "Toshiba Compact ISDN Router snoop", "toshiba", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_VISUAL_NETWORKS */
	{ "Visual Networks traffic capture", "visual", "*.*", NULL, TRUE, FALSE,
	  visual_dump_can_write_encap, visual_dump_open },

	/* WTAP_FILE_ETHERPEEK_V56 */
	{ "WildPackets Ether/TokenPeek (V5 & V6)", "peek56", "*.tpc;*.apc;*.pkt;*.wpz", ".pkt", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_ETHERPEEK_V7 */
	{ "WildPackets Ether/Token/AiroPeek (V7)", "peek7", "*.tpc;*.apc;*.pkt;*.wpz", ".pkt", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_ETHERPEEK_V9 */
	{ "WildPackets Ether/AiroPeek (V9)", "peek9", "*.tpc;*.apc;*.pkt;*.wpz", ".pkt", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_MPEG */
	{ "MPEG", "mpeg", "*.mpeg;*.mpg;*.mp3", ".mpeg", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_K12TEXT  */
	{ "K12 text file", "k12text", "*.txt", ".txt", FALSE, FALSE,
	  k12text_dump_can_write_encap, k12text_dump_open },

	/* WTAP_FILE_NETSCREEN */
	{ "NetScreen snoop text file", "netscreen", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_COMMVIEW */
	{ "TamoSoft CommView", "commview", "*.ncf", ".ncf", FALSE, FALSE,
	  commview_dump_can_write_encap, commview_dump_open },

	/* WTAP_FILE_PCAPNG */
	{ "Wireshark - pcapng", "pcapng", "*.pcapng", NULL, FALSE, TRUE,
	  pcapng_dump_can_write_encap, pcapng_dump_open },

	/* WTAP_FILE_BTSNOOP */
	{ "Symbian OS btsnoop", "btsnoop", "*.log", ".log", FALSE, FALSE,
	  btsnoop_dump_can_write_encap, btsnoop_dump_open_h4 },

	/* WTAP_FILE_X2E_XORAYA */
	{ NULL, NULL, NULL, NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_TNEF */
	{ "Transport-Neutral Encapsulation Format", "tnef", "*.*", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_DCT3TRACE */
	{ "Gammu DCT3 trace", "dct3trace", "*.xml", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_PACKETLOGGER */
	{ "PacketLogger", "pklg", "*.pklg", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_DAINTREE_SNA */
	{ "Daintree SNA", "dsna", "*.dcf", NULL, FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_NETSCALER_1_0 */
	{ "NetScaler Trace (Version 1.0)", "nstrace10", "*.*", "*.*", TRUE, FALSE,
	  nstrace_10_dump_can_write_encap, nstrace_dump_open },

	/* WTAP_FILE_NETSCALER_2_0 */
	{ "NetScaler Trace (Version 2.0)", "nstrace20", "*.cap", "*.cap", TRUE, FALSE,
	  nstrace_20_dump_can_write_encap, nstrace_dump_open },

	/* WTAP_FILE_JPEG_JFIF */
	{ "JPEG/JFIF", "jpeg", "*.jpg;*.jpeg;*.jfif", ".jpg", FALSE, FALSE,
	  NULL, NULL },

	/* WTAP_FILE_IPFIX */
	{ "IPFIX File Format", "ipfix", "*.pfx;*.ipfix", NULL, FALSE, FALSE,
	  NULL, NULL }
};

gint wtap_num_file_types = sizeof(dump_open_table_base) / sizeof(struct file_type_info);

static GArray*  dump_open_table_arr = NULL;
static const struct file_type_info* dump_open_table = dump_open_table_base;

/* initialize the open routines array if it has not being initialized yet */
static void init_file_types(void) {

	if (dump_open_table_arr) return;

	dump_open_table_arr = g_array_new(FALSE,TRUE,sizeof(struct file_type_info));

	g_array_append_vals(dump_open_table_arr,dump_open_table_base,wtap_num_file_types);

	dump_open_table = (const struct file_type_info*)(void *)dump_open_table_arr->data;
}

int wtap_register_file_type(const struct file_type_info* fi) {
	init_file_types();

	g_array_append_val(dump_open_table_arr,*fi);

	dump_open_table = (const struct file_type_info*)(void *)dump_open_table_arr->data;

	return wtap_num_file_types++;
}

int wtap_get_num_file_types(void)
{
	return wtap_num_file_types;
}

/* Name that should be somewhat descriptive. */
const char *wtap_file_type_string(int filetype)
{
	if (filetype < 0 || filetype >= wtap_num_file_types) {
		g_error("Unknown capture file type %d", filetype);
		/** g_error() does an abort() and thus never returns **/
		return "";
	} else
		return dump_open_table[filetype].name;
}

/* Name to use in, say, a command-line flag specifying the type. */
const char *wtap_file_type_short_string(int filetype)
{
	if (filetype < 0 || filetype >= wtap_num_file_types)
		return NULL;
	else
		return dump_open_table[filetype].short_name;
}

/* Translate a short name to a capture file type. */
int wtap_short_string_to_file_type(const char *short_name)
{
	int filetype;

	for (filetype = 0; filetype < wtap_num_file_types; filetype++) {
		if (dump_open_table[filetype].short_name != NULL &&
		    strcmp(short_name, dump_open_table[filetype].short_name) == 0)
			return filetype;
	}
	return -1;	/* no such file type, or we can't write it */
}

/* file extensions to use. */
const char *wtap_file_extensions_string(int filetype)
{
	if (filetype < 0 || filetype >= wtap_num_file_types)
		return NULL;
	else
		return dump_open_table[filetype].file_extensions;
}

/* default file extension to use. */
const char *wtap_file_extension_default_string(int filetype)
{
	if (filetype < 0 || filetype >= wtap_num_file_types)
		return NULL;
	else
		return dump_open_table[filetype].file_extension_default;
}

gboolean wtap_dump_can_open(int filetype)
{
	if (filetype < 0 || filetype >= wtap_num_file_types
	    || dump_open_table[filetype].dump_open == NULL)
		return FALSE;

	return TRUE;
}

gboolean wtap_dump_can_write_encap(int filetype, int encap)
{
	if (filetype < 0 || filetype >= wtap_num_file_types
	    || dump_open_table[filetype].can_write_encap == NULL)
		return FALSE;

	if ((*dump_open_table[filetype].can_write_encap)(encap) != 0)
		return FALSE;

	return TRUE;
}

#ifdef HAVE_LIBZ
gboolean wtap_dump_can_compress(int filetype)
{
	/*
	 * If this is an unknown file type, or if we have to
	 * seek when writing out a file with this file type,
	 * return FALSE.
	 */
	if (filetype < 0 || filetype >= wtap_num_file_types
	    || dump_open_table[filetype].writing_must_seek)
		return FALSE;

	return TRUE;
}
#else
gboolean wtap_dump_can_compress(int filetype _U_)
{
	return FALSE;
}
#endif

gboolean wtap_dump_has_name_resolution(int filetype)
{
	if (filetype < 0 || filetype >= wtap_num_file_types
	    || dump_open_table[filetype].has_name_resolution == FALSE)
		return FALSE;

	return TRUE;
}

static gboolean wtap_dump_open_check(int filetype, int encap, gboolean comressed, int *err);
static wtap_dumper* wtap_dump_alloc_wdh(int filetype, int encap, int snaplen,
					gboolean compressed, int *err);
static gboolean wtap_dump_open_finish(wtap_dumper *wdh, int filetype, gboolean compressed, int *err);

static WFILE_T wtap_dump_file_open(wtap_dumper *wdh, const char *filename);
static WFILE_T wtap_dump_file_fdopen(wtap_dumper *wdh, int fd);
static int wtap_dump_file_close(wtap_dumper *wdh);

wtap_dumper* wtap_dump_open(const char *filename, int filetype, int encap,
				int snaplen, gboolean compressed, int *err)
{
	wtap_dumper *wdh;
	WFILE_T fh;

	/* Check whether we can open a capture file with that file type
	   and that encapsulation. */
	if (!wtap_dump_open_check(filetype, encap, compressed, err))
		return NULL;

	/* Allocate a data structure for the output stream. */
	wdh = wtap_dump_alloc_wdh(filetype, encap, snaplen, compressed, err);
	if (wdh == NULL)
		return NULL;	/* couldn't allocate it */

	/* "-" means stdout */
	if (strcmp(filename, "-") == 0) {
		if (compressed) {
			*err = EINVAL;	/* XXX - return a Wiretap error code for this */
			g_free(wdh);
			return NULL;	/* compress won't work on stdout */
		}
#ifdef _WIN32
		if (_setmode(fileno(stdout), O_BINARY) == -1) {
			/* "Should not happen" */
			*err = errno;
			g_free(wdh);
			return NULL;	/* couldn't put standard output in binary mode */
		}
#endif
		wdh->fh = stdout;
	} else {
		/* In case "fopen()" fails but doesn't set "errno", set "errno"
		   to a generic "the open failed" error. */
		errno = WTAP_ERR_CANT_OPEN;
		fh = wtap_dump_file_open(wdh, filename);
		if (fh == NULL) {
			*err = errno;
			g_free(wdh);
			return NULL;	/* can't create file */
		}
		wdh->fh = fh;
	}

	if (!wtap_dump_open_finish(wdh, filetype, compressed, err)) {
		/* Get rid of the file we created; we couldn't finish
		   opening it. */
		if (wdh->fh != stdout) {
			wtap_dump_file_close(wdh);
			ws_unlink(filename);
		}
		g_free(wdh);
		return NULL;
	}
	return wdh;
}

wtap_dumper* wtap_dump_fdopen(int fd, int filetype, int encap, int snaplen,
				gboolean compressed, int *err)
{
	wtap_dumper *wdh;
	WFILE_T fh;

	/* Check whether we can open a capture file with that file type
	   and that encapsulation. */
	if (!wtap_dump_open_check(filetype, encap, compressed, err))
		return NULL;

	/* Allocate a data structure for the output stream. */
	wdh = wtap_dump_alloc_wdh(filetype, encap, snaplen, compressed, err);
	if (wdh == NULL)
		return NULL;	/* couldn't allocate it */

#ifdef _WIN32
	if (fd == 1) {
		if (_setmode(fileno(stdout), O_BINARY) == -1) {
			/* "Should not happen" */
			*err = errno;
			g_free(wdh);
			return NULL;	/* couldn't put standard output in binary mode */
		}
	}
#endif

	/* In case "fopen()" fails but doesn't set "errno", set "errno"
	   to a generic "the open failed" error. */
	errno = WTAP_ERR_CANT_OPEN;
	fh = wtap_dump_file_fdopen(wdh, fd);
	if (fh == NULL) {
		*err = errno;
		g_free(wdh);
		return NULL;	/* can't create standard I/O stream */
	}
	wdh->fh = fh;

	if (!wtap_dump_open_finish(wdh, filetype, compressed, err)) {
		wtap_dump_file_close(wdh);
		g_free(wdh);
		return NULL;
	}
	return wdh;
}

static gboolean wtap_dump_open_check(int filetype, int encap, gboolean compressed, int *err)
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

	/* if compression is wanted, do we support this for this filetype? */
	if(compressed && !wtap_dump_can_compress(filetype)) {
		*err = WTAP_ERR_COMPRESSION_NOT_SUPPORTED;
		return FALSE;
	}

	*err = (*dump_open_table[filetype].can_write_encap)(encap);
	if (*err != 0)
		return FALSE;

	/* All systems go! */
	return TRUE;
}

static wtap_dumper* wtap_dump_alloc_wdh(int filetype, int encap, int snaplen,
					gboolean compressed, int *err)
{
	wtap_dumper *wdh;

	wdh = (wtap_dumper *)g_malloc0(sizeof (wtap_dumper));
	if (wdh == NULL) {
		*err = errno;
		return NULL;
	}

	wdh->file_type = filetype;
	wdh->snaplen = snaplen;
	wdh->encap = encap;
	wdh->compressed = compressed;
	return wdh;
}

static gboolean wtap_dump_open_finish(wtap_dumper *wdh, int filetype, gboolean compressed, int *err)
{
	int fd;
	gboolean cant_seek;

	/* Can we do a seek on the file descriptor?
	   If not, note that fact. */
	if(compressed) {
		cant_seek = TRUE;
	} else {
		fd = fileno((FILE *)wdh->fh);
		if (lseek(fd, 1, SEEK_CUR) == -1)
			cant_seek = TRUE;
		else {
			/* Undo the seek. */
			lseek(fd, 0, SEEK_SET);
			cant_seek = FALSE;
		}
	}

	/* If this file type requires seeking, and we can't seek, fail. */
	if (dump_open_table[filetype].writing_must_seek && cant_seek) {
		*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
		return FALSE;
	}

	/* Now try to open the file for writing. */
	if (!(*dump_open_table[filetype].dump_open)(wdh, err)) {
		return FALSE;
	}

	return TRUE;	/* success! */
}

gboolean wtap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
		   const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err)
{
	return (wdh->subtype_write)(wdh, phdr, pseudo_header, pd, err);
}

void wtap_dump_flush(wtap_dumper *wdh)
{
#ifdef HAVE_LIBZ
	if(wdh->compressed) {
		gzwfile_flush((GZWFILE_T)wdh->fh);
	} else
#endif
	{
		fflush((FILE *)wdh->fh);
	}
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
		if (wtap_dump_file_close(wdh) == EOF) {
			if (ret) {
				/* The per-format close function succeeded,
				   but the fclose didn't.  Save the reason
				   why, if our caller asked for it. */
				if (err != NULL)
					*err = errno;
			}
			ret = FALSE;
		}
	} else {
		/* as we don't close stdout, at least try to flush it */
		wtap_dump_flush(wdh);
	}
	if (wdh->priv != NULL)
		g_free(wdh->priv);
	g_free(wdh);
	return ret;
}

gint64 wtap_get_bytes_dumped(wtap_dumper *wdh)
{
	return wdh->bytes_dumped;
}

void wtap_set_bytes_dumped(wtap_dumper *wdh, gint64 bytes_dumped)
{
	wdh->bytes_dumped = bytes_dumped;
}

gboolean wtap_dump_set_addrinfo_list(wtap_dumper *wdh, struct addrinfo *addrinfo_list)
{
	if (!wdh || wdh->file_type < 0 || wdh->file_type >= wtap_num_file_types
		|| dump_open_table[wdh->file_type].has_name_resolution == FALSE)
			return FALSE;
	wdh->addrinfo_list = addrinfo_list;
	return TRUE;
}

/* internally open a file for writing (compressed or not) */
#ifdef HAVE_LIBZ
static WFILE_T wtap_dump_file_open(wtap_dumper *wdh, const char *filename)
{
	if(wdh->compressed) {
		return gzwfile_open(filename);
	} else {
		return ws_fopen(filename, "wb");
	}
}
#else
static WFILE_T wtap_dump_file_open(wtap_dumper *wdh _U_, const char *filename)
{
	return ws_fopen(filename, "wb");
}
#endif

/* internally open a file for writing (compressed or not) */
#ifdef HAVE_LIBZ
static WFILE_T wtap_dump_file_fdopen(wtap_dumper *wdh, int fd)
{
	if(wdh->compressed) {
		return gzwfile_fdopen(fd);
	} else {
		return fdopen(fd, "wb");
	}
}
#else
static WFILE_T wtap_dump_file_fdopen(wtap_dumper *wdh _U_, int fd)
{
	return fdopen(fd, "wb");
}
#endif

/* internally writing raw bytes (compressed or not) */
gboolean wtap_dump_file_write(wtap_dumper *wdh, const void *buf, size_t bufsize,
		     int *err)
{
	size_t nwritten;

#ifdef HAVE_LIBZ
	if (wdh->compressed) {
		nwritten = gzwfile_write((GZWFILE_T)wdh->fh, buf, (unsigned) bufsize);
		/*
		 * gzwfile_write() returns 0 on error.
		 */
		if (nwritten == 0) {
			*err = gzwfile_geterr((GZWFILE_T)wdh->fh);
			return FALSE;
		}
	} else
#endif
	{
		nwritten = fwrite(buf, 1, bufsize, (FILE *)wdh->fh);
		/*
		 * At least according to the Mac OS X man page,
		 * this can return a short count on an error.
		 */
		if (nwritten != bufsize) {
			if (ferror((FILE *)wdh->fh))
				*err = errno;
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
	}
	return TRUE;
}

/* internally close a file for writing (compressed or not) */
static int wtap_dump_file_close(wtap_dumper *wdh)
{
#ifdef HAVE_LIBZ
	if(wdh->compressed) {
		return gzwfile_close((GZWFILE_T)wdh->fh);
	} else
#endif
	{
		return fclose((FILE *)wdh->fh);
	}
}
