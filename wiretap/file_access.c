/* file_access.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

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
#include "peekclassic.h"
#include "peektagged.h"
#include "vms.h"
#include "dbs-etherwatch.h"
#include "visual.h"
#include "cosine.h"
#include "5views.h"
#include "erf.h"
#include "hcidump.h"
#include "logcat.h"
#include "network_instruments.h"
#include "k12.h"
#include "ber.h"
#include "catapult_dct2000.h"
#include "mp2t.h"
#include "mpeg.h"
#include "netscreen.h"
#include "commview.h"
#include "pcapng.h"
#include "aethra.h"
#include "btsnoop.h"
#include "tnef.h"
#include "dct3trace.h"
#include "packetlogger.h"
#include "daintree-sna.h"
#include "netscaler.h"
#include "mime_file.h"
#include "ipfix.h"
#include "vwr.h"
#include "camins.h"
#include "stanag4607.h"
#include "pcap-encap.h"

/*
 * Add an extension, and all compressed versions thereof, to a GSList
 * of extensions.
 */
static GSList *add_extensions(GSList *extensions, const gchar *extension,
    GSList *compressed_file_extensions)
{
	GSList *compressed_file_extension;

	/*
	 * Add the specified extension.
	 */
	extensions = g_slist_append(extensions, g_strdup(extension));

	/*
	 * Now add the extensions for compressed-file versions of
	 * that extension.
	 */
	for (compressed_file_extension = compressed_file_extensions;
	    compressed_file_extension != NULL;
	    compressed_file_extension = g_slist_next(compressed_file_extension)) {
		extensions = g_slist_append(extensions,
		    g_strdup_printf("%s.%s", extension,
		      (gchar *)compressed_file_extension->data));
	}

	return extensions;
}

/*
 * File types that can be identified by file extensions.
 */
static const struct file_extension_info file_type_extensions_base[] = {
	{ "Wireshark/tcpdump/... - pcap", "pcap;cap;dmp" },
	{ "Wireshark/... - pcapng", "pcapng;ntar" },
	{ "Network Monitor, Surveyor, NetScaler", "cap" },
	{ "InfoVista 5View capture", "5vw" },
	{ "Sniffer (DOS)", "cap;enc;trc;fdc;syc" },
	{ "NetXRay, Sniffer (Windows)", "cap;caz" },
	{ "Endace ERF capture", "erf" },
	{ "EyeSDN USB S0/E1 ISDN trace format", "trc" },
	{ "HP-UX nettl trace", "trc0;trc1" },
	{ "Network Instruments Observer", "bfr" },
	{ "Novell LANalyzer", "tr1" },
	{ "Tektronix K12xx 32-bit .rf5 format", "rf5" },
	{ "WildPackets *Peek", "pkt;tpc;apc;wpz" },
	{ "Catapult DCT2000 trace (.out format)", "out" },
	{ "MPEG files", "mpg;mp3" },
	{ "CommView", "ncf" },
	{ "Symbian OS btsnoop", "log" },
	{ "Transport-Neutral Encapsulation Format", "tnef" },
	{ "XML files (including Gammu DCT3 traces)", "xml" },
	{ "OS X PacketLogger", "pklg" },
	{ "Daintree SNA", "dcf" },
	{ "JPEG/JFIF files", "jpg;jpeg;jfif" },
	{ "IPFIX File Format", "pfx;ipfix" },
	{ "Aethra .aps file", "aps" },
	{ "MPEG2 transport stream", "mp2t;ts;mpg" },
	{ "Ixia IxVeriWave .vwr Raw 802.11 Capture", "vwr" },
	{ "CAM Inspector file", "camins" },
};

#define	N_FILE_TYPE_EXTENSIONS	(sizeof file_type_extensions_base / sizeof file_type_extensions_base[0])

static const struct file_extension_info* file_type_extensions = NULL;

static GArray* file_type_extensions_arr = NULL;

/* initialize the extensions array if it has not been initialized yet */
static void init_file_type_extensions(void) {

	if (file_type_extensions_arr) return;

	file_type_extensions_arr = g_array_new(FALSE,TRUE,sizeof(struct file_extension_info));

	g_array_append_vals(file_type_extensions_arr,file_type_extensions_base,N_FILE_TYPE_EXTENSIONS);

	file_type_extensions = (struct file_extension_info*)(void *)file_type_extensions_arr->data;
}

void wtap_register_file_type_extension(const struct file_extension_info *ei) {
	init_file_type_extensions();

	g_array_append_val(file_type_extensions_arr,*ei);

	file_type_extensions = (const struct file_extension_info*)(void *)file_type_extensions_arr->data;
}

int wtap_get_num_file_type_extensions(void)
{
	return file_type_extensions_arr->len;
}

const char *wtap_get_file_extension_type_name(int extension_type)
{
	return file_type_extensions[extension_type].name;
}

static GSList *add_extensions_for_file_extensions_type(int extension_type,
    GSList *extensions, GSList *compressed_file_extensions)
{
	gchar **extensions_set, **extensionp, *extension;

	/*
	 * Split the extension-list string into a set of extensions.
	 */
	extensions_set = g_strsplit(file_type_extensions[extension_type].extensions,
	    ";", 0);

	/*
	 * Add each of those extensions to the list.
	 */
	for (extensionp = extensions_set; *extensionp != NULL; extensionp++) {
		extension = *extensionp;

		/*
		 * Add the extension, and all compressed variants
		 * of it.
		 */
		extensions = add_extensions(extensions, extension,
		    compressed_file_extensions);
	}

	g_strfreev(extensions_set);
	return extensions;
}

/* Return a list of file extensions that are used by the specified file
   extension type.

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *wtap_get_file_extension_type_extensions(guint extension_type)
{
	GSList *compressed_file_extensions;
	GSList *extensions;

	if (extension_type >= file_type_extensions_arr->len)
		return NULL;	/* not a valid extension type */

	extensions = NULL;	/* empty list, to start with */

	/*
	 * Get the list of compressed-file extensions.
	 */
	compressed_file_extensions = wtap_get_compressed_file_extensions();

	/*
	 * Add all this file extension type's extensions, with compressed
	 * variants.
	 */
	extensions = add_extensions_for_file_extensions_type(extension_type,
	    extensions, compressed_file_extensions);

	g_slist_free(compressed_file_extensions);
	return extensions;
}

/* Return a list of all extensions that are used by all file types,
   including compressed extensions, e.g. not just "pcap" but also
   "pcap.gz" if we can read gzipped files.

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *wtap_get_all_file_extensions_list(void)
{
	GSList *compressed_file_extensions;
	GSList *extensions;
	unsigned int i;

	init_file_type_extensions();

	extensions = NULL;	/* empty list, to start with */

	/*
	 * Get the list of compressed-file extensions.
	 */
	compressed_file_extensions = wtap_get_compressed_file_extensions();

	for (i = 0; i < file_type_extensions_arr->len; i++) {
		/*
		 * Add all this file extension type's extensions, with
		 * compressed variants.
		 */
		extensions = add_extensions_for_file_extensions_type(i,
		    extensions, compressed_file_extensions);
	}

	g_slist_free(compressed_file_extensions);
	return extensions;
}

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
 * Note that the routine does not have to free the private data pointer on
 * error. The caller takes care of that by calling wtap_close on error.
 * (See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8518)
 *
 * However, the caller does have to free the private data pointer when
 * returning 0, since the next file type will be called and will likely
 * just overwrite the pointer.
 */

static struct open_info open_info_base[] = {
    { "Pcap",                        OPEN_INFO_MAGIC,     libpcap_open,             "pcap",     NULL, NULL },
    { "PcapNG",                      OPEN_INFO_MAGIC,     pcapng_open,              "pcapng",   NULL, NULL },
    { "NgSniffer",                   OPEN_INFO_MAGIC,     ngsniffer_open,           NULL,       NULL, NULL },
    { "Snoop",                       OPEN_INFO_MAGIC,     snoop_open,               NULL,       NULL, NULL },
    { "IP Trace",                    OPEN_INFO_MAGIC,     iptrace_open,             NULL,       NULL, NULL },
    { "Netmon",                      OPEN_INFO_MAGIC,     netmon_open,              NULL,       NULL, NULL },
    { "Netxray",                     OPEN_INFO_MAGIC,     netxray_open,             NULL,       NULL, NULL },
    { "Radcom",                      OPEN_INFO_MAGIC,     radcom_open,              NULL,       NULL, NULL },
    { "Nettl",                       OPEN_INFO_MAGIC,     nettl_open,               NULL,       NULL, NULL },
    { "Visual",                      OPEN_INFO_MAGIC,     visual_open,              NULL,       NULL, NULL },
    { "5 Views",                     OPEN_INFO_MAGIC,     _5views_open,             NULL,       NULL, NULL },
    { "Network Instruments",         OPEN_INFO_MAGIC,     network_instruments_open, NULL,       NULL, NULL },
    { "Peek Tagged",                 OPEN_INFO_MAGIC,     peektagged_open,          NULL,       NULL, NULL },
    { "DBS Etherwatch",              OPEN_INFO_MAGIC,     dbs_etherwatch_open,      NULL,       NULL, NULL },
    { "K12",                         OPEN_INFO_MAGIC,     k12_open,                 NULL,       NULL, NULL },
    { "Catapult DCT 2000",           OPEN_INFO_MAGIC,     catapult_dct2000_open,    NULL,       NULL, NULL },
    { "Aethra",                      OPEN_INFO_MAGIC,     aethra_open,              NULL,       NULL, NULL },
    { "BTSNOOP",                     OPEN_INFO_MAGIC,     btsnoop_open,             "log",      NULL, NULL },
    { "EYESDN",                      OPEN_INFO_MAGIC,     eyesdn_open,              NULL,       NULL, NULL },
    { "TNEF",                        OPEN_INFO_MAGIC,     tnef_open,                NULL,       NULL, NULL },
    { "MIME Files with Magic Bytes", OPEN_INFO_MAGIC,     mime_file_open,           NULL,       NULL, NULL },
    { "Lanalyzer",                   OPEN_INFO_HEURISTIC, lanalyzer_open,           "tr1",      NULL, NULL },
    /*
     * PacketLogger must come before MPEG, because its files
     * are sometimes grabbed by mpeg_open.
     */
    { "Packet Logger",               OPEN_INFO_HEURISTIC, packetlogger_open,        "pklg",     NULL, NULL },
    /* Some MPEG files have magic numbers, others just have heuristics. */
    { "Mpeg",                        OPEN_INFO_HEURISTIC, mpeg_open,                "mpg;mp3",  NULL, NULL },
    { "DCT3 Trace",                  OPEN_INFO_HEURISTIC, dct3trace_open,           "xml",      NULL, NULL },
    { "Daintree SNA",                OPEN_INFO_HEURISTIC, daintree_sna_open,        "dcf",      NULL, NULL },
    { "Stanag 4607",                 OPEN_INFO_HEURISTIC, stanag4607_open,          NULL,       NULL, NULL },
    { "BER",                         OPEN_INFO_HEURISTIC, ber_open,                 NULL,       NULL, NULL },
    /* I put NetScreen *before* erf, because there were some
     * false positives with my test-files (Sake Blok, July 2007)
     *
     * I put VWR *after* ERF, because there were some cases where
     * ERF files were misidentified as vwr files (Stephen
     * Donnelly, August 2013; see bug 9054)
     *
     * I put VWR *after* Peek Classic, CommView, iSeries text,
     * Toshiba text, K12 text, VMS tcpiptrace text, and NetScaler,
     * because there were some cases where files of those types were
     * misidentified as vwr files (Guy Harris, December 2013)
     */
    { "Netscreen",                   OPEN_INFO_HEURISTIC, netscreen_open,           "txt",      NULL, NULL },
    { "ERF",                         OPEN_INFO_HEURISTIC, erf_open,                 "erf",      NULL, NULL },
    { "IPfix",                       OPEN_INFO_HEURISTIC, ipfix_open,               "pfx;ipfix",NULL, NULL },
    { "K12 Text",                    OPEN_INFO_HEURISTIC, k12text_open,             "txt",      NULL, NULL },
    { "Peek Classic",                OPEN_INFO_HEURISTIC, peekclassic_open,         "pkt;tpc;apc;wpz", NULL, NULL },
    { "PPP Dump",                    OPEN_INFO_HEURISTIC, pppdump_open,             NULL,       NULL, NULL },
    { "iSeries",                     OPEN_INFO_HEURISTIC, iseries_open,             "txt",      NULL, NULL },
    { "i4btrace",                    OPEN_INFO_HEURISTIC, i4btrace_open,            NULL,       NULL, NULL },
    { "Mp2t",                        OPEN_INFO_HEURISTIC, mp2t_open,                "ts;mpg",   NULL, NULL },
    { "Csids",                       OPEN_INFO_HEURISTIC, csids_open,               NULL,       NULL, NULL },
    { "VMS",                         OPEN_INFO_HEURISTIC, vms_open,                 "txt",      NULL, NULL },
    { "Cosine",                      OPEN_INFO_HEURISTIC, cosine_open,              "txt",      NULL, NULL },
    { "Hcidump",                     OPEN_INFO_HEURISTIC, hcidump_open,             NULL,       NULL, NULL },
    { "Commview",                    OPEN_INFO_HEURISTIC, commview_open,            "ncf",      NULL, NULL },
    { "Nstrace",                     OPEN_INFO_HEURISTIC, nstrace_open,             "txt",      NULL, NULL },
    { "Logcat ",                     OPEN_INFO_HEURISTIC, logcat_open,              "logcat",   NULL, NULL },
    /* ASCII trace files from Telnet sessions. */
    { "Ascend",                      OPEN_INFO_HEURISTIC, ascend_open,              "txt",      NULL, NULL },
    { "Toshiba",                     OPEN_INFO_HEURISTIC, toshiba_open,             "txt",      NULL, NULL },
    /* Extremely weak heuristics - put them at the end. */
    { "VWR",                         OPEN_INFO_HEURISTIC, vwr_open,                 "vwr",      NULL, NULL },
    { "Camins",                      OPEN_INFO_HEURISTIC, camins_open,              "camins",   NULL, NULL },
};

/* this is only used to build the dynamic array on load, do NOT use this
 * for anything else, because the size of the actual array will change if
 *  Lua scripts register a new file reader.
 */
#define N_OPEN_INFO_ROUTINES  ((sizeof open_info_base / sizeof open_info_base[0]))

static GArray *open_info_arr = NULL;

/* this always points to the top of the created array */
struct open_info *open_routines = NULL;

/* this points to the first OPEN_INFO_HEURISTIC type in the array */
static guint heuristic_open_routine_idx = 0;

static void set_heuristic_routine(void) {
	guint i;
	g_assert(open_info_arr != NULL);

	for (i = 0; i < open_info_arr->len; i++) {
		if (open_routines[i].type == OPEN_INFO_HEURISTIC) {
			heuristic_open_routine_idx = i;
			break;
		}
		/* sanity check */
		g_assert(open_routines[i].type == OPEN_INFO_MAGIC);
	}

	g_assert(heuristic_open_routine_idx > 0);
}

void init_open_routines(void) {
    unsigned int i;
    struct open_info *i_open;

    if (open_info_arr)
        return;

    open_info_arr = g_array_new(TRUE,TRUE,sizeof(struct open_info));

    g_array_append_vals(open_info_arr, open_info_base, N_OPEN_INFO_ROUTINES);

    open_routines = (struct open_info *)(void*) open_info_arr->data;

    /* Populate the extensions_set list now */
    for (i = 0, i_open = open_routines; i < open_info_arr->len; i++, i_open++) {
        if (i_open->extensions != NULL)
            i_open->extensions_set = g_strsplit(i_open->extensions, ";", 0);
    }

    set_heuristic_routine();
}

/* Registers a new file reader - currently only called by wslua code for Lua readers.
 * If first_routine is true, it's added before other readers of its type (magic or heuristic).
 * Also, it checks for an existing reader of the same name and errors if it finds one; if
 * you want to handle that condition more gracefully, call wtap_has_open_info() first.
 */
void wtap_register_open_info(struct open_info *oi, const gboolean first_routine) {
    init_open_routines();

    if (!oi || !oi->name) {
        g_error("No open_info name given to register");
        return;
    }

    /* verify name doesn't already exist */
    if (wtap_has_open_info(oi->name)) {
        g_error("Name given to register_open_info already exists");
        return;
    }

    if (oi->extensions != NULL)
        oi->extensions_set = g_strsplit(oi->extensions, ";", 0);

    /* if it's magic and first, prepend it; if it's heuristic and not first,
       append it; if it's anything else, stick it in the middle */
    if (first_routine && oi->type == OPEN_INFO_MAGIC) {
        g_array_prepend_val(open_info_arr, *oi);
    } else if (!first_routine && oi->type == OPEN_INFO_HEURISTIC) {
        g_array_append_val(open_info_arr, *oi);
    } else {
        g_array_insert_val(open_info_arr, heuristic_open_routine_idx, *oi);
    }

    open_routines = (struct open_info *)(void*) open_info_arr->data;
    set_heuristic_routine();
}

/* De-registers a file reader by removign it from the GArray based on its name.
 * This function must NOT be called during wtap_open_offline(), since it changes the array.
 * Note: this function will error if it doesn't find the given name; if you want to handle
 * that condition more gracefully, call wtap_has_open_info() first.
 */
void wtap_deregister_open_info(const gchar *name) {
    guint i;
    init_open_routines();

    if (!name) {
        g_error("Missing open_info name to de-register");
        return;
    }

    for (i = 0; i < open_info_arr->len; i++) {
        if (open_routines[i].name && strcmp(open_routines[i].name, name) == 0) {
            if (open_routines[i].extensions_set != NULL)
                g_strfreev(open_routines[i].extensions_set);
            open_info_arr = g_array_remove_index(open_info_arr, i);
            set_heuristic_routine();
            return;
        }
    }

    g_error("deregister_open_info: name not found");
}

/* Determines if a open routine short name already exists
 */
gboolean wtap_has_open_info(const gchar *name) {
    guint i;
    init_open_routines();

    if (!name) {
        g_error("No name given to wtap_has_open_info!");
        return FALSE;
    }


    for (i = 0; i < open_info_arr->len; i++) {
        if (open_routines[i].name && strcmp(open_routines[i].name, name) == 0) {
            return TRUE;
        }
    }

    return FALSE;
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

/* returns the 'type' number to use for wtap_open_offline based on the
   passed-in name (the name in the open_info struct). It returns WTAP_TYPE_AUTO
   on failure, which is the number 0. The 'type' number is the entry's index+1,
   because that's what wtap_open_offline() expects it to be. */
unsigned int open_info_name_to_type(const char *name)
{
	unsigned int i;
	init_open_routines();

	if (!name)
		return WTAP_TYPE_AUTO;

	for (i = 0; i < open_info_arr->len; i++) {
		if (open_routines[i].name != NULL &&
			strcmp(name, open_routines[i].name) == 0)
			return i+1;
	}

	return WTAP_TYPE_AUTO; /* no such file type */
}

static char *get_file_extension(const char *pathname)
{
	gchar *filename;
	gchar **components;
	size_t ncomponents;
	GSList *compressed_file_extensions, *compressed_file_extension;
	gchar *extensionp;

	/*
	 * Is the pathname empty?
	 */
	if (strcmp(pathname, "") == 0)
		return NULL;	/* no extension */

	/*
	 * Find the last component of the pathname.
	 */
	filename = g_path_get_basename(pathname);

	/*
	 * Does it have an extension?
	 */
	if (strchr(filename, '.') == NULL) {
		g_free(filename);
		return NULL;	/* no extension whatsoever */
	}

	/*
	 * Yes.  Split it into components separated by ".".
	 */
	components = g_strsplit(filename, ".", 0);
	g_free(filename);

	/*
	 * Count the components.
	 */
	for (ncomponents = 0; components[ncomponents] != NULL; ncomponents++)
		;

	if (ncomponents == 0) {
		g_strfreev(components);
		return NULL;	/* no components */
	}
	if (ncomponents == 1) {
		g_strfreev(components);
		return NULL;	/* only one component, with no "." */
	}

	/*
	 * Is the last component one of the extensions used for compressed
	 * files?
	 */
	compressed_file_extensions = wtap_get_compressed_file_extensions();
	if (compressed_file_extensions == NULL) {
		/*
		 * We don't support reading compressed files, so just
		 * return a copy of whatever extension we did find.
		 */
		extensionp = g_strdup(components[ncomponents - 1]);
		g_strfreev(components);
		return extensionp;
	}
	extensionp = components[ncomponents - 1];
	for (compressed_file_extension = compressed_file_extensions;
	    compressed_file_extension != NULL;
	    compressed_file_extension = g_slist_next(compressed_file_extension)) {
		if (strcmp(extensionp, (char *)compressed_file_extension->data) == 0) {
			/*
			 * Yes, it's one of the compressed-file extensions.
			 * Is there an extension before that?
			 */
			if (ncomponents == 2) {
				g_strfreev(components);
				return NULL;	/* no, only two components */
			}

			/*
			 * Yes, return that extension.
			 */
			extensionp = g_strdup(components[ncomponents - 2]);
			g_strfreev(components);
			return extensionp;
		}
	}

	/*
	 * The extension isn't one of the compressed-file extensions;
	 * return it.
	 */
	extensionp = g_strdup(extensionp);
	g_strfreev(components);
	return extensionp;
}

/*
 * Check if file extension is used in this heuristic
 */
static gboolean heuristic_uses_extension(unsigned int i, const char *extension)
{
	gchar **extensionp;

	/*
	 * Does this file type *have* any extensions?
	 */
	if (open_routines[i].extensions == NULL)
		return FALSE;	/* no */

	/*
	 * Check each of them against the specified extension.
	 */
	for (extensionp = open_routines[i].extensions_set; *extensionp != NULL;
	    extensionp++) {
		if (strcmp(extension, *extensionp) == 0) {
			return TRUE;	/* it's one of them */
		}
	}

	return FALSE;	/* it's not one of them */
}

/* Opens a file and prepares a wtap struct.
   If "do_random" is TRUE, it opens the file twice; the second open
   allows the application to do random-access I/O without moving
   the seek offset for sequential I/O, which is used by Wireshark
   so that it can do sequential I/O to a capture file that's being
   written to as new packets arrive independently of random I/O done
   to display protocol trees for packets when they're selected. */
wtap* wtap_open_offline(const char *filename, unsigned int type, int *err, char **err_info,
			gboolean do_random)
{
	int	fd;
	ws_statb64 statb;
	wtap	*wth;
	unsigned int	i;
	gboolean use_stdin = FALSE;
	gchar *extension;

	init_open_routines();

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
		if (!(wth->fh = file_fdopen(fd))) {
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
	wth->subtype_sequential_close = NULL;
	wth->subtype_close = NULL;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;
	wth->priv = NULL;
	wth->wslua_data = NULL;

	/* Initialize the array containing a list of interfaces. pcapng_open and
	 * erf_open needs this (and libpcap_open for ERF encapsulation types).
	 * Always initing it here saves checking for a NULL ptr later. */
	wth->interface_data = g_array_new(FALSE, FALSE, sizeof(wtapng_if_descr_t));

	if (wth->random_fh) {
		wth->fast_seek = g_ptr_array_new();

		file_set_random_access(wth->fh, FALSE, wth->fast_seek);
		file_set_random_access(wth->random_fh, TRUE, wth->fast_seek);
	}

	/* 'type' is 1 greater than the array index */
	if (type != WTAP_TYPE_AUTO && type <= open_info_arr->len) {
		int result;

		if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
			/* I/O error - give up */
			wtap_close(wth);
			return NULL;
		}

		/* Set wth with wslua data if any - this is how we pass the data
		 * to the file reader, kinda like the priv member but not free'd later.
		 * It's ok for this to copy a NULL.
		 */
		wth->wslua_data = open_routines[type - 1].wslua_data;

		result = (*open_routines[type - 1].open_routine)(wth, err, err_info);

		switch (result) {
			case -1:
				/* I/O error - give up */
				wtap_close(wth);
				return NULL;

			case 0:
				/* No I/O error, but not that type of file */
				goto fail;

			case 1:
				/* We found the file type */
				goto success;
		}
	}

	/* Try all file types that support magic numbers */
	for (i = 0; i < heuristic_open_routine_idx; i++) {
		/* Seek back to the beginning of the file; the open routine
		   for the previous file type may have left the file
		   position somewhere other than the beginning, and the
		   open routine for this file type will probably want
		   to start reading at the beginning.

		   Initialize the data offset while we're at it. */
		if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
			/* I/O error - give up */
			wtap_close(wth);
			return NULL;
		}

		/* Set wth with wslua data if any - this is how we pass the data
		 * to the file reader, kinda like the priv member but not free'd later.
		 * It's ok for this to copy a NULL.
		 */
		wth->wslua_data = open_routines[i].wslua_data;

		switch ((*open_routines[i].open_routine)(wth, err, err_info)) {

		case -1:
			/* I/O error - give up */
			wtap_close(wth);
			return NULL;

		case 0:
			/* No I/O error, but not that type of file */
			break;

		case 1:
			/* We found the file type */
			goto success;
		}
	}


	/* Does this file's name have an extension? */
	extension = get_file_extension(filename);
	if (extension != NULL) {
		/* Yes - try the heuristic types that use that extension first. */
		for (i = heuristic_open_routine_idx; i < open_info_arr->len; i++) {
			/* Does this type use that extension? */
			if (heuristic_uses_extension(i, extension)) {
				/* Yes. */
				if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
					/* I/O error - give up */
					g_free(extension);
					wtap_close(wth);
					return NULL;
				}

				/* Set wth with wslua data if any - this is how we pass the data
				 * to the file reader, kind of like priv but not free'd later.
				 */
				wth->wslua_data = open_routines[i].wslua_data;

				switch ((*open_routines[i].open_routine)(wth,
				    err, err_info)) {

				case -1:
					/* I/O error - give up */
					g_free(extension);
					wtap_close(wth);
					return NULL;

				case 0:
					/* No I/O error, but not that type of file */
					break;

				case 1:
					/* We found the file type */
					g_free(extension);
					goto success;
				}
			}
		}

		/* Now try the ones that don't use it. */
		for (i = heuristic_open_routine_idx; i < open_info_arr->len; i++) {
			/* Does this type use that extension? */
			if (!heuristic_uses_extension(i, extension)) {
				/* No. */
				if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
					/* I/O error - give up */
					g_free(extension);
					wtap_close(wth);
					return NULL;
				}

				/* Set wth with wslua data if any - this is how we pass the data
				 * to the file reader, kind of like priv but not free'd later.
				 */
				wth->wslua_data = open_routines[i].wslua_data;

				switch ((*open_routines[i].open_routine)(wth,
				    err, err_info)) {

				case -1:
					/* I/O error - give up */
					g_free(extension);
					wtap_close(wth);
					return NULL;

				case 0:
					/* No I/O error, but not that type of file */
					break;

				case 1:
					/* We found the file type */
					g_free(extension);
					goto success;
				}
			}
		}
		g_free(extension);
	} else {
		/* No - try all the heuristics types in order. */
		for (i = heuristic_open_routine_idx; i < open_info_arr->len; i++) {

			if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
				/* I/O error - give up */
				wtap_close(wth);
				return NULL;
			}

			/* Set wth with wslua data if any - this is how we pass the data
			 * to the file reader, kind of like priv but not free'd later.
			 */
			wth->wslua_data = open_routines[i].wslua_data;

			switch ((*open_routines[i].open_routine)(wth, err, err_info)) {

			case -1:
				/* I/O error - give up */
				wtap_close(wth);
				return NULL;

			case 0:
				/* No I/O error, but not that type of file */
				break;

			case 1:
				/* We found the file type */
				goto success;
			}
		}
	}

fail:

	/* Well, it's not one of the types of file we know about. */
	wtap_close(wth);
	*err = WTAP_ERR_FILE_UNKNOWN_FORMAT;
	return NULL;

success:
	wth->frame_buffer = (struct Buffer *)g_malloc(sizeof(struct Buffer));
	buffer_init(wth->frame_buffer, 1500);

	if(wth->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_PCAP){

		wtapng_if_descr_t descr;

		descr.wtap_encap = wth->file_encap;
		descr.time_units_per_second = 1000000; /* default microsecond resolution */
		descr.link_type = wtap_wtap_encap_to_pcap_encap(wth->file_encap);
		descr.snap_len = wth->snapshot_length;
		descr.opt_comment = NULL;
		descr.if_name = NULL;
		descr.if_description = NULL;
		descr.if_speed = 0;
		descr.if_tsresol = 6;
		descr.if_filter_str= NULL;
		descr.bpf_filter_len= 0;
		descr.if_filter_bpf_bytes= NULL;
		descr.if_os = NULL;
		descr.if_fcslen = -1;
		descr.num_stat_entries = 0;          /* Number of ISB:s */
		descr.interface_statistics = NULL;
		g_array_append_val(wth->interface_data, descr);

	}
	return wth;
}

/*
 * Given the pathname of the file we just closed with wtap_fdclose(), attempt
 * to reopen that file and assign the new file descriptor(s) to the sequential
 * stream and, if do_random is TRUE, to the random stream.  Used on Windows
 * after the rename of a file we had open was done or if the rename of a
 * file on top of a file we had open failed.
 *
 * This is only required by Wireshark, not TShark, and, at the point that
 * Wireshark is doing this, the sequential stream is closed, and the
 * random stream is open, so this refuses to open pipes, and only
 * reopens the random stream.
 */
gboolean
wtap_fdreopen(wtap *wth, const char *filename, int *err)
{
	ws_statb64 statb;

	/*
	 * We need two independent descriptors for random access, so
	 * they have different file positions.  If we're opening the
	 * standard input, we can only dup it to get additional
	 * descriptors, so we can't have two independent descriptors,
	 * and thus can't do random access.
	 */
	if (strcmp(filename, "-") == 0) {
		*err = WTAP_ERR_RANDOM_OPEN_STDIN;
		return FALSE;
	}

	/* First, make sure the file is valid */
	if (ws_stat64(filename, &statb) < 0) {
		*err = errno;
		return FALSE;
	}
	if (S_ISFIFO(statb.st_mode)) {
		/*
		 * Opens of FIFOs are not allowed; see above.
		 */
		*err = WTAP_ERR_RANDOM_OPEN_PIPE;
		return FALSE;
	} else if (S_ISDIR(statb.st_mode)) {
		/*
		 * Return different errors for "this is a directory"
		 * and "this is some random special file type", so
		 * the user can get a potentially more helpful error.
		 */
		*err = EISDIR;
		return FALSE;
	} else if (! S_ISREG(statb.st_mode)) {
		*err = WTAP_ERR_NOT_REGULAR_FILE;
		return FALSE;
	}

	/* Open the file */
	errno = WTAP_ERR_CANT_OPEN;
	if (!file_fdreopen(wth->random_fh, filename)) {
		*err = errno;
		return FALSE;
	}
	return TRUE;
}

/* Table of the file types we know about.
   Entries must be sorted by WTAP_FILE_TYPE_SUBTYPE_xxx values in ascending order */
static const struct file_type_subtype_info dump_open_table_base[] = {
	/* WTAP_FILE_TYPE_SUBTYPE_UNKNOWN (only used internally for initialization) */
	{ NULL, NULL, NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PCAP */
        /* Gianluca Varenni suggests that we add "deprecated" to the description. */
	{ "Wireshark/tcpdump/... - pcap", "pcap", "pcap", "cap;dmp",
	  FALSE, FALSE, 0,
	  libpcap_dump_can_write_encap, libpcap_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PCAPNG */
	{ "Wireshark/... - pcapng", "pcapng", "pcapng", "ntar",
	  FALSE, TRUE, WTAP_COMMENT_PER_SECTION|WTAP_COMMENT_PER_INTERFACE|WTAP_COMMENT_PER_PACKET,
	  pcapng_dump_can_write_encap, pcapng_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC */
	{ "Wireshark - nanosecond libpcap", "nseclibpcap", "pcap", "cap;dmp",
	  FALSE, FALSE, 0,
	  libpcap_dump_can_write_encap, libpcap_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PCAP_AIX */
	{ "AIX tcpdump - libpcap", "aixlibpcap", "pcap", "cap;dmp",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PCAP_SS991029 */
	{ "Modified tcpdump - libpcap", "modlibpcap", "pcap", "cap;dmp",
	  FALSE, FALSE, 0,
	  libpcap_dump_can_write_encap, libpcap_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PCAP_NOKIA */
	{ "Nokia tcpdump - libpcap ", "nokialibpcap", "pcap", "cap;dmp",
	  FALSE, FALSE, 0,
	  libpcap_dump_can_write_encap, libpcap_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990417 */
	{ "RedHat 6.1 tcpdump - libpcap", "rh6_1libpcap", "pcap", "cap;dmp",
	  FALSE, FALSE, 0,
	  libpcap_dump_can_write_encap, libpcap_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PCAP_SS990915 */
	{ "SuSE 6.3 tcpdump - libpcap", "suse6_3libpcap", "pcap", "cap;dmp",
	  FALSE, FALSE, 0,
	  libpcap_dump_can_write_encap, libpcap_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_5VIEWS */
	{ "InfoVista 5View capture", "5views", "5vw", NULL,
	   TRUE, FALSE, 0,
	  _5views_dump_can_write_encap, _5views_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_IPTRACE_1_0 */
	{ "AIX iptrace 1.0", "iptrace_1", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_IPTRACE_2_0 */
	{ "AIX iptrace 2.0", "iptrace_2", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_BER */
	{ "ASN.1 Basic Encoding Rules", "ber", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_HCIDUMP */
	{ "Bluetooth HCI dump", "hcidump", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_CATAPULT_DCT2000 */
	{ "Catapult DCT2000 trace (.out format)", "dct2000", "out", NULL,
	  FALSE, FALSE, 0,
	  catapult_dct2000_dump_can_write_encap, catapult_dct2000_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETXRAY_OLD */
	{ "Cinco Networks NetXRay 1.x", "netxray1", "cap", NULL,
	  TRUE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETXRAY_1_0 */
	{ "Cinco Networks NetXRay 2.0 or later", "netxray2", "cap", NULL,
	  TRUE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_COSINE */
	{ "CoSine IPSX L2 capture", "cosine", "txt", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_CSIDS */
	{ "CSIDS IPLog", "csids", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_DBS_ETHERWATCH */
	{ "DBS Etherwatch (VMS)", "etherwatch", "txt", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_ERF */
	{ "Endace ERF capture", "erf", "erf", NULL,
	  FALSE, FALSE, 0,
	  erf_dump_can_write_encap, erf_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_EYESDN */
	{ "EyeSDN USB S0/E1 ISDN trace format", "eyesdn", "trc", NULL,
	   FALSE, FALSE, 0,
	   eyesdn_dump_can_write_encap, eyesdn_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETTL */
	{ "HP-UX nettl trace", "nettl", "trc0", "trc1",
	  FALSE, FALSE, 0,
	  nettl_dump_can_write_encap, nettl_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_ISERIES */
	{ "IBM iSeries comm. trace (ASCII)", "iseries_ascii", "txt", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_ISERIES_UNICODE */
	{ "IBM iSeries comm. trace (UNICODE)", "iseries_unicode", "txt", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_I4BTRACE */
	{ "I4B ISDN trace", "i4btrace", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_ASCEND */
	{ "Lucent/Ascend access server trace", "ascend", "txt", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETMON_1_x */
	{ "Microsoft NetMon 1.x", "netmon1", "cap", NULL,
	  TRUE, FALSE, 0,
	  netmon_dump_can_write_encap_1_x, netmon_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETMON_2_x */
	{ "Microsoft NetMon 2.x", "netmon2", "cap", NULL,
	  TRUE, FALSE, 0,
	  netmon_dump_can_write_encap_2_x, netmon_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NGSNIFFER_UNCOMPRESSED */
	{ "Sniffer (DOS)", "ngsniffer", "cap", "enc;trc;fdc;syc",
	  FALSE, FALSE, 0,
	  ngsniffer_dump_can_write_encap, ngsniffer_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NGSNIFFER_COMPRESSED */
	{ "Sniffer (DOS), compressed", "ngsniffer_comp", "cap", "enc;trc;fdc;syc",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETXRAY_1_1 */
	{ "NetXray, Sniffer (Windows) 1.1", "ngwsniffer_1_1", "cap", NULL,
	  TRUE, FALSE, 0,
	  netxray_dump_can_write_encap_1_1, netxray_dump_open_1_1, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETXRAY_2_00x */
	{ "Sniffer (Windows) 2.00x", "ngwsniffer_2_0", "cap", "caz",
	  TRUE, FALSE, 0,
	  netxray_dump_can_write_encap_2_0, netxray_dump_open_2_0, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETWORK_INSTRUMENTS */
	{ "Network Instruments Observer", "niobserver", "bfr", NULL,
	  FALSE, FALSE, 0,
	  network_instruments_dump_can_write_encap, network_instruments_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_LANALYZER */
	{ "Novell LANalyzer","lanalyzer", "tr1", NULL,
	  TRUE, FALSE, 0,
	  lanalyzer_dump_can_write_encap, lanalyzer_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PPPDUMP */
	{ "pppd log (pppdump format)", "pppd", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_RADCOM */
	{ "RADCOM WAN/LAN analyzer", "radcom", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_SNOOP */
	{ "Sun snoop", "snoop", "snoop", "cap",
	  FALSE, FALSE, 0,
	  snoop_dump_can_write_encap, snoop_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_SHOMITI */
	{ "Shomiti/Finisar Surveyor", "shomiti", "cap", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_VMS */
	{ "TCPIPtrace (VMS)", "tcpiptrace", "txt", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_K12 */
	{ "Tektronix K12xx 32-bit .rf5 format", "rf5", "rf5", NULL,
	   TRUE, FALSE, 0,
	   k12_dump_can_write_encap, k12_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_TOSHIBA */
	{ "Toshiba Compact ISDN Router snoop", "toshiba", "txt", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_VISUAL_NETWORKS */
	{ "Visual Networks traffic capture", "visual", NULL, NULL,
	  TRUE, FALSE, 0,
	  visual_dump_can_write_encap, visual_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PEEKCLASSIC_V56 */
	{ "WildPackets classic (V5 and V6)", "peekclassic56", "pkt", "tpc;apc;wpz",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PEEKCLASSIC_V7 */
	{ "WildPackets classic (V7)", "peekclassic7", "pkt", "tpc;apc;wpz",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PEEKTAGGED */
	{ "WildPackets tagged", "peektagged", "pkt", "tpc;apc;wpz",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_MPEG */
	{ "MPEG", "mpeg", "mpeg", "mpg;mp3",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_K12TEXT  */
	{ "K12 text file", "k12text", "txt", NULL,
	  FALSE, FALSE, 0,
	  k12text_dump_can_write_encap, k12text_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETSCREEN */
	{ "NetScreen snoop text file", "netscreen", "txt", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_COMMVIEW */
	{ "TamoSoft CommView", "commview", "ncf", NULL,
	  FALSE, FALSE, 0,
	  commview_dump_can_write_encap, commview_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_BTSNOOP */
	{ "Symbian OS btsnoop", "btsnoop", "log", NULL,
	  FALSE, FALSE, 0,
	  btsnoop_dump_can_write_encap, btsnoop_dump_open_h4, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_TNEF */
	{ "Transport-Neutral Encapsulation Format", "tnef", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_DCT3TRACE */
	{ "Gammu DCT3 trace", "dct3trace", "xml", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_PACKETLOGGER */
	{ "PacketLogger", "pklg", "pklg", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_DAINTREE_SNA */
	{ "Daintree SNA", "dsna", "dcf", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETSCALER_1_0 */
	{ "NetScaler Trace (Version 1.0)", "nstrace10", NULL, NULL,
	  TRUE, FALSE, 0,
	  nstrace_10_dump_can_write_encap, nstrace_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_NETSCALER_2_0 */
	{ "NetScaler Trace (Version 2.0)", "nstrace20", "cap", NULL,
	  TRUE, FALSE, 0,
	  nstrace_20_dump_can_write_encap, nstrace_dump_open, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_JPEG_JFIF */
	{ "JPEG/JFIF", "jpeg", "jpg", "jpeg;jfif",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_IPFIX */
	{ "IPFIX File Format", "ipfix", "pfx", "ipfix",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_ENCAP_MIME */
	{ "MIME File Format", "mime", NULL, NULL,
	   FALSE, FALSE, 0,
	   NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_AETHRA */
	{ "Aethra .aps file", "aethra", "aps", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_MPEG_2_TS */
	{ "MPEG2 transport stream", "mp2t", "mp2t", "ts;mpg",
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_VWR_80211 */
	{ "Ixia IxVeriWave .vwr Raw 802.11 Capture", "vwr80211", "vwr", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_VWR_ETH */
	{ "Ixia IxVeriWave .vwr Raw Ethernet Capture", "vwreth", "vwr", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_CAMINS */
	{ "CAM Inspector file", "camins", "camins", NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_TYPE_SUBTYPE_STANAG_4607 */
	{ "STANAG 4607 Format", "stanag4607", NULL, NULL,
	  FALSE, FALSE, 0,
	  NULL, NULL, NULL },

	/* WTAP_FILE_NETSCALER_3_0 */
	{ "NetScaler Trace (Version 3.0)", "nstrace30", "cap", NULL,
	  TRUE, FALSE, 0,
	  nstrace_30_dump_can_write_encap, nstrace_dump_open, NULL },

	/* WTAP_FILE_LOGCAT */
	{ "Android Logcat Binary format",          "logcat",         "logcat", NULL,
	  FALSE, FALSE, 0,
	  logcat_dump_can_write_encap, logcat_binary_dump_open, NULL },
	{ "Android Logcat Brief text format",      "logcat-brief",      NULL, NULL,
	  FALSE, FALSE, 0,
	  logcat_dump_can_write_encap, logcat_text_brief_dump_open, NULL },
	{ "Android Logcat Process text format",    "logcat-process",    NULL, NULL,
	  FALSE, FALSE, 0,
	  logcat_dump_can_write_encap, logcat_text_process_dump_open, NULL },
	{ "Android Logcat Tag text format",        "logcat-tag",        NULL, NULL,
	  FALSE, FALSE, 0,
	  logcat_dump_can_write_encap, logcat_text_tag_dump_open, NULL },
	{ "Android Logcat Time text format",       "logcat-time",       NULL, NULL,
	  FALSE, FALSE, 0,
	  logcat_dump_can_write_encap, logcat_text_time_dump_open, NULL },
	{ "Android Logcat Thread text format",     "logcat-thread",     NULL, NULL,
	  FALSE, FALSE, 0,
	  logcat_dump_can_write_encap, logcat_text_thread_dump_open, NULL },
	{ "Android Logcat Threadtime text format", "logcat-threadtime", NULL, NULL,
	  FALSE, FALSE, 0,
	  logcat_dump_can_write_encap, logcat_text_threadtime_dump_open, NULL },
	{ "Android Logcat Long text format",       "logcat-long",       NULL, NULL,
	  FALSE, FALSE, 0,
	  logcat_dump_can_write_encap, logcat_text_long_dump_open, NULL }

};

gint wtap_num_file_types_subtypes = sizeof(dump_open_table_base) / sizeof(struct file_type_subtype_info);

static GArray*  dump_open_table_arr = NULL;
static const struct file_type_subtype_info* dump_open_table = dump_open_table_base;

/* initialize the file types array if it has not being initialized yet */
static void init_file_types_subtypes(void) {

	if (dump_open_table_arr) return;

	dump_open_table_arr = g_array_new(FALSE,TRUE,sizeof(struct file_type_subtype_info));

	g_array_append_vals(dump_open_table_arr,dump_open_table_base,wtap_num_file_types_subtypes);

	dump_open_table = (const struct file_type_subtype_info*)(void *)dump_open_table_arr->data;
}

/* if subtype is WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, then create a new subtype as well as register it, else replace the
   existing entry in that spot */
int wtap_register_file_type_subtypes(const struct file_type_subtype_info* fi, const int subtype) {
	struct file_type_subtype_info* finfo = NULL;
	init_file_types_subtypes();

	if (!fi || !fi->name || !fi->short_name || subtype > wtap_num_file_types_subtypes) {
		g_error("no file type info or invalid file type to register");
		return subtype;
	}

	/* do we want a new registration? */
	if (subtype == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
		/* register a new one; first verify there isn't one named this already */
		if (wtap_short_string_to_file_type_subtype(fi->short_name) > -1 ) {
			g_error("file type short name already exists");
			return subtype;
		}

		g_array_append_val(dump_open_table_arr,*fi);

		dump_open_table = (const struct file_type_subtype_info*)(void *)dump_open_table_arr->data;

		return wtap_num_file_types_subtypes++;
	}

	/* re-register an existing one - verify the short names do match (sanity check really) */
	if (!dump_open_table[subtype].short_name || strcmp(dump_open_table[subtype].short_name,fi->short_name) != 0) {
		g_error("invalid file type name given to register");
		return subtype;
	}

	/* yes, we're going to cast to change its const-ness */
	finfo = (struct file_type_subtype_info*)(&dump_open_table[subtype]);
	/*finfo->name = fi->name;*/
	/*finfo->short_name = fi->short_name;*/
	finfo->default_file_extension     = fi->default_file_extension;
	finfo->additional_file_extensions = fi->additional_file_extensions;
	finfo->writing_must_seek          = fi->writing_must_seek;
	finfo->has_name_resolution        = fi->has_name_resolution;
	finfo->supported_comment_types    = fi->supported_comment_types;
	finfo->can_write_encap            = fi->can_write_encap;
	finfo->dump_open                  = fi->dump_open;
	finfo->wslua_info                 = fi->wslua_info;

	return subtype;
}

/* De-registers a file writer - they can never be removed from the GArray, but we can "clear" an entry.
 */
void wtap_deregister_file_type_subtype(const int subtype) {
	struct file_type_subtype_info* finfo = NULL;

	if (subtype < 0 || subtype >= wtap_num_file_types_subtypes) {
		g_error("invalid file type to de-register");
		return;
	}

	/* yes, we're going to cast to change its const-ness */
	finfo = (struct file_type_subtype_info*)(&dump_open_table[subtype]);
	/* unfortunately, it's not safe to null-out the name or short_name; bunch of other code doesn't guard aainst that, afaict */
	/*finfo->name = NULL;*/
	/*finfo->short_name = NULL;*/
	finfo->default_file_extension = NULL;
	finfo->additional_file_extensions = NULL;
	finfo->writing_must_seek = FALSE;
	finfo->has_name_resolution = FALSE;
	finfo->supported_comment_types = 0;
	finfo->can_write_encap = NULL;
	finfo->dump_open = NULL;
	finfo->wslua_info = NULL;
}

int wtap_get_num_file_types_subtypes(void)
{
	return wtap_num_file_types_subtypes;
}

/*
 * Given a GArray of WTAP_ENCAP_ types, return the per-file encapsulation
 * type that would be needed to write out a file with those types.  If
 * there's only one type, it's that type, otherwise it's
 * WTAP_ENCAP_PER_PACKET.
 */
int
wtap_dump_file_encap_type(const GArray *file_encaps)
{
	int encap;

	encap = WTAP_ENCAP_PER_PACKET;
	if (file_encaps->len == 1) {
		/* OK, use the one-and-only encapsulation type. */
		encap = g_array_index(file_encaps, gint, 0);
	}
	return encap;
}

static gboolean
wtap_dump_can_write_encap(int filetype, int encap)
{
	int result = 0;

	if (filetype < 0 || filetype >= wtap_num_file_types_subtypes
	    || dump_open_table[filetype].can_write_encap == NULL)
		return FALSE;

	result = (*dump_open_table[filetype].can_write_encap)(encap);

	if (result != 0) {
		/* if the err said to check wslua's can_write_encap, try that */
		if (result == WTAP_ERR_CHECK_WSLUA
			&& dump_open_table[filetype].wslua_info != NULL
			&& dump_open_table[filetype].wslua_info->wslua_can_write_encap != NULL) {

			result = (*dump_open_table[filetype].wslua_info->wslua_can_write_encap)(encap, dump_open_table[filetype].wslua_info->wslua_data);

		}

		if (result != 0)
			return FALSE;
	}

	return TRUE;
}

/*
 * Return TRUE if a capture with a given GArray of encapsulation types
 * and a given bitset of comment types can be written in a specified
 * format, and FALSE if it can't.
 */
static gboolean
wtap_dump_can_write_format(int ft, const GArray *file_encaps,
    guint32 required_comment_types)
{
	guint i;

	/*
	 * Can we write in this format?
	 */
	if (!wtap_dump_can_open(ft)) {
		/* No. */
		return FALSE;
	}

	/*
	 * Yes.  Can we write out all the required comments in this
	 * format?
	 */
	if (!wtap_dump_supports_comment_types(ft, required_comment_types)) {
		/* No. */
		return FALSE;
	}

	/*
	 * Yes.  Is the required per-file encapsulation type supported?
	 * This might be WTAP_ENCAP_PER_PACKET.
	 */
	if (!wtap_dump_can_write_encap(ft, wtap_dump_file_encap_type(file_encaps))) {
		/* No. */
		return FALSE;
	}

	/*
	 * Yes.  Are all the individual encapsulation types supported?
	 */
	for (i = 0; i < file_encaps->len; i++) {
		if (!wtap_dump_can_write_encap(ft,
		    g_array_index(file_encaps, int, i))) {
			/* No - one of them isn't. */
			return FALSE;
		}
	}

	/* Yes - we're OK. */
	return TRUE;
}

/**
 * Return TRUE if we can write a file with the given GArray of
 * encapsulation types and the given bitmask of comment types.
 */
gboolean
wtap_dump_can_write(const GArray *file_encaps, guint32 required_comment_types)
{
  int ft;

  for (ft = 0; ft < WTAP_NUM_FILE_TYPES_SUBTYPES; ft++) {
    /* To save a file with Wiretap, Wiretap has to handle that format,
       and its code to handle that format must be able to write a file
       with this file's encapsulation types. */
    if (wtap_dump_can_write_format(ft, file_encaps, required_comment_types)) {
      /* OK, we can write it out in this type. */
      return TRUE;
    }
  }

  /* No, we couldn't save it in any format. */
  return FALSE;
}

/**
 * Get a GArray of WTAP_FILE_TYPE_SUBTYPE_ values for file types/subtypes
 * that can be used to save a file of a given type/subtype with a given
 * GArray of encapsulation types and the given bitmask of comment types.
 */
GArray *
wtap_get_savable_file_types_subtypes(int file_type_subtype,
    const GArray *file_encaps, guint32 required_comment_types)
{
	GArray *savable_file_types_subtypes;
	int ft;
	int default_file_type_subtype = -1;
	int other_file_type_subtype = -1;

	/* Can we save this file in its own file type/subtype? */
	if (wtap_dump_can_write_format(file_type_subtype, file_encaps,
	                               required_comment_types)) {
		/* Yes - make that the default file type/subtype. */
		default_file_type_subtype = file_type_subtype;
	} else {
		/* OK, find the first file type/subtype we *can* save it as. */
		default_file_type_subtype = -1;
		for (ft = 0; ft < WTAP_NUM_FILE_TYPES_SUBTYPES; ft++) {
			if (wtap_dump_can_write_format(ft, file_encaps,
			                               required_comment_types)) {
				/* OK, got it. */
				default_file_type_subtype = ft;
			}
		}
	}

	if (default_file_type_subtype == -1) {
		/* We don't support writing this file as any file type/subtype. */
		return NULL;
	}

	/* Allocate the array. */
	savable_file_types_subtypes = g_array_new(FALSE, FALSE, (guint)sizeof (int));

	/* Put the default file type/subtype first in the list. */
	g_array_append_val(savable_file_types_subtypes, default_file_type_subtype);

	/* If the default is pcap, put pcap-NG right after it if we can
	   also write it in pcap-NG format; otherwise, if the default is
	   pcap-NG, put pcap right after it if we can also write it in
	   pcap format. */
	if (default_file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_PCAP) {
		if (wtap_dump_can_write_format(WTAP_FILE_TYPE_SUBTYPE_PCAPNG, file_encaps,
		                               required_comment_types))
			other_file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PCAPNG;
	} else if (default_file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_PCAPNG) {
		if (wtap_dump_can_write_format(WTAP_FILE_TYPE_SUBTYPE_PCAP, file_encaps,
		                               required_comment_types))
			other_file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PCAP;
	}
	if (other_file_type_subtype != -1)
		g_array_append_val(savable_file_types_subtypes, other_file_type_subtype);

	/* Add all the other file types/subtypes that work. */
	for (ft = 0; ft < WTAP_NUM_FILE_TYPES_SUBTYPES; ft++) {
		if (ft == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN)
			continue;	/* not a real file type */
		if (ft == default_file_type_subtype || ft == other_file_type_subtype)
			continue;	/* we've already done this one */
		if (wtap_dump_can_write_format(ft, file_encaps,
		                               required_comment_types)) {
			/* OK, we can write it out in this type. */
			g_array_append_val(savable_file_types_subtypes, ft);
		}
	}

	return savable_file_types_subtypes;
}

/* Name that should be somewhat descriptive. */
const char *wtap_file_type_subtype_string(int file_type_subtype)
{
	if (file_type_subtype < 0 || file_type_subtype >= wtap_num_file_types_subtypes) {
		g_error("Unknown capture file type %d", file_type_subtype);
		/** g_error() does an abort() and thus never returns **/
		return "";
	} else
		return dump_open_table[file_type_subtype].name;
}

/* Name to use in, say, a command-line flag specifying the type/subtype. */
const char *wtap_file_type_subtype_short_string(int file_type_subtype)
{
	if (file_type_subtype < 0 || file_type_subtype >= wtap_num_file_types_subtypes)
		return NULL;
	else
		return dump_open_table[file_type_subtype].short_name;
}

/* Translate a short name to a capture file type/subtype. */
int wtap_short_string_to_file_type_subtype(const char *short_name)
{
	int file_type_subtype;

	for (file_type_subtype = 0; file_type_subtype < wtap_num_file_types_subtypes; file_type_subtype++) {
		if (dump_open_table[file_type_subtype].short_name != NULL &&
		    strcmp(short_name, dump_open_table[file_type_subtype].short_name) == 0)
			return file_type_subtype;
	}

	/*
	 * We now call the "libpcap" file format just "pcap", but we
	 * allow it to be specified as "libpcap" as well, for
	 * backwards compatibility.
	 */
	if (strcmp(short_name, "libpcap") == 0)
		return WTAP_FILE_TYPE_SUBTYPE_PCAP;

	return -1;	/* no such file type, or we can't write it */
}

static GSList *
add_extensions_for_file_type_subtype(int file_type_subtype, GSList *extensions,
    GSList *compressed_file_extensions)
{
	gchar **extensions_set, **extensionp;
	gchar *extension;

	/*
	 * Add the default extension, and all compressed variants of
	 * it.
	 */
	extensions = add_extensions(extensions,
	    dump_open_table[file_type_subtype].default_file_extension,
	    compressed_file_extensions);

	if (dump_open_table[file_type_subtype].additional_file_extensions != NULL) {
		/*
		 * We have additional extensions; add them.
		 *
		 * First, split the extension-list string into a set of
		 * extensions.
		 */
		extensions_set = g_strsplit(dump_open_table[file_type_subtype].additional_file_extensions,
		    ";", 0);

		/*
		 * Add each of those extensions to the list.
		 */
		for (extensionp = extensions_set; *extensionp != NULL;
		    extensionp++) {
			extension = *extensionp;

			/*
			 * Add the extension, and all compressed variants
			 * of it.
			 */
			extensions = add_extensions(extensions, extension,
			    compressed_file_extensions);
		}

		g_strfreev(extensions_set);
	}
	return extensions;
}

/* Return a list of file extensions that are used by the specified file type.

   If include_compressed is TRUE, the list will include compressed
   extensions, e.g. not just "pcap" but also "pcap.gz" if we can read
   gzipped files.

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *wtap_get_file_extensions_list(int file_type_subtype, gboolean include_compressed)
{
	GSList *compressed_file_extensions;
	GSList *extensions;

	if (file_type_subtype < 0 || file_type_subtype >= wtap_num_file_types_subtypes)
		return NULL;	/* not a valid file type */

	if (dump_open_table[file_type_subtype].default_file_extension == NULL)
		return NULL;	/* valid, but no extensions known */

	extensions = NULL;	/* empty list, to start with */

	/*
	 * If include_compressions is true, get the list of compressed-file
	 * extensions.
	 */
	if (include_compressed)
		compressed_file_extensions = wtap_get_compressed_file_extensions();
	else
		compressed_file_extensions = NULL;

	/*
	 * Add all this file type's extensions, with compressed
	 * variants.
	 */
	extensions = add_extensions_for_file_type_subtype(file_type_subtype, extensions,
	    compressed_file_extensions);

	g_slist_free(compressed_file_extensions);
	return extensions;
}

/*
 * Free a list returned by wtap_get_file_extension_type_extensions(),
 * wtap_get_all_file_extensions_list, or wtap_get_file_extensions_list().
 */
void wtap_free_extensions_list(GSList *extensions)
{
	GSList *extension;

	for (extension = extensions; extension != NULL;
	    extension = g_slist_next(extension)) {
		g_free(extension->data);
	}
	g_slist_free(extensions);
}

/* Return the default file extension to use with the specified file type;
   that's just the extension, without any ".". */
const char *wtap_default_file_extension(int file_type_subtype)
{
	if (file_type_subtype < 0 || file_type_subtype >= wtap_num_file_types_subtypes)
		return NULL;
	else
		return dump_open_table[file_type_subtype].default_file_extension;
}

gboolean wtap_dump_can_open(int file_type_subtype)
{
	if (file_type_subtype < 0 || file_type_subtype >= wtap_num_file_types_subtypes
	    || dump_open_table[file_type_subtype].dump_open == NULL)
		return FALSE;

	return TRUE;
}

#ifdef HAVE_LIBZ
gboolean wtap_dump_can_compress(int file_type_subtype)
{
	/*
	 * If this is an unknown file type, or if we have to
	 * seek when writing out a file with this file type,
	 * return FALSE.
	 */
	if (file_type_subtype < 0 || file_type_subtype >= wtap_num_file_types_subtypes
	    || dump_open_table[file_type_subtype].writing_must_seek)
		return FALSE;

	return TRUE;
}
#else
gboolean wtap_dump_can_compress(int file_type_subtype _U_)
{
	return FALSE;
}
#endif

gboolean wtap_dump_has_name_resolution(int file_type_subtype)
{
	if (file_type_subtype < 0 || file_type_subtype >= wtap_num_file_types_subtypes
	    || dump_open_table[file_type_subtype].has_name_resolution == FALSE)
		return FALSE;

	return TRUE;
}

gboolean wtap_dump_supports_comment_types(int file_type_subtype, guint32 comment_types)
{
	guint32 supported_comment_types;

	if (file_type_subtype < 0 || file_type_subtype >= wtap_num_file_types_subtypes)
		return FALSE;

	supported_comment_types = dump_open_table[file_type_subtype].supported_comment_types;

	if ((comment_types & supported_comment_types) == comment_types)
		return TRUE;
	return FALSE;
}

static gboolean wtap_dump_open_check(int file_type_subtype, int encap, gboolean comressed, int *err);
static wtap_dumper* wtap_dump_alloc_wdh(int file_type_subtype, int encap, int snaplen,
					gboolean compressed, int *err);
static gboolean wtap_dump_open_finish(wtap_dumper *wdh, int file_type_subtype, gboolean compressed, int *err);

static WFILE_T wtap_dump_file_open(wtap_dumper *wdh, const char *filename);
static WFILE_T wtap_dump_file_fdopen(wtap_dumper *wdh, int fd);
static int wtap_dump_file_close(wtap_dumper *wdh);

wtap_dumper* wtap_dump_open(const char *filename, int file_type_subtype, int encap,
				int snaplen, gboolean compressed, int *err)
{
	return wtap_dump_open_ng(filename, file_type_subtype, encap,snaplen, compressed, NULL, NULL, err);
}

static wtap_dumper *
wtap_dump_init_dumper(int file_type_subtype, int encap, int snaplen, gboolean compressed,
    wtapng_section_t *shb_hdr, wtapng_iface_descriptions_t *idb_inf, int *err)
{
	wtap_dumper *wdh;

	/* Allocate a data structure for the output stream. */
	wdh = wtap_dump_alloc_wdh(file_type_subtype, encap, snaplen, compressed, err);
	if (wdh == NULL)
		return NULL;	/* couldn't allocate it */

	/* Set Section Header Block data */
	wdh->shb_hdr = shb_hdr;
	/* Set Interface Description Block data */
	if ((idb_inf != NULL) && (idb_inf->interface_data->len > 0)) {
		wdh->interface_data = idb_inf->interface_data;
	} else {
		wtapng_if_descr_t descr;

		descr.wtap_encap = encap;
		descr.time_units_per_second = 1000000; /* default microsecond resolution */
		descr.link_type = wtap_wtap_encap_to_pcap_encap(encap);
		descr.snap_len = snaplen;
		descr.opt_comment = NULL;
		descr.if_name = g_strdup("Unknown/not available in original file format(libpcap)");
		descr.if_description = NULL;
		descr.if_speed = 0;
		descr.if_tsresol = 6;
		descr.if_filter_str= NULL;
		descr.bpf_filter_len= 0;
		descr.if_filter_bpf_bytes= NULL;
		descr.if_os = NULL;
		descr.if_fcslen = -1;
		descr.num_stat_entries = 0;          /* Number of ISB:s */
		descr.interface_statistics = NULL;
		wdh->interface_data = g_array_new(FALSE, FALSE, sizeof(wtapng_if_descr_t));
		g_array_append_val(wdh->interface_data, descr);
	}
	return wdh;
}

wtap_dumper* wtap_dump_open_ng(const char *filename, int file_type_subtype, int encap,
				int snaplen, gboolean compressed, wtapng_section_t *shb_hdr, wtapng_iface_descriptions_t *idb_inf, int *err)
{
	wtap_dumper *wdh;
	WFILE_T fh;

	/* Check whether we can open a capture file with that file type
	   and that encapsulation. */
	if (!wtap_dump_open_check(file_type_subtype, encap, compressed, err))
		return NULL;

	/* Allocate and initialize a data structure for the output stream. */
	wdh = wtap_dump_init_dumper(file_type_subtype, encap, snaplen, compressed,
	    shb_hdr, idb_inf, err);
	if (wdh == NULL)
		return NULL;

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

	if (!wtap_dump_open_finish(wdh, file_type_subtype, compressed, err)) {
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

wtap_dumper* wtap_dump_fdopen(int fd, int file_type_subtype, int encap, int snaplen,
				gboolean compressed, int *err)
{
	return wtap_dump_fdopen_ng(fd, file_type_subtype, encap, snaplen, compressed, NULL, NULL, err);
}

wtap_dumper* wtap_dump_fdopen_ng(int fd, int file_type_subtype, int encap, int snaplen,
				gboolean compressed, wtapng_section_t *shb_hdr, wtapng_iface_descriptions_t *idb_inf, int *err)
{
	wtap_dumper *wdh;
	WFILE_T fh;

	/* Check whether we can open a capture file with that file type
	   and that encapsulation. */
	if (!wtap_dump_open_check(file_type_subtype, encap, compressed, err))
		return NULL;

	/* Allocate and initialize a data structure for the output stream. */
	wdh = wtap_dump_init_dumper(file_type_subtype, encap, snaplen, compressed,
	    shb_hdr, idb_inf, err);
	if (wdh == NULL)
		return NULL;

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

	if (!wtap_dump_open_finish(wdh, file_type_subtype, compressed, err)) {
		wtap_dump_file_close(wdh);
		g_free(wdh);
		return NULL;
	}
	return wdh;
}

static gboolean wtap_dump_open_check(int file_type_subtype, int encap, gboolean compressed, int *err)
{
	if (!wtap_dump_can_open(file_type_subtype)) {
		/* Invalid type, or type we don't know how to write. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	/* OK, we know how to write that type; can we write the specified
	   encapsulation type? */
	*err = (*dump_open_table[file_type_subtype].can_write_encap)(encap);
	/* if the err said to check wslua's can_write_encap, try that */
	if (*err == WTAP_ERR_CHECK_WSLUA
		&& dump_open_table[file_type_subtype].wslua_info != NULL
		&& dump_open_table[file_type_subtype].wslua_info->wslua_can_write_encap != NULL) {

		*err = (*dump_open_table[file_type_subtype].wslua_info->wslua_can_write_encap)(encap, dump_open_table[file_type_subtype].wslua_info->wslua_data);

	}

	if (*err != 0)
		return FALSE;

	/* if compression is wanted, do we support this for this file_type_subtype? */
	if(compressed && !wtap_dump_can_compress(file_type_subtype)) {
		*err = WTAP_ERR_COMPRESSION_NOT_SUPPORTED;
		return FALSE;
	}

	/* All systems go! */
	return TRUE;
}

static wtap_dumper* wtap_dump_alloc_wdh(int file_type_subtype, int encap, int snaplen,
					gboolean compressed, int *err)
{
	wtap_dumper *wdh;

	wdh = (wtap_dumper *)g_malloc0(sizeof (wtap_dumper));
	if (wdh == NULL) {
		*err = errno;
		return NULL;
	}

	wdh->file_type_subtype = file_type_subtype;
	wdh->snaplen = snaplen;
	wdh->encap = encap;
	wdh->compressed = compressed;
	wdh->wslua_data = NULL;
	return wdh;
}

static gboolean wtap_dump_open_finish(wtap_dumper *wdh, int file_type_subtype, gboolean compressed, int *err)
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
	if (dump_open_table[file_type_subtype].writing_must_seek && cant_seek) {
		*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
		return FALSE;
	}

	/* Set wdh with wslua data if any - this is how we pass the data
	 * to the file writer.
	 */
	if (dump_open_table[file_type_subtype].wslua_info)
		wdh->wslua_data = dump_open_table[file_type_subtype].wslua_info->wslua_data;

	/* Now try to open the file for writing. */
	if (!(*dump_open_table[file_type_subtype].dump_open)(wdh, err)) {
		return FALSE;
	}

	return TRUE;	/* success! */
}

gboolean wtap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
		   const guint8 *pd, int *err)
{
	return (wdh->subtype_write)(wdh, phdr, pd, err);
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

gboolean wtap_dump_set_addrinfo_list(wtap_dumper *wdh, addrinfo_lists_t *addrinfo_lists)
{
	if (!wdh || wdh->file_type_subtype < 0 || wdh->file_type_subtype >= wtap_num_file_types_subtypes
		|| dump_open_table[wdh->file_type_subtype].has_name_resolution == FALSE)
			return FALSE;
	wdh->addrinfo_lists = addrinfo_lists;
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
		nwritten = gzwfile_write((GZWFILE_T)wdh->fh, buf, (unsigned int) bufsize);
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

gint64 wtap_dump_file_seek(wtap_dumper *wdh, gint64 offset, int whence, int *err)
{
#ifdef HAVE_LIBZ
	if(wdh->compressed) {
		*err = WTAP_ERR_CANT_SEEK_COMPRESSED;
		return -1;
	} else
#endif
	{
		if (-1 == fseek((FILE *)wdh->fh, (long)offset, whence)) {
			*err = errno;
			return -1;
		} else
		{
			return 0;
		}
	}
}
gint64 wtap_dump_file_tell(wtap_dumper *wdh, int *err)
{
	gint64 rval;
#ifdef HAVE_LIBZ
	if(wdh->compressed) {
		*err = WTAP_ERR_CANT_SEEK_COMPRESSED;
		return -1;
	} else
#endif
	{
		if (-1 == (rval = ftell((FILE *)wdh->fh))) {
			*err = errno;
			return -1;
		} else
		{
			return rval;
		}
	}
}
