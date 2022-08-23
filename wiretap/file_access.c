/* file_access.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include <wsutil/file_util.h>
#include <wsutil/tempfile.h>
#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

#include "wtap-int.h"
#include "wtap_modules.h"
#include "file_wrappers.h"
#include "required_file_handlers.h"
#include <wsutil/buffer.h>

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
#include "logcat_text.h"
#include "json.h"
#include "observer.h"
#include "k12.h"
#include "ber.h"
#include "catapult_dct2000.h"
#include "mp4.h"
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
#include "capsa.h"
#include "nettrace_3gpp_32_423.h"
#include "mplog.h"
#include "dpa400.h"
#include "rfc7468.h"
#include "ruby_marshal.h"
#include "systemd_journal.h"
#include "log3gpp.h"
#include "candump.h"
#include "busmaster.h"
#include "blf.h"
#include "eri_enb_log.h"
#include "autosar_dlt.h"


/*
 * Add an extension, and all compressed versions thereof if requested,
 * to a GSList of extensions.
 */
static GSList *
add_extensions(GSList *extensions, const gchar *extension,
    GSList *compression_type_extensions)
{
	/*
	 * Add the specified extension.
	 */
	extensions = g_slist_prepend(extensions, g_strdup(extension));

	/*
	 * Add whatever compressed versions we were supplied.
	 */
	for (GSList *compression_type_extension = compression_type_extensions;
	    compression_type_extension != NULL;
	    compression_type_extension = g_slist_next(compression_type_extension)) {
		extensions = g_slist_prepend(extensions,
		    ws_strdup_printf("%s.%s", extension,
		        (const char *)compression_type_extension->data));
	}

	return extensions;
}

/*
 * File types that can be identified by file extensions.
 *
 * These are used in file open dialogs to offer choices of extensions
 * for which to filter.  Note that the first field can list more than
 * one type of file, because, for example, ".cap" is a popular
 * extension used by a number of capture file types.
 *
 * File types that *don't* have a file extension used for them should
 * *not* be placed here; if there's nothing to put in the last field
 * of the structure, don't put an entry here, not even one with an
 * empty string for the extensions list.
 */
static const struct file_extension_info file_type_extensions_base[] = {
	{ "Wireshark/tcpdump/... - pcap", TRUE, "pcap;cap;dmp" },
	{ "Wireshark/... - pcapng", TRUE, "pcapng;ntar" },
	{ "Network Monitor, Surveyor, NetScaler", TRUE, "cap" },
	{ "InfoVista 5View capture", TRUE, "5vw" },
	{ "Sniffer (DOS)", TRUE, "cap;enc;trc;fdc;syc" },
	{ "Cinco NetXRay, Sniffer (Windows)", TRUE, "cap;caz" },
	{ "Endace ERF capture", TRUE, "erf" },
	{ "EyeSDN USB S0/E1 ISDN trace format", TRUE, "trc" },
	{ "HP-UX nettl trace", TRUE, "trc0;trc1" },
	{ "Viavi Observer", TRUE, "bfr" },
	{ "Colasoft Capsa", TRUE, "cscpkt" },
	{ "Novell LANalyzer", TRUE, "tr1" },
	{ "Tektronix K12xx 32-bit .rf5 format", TRUE, "rf5" },
	{ "Savvius *Peek", TRUE, "pkt;tpc;apc;wpz" },
	{ "Catapult DCT2000 trace (.out format)", TRUE, "out" },
	{ "Micropross mplog", TRUE, "mplog" },
	{ "TamoSoft CommView NCF", TRUE, "ncf" },
	{ "TamoSoft CommView NCFX", TRUE, "ncfx" },
	{ "Symbian OS btsnoop", TRUE, "log" },
	{ "XML files (including Gammu DCT3 traces)", TRUE, "xml" },
	{ "macOS PacketLogger", TRUE, "pklg" },
	{ "Daintree SNA", TRUE, "dcf" },
	{ "IPFIX File Format", TRUE, "pfx;ipfix" },
	{ "Aethra .aps file", TRUE, "aps" },
	{ "MPEG2 transport stream", TRUE, "mp2t;ts;mpg" },
	{ "Ixia IxVeriWave .vwr Raw 802.11 Capture", TRUE, "vwr" },
	{ "CAM Inspector file", TRUE, "camins" },
	{ "BLF file", TRUE, "blf" },
	{ "AUTOSAR DLT file", TRUE, "dlt" },
	{ "MPEG files", FALSE, "mpg;mp3" },
	{ "Transport-Neutral Encapsulation Format", FALSE, "tnef" },
	{ "JPEG/JFIF files", FALSE, "jpg;jpeg;jfif" },
	{ "JavaScript Object Notation file", FALSE, "json" },
	{ "MP4 file", FALSE, "mp4" },
};

#define	N_FILE_TYPE_EXTENSIONS	(sizeof file_type_extensions_base / sizeof file_type_extensions_base[0])

static const struct file_extension_info* file_type_extensions = NULL;

static GArray* file_type_extensions_arr = NULL;

/* initialize the extensions array if it has not been initialized yet */
static void
init_file_type_extensions(void)
{

	if (file_type_extensions_arr) return;

	file_type_extensions_arr = g_array_new(FALSE,TRUE,sizeof(struct file_extension_info));

	g_array_append_vals(file_type_extensions_arr,file_type_extensions_base,N_FILE_TYPE_EXTENSIONS);

	file_type_extensions = (struct file_extension_info*)(void *)file_type_extensions_arr->data;
}

void
wtap_register_file_type_extension(const struct file_extension_info *ei)
{
	init_file_type_extensions();

	g_array_append_val(file_type_extensions_arr,*ei);

	file_type_extensions = (const struct file_extension_info*)(void *)file_type_extensions_arr->data;
}

int
wtap_get_num_file_type_extensions(void)
{
	return file_type_extensions_arr->len;
}

const char *
wtap_get_file_extension_type_name(int extension_type)
{
	return file_type_extensions[extension_type].name;
}

static GSList *
add_extensions_for_file_extensions_type(int extension_type, GSList *extensions,
    GSList *compression_type_extensions)
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
		    compression_type_extensions);
	}

	g_strfreev(extensions_set);
	return extensions;
}

/* Return a list of file extensions that are used by the specified file
   extension type.

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *
wtap_get_file_extension_type_extensions(guint extension_type)
{
	GSList *extensions, *compression_type_extensions;

	if (extension_type >= file_type_extensions_arr->len)
		return NULL;	/* not a valid extension type */

	extensions = NULL;	/* empty list, to start with */

	/*
	 * Get compression-type extensions, if any.
	 */
	compression_type_extensions = wtap_get_all_compression_type_extensions_list();

	/*
	 * Add all this file extension type's extensions, with compressed
	 * variants.
	 */
	extensions = add_extensions_for_file_extensions_type(extension_type,
	    extensions, compression_type_extensions);

	g_slist_free(compression_type_extensions);

	return extensions;
}

/* Return a list of all extensions that are used by all capture file
   types, including compressed extensions, e.g. not just "pcap" but
   also "pcap.gz" if we can read gzipped files.

   "Capture files" means "include file types that correspond to
   collections of network packets, but not file types that
   store data that just happens to be transported over protocols
   such as HTTP but that aren't collections of network packets",
   so that it could be used for "All Capture Files" without picking
   up JPEG files or files such as that - those aren't capture files,
   and we *do* have them listed in the long list of individual file
   types, so omitting them from "All Capture Files" is the right
   thing to do.

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *
wtap_get_all_capture_file_extensions_list(void)
{
	GSList *extensions, *compression_type_extensions;
	unsigned int i;

	init_file_type_extensions();

	extensions = NULL;	/* empty list, to start with */

	/*
	 * Get compression-type extensions, if any.
	 */
	compression_type_extensions = wtap_get_all_compression_type_extensions_list();

	for (i = 0; i < file_type_extensions_arr->len; i++) {
		/*
		 * Is this a capture file, rather than one of the
		 * other random file types we can read?
		 */
		if (file_type_extensions[i].is_capture_file) {
			/*
			 * Yes.  Add all this file extension type's
			 * extensions, with compressed variants.
			 */
			extensions = add_extensions_for_file_extensions_type(i,
			    extensions, compression_type_extensions);
		}
	}

	g_slist_free(compression_type_extensions);

	return extensions;
}

/*
 * The open_file_* routines should return:
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
 * (See https://gitlab.com/wireshark/wireshark/-/issues/8518)
 *
 * However, the caller does have to free the private data pointer when
 * returning 0, since the next file type will be called and will likely
 * just overwrite the pointer.
 *
 * The names are used in file open dialogs to select, for files that
 * don't have magic numbers and that could potentially be files of
 * more than one type based on the heuristics, a particular file
 * type to interpret it as, if the file name has no extension, the
 * extension isn't sufficient to determine the appropriate file type,
 * or the extension is wrong.
 *
 * NOTE: when adding file formats to this list you may also want to add them
 * to the following files so that the various desktop environments will
 * know that Wireshark can open the file:
 *	1) resources/freedesktop/org.wireshark.Wireshark-mime.xml (for freedesktop.org environments)
 *	2) packaging/macosx/WiresharkInfo.plist.in (for macOS)
 *	3) packaging/nsis/AdditionalTasksPage.ini, packaging/nsis/wireshark-common.nsh,
 *	   and packaging/wix/ComponentGroups.wxi (for Windows)
 *
 * If your file format has an expected extension (e.g., ".pcap") then you
 * should probably also add it to file_type_extensions_base[] (in this file).
 */
static const struct open_info open_info_base[] = {
	{ "Wireshark/tcpdump/... - pcap",           OPEN_INFO_MAGIC,     libpcap_open,             "pcap",     NULL, NULL },
	{ "Wireshark/... - pcapng",                 OPEN_INFO_MAGIC,     pcapng_open,              "pcapng",   NULL, NULL },
	{ "Sniffer (DOS)",                          OPEN_INFO_MAGIC,     ngsniffer_open,           NULL,       NULL, NULL },
	{ "Snoop, Shomiti/Finisar Surveyor",        OPEN_INFO_MAGIC,     snoop_open,               NULL,       NULL, NULL },
	{ "AIX iptrace",                            OPEN_INFO_MAGIC,     iptrace_open,             NULL,       NULL, NULL },
	{ "Microsoft Network Monitor",              OPEN_INFO_MAGIC,     netmon_open,              NULL,       NULL, NULL },
	{ "Cinco NetXray/Sniffer (Windows)",        OPEN_INFO_MAGIC,     netxray_open,             NULL,       NULL, NULL },
	{ "RADCOM WAN/LAN analyzer",                OPEN_INFO_MAGIC,     radcom_open,              NULL,       NULL, NULL },
	{ "HP-UX nettl trace",                      OPEN_INFO_MAGIC,     nettl_open,               NULL,       NULL, NULL },
	{ "Visual Networks traffic capture",        OPEN_INFO_MAGIC,     visual_open,              NULL,       NULL, NULL },
	{ "InfoVista 5View capture",                OPEN_INFO_MAGIC,     _5views_open,             NULL,       NULL, NULL },
	{ "Viavi Observer",                         OPEN_INFO_MAGIC,     observer_open,            NULL,       NULL, NULL },
	{ "Savvius tagged",                         OPEN_INFO_MAGIC,     peektagged_open,          NULL,       NULL, NULL },
	{ "Colasoft Capsa",                         OPEN_INFO_MAGIC,     capsa_open,               NULL,       NULL, NULL },
	{ "DBS Etherwatch (VMS)",                   OPEN_INFO_MAGIC,     dbs_etherwatch_open,      NULL,       NULL, NULL },
	{ "Tektronix K12xx 32-bit .rf5 format",     OPEN_INFO_MAGIC,     k12_open,                 NULL,       NULL, NULL },
	{ "Catapult DCT2000 trace (.out format)",   OPEN_INFO_MAGIC,     catapult_dct2000_open,    NULL,       NULL, NULL },
	{ "Aethra .aps file",                       OPEN_INFO_MAGIC,     aethra_open,              NULL,       NULL, NULL },
	{ "Symbian OS btsnoop",                     OPEN_INFO_MAGIC,     btsnoop_open,             "log",      NULL, NULL },
	{ "EyeSDN USB S0/E1 ISDN trace format",     OPEN_INFO_MAGIC,     eyesdn_open,              NULL,       NULL, NULL },
	{ "Transport-Neutral Encapsulation Format", OPEN_INFO_MAGIC,     tnef_open,                NULL,       NULL, NULL },
	/* 3GPP TS 32.423 Trace must come before MIME Files as it's XML based*/
	{ "3GPP TS 32.423 Trace format",            OPEN_INFO_MAGIC,     nettrace_3gpp_32_423_file_open, NULL, NULL, NULL },
	/* Gammu DCT3 trace must come before MIME files as it's XML based*/
	{ "Gammu DCT3 trace",                       OPEN_INFO_MAGIC,     dct3trace_open,           NULL,       NULL, NULL },
	{ "BLF Logfile",                            OPEN_INFO_MAGIC,     blf_open,                 "blf",      NULL, NULL },
	{ "AUTOSAR DLT Logfile",                    OPEN_INFO_MAGIC,     autosar_dlt_open,         "dlt",      NULL, NULL },
	{ "MIME Files Format",                      OPEN_INFO_MAGIC,     mime_file_open,           NULL,       NULL, NULL },
	{ "Micropross mplog",                       OPEN_INFO_MAGIC,     mplog_open,               "mplog",    NULL, NULL },
	{ "Unigraf DPA-400 capture",                OPEN_INFO_MAGIC,     dpa400_open,              "bin",      NULL, NULL },
	{ "RFC 7468 files",                         OPEN_INFO_MAGIC,     rfc7468_open,             "pem;crt",  NULL, NULL },
	{ "Novell LANalyzer",                       OPEN_INFO_HEURISTIC, lanalyzer_open,           "tr1",      NULL, NULL },
	/*
	 * PacketLogger must come before MPEG, because its files
	 * are sometimes grabbed by mpeg_open.
	 */
	{ "macOS PacketLogger",                     OPEN_INFO_HEURISTIC, packetlogger_open,        "pklg",     NULL, NULL },
	/* Some MPEG files have magic numbers, others just have heuristics. */
	{ "MPEG",                                   OPEN_INFO_HEURISTIC, mpeg_open,                "mpg;mp3",  NULL, NULL },
	{ "Daintree SNA",                           OPEN_INFO_HEURISTIC, daintree_sna_open,        "dcf",      NULL, NULL },
	{ "STANAG 4607 Format",                     OPEN_INFO_HEURISTIC, stanag4607_open,          NULL,       NULL, NULL },
	{ "ASN.1 Basic Encoding Rules",             OPEN_INFO_HEURISTIC, ber_open,                 NULL,       NULL, NULL },
	/*
	 * I put NetScreen *before* erf, because there were some
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
	{ "NetScreen snoop text file",              OPEN_INFO_HEURISTIC, netscreen_open,           "txt",      NULL, NULL },
	{ "Endace ERF capture",                     OPEN_INFO_HEURISTIC, erf_open,                 "erf",      NULL, NULL },
	{ "IPFIX File Format",                      OPEN_INFO_HEURISTIC, ipfix_open,               "pfx;ipfix",NULL, NULL },
	{ "K12 text file",                          OPEN_INFO_HEURISTIC, k12text_open,             "txt",      NULL, NULL },
	{ "Savvius classic",                        OPEN_INFO_HEURISTIC, peekclassic_open,         "pkt;tpc;apc;wpz", NULL, NULL },
	{ "pppd log (pppdump format)",              OPEN_INFO_HEURISTIC, pppdump_open,             NULL,       NULL, NULL },
	{ "IBM iSeries comm. trace",                OPEN_INFO_HEURISTIC, iseries_open,             "txt",      NULL, NULL },
	{ "I4B ISDN trace",                         OPEN_INFO_HEURISTIC, i4btrace_open,            NULL,       NULL, NULL },
	{ "MPEG2 transport stream",                 OPEN_INFO_HEURISTIC, mp2t_open,                "ts;mpg",   NULL, NULL },
	{ "CSIDS IPLog",                            OPEN_INFO_HEURISTIC, csids_open,               NULL,       NULL, NULL },
	{ "TCPIPtrace (VMS)",                       OPEN_INFO_HEURISTIC, vms_open,                 "txt",      NULL, NULL },
	{ "CoSine IPSX L2 capture",                 OPEN_INFO_HEURISTIC, cosine_open,              "txt",      NULL, NULL },
	{ "Bluetooth HCI dump",                     OPEN_INFO_HEURISTIC, hcidump_open,             NULL,       NULL, NULL },
	{ "TamoSoft CommView NCF",                  OPEN_INFO_HEURISTIC, commview_ncf_open,        "ncf",      NULL, NULL },
	{ "TamoSoft CommView NCFX",                 OPEN_INFO_HEURISTIC, commview_ncfx_open,       "ncfx",      NULL, NULL },
	{ "NetScaler",                              OPEN_INFO_HEURISTIC, nstrace_open,             "cap",      NULL, NULL },
	{ "Android Logcat Binary format",           OPEN_INFO_HEURISTIC, logcat_open,              "logcat",   NULL, NULL },
	{ "Android Logcat Text formats",            OPEN_INFO_HEURISTIC, logcat_text_open,         "txt",      NULL, NULL },
	{ "Candump log",                            OPEN_INFO_HEURISTIC, candump_open,             NULL,       NULL, NULL },
	{ "Busmaster log",                          OPEN_INFO_HEURISTIC, busmaster_open,           NULL,       NULL, NULL },
	{ "Ericsson eNode-B raw log",               OPEN_INFO_MAGIC,     eri_enb_log_open,         NULL,       NULL, NULL },
	{ "Systemd Journal",                        OPEN_INFO_HEURISTIC, systemd_journal_open,     "log;jnl;journal",      NULL, NULL },

	/* ASCII trace files from Telnet sessions. */
	{ "Lucent/Ascend access server trace",      OPEN_INFO_HEURISTIC, ascend_open,              "txt",      NULL, NULL },
	{ "Toshiba Compact ISDN Router snoop",      OPEN_INFO_HEURISTIC, toshiba_open,             "txt",      NULL, NULL },
	/* Extremely weak heuristics - put them at the end. */
	{ "Ixia IxVeriWave .vwr Raw Capture",       OPEN_INFO_HEURISTIC, vwr_open,                 "vwr",      NULL, NULL },
	{ "CAM Inspector file",                     OPEN_INFO_HEURISTIC, camins_open,              "camins",   NULL, NULL },
	{ "JavaScript Object Notation",             OPEN_INFO_HEURISTIC, json_open,                "json",     NULL, NULL },
	{ "Ruby Marshal Object",                    OPEN_INFO_HEURISTIC, ruby_marshal_open,        "",         NULL, NULL },
	{ "3gpp phone log",                         OPEN_INFO_MAGIC,     log3gpp_open,             "log",      NULL, NULL },
	{ "MP4 media file",                         OPEN_INFO_MAGIC,     mp4_open,                 "mp4",      NULL, NULL },

};

/* this is only used to build the dynamic array on load, do NOT use this
 * for anything else, because the size of the actual array will change if
 * Lua scripts register a new file reader.
 */
#define N_OPEN_INFO_ROUTINES  ((sizeof open_info_base / sizeof open_info_base[0]))

static GArray *open_info_arr = NULL;

/* this always points to the top of the created array */
struct open_info *open_routines = NULL;

/* this points to the first OPEN_INFO_HEURISTIC type in the array */
static guint heuristic_open_routine_idx = 0;

static void
set_heuristic_routine(void)
{
	guint i;
	ws_assert(open_info_arr != NULL);

	for (i = 0; i < open_info_arr->len; i++) {
		if (open_routines[i].type == OPEN_INFO_HEURISTIC) {
			heuristic_open_routine_idx = i;
			break;
		}
		/* sanity check */
		ws_assert(open_routines[i].type == OPEN_INFO_MAGIC);
	}

	ws_assert(heuristic_open_routine_idx > 0);
}

void
init_open_routines(void)
{
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

/*
 * Registers a new file reader - currently only called by wslua code for Lua readers.
 * If first_routine is true, it's added before other readers of its type (magic or heuristic).
 * Also, it checks for an existing reader of the same name and errors if it finds one; if
 * you want to handle that condition more gracefully, call wtap_has_open_info() first.
 */
void
wtap_register_open_info(struct open_info *oi, const gboolean first_routine)
{
	if (!oi || !oi->name) {
		ws_error("No open_info name given to register");
		return;
	}

	/* verify name doesn't already exist */
	if (wtap_has_open_info(oi->name)) {
		ws_error("Name given to register_open_info already exists");
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
void
wtap_deregister_open_info(const gchar *name)
{
	guint i;

	if (!name) {
		ws_error("Missing open_info name to de-register");
		return;
	}

	for (i = 0; i < open_info_arr->len; i++) {
		if (open_routines[i].name && strcmp(open_routines[i].name, name) == 0) {
			g_strfreev(open_routines[i].extensions_set);
			open_info_arr = g_array_remove_index(open_info_arr, i);
			set_heuristic_routine();
			return;
		}
	}

	ws_error("deregister_open_info: name not found");
}

/* Determines if a open routine short name already exists
 */
gboolean
wtap_has_open_info(const gchar *name)
{
	guint i;

	if (!name) {
		ws_error("No name given to wtap_has_open_info!");
		return FALSE;
	}


	for (i = 0; i < open_info_arr->len; i++) {
		if (open_routines[i].name && strcmp(open_routines[i].name, name) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

gboolean
wtap_uses_lua_filehandler(const wtap* wth)
{
	if (wth && wth->wslua_data != NULL) {
		/*
		 * Currently, wslua_data is set if and only if using a Lua
		 * file handler.
		 */
		return TRUE;
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
unsigned int
open_info_name_to_type(const char *name)
{
	unsigned int i;

	if (!name)
		return WTAP_TYPE_AUTO;

	for (i = 0; i < open_info_arr->len; i++) {
		if (open_routines[i].name != NULL &&
		    strcmp(name, open_routines[i].name) == 0)
			return i+1;
	}

	return WTAP_TYPE_AUTO; /* no such file type */
}

static char *
get_file_extension(const char *pathname)
{
	gchar *filename;
	gchar **components;
	size_t ncomponents;
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
	 * Get compression-type extensions, if any.
	 */
	GSList *compression_type_extensions = wtap_get_all_compression_type_extensions_list();

	/*
	 * Is the last component one of the extensions used for compressed
	 * files?
	 */
	extensionp = components[ncomponents - 1];
	for (GSList *compression_type_extension = compression_type_extensions;
	    compression_type_extension != NULL;
	    compression_type_extension = g_slist_next(compression_type_extension)) {
		if (strcmp(extensionp, (const char *)compression_type_extension->data) == 0) {
			/*
			 * Yes, so it's one of the compressed-file extensions.
			 * Is there an extension before that?
			 */
			if (ncomponents == 2) {
				g_slist_free(compression_type_extensions);
				g_strfreev(components);
				return NULL;	/* no, only two components */
			}

			/*
			 * Yes, return that extension.
			 */
			g_slist_free(compression_type_extensions);
			extensionp = g_strdup(components[ncomponents - 2]);
			g_strfreev(components);
			return extensionp;
		}
	}

	g_slist_free(compression_type_extensions);

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
static gboolean
heuristic_uses_extension(unsigned int i, const char *extension)
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
wtap *
wtap_open_offline(const char *filename, unsigned int type, int *err, char **err_info,
		  gboolean do_random)
{
	int	fd;
	ws_statb64 statb;
	gboolean ispipe = FALSE;
	wtap	*wth;
	unsigned int	i;
	gboolean use_stdin = FALSE;
	gchar *extension;
	wtap_block_t shb;

	*err = 0;
	*err_info = NULL;

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
		 * Currently, we do seeking when trying to find out
		 * the file type, but our I/O routines do some amount
		 * of buffering, and do backward seeks within the buffer
		 * if possible, so at least some file types can be
		 * opened from pipes, so we don't completely disallow opens
		 * of pipes.
		 */
		if (do_random) {
			*err = WTAP_ERR_RANDOM_OPEN_PIPE;
			return NULL;
		}
		ispipe = TRUE;
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
	wth = g_new0(wtap, 1);

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
	wth->ispipe = ispipe;
	wth->file_encap = WTAP_ENCAP_UNKNOWN;
	wth->subtype_sequential_close = NULL;
	wth->subtype_close = NULL;
	wth->file_tsprec = WTAP_TSPREC_USEC;
	wth->pathname = g_strdup(filename);
	wth->priv = NULL;
	wth->wslua_data = NULL;
	wth->shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
	shb = wtap_block_create(WTAP_BLOCK_SECTION);
	if (shb)
		g_array_append_val(wth->shb_hdrs, shb);

	/* Initialize the array containing a list of interfaces. pcapng_open and
	 * erf_open needs this (and libpcap_open for ERF encapsulation types).
	 * Always initing it here saves checking for a NULL ptr later. */
	wth->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
	/*
	 * Next interface data that wtap_get_next_interface_description()
	 * will return.
	 */
	wth->next_interface_data = 0;

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
			case WTAP_OPEN_ERROR:
				/* Error - give up */
				wtap_close(wth);
				return NULL;

			case WTAP_OPEN_NOT_MINE:
				/* No error, but not that type of file */
				goto fail;

			case WTAP_OPEN_MINE:
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
			/* Error - give up */
			wtap_close(wth);
			return NULL;
		}

		/* Set wth with wslua data if any - this is how we pass the data
		 * to the file reader, kinda like the priv member but not free'd later.
		 * It's ok for this to copy a NULL.
		 */
		wth->wslua_data = open_routines[i].wslua_data;

		switch ((*open_routines[i].open_routine)(wth, err, err_info)) {

		case WTAP_OPEN_ERROR:
			/* Error - give up */
			wtap_close(wth);
			return NULL;

		case WTAP_OPEN_NOT_MINE:
			/* No error, but not that type of file */
			break;

		case WTAP_OPEN_MINE:
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
					/* Error - give up */
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

				case WTAP_OPEN_ERROR:
					/* Error - give up */
					g_free(extension);
					wtap_close(wth);
					return NULL;

				case WTAP_OPEN_NOT_MINE:
					/* No error, but not that type of file */
					break;

				case WTAP_OPEN_MINE:
					/* We found the file type */
					g_free(extension);
					goto success;
				}
			}
		}

		/*
		 * Now try the heuristic types that have no extensions
		 * to check; we try those before the ones that have
		 * extensions that *don't* match this file's extension,
		 * on the theory that files of those types generally
		 * have one of the type's extensions, and, as this file
		 * *doesn't* have one of those extensions, it's probably
		 * *not* one of those files.
		 */
		for (i = heuristic_open_routine_idx; i < open_info_arr->len; i++) {
			/* Does this type have any extensions? */
			if (open_routines[i].extensions == NULL) {
				/* No. */
				if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
					/* Error - give up */
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

				case WTAP_OPEN_ERROR:
					/* Error - give up */
					g_free(extension);
					wtap_close(wth);
					return NULL;

				case WTAP_OPEN_NOT_MINE:
					/* No error, but not that type of file */
					break;

				case WTAP_OPEN_MINE:
					/* We found the file type */
					g_free(extension);
					goto success;
				}
			}
		}

		/*
		 * Now try the ones that have extensions where none of
		 * them matches this file's extensions.
		 */
		for (i = heuristic_open_routine_idx; i < open_info_arr->len; i++) {
			/*
			 * Does this type have extensions and is this file's
			 * extension one of them?
			 */
			if (open_routines[i].extensions != NULL &&
			    !heuristic_uses_extension(i, extension)) {
				/* Yes and no. */
				if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
					/* Error - give up */
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

				case WTAP_OPEN_ERROR:
					/* Error - give up */
					g_free(extension);
					wtap_close(wth);
					return NULL;

				case WTAP_OPEN_NOT_MINE:
					/* No error, but not that type of file */
					break;

				case WTAP_OPEN_MINE:
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
				/* Error - give up */
				wtap_close(wth);
				return NULL;
			}

			/* Set wth with wslua data if any - this is how we pass the data
			 * to the file reader, kind of like priv but not free'd later.
			 */
			wth->wslua_data = open_routines[i].wslua_data;

			switch ((*open_routines[i].open_routine)(wth, err, err_info)) {

			case WTAP_OPEN_ERROR:
				/* Error - give up */
				wtap_close(wth);
				return NULL;

			case WTAP_OPEN_NOT_MINE:
				/* No error, but not that type of file */
				break;

			case WTAP_OPEN_MINE:
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
	if (strcmp(filename, wth->pathname) != 0) {
		g_free(wth->pathname);
		wth->pathname = g_strdup(filename);
	}
	return TRUE;
}

/* Table of the file types and subtypes for which we have support. */

/*
 * Pointer to the GArray holding the registered file types.
 */
static GArray*  file_type_subtype_table_arr;

/*
 * Pointer to the table of registered file types in that GArray.
 */
static const struct file_type_subtype_info* file_type_subtype_table;

/*
 * Number of elements in the table for builtin file types/subtypes.
 */
static guint wtap_num_builtin_file_types_subtypes;

/*
 * Required builtin types.
 */
int pcap_file_type_subtype = -1;
int pcap_nsec_file_type_subtype = -1;
int pcapng_file_type_subtype = -1;

/*
 * Table for mapping old file type/subtype names to new ones for
 * backwards compatibility.
 */
static GHashTable *type_subtype_name_map;

/*
 * Initialize the table of file types/subtypes with all the builtin
 * types/subtypes.
 */
void
wtap_init_file_type_subtypes(void)
{
	/* Don't do this twice. */
	ws_assert(file_type_subtype_table_arr == NULL);

	/*
	 * Estimate the number of file types/subtypes as twice the
	 * number of modules; that's probably an overestimate, as
	 * the average number of file types/subtypes registered by
	 * a module is > 1 but probably < 2, but that shouldn't
	 * waste too much memory.
	 *
	 * Add on 7 more for pcapng, pcap, nanosecond pcap, and the
	 * extra modified flavors of pcap.
	 */
	file_type_subtype_table_arr = g_array_sized_new(FALSE, TRUE,
	    sizeof(struct file_type_subtype_info), wtap_module_count*2 + 7);
	file_type_subtype_table = (const struct file_type_subtype_info*)(void *)file_type_subtype_table_arr->data;

	/*
	 * Initialize the hash table for mapping old file type/subtype
	 * names to the corresponding new names.
	 */
	type_subtype_name_map = g_hash_table_new_full(g_str_hash,
	    g_str_equal, g_free, g_free);

	/* No entries yet, so no builtin entries yet. */
	wtap_num_builtin_file_types_subtypes = 0;

	/*
	 * Register the builtin entries that aren't in the table.
	 * First, do the required ones; register pcapng first, then
	 * pcap, so, at the beginning of the table, we have pcapng,
	 * pcap, nanosecond pcap, and the weird modified pcaps, so
	 * searches for file types that can write a file format
	 * start with pcapng, pcap, and nanosecond pcap.
	 */
	register_pcapng();
	register_pcap();

	/* Now register the ones found by the build process */
	for (guint i = 0; i < wtap_module_count; i++)
		wtap_module_reg[i].cb_func();

	/* Update the number of builtin entries. */
	wtap_num_builtin_file_types_subtypes = file_type_subtype_table_arr->len;
}

/*
 * Attempt to register a new file type/subtype; fails if a type/subtype
 * with that name is already registered.
 */
int
wtap_register_file_type_subtype(const struct file_type_subtype_info* fi)
{
	struct file_type_subtype_info* finfo;
	guint file_type_subtype;

	/*
	 * Check for required fields (description and name).
	 */
	if (!fi || !fi->description || !fi->name) {
		ws_warning("no file type info");
		return -1;
	}

	/*
	 * There must be at least one block type that this file
	 * type/subtype supports.
	 */
	if (fi->num_supported_blocks == 0 || fi->supported_blocks == NULL) {
		ws_warning("no blocks supported by file type \"%s\"", fi->name);
		return -1;
	}

	/*
	 * Is this type already registered?
	 */
	if (wtap_name_to_file_type_subtype(fi->name) != -1) {
		/*
		 * Yes.  You don't get to replace an existing handler.
		 */
		ws_warning("file type \"%s\" is already registered", fi->name);
		return -1;
	}

	/*
	 * Is there a freed entry in the array, due to a file type
	 * being de-registered?
	 *
	 * Skip the built-in entries, as they're never deregistered.
	 */
	for (file_type_subtype = wtap_num_builtin_file_types_subtypes;
	    file_type_subtype < file_type_subtype_table_arr->len;
	    file_type_subtype++) {
		if (file_type_subtype_table[file_type_subtype].name == NULL) {
			/*
			 * We found such an entry.
			 *
			 * Get the pointer from the GArray, so that we get a
			 * non-const pointer.
			 */
			finfo = &g_array_index(file_type_subtype_table_arr, struct file_type_subtype_info, file_type_subtype);

			/*
			 * Fill in the entry with the new values.
			 */
			*finfo = *fi;

			return (gint)file_type_subtype;
		}
	}

	/*
	 * There aren't any free slots, so add a new entry.
	 * Get the number of current number of entries, which will
	 * be the index of the new entry, then append this entry
	 * to the end of the array, change file_type_subtype_table
	 * in case the array had to get reallocated, and return
	 * the index of the new entry.
	 */
	file_type_subtype = file_type_subtype_table_arr->len;
	g_array_append_val(file_type_subtype_table_arr, *fi);
	file_type_subtype_table = (const struct file_type_subtype_info*)(void *)file_type_subtype_table_arr->data;
	return file_type_subtype;
}

/* De-registers a file writer - they can never be removed from the GArray, but we can "clear" an entry.
 */
void
wtap_deregister_file_type_subtype(const int subtype)
{
	struct file_type_subtype_info* finfo;

	if (subtype < 0 || subtype >= (int)file_type_subtype_table_arr->len) {
		ws_error("invalid file type to de-register");
		return;
	}
	if ((guint)subtype < wtap_num_builtin_file_types_subtypes) {
		ws_error("built-in file types cannot be de-registered");
		return;
	}

	/*
	 * Get the pointer from the GArray, so that we get a non-const
	 * pointer.
	 */
	finfo = &g_array_index(file_type_subtype_table_arr, struct file_type_subtype_info, subtype);
	/*
	 * Clear out this entry.
	 */
	finfo->description = NULL;
	finfo->name = NULL;
	finfo->default_file_extension = NULL;
	finfo->additional_file_extensions = NULL;
	finfo->writing_must_seek = FALSE;
	finfo->num_supported_blocks = 0;
	finfo->supported_blocks = NULL;
	finfo->can_write_encap = NULL;
	finfo->dump_open = NULL;
	finfo->wslua_info = NULL;
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

gboolean
wtap_dump_can_write_encap(int file_type_subtype, int encap)
{
	int result = 0;

	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len ||
	    file_type_subtype_table[file_type_subtype].can_write_encap == NULL)
		return FALSE;

	result = (*file_type_subtype_table[file_type_subtype].can_write_encap)(encap);

	if (result != 0) {
		/* if the err said to check wslua's can_write_encap, try that */
		if (result == WTAP_ERR_CHECK_WSLUA
			&& file_type_subtype_table[file_type_subtype].wslua_info != NULL
			&& file_type_subtype_table[file_type_subtype].wslua_info->wslua_can_write_encap != NULL) {

			result = (*file_type_subtype_table[file_type_subtype].wslua_info->wslua_can_write_encap)(encap, file_type_subtype_table[file_type_subtype].wslua_info->wslua_data);

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
	if (required_comment_types & WTAP_COMMENT_PER_SECTION) {
		if (wtap_file_type_subtype_supports_option(ft,
		    WTAP_BLOCK_SECTION, OPT_COMMENT) == OPTION_NOT_SUPPORTED) {
			/* Not section comments. */
			return FALSE;
		}
	}
	if (required_comment_types & WTAP_COMMENT_PER_INTERFACE) {
		if (wtap_file_type_subtype_supports_option(ft,
		    WTAP_BLOCK_IF_ID_AND_INFO, OPT_COMMENT) == OPTION_NOT_SUPPORTED) {
			/* Not interface comments. */
			return FALSE;
		}
	}
	if (required_comment_types & WTAP_COMMENT_PER_PACKET) {
		if (wtap_file_type_subtype_supports_option(ft,
		    WTAP_BLOCK_PACKET, OPT_COMMENT) == OPTION_NOT_SUPPORTED) {
			/* Not packet comments. */
			return FALSE;
		}
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

	for (ft = 0; ft < (int)file_type_subtype_table_arr->len; ft++) {
		/* To save a file with Wiretap, Wiretap has to handle that format,
		 * and its code to handle that format must be able to write a file
		 * with this file's encapsulation types.
		 */
		if (wtap_dump_can_write_format(ft, file_encaps, required_comment_types)) {
			/* OK, we can write it out in this type. */
			return TRUE;
		}
	}

	/* No, we couldn't save it in any format. */
	return FALSE;
}

/*
 * Sort by file type/subtype name.
 */
static int
compare_file_type_subtypes_by_name(gconstpointer a, gconstpointer b)
{
	int file_type_subtype_a = *(const int *)a;
	int file_type_subtype_b = *(const int *)b;

	return strcmp(wtap_file_type_subtype_name(file_type_subtype_a),
	              wtap_file_type_subtype_name(file_type_subtype_b));
}

/*
 * Sort by file type/subtype description.
 */
static int
compare_file_type_subtypes_by_description(gconstpointer a, gconstpointer b)
{
	int file_type_subtype_a = *(const int *)a;
	int file_type_subtype_b = *(const int *)b;

	return strcmp(wtap_file_type_subtype_description(file_type_subtype_a),
	              wtap_file_type_subtype_description(file_type_subtype_b));
}

/**
 * Get a GArray of file type/subtype values for file types/subtypes
 * that can be used to save a file of a given type/subtype with a given
 * GArray of encapsulation types and the given bitmask of comment types.
 */
GArray *
wtap_get_savable_file_types_subtypes_for_file(int file_type_subtype,
    const GArray *file_encaps, guint32 required_comment_types,
    ft_sort_order sort_order)
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
	} else if (wtap_dump_can_write_format(pcap_file_type_subtype,
					      file_encaps,
					      required_comment_types)) {
		/*
		 * No, but we can write it as a pcap file; make that
		 * the default file type/subtype.
		 */
		default_file_type_subtype = pcap_file_type_subtype;
	} else if (wtap_dump_can_write_format(pcapng_file_type_subtype,
					      file_encaps,
					      required_comment_types)) {
		/*
		 * No, but we can write it as a pcapng file; make that
		 * the default file type/subtype.
		 */
		default_file_type_subtype = pcapng_file_type_subtype;
	} else {
		/* OK, find the first file type/subtype we *can* save it as. */
		default_file_type_subtype = -1;
		for (ft = 0; ft < (int)file_type_subtype_table_arr->len; ft++) {
			if (wtap_dump_can_write_format(ft, file_encaps,
						       required_comment_types)) {
				/* OK, got it. */
				default_file_type_subtype = ft;
				break;
			}
		}
	}

	if (default_file_type_subtype == -1) {
		/* We don't support writing this file as any file type/subtype. */
		return NULL;
	}

	/*
	 * If the default is pcap, put pcapng right after it if we can
	 * also write it in pcapng format; otherwise, if the default is
	 * pcapng, put pcap right after it if we can also write it in
	 * pcap format.
	 */
	if (default_file_type_subtype == pcap_file_type_subtype) {
		if (wtap_dump_can_write_format(pcapng_file_type_subtype,
		                               file_encaps,
		                               required_comment_types))
			other_file_type_subtype = pcapng_file_type_subtype;
	} else if (default_file_type_subtype == pcapng_file_type_subtype) {
		if (wtap_dump_can_write_format(pcap_file_type_subtype,
		                               file_encaps,
					       required_comment_types))
			other_file_type_subtype = pcap_file_type_subtype;
	}

	/* Allocate the array. */
	savable_file_types_subtypes = g_array_new(FALSE, FALSE,
	    sizeof (int));

	/*
	 * First, add the types we don't want to force to the
	 * beginning of the list.
	 */
	for (ft = 0; ft < (int)file_type_subtype_table_arr->len; ft++) {
		if (ft == default_file_type_subtype ||
		    ft == other_file_type_subtype)
			continue;	/* we will done this one later */
		if (wtap_dump_can_write_format(ft, file_encaps,
					       required_comment_types)) {
			/* OK, we can write it out in this type. */
			g_array_append_val(savable_file_types_subtypes, ft);
		}
	}

	/* Now, sort the list. */
	g_array_sort(savable_file_types_subtypes,
	    (sort_order == FT_SORT_BY_NAME) ? compare_file_type_subtypes_by_name :
	                                      compare_file_type_subtypes_by_description);

	/*
	 * If we have a type/subtype to put above the default one,
	 * do so.
	 *
	 * We put this type at the beginning before putting the
	 * default there, so the default is at the top.
	 */
	if (other_file_type_subtype != -1)
		g_array_prepend_val(savable_file_types_subtypes,
		    other_file_type_subtype);

	/* Put the default file type/subtype first in the list. */
	g_array_prepend_val(savable_file_types_subtypes,
	    default_file_type_subtype);

	return savable_file_types_subtypes;
}

/**
 * Get a GArray of all writable file type/subtype values.
 */
GArray *
wtap_get_writable_file_types_subtypes(ft_sort_order sort_order)
{
	GArray *writable_file_types_subtypes;
	int ft;

	/*
	 * Allocate the array.
	 * Pre-allocate room enough for all types.
	 * XXX - that's overkill; just scan the table to find all the
	 * writable types and count them.
	 */
	writable_file_types_subtypes = g_array_sized_new(FALSE, FALSE,
	    sizeof (int), file_type_subtype_table_arr->len);

	/*
	 * First, add the types we don't want to force to the
	 * beginning of the list.
	 */
	for (ft = 0; ft < (int)file_type_subtype_table_arr->len; ft++) {
		if (ft == pcap_file_type_subtype ||
		    ft == pcapng_file_type_subtype)
			continue;	/* we've already done these two */
		if (wtap_dump_can_open(ft)) {
			/* OK, we can write this type. */
			g_array_append_val(writable_file_types_subtypes, ft);
		}
	}

	/* Now, sort the list. */
	g_array_sort(writable_file_types_subtypes,
	    (sort_order == FT_SORT_BY_NAME) ? compare_file_type_subtypes_by_name :
	                                      compare_file_type_subtypes_by_description);

	/*
	 * Now, put pcap and pcapng at the beginning, as they're
	 * our "native" formats.  Put pcapng there first, and
	 * pcap before it.
	 */
	if (pcapng_file_type_subtype != -1 &&
	    wtap_dump_can_open(pcapng_file_type_subtype)) {
		/*
		 * We can write pcapng.  (If we can't, that's a huge
		 * mistake.)
		 */
		g_array_prepend_val(writable_file_types_subtypes,
		    pcapng_file_type_subtype);
	}
	if (pcap_file_type_subtype != -1 &&
	    wtap_dump_can_open(pcap_file_type_subtype)) {
		/*
		 * We can write pcap.  (If we can't, that's a huge
		 * mistake.)
		 */
		g_array_prepend_val(writable_file_types_subtypes,
		    pcap_file_type_subtype);
	}

	return writable_file_types_subtypes;
}

/* String describing the file type/subtype. */
const char *
wtap_file_type_subtype_description(int file_type_subtype)
{
	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len)
		return NULL;
	else
		return file_type_subtype_table[file_type_subtype].description;
}

/* Name to use in, say, a command-line flag specifying the type/subtype. */
const char *
wtap_file_type_subtype_name(int file_type_subtype)
{
	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len)
		return NULL;
	else
		return file_type_subtype_table[file_type_subtype].name;
}

/*
 * Register a backwards-compatibility name.
 */
void
wtap_register_compatibility_file_subtype_name(const char *old_name,
    const char *new_name)
{
	g_hash_table_insert(type_subtype_name_map, g_strdup(old_name),
	    g_strdup(new_name));
}

/* Translate a name to a capture file type/subtype. */
int
wtap_name_to_file_type_subtype(const char *name)
{
	char *new_name;
	int file_type_subtype;

	/*
	 * Is this name a backwards-compatibility name?
	 */
	new_name = (char *)g_hash_table_lookup(type_subtype_name_map,
	    (gpointer)name);
	if (new_name != NULL) {
		/*
		 * Yes, and new_name is the name to which it should
		 * be mapped.
		 */
		name = new_name;
	}
	for (file_type_subtype = 0;
	    file_type_subtype < (int)file_type_subtype_table_arr->len;
	    file_type_subtype++) {
		if (file_type_subtype_table[file_type_subtype].name != NULL &&
		    strcmp(name, file_type_subtype_table[file_type_subtype].name) == 0)
			return file_type_subtype;
	}

	return -1;	/* no such file type, or we can't write it */
}

/*
 * Provide the file type/subtype for pcap.
 */
int
wtap_pcap_file_type_subtype(void)
{
	/*
	 * Make sure pcap was registered as a file type/subtype;
	 * it's one of our "native" formats.
	 */
	ws_assert(pcap_file_type_subtype != -1);
	return pcap_file_type_subtype;
}

/*
 * Provide the file type/subtype for nanosecond-resolution pcap.
 */
int
wtap_pcap_nsec_file_type_subtype(void)
{
	/*
	 * Make sure nanosecond-resolution pcap was registered
	 * as a file type/subtype; it's one of our "native" formats.
	 */
	ws_assert(pcap_nsec_file_type_subtype != -1);
	return pcap_nsec_file_type_subtype;
}

/*
 * Provide the file type/subtype for pcapng.
 */
int
wtap_pcapng_file_type_subtype(void)
{
	/*
	 * Make sure pcapng was registered as a file type/subtype;
	 * it's one of our "native" formats.
	 */
	ws_assert(pcapng_file_type_subtype != -1);
	return pcapng_file_type_subtype;
}

block_support_t
wtap_file_type_subtype_supports_block(int file_type_subtype,
    wtap_block_type_t type)
{
	size_t num_supported_blocks;
	const struct supported_block_type *supported_blocks;

	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len) {
		/*
		 * There's no such file type, so it can't support any
		 * blocks.
		 */
		return BLOCK_NOT_SUPPORTED;
	}

	num_supported_blocks = file_type_subtype_table[file_type_subtype].num_supported_blocks;
	supported_blocks = file_type_subtype_table[file_type_subtype].supported_blocks;

	for (size_t block_idx = 0; block_idx < num_supported_blocks;
	    block_idx++) {
		if (supported_blocks[block_idx].type == type)
			return supported_blocks[block_idx].support;
	}

	/*
	 * Not found, which means not supported.
	 */
	return BLOCK_NOT_SUPPORTED;
}

option_support_t
wtap_file_type_subtype_supports_option(int file_type_subtype,
    wtap_block_type_t type, guint option)
{
	size_t num_supported_blocks;
	const struct supported_block_type *supported_blocks;

	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len) {
		/*
		 * There's no such file type, so it can't support any
		 * blocks, and thus can't support any options.
		 */
		return OPTION_NOT_SUPPORTED;
	}

	num_supported_blocks = file_type_subtype_table[file_type_subtype].num_supported_blocks;
	supported_blocks = file_type_subtype_table[file_type_subtype].supported_blocks;

	for (size_t block_idx = 0; block_idx < num_supported_blocks;
	    block_idx++) {
		if (supported_blocks[block_idx].type == type) {
			/*
			 * OK, that block is known.
			 * Is it supported?
			 */
			if (supported_blocks[block_idx].support == BLOCK_NOT_SUPPORTED) {
				/*
				 * No, so clearly the option isn't
				 * supported in that block.
				 */
				return OPTION_NOT_SUPPORTED;
			}

			/*
			 * Yes, so check the options.
			 */
			size_t num_supported_options;
			const struct supported_option_type *supported_options;

			num_supported_options = supported_blocks[block_idx].num_supported_options;
			supported_options = supported_blocks[block_idx].supported_options;
			for (size_t opt_idx = 0; opt_idx < num_supported_options;
			    opt_idx++) {
				if (supported_options[opt_idx].opt == option)
					return supported_options[opt_idx].support;
			}

			/*
			 * Not found, which means not supported.
			 */
			return OPTION_NOT_SUPPORTED;
		}
	}

	/*
	 * The block type wasn't found, which means it's not supported,
	 * which means the option isn't supported in that block.
	 */
	return OPTION_NOT_SUPPORTED;
}

static GSList *
add_extensions_for_file_type_subtype(int file_type_subtype, GSList *extensions,
    GSList *compression_type_extensions)
{
	gchar **extensions_set, **extensionp;
	gchar *extension;

	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len) {
		/*
		 * There's no such file type, so it has no extensions
		 * to add.
		 */
		return extensions;
	}

	/*
	 * Add the default extension, and all of the compressed variants
	 * from the list of compressed-file extensions, if there is a
	 * default extension.
	 */
	if (file_type_subtype_table[file_type_subtype].default_file_extension != NULL) {
		extensions = add_extensions(extensions,
		    file_type_subtype_table[file_type_subtype].default_file_extension,
		    compression_type_extensions);
	}

	if (file_type_subtype_table[file_type_subtype].additional_file_extensions != NULL) {
		/*
		 * We have additional extensions; add them.
		 *
		 * First, split the extension-list string into a set of
		 * extensions.
		 */
		extensions_set = g_strsplit(file_type_subtype_table[file_type_subtype].additional_file_extensions,
		    ";", 0);

		/*
		 * Add each of those extensions to the list.
		 */
		for (extensionp = extensions_set; *extensionp != NULL;
		    extensionp++) {
			extension = *extensionp;

			/*
			 * Add the extension, and all compressed variants
			 * of it if requested.
			 */
			extensions = add_extensions(extensions, extension,
			    compression_type_extensions);
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
GSList *
wtap_get_file_extensions_list(int file_type_subtype, gboolean include_compressed)
{
	GSList *extensions, *compression_type_extensions;

	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len)
		return NULL;	/* not a valid file type */

	if (file_type_subtype_table[file_type_subtype].default_file_extension == NULL)
		return NULL;	/* valid, but no extensions known */

	extensions = NULL;	/* empty list, to start with */

	/*
	 * Add all this file type's extensions, with compressed
	 * variants if include_compressed is true.
	 */
	if (include_compressed) {
		/*
		 * Get compression-type extensions, if any.
		 */
		compression_type_extensions = wtap_get_all_compression_type_extensions_list();
	} else {
		/*
		 * We don't want the compressed file extensions.
		 */
		compression_type_extensions = NULL;
	}
	extensions = add_extensions_for_file_type_subtype(file_type_subtype, extensions,
	    compression_type_extensions);

	g_slist_free(compression_type_extensions);

	return extensions;
}

/* Return a list of all extensions that are used by all file types that
   we can read, including compressed extensions, e.g. not just "pcap" but
   also "pcap.gz" if we can read gzipped files.

   "File type" means "include file types that correspond to collections
   of network packets, as well as file types that store data that just
   happens to be transported over protocols such as HTTP but that aren't
   collections of network packets, and plain text files".

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *
wtap_get_all_file_extensions_list(void)
{
	GSList *extensions, *compression_type_extensions;

	extensions = NULL;	/* empty list, to start with */

	/*
	 * Get compression-type extensions, if any.
	 */
	compression_type_extensions = wtap_get_all_compression_type_extensions_list();

	for (int ft = 0; ft < (int)file_type_subtype_table_arr->len; ft++) {
		extensions = add_extensions_for_file_type_subtype(ft, extensions,
		    compression_type_extensions);
	}

	g_slist_free(compression_type_extensions);

	return extensions;
}

/*
 * Free a list returned by wtap_get_file_extension_type_extensions(),
 * wtap_get_all_capture_file_extensions_list, wtap_get_file_extensions_list(),
 * or wtap_get_all_file_extensions_list().
 */
void
wtap_free_extensions_list(GSList *extensions)
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
const char *
wtap_default_file_extension(int file_type_subtype)
{
	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len)
		return NULL;
	else
		return file_type_subtype_table[file_type_subtype].default_file_extension;
}

gboolean
wtap_dump_can_open(int file_type_subtype)
{
	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len ||
	    file_type_subtype_table[file_type_subtype].dump_open == NULL)
		return FALSE;

	return TRUE;
}

#ifdef HAVE_ZLIB
gboolean
wtap_dump_can_compress(int file_type_subtype)
{
	/*
	 * If this is an unknown file type, or if we have to
	 * seek when writing out a file with this file type,
	 * return FALSE.
	 */
	if (file_type_subtype < 0 ||
	    file_type_subtype >= (int)file_type_subtype_table_arr->len ||
	    file_type_subtype_table[file_type_subtype].writing_must_seek)
		return FALSE;

	return TRUE;
}
#else
gboolean
wtap_dump_can_compress(int file_type_subtype _U_)
{
	return FALSE;
}
#endif

static gboolean wtap_dump_open_finish(wtap_dumper *wdh, int *err,
				      gchar **err_info);

static WFILE_T wtap_dump_file_open(wtap_dumper *wdh, const char *filename);
static WFILE_T wtap_dump_file_fdopen(wtap_dumper *wdh, int fd);
static int wtap_dump_file_close(wtap_dumper *wdh);

static wtap_dumper *
wtap_dump_init_dumper(int file_type_subtype, wtap_compression_type compression_type,
                      const wtap_dump_params *params, int *err)
{
	wtap_dumper *wdh;
	wtap_block_t descr, file_int_data;
	wtapng_if_descr_mandatory_t *descr_mand, *file_int_data_mand;
	GArray *interfaces = params->idb_inf ? params->idb_inf->interface_data : NULL;

	/* Can we write files of this file type/subtype?
	 *
	 * This will fail if file_type_subtype isn't a valid
	 * file type/subtype value, so, if it doesn't fail,
	 * we know file_type_subtype is within the bounds of
	 * the table of file types/subtypes. */
	if (!wtap_dump_can_open(file_type_subtype)) {
		/* Invalid type, or type we don't know how to write. */
		*err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
		return FALSE;
	}

	/* OK, we know how to write that file type/subtype; can we write
	   the specified encapsulation type in that file type/subtype? */
	*err = (*file_type_subtype_table[file_type_subtype].can_write_encap)(params->encap);
	/* if the err said to check wslua's can_write_encap, try that */
	if (*err == WTAP_ERR_CHECK_WSLUA
		&& file_type_subtype_table[file_type_subtype].wslua_info != NULL
		&& file_type_subtype_table[file_type_subtype].wslua_info->wslua_can_write_encap != NULL) {

		*err = (*file_type_subtype_table[file_type_subtype].wslua_info->wslua_can_write_encap)(params->encap, file_type_subtype_table[file_type_subtype].wslua_info->wslua_data);
	}

	if (*err != 0) {
		/* No, we can't. */
		return NULL;
	}

	/* Check whether we can open a capture file with that file type
	   and that encapsulation, and, if the compression type isn't
	   "uncompressed", whether we can write a *compressed* file
	   of that file type. */
	/* If we're doing compression, can this file type/subtype be
	   written in compressed form?

	   (The particular type doesn't matter - if the file can't
	   be written 100% sequentially, we can't compress it,
	   because we can't go back and overwrite something we've
	   already written. */
	if (compression_type != WTAP_UNCOMPRESSED &&
	    !wtap_dump_can_compress(file_type_subtype)) {
		*err = WTAP_ERR_COMPRESSION_NOT_SUPPORTED;
		return NULL;
	}

	/* Allocate a data structure for the output stream. */
	wdh = g_new0(wtap_dumper, 1);
	if (wdh == NULL) {
		*err = errno;
		return NULL;
	}

	wdh->file_type_subtype = file_type_subtype;
	wdh->snaplen = params->snaplen;
	wdh->encap = params->encap;
	wdh->compression_type = compression_type;
	wdh->wslua_data = NULL;
	wdh->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

	/* Set Section Header Block data */
	wdh->shb_hdrs = params->shb_hdrs;
	/* Set Name Resolution Block data */
	wdh->nrb_hdrs = params->nrb_hdrs;
	/* Set Interface Description Block data */
	if (interfaces && interfaces->len) {
		if (!params->dont_copy_idbs) {	/* XXX */
			guint itf_count;

			/* Note: this memory is owned by wtap_dumper and will become
			 * invalid after wtap_dump_close. */
			for (itf_count = 0; itf_count < interfaces->len; itf_count++) {
				file_int_data = g_array_index(interfaces, wtap_block_t, itf_count);
				file_int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(file_int_data);
				descr = wtap_block_make_copy(file_int_data);
				if ((params->encap != WTAP_ENCAP_PER_PACKET) && (params->encap != file_int_data_mand->wtap_encap)) {
					descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(descr);
					descr_mand->wtap_encap = params->encap;
				}
				g_array_append_val(wdh->interface_data, descr);
			}
		}
	} else {
		int snaplen;

		// XXX IDBs should be optional.
		descr = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
		descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(descr);
		descr_mand->wtap_encap = params->encap;
		descr_mand->tsprecision = params->tsprec;
		switch (params->tsprec) {

		case WTAP_TSPREC_SEC:
			descr_mand->time_units_per_second = 1;
			wtap_block_add_uint8_option(descr, OPT_IDB_TSRESOL, 0);
			break;

		case WTAP_TSPREC_DSEC:
			descr_mand->time_units_per_second = 10;
			wtap_block_add_uint8_option(descr, OPT_IDB_TSRESOL, 1);
			break;

		case WTAP_TSPREC_CSEC:
			descr_mand->time_units_per_second = 100;
			wtap_block_add_uint8_option(descr, OPT_IDB_TSRESOL, 2);
			break;

		case WTAP_TSPREC_MSEC:
			descr_mand->time_units_per_second = 1000;
			wtap_block_add_uint8_option(descr, OPT_IDB_TSRESOL, 3);
			break;

		case WTAP_TSPREC_USEC:
			descr_mand->time_units_per_second = 1000000;
			/* This is the default, so we save a few bytes by not adding the option. */
			break;

		case WTAP_TSPREC_NSEC:
			descr_mand->time_units_per_second = 1000000000;
			wtap_block_add_uint8_option(descr, OPT_IDB_TSRESOL, 9);
			break;

		default:
			descr_mand->time_units_per_second = 1000000; /* default microsecond resolution */
			break;
		}
		snaplen = params->snaplen;
		if (snaplen == 0) {
			/*
			 * No snapshot length was specified.  Pick an
			 * appropriate snapshot length for this
			 * link-layer type.
			 *
			 * We use WTAP_MAX_PACKET_SIZE_STANDARD for everything except
			 * D-Bus, which has a maximum packet size of 128MB,
			 * and EBHSCR, which has a maximum packet size of 8MB,
			 * which is more than we want to put into files
			 * with other link-layer header types, as that
			 * might cause some software reading those files
			 * to allocate an unnecessarily huge chunk of
			 * memory for a packet buffer.
			 */
			if (params->encap == WTAP_ENCAP_DBUS)
				snaplen = 128*1024*1024;
			else if (params->encap == WTAP_ENCAP_EBHSCR)
				snaplen = 8*1024*1024;
			else
				snaplen = WTAP_MAX_PACKET_SIZE_STANDARD;
		}
		descr_mand->snap_len = snaplen;
		descr_mand->num_stat_entries = 0;          /* Number of ISB:s */
		descr_mand->interface_statistics = NULL;
		g_array_append_val(wdh->interface_data, descr);
	}
	/* Set Decryption Secrets Blocks */
	wdh->dsbs_initial = params->dsbs_initial;
	wdh->dsbs_growing = params->dsbs_growing;
	return wdh;
}

wtap_dumper *
wtap_dump_open(const char *filename, int file_type_subtype,
    wtap_compression_type compression_type, const wtap_dump_params *params,
    int *err, gchar **err_info)
{
	wtap_dumper *wdh;
	WFILE_T fh;

	*err = 0;
	*err_info = NULL;

	/* Allocate and initialize a data structure for the output stream. */
	wdh = wtap_dump_init_dumper(file_type_subtype, compression_type, params,
	    err);
	if (wdh == NULL)
		return NULL;

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

	if (!wtap_dump_open_finish(wdh, err, err_info)) {
		/* Get rid of the file we created; we couldn't finish
		   opening it. */
		wtap_dump_file_close(wdh);
		ws_unlink(filename);
		g_free(wdh);
		return NULL;
	}
	return wdh;
}

wtap_dumper *
wtap_dump_open_tempfile(const char *tmpdir, char **filenamep, const char *pfx,
    int file_type_subtype, wtap_compression_type compression_type,
    const wtap_dump_params *params, int *err, gchar **err_info)
{
	int fd;
	const char *ext;
	char sfx[16];
	wtap_dumper *wdh;
	WFILE_T fh;

	/* No path name for the temporary file yet. */
	*filenamep = NULL;

	*err = 0;
	*err_info = NULL;

	/* Allocate and initialize a data structure for the output stream. */
	wdh = wtap_dump_init_dumper(file_type_subtype, compression_type, params,
	    err);
	if (wdh == NULL)
		return NULL;

	/* Choose an appropriate suffix for the file */
	ext = wtap_default_file_extension(file_type_subtype);
	if (ext == NULL)
		ext = "tmp";
	sfx[0] = '.';
	sfx[1] = '\0';
	(void) g_strlcat(sfx, ext, 16);

	/* Choose a random name for the file */
	fd = create_tempfile(tmpdir, filenamep, pfx, sfx, NULL);
	if (fd == -1) {
		*err = WTAP_ERR_CANT_OPEN;
		g_free(wdh);
		return NULL;	/* can't create file */
	}

	/* In case "fopen()" fails but doesn't set "errno", set "errno"
	   to a generic "the open failed" error. */
	errno = WTAP_ERR_CANT_OPEN;
	fh = wtap_dump_file_fdopen(wdh, fd);
	if (fh == NULL) {
		*err = errno;
		ws_close(fd);
		g_free(wdh);
		return NULL;	/* can't create file */
	}
	wdh->fh = fh;

	if (!wtap_dump_open_finish(wdh, err, err_info)) {
		/* Get rid of the file we created; we couldn't finish
		   opening it. */
		wtap_dump_file_close(wdh);
		ws_unlink(*filenamep);
		g_free(wdh);
		return NULL;
	}
	return wdh;
}

wtap_dumper *
wtap_dump_fdopen(int fd, int file_type_subtype, wtap_compression_type compression_type,
    const wtap_dump_params *params, int *err, gchar **err_info)
{
	wtap_dumper *wdh;
	WFILE_T fh;

	*err = 0;
	*err_info = NULL;

	/* Allocate and initialize a data structure for the output stream. */
	wdh = wtap_dump_init_dumper(file_type_subtype, compression_type, params,
	    err);
	if (wdh == NULL)
		return NULL;

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

	if (!wtap_dump_open_finish(wdh, err, err_info)) {
		wtap_dump_file_close(wdh);
		g_free(wdh);
		return NULL;
	}
	return wdh;
}

wtap_dumper *
wtap_dump_open_stdout(int file_type_subtype, wtap_compression_type compression_type,
    const wtap_dump_params *params, int *err, gchar **err_info)
{
	int new_fd;
	wtap_dumper *wdh;

	/*
	 * Duplicate the file descriptor, so that we can close the
	 * wtap_dumper handle the same way we close any other
	 * wtap_dumper handle, without closing the standard output.
	 */
	new_fd = ws_dup(1);
	if (new_fd == -1) {
		/* dup failed */
		*err = errno;
		return NULL;
	}
#ifdef _WIN32
	/*
	 * Put the new descriptor into binary mode.
	 *
	 * XXX - even if the file format we're writing is a text
	 * format?
	 */
	if (_setmode(new_fd, O_BINARY) == -1) {
		/* "Should not happen" */
		*err = errno;
		ws_close(new_fd);
		return NULL;
	}
#endif

	wdh = wtap_dump_fdopen(new_fd, file_type_subtype, compression_type,
	    params, err, err_info);
	if (wdh == NULL) {
		/* Failed; close the new FD */
		ws_close(new_fd);
		return NULL;
	}
	return wdh;
}

static gboolean
wtap_dump_open_finish(wtap_dumper *wdh, int *err, gchar **err_info)
{
	int fd;
	gboolean cant_seek;

	/* Can we do a seek on the file descriptor?
	   If not, note that fact. */
	if (wdh->compression_type != WTAP_UNCOMPRESSED) {
		cant_seek = TRUE;
	} else {
		fd = ws_fileno((FILE *)wdh->fh);
		if (ws_lseek64(fd, 1, SEEK_CUR) == (off_t) -1)
			cant_seek = TRUE;
		else {
			/* Undo the seek. */
			ws_lseek64(fd, 0, SEEK_SET);
			cant_seek = FALSE;
		}
	}

	/* If this file type requires seeking, and we can't seek, fail. */
	if (file_type_subtype_table[wdh->file_type_subtype].writing_must_seek && cant_seek) {
		*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
		return FALSE;
	}

	/* Set wdh with wslua data if any - this is how we pass the data
	 * to the file writer.
	 */
	if (file_type_subtype_table[wdh->file_type_subtype].wslua_info)
		wdh->wslua_data = file_type_subtype_table[wdh->file_type_subtype].wslua_info->wslua_data;

	/* Now try to open the file for writing. */
	if (!(*file_type_subtype_table[wdh->file_type_subtype].dump_open)(wdh, err,
	    err_info)) {
		return FALSE;
	}

	return TRUE;	/* success! */
}

gboolean
wtap_dump_add_idb(wtap_dumper *wdh, wtap_block_t idb, int *err,
                  gchar **err_info)
{
	if (wdh->subtype_add_idb == NULL) {
		/* Not supported. */
		*err = WTAP_ERR_UNWRITABLE_REC_TYPE;
		*err_info = g_strdup("Adding IDBs isn't supported by this file type");
		return FALSE;
	}
	*err = 0;
	*err_info = NULL;
	return (wdh->subtype_add_idb)(wdh, idb, err, err_info);
}

gboolean
wtap_dump(wtap_dumper *wdh, const wtap_rec *rec,
	  const guint8 *pd, int *err, gchar **err_info)
{
	*err = 0;
	*err_info = NULL;
	return (wdh->subtype_write)(wdh, rec, pd, err, err_info);
}

gboolean
wtap_dump_flush(wtap_dumper *wdh, int *err)
{
#ifdef HAVE_ZLIB
	if (wdh->compression_type == WTAP_GZIP_COMPRESSED) {
		if (gzwfile_flush((GZWFILE_T)wdh->fh) == -1) {
			*err = gzwfile_geterr((GZWFILE_T)wdh->fh);
			return FALSE;
		}
	} else
#endif
	{
		if (fflush((FILE *)wdh->fh) == EOF) {
			*err = errno;
			return FALSE;
		}
	}
	return TRUE;
}

gboolean
wtap_dump_close(wtap_dumper *wdh, gboolean *needs_reload,
    int *err, gchar **err_info)
{
	gboolean ret = TRUE;

	*err = 0;
	*err_info = NULL;
	if (wdh->subtype_finish != NULL) {
		/* There's a finish routine for this dump stream. */
		if (!(wdh->subtype_finish)(wdh, err, err_info))
			ret = FALSE;
	}
	errno = WTAP_ERR_CANT_CLOSE;
	if (wtap_dump_file_close(wdh) == EOF) {
		if (ret) {
			/* The per-format finish function succeeded,
			   but the stream close didn't.  Save the
			   reason why, if our caller asked for it. */
			if (err != NULL)
				*err = errno;
		}
		ret = FALSE;
	}
	if (needs_reload != NULL)
		*needs_reload = wdh->needs_reload;
	g_free(wdh->priv);
	wtap_block_array_free(wdh->interface_data);
	wtap_block_array_free(wdh->dsbs_initial);
	g_free(wdh);
	return ret;
}

int
wtap_dump_file_type_subtype(wtap_dumper *wdh)
{
	return wdh->file_type_subtype;
}

gint64
wtap_get_bytes_dumped(wtap_dumper *wdh)
{
	return wdh->bytes_dumped;
}

void
wtap_set_bytes_dumped(wtap_dumper *wdh, gint64 bytes_dumped)
{
	wdh->bytes_dumped = bytes_dumped;
}

gboolean
wtap_addrinfo_list_empty(addrinfo_lists_t *addrinfo_lists)
{
	return (addrinfo_lists == NULL) ||
	    ((addrinfo_lists->ipv4_addr_list == NULL) &&
	     (addrinfo_lists->ipv6_addr_list == NULL));
}

gboolean
wtap_dump_set_addrinfo_list(wtap_dumper *wdh, addrinfo_lists_t *addrinfo_lists)
{
	if (!wdh || wdh->file_type_subtype < 0 ||
	    wdh->file_type_subtype >= (int)file_type_subtype_table_arr->len ||
	    wtap_file_type_subtype_supports_block(wdh->file_type_subtype, WTAP_BLOCK_NAME_RESOLUTION) == BLOCK_NOT_SUPPORTED)
		return FALSE;
	wdh->addrinfo_lists = addrinfo_lists;
	return TRUE;
}

void
wtap_dump_discard_decryption_secrets(wtap_dumper *wdh)
{
	/*
	 * This doesn't free the data, as it might be pointed to
	 * from other structures; it merely marks all of them as
	 * having been written to the file, so that they don't
	 * get written by wtap_dump().
	 *
	 * XXX - our APIs for dealing with some metadata, such as
	 * resolved names, decryption secrets, and interface
	 * statistics is not very well oriented towards one-pass
	 * programs; this needs to be cleaned up.  See bug 15502.
	 */
	if (wdh->dsbs_growing) {
		/*
		 * Pretend we've written all of them.
		 */
		wdh->dsbs_growing_written = wdh->dsbs_growing->len;
	}
}

/* internally open a file for writing (compressed or not) */
#ifdef HAVE_ZLIB
static WFILE_T
wtap_dump_file_open(wtap_dumper *wdh, const char *filename)
{
	if (wdh->compression_type == WTAP_GZIP_COMPRESSED) {
		return gzwfile_open(filename);
	} else {
		return ws_fopen(filename, "wb");
	}
}
#else
static WFILE_T
wtap_dump_file_open(wtap_dumper *wdh _U_, const char *filename)
{
	return ws_fopen(filename, "wb");
}
#endif

/* internally open a file for writing (compressed or not) */
#ifdef HAVE_ZLIB
static WFILE_T
wtap_dump_file_fdopen(wtap_dumper *wdh, int fd)
{
	if (wdh->compression_type == WTAP_GZIP_COMPRESSED) {
		return gzwfile_fdopen(fd);
	} else {
		return ws_fdopen(fd, "wb");
	}
}
#else
static WFILE_T
wtap_dump_file_fdopen(wtap_dumper *wdh _U_, int fd)
{
	return ws_fdopen(fd, "wb");
}
#endif

/* internally writing raw bytes (compressed or not) */
gboolean
wtap_dump_file_write(wtap_dumper *wdh, const void *buf, size_t bufsize, int *err)
{
	size_t nwritten;

#ifdef HAVE_ZLIB
	if (wdh->compression_type == WTAP_GZIP_COMPRESSED) {
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
		errno = WTAP_ERR_CANT_WRITE;
		nwritten = fwrite(buf, 1, bufsize, (FILE *)wdh->fh);
		/*
		 * At least according to the macOS man page,
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
static int
wtap_dump_file_close(wtap_dumper *wdh)
{
#ifdef HAVE_ZLIB
	if (wdh->compression_type == WTAP_GZIP_COMPRESSED)
		return gzwfile_close((GZWFILE_T)wdh->fh);
	else
#endif
		return fclose((FILE *)wdh->fh);
}

gint64
wtap_dump_file_seek(wtap_dumper *wdh, gint64 offset, int whence, int *err)
{
#ifdef HAVE_ZLIB
	if (wdh->compression_type != WTAP_UNCOMPRESSED) {
		*err = WTAP_ERR_CANT_SEEK_COMPRESSED;
		return -1;
	} else
#endif
	{
		if (-1 == ws_fseek64((FILE *)wdh->fh, offset, whence)) {
			*err = errno;
			return -1;
		} else
		{
			return 0;
		}
	}
}

gint64
wtap_dump_file_tell(wtap_dumper *wdh, int *err)
{
	gint64 rval;
#ifdef HAVE_ZLIB
	if (wdh->compression_type != WTAP_UNCOMPRESSED) {
		*err = WTAP_ERR_CANT_SEEK_COMPRESSED;
		return -1;
	} else
#endif
	{
		if (-1 == (rval = ws_ftell64((FILE *)wdh->fh))) {
			*err = errno;
			return -1;
		} else
		{
			return rval;
		}
	}
}

void
cleanup_open_routines(void)
{
	guint i;
	struct open_info *i_open;

	if (open_routines != NULL && open_info_arr) {
		for (i = 0, i_open = open_routines; i < open_info_arr->len; i++, i_open++) {
			if (i_open->extensions != NULL)
				g_strfreev(i_open->extensions_set);
		}

		g_array_free(open_info_arr, TRUE);
		open_info_arr = NULL;
	}
}

/*
 * Allow built-in file handlers (but *not* plugin file handlers!) to
 * register a "backwards-compatibility" name and file type value, to
 * put in the Lua wtap_filetypes table.
 *
 * This is only to be used as long as we have that table; new Lua
 * code should use wtap_name_to_file_type_subtype() to look up
 * file types by their name, just as C code should.
 *
 * The backwards-ccmpatibility names are the old WTAP_FILE_TYPE_SUBTYPE_
 * #define name, with WTAP_FILE_TYPE_SUBTYPE_ removed.
 */

static GArray *backwards_compatibility_lua_names;

void
wtap_register_backwards_compatibility_lua_name(const char *name, int ft)
{
	struct backwards_compatibiliity_lua_name entry;

	/*
	 * Create the table if it doesn't already exist.
	 * Use the same size as we do for the file type/subtype table.
	 */
	if (backwards_compatibility_lua_names == NULL) {
		backwards_compatibility_lua_names = g_array_sized_new(FALSE,
		    TRUE, sizeof(struct backwards_compatibiliity_lua_name),
		    wtap_module_count*2);

		/*
		 * Extra backwards compatibility hack - add entries
		 * for time stamp precision values(!), as well as
		 * for "UNKNOWN" and types that don't yet register
		 * themselves.
		 *
		 * If new WS_TSPREC_ value are added, don't bother
		 * adding them to this table; any Lua program that
		 * would use them should use the wtap_tsprecs type.
		 *
		 * (Recursion: see "recursion".)
		 */
		wtap_register_backwards_compatibility_lua_name("TSPREC_SEC",
		    WTAP_TSPREC_SEC);
		wtap_register_backwards_compatibility_lua_name("TSPREC_DSEC",
		    WTAP_TSPREC_DSEC);
		wtap_register_backwards_compatibility_lua_name("TSPREC_CSEC",
		    WTAP_TSPREC_CSEC);
		wtap_register_backwards_compatibility_lua_name("TSPREC_MSEC",
		    WTAP_TSPREC_MSEC);
		wtap_register_backwards_compatibility_lua_name("TSPREC_USEC",
		    WTAP_TSPREC_USEC);
		wtap_register_backwards_compatibility_lua_name("TSPREC_NSEC",
		    WTAP_TSPREC_NSEC);
		wtap_register_backwards_compatibility_lua_name("UNKNOWN",
		    WTAP_FILE_TYPE_SUBTYPE_UNKNOWN);
	}
	entry.name = name;
	entry.ft = ft;
	g_array_append_val(backwards_compatibility_lua_names, entry);
}

const GArray *
get_backwards_compatibility_lua_table(void)
{
	return backwards_compatibility_lua_names;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
