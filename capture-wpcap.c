/* capture-wpcap.c
 * WinPcap-specific interfaces for capturing.  We load WinPcap at run
 * time, so that we only need one Wireshark binary and one TShark binary
 * for Windows, regardless of whether WinPcap is installed or not.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include <glib.h>
#include <gmodule.h>

#include "capture-pcap-util.h"
#include "capture-pcap-util-int.h"

/* XXX - yes, I know, I should move cppmagic.h to a generic location. */
#include "tools/lemon/cppmagic.h"


#define MAX_WIN_IF_NAME_LEN 511


gboolean has_wpcap = FALSE;

#ifdef HAVE_LIBPCAP

/*
 * XXX - should we require at least WinPcap 3.1 both for building an
 * for using Wireshark?
 */

static char*   (*p_pcap_lookupdev) (char *);
static void    (*p_pcap_close) (pcap_t *);
static int     (*p_pcap_stats) (pcap_t *, struct pcap_stat *);
static int     (*p_pcap_dispatch) (pcap_t *, int, pcap_handler, guchar *);
static int     (*p_pcap_snapshot) (pcap_t *);
static int     (*p_pcap_datalink) (pcap_t *);
static int     (*p_pcap_setfilter) (pcap_t *, struct bpf_program *);
static char*   (*p_pcap_geterr) (pcap_t *);
static int     (*p_pcap_compile) (pcap_t *, struct bpf_program *, char *, int,
			bpf_u_int32);
#ifdef WPCAP_CONSTIFIED
static int     (*p_pcap_lookupnet) (const char *, bpf_u_int32 *, bpf_u_int32 *,
			char *);
static pcap_t* (*p_pcap_open_live) (const char *, int, int, int, char *);
#else
static int     (*p_pcap_lookupnet) (char *, bpf_u_int32 *, bpf_u_int32 *,
			char *);
static pcap_t* (*p_pcap_open_live) (char *, int, int, int, char *);
#endif
static int     (*p_pcap_loop) (pcap_t *, int, pcap_handler, guchar *);
static void    (*p_pcap_freecode) (struct bpf_program *);
#ifdef HAVE_PCAP_FINDALLDEVS
static int     (*p_pcap_findalldevs) (pcap_if_t **, char *);
static void    (*p_pcap_freealldevs) (pcap_if_t *);
#endif
#ifdef HAVE_PCAP_DATALINK_NAME_TO_VAL
static int (*p_pcap_datalink_name_to_val) (const char *);
#endif
#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
static const char *(*p_pcap_datalink_val_to_name) (int);
#endif
#ifdef HAVE_PCAP_BREAKLOOP
static void    (*p_pcap_breakloop) (pcap_t *);
#endif
static const char *(*p_pcap_lib_version) (void);
static int     (*p_pcap_setbuff) (pcap_t *, int dim);
static int     (*p_pcap_next_ex) (pcap_t *, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);

typedef struct {
	const char	*name;
	gpointer	*ptr;
	gboolean	optional;
} symbol_table_t;

#define SYM(x, y)	{ STRINGIFY(x) , (gpointer) &CONCAT(p_,x), y }

void
load_wpcap(void)
{

	/* These are the symbols I need or want from Wpcap */
	static const symbol_table_t	symbols[] = {
		SYM(pcap_lookupdev, FALSE),
		SYM(pcap_close, FALSE),
		SYM(pcap_stats, FALSE),
		SYM(pcap_dispatch, FALSE),
		SYM(pcap_snapshot, FALSE),
		SYM(pcap_datalink, FALSE),
		SYM(pcap_setfilter, FALSE),
		SYM(pcap_geterr, FALSE),
		SYM(pcap_compile, FALSE),
		SYM(pcap_lookupnet, FALSE),
		SYM(pcap_open_live, FALSE),
		SYM(pcap_loop, FALSE),
		SYM(pcap_freecode, TRUE),
#ifdef HAVE_PCAP_FINDALLDEVS
		SYM(pcap_findalldevs, TRUE),
		SYM(pcap_freealldevs, TRUE),
#endif
#ifdef HAVE_PCAP_DATALINK_NAME_TO_VAL
		SYM(pcap_datalink_name_to_val, TRUE),
#endif
#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
		SYM(pcap_datalink_val_to_name, TRUE),
#endif
#ifdef HAVE_PCAP_BREAKLOOP
		/*
		 * We don't try to work around the lack of this at
		 * run time; it's present in WinPcap 3.1, which is
		 * the version we build with and ship with.
		 */
		SYM(pcap_breakloop, FALSE),
#endif
		SYM(pcap_lib_version, TRUE),
		SYM(pcap_setbuff, TRUE),
		SYM(pcap_next_ex, TRUE),
		{ NULL, NULL, FALSE }
	};

	GModule		*wh; /* wpcap handle */
	const symbol_table_t	*sym;

	wh = g_module_open("wpcap", 0);

	if (!wh) {
		return;
	}

	sym = symbols;
	while (sym->name) {
		if (!g_module_symbol(wh, sym->name, sym->ptr)) {
			if (sym->optional) {
				/*
				 * We don't care if it's missing; we just
				 * don't use it.
				 */
				*sym->ptr = NULL;
			} else {
				/*
				 * We require this symbol.
				 */
				return;
			}
		}
		sym++;
	}


	has_wpcap = TRUE;
}

char*
pcap_lookupdev (char *a)
{
	g_assert(has_wpcap);
	return p_pcap_lookupdev(a);
}

void
pcap_close(pcap_t *a)
{
	g_assert(has_wpcap);
	p_pcap_close(a);
}

int
pcap_stats(pcap_t *a, struct pcap_stat *b)
{
	g_assert(has_wpcap);
	return p_pcap_stats(a, b);
}

int
pcap_dispatch(pcap_t *a, int b, pcap_handler c, guchar *d)
{
	g_assert(has_wpcap);
	return p_pcap_dispatch(a, b, c, d);
}

int
pcap_snapshot(pcap_t *a)
{
	g_assert(has_wpcap);
	return p_pcap_snapshot(a);
}

int
pcap_datalink(pcap_t *a)
{
	g_assert(has_wpcap);
	return p_pcap_datalink(a);
}

int
pcap_setfilter(pcap_t *a, struct bpf_program *b)
{
	g_assert(has_wpcap);
	return p_pcap_setfilter(a, b);
}

char*
pcap_geterr(pcap_t *a)
{
	g_assert(has_wpcap);
	return p_pcap_geterr(a);
}

int
pcap_compile(pcap_t *a, struct bpf_program *b, char *c, int d,
            bpf_u_int32 e)
{
	g_assert(has_wpcap);
	return p_pcap_compile(a, b, c, d, e);
}

int
#ifdef WPCAP_CONSTIFIED
pcap_lookupnet(const char *a, bpf_u_int32 *b, bpf_u_int32 *c, char *d)
#else
pcap_lookupnet(char *a, bpf_u_int32 *b, bpf_u_int32 *c, char *d)
#endif
{
	g_assert(has_wpcap);
	return p_pcap_lookupnet(a, b, c, d);
}

pcap_t*
#ifdef WPCAP_CONSTIFIED
pcap_open_live(const char *a, int b, int c, int d, char *e)
#else
pcap_open_live(char *a, int b, int c, int d, char *e)
#endif
{
	g_assert(has_wpcap);
	return p_pcap_open_live(a, b, c, d, e);
}

int
pcap_loop(pcap_t *a, int b, pcap_handler c, guchar *d)
{
	g_assert(has_wpcap);
	return p_pcap_loop(a, b, c, d);
}

void
pcap_freecode(struct bpf_program *a)
{
	g_assert(has_wpcap);
    if(p_pcap_freecode) {
	    p_pcap_freecode(a);
    }
}

#ifdef HAVE_PCAP_FINDALLDEVS
int
pcap_findalldevs(pcap_if_t **a, char *b)
{
	g_assert(has_wpcap && p_pcap_findalldevs != NULL);
	return p_pcap_findalldevs(a, b);
}

void
pcap_freealldevs(pcap_if_t *a)
{
	g_assert(has_wpcap && p_pcap_freealldevs != NULL);
	p_pcap_freealldevs(a);
}
#endif

#if defined(HAVE_PCAP_DATALINK_NAME_TO_VAL) || defined(HAVE_PCAP_DATALINK_VAL_TO_NAME)
/*
 * Table of DLT_ types, names, and descriptions, for use if the version
 * of WinPcap we have installed lacks "pcap_datalink_name_to_val()"
 * or "pcap_datalink_val_to_name()".
 */
struct dlt_choice {
	const char *name;
	const char *description;
	int	dlt;
};

#define DLT_CHOICE(code, description) { #code, description, code }
#define DLT_CHOICE_SENTINEL { NULL, NULL, 0 }

static struct dlt_choice dlt_choices[] = {
	DLT_CHOICE(DLT_NULL, "BSD loopback"),
	DLT_CHOICE(DLT_EN10MB, "Ethernet"),
	DLT_CHOICE(DLT_IEEE802, "Token ring"),
	DLT_CHOICE(DLT_ARCNET, "ARCNET"),
	DLT_CHOICE(DLT_SLIP, "SLIP"),
	DLT_CHOICE(DLT_PPP, "PPP"),
	DLT_CHOICE(DLT_FDDI, "FDDI"),
	DLT_CHOICE(DLT_ATM_RFC1483, "RFC 1483 IP-over-ATM"),
	DLT_CHOICE(DLT_RAW, "Raw IP"),
#ifdef DLT_SLIP_BSDOS
	DLT_CHOICE(DLT_SLIP_BSDOS, "BSD/OS SLIP"),
#endif
#ifdef DLT_PPP_BSDOS
	DLT_CHOICE(DLT_PPP_BSDOS, "BSD/OS PPP"),
#endif
#ifdef DLT_ATM_CLIP
	DLT_CHOICE(DLT_ATM_CLIP, "Linux Classical IP-over-ATM"),
#endif
#ifdef DLT_PPP_SERIAL
	DLT_CHOICE(DLT_PPP_SERIAL, "PPP over serial"),
#endif
#ifdef DLT_PPP_ETHER
	DLT_CHOICE(DLT_PPP_ETHER, "PPPoE"),
#endif
#ifdef DLT_C_HDLC
	DLT_CHOICE(DLT_C_HDLC, "Cisco HDLC"),
#endif
#ifdef DLT_IEEE802_11
	DLT_CHOICE(DLT_IEEE802_11, "802.11"),
#endif
#ifdef DLT_FRELAY
	DLT_CHOICE(DLT_FRELAY, "Frame Relay"),
#endif
#ifdef DLT_LOOP
	DLT_CHOICE(DLT_LOOP, "OpenBSD loopback"),
#endif
#ifdef DLT_ENC
	DLT_CHOICE(DLT_ENC, "OpenBSD encapsulated IP"),
#endif
#ifdef DLT_LINUX_SLL
	DLT_CHOICE(DLT_LINUX_SLL, "Linux cooked"),
#endif
#ifdef DLT_LTALK
	DLT_CHOICE(DLT_LTALK, "Localtalk"),
#endif
#ifdef DLT_PFLOG
	DLT_CHOICE(DLT_PFLOG, "OpenBSD pflog file"),
#endif
#ifdef DLT_PRISM_HEADER
	DLT_CHOICE(DLT_PRISM_HEADER, "802.11 plus Prism header"),
#endif
#ifdef DLT_IP_OVER_FC
	DLT_CHOICE(DLT_IP_OVER_FC, "RFC 2625 IP-over-Fibre Channel"),
#endif
#ifdef DLT_SUNATM
	DLT_CHOICE(DLT_SUNATM, "Sun raw ATM"),
#endif
#ifdef DLT_IEEE802_11_RADIO
	DLT_CHOICE(DLT_IEEE802_11_RADIO, "802.11 plus radio information header"),
#endif
#ifdef DLT_ARCNET_LINUX
	DLT_CHOICE(DLT_ARCNET_LINUX, "Linux ARCNET"),
#endif
#ifdef DLT_LINUX_IRDA
	DLT_CHOICE(DLT_LINUX_IRDA, "Linux IrDA"),
#endif
#ifdef DLT_LINUX_LAPD
	DLT_CHOICE(DLT_LINUX_LAPD, "Linux vISDN LAPD"),
#endif
#ifdef DLT_LANE8023
	DLT_CHOICE(DLT_LANE8023, "Linux 802.3 LANE"),
#endif
#ifdef DLT_CIP
	DLT_CHOICE(DLT_CIP, "Linux Classical IP-over-ATM"),
#endif
#ifdef DLT_HDLC
	DLT_CHOICE(DLT_HDLC, "Cisco HDLC"),
#endif
	DLT_CHOICE_SENTINEL
};
#endif /* defined(HAVE_PCAP_DATALINK_NAME_TO_VAL) || defined(HAVE_PCAP_DATALINK_VAL_TO_NAME) */

#ifdef HAVE_PCAP_DATALINK_NAME_TO_VAL
int
pcap_datalink_name_to_val(const char *name)
{
	int i;

	g_assert(has_wpcap);

	if (p_pcap_datalink_name_to_val != NULL)
		return p_pcap_datalink_name_to_val(name);
	else {
		/*
		 * We don't have it in WinPcap; do it ourselves.
		 */
		for (i = 0; dlt_choices[i].name != NULL; i++) {
			if (strcasecmp(dlt_choices[i].name + sizeof("DLT_") - 1,
			    name) == 0)
				return dlt_choices[i].dlt;
		}
		return -1;
	}
}
#endif

#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
const char *
pcap_datalink_val_to_name(int dlt)
{
	int i;

	g_assert(has_wpcap);

	if (p_pcap_datalink_val_to_name != NULL)
		return p_pcap_datalink_val_to_name(dlt);
	else {
		/*
		 * We don't have it in WinPcap; do it ourselves.
		 */
		for (i = 0; dlt_choices[i].name != NULL; i++) {
			if (dlt_choices[i].dlt == dlt)
				return dlt_choices[i].name + sizeof("DLT_") - 1;
		}
		return NULL;
	}
}
#endif

#ifdef HAVE_PCAP_BREAKLOOP
void pcap_breakloop(pcap_t *a)
{
	p_pcap_breakloop(a);
}
#endif

/* setbuff is win32 specific! */
int pcap_setbuff(pcap_t *a, int b)
{
	g_assert(has_wpcap);
	return p_pcap_setbuff(a, b);
}

/* pcap_next_ex is available since libpcap 0.8 / WinPcap 3.0! */
/* (if you get a declaration warning here, try to update to at least WinPcap 3.1b4 develpack) */
int pcap_next_ex (pcap_t *a, struct pcap_pkthdr **b, const u_char **c)
{
	g_assert(has_wpcap);
	return p_pcap_next_ex(a, b, c);
}

/*
 * This will use "pcap_findalldevs()" if we have it, otherwise it'll
 * fall back on "pcap_lookupdev()".
 */
GList *
get_interface_list(int *err, char *err_str)
{
	GList  *il = NULL;
	wchar_t *names;
	char *win95names;
	char ascii_name[MAX_WIN_IF_NAME_LEN + 1];
	char ascii_desc[MAX_WIN_IF_NAME_LEN + 1];
	int i, j;

#ifdef HAVE_PCAP_FINDALLDEVS
	if (p_pcap_findalldevs != NULL)
		return get_interface_list_findalldevs(err, err_str);
#endif

	/*
	 * In WinPcap, pcap_lookupdev is implemented by calling
	 * PacketGetAdapterNames.  According to the documentation
	 * I could find:
	 *
	 *	http://www.winpcap.org/docs/man/html/Packet32_8c.html#a43
	 *
	 * this means that:
	 *
	 * On Windows OT (95, 98, Me), pcap_lookupdev returns a sequence
	 * of bytes consisting of:
	 *
	 *	a sequence of null-terminated ASCII strings (i.e., each
	 *	one is terminated by a single 0 byte), giving the names
	 *	of the interfaces;
	 *
	 *	an empty ASCII string (i.e., a single 0 byte);
	 *
	 *	a sequence of null-terminated ASCII strings, giving the
	 *	descriptions of the interfaces;
	 *
	 *	an empty ASCII string.
	 *
	 * On Windows NT (NT 4.0, W2K, WXP, W2K3, etc.), pcap_lookupdev
	 * returns a sequence of bytes consisting of:
	 *
	 *	a sequence of null-terminated double-byte Unicode strings
	 *	(i.e., each one consits of a sequence of double-byte
	 *	characters, terminated by a double-byte 0), giving the
	 *	names of the interfaces;
	 *
	 *	an empty Unicode string (i.e., a double 0 byte);
	 *
	 *	a sequence of null-terminated ASCII strings, giving the
	 *	descriptions of the interfaces;
	 *
	 *	an empty ASCII string.
	 *
	 * The Nth string in the first sequence is the name of the Nth
	 * adapter; the Nth string in the second sequence is the
	 * description of the Nth adapter.
	 */

	names = (wchar_t *)pcap_lookupdev(err_str);
	i = 0;

	if (names) {
		char* desc = 0;
		int desc_pos = 0;

		if (names[0]<256) {
			/*
			 * If names[0] is less than 256 it means the first
			 * byte is 0.  This implies that we are using Unicode
			 * characters.
			 */
			while (*(names+desc_pos) || *(names+desc_pos-1))
				desc_pos++;
			desc_pos++;	/* Step over the extra '\0' */
			desc = (char*)(names + desc_pos); /* cast *after* addition */

			while (names[i] != 0) {
				/*
				 * Copy the Unicode description to an ASCII
				 * string.
				 */
				j = 0;
				while (*desc != 0) {
					if (j < MAX_WIN_IF_NAME_LEN)
						ascii_desc[j++] = *desc;
					desc++;
				}
				ascii_desc[j] = '\0';
				desc++;

				/*
				 * Copy the Unicode name to an ASCII string.
				 */
				j = 0;
				while (names[i] != 0) {
					if (j < MAX_WIN_IF_NAME_LEN)
					ascii_name[j++] = (char) names[i++];
				}
				ascii_name[j] = '\0';
				i++;
				il = g_list_append(il,
				    if_info_new(ascii_name, ascii_desc));
			}
		} else {
			/*
			 * Otherwise we are in Windows 95/98 and using ASCII
			 * (8-bit) characters.
			 */
			win95names=(char *)names;
			while (*(win95names+desc_pos) || *(win95names+desc_pos-1))
				desc_pos++;
			desc_pos++;	/* Step over the extra '\0' */
			desc = win95names + desc_pos;

			while (win95names[i] != '\0') {
				/*
				 * "&win95names[i]" points to the current
				 * interface name, and "desc" points to
				 * that interface's description.
				 */
				il = g_list_append(il,
				    if_info_new(&win95names[i], desc));

				/*
				 * Skip to the next description.
				 */
				while (*desc != 0)
					desc++;
				desc++;

				/*
				 * Skip to the next name.
				 */
				while (win95names[i] != 0)
					i++;
				i++;
			}
		}
	}

	if (il == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = NO_INTERFACES_FOUND;
	}

	return il;
}

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_interface_list()".
 */
gchar *
cant_get_if_list_error_message(const char *err_str)
{
	/*
	 * If the error message includes "Not enough storage is available
	 * to process this command" or "The operation completed successfully",
	 * suggest that they install a WinPcap version later than 3.0.
	 */
	if (strstr(err_str, "Not enough storage is available to process this command") != NULL ||
	    strstr(err_str, "The operation completed successfully") != NULL) {
		return g_strdup_printf("Can't get list of interfaces: %s\n"
"This might be a problem with WinPcap 3.0; you should try updating to\n"
"a later version of WinPcap - see the WinPcap site at www.winpcap.org",
		    err_str);
	}
	return g_strdup_printf("Can't get list of interfaces: %s", err_str);
}

/*
 * Append the version of WinPcap with which we were compiled to a GString.
 */
void
get_compiled_pcap_version(GString *str)
{
	g_string_append(str, "with WinPcap (version unknown)");
}

/*
 * Append the version of WinPcap with which we we're running to a GString.
 */
void
get_runtime_pcap_version(GString *str)
{
	/*
	 * On Windows, we might have been compiled with WinPcap but
	 * might not have it loaded; indicate whether we have it or
	 * not and, if we have it and we have "pcap_lib_version()",
	 * what version we have.
	 */
	GModule *handle;		/* handle returned by dlopen */
	static gchar *packetVer;
	gchar *blankp;

	if (has_wpcap) {
		g_string_sprintfa(str, "with ");
		if (p_pcap_lib_version != NULL)
			g_string_sprintfa(str, p_pcap_lib_version());
		else {
			/*
			 * An alternative method of obtaining the version
			 * number, by using the PacketLibraryVersion
			 * string from packet.dll.
			 *
			 * Unfortunately, in WinPcap 3.0, it returns
			 * "3.0 alpha3", even in the final version of
			 * WinPcap 3.0, so if there's a blank in the
			 * string, we strip it and everything after
			 * it from the string, so we don't misleadingly
			 * report that 3.0 alpha3 is being used when
			 * the final version is being used.
			 */
			if (packetVer == NULL) {
				packetVer = "version unknown";
				handle = g_module_open("Packet.dll", 0);
				if (handle != NULL) {
					if (g_module_symbol(handle,
					    "PacketLibraryVersion",
					    (gpointer*)&packetVer)) {
						packetVer = g_strdup(packetVer);
						blankp = strchr(packetVer, ' ');
						if (blankp != NULL)
							*blankp = '\0';
					} else {
						packetVer = "version unknown";
					}
					g_module_close(handle);
				}
			}
			g_string_sprintfa(str, "WinPcap (%s)", packetVer);
		}
	} else
		g_string_append(str, "without WinPcap");

	/*g_string_append(str, " ");*/
}

#else /* HAVE_LIBPCAP */

void
load_wpcap(void)
{
	return;
}

/*
 * Append an indication that we were not compiled with WinPcap
 * to a GString.
 */
void
get_compiled_pcap_version(GString *str)
{
	g_string_append(str, "without WinPcap");
}

/*
 * Don't append anything, as we weren't even compiled to use WinPcap.
 */
void
get_runtime_pcap_version(GString *str _U_)
{
}

#endif /* HAVE_LIBPCAP */
