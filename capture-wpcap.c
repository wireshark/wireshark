/* capture-wpcap.c
 * WinPcap-specific interfaces for capturing.  We load WinPcap at run
 * time, so that we only need one Ethereal binary and one Tethereal binary
 * for Windows, regardless of whether WinPcap is installed or not.
 *
 * $Id: capture-wpcap.c,v 1.4 2003/10/10 03:00:09 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <glib.h>
#include <gmodule.h>

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include "pcap-util.h"
#include "pcap-util-int.h"

/* XXX - yes, I know, I should move cppmagic.h to a generic location. */
#include "tools/lemon/cppmagic.h"

gboolean has_wpcap = FALSE;

#ifdef HAVE_LIBPCAP

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
static int     (*p_pcap_lookupnet) (char *, bpf_u_int32 *, bpf_u_int32 *,
			char *);
static pcap_t* (*p_pcap_open_live) (char *, int, int, int, char *);
static int     (*p_pcap_loop) (pcap_t *, int, pcap_handler, guchar *);

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
		SYM(pcap_findalldevs, TRUE),
		{ NULL, NULL, FALSE }
	};

	GModule		*wh; /* wpcap handle */
	symbol_table_t	*sym;

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
pcap_lookupnet(char *a, bpf_u_int32 *b, bpf_u_int32 *c, char *d)
{
	g_assert(has_wpcap);
	return p_pcap_lookupnet(a, b, c, d);
}

pcap_t*
pcap_open_live(char *a, int b, int c, int d, char *e)
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

#ifdef HAVE_PCAP_FINDALLDEVS
int
pcap_findalldevs(pcap_if_t **a, char *b)
{
	g_assert(has_wpcap && p_pcap_findalldevs != NULL)
	return p_pcap_findalldevs(a, b);
}
#endif

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
		return get_interface_list_findalldevs(err, errstr);
#endif

	/*
	 * In WinPcap, pcap_lookupdev is implemented by calling
	 * PacketGetAdapterNames.  According to the documentation
	 * I could find:
	 *
	 *	http://winpcap.polito.it/docs/man/html/Packet32_8c.html#a43
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
					ascii_name[j++] = names[i++];
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

#else /* HAVE_LIBPCAP */

void
load_wpcap(void)
{
	return;
}

#endif /* HAVE_LIBPCAP */
