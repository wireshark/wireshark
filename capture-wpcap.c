/* capture-wpcap.c
 * Try to load WinPcap DLL at run-time.
 *
 * $Id: capture-wpcap.c,v 1.1 2001/04/03 05:26:26 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
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

/* XXX - yes, I know, I should move cppmagic.h to a generic location. */
#include "tools/lemon/cppmagic.h"

gboolean has_wpcap = FALSE;

#ifdef HAVE_LIBPCAP


static char*   (*p_pcap_lookupdev) (char *);
static void    (*p_pcap_close) (pcap_t *);
static int     (*p_pcap_stats) (pcap_t *, struct pcap_stat *);
static int     (*p_pcap_dispatch) (pcap_t *, int, pcap_handler, u_char *);
static int     (*p_pcap_snapshot) (pcap_t *);
static int     (*p_pcap_datalink) (pcap_t *);
static int     (*p_pcap_setfilter) (pcap_t *, struct bpf_program *);
static char*   (*p_pcap_geterr) (pcap_t *);
static int     (*p_pcap_compile) (pcap_t *, struct bpf_program *, char *, int,
			bpf_u_int32);
static int     (*p_pcap_lookupnet) (char *, bpf_u_int32 *, bpf_u_int32 *,
			char *);
static pcap_t* (*p_pcap_open_live) (char *, int, int, int, char *);
static int     (*p_pcap_loop) (pcap_t *, int, pcap_handler, u_char *);

typedef struct {
	const char	*name;
	gpointer	*ptr;
} symbol_table_t;

#define SYM(x)	STRINGIFY(x) , (gpointer) &CONCAT(p_,x)

void
load_wpcap(void)
{

	/* These are the symbols I need from Wpcap */
	symbol_table_t	symbols[] = {
		SYM(pcap_lookupdev),
		SYM(pcap_close),
		SYM(pcap_stats),
		SYM(pcap_dispatch),
		SYM(pcap_snapshot),
		SYM(pcap_datalink),
		SYM(pcap_setfilter),
		SYM(pcap_geterr),
		SYM(pcap_compile),
		SYM(pcap_lookupnet),
		SYM(pcap_open_live),
		SYM(pcap_loop),
		NULL, NULL
	};

	GModule		*wh; /* wpcap handle */
	symbol_table_t	*sym;

	wh = g_module_open("wpcap", 0);

	if (!wh) {
		return;
	}

	sym = symbols;
	while (sym && sym->name) {
		if (!g_module_symbol(wh, sym->name, sym->ptr)) {
			return;
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
pcap_dispatch(pcap_t *a, int b, pcap_handler c, u_char *d)
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
pcap_loop(pcap_t *a, int b, pcap_handler c, u_char *d)
{
	g_assert(has_wpcap);
	return p_pcap_loop(a, b, c, d);
}

#else /* HAVE_LIBPCAP */

void
load_wpcap(void)
{
	return;
}


#endif /* HAVE_LIBPCAP */
