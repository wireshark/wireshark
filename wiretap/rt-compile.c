/*
 * rt-compile.c
 * ------------
 *
 */

#include <glib.h>
#include "wtap.h"
#include "bpf.h"
#include "rt-compile.h"
#include "rt-global.h"

int (*mk_attach)
	(wtap *wth);

/* Takes a string representing a display filter, compiles it, and
if the filter compiles successfully, attaches the filter to the wtap handle.
The tricky part comes from the fact that some display filters are
datalink-type-independent (they refer to layers 3 and above of the OSI
protocol stack), whereas others are datalink-type-dependent. Furthermore, some
trace files supported by wiretap can handle more than one datalink type. 

We rely on the user to use the proper logic for multiple datalink types. For
example, if the user has a trace file with ethernet and token-ring packets,
and wants to filter on the MAC-layer broadcast address, he should write:

	(eth.dst eq ff:ff:ff:ff:ff:ff or tr.dst eq ff:ff:ff:ff:ff:ff)

That is, "eth.dst eq ...." fails for a token-ring interface, and
"tr.dst eq ...." fails for an ethernet device. A logical "or" is needed
to find MAC-level broadcast addresses in both datalink types. */

int wtap_offline_filter(wtap *wth, char *filter)
{
	int encap_type;

	if (!filter)
		return 0;

	/* temporary hack */
	if (filter[0] == 0) {
		wtap_filter_offline_clear(wth);
		return 0;
	}

	/* we use the BPF engine for offline filters */
	wtap_filter_offline_init(wth);
	wth->filter_text = g_strdup(filter);

	/* if the file format we are using has a per-file encapsulation
	 * type, then we can go ahead and compile the display filter for
	 * that datalink type. Otherwise, we'll guess ethernet.
	 */
	if (wth->file_encap != WTAP_ENCAP_NONE)
		encap_type = wth->file_encap;
	else
		encap_type = WTAP_ENCAP_ETHERNET;

	if (!wtap_offline_filter_compile(wth, encap_type)) {
		wtap_filter_offline_clear(wth);
		return -1;
	}

	return 0;
}

/* this function is called from within wiretap to recompile the same display
 * filter for a different datalink type. This is needed for trace files that
 * have more than one encapsulation type in the same file
 */
int wtap_offline_filter_compile(wtap *wth, int encap_type)
{
	comp_encap_type = encap_type;
	filter_parsed = 0;
	lex_init(wth->filter_text);
	wtap_parse();

	if (!filter_parsed)
		return 0;

	return mk_attach(wth);
}
