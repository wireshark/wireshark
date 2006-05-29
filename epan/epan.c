/* epan.h
 *
 * $Id$
 *
 * Wireshark Protocol Analyzer Library
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include "epan.h"
#include "epan_dissect.h"
#include "report_err.h"

#include "conversation.h"
#include "circuit.h"
#include "except.h"
#include "packet.h"
#include "column-utils.h"
#include "tap.h"
#include "addr_resolv.h"
#include "oid_resolv.h"
#include "emem.h"
#include "expert.h"

static void (*report_failure_func)(const char *, va_list);
static void (*report_open_failure_func)(const char *, int, gboolean);
static void (*report_read_failure_func)(const char *, int);

/*
 * XXX - this takes the plugin directory as an argument, because
 * libethereal now has its own configure script and "config.h" file,
 * which is what code in the "epan" directory includes, but we need
 * to define PLUGIN_DIR in the top-level directory, as it's used by,
 * for example, the Makefile for the Gryphon plugin, so it knows
 * where to install the plugin.
 *
 * Eventually, we should probably have an "epan-configure" script
 * (or "libethereal-configure", or whatever), along the lines of what
 * GTK+ and GLib have, that can print, among other things, the directory
 * into which plugins should be installed.  That way, only libethereal
 * need know what directory that is; programs using it won't, *and*
 * Makefiles for plugins can just use "epan-configure" to figure out
 * where to install the plugins.
 *
 * (Would that *more* libraries had configure scripts like that, so
 * that configure scripts didn't have to go through various contortions
 * to figure out where the header files and libraries for various
 * libraries are located.)
 */
void
epan_init(const char *plugin_dir, void (*register_all_protocols)(void),
	  void (*register_all_handoffs)(void),
	  void (*report_failure)(const char *, va_list),
	  void (*report_open_failure)(const char *, int, gboolean),
	  void (*report_read_failure)(const char *, int))
{
	report_failure_func = report_failure;
	report_open_failure_func = report_open_failure;
	report_read_failure_func = report_read_failure;
	except_init();
	tvbuff_init();
	oid_resolv_init();
	tap_init();
	proto_init(plugin_dir,register_all_protocols,register_all_handoffs);
	packet_init();
	dfilter_init();
	final_registration_all_protocols();
	host_name_lookup_init();
	expert_init();
}

void
epan_cleanup(void)
{
	expert_cleanup();
	dfilter_cleanup();
	proto_cleanup();
	packet_cleanup();
	oid_resolv_cleanup();
	tvbuff_cleanup();
	except_deinit();
	host_name_lookup_cleanup();
}

void
epan_conversation_init(void)
{
	conversation_init();
}

void
epan_circuit_init(void)
{
	circuit_init();
}

/*
 * Report a general error.
 */
void
report_failure(const char *msg_format, ...)
{
	va_list ap;

	va_start(ap, msg_format);
	(*report_failure_func)(msg_format, ap);
	va_end(ap);
}

/*
 * Report an error when trying to open or create a file.
 * "err" is assumed to be an error code from Wiretap; positive values are
 * UNIX-style errnos, so this can be used for open failures not from
 * Wiretap as long as the failue code is just an errno.
 */
void
report_open_failure(const char *filename, int err,
    gboolean for_writing)
{
	(*report_open_failure_func)(filename, err, for_writing);
}

/*
 * Report an error when trying to read a file.
 * "err" is assumed to be a UNIX-style errno.
 */
void
report_read_failure(const char *filename, int err)
{
	(*report_read_failure_func)(filename, err);
}

epan_dissect_t*
epan_dissect_new(gboolean create_proto_tree, gboolean proto_tree_visible)
{
	epan_dissect_t	*edt;

	edt = g_new(epan_dissect_t, 1);

	if (create_proto_tree) {
		edt->tree = proto_tree_create_root();
		proto_tree_set_visible(edt->tree, proto_tree_visible);
	}
	else {
		edt->tree = NULL;
	}

	return edt;
}

void
epan_dissect_run(epan_dissect_t *edt, void* pseudo_header,
        const guint8* data, frame_data *fd, column_info *cinfo)
{
	/* free all memory allocated during previous packet */
	ep_free_all();

	dissect_packet(edt, pseudo_header, data, fd, cinfo);
}


void
epan_dissect_free(epan_dissect_t* edt)
{
	/* Free the data sources list. */
	free_data_sources(&edt->pi);

	/* Free all tvb's created from this tvb, unless dissector
	 * wanted to store the pointer (in which case, the dissector
	 * would have incremented the usage count on that tvbuff_t*) */
	tvb_free_chain(edt->tvb);

	if (edt->tree) {
		proto_tree_free(edt->tree);
	}

	g_free(edt);
}

void
epan_dissect_prime_dfilter(epan_dissect_t *edt, const dfilter_t* dfcode)
{
	dfilter_prime_proto_tree(dfcode, edt->tree);
}

void
epan_dissect_fill_in_columns(epan_dissect_t *edt)
{
    col_fill_in(&edt->pi);
}
