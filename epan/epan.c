/* epan.c
 *
 * $Id$
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
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

#if (defined(HAVE_LIBGCRYPT) || defined(HAVE_LIBGNUTLS)) && defined(_WIN32)
#include <winposixtype.h>
#endif

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#endif /* HAVE_LIBGNUTLS */


#include <glib.h>
#include "epan.h"
#include "epan_dissect.h"
#include "report_err.h"

#include "conversation.h"
#include "circuit.h"
#include "except.h"
#include "packet.h"
#include "prefs.h"
#include "column-utils.h"
#include "tap.h"
#include "addr_resolv.h"
#include "oids.h"
#include "emem.h"
#include "expert.h"

#ifdef HAVE_LUA_5_1
	int wslua_init(void*);
#endif

#ifdef HAVE_GEOIP
#include "geoip_db.h"
#endif

gchar*
epan_get_version(void) {
  return VERSION;
}

void
epan_init(void (*register_all_protocols_func)(register_cb cb, gpointer client_data),
	  void (*register_all_handoffs_func)(register_cb cb, gpointer client_data),
	  register_cb cb,
	  gpointer client_data,
	  void (*report_failure)(const char *, va_list),
	  void (*report_open_failure)(const char *, int, gboolean),
	  void (*report_read_failure)(const char *, int),
	  void (*report_write_failure)(const char *, int))
{
	init_report_err(report_failure, report_open_failure,
	    report_read_failure, report_write_failure);

	/* initialize memory allocation subsystem */
	ep_init_chunk();
	se_init_chunk();

	/* initialize the GUID to name mapping table */
	guids_init();

	except_init();
#ifdef HAVE_LIBGNUTLS
	gnutls_global_init();
#elif defined(HAVE_LIBGCRYPT)
	gcry_check_version(NULL);
#endif
	tvbuff_init();
	tap_init();
	prefs_init();
	proto_init(register_all_protocols_func, register_all_handoffs_func,
	    cb, client_data);
	packet_init();
	dfilter_init();
	final_registration_all_protocols();
	host_name_lookup_init();
	expert_init();
	oids_init();
#ifdef HAVE_LUA_5_1
	wslua_init(NULL);
#endif
#ifdef HAVE_GEOIP
	geoip_db_init();
#endif

}

void
epan_cleanup(void)
{
	se_free_all();
	expert_cleanup();
	dfilter_cleanup();
	proto_cleanup();
	prefs_cleanup();
	packet_cleanup();
	oid_resolv_cleanup();
	tvbuff_cleanup();
#ifdef HAVE_LIBGNUTLS
	gnutls_global_deinit();
#endif
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
epan_dissect_fake_protocols(epan_dissect_t *edt, gboolean fake_protocols)
{
	if (edt)
		proto_tree_set_fake_protocols(edt->tree, fake_protocols);
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
epan_dissect_fill_in_columns(epan_dissect_t *edt, gboolean fill_fd_colums)
{
    col_fill_in(&edt->pi, fill_fd_colums);
}
