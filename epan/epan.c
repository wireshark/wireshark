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

#ifdef HAVE_PYTHON
#include <Python.h> /* to get the Python version number (PY_VERSION) */
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
#include <lua.h>
#include <wslua/wslua.h>
#endif

#ifdef HAVE_LIBSMI
#include <smi.h>
#endif

#ifdef HAVE_C_ARES
#include <ares_version.h>
#endif

#ifdef HAVE_GEOIP
#include "geoip_db.h"
#endif

const gchar*
epan_get_version(void) {
	return VERSION;
}

void
epan_init(void (*register_all_protocols_func)(register_cb cb, gpointer client_data),
	  void (*register_all_handoffs_func)(register_cb cb, gpointer client_data),
	  register_cb cb,
	  gpointer client_data,
	  void (*report_failure_fcn_p)(const char *, va_list),
	  void (*report_open_failure_fcn_p)(const char *, int, gboolean),
	  void (*report_read_failure_fcn_p)(const char *, int),
	  void (*report_write_failure_fcn_p)(const char *, int))
{
	init_report_err(report_failure_fcn_p, report_open_failure_fcn_p,
	    report_read_failure_fcn_p, report_write_failure_fcn_p);

	/* initialize memory allocation subsystem */
	emem_init();

	/* initialize the GUID to name mapping table */
	guids_init();

	except_init();
#ifdef HAVE_LIBGNUTLS
	gnutls_global_init();
#elif defined(HAVE_LIBGCRYPT)
	gcry_check_version(NULL);
#endif
	tap_init();
	prefs_init();
	proto_init(register_all_protocols_func, register_all_handoffs_func,
	    cb, client_data);
	packet_init();
	dfilter_init();
	final_registration_all_protocols();
	host_name_lookup_init();
	expert_init();
#ifdef HAVE_LUA_5_1
	wslua_init(cb, client_data);
#endif
#ifdef HAVE_GEOIP
	geoip_db_init();
#endif

}

void
epan_cleanup(void)
{
	cleanup_dissection();
	dfilter_cleanup();
	proto_cleanup();
	prefs_cleanup();
	packet_cleanup();
	oid_resolv_cleanup();
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
epan_conversation_cleanup(void)
{
	conversation_cleanup();
}

void
epan_circuit_init(void)
{
	circuit_init();
}

void
epan_circuit_cleanup(void)
{
	circuit_cleanup();
}

epan_dissect_t*
epan_dissect_init(epan_dissect_t *edt, const gboolean create_proto_tree, const gboolean proto_tree_visible)
{
	g_assert(edt);

	if (create_proto_tree) {
		edt->tree = proto_tree_create_root();
		proto_tree_set_visible(edt->tree, proto_tree_visible);
	}
	else {
		edt->tree = NULL;
	}

	edt->pi.dependent_frames = NULL;

	return edt;
}

epan_dissect_t*
epan_dissect_new(const gboolean create_proto_tree, const gboolean proto_tree_visible)
{
	epan_dissect_t *edt;

	edt = g_new0(epan_dissect_t, 1);

	return epan_dissect_init(edt, create_proto_tree, proto_tree_visible);
}

void
epan_dissect_fake_protocols(epan_dissect_t *edt, const gboolean fake_protocols)
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
epan_dissect_cleanup(epan_dissect_t* edt)
{
	g_assert(edt);

	/* Free the data sources list. */
	free_data_sources(&edt->pi);

	/* Free all tvb's chained from this tvb */
	tvb_free_chain(edt->tvb);

	if (edt->tree) {
		proto_tree_free(edt->tree);
	}
}

void
epan_dissect_free(epan_dissect_t* edt)
{
	epan_dissect_cleanup(edt);
	g_free(edt);
}

void
epan_dissect_prime_dfilter(epan_dissect_t *edt, const dfilter_t* dfcode)
{
    dfilter_prime_proto_tree(dfcode, edt->tree);
}

/* ----------------------- */
const gchar *
epan_custom_set(epan_dissect_t *edt, int field_id,
                             gint occurrence,
                             gchar *result,
                             gchar *expr, const int size )
{
    return proto_custom_set(edt->tree, field_id, occurrence, result, expr, size);
}

void
epan_dissect_fill_in_columns(epan_dissect_t *edt, const gboolean fill_col_exprs, const gboolean fill_fd_colums)
{
    col_custom_set_edt(edt, edt->pi.cinfo);
    col_fill_in(&edt->pi, fill_col_exprs, fill_fd_colums);
}

/*
 * Get compile-time information for libraries used by libwireshark.
 */
void
epan_get_compiled_version_info(GString *str)
{
        /* SNMP */
	g_string_append(str, ", ");
#ifdef HAVE_LIBSMI
	g_string_append(str, "with SMI " SMI_VERSION_STRING);
#else /* no SNMP library */
	g_string_append(str, "without SMI");
#endif /* _SMI_H */

	/* c-ares */
	g_string_append(str, ", ");
#ifdef HAVE_C_ARES
	g_string_append(str, "with c-ares " ARES_VERSION_STR);
#else
	g_string_append(str, "without c-ares");

	/* ADNS - only add if no c-ares */
	g_string_append(str, ", ");
#ifdef HAVE_GNU_ADNS
	g_string_append(str, "with ADNS");
#else
	g_string_append(str, "without ADNS");
#endif /* HAVE_GNU_ADNS */
#endif /* HAVE_C_ARES */

        /* LUA */
	g_string_append(str, ", ");
#ifdef HAVE_LUA_5_1
	g_string_append(str, "with ");
	g_string_append(str, LUA_VERSION);
#else
	g_string_append(str, "without Lua");
#endif /* HAVE_LUA_5_1 */

	g_string_append(str, ", ");
#ifdef HAVE_PYTHON
	g_string_append(str, "with Python");
#ifdef PY_VERSION
	g_string_append(str, " " PY_VERSION);
#endif /* PY_VERSION */
#else
	g_string_append(str, "without Python");
#endif /* HAVE_PYTHON */

        /* GnuTLS */
	g_string_append(str, ", ");
#ifdef HAVE_LIBGNUTLS
	g_string_append(str, "with GnuTLS " LIBGNUTLS_VERSION);
#else
	g_string_append(str, "without GnuTLS");
#endif /* HAVE_LIBGNUTLS */

        /* Gcrypt */
	g_string_append(str, ", ");
#ifdef HAVE_LIBGCRYPT
	g_string_append(str, "with Gcrypt " GCRYPT_VERSION);
#else
	g_string_append(str, "without Gcrypt");
#endif /* HAVE_LIBGCRYPT */

        /* Kerberos */
        /* XXX - I don't see how to get the version number, at least for KfW */
	g_string_append(str, ", ");
#ifdef HAVE_KERBEROS
#ifdef HAVE_MIT_KERBEROS
	g_string_append(str, "with MIT Kerberos");
#else
        /* HAVE_HEIMDAL_KERBEROS */
	g_string_append(str, "with Heimdal Kerberos");
#endif
#else
	g_string_append(str, "without Kerberos");
#endif /* HAVE_KERBEROS */

	/* GeoIP */
	g_string_append(str, ", ");
#ifdef HAVE_GEOIP
	g_string_append(str, "with GeoIP");
#else
	g_string_append(str, "without GeoIP");
#endif /* HAVE_GEOIP */

}

/*
 * Get runtime information for libraries used by libwireshark.
 */
void
epan_get_runtime_version_info(GString *str
#if !defined(HAVE_LIBGNUTLS) && !defined(HAVE_LIBGCRYPT)
_U_
#endif
)
{
        /* GnuTLS */
#ifdef HAVE_LIBGNUTLS
	g_string_append_printf(str, ", GnuTLS %s", gnutls_check_version(NULL));
#endif /* HAVE_LIBGNUTLS */

        /* Gcrypt */
#ifdef HAVE_LIBGCRYPT
	g_string_append_printf(str, ", Gcrypt %s", gcry_check_version(NULL));
#endif /* HAVE_LIBGCRYPT */
}
