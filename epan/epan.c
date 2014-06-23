/* epan.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#ifdef HAVE_LIBGCRYPT
#include <wsutil/wsgcrypt.h>
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#endif /* HAVE_LIBGNUTLS */

#include <glib.h>

#include "epan-int.h"
#include "epan.h"
#include "dfilter/dfilter.h"
#include "epan_dissect.h"

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
#include "wmem/wmem.h"
#include "expert.h"

#ifdef HAVE_LUA
#include <lua.h>
#include <wslua/wslua.h>
#endif

#ifdef HAVE_LIBSMI
#include <smi.h>
#endif

#ifdef HAVE_C_ARES
#include <ares_version.h>
#endif

static wmem_allocator_t *pinfo_pool_cache = NULL;

const gchar*
epan_get_version(void) {
	return VERSION;
}

/*
 * Register all the plugin types that are part of libwireshark, namely
 * dissector and tap plugins.
 *
 * Must be called before init_plugins(), which must be called before
 * any registration routines are called.
 */
void
epan_register_plugin_types(void)
{
#ifdef HAVE_PLUGINS
	register_dissector_plugin_type();
	register_tap_plugin_type();
#endif
}

void
epan_init(void (*register_all_protocols_func)(register_cb cb, gpointer client_data),
	  void (*register_all_handoffs_func)(register_cb cb, gpointer client_data),
	  register_cb cb,
	  gpointer client_data)
{
	/* initialize memory allocation subsystems */
	emem_init();
	wmem_init();

	/* initialize the GUID to name mapping table */
	guids_init();

        /* initialize name resolution (addr_resolv.c) */
        addr_resolv_init();

	except_init();
#ifdef HAVE_LIBGCRYPT
	/* initialize libgcrypt (beware, it won't be thread-safe) */
	gcry_check_version(NULL);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif
#ifdef HAVE_LIBGNUTLS
	gnutls_global_init();
#endif
	tap_init();
	prefs_init();
	expert_init();
	packet_init();
	proto_init(register_all_protocols_func, register_all_handoffs_func,
	    cb, client_data);
	packet_cache_proto_handles();
	dfilter_init();
	final_registration_all_protocols();
	expert_packet_init();
#ifdef HAVE_LUA
	wslua_init(cb, client_data);
#endif
}

void
epan_cleanup(void)
{
	dfilter_cleanup();
	proto_cleanup();
	prefs_cleanup();
	packet_cleanup();
	expert_cleanup();
#ifdef HAVE_LUA
	wslua_cleanup();
#endif
#ifdef HAVE_LIBGNUTLS
	gnutls_global_deinit();
#endif
	except_deinit();
	addr_resolv_cleanup();

	if (pinfo_pool_cache != NULL) {
		wmem_destroy_allocator(pinfo_pool_cache);
		pinfo_pool_cache = NULL;
	}

	wmem_cleanup();
}

epan_t *
epan_new(void)
{
	epan_t *session = g_slice_new(epan_t);

	/* XXX, it should take session as param */
	init_dissection();

	return session;
}

const char *
epan_get_user_comment(const epan_t *session, const frame_data *fd)
{
	if (session->get_user_comment)
		return session->get_user_comment(session->data, fd);

	return NULL;
}

const char *
epan_get_interface_name(const epan_t *session, guint32 interface_id)
{
	if (session->get_interface_name)
		return session->get_interface_name(session->data, interface_id);

	return NULL;
}

const nstime_t *
epan_get_frame_ts(const epan_t *session, guint32 frame_num)
{
	const nstime_t *abs_ts = NULL;

	if (session->get_frame_ts)
		abs_ts = session->get_frame_ts(session->data, frame_num);

	if (!abs_ts)
		g_warning("!!! couldn't get frame ts for %u !!!\n", frame_num);

	return abs_ts;
}

void
epan_free(epan_t *session)
{
	if (session) {
		/* XXX, it should take session as param */
		cleanup_dissection();

		g_slice_free(epan_t, session);
	}
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

/* Overrides proto_tree_visible i epan_dissect_init to make all fields visible.
 * This is > 0 if a Lua script wanted to see all fields all the time.
 * This is ref-counted, so clearing it won't override other taps/scripts wanting it.
 */
static gint always_visible_refcount = 0;

void
epan_set_always_visible(gboolean force)
{
	if (force)
		always_visible_refcount++;
	else if (always_visible_refcount > 0)
		always_visible_refcount--;
}

epan_dissect_t*
epan_dissect_init(epan_dissect_t *edt, epan_t *session, const gboolean create_proto_tree, const gboolean proto_tree_visible)
{
	g_assert(edt);

	edt->session = session;

	memset(&edt->pi, 0, sizeof(edt->pi));
	if (pinfo_pool_cache != NULL) {
		edt->pi.pool = pinfo_pool_cache;
		pinfo_pool_cache = NULL;
	}
	else {
		edt->pi.pool = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK_FAST);
	}

	if (create_proto_tree) {
		edt->tree = proto_tree_create_root(&edt->pi);
		proto_tree_set_visible(edt->tree, (always_visible_refcount > 0) ? TRUE : proto_tree_visible);
	}
	else {
		edt->tree = NULL;
	}

	edt->tvb = NULL;

	return edt;
}

void
epan_dissect_reset(epan_dissect_t *edt)
{
	/* We have to preserve the pool pointer across the memzeroing */
	wmem_allocator_t *tmp;

	g_assert(edt);

	g_slist_free(edt->pi.proto_data);
	g_slist_free(edt->pi.dependent_frames);

	/* Free the data sources list. */
	free_data_sources(&edt->pi);

	if (edt->tvb) {
		/* Free all tvb's chained from this tvb */
		tvb_free_chain(edt->tvb);
		edt->tvb = NULL;
	}

	if (edt->tree)
		proto_tree_reset(edt->tree);

	tmp = edt->pi.pool;
	wmem_free_all(tmp);

	memset(&edt->pi, 0, sizeof(edt->pi));
	edt->pi.pool = tmp;
}

epan_dissect_t*
epan_dissect_new(epan_t *session, const gboolean create_proto_tree, const gboolean proto_tree_visible)
{
	epan_dissect_t *edt;

	edt = g_new0(epan_dissect_t, 1);

	return epan_dissect_init(edt, session, create_proto_tree, proto_tree_visible);
}

void
epan_dissect_fake_protocols(epan_dissect_t *edt, const gboolean fake_protocols)
{
	if (edt)
		proto_tree_set_fake_protocols(edt->tree, fake_protocols);
}

void
epan_dissect_run(epan_dissect_t *edt, int file_type_subtype,
        struct wtap_pkthdr *phdr, tvbuff_t *tvb, frame_data *fd,
        column_info *cinfo)
{
#ifdef HAVE_LUA
	wslua_prime_dfilter(edt); /* done before entering wmem scope */
#endif
	wmem_enter_packet_scope();
	dissect_record(edt, file_type_subtype, phdr, tvb, fd, cinfo);

	/* free all memory allocated */
	ep_free_all();
	wmem_leave_packet_scope();
}

void
epan_dissect_run_with_taps(epan_dissect_t *edt, int file_type_subtype,
        struct wtap_pkthdr *phdr, tvbuff_t *tvb, frame_data *fd,
        column_info *cinfo)
{
	wmem_enter_packet_scope();
	tap_queue_init(edt);
	dissect_record(edt, file_type_subtype, phdr, tvb, fd, cinfo);
	tap_push_tapped_queue(edt);

	/* free all memory allocated */
	ep_free_all();
	wmem_leave_packet_scope();
}

void
epan_dissect_file_run(epan_dissect_t *edt, struct wtap_pkthdr *phdr,
        tvbuff_t *tvb, frame_data *fd, column_info *cinfo)
{
#ifdef HAVE_LUA
	wslua_prime_dfilter(edt); /* done before entering wmem scope */
#endif
	wmem_enter_packet_scope();
	dissect_file(edt, phdr, tvb, fd, cinfo);

	/* free all memory allocated */
	ep_free_all();
	wmem_leave_packet_scope();
}

void
epan_dissect_file_run_with_taps(epan_dissect_t *edt, struct wtap_pkthdr *phdr,
        tvbuff_t *tvb, frame_data *fd, column_info *cinfo)
{
	wmem_enter_packet_scope();
	tap_queue_init(edt);
	dissect_file(edt, phdr, tvb, fd, cinfo);
	tap_push_tapped_queue(edt);

	/* free all memory allocated */
	ep_free_all();
	wmem_leave_packet_scope();
}

void
epan_dissect_cleanup(epan_dissect_t* edt)
{
	g_assert(edt);

	g_slist_free(edt->pi.proto_data);
	g_slist_free(edt->pi.dependent_frames);

	/* Free the data sources list. */
	free_data_sources(&edt->pi);

	if (edt->tvb) {
		/* Free all tvb's chained from this tvb */
		tvb_free_chain(edt->tvb);
	}

	if (edt->tree) {
		proto_tree_free(edt->tree);
	}

	if (pinfo_pool_cache == NULL) {
		wmem_free_all(edt->pi.pool);
		pinfo_pool_cache = edt->pi.pool;
	}
	else {
		wmem_destroy_allocator(edt->pi.pool);
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

gboolean
epan_dissect_packet_contains_field(epan_dissect_t* edt,
                                   const char *field_name)
{
    GPtrArray* array;
    int        field_id;
    gboolean   contains_field;

    if (!edt || !edt->tree)
        return FALSE;
    field_id = proto_get_id_by_filter_name(field_name);
    if (field_id < 0)
        return FALSE;
    array = proto_find_finfo(edt->tree, field_id);
    contains_field = (array->len > 0) ? TRUE : FALSE;
    g_ptr_array_free(array, TRUE);
    return contains_field;
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
#ifdef HAVE_LUA
	g_string_append(str, "with ");
	g_string_append(str, LUA_VERSION);
#else
	g_string_append(str, "without Lua");
#endif /* HAVE_LUA */

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
	g_string_append_printf(str, ", with GnuTLS %s", gnutls_check_version(NULL));
#endif /* HAVE_LIBGNUTLS */

        /* Gcrypt */
#ifdef HAVE_LIBGCRYPT
	g_string_append_printf(str, ", with Gcrypt %s", gcry_check_version(NULL));
#endif /* HAVE_LIBGCRYPT */
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
