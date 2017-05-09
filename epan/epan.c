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

#include <stdarg.h>

#include <wsutil/wsgcrypt.h>
#include <wsutil/ws_printf.h> /* ws_g_warning */

#ifdef HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#endif /* HAVE_LIBGNUTLS */

#include <glib.h>

#include <wsutil/report_message.h>

#include <epan/exceptions.h>

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
#include "wmem/wmem.h"
#include "expert.h"
#include "print.h"
#include "capture_dissectors.h"
#include "exported_pdu.h"
#include "export_object.h"
#include "stat_tap_ui.h"
#include "follow.h"
#include "disabled_protos.h"
#include "decode_as.h"
#include "dissector_filters.h"
#include "conversation_table.h"
#include "reassemble.h"
#include "srt_table.h"
#include "stats_tree.h"
#include <dtd.h>

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

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2ver.h>
#endif

#ifdef HAVE_LIBXML2
#include <libxml/xmlversion.h>
#include <libxml/parser.h>
#endif

static wmem_allocator_t *pinfo_pool_cache = NULL;

const gchar*
epan_get_version(void) {
	return VERSION;
}

#if defined(_WIN32)
// Libgcrypt prints all log messages to stderr by default. This is noisier
// than we would like on Windows. In particular slow_gatherer tends to print
//     "NOTE: you should run 'diskperf -y' to enable the disk statistics"
// which we don't care about.
static void
quiet_gcrypt_logger (void *dummy _U_, int level, const char *format, va_list args)
{
	GLogLevelFlags log_level = G_LOG_LEVEL_WARNING;

	switch (level) {
	case GCRY_LOG_CONT: // Continuation. Ignore for now.
	case GCRY_LOG_DEBUG:
	case GCRY_LOG_INFO:
	default:
		return;
	case GCRY_LOG_WARN:
	case GCRY_LOG_BUG:
		log_level = G_LOG_LEVEL_WARNING;
		break;
	case GCRY_LOG_ERROR:
		log_level = G_LOG_LEVEL_ERROR;
		break;
	case GCRY_LOG_FATAL:
		log_level = G_LOG_LEVEL_CRITICAL;
		break;
	}
	g_logv(NULL, log_level, format, args);
}
#endif // _WIN32

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

gboolean
epan_init(void (*register_all_protocols_func)(register_cb cb, gpointer client_data),
	  void (*register_all_handoffs_func)(register_cb cb, gpointer client_data),
	  register_cb cb,
	  gpointer client_data)
{
	volatile gboolean status = TRUE;

	/* initialize memory allocation subsystem */
	wmem_init();

	/* initialize the GUID to name mapping table */
	guids_init();

	/* initialize name resolution (addr_resolv.c) */
	addr_resolv_init();

	except_init();
	/* initialize libgcrypt (beware, it won't be thread-safe) */

	gcry_check_version(NULL);
#if defined(_WIN32)
	gcry_set_log_handler (quiet_gcrypt_logger, NULL);
#endif
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#ifdef HAVE_LIBGNUTLS
	gnutls_global_init();
#endif
#ifdef HAVE_LIBXML2
	xmlInitParser();
	LIBXML_TEST_VERSION;
#endif
	TRY {
		tap_init();
		prefs_init();
		expert_init();
		packet_init();
		conversation_init();
		capture_dissector_init();
		reassembly_tables_init();
		proto_init(register_all_protocols_func, register_all_handoffs_func,
		    cb, client_data);
		packet_cache_proto_handles();
		dfilter_init();
		final_registration_all_protocols();
		print_cache_field_handles();
		expert_packet_init();
		export_pdu_init();
#ifdef HAVE_LUA
		wslua_init(cb, client_data);
#endif
	}
	CATCH(DissectorError) {
		/*
		 * This is probably a dissector, or something it calls,
		 * calling REPORT_DISSECTOR_ERROR() in a registration
		 * routine or something else outside the normal dissection
		 * code path.
		 */
		const char *exception_message = GET_MESSAGE;
		static const char dissector_error_nomsg[] =
		    "Dissector writer didn't bother saying what the error was";

		report_failure("Dissector bug: %s",
			       exception_message == NULL ?
				 dissector_error_nomsg : exception_message);
		if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL)
			abort();
		status = FALSE;
	}
	ENDTRY;
	return status;
}

/*
 * Load all settings, from the current profile, that affect libwireshark.
 */
e_prefs *
epan_load_settings(void)
{
	e_prefs *prefs_p;

	/* load the decode as entries of the current profile */
	load_decode_as_entries();

	prefs_p = read_prefs();

	/*
	 * Read the files that enable and disable protocols and heuristic
	 * dissectors.
	 */
	read_enabled_and_disabled_lists();

	return prefs_p;
}

void
epan_cleanup(void)
{
	dfilter_cleanup();
	proto_cleanup();
	prefs_cleanup();
	decode_clear_all();
	conversation_filters_cleanup();
	reassembly_table_cleanup();
	tap_cleanup();
	packet_cleanup();
	expert_cleanup();
	capture_dissector_cleanup();
	export_pdu_cleanup();
	cleanup_enabled_and_disabled_lists();
	stats_tree_cleanup();
	dtd_location(NULL);
#ifdef HAVE_LUA
	wslua_cleanup();
#endif
#ifdef HAVE_LIBGNUTLS
	gnutls_global_deinit();
#endif
#ifdef HAVE_LIBXML2
	xmlCleanupParser();
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

const char *
epan_get_interface_description(const epan_t *session, guint32 interface_id)
{
	if (session->get_interface_description)
		return session->get_interface_description(session->data, interface_id);

	return NULL;
}

const nstime_t *
epan_get_frame_ts(const epan_t *session, guint32 frame_num)
{
	const nstime_t *abs_ts = NULL;

	if (session->get_frame_ts)
		abs_ts = session->get_frame_ts(session->data, frame_num);

	if (!abs_ts)
		ws_g_warning("!!! couldn't get frame ts for %u !!!\n", frame_num);

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
	conversation_epan_reset();
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

void
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

	epan_dissect_init(edt, session, create_proto_tree, proto_tree_visible);
	return edt;
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
epan_dissect_prime_with_dfilter(epan_dissect_t *edt, const dfilter_t* dfcode)
{
	dfilter_prime_proto_tree(dfcode, edt->tree);
}

void
epan_dissect_prime_with_hfid(epan_dissect_t *edt, int hfid)
{
	proto_tree_prime_with_hfid(edt->tree, hfid);
}

void
epan_dissect_prime_with_hfid_array(epan_dissect_t *edt, GArray *hfids)
{
	guint i;

	for (i = 0; i < hfids->len; i++) {
		proto_tree_prime_with_hfid(edt->tree,
		    g_array_index(hfids, int, i));
	}
}

/* ----------------------- */
const gchar *
epan_custom_set(epan_dissect_t *edt, GSList *field_ids,
			     gint occurrence,
			     gchar *result,
			     gchar *expr, const int size )
{
	return proto_custom_set(edt->tree, field_ids, occurrence, result, expr, size);
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
	int field_id;
	gboolean contains_field;

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
#endif /* HAVE_C_ARES */

	/* LUA */
	g_string_append(str, ", ");
#ifdef HAVE_LUA
	g_string_append(str, "with ");
	g_string_append(str, LUA_RELEASE);
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
	g_string_append(str, "with Gcrypt " GCRYPT_VERSION);

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

	/* nghttp2 */
	g_string_append(str, ", ");
#ifdef HAVE_NGHTTP2
	g_string_append(str, "with nghttp2 " NGHTTP2_VERSION);
#else
	g_string_append(str, "without nghttp2");
#endif /* HAVE_NGHTTP2 */

	/* LZ4 */
	g_string_append(str, ", ");
#ifdef HAVE_LZ4
	g_string_append(str, "with LZ4");
#else
	g_string_append(str, "without LZ4");
#endif /* HAVE_LZ4 */

	/* Snappy */
	g_string_append(str, ", ");
#ifdef HAVE_SNAPPY
	g_string_append(str, "with Snappy");
#else
	g_string_append(str, "without Snappy");
#endif /* HAVE_SNAPPY */

	/* libxml2 */
	g_string_append(str, ", ");
#ifdef HAVE_LIBXML2
	g_string_append(str, "with libxml2 " LIBXML_DOTTED_VERSION);
#else
	g_string_append(str, "without libxml2");
#endif /* HAVE_LIBXML2 */

}

/*
 * Get runtime information for libraries used by libwireshark.
 */
void
epan_get_runtime_version_info(GString *str)
{
	/* GnuTLS */
#ifdef HAVE_LIBGNUTLS
	g_string_append_printf(str, ", with GnuTLS %s", gnutls_check_version(NULL));
#endif /* HAVE_LIBGNUTLS */

	/* Gcrypt */
	g_string_append_printf(str, ", with Gcrypt %s", gcry_check_version(NULL));
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
