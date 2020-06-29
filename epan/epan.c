/* epan.c
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdarg.h>

#include <wsutil/wsgcrypt.h>

#ifdef HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#endif /* HAVE_LIBGNUTLS */

#include <glib.h>

#include <version_info.h>
#include <wsutil/report_message.h>

#include <epan/exceptions.h>

#include "epan.h"
#include "epan/frame_data.h"

#include "dfilter/dfilter.h"
#include "epan_dissect.h"

#include <wsutil/nstime.h>

#include "conversation.h"
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
#include "conversation_filter.h"
#include "conversation_table.h"
#include "reassemble.h"
#include "srt_table.h"
#include "stats_tree.h"
#include "secrets.h"
#include "funnel.h"
#include <dtd.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#ifdef HAVE_LUA
#include <lua.h>
#include <wslua/wslua.h>
#endif

#ifdef HAVE_LIBSMI
#include <smi.h>
#endif

#include <ares_version.h>

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2ver.h>
#endif

#ifdef HAVE_BROTLI
#include <brotli/decode.h>
#endif

#ifdef HAVE_LIBXML2
#include <libxml/xmlversion.h>
#include <libxml/parser.h>
#endif

#ifndef _WIN32
#include <signal.h>
#endif

static GSList *epan_plugin_register_all_procotols = NULL;
static GSList *epan_plugin_register_all_handoffs = NULL;

static wmem_allocator_t *pinfo_pool_cache = NULL;

/* Global variables holding the content of the corresponding environment variable
 * to save fetching it repeatedly.
 */
gboolean wireshark_abort_on_dissector_bug = FALSE;
gboolean wireshark_abort_on_too_many_items = FALSE;

#ifdef HAVE_PLUGINS
plugins_t *libwireshark_plugins = NULL;
static GSList *epan_plugins = NULL;
#endif

const gchar*
epan_get_version(void) {
	return VERSION;
}

void
epan_get_version_number(int *major, int *minor, int *micro)
{
	get_ws_version_number(major, minor, micro);
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

#ifdef HAVE_PLUGINS
static void
epan_plugin_init(gpointer data, gpointer user_data _U_)
{
	((epan_plugin *)data)->init();
}

static void
epan_plugin_dissect_init(gpointer data, gpointer user_data)
{
	((epan_plugin *)data)->dissect_init((epan_dissect_t *)user_data);
}

static void
epan_plugin_dissect_cleanup(gpointer data, gpointer user_data)
{
	((epan_plugin *)data)->dissect_cleanup((epan_dissect_t *)user_data);
}

static void
epan_plugin_cleanup(gpointer data, gpointer user_data _U_)
{
	((epan_plugin *)data)->cleanup();
}

void epan_register_plugin(const epan_plugin *plug)
{
	epan_plugins = g_slist_prepend(epan_plugins, (epan_plugin *)plug);
	if (plug->register_all_protocols)
		epan_plugin_register_all_procotols = g_slist_prepend(epan_plugin_register_all_procotols, plug->register_all_protocols);
	if (plug->register_all_handoffs)
		epan_plugin_register_all_handoffs = g_slist_prepend(epan_plugin_register_all_handoffs, plug->register_all_handoffs);
}

void epan_plugin_register_all_tap_listeners(gpointer data, gpointer user_data _U_)
{
	epan_plugin *plug = (epan_plugin *)data;
	if (plug->register_all_tap_listeners)
		plug->register_all_tap_listeners();
}
#endif

gboolean
epan_init(register_cb cb, gpointer client_data, gboolean load_plugins)
{
	volatile gboolean status = TRUE;

	/* Get the value of some environment variables and set corresponding globals for performance reasons*/
	/* If the WIRESHARK_ABORT_ON_DISSECTOR_BUG environment variable is set,
	 * it will call abort(), instead, to make it easier to get a stack trace.
	*/
	if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL) {
		wireshark_abort_on_dissector_bug = TRUE;
	} else {
		wireshark_abort_on_dissector_bug = FALSE;
	}

	if (getenv("WIRESHARK_ABORT_ON_TOO_MANY_ITEMS") != NULL) {
		wireshark_abort_on_too_many_items = TRUE;
	} else {
		wireshark_abort_on_too_many_items = FALSE;
	}

	/*
	 * proto_init -> register_all_protocols -> g_async_queue_new which
	 * requires threads to be initialized. This happens automatically with
	 * GLib 2.32, before that g_thread_init must be called. But only since
	 * GLib 2.24, multiple invocations are allowed. Check for an earlier
	 * invocation just in case.
	 */
	/* initialize memory allocation subsystem */
	wmem_init();

	/* initialize the GUID to name mapping table */
	guids_init();

	/* initialize name resolution (addr_resolv.c) */
	addr_resolv_init();

	except_init();

	if (load_plugins) {
#ifdef HAVE_PLUGINS
		libwireshark_plugins = plugins_init(WS_PLUGIN_EPAN);
#endif
	}

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

#ifndef _WIN32
	// We might receive a SIGPIPE due to maxmind_db.
	signal(SIGPIPE, SIG_IGN);
#endif

	TRY {
		tap_init();
		prefs_init();
		expert_init();
		packet_init();
		secrets_init();
		conversation_init();
		capture_dissector_init();
		reassembly_tables_init();
#ifdef HAVE_PLUGINS
		g_slist_foreach(epan_plugins, epan_plugin_init, NULL);
#endif
		proto_init(epan_plugin_register_all_procotols, epan_plugin_register_all_handoffs, cb, client_data);
#ifdef HAVE_PLUGINS
		g_slist_foreach(epan_plugins, epan_plugin_register_all_tap_listeners, NULL);
#endif
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
#ifdef HAVE_PLUGINS
	g_slist_foreach(epan_plugins, epan_plugin_cleanup, NULL);
	g_slist_free(epan_plugins);
	epan_plugins = NULL;
#endif
	g_slist_free(epan_plugin_register_all_procotols);
	epan_plugin_register_all_procotols = NULL;
	g_slist_free(epan_plugin_register_all_handoffs);
	epan_plugin_register_all_handoffs = NULL;

	dfilter_cleanup();
	decode_clear_all();
	decode_cleanup();

#ifdef HAVE_LUA
	/*
	 * Must deregister Proto objects in Lua before destroying dissector
	 * tables in packet_cleanup(). Doing so will also deregister and free
	 * preferences, this must happen before prefs_cleanup(). That will
	 * update the list of deregistered fields which must be followed by
	 * proto_cleanup() to complete deallocation.
	 */
	wslua_early_cleanup();
#endif

	/*
	 * Note: packet_cleanup() will call registered shutdown routines which
	 * may be used to deregister dynamically registered protocol fields,
	 * and prefs_cleanup() will call uat_clear() which also may be used to
	 * deregister dynamically registered protocol fields. This must be done
	 * before proto_cleanup() to avoid inconsistency and memory leaks.
	 */
	packet_cleanup();
	prefs_cleanup();
	proto_cleanup();

	secrets_cleanup();
	conversation_filters_cleanup();
	reassembly_table_cleanup();
	tap_cleanup();
	expert_cleanup();
	capture_dissector_cleanup();
	export_pdu_cleanup();
	cleanup_enabled_and_disabled_lists();
	stats_tree_cleanup();
	funnel_cleanup();
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

#ifdef HAVE_PLUGINS
	plugins_cleanup(libwireshark_plugins);
	libwireshark_plugins = NULL;
#endif

	if (pinfo_pool_cache != NULL) {
		wmem_destroy_allocator(pinfo_pool_cache);
		pinfo_pool_cache = NULL;
	}

	wmem_cleanup();
}

struct epan_session {
	struct packet_provider_data *prov;	/* packet provider data for this session */
	struct packet_provider_funcs funcs;	/* functions using that data */
};

epan_t *
epan_new(struct packet_provider_data *prov,
    const struct packet_provider_funcs *funcs)
{
	epan_t *session = g_slice_new0(epan_t);

	session->prov = prov;
	session->funcs = *funcs;

	/* XXX, it should take session as param */
	init_dissection();

	return session;
}

const char *
epan_get_user_comment(const epan_t *session, const frame_data *fd)
{
	if (session->funcs.get_user_comment)
		return session->funcs.get_user_comment(session->prov, fd);

	return NULL;
}

const char *
epan_get_interface_name(const epan_t *session, guint32 interface_id)
{
	if (session->funcs.get_interface_name)
		return session->funcs.get_interface_name(session->prov, interface_id);

	return NULL;
}

const char *
epan_get_interface_description(const epan_t *session, guint32 interface_id)
{
	if (session->funcs.get_interface_description)
		return session->funcs.get_interface_description(session->prov, interface_id);

	return NULL;
}

const nstime_t *
epan_get_frame_ts(const epan_t *session, guint32 frame_num)
{
	const nstime_t *abs_ts = NULL;

	if (session && session->funcs.get_frame_ts)
		abs_ts = session->funcs.get_frame_ts(session->prov, frame_num);

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
	conversation_epan_reset();
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

#ifdef HAVE_PLUGINS
	g_slist_foreach(epan_plugins, epan_plugin_dissect_init, edt);
#endif
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
	wtap_rec *rec, tvbuff_t *tvb, frame_data *fd,
	column_info *cinfo)
{
#ifdef HAVE_LUA
	wslua_prime_dfilter(edt); /* done before entering wmem scope */
#endif
	wmem_enter_packet_scope();
	dissect_record(edt, file_type_subtype, rec, tvb, fd, cinfo);

	/* free all memory allocated */
	wmem_leave_packet_scope();
}

void
epan_dissect_run_with_taps(epan_dissect_t *edt, int file_type_subtype,
	wtap_rec *rec, tvbuff_t *tvb, frame_data *fd,
	column_info *cinfo)
{
	wmem_enter_packet_scope();
	tap_queue_init(edt);
	dissect_record(edt, file_type_subtype, rec, tvb, fd, cinfo);
	tap_push_tapped_queue(edt);

	/* free all memory allocated */
	wmem_leave_packet_scope();
}

void
epan_dissect_file_run(epan_dissect_t *edt, wtap_rec *rec,
	tvbuff_t *tvb, frame_data *fd, column_info *cinfo)
{
#ifdef HAVE_LUA
	wslua_prime_dfilter(edt); /* done before entering wmem scope */
#endif
	wmem_enter_packet_scope();
	dissect_file(edt, rec, tvb, fd, cinfo);

	/* free all memory allocated */
	wmem_leave_packet_scope();
}

void
epan_dissect_file_run_with_taps(epan_dissect_t *edt, wtap_rec *rec,
	tvbuff_t *tvb, frame_data *fd, column_info *cinfo)
{
	wmem_enter_packet_scope();
	tap_queue_init(edt);
	dissect_file(edt, rec, tvb, fd, cinfo);
	tap_push_tapped_queue(edt);

	/* free all memory allocated */
	wmem_leave_packet_scope();
}

void
epan_dissect_cleanup(epan_dissect_t* edt)
{
	g_assert(edt);

#ifdef HAVE_PLUGINS
	g_slist_foreach(epan_plugins, epan_plugin_dissect_cleanup, edt);
#endif

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
	g_string_append(str, "with c-ares " ARES_VERSION_STR);

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
#ifdef HAVE_GNUTLS_PKCS11
	g_string_append(str, " and PKCS #11 support");
#endif /* HAVE_GNUTLS_PKCS11 */
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

	/* MaxMindDB */
	g_string_append(str, ", ");
#ifdef HAVE_MAXMINDDB
	g_string_append(str, "with MaxMind DB resolver");
#else
	g_string_append(str, "without MaxMind DB resolver");
#endif /* HAVE_MAXMINDDB */

	/* nghttp2 */
	g_string_append(str, ", ");
#ifdef HAVE_NGHTTP2
	g_string_append(str, "with nghttp2 " NGHTTP2_VERSION);
#else
	g_string_append(str, "without nghttp2");
#endif /* HAVE_NGHTTP2 */

	/* brotli */
	g_string_append(str, ", ");
#ifdef HAVE_BROTLI
	g_string_append(str, "with brotli");
#else
	g_string_append(str, "without brotli");
#endif /* HAVE_BROTLI */

	/* LZ4 */
	g_string_append(str, ", ");
#ifdef HAVE_LZ4
	g_string_append(str, "with LZ4");
#else
	g_string_append(str, "without LZ4");
#endif /* HAVE_LZ4 */

	/* Zstandard */
	g_string_append(str, ", ");
#ifdef HAVE_ZSTD
	g_string_append(str, "with Zstandard");
#else
	g_string_append(str, "without Zstandard");
#endif /* HAVE_ZSTD */

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

	/* brotli */
#ifdef HAVE_BROTLI
	g_string_append_printf(str, ", with brotli %d.%d.%d", BrotliDecoderVersion() >> 24,
		(BrotliDecoderVersion() >> 12) & 0xFFF, BrotliDecoderVersion() & 0xFFF);
#endif
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
