/* epan.c
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "epan.h"

#include <stdarg.h>

#include <gcrypt.h>

#ifdef HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#endif /* HAVE_LIBGNUTLS */

#include <glib.h>

#include <wsutil/report_message.h>

#include <epan/exceptions.h>

#include "epan/frame_data.h"

#include "dfilter/dfilter.h"
#include "dfilter/dfilter-translator.h"
#include "epan_dissect.h"

#include <wsutil/nstime.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include <wsutil/version_info.h>

#include "conversation.h"
#include "except.h"
#include "packet.h"
#include "prefs.h"
#include "column-info.h"
#include "tap.h"
#include "addr_resolv.h"
#include "oids.h"
#include <epan/wmem_scopes.h>
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
#include "wscbor.h"
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

#include <ares.h>

#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#ifdef HAVE_NGHTTP3
#include <nghttp3/nghttp3.h>
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

static GSList *epan_plugin_register_all_procotols;
static GSList *epan_plugin_register_all_handoffs;

static wmem_allocator_t *pinfo_pool_cache;

/* Global variables holding the content of the corresponding environment variable
 * to save fetching it repeatedly.
 */
bool wireshark_abort_on_dissector_bug;
bool wireshark_abort_on_too_many_items;

#ifdef HAVE_PLUGINS
/* Used for bookkeeping, includes all libwireshark plugin types (dissector, tap, epan). */
static plugins_t *libwireshark_plugins;
#endif

/* "epan_plugins" are a specific type of libwireshark plugin (the name isn't the best for clarity). */
static GSList *epan_plugins;

const char*
epan_get_version(void) {
	return VERSION;
}

void
epan_get_version_number(int *major, int *minor, int *micro)
{
	if (major)
		*major = VERSION_MAJOR;
	if (minor)
		*minor = VERSION_MINOR;
	if (micro)
		*micro = VERSION_MICRO;
}

#if defined(_WIN32)
// Libgcrypt prints all log messages to stderr by default. This is noisier
// than we would like on Windows. In particular slow_gatherer tends to print
//     "NOTE: you should run 'diskperf -y' to enable the disk statistics"
// which we don't care about.
static void
quiet_gcrypt_logger (void *dummy _U_, int level, const char *format, va_list args)
{
	enum ws_log_level log_level;

	switch (level) {
	case GCRY_LOG_CONT: // Continuation. Ignore for now.
	case GCRY_LOG_DEBUG:
	case GCRY_LOG_INFO:
		return;
	case GCRY_LOG_WARN:
	case GCRY_LOG_BUG:
		log_level = LOG_LEVEL_WARNING;
		break;
	case GCRY_LOG_ERROR:
		log_level = LOG_LEVEL_ERROR;
		break;
	case GCRY_LOG_FATAL:
		log_level = LOG_LEVEL_CRITICAL;
		break;
	default:
		return;
	}
	ws_logv(LOG_DOMAIN_EPAN, log_level, format, args);
}
#endif // _WIN32

static void
epan_plugin_init(void *data, void *user_data _U_)
{
	((epan_plugin *)data)->init();
}

static void
epan_plugin_post_init(void *data, void *user_data _U_)
{
	((epan_plugin *)data)->post_init();
}

static void
epan_plugin_dissect_init(void *data, void *user_data)
{
	((epan_plugin *)data)->dissect_init((epan_dissect_t *)user_data);
}

static void
epan_plugin_dissect_cleanup(void *data, void *user_data)
{
	((epan_plugin *)data)->dissect_cleanup((epan_dissect_t *)user_data);
}

static void
epan_plugin_cleanup(void *data, void *user_data _U_)
{
	((epan_plugin *)data)->cleanup();
}

#ifdef HAVE_PLUGINS
void epan_register_plugin(const epan_plugin *plug)
{
	epan_plugins = g_slist_prepend(epan_plugins, (epan_plugin *)plug);
	if (plug->register_all_protocols)
		epan_plugin_register_all_procotols = g_slist_prepend(epan_plugin_register_all_procotols, plug->register_all_protocols);
	if (plug->register_all_handoffs)
		epan_plugin_register_all_handoffs = g_slist_prepend(epan_plugin_register_all_handoffs, plug->register_all_handoffs);
}
#else /* HAVE_PLUGINS */
void epan_register_plugin(const epan_plugin *plug _U_)
{
	ws_warning("epan_register_plugin: built without support for binary plugins");
}
#endif /* HAVE_PLUGINS */

int epan_plugins_supported(void)
{
#ifdef HAVE_PLUGINS
	return plugins_supported() ? 0 : 1;
#else
	return -1;
#endif
}

static void epan_plugin_register_all_tap_listeners(void *data, void *user_data _U_)
{
	epan_plugin *plug = (epan_plugin *)data;
	if (plug->register_all_tap_listeners)
		plug->register_all_tap_listeners();
}

bool
epan_init(register_cb cb, void *client_data, bool load_plugins)
{
	volatile bool status = true;

	/* Get the value of some environment variables and set corresponding globals for performance reasons*/
	/* If the WIRESHARK_ABORT_ON_DISSECTOR_BUG environment variable is set,
	 * it will call abort(), instead, to make it easier to get a stack trace.
	*/
	if (getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL) {
		wireshark_abort_on_dissector_bug = true;
	} else {
		wireshark_abort_on_dissector_bug = false;
	}

	if (getenv("WIRESHARK_ABORT_ON_TOO_MANY_ITEMS") != NULL) {
		wireshark_abort_on_too_many_items = true;
	} else {
		wireshark_abort_on_too_many_items = false;
	}

	/*
	 * proto_init -> register_all_protocols -> g_async_queue_new which
	 * requires threads to be initialized. This happens automatically with
	 * GLib 2.32, before that g_thread_init must be called. But only since
	 * GLib 2.24, multiple invocations are allowed. Check for an earlier
	 * invocation just in case.
	 */
	/* initialize memory allocation subsystem */
	wmem_init_scopes();

	/* initialize the GUID to name mapping table */
	guids_init();

	/* initialize name resolution (addr_resolv.c) */
	addr_resolv_init();

	except_init();

	dfilter_translator_init();

	if (load_plugins) {
#ifdef HAVE_PLUGINS
		libwireshark_plugins = plugins_init(WS_PLUGIN_EPAN);
#endif
	}

	/* initialize libgcrypt (beware, it won't be thread-safe) */
#if GCRYPT_VERSION_NUMBER >= 0x010a00
	/* Ensure FIPS mode is disabled; it makes it impossible to decrypt
	 * non-NIST approved algorithms. We're decrypting, not promising
	 * security. This overrides any file or environment variables that
	 * would normally turn on FIPS mode, and has to be done prior to
	 * gcry_check_version().
	 */
	gcry_control (GCRYCTL_NO_FIPS_MODE);
#endif
	gcry_check_version(NULL);
#if defined(_WIN32)
	gcry_set_log_handler (quiet_gcrypt_logger, NULL);
#endif
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#ifdef HAVE_LIBGNUTLS
	gnutls_global_init();
#if GNUTLS_VERSION_NUMBER >= 0x030602
	if (gnutls_fips140_mode_enabled()) {
		gnutls_fips140_set_mode(GNUTLS_FIPS140_LAX, 0);
	}
#endif
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
		export_pdu_init();
		tap_init();
		prefs_init();
		expert_init();
		packet_init();
		secrets_init();
		conversation_init();
		capture_dissector_init();
		reassembly_tables_init();
		conversation_filters_init();
		g_slist_foreach(epan_plugins, epan_plugin_init, NULL);
		proto_init(epan_plugin_register_all_procotols, epan_plugin_register_all_handoffs, cb, client_data);
		g_slist_foreach(epan_plugins, epan_plugin_register_all_tap_listeners, NULL);
		packet_cache_proto_handles();
		dfilter_init();
		wscbor_init();
		final_registration_all_protocols();
		print_cache_field_handles();
		expert_packet_init();
#ifdef HAVE_LUA
		wslua_init(cb, client_data);
#endif
		g_slist_foreach(epan_plugins, epan_plugin_post_init, NULL);
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
		status = false;
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
	g_slist_foreach(epan_plugins, epan_plugin_cleanup, NULL);
	g_slist_free(epan_plugins);
	epan_plugins = NULL;
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

	dfilter_translator_cleanup();

	if (pinfo_pool_cache != NULL) {
		wmem_destroy_allocator(pinfo_pool_cache);
		pinfo_pool_cache = NULL;
	}

	wmem_cleanup_scopes();

#ifdef HAVE_PLUGINS
	plugins_cleanup(libwireshark_plugins);
	libwireshark_plugins = NULL;
#endif
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

wtap_block_t
epan_get_modified_block(const epan_t *session, const frame_data *fd)
{
	if (session->funcs.get_modified_block)
		return session->funcs.get_modified_block(session->prov, fd);

	return NULL;
}

const char *
epan_get_interface_name(const epan_t *session, uint32_t interface_id, unsigned section_number)
{
	if (session->funcs.get_interface_name)
		return session->funcs.get_interface_name(session->prov, interface_id, section_number);

	return NULL;
}

const char *
epan_get_interface_description(const epan_t *session, uint32_t interface_id, unsigned section_number)
{
	if (session->funcs.get_interface_description)
		return session->funcs.get_interface_description(session->prov, interface_id, section_number);

	return NULL;
}

const nstime_t *
epan_get_frame_ts(const epan_t *session, uint32_t frame_num)
{
	const nstime_t *abs_ts = NULL;

	if (session && session->funcs.get_frame_ts)
		abs_ts = session->funcs.get_frame_ts(session->prov, frame_num);

	if (!abs_ts) {
		/* This can happen if frame_num doesn't have a ts */
		ws_debug("!!! couldn't get frame ts for %u !!!\n", frame_num);
	}

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
static int always_visible_refcount;

void
epan_set_always_visible(bool force)
{
	if (force)
		always_visible_refcount++;
	else if (always_visible_refcount > 0)
		always_visible_refcount--;
}

void
epan_dissect_init(epan_dissect_t *edt, epan_t *session, const bool create_proto_tree, const bool proto_tree_visible)
{
	ws_assert(edt);

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
		proto_tree_set_visible(edt->tree, (always_visible_refcount > 0) ? true : proto_tree_visible);
	}
	else {
		edt->tree = NULL;
	}

	edt->tvb = NULL;

	g_slist_foreach(epan_plugins, epan_plugin_dissect_init, edt);
}

void
epan_dissect_reset(epan_dissect_t *edt)
{
	/* We have to preserve the pool pointer across the memzeroing */
	wmem_allocator_t *tmp;

	ws_assert(edt);

	wtap_block_unref(edt->pi.rec->block);

	g_slist_free(edt->pi.proto_data);

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
epan_dissect_new(epan_t *session, const bool create_proto_tree, const bool proto_tree_visible)
{
	epan_dissect_t *edt;

	edt = g_new0(epan_dissect_t, 1);

	epan_dissect_init(edt, session, create_proto_tree, proto_tree_visible);
	return edt;
}

void
epan_dissect_fake_protocols(epan_dissect_t *edt, const bool fake_protocols)
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
	wtap_block_unref(rec->block);
	rec->block = NULL;
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
	wtap_block_unref(rec->block);
	rec->block = NULL;
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
	wtap_block_unref(rec->block);
	rec->block = NULL;
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
	wtap_block_unref(rec->block);
	rec->block = NULL;
}

void
epan_dissect_cleanup(epan_dissect_t* edt)
{
	ws_assert(edt);

	g_slist_foreach(epan_plugins, epan_plugin_dissect_cleanup, edt);

	g_slist_free(edt->pi.proto_data);

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
	unsigned i;

	for (i = 0; i < hfids->len; i++) {
		proto_tree_prime_with_hfid(edt->tree,
		    g_array_index(hfids, int, i));
	}
}

/* ----------------------- */
const char *
epan_custom_set(epan_dissect_t *edt, GSList *field_ids,
			     int occurrence,
			     char *result,
			     char *expr, const int size )
{
	return proto_custom_set(edt->tree, field_ids, occurrence, result, expr, size);
}

void
epan_dissect_fill_in_columns(epan_dissect_t *edt, const bool fill_col_exprs, const bool fill_fd_colums)
{
	col_custom_set_edt(edt, edt->pi.cinfo);
	col_fill_in(&edt->pi, fill_col_exprs, fill_fd_colums);
}

bool
epan_dissect_packet_contains_field(epan_dissect_t* edt,
				   const char *field_name)
{
	GPtrArray* array;
	int field_id;
	bool contains_field;

	if (!edt || !edt->tree)
		return false;
	field_id = proto_get_id_by_filter_name(field_name);
	if (field_id < 0)
		return false;
	array = proto_find_finfo(edt->tree, field_id);
	contains_field = (array->len > 0) ? true : false;
	g_ptr_array_free(array, true);
	return contains_field;
}

/*
 * Get compile-time information for libraries used by libwireshark.
 */
void
epan_gather_compile_info(feature_list l)
{
	gather_zlib_compile_info(l);
	gather_zlib_ng_compile_info(l);
	gather_pcre2_compile_info(l);

	/* Lua */
#ifdef HAVE_LUA
#ifdef HAVE_LUA_UNICODE
	with_feature(l, "%s", LUA_RELEASE" (with UfW patches)");
#else /* HAVE_LUA_UNICODE */
	with_feature(l, "%s", LUA_RELEASE);
#endif /* HAVE_LUA_UNICODE */
#else /* HAVE_LUA */
	without_feature(l, "Lua");
#endif /* HAVE_LUA */

	/* GnuTLS */
#ifdef HAVE_LIBGNUTLS
#ifdef HAVE_GNUTLS_PKCS11
	with_feature(l, "GnuTLS %s and PKCS #11 support", LIBGNUTLS_VERSION);
#else
	with_feature(l, "GnuTLS %s", LIBGNUTLS_VERSION);
#endif /* HAVE_GNUTLS_PKCS11 */
#else
	without_feature(l, "GnuTLS");
#endif /* HAVE_LIBGNUTLS */

	/* Gcrypt */
	with_feature(l, "Gcrypt %s", GCRYPT_VERSION);

	/* Kerberos */
#if defined(HAVE_MIT_KERBEROS)
	with_feature(l, "Kerberos (MIT)");
#elif defined(HAVE_HEIMDAL_KERBEROS)
	with_feature(l, "Kerberos (Heimdal)");
#else
	without_feature(l, "Kerberos");
#endif /* HAVE_KERBEROS */

	/* MaxMindDB */
#ifdef HAVE_MAXMINDDB
	with_feature(l, "MaxMind");
#else
	without_feature(l, "MaxMind");
#endif /* HAVE_MAXMINDDB */

	/* nghttp2 */
#ifdef HAVE_NGHTTP2
	with_feature(l, "nghttp2 %s", NGHTTP2_VERSION);
#else
	without_feature(l, "nghttp2");
#endif /* HAVE_NGHTTP2 */

	/* nghttp3 */
#ifdef HAVE_NGHTTP3
	with_feature(l, "nghttp3 %s", NGHTTP3_VERSION);
#else
	without_feature(l, "nghttp3");
#endif /* HAVE_NGHTTP3 */

	/* brotli */
#ifdef HAVE_BROTLI
	with_feature(l, "brotli");
#else
	without_feature(l, "brotli");
#endif /* HAVE_BROTLI */

	/* LZ4 */
#ifdef HAVE_LZ4
	with_feature(l, "LZ4");
#else
	without_feature(l, "LZ4");
#endif /* HAVE_LZ4 */

	/* Zstandard */
#ifdef HAVE_ZSTD
	with_feature(l, "Zstandard");
#else
	without_feature(l, "Zstandard");
#endif /* HAVE_ZSTD */

	/* Snappy */
#ifdef HAVE_SNAPPY
	with_feature(l, "Snappy");
#else
	without_feature(l, "Snappy");
#endif /* HAVE_SNAPPY */

	/* libxml2 */
#ifdef HAVE_LIBXML2
	with_feature(l, "libxml2 %s", LIBXML_DOTTED_VERSION);
#else
	without_feature(l, "libxml2");
#endif /* HAVE_LIBXML2 */

	/* libsmi */
#ifdef HAVE_LIBSMI
	with_feature(l, "libsmi %s", SMI_VERSION_STRING);
#else
	without_feature(l, "libsmi");
#endif /* HAVE_LIBSMI */
}

/*
 * Get runtime information for libraries used by libwireshark.
 */
void
epan_gather_runtime_info(feature_list l)
{
	gather_zlib_runtime_info(l);
	gather_pcre2_runtime_info(l);

	/* c-ares */
	with_feature(l, "c-ares %s", ares_version(NULL));

	/* GnuTLS */
#ifdef HAVE_LIBGNUTLS
	with_feature(l, "GnuTLS %s", gnutls_check_version(NULL));
#endif /* HAVE_LIBGNUTLS */

	/* Gcrypt */
	with_feature(l, "Gcrypt %s", gcry_check_version(NULL));

	/* nghttp2 */
#if NGHTTP2_VERSION_AGE >= 1
	nghttp2_info *nghttp2_ptr = nghttp2_version(0);
	with_feature(l, "nghttp2 %s",  nghttp2_ptr->version_str);
#endif /* NGHTTP2_VERSION_AGE */

	/* nghttp3 */
#if NGHTTP3_VERSION_AGE >= 1
	const nghttp3_info *nghttp3_ptr = nghttp3_version(0);
	with_feature(l, "nghttp3 %s", nghttp3_ptr->version_str);
#endif /* NGHTTP3_VERSION_AGE */

	/* brotli */
#ifdef HAVE_BROTLI
	with_feature(l, "brotli %d.%d.%d", BrotliDecoderVersion() >> 24,
		(BrotliDecoderVersion() >> 12) & 0xFFF, BrotliDecoderVersion() & 0xFFF);
#endif

	/* LZ4 */
#if LZ4_VERSION_NUMBER >= 10703
	with_feature(l, "LZ4 %s", LZ4_versionString());
#endif /* LZ4_VERSION_NUMBER */

	/* Zstandard */
#if ZSTD_VERSION_NUMBER >= 10300
	with_feature(l, "Zstandard %s", ZSTD_versionString());
#endif /* ZSTD_VERSION_NUMBER */

	/* libsmi */
#ifdef HAVE_SMI_VERSION_STRING
	with_feature(l, "libsmi %s", smi_version_string);
#endif /* HAVE_SMI_VERSION_STRING */
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
