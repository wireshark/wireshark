/* oss-fuzzshark.c
 *
 * Fuzzer variant of Wireshark for oss-fuzz
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <glib.h>

#include <epan/epan-int.h>
#include <epan/epan.h>

#include <wsutil/cmdarg_err.h>
#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <ws_version_info.h>

#include <wiretap/wtap.h>

#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/print.h>
#include <epan/epan_dissect.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#define EPAN_INIT_FAIL 2

static column_info fuzz_cinfo;
static epan_t *fuzz_epan;
static epan_dissect_t *fuzz_edt;

/*
 * General errors and warnings are reported with an console message
 * in oss-fuzzshark.
 */
static void
failure_warning_message(const char *msg_format, va_list ap)
{
	fprintf(stderr, "oss-fuzzshark: ");
	vfprintf(stderr, msg_format, ap);
	fprintf(stderr, "\n");
}

/*
 * Open/create errors are reported with an console message in oss-fuzzshark.
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
	fprintf(stderr, "oss-fuzzshark: ");
	fprintf(stderr, file_open_error_message(err, for_writing), filename);
	fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in oss-fuzzshark.
 */
static void
read_failure_message(const char *filename, int err)
{
	cmdarg_err("An error occurred while reading from the file \"%s\": %s.", filename, g_strerror(err));
}

/*
 * Write errors are reported with an console message in oss-fuzzshark.
 */
static void
write_failure_message(const char *filename, int err)
{
	cmdarg_err("An error occurred while writing to the file \"%s\": %s.", filename, g_strerror(err));
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
failure_message_cont(const char *msg_format, va_list ap)
{
	vfprintf(stderr, msg_format, ap);
	fprintf(stderr, "\n");
}

static const nstime_t *
fuzzshark_get_frame_ts(void *data _U_, guint32 frame_num _U_)
{
	static nstime_t empty;

	return &empty;
}

static epan_t *
fuzzshark_epan_new(void)
{
	epan_t *epan = epan_new();

	epan->get_frame_ts = fuzzshark_get_frame_ts;
	epan->get_interface_name = NULL;
	epan->get_interface_description = NULL;
	epan->get_user_comment = NULL;

	return epan;
}

static int
fuzz_init(int argc _U_, char **argv)
{
	GString             *comp_info_str;
	GString             *runtime_info_str;
	char                *init_progfile_dir_error;

	char                *err_msg = NULL;
	e_prefs             *prefs_p;
	int                  ret = EXIT_SUCCESS;

#if defined(FUZZ_DISSECTOR_TARGET)
	dissector_handle_t fuzz_handle = NULL;
#endif

	cmdarg_err_init(failure_warning_message, failure_message_cont);

	/*
	 * Get credential information for later use, and drop privileges
	 * before doing anything else.
	 * Let the user know if anything happened.
	 */
	init_process_policies();
#if 0 /* disable setresgid(), it fails with -EINVAL https://github.com/google/oss-fuzz/pull/532#issuecomment-294515463 */
	relinquish_special_privs_perm();
#endif

	/*
	 * Attempt to get the pathname of the executable file.
	 */
	init_progfile_dir_error = init_progfile_dir(argv[0], fuzz_init);
	if (init_progfile_dir_error != NULL)
		fprintf(stderr, "fuzzshark: Can't get pathname of oss-fuzzshark program: %s.\n", init_progfile_dir_error);

	/* Get the compile-time version information string */
	comp_info_str = get_compiled_version_info(NULL, epan_get_compiled_version_info);

	/* Get the run-time version information string */
	runtime_info_str = get_runtime_version_info(epan_get_runtime_version_info);

	/* Add it to the information to be reported on a crash. */
	ws_add_crash_info("OSS Fuzzshark (Wireshark) %s\n"
	     "\n"
	     "%s"
	     "\n"
	     "%s",
	     get_ws_vcs_version_info(),
	     comp_info_str->str,
	     runtime_info_str->str);
	g_string_free(comp_info_str, TRUE);
	g_string_free(runtime_info_str, TRUE);

	init_report_message(failure_warning_message, failure_warning_message,
	     open_failure_message, read_failure_message, write_failure_message);

	timestamp_set_type(TS_RELATIVE);
	timestamp_set_precision(TS_PREC_AUTO);
	timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

	wtap_init();

#ifdef HAVE_PLUGINS
	/* Register all the plugin types we have. */
	epan_register_plugin_types(); /* Types known to libwireshark */

	/* Scan for plugins.  This does *not* call their registration routines; that's done later. */
	scan_plugins(REPORT_LOAD_FAILURE);

	/* Register all libwiretap plugin modules. */
	register_all_wiretap_modules();
#endif

	/* Register all dissectors; we must do this before checking for the
	   "-G" flag, as the "-G" flag dumps information registered by the
	   dissectors, and we must do it before we read the preferences, in
	   case any dissectors register preferences. */
	if (!epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL))
	{
		ret = EPAN_INIT_FAIL;
		goto clean_exit;
	}

	/* Load libwireshark settings from the current profile. */
	prefs_p = epan_load_settings();

	if (!color_filters_init(&err_msg, NULL))
	{
		fprintf(stderr, "%s\n", err_msg);
		g_free(err_msg);
	}

	/* Notify all registered modules that have had any of their preferences
	   changed either from one of the preferences file or from the command
	   line that their preferences have changed. */
	prefs_apply_all();

	/* Build the column format array */
	build_column_format_array(&fuzz_cinfo, prefs_p->num_cols, TRUE);

#if defined(FUZZ_DISSECTOR_TABLE) && defined(FUZZ_DISSECTOR_TARGET)
# define FUZZ_EPAN 1
	fprintf(stderr, "oss-fuzzshark: configured for dissector: %s in table: %s\n", FUZZ_DISSECTOR_TARGET, FUZZ_DISSECTOR_TABLE);

	/* search for handle, cannot use dissector_table_get_dissector_handle() cause it's using short-name, and I already used filter name in samples ;/ */
	{
		GSList *handle_list = dissector_table_get_dissector_handles(find_dissector_table(FUZZ_DISSECTOR_TABLE));
		while (handle_list)
		{
			dissector_handle_t handle = (dissector_handle_t) handle_list->data;
			const char *handle_filter_name = proto_get_protocol_filter_name(dissector_handle_get_protocol_index(handle));

			if (!strcmp(handle_filter_name, FUZZ_DISSECTOR_TARGET))
				fuzz_handle = handle;
			handle_list = handle_list->next;
		}
	}

#elif defined(FUZZ_DISSECTOR_TARGET)
# define FUZZ_EPAN 2
	fprintf(stderr, "oss-fuzzshark: configured for dissector: %s\n", FUZZ_DISSECTOR_TARGET);
	fuzz_handle = find_dissector(FUZZ_DISSECTOR_TARGET);
#endif

#ifdef FUZZ_EPAN
	g_assert(fuzz_handle != NULL);
	register_postdissector(fuzz_handle);
#endif

	fuzz_epan = fuzzshark_epan_new();
	fuzz_edt = epan_dissect_new(fuzz_epan, TRUE, FALSE);

	return 0;
clean_exit:
	wtap_cleanup();
	free_progdirs();
#ifdef HAVE_PLUGINS
	plugins_cleanup();
#endif
	return ret;
}

#ifdef FUZZ_EPAN
int
LLVMFuzzerTestOneInput(guint8 *buf, size_t real_len)
{
	static guint32 framenum = 0;
	epan_dissect_t *edt = fuzz_edt;

	guint32 len = (guint32) real_len;

	struct wtap_pkthdr whdr;
	frame_data fdlocal;

	memset(&whdr, 0, sizeof(whdr));

	whdr.rec_type = REC_TYPE_PACKET;
	whdr.caplen = len;
	whdr.len = len;

	/* whdr.pkt_encap = WTAP_ENCAP_ETHERNET; */
	whdr.pkt_encap = G_MAXINT16;
	whdr.presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN; /* most common flags... */

	frame_data_init(&fdlocal, ++framenum, &whdr, /* offset */ 0, /* cum_bytes */ 0);
	/* frame_data_set_before_dissect() not needed */
	epan_dissect_run(edt, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, &whdr, tvb_new_real_data(buf, len, len), &fdlocal, NULL /* &fuzz_cinfo */);
	frame_data_destroy(&fdlocal);

	epan_dissect_reset(edt);
	return 0;
}

#else
# error "Missing fuzz target."
#endif

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int ret;

	ret = fuzz_init(*argc, *argv);
	if (ret != 0)
		exit(ret);

	return 0;
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
