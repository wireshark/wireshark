/* sdjournal.c
 * sdjournal is an extcap tool used to dump systemd journal entries.
 *
 * Adapted from sshdump.
 * Copyright 2018, Gerald Combs and Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * To do:
 * - Add an option for sd_journal_open flags, e.g. SD_JOURNAL_LOCAL_ONLY.
 * - Add journalctl options - --boot, --machine, --directory, etc.
 */

#include "config.h"

#include <extcap/extcap-base.h>
#include <wsutil/interface.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <writecap/pcapio.h>
#include <wiretap/wtap.h>

#include <systemd/sd-journal.h>
#include <systemd/sd-id128.h>

#include <errno.h>
#include <string.h>
#include <fcntl.h>

#define SDJOURNAL_VERSION_MAJOR "1"
#define SDJOURNAL_VERSION_MINOR "0"
#define SDJOURNAL_VERSION_RELEASE "0"

#define SDJOURNAL_EXTCAP_INTERFACE "sdjournal"
#define BLOCK_TYPE_SYSTEMD_JOURNAL 0x00000009

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_START_FROM
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	{ "help", no_argument, NULL, OPT_HELP},
	{ "version", no_argument, NULL, OPT_VERSION},
	{ "start-from", required_argument, NULL, OPT_START_FROM},
	{ 0, 0, 0, 0}
};

#define FLD_BOOT_ID "_BOOT_ID="
#define FLD_BOOT_ID_LEN (8 + 1 + 33 + 1)

// The Journal Export Format specification doesn't place limits on entry
// lengths or lines per entry. We do.
#define ENTRY_BUF_LENGTH WTAP_MAX_PACKET_SIZE_STANDARD
#define MAX_EXPORT_ENTRY_LENGTH (ENTRY_BUF_LENGTH - 4 - 4 - 4) // Block type - total length - total length

static int sdj_dump_entries(sd_journal *jnl, FILE* fp)
{
	int ret = EXIT_SUCCESS;
	guint8 *entry_buff = g_new(guint8, ENTRY_BUF_LENGTH);
	int jr = 0;

	/*
	 * Read journal entries and write them as packets. Output must
	 * match `journalctl --output=export`.
	 */
	while (jr == 0) {
		char *cursor;
		uint64_t pkt_rt_ts, mono_ts;
		sd_id128_t boot_id;
		char boot_id_str[FLD_BOOT_ID_LEN] = FLD_BOOT_ID;
		guint32 block_type = BLOCK_TYPE_SYSTEMD_JOURNAL;
		guint32 data_end = 8; // Block type + total length
		const void *fld_data;
		size_t fld_len;
		guint64 bytes_written = 0;
		int err;

		memcpy(entry_buff, &block_type, 4);

		jr = sd_journal_next(jnl);
		g_debug("sd_journal_next: %d", jr);
		if (jr < 0) {
			g_warning("Error fetching journal entry: %s", g_strerror(jr));
			goto end;
		} else if (jr == 0) {
			sd_journal_wait(jnl, (uint64_t) -1);
			continue;
		}

		jr = sd_journal_get_cursor(jnl, &cursor);
		if (jr < 0) {
			g_warning("Error fetching cursor: %s", g_strerror(jr));
			goto end;
		}
		data_end += g_snprintf(entry_buff+data_end, MAX_EXPORT_ENTRY_LENGTH-data_end, "__CURSOR=%s\n", cursor);
		free(cursor);

		jr = sd_journal_get_realtime_usec(jnl, &pkt_rt_ts);
		if (jr < 0) {
			g_warning("Error fetching realtime timestamp: %s", g_strerror(jr));
			goto end;
		}
		data_end += g_snprintf(entry_buff+data_end, MAX_EXPORT_ENTRY_LENGTH-data_end, "__REALTIME_TIMESTAMP=%" G_GUINT64_FORMAT "\n", pkt_rt_ts);

		jr = sd_journal_get_monotonic_usec(jnl, &mono_ts, &boot_id);
		if (jr < 0) {
			g_warning("Error fetching monotonic timestamp: %s", g_strerror(jr));
			goto end;
		}
		sd_id128_to_string(boot_id, boot_id_str + strlen(FLD_BOOT_ID));
		data_end += g_snprintf(entry_buff+data_end, MAX_EXPORT_ENTRY_LENGTH-data_end, "__MONOTONIC_TIMESTAMP=%" G_GUINT64_FORMAT "\n%s\n", mono_ts, boot_id_str);
		g_debug("Entry header is %u bytes", data_end);

		SD_JOURNAL_FOREACH_DATA(jnl, fld_data, fld_len) {
			guint8 *eq_ptr = (guint8 *) memchr(fld_data, '=', fld_len);
			if (!eq_ptr) {
				g_warning("Invalid field.");
				goto end;
			}
			if (g_utf8_validate((const char *) fld_data, (gssize) fld_len, NULL)) {
				// Allow for two trailing newlines, one here and one
				// at the end of the buffer.
				if (fld_len > MAX_EXPORT_ENTRY_LENGTH-data_end-2) {
					g_debug("Breaking on UTF-8 field: %u + %zd", data_end, fld_len);
					break;
				}
				memcpy(entry_buff+data_end, fld_data, fld_len);
				data_end += (guint32) fld_len;
				entry_buff[data_end] = '\n';
				data_end++;
			} else {
				// \n + 64-bit size + \n + trailing \n = 11
				if (fld_len > MAX_EXPORT_ENTRY_LENGTH-data_end-11) {
					g_debug("Breaking on binary field: %u + %zd", data_end, fld_len);
					break;
				}
				ptrdiff_t name_len = eq_ptr - (const guint8 *) fld_data;
				uint64_t le_data_len;
				le_data_len = htole64(fld_len - name_len - 1);
				memcpy(entry_buff+data_end, fld_data, name_len);
				data_end+= name_len;
				entry_buff[data_end] = '\n';
				data_end++;
				memcpy(entry_buff+data_end, &le_data_len, 8);
				data_end += 8;
				memcpy(entry_buff+data_end, (const guint8 *) fld_data + name_len + 1, fld_len - name_len);
				data_end += fld_len - name_len;
			}
		}

		if (data_end % 4) {
			size_t pad_len = 4 - (data_end % 4);
			memset(entry_buff+data_end, '\0', pad_len);
			data_end += pad_len;
		}

		guint32 total_len = data_end + 4;
		memcpy (entry_buff+4, &total_len, 4);
		memcpy (entry_buff+data_end, &total_len, 4);

		g_debug("Attempting to write %u bytes", total_len);
		if (!pcapng_write_block(fp, entry_buff, total_len, &bytes_written, &err)) {
			g_warning("Can't write event: %s", strerror(err));
			ret = EXIT_FAILURE;
			break;
		}

		fflush(fp);
	}

end:
	g_free(entry_buff);
	return ret;
}

static int sdj_start_export(const int start_from_entries, const gboolean start_from_end, const char* fifo)
{
	FILE* fp = stdout;
	guint64 bytes_written = 0;
	int err;
	sd_journal *jnl = NULL;
	sd_id128_t boot_id;
	char boot_id_str[FLD_BOOT_ID_LEN] = FLD_BOOT_ID;
	int ret = EXIT_FAILURE;
	char* err_info = NULL;
	char *appname;
	gboolean success;
	int jr = 0;

	if (g_strcmp0(fifo, "-")) {
		/* Open or create the output file */
		fp = fopen(fifo, "wb");
		if (fp == NULL) {
			g_warning("Error creating output file: %s (%s)", fifo, g_strerror(errno));
			return EXIT_FAILURE;
		}
	}


	appname = g_strdup_printf(SDJOURNAL_EXTCAP_INTERFACE " (Wireshark) %s.%s.%s",
		SDJOURNAL_VERSION_MAJOR, SDJOURNAL_VERSION_MINOR, SDJOURNAL_VERSION_RELEASE);
	success = pcapng_write_section_header_block(fp,
							NULL,    /* Comment */
							NULL,    /* HW */
							NULL,    /* OS */
							appname,
							-1,      /* section_length */
							&bytes_written,
							&err);
	g_free(appname);

	if (!success) {
		g_warning("Can't write pcapng file header");
		goto cleanup;
	}

	jr = sd_journal_open(&jnl, 0);
	if (jr < 0) {
		g_warning("Error opening journal: %s", g_strerror(jr));
		goto cleanup;
	}

	jr = sd_id128_get_boot(&boot_id);
	if (jr < 0) {
		g_warning("Error fetching system boot ID: %s", g_strerror(jr));
		goto cleanup;
	}

	sd_id128_to_string(boot_id, boot_id_str + strlen(FLD_BOOT_ID));
	jr = sd_journal_add_match(jnl, boot_id_str, strlen(boot_id_str));
	if (jr < 0) {
		g_warning("Error adding match: %s", g_strerror(jr));
		goto cleanup;
	}

	// According to the documentation, fields *might be* truncated to 64K.
	// Let's assume that 2048 is a good balance between fetching entire fields
	// and being able to fit as many fields as possible into a packet.
	sd_journal_set_data_threshold(jnl, 2048);

	if (start_from_end) {
		g_debug("Attempting to seek %d entries from the end", start_from_entries);
		jr = sd_journal_seek_tail(jnl);
		if (jr < 0) {
			g_warning("Error starting at end: %s", g_strerror(jr));
			goto cleanup;
		}
		jr = sd_journal_previous_skip(jnl, (uint64_t) start_from_entries + 1);
		if (jr < 0) {
			g_warning("Error skipping backward: %s", g_strerror(jr));
			goto cleanup;
		}
	} else {
		g_debug("Attempting to seek %d entries from the beginning", start_from_entries);
		jr = sd_journal_seek_head(jnl);
		if (jr < 0) {
			g_warning("Error starting at beginning: %s", g_strerror(jr));
			goto cleanup;
		}
		if (start_from_entries > 0) {
			jr = sd_journal_next_skip(jnl, (uint64_t) start_from_entries);
			if (jr < 0) {
				g_warning("Error skipping forward: %s", g_strerror(jr));
				goto cleanup;
			}
		}
	}

	/* read from channel and write into fp */
	if (sdj_dump_entries(jnl, fp) != 0) {
		g_warning("Error dumping entries");
		goto cleanup;
	}

	ret = EXIT_SUCCESS;

cleanup:
	if (jnl) {
		sd_journal_close(jnl);
	}

	if (err_info) {
		g_warning("%s", err_info);
	}

	g_free(err_info);

	/* clean up and exit */
	if (g_strcmp0(fifo, "-")) {
		fclose(fp);
	}
	return ret;
}

static int list_config(char *interface)
{
	unsigned inc = 0;

	if (!interface) {
		g_warning("ERROR: No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, SDJOURNAL_EXTCAP_INTERFACE)) {
		g_warning("ERROR: interface must be %s", SDJOURNAL_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	printf("arg {number=%u}{call=--start-from}{display=Starting position}"
			"{type=string}{tooltip=The journal starting position. Values "
			"with a leading \"+\" start from the beginning, similar to the "
			"\"tail\" command}{required=false}{group=Journal}\n", inc++);

	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	char* init_progfile_dir_error;
	int result;
	int option_idx = 0;
	int start_from_entries = 10;
	gboolean start_from_end = TRUE;
	int ret = EXIT_FAILURE;
	extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
	char* help_url;
	char* help_header = NULL;

	/*
	 * Get credential information for later use.
	 */
	init_process_policies();

	/*
	 * Attempt to get the pathname of the directory containing the
	 * executable file.
	 */
	init_progfile_dir_error = init_progfile_dir(argv[0]);
	if (init_progfile_dir_error != NULL) {
		g_warning("Can't get pathname of directory containing the captype program: %s.",
			init_progfile_dir_error);
		g_free(init_progfile_dir_error);
	}

	help_url = data_file_url("sdjournal.html");
	extcap_base_set_util_info(extcap_conf, argv[0], SDJOURNAL_VERSION_MAJOR, SDJOURNAL_VERSION_MINOR,
			SDJOURNAL_VERSION_RELEASE, help_url);
	g_free(help_url);
	// We don't have an SDJOURNAL DLT, so use USER0 (147).
	extcap_base_register_interface(extcap_conf, SDJOURNAL_EXTCAP_INTERFACE, "systemd Journal Export", 147, "USER0");

	help_header = g_strdup_printf(
			" %s --extcap-interfaces\n"
			" %s --extcap-interface=%s --extcap-dlts\n"
			" %s --extcap-interface=%s --extcap-config\n"
			" %s --extcap-interface=%s --start-from=+0 --fifo=FILENAME --capture\n",
			argv[0],
			argv[0], SDJOURNAL_EXTCAP_INTERFACE,
			argv[0], SDJOURNAL_EXTCAP_INTERFACE,
			argv[0], SDJOURNAL_EXTCAP_INTERFACE);
	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);
	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");
	extcap_help_add_option(extcap_conf, "--start-from <entry count>", "starting position");

	opterr = 0;
	optind = 0;

	if (argc == 1) {
		extcap_help_print(extcap_conf);
		goto end;
	}

	while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {

		switch (result) {

			case OPT_HELP:
				extcap_help_print(extcap_conf);
				ret = EXIT_SUCCESS;
				goto end;

			case OPT_VERSION:
				extcap_version_print(extcap_conf);
				ret = EXIT_SUCCESS;
				goto end;

			case OPT_START_FROM:
				start_from_entries = (int) strtol(optarg, NULL, 10);
				if (errno == EINVAL) {
					g_warning("Invalid entry count: %s", optarg);
					goto end;
				}
				if (strlen(optarg) > 0 && optarg[0] == '+') {
					start_from_end = FALSE;
				}
				if (start_from_entries < 0) {
					start_from_end = TRUE;
					start_from_entries *= -1;
				}
				g_debug("start %d from %s", start_from_entries, start_from_end ? "end" : "beginning");
				break;

			case ':':
				/* missing option argument */
				g_warning("Option '%s' requires an argument", argv[optind - 1]);
				break;

			default:
				if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, optarg)) {
					g_warning("Invalid option: %s", argv[optind - 1]);
					goto end;
				}
		}
	}

	extcap_cmdline_debug(argv, argc);

	if (extcap_base_handle_interface(extcap_conf)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (extcap_conf->show_config) {
		ret = list_config(extcap_conf->interface);
		goto end;
	}

	if (extcap_conf->capture) {
		ret = sdj_start_export(start_from_entries, start_from_end, extcap_conf->fifo);
	} else {
		g_debug("You should not come here... maybe some parameter missing?");
		ret = EXIT_FAILURE;
	}

end:
	/* clean up stuff */
	extcap_base_cleanup(&extcap_conf);
	return ret;
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
