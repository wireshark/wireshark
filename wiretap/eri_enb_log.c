/* eri_enb_log.c
 *
 * Ericsson eNode-B raw log file format decoder for the Wiretap library.
 *
 * Wiretap Library
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "eri_enb_log.h"

#include <string.h>

#include "file_wrappers.h"
#include "wtap-int.h"

static const char eri_enb_log_magic[] = "com_ericsson";

static int eri_enb_log_file_type_subtype = -1;

void register_eri_enb_log(void);

#define MAX_LINE_LENGTH            131072

static bool eri_enb_log_get_packet(FILE_T fh, wtap_rec* rec,
	Buffer* buf, int* err _U_, char** err_info _U_)
{
	static char line[MAX_LINE_LENGTH];
	/* Read in a line */
	int64_t pos_before = file_tell(fh);

	while (file_gets(line, sizeof(line), fh) != NULL)
	{
		nstime_t packet_time;
		int length;
		/* Set length (avoiding strlen()) and offset.. */
		length = (int)(file_tell(fh) - pos_before);

		/* ...but don't want to include newline in line length */
		if (length > 0 && line[length - 1] == '\n') {
			line[length - 1] = '\0';
			length = length - 1;
		}
		/* Nor do we want '\r' (as will be written when log is created on windows) */
		if (length > 0 && line[length - 1] == '\r') {
			line[length - 1] = '\0';
			length = length - 1;
		}

		if (NULL != iso8601_to_nstime(&packet_time, line+1, ISO8601_DATETIME)) {
			rec->ts.secs = packet_time.secs;
			rec->ts.nsecs = packet_time.nsecs;
			rec->presence_flags |= WTAP_HAS_TS;
		} else {
			rec->ts.secs = 0;
			rec->ts.nsecs = 0;
			rec->presence_flags = 0; /* no time stamp, no separate "on the wire" length */
		}
		/* We've got a full packet! */
		rec->rec_type = REC_TYPE_PACKET;
		rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
		rec->rec_header.packet_header.caplen = length;
		rec->rec_header.packet_header.len = length;

		*err = 0;

		/* Make sure we have enough room for the packet */
		ws_buffer_assure_space(buf, rec->rec_header.packet_header.caplen);
		memcpy(ws_buffer_start_ptr(buf), line, rec->rec_header.packet_header.caplen);

		return true;

	}
	return false;
}

/* Find the next packet and parse it; called from wtap_read(). */
static bool eri_enb_log_read(wtap* wth, wtap_rec* rec, Buffer* buf,
	int* err, char** err_info, int64_t* data_offset)
{
	*data_offset = file_tell(wth->fh);

	return eri_enb_log_get_packet(wth->fh, rec, buf, err, err_info);
}

/* Used to read packets in random-access fashion */
static bool eri_enb_log_seek_read(wtap* wth, int64_t seek_off,
	wtap_rec* rec, Buffer* buf, int* err, char** err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
	{
		return false;
	}

	return eri_enb_log_get_packet(wth->random_fh, rec, buf, err, err_info);
}

wtap_open_return_val
eri_enb_log_open(wtap *wth, int *err, char **err_info)
{
	char line1[64];

	/* Look for Gammu DCT3 trace header */
	if (file_gets(line1, sizeof(line1), wth->fh) == NULL)
	{
		*err = file_error(wth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (g_strstr_len(line1, sizeof(line1), eri_enb_log_magic) == NULL)
	{
		return WTAP_OPEN_NOT_MINE;
	}

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	wth->file_type_subtype = eri_enb_log_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_ERI_ENB_LOG;
	wth->file_tsprec = WTAP_TSPREC_NSEC;
	wth->subtype_read = eri_enb_log_read;
	wth->subtype_seek_read = eri_enb_log_seek_read;
	wth->snapshot_length = 0;

	return WTAP_OPEN_MINE;
}

static const struct supported_block_type eri_enb_log_blocks_supported[] = {
	/*
	 * This is a file format that we dissect, so we provide
	 * only one "packet" with the file's contents, and don't
	 * support any options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info eri_enb_log_info = {
	"Ericsson eNode-B raw log", "eri_enb_log", "eri_enb_log", NULL,
	false, BLOCKS_SUPPORTED(eri_enb_log_blocks_supported),
	NULL, NULL, NULL
};

void register_eri_enb_log(void)
{
	eri_enb_log_file_type_subtype = wtap_register_file_type_subtype(&eri_enb_log_info);

	/*
	 * Register name for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	//wtap_register_backwards_compatibility_lua_name("MP4",
	//    eri_enb_log_file_type_subtype);
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
