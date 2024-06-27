/* dpa400.c
 *
 * Unigraf DisplayPort AUX channel monitor output parser
 * Copyright 2018, Dirk Eibach, Guntermann & Drunck GmbH <dirk.eibach@gdsys.cc>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "dpa400.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

enum {
	DPA400_DATA = 0x00,
	DPA400_DATA_END = 0x01,
	DPA400_EVENT = 0x02,
	DPA400_START = 0x03,
	DPA400_STOP = 0x04,
	DPA400_TS_OVERFLOW = 0x84,
};

struct dpa400_header {
	uint8_t t0;
	uint8_t sb0;
	uint8_t t1;
	uint8_t sb1;
	uint8_t t2;
	uint8_t sb2;
};

static int dpa400_file_type_subtype = -1;

void register_dpa400(void);

static bool dpa400_read_header(FILE_T fh, struct dpa400_header *hdr, int *err, char **err_info)
{
	if (!wtap_read_bytes_or_eof(fh, hdr, sizeof(struct dpa400_header), err, err_info))
		return false;

	if (hdr->sb0 || hdr->sb1 || hdr->sb2) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("dpa400: malformed packet header");
		return false;
	}

	return true;
}

static void get_ts(struct dpa400_header *hdr, nstime_t *ts)
{
	uint32_t val;

	val = (hdr->t0 | (hdr->t1 << 8) | ((hdr->t2 & 0x7f) << 16)) << 5;

	ts->secs = val / 1000000;
	ts->nsecs = (val % 1000000) * 1000;
}

static void get_ts_overflow(nstime_t *ts)
{
	uint32_t val = 0x7fffff << 5;

	ts->secs = val / 1000000;
	ts->nsecs = (val % 1000000) * 1000;
}

static uint8_t get_from(struct dpa400_header *hdr)
{
	return hdr->t2 & 0x80;
}

static bool dpa400_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info)
{
	uint8_t chunk[2];
	uint32_t ctr = 0;

	if (!wth || !rec || !buf)
		return false;

	if (!wtap_read_bytes_or_eof(fh, chunk, sizeof(chunk), err, err_info))
		return false;

	if (chunk[1] != 1) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("dpa400: malformed packet framing");
		return false;
	}

	ws_buffer_clean(buf);

	ws_buffer_append(buf, &chunk[0], 1);
	ctr++;

	switch (chunk[0]) {
	case DPA400_STOP: {
		struct dpa400_header hdr;

		if (!dpa400_read_header(fh, &hdr, err, err_info))
			return false;

		get_ts(&hdr, &rec->ts);

		rec->rec_type = REC_TYPE_PACKET;
		rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
		rec->presence_flags = WTAP_HAS_TS;
		rec->rec_header.packet_header.caplen = rec->rec_header.packet_header.len = 0;

		break;
	}

	case DPA400_START:
	case DPA400_EVENT: {
		struct dpa400_header hdr;

		if (!dpa400_read_header(fh, &hdr, err, err_info))
			return false;

		get_ts(&hdr, &rec->ts);

		if (!wtap_read_bytes_or_eof(fh, chunk, sizeof(chunk), err, err_info))
			return false;

		if (chunk[1]) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup("dpa400: malformed packet");
			return false;
		}

		ws_buffer_append(buf, &chunk[0], 1);
		ctr++;

		rec->rec_type = REC_TYPE_PACKET;
		rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
		rec->presence_flags = WTAP_HAS_TS;
		rec->rec_header.packet_header.caplen = rec->rec_header.packet_header.len = ctr;

		break;
	}

	case DPA400_DATA: {
		struct dpa400_header hdr;
		uint8_t from_source;

		if (!dpa400_read_header(fh, &hdr, err, err_info))
			return false;

		get_ts(&hdr, &rec->ts);

		from_source = !get_from(&hdr);
		ws_buffer_append(buf, &from_source, 1);
		ctr++;

		while (1) {
			if (!wtap_read_bytes_or_eof(fh, chunk, sizeof(chunk), err, err_info))
				return false;

			if (chunk[1])
				break;

			if (++ctr > WTAP_MAX_PACKET_SIZE_STANDARD) {
				*err = WTAP_ERR_BAD_FILE;
				*err_info = ws_strdup_printf("dpa400: File has data record bigger than maximum of %u",
					WTAP_MAX_PACKET_SIZE_STANDARD);
				return false;
			}

			ws_buffer_append(buf, &chunk[0], 1);
		}

		rec->rec_type = REC_TYPE_PACKET;
		rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
		rec->presence_flags = WTAP_HAS_TS;
		rec->rec_header.packet_header.caplen = rec->rec_header.packet_header.len = ctr;

		break;
	}

	case DPA400_TS_OVERFLOW: {
		get_ts_overflow(&rec->ts);

		rec->rec_type = REC_TYPE_PACKET;
		rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
		rec->presence_flags = WTAP_HAS_TS;
		rec->rec_header.packet_header.caplen = rec->rec_header.packet_header.len = ctr;

		break;
	}

	default:
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("dpa400: unknown packet type %02x", chunk[0]);
		return false;
	}

	return true;
}

static bool dpa400_seek_read(wtap *wth,int64_t seek_off, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	return dpa400_read_packet(wth, wth->random_fh, rec, buf, err, err_info);
}

static bool dpa400_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return dpa400_read_packet(wth, wth->fh, rec, buf, err, err_info);
}

wtap_open_return_val dpa400_open(wtap *wth, int *err, char **err_info)
{
	char magic[4];
	const char dpa_magic[] = { 'D', 'B', 'F', 'R' };

	/* Read in the number that should be at the start of a "dpa-400" file */
	if (!wtap_read_bytes(wth->fh, &magic, sizeof magic, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(magic, dpa_magic, sizeof(dpa_magic)))
		return WTAP_OPEN_NOT_MINE;

	wth->file_type_subtype = dpa400_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_DPAUXMON;
	wth->file_tsprec = WTAP_TSPREC_USEC;
	wth->subtype_read = dpa400_read;
	wth->subtype_seek_read = dpa400_seek_read;
	wth->snapshot_length = 0;

	/*
	 * Add an IDB; we don't know how many interfaces were
	 * involved, so we just say one interface, about which
	 * we only know the link-layer type, snapshot length,
	 * and time stamp resolution.
	 */
	wtap_add_generated_idb(wth);

	return WTAP_OPEN_MINE;
}

static const struct supported_block_type dpa400_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info dpa400_info = {
	"Unigraf DPA-400 capture", "dpa400", "bin", NULL,
	false, BLOCKS_SUPPORTED(dpa400_blocks_supported),
	NULL, NULL, NULL
};

void register_dpa400(void)
{
	dpa400_file_type_subtype = wtap_register_file_type_subtype(&dpa400_info);

	/*
	 * Register name for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("DPA400",
	    dpa400_file_type_subtype);
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
