/* mp4.c
 *
 * MP4 (ISO/IEC 14496-12) file format decoder for the Wiretap library.
 *
 * Wiretap Library
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mp4.h"

#include <string.h>

#include "file_wrappers.h"
#include "wtap-int.h"

static const uint8_t mp4_magic[] = { 'f', 't', 'y', 'p' };
static const uint8_t mp4_magic_sidx[] = { 's', 'i', 'd', 'x' };
static const uint8_t mp4_magic_styp[] = { 's', 't', 'y', 'p' };

static int mp4_file_type_subtype = -1;

void register_mp4(void);

wtap_open_return_val
mp4_open(wtap *wth, int *err, char **err_info)
{
	char magic_buf[8];
	int bytes_read;

	bytes_read = file_read(magic_buf, sizeof (magic_buf), wth->fh);

	if (bytes_read < 0) {
		*err = file_error(wth->fh, err_info);
		return WTAP_OPEN_ERROR;
	}
	if (bytes_read == 0)
		return WTAP_OPEN_NOT_MINE;

	if (bytes_read == sizeof (magic_buf) &&
			memcmp(magic_buf + 4, mp4_magic, sizeof (mp4_magic)) &&
			memcmp(magic_buf + 4, mp4_magic_sidx, sizeof (mp4_magic_sidx)) &&
			memcmp(magic_buf + 4, mp4_magic_styp, sizeof (mp4_magic_styp)))
		return WTAP_OPEN_NOT_MINE;

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	wth->file_type_subtype = mp4_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_MP4;
	wth->file_tsprec = WTAP_TSPREC_SEC;
	wth->subtype_read = wtap_full_file_read;
	wth->subtype_seek_read = wtap_full_file_seek_read;
	wth->snapshot_length = 0;

	return WTAP_OPEN_MINE;
}

static const struct supported_block_type mp4_blocks_supported[] = {
	/*
	 * This is a file format that we dissect, so we provide
	 * only one "packet" with the file's contents, and don't
	 * support any options.
	 */
	{ WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info mp4_info = {
	"MP4 media", "mp4", "mp4", NULL,
	false, BLOCKS_SUPPORTED(mp4_blocks_supported),
	NULL, NULL, NULL
};

void register_mp4(void)
{
	mp4_file_type_subtype = wtap_register_file_type_subtype(&mp4_info);

	/*
	 * Register name for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("MP4",
	    mp4_file_type_subtype);
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
