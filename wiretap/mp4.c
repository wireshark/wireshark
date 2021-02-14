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

static const guint8 mp4_magic[] = { 'f', 't', 'y', 'p' };

static int mp4_file_type_subtype = -1;

void register_mp4(void);

wtap_open_return_val
mp4_open(wtap *wth, int *err, gchar **err_info)
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
			memcmp(magic_buf + 4, mp4_magic, sizeof (mp4_magic)))
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

static const struct file_type_subtype_info mp4_info = {
	/* WTAP_FILE_TYPE_SUBTYPE_MP4 */
	"MP4 media", "mp4", "mp4", NULL,
	FALSE, FALSE, 0,
	NULL, NULL, NULL
};

void register_mp4(void)
{
	mp4_file_type_subtype =
	    wtap_register_file_type_subtypes(&mp4_info,
	        WTAP_FILE_TYPE_SUBTYPE_UNKNOWN);
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
