/* json.c
 *
 * Copyright 2015, Dario Lombardo <lomato@gmail.com>
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

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include "json.h"
#include <wsutil/jsmn.h>

static gboolean json_read_file(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
    gint64 file_size;
    int packet_size;

    if ((file_size = wtap_file_size(wth, err)) == -1)
        return FALSE;

    if (file_size > MAX_FILE_SIZE) {
        /*
         * Don't blow up trying to allocate space for an
         * immensely-large file.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("mime_file: File has %" G_GINT64_MODIFIER "d-byte packet, bigger than maximum of %u",
            file_size, MAX_FILE_SIZE);
        return FALSE;
    }
    packet_size = (int)file_size;

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */

    phdr->caplen = packet_size;
    phdr->len = packet_size;

    phdr->ts.secs = 0;
    phdr->ts.nsecs = 0;

    return wtap_read_packet_bytes(fh, buf, packet_size, err, err_info);
}

static gboolean json_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
    /* there is only one packet */
    if (seek_off > 0) {
        *err = 0;
        return FALSE;
    }

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    return json_read_file(wth, wth->random_fh, phdr, buf, err, err_info);
}

static gboolean json_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    gint64 offset;

    *err = 0;

    offset = file_tell(wth->fh);

    /* there is only ever one packet */
    if (offset != 0)
        return FALSE;

    *data_offset = offset;

    return json_read_file(wth, wth->fh, &wth->phdr, wth->frame_buffer, err, err_info);
}

wtap_open_return_val json_open(wtap *wth, int *err, gchar **err_info)
{
    guint8* filebuf;
    int bytes_read;

    filebuf = (guint8*)g_malloc0(MAX_FILE_SIZE);
    if (!filebuf)
        return WTAP_OPEN_ERROR;

    bytes_read = file_read(filebuf, MAX_FILE_SIZE, wth->fh);
    if (bytes_read < 0) {
        /* Read error. */
        *err = file_error(wth->fh, err_info);
        g_free(filebuf);
        return WTAP_OPEN_ERROR;
    }
    if (bytes_read == 0) {
        /* empty file, not *anybody's* */
        g_free(filebuf);
        return WTAP_OPEN_NOT_MINE;
    }

    if (jsmn_is_json(filebuf, bytes_read) == FALSE) {
        g_free(filebuf);
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        g_free(filebuf);
        return WTAP_OPEN_ERROR;
    }

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_JSON;
    wth->file_encap = WTAP_ENCAP_JSON;
    wth->file_tsprec = WTAP_TSPREC_SEC;
    wth->subtype_read = json_read;
    wth->subtype_seek_read = json_seek_read;
    wth->snapshot_length = 0;

    g_free(filebuf);
    return WTAP_OPEN_MINE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
