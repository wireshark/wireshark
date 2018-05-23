/* ruby_marshal.c
 *
 * Routines for reading a binary file containing a ruby marshal object
 *
 * Copyright 2018, Dario Lombardo <lomato@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include "ruby_marshal.h"

/*
 * Impose a not-too-large limit on the maximum file size, to avoid eating
 * up 99% of the (address space, swap partition, disk space for swap/page
 * files); if we were to return smaller chunks and let the dissector do
 * reassembly, it would *still* have to allocate a buffer the size of
 * the file, so it's not as if we'd neve try to allocate a buffer the
 * size of the file.
 *
 * For now, go for 50MB.
 */
#define MAX_FILE_SIZE (50*1024*1024)

static gboolean ruby_marshal_read_file(wtap *wth, FILE_T fh, wtap_rec *rec,
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
        *err_info = g_strdup_printf("ruby_marshal: File has %" G_GINT64_MODIFIER "d-byte packet, bigger than maximum of %u",
            file_size, MAX_FILE_SIZE);
        return FALSE;
    }
    packet_size = (int)file_size;

    rec->rec_type = REC_TYPE_PACKET;
    rec->presence_flags = 0;

    rec->rec_header.packet_header.caplen = packet_size;
    rec->rec_header.packet_header.len = packet_size;

    rec->ts.secs = 0;
    rec->ts.nsecs = 0;

    return wtap_read_packet_bytes(fh, buf, packet_size, err, err_info);
}

static gboolean ruby_marshal_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info)
{
    /* there is only one packet */
    if (seek_off > 0) {
        *err = 0;
        return FALSE;
    }

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    return ruby_marshal_read_file(wth, wth->random_fh, rec, buf, err, err_info);
}

static gboolean ruby_marshal_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    gint64 offset;

    *err = 0;

    offset = file_tell(wth->fh);

    /* there is only ever one packet */
    if (offset != 0)
        return FALSE;

    *data_offset = offset;

    return ruby_marshal_read_file(wth, wth->fh, &wth->rec, wth->rec_data, err, err_info);
}

static gboolean is_ruby_marshal(const guint8* filebuf)
{
    if (filebuf[0] != RUBY_MARSHAL_MAJOR)
        return FALSE;
    if (filebuf[1] != RUBY_MARSHAL_MINOR)
        return FALSE;
    switch (filebuf[2]) {
        case '0':
        case 'T':
        case 'F':
        case 'i':
        case ':':
        case '"':
        case 'I':
        case '[':
        case '{':
        case 'f':
        case 'c':
        case 'm':
        case 'S':
        case '/':
        case 'o':
        case 'C':
        case 'e':
        case ';':
        case '@':
            return TRUE;
            break;
        default:
            return FALSE;
    }
}

wtap_open_return_val ruby_marshal_open(wtap *wth, int *err, gchar **err_info)
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

    if (!is_ruby_marshal(filebuf)) {
        g_free(filebuf);
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        g_free(filebuf);
        return WTAP_OPEN_ERROR;
    }

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_RUBY_MARSHAL;
    wth->file_encap = WTAP_ENCAP_RUBY_MARSHAL;
    wth->file_tsprec = WTAP_TSPREC_SEC;
    wth->subtype_read = ruby_marshal_read;
    wth->subtype_seek_read = ruby_marshal_seek_read;
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
