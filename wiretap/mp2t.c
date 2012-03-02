/* mp2t.c
 *
 * ISO/IEC 13818-1 MPEG2-TS file format decoder for the Wiretap library.
 * Written by Weston Schmidt <weston_schmidt@alumni.purdue.edu>
 * Copyright 2012 Weston Schmidt
 *
 * $Id$
 *
 * Wiretap Library
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "mp2t.h"

#include "wtap-int.h"
#include "buffer.h"
#include "file_wrappers.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MP2T_SYNC_BYTE      0x47
#define MP2T_SIZE           188
#define MP2T_QAM256_BITRATE 38810700    /* bits per second */
#define MP2T_QAM64_BITRATE  26970350    /* bits per second */

typedef struct {
    guint32 offset;
    struct wtap_nstime now;
} mp2t_filetype_t;

static gboolean
mp2t_read_data(guint8 *dest, int length, int *err, gchar **err_info, FILE_T fh)
{
    int bytes_read;

    bytes_read = file_read(dest, length, fh);
    if (MP2T_SIZE != bytes_read) {
        *err = file_error(fh, err_info);
        if (*err == 0) {
            *err = WTAP_ERR_SHORT_READ;
        }
        return FALSE;
    }

    return TRUE;
}

static gboolean
mp2t_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    mp2t_filetype_t *mp2t;
    guint64 tmp;

    mp2t = (mp2t_filetype_t*) wth->priv;

    *data_offset = mp2t->offset;
    buffer_assure_space(wth->frame_buffer, MP2T_SIZE);
    if (FALSE == mp2t_read_data(buffer_start_ptr(wth->frame_buffer),
                                MP2T_SIZE, err, err_info, wth->fh))
    {
        return FALSE;
    }

    mp2t->offset += MP2T_SIZE;
    wth->phdr.presence_flags = WTAP_HAS_TS;

    /* It would be really cool to be able to configure the bitrate... */
    tmp = MP2T_SIZE * 8;
    tmp *= 1000000000;
    tmp /= MP2T_QAM256_BITRATE;

    wth->phdr.ts.secs = mp2t->now.secs;
    wth->phdr.ts.nsecs = mp2t->now.nsecs;
    mp2t->now.nsecs += (guint32)tmp;
    if (1000000000 <= mp2t->now.nsecs) {
        mp2t->now.nsecs -= 1000000000;
        mp2t->now.secs++;
    }
    wth->phdr.caplen = MP2T_SIZE;
    wth->phdr.len = MP2T_SIZE;

    return TRUE;
}

static gboolean
mp2t_seek_read(wtap *wth, gint64 seek_off,
        union wtap_pseudo_header *pseudo_header _U_, guint8 *pd, int length,
        int *err, gchar **err_info)
{
    if (-1 == file_seek(wth->random_fh, seek_off, SEEK_SET, err)) {
        return FALSE;
    }

    return mp2t_read_data(pd, length, err, err_info, wth->random_fh);
}

int
mp2t_open(wtap *wth, int *err, gchar **err_info)
{
    int bytes_read;
    guint8 buffer[MP2T_SIZE];
    int i;
    int first;
    mp2t_filetype_t *mp2t;

    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(buffer, sizeof(buffer), wth->fh);

    if (sizeof(buffer) != bytes_read) {
        *err = file_error(wth->fh, err_info);
        return (*err == 0) ? 0 : -1;
    }

    first = -1;
    for (i = 0; i < MP2T_SIZE; i++) {
        if (MP2T_SYNC_BYTE == buffer[i]) {
            first = i;
            break;
        }
    }

    if (-1 == first) {
        return 0;
    }

    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
        return -1;
    }

    wth->file_type = WTAP_FILE_MPEG_2_TS;
    wth->file_encap = WTAP_ENCAP_MPEG_2_TS;
    wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
    wth->subtype_read = mp2t_read;
    wth->subtype_seek_read = mp2t_seek_read;
    wth->snapshot_length = 0;

    mp2t = (mp2t_filetype_t*) g_malloc(sizeof(mp2t_filetype_t));
    if (NULL == mp2t) {
        return -1;
    }

    wth->priv = mp2t;
    mp2t->offset = (guint32) first;
    mp2t->now.secs = 0;
    mp2t->now.nsecs = 0;

    return 1;
}
