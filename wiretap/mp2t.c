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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

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

/* we try to detect trailing data up to 40 bytes after each packet */
#define TRAILER_LEN_MAX 40

/* number of consecutive packets we must read to decide that a file
   is actually an mpeg2 ts */
#define SYNC_STEPS   10


typedef struct {
    int start_offset;
    /* length of trailing data (e.g. FEC) that's appended after each packet */
    guint8  trailer_len;
} mp2t_filetype_t;

static gboolean
mp2t_read_data(guint8 *dest, int length, int *err, gchar **err_info, FILE_T fh)
{
    int bytes_read;

    bytes_read = file_read(dest, length, fh);
    if (length != bytes_read) {
        *err = file_error(fh, err_info);
        /* bytes_read==0 is end of file, not a short read */
        if (bytes_read>0 && *err == 0) {
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

    *data_offset = file_tell(wth->fh);

    /* read only the actual mpeg2 ts packet, not including a trailer */
    buffer_assure_space(wth->frame_buffer, MP2T_SIZE);
    if (FALSE == mp2t_read_data(buffer_start_ptr(wth->frame_buffer),
                                MP2T_SIZE, err, err_info, wth->fh))
    {
        return FALSE;
    }

    /* if there's a trailer, skip it and go to the start of the next packet */
    if (mp2t->trailer_len!=0 &&
        (-1 == file_seek(wth->fh, mp2t->trailer_len, SEEK_CUR, err))) {
        return FALSE;
    }

    /* XXX - relative, not absolute, time stamps */
    wth->phdr.presence_flags = WTAP_HAS_TS;

    /*
     * Every packet in an MPEG2-TS stream is has a fixed size of
     * MP2T_SIZE plus the number of trailer bytes.
     *
     * The bitrate is constant, so the time offset, from the beginning
     * of the stream, of a given packet is the packet offset, in bits,
     * divided by the bitrate.
     *
     * It would be really cool to be able to configure the bitrate...
     */
    tmp = ((guint64)(*data_offset - mp2t->start_offset) * 8);	/* offset, in bits */
    wth->phdr.ts.secs = tmp / MP2T_QAM256_BITRATE;
    wth->phdr.ts.nsecs = (tmp % MP2T_QAM256_BITRATE) * 1000000000 / MP2T_QAM256_BITRATE;

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
    guint8 buffer[MP2T_SIZE+TRAILER_LEN_MAX];
    guint8 trailer_len = 0;
    guint sync_steps = 0;
    int i;
    int first;
    mp2t_filetype_t *mp2t;


    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(buffer, MP2T_SIZE, wth->fh);

    if (MP2T_SIZE != bytes_read) {
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
        return 0; /* wrong file type - not an mpeg2 ts file */
    }

    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
        return -1;
    }
    /* read some packets and make sure they all start with a sync byte */
    do {
       bytes_read = file_read(buffer, MP2T_SIZE+trailer_len, wth->fh);
       if (bytes_read < 0)
          return -1;  /* read error */
       if (bytes_read < MP2T_SIZE+trailer_len) {
	  if(sync_steps<2) return 0; /* wrong file type - not an mpeg2 ts file */
          break;  /* end of file, that's ok if we're still in sync */
       }
       if (buffer[0] == MP2T_SYNC_BYTE) {
               sync_steps++;
       }
       else {
           /* no sync byte found, check if trailing data is appended
              and we have to increase the packet size */

           /* if we've already detected a trailer field, we must remain in sync
              another mismatch means we have no mpeg2 ts file */
           if (trailer_len>0)
               return 0;

           /* check if a trailer is appended to the packet */
           for (i=0; i<TRAILER_LEN_MAX; i++) {
               if (buffer[i] == MP2T_SYNC_BYTE) {
                   trailer_len = i;
                   if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
                       return -1;
                   }
                   sync_steps = 0;
                   break;
               }
           }
           /* no sync byte found in the vicinity, this is no mpeg2 ts file */
           if (i==TRAILER_LEN_MAX)
               return 0;
       }
    } while (sync_steps < SYNC_STEPS);

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
    mp2t->start_offset = first;
    mp2t->trailer_len = trailer_len;

    return 1;
}
