/* mp2t.c
 *
 * ISO/IEC 13818-1 MPEG2-TS file format decoder for the Wiretap library.
 * Written by Weston Schmidt <weston_schmidt@alumni.purdue.edu>
 * Copyright 2012 Weston Schmidt
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
#include <wsutil/buffer.h>
#include "file_wrappers.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MP2T_SYNC_BYTE      0x47
#define MP2T_SIZE           188
#define MP2T_QAM64_BITRATE  26970350    /* bits per second */
#define MP2T_PCR_CLOCK      27000000    /* cycles per second - 27MHz */

/* we try to detect trailing data up to 40 bytes after each packet */
#define TRAILER_LEN_MAX 40

/* number of consecutive packets we must read to decide that a file
   is actually an mpeg2 ts */
#define SYNC_STEPS   10


typedef struct {
    guint32 start_offset;
    guint64 bitrate;
    /* length of trailing data (e.g. FEC) that's appended after each packet */
    guint8  trailer_len;
} mp2t_filetype_t;

static gboolean
mp2t_read_packet(mp2t_filetype_t *mp2t, FILE_T fh, gint64 offset,
                 struct wtap_pkthdr *phdr, Buffer *buf, int *err,
                 gchar **err_info)
{
    guint64 tmp;

    /*
     * MP2T_SIZE will always be less than WTAP_MAX_PACKET_SIZE, so
     * we don't have to worry about the packet being too big.
     */
    ws_buffer_assure_space(buf, MP2T_SIZE);
    if (!wtap_read_bytes_or_eof(fh, ws_buffer_start_ptr(buf), MP2T_SIZE, err, err_info))
        return FALSE;

    phdr->rec_type = REC_TYPE_PACKET;

    /* XXX - relative, not absolute, time stamps */
    phdr->presence_flags = WTAP_HAS_TS;

    /*
     * Every packet in an MPEG2-TS stream is has a fixed size of
     * MP2T_SIZE plus the number of trailer bytes.
     *
     * We assume that the bits in the transport stream are supplied at
     * a constant rate; is that guaranteed by all media that use
     * MPEG2-TS?  If so, the time offset, from the beginning of the
     * stream, of a given packet is the packet offset, in bits, divided
     * by the bitrate.
     *
     * It would be really cool to be able to configure the bitrate, in
     * case our attempt to guess it from the PCRs of one of the programs
     * doesn't get the right answer.
     */
    tmp = ((guint64)(offset - mp2t->start_offset) * 8); /* offset, in bits */
    phdr->ts.secs = (time_t)(tmp / mp2t->bitrate);
    phdr->ts.nsecs = (int)((tmp % mp2t->bitrate) * 1000000000 / mp2t->bitrate);

    phdr->caplen = MP2T_SIZE;
    phdr->len = MP2T_SIZE;

    return TRUE;
}

static gboolean
mp2t_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    mp2t_filetype_t *mp2t;

    mp2t = (mp2t_filetype_t*) wth->priv;

    *data_offset = file_tell(wth->fh);

    if (!mp2t_read_packet(mp2t, wth->fh, *data_offset, &wth->phdr,
                          wth->frame_buffer, err, err_info)) {
        return FALSE;
    }

    /* if there's a trailer, skip it and go to the start of the next packet */
    if (mp2t->trailer_len!=0) {
        if (-1 == file_seek(wth->fh, mp2t->trailer_len, SEEK_CUR, err)) {
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
mp2t_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
        Buffer *buf, int *err, gchar **err_info)
{
    mp2t_filetype_t *mp2t;

    if (-1 == file_seek(wth->random_fh, seek_off, SEEK_SET, err)) {
        return FALSE;
    }

    mp2t = (mp2t_filetype_t*) wth->priv;

    if (!mp2t_read_packet(mp2t, wth->random_fh, seek_off, phdr, buf,
                          err, err_info)) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    return TRUE;
}

static guint64
mp2t_read_pcr(guint8 *buffer)
{
    guint64 base;
    guint64 ext;

    base = pntoh40(buffer);
    base >>= 7;

    ext = pntoh16(&buffer[4]);
    ext &= 0x01ff;

    return (base * 300 + ext);
}

static gboolean
mp2t_find_next_pcr(wtap *wth, guint8 trailer_len,
        int *err, gchar **err_info, guint32 *idx, guint64 *pcr, guint16 *pid)
{
    guint8 buffer[MP2T_SIZE+TRAILER_LEN_MAX];
    gboolean found;
    guint8 afc;
    guint timeout = 0;

    found = FALSE;
    while (FALSE == found && timeout++ < SYNC_STEPS * SYNC_STEPS) {
        (*idx)++;
        if (!wtap_read_bytes_or_eof(
                    wth->fh, buffer, MP2T_SIZE+trailer_len, err, err_info)) {
            /* Read error, short read, or EOF */
            return FALSE;
        }

        if (MP2T_SYNC_BYTE != buffer[0]) {
            continue;
        }

        /* Read out the AFC value. */
        afc = 3 & (buffer[3] >> 4);
        if (afc < 2) {
            continue;
        }

        /* Check the length. */
        if (buffer[4] < 7) {
            continue;
        }

        /* Check that there is the PCR flag. */
        if (0x10 != (0x10 & buffer[5])) {
            continue;
        }

        /* We have a PCR value! */
        *pcr = mp2t_read_pcr(&buffer[6]);
        *pid = 0x01ff & pntoh16(&buffer[1]);
        found = TRUE;
    }

    return found;
}

static wtap_open_return_val
mp2t_bits_per_second(wtap *wth, guint32 first, guint8 trailer_len,
        guint64 *bitrate, int *err, gchar **err_info)
{
    guint32 pn1, pn2;
    guint64 pcr1, pcr2;
    guint16 pid1, pid2;
    guint32 idx;
    guint64 pcr_delta, bits_passed;

    /* Find the first PCR + PID.
     * Then find another PCR in that PID.
     * Take the difference and that's our bitrate.
     * All the different PCRs in different PIDs 'should' be the same.
     *
     * XXX - is this assuming that the time stamps in the PCRs correspond
     * to the time scale of the underlying transport stream?
     */
    idx = first;

    if (!mp2t_find_next_pcr(wth, trailer_len, err, err_info, &idx, &pcr1, &pid1)) {
        /* Read error, short read, or EOF */
        if (*err == WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_NOT_MINE;    /* not a full frame */
        if (*err != 0)
            return WTAP_OPEN_ERROR;

        /* We don't have any PCRs, so we can't guess the bit rate.
         * Default to something reasonable.
         */
        *bitrate = MP2T_QAM64_BITRATE;
        return WTAP_OPEN_MINE;
    }

    pn1 = idx;
    pn2 = pn1;

    while (pn1 == pn2) {
        if (!mp2t_find_next_pcr(wth, trailer_len, err, err_info, &idx, &pcr2, &pid2)) {
            /* Read error, short read, or EOF */
            if (*err == WTAP_ERR_SHORT_READ)
                return WTAP_OPEN_NOT_MINE;    /* not a full frame */
            if (*err != 0)
                return WTAP_OPEN_ERROR;

            /* We don't have two PCRs for the same PID, so we can't guess
             * the bit rate.
             * Default to something reasonable.
             */
            *bitrate = MP2T_QAM64_BITRATE;
            return WTAP_OPEN_MINE;
        }

        if (pid1 == pid2) {
            pn2 = idx;
        }
    }

    if (pcr2 <= pcr1) {
        /* The PCRs for that PID didn't go forward; treat that as an
         * indication that this isn't an MPEG-2 TS.
         */
        return WTAP_OPEN_NOT_MINE;
    }
    pcr_delta = pcr2 - pcr1;
    /* cast one of the factors to guint64
       otherwise, the multiplication would use guint32 and could
       overflow before the result is assigned to the guint64 bits_passed */
    bits_passed = (guint64)MP2T_SIZE * (pn2 - pn1) * 8;

    *bitrate = ((MP2T_PCR_CLOCK * bits_passed) / pcr_delta);
    if (*bitrate == 0) {
        /* pcr_delta < MP2T_PCR_CLOCK * bits_passed (pn2 != pn1,
         * as that's the test for the loop above, so bits_passed
         * is non-zero).
         *
         * That will produce a fractional bitrate, which turns
         * into zero, causing a zero divide later.
         *
         * XXX - should we report this as "not ours"?  A bitrate
         * of less than 1 bit per second is not very useful for any
         * form of audio/video, so presumably that's unlikely to
         * be an MP2T file.
         */
        return WTAP_OPEN_ERROR;
    }
    return WTAP_OPEN_MINE;
}

wtap_open_return_val
mp2t_open(wtap *wth, int *err, gchar **err_info)
{
    guint8 buffer[MP2T_SIZE+TRAILER_LEN_MAX];
    guint8 trailer_len = 0;
    guint sync_steps = 0;
    guint i;
    guint32 first = 0;
    mp2t_filetype_t *mp2t;
    wtap_open_return_val status;
    guint64 bitrate;


    if (!wtap_read_bytes(wth->fh, buffer, MP2T_SIZE, err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }

    for (i = 0; i < MP2T_SIZE; i++) {
        if (MP2T_SYNC_BYTE == buffer[i]) {
            first = i;
            goto found;
        }
    }
    /*
     * No sync bytes found, so not an MPEG-2 Transport Stream file.
     */
    return WTAP_OPEN_NOT_MINE; /* wrong file type - not an mpeg2 ts file */

found:
    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
        return WTAP_OPEN_ERROR;
    }

    /* read some packets and make sure they all start with a sync byte */
    do {
       if (!wtap_read_bytes(wth->fh, buffer, MP2T_SIZE+trailer_len, err, err_info)) {
          if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;  /* read error */
          if(sync_steps<2) return WTAP_OPEN_NOT_MINE; /* wrong file type - not an mpeg2 ts file */
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
               return WTAP_OPEN_NOT_MINE;

           /* check if a trailer is appended to the packet */
           for (i=0; i<TRAILER_LEN_MAX; i++) {
               if (buffer[i] == MP2T_SYNC_BYTE) {
                   trailer_len = i;
                   if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
                       return WTAP_OPEN_ERROR;
                   }
                   sync_steps = 0;
                   break;
               }
           }
           /* no sync byte found in the vicinity, this is no mpeg2 ts file */
           if (i==TRAILER_LEN_MAX)
               return WTAP_OPEN_NOT_MINE;
       }
    } while (sync_steps < SYNC_STEPS);

    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
        return WTAP_OPEN_ERROR;
    }

    /* Ensure there is a valid bitrate */
    status = mp2t_bits_per_second(wth, first, trailer_len,
            &bitrate, err, err_info);
    if (status != WTAP_OPEN_MINE) {
        return status;
    }

    if (-1 == file_seek(wth->fh, first, SEEK_SET, err)) {
        return WTAP_OPEN_ERROR;
    }

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_MPEG_2_TS;
    wth->file_encap = WTAP_ENCAP_MPEG_2_TS;
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->subtype_read = mp2t_read;
    wth->subtype_seek_read = mp2t_seek_read;
    wth->snapshot_length = 0;

    mp2t = (mp2t_filetype_t*) g_malloc(sizeof(mp2t_filetype_t));

    wth->priv = mp2t;
    mp2t->start_offset = first;
    mp2t->trailer_len = trailer_len;
    mp2t->bitrate = bitrate;

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
