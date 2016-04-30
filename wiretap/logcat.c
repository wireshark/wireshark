/* logcat.c
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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

#include "logcat.h"

/* Returns '?' for invalid priorities */
static gchar get_priority(const guint8 priority) {
    static gchar priorities[] = "??VDIWEFS";

    if (priority >= (guint8) sizeof(priorities))
        return '?';

    return priorities[priority];
}

/*
 * Returns:
 *
 *  -2 if we get an EOF at the beginning;
 *  -1 on an I/O error;
 *  0 if the record doesn't appear to be valid;
 *  1-{max gint} as a version number if we got a valid record.
 */
static gint detect_version(FILE_T fh, int *err, gchar **err_info)
{
    guint16                  payload_length;
    guint16                  hdr_size;
    guint16                  read_sofar;
    guint16                  entry_len;
    gint                     version;
    struct logger_entry     *log_entry;
    struct logger_entry_v2  *log_entry_v2;
    guint8                  *buffer;
    guint16                  tmp;
    guint8                  *msg_payload;
    guint8                  *msg_part;
    guint8                  *msg_end;
    guint16                  msg_len;

    /* 16-bit payload length */
    if (!wtap_read_bytes_or_eof(fh, &tmp, 2, err, err_info)) {
        if (*err == 0) {
            /*
             * Got an EOF at the beginning.
             */
            return -2;
        }
        if (*err != WTAP_ERR_SHORT_READ)
            return -1;
        return 0;
    }
    payload_length = pletoh16(&tmp);

    /* must contain at least priority and two nulls as separator */
    if (payload_length < 3)
        return 0;
    /* payload length may not exceed the maximum payload size */
    if (payload_length > LOGGER_ENTRY_MAX_PAYLOAD)
        return 0;

    /* 16-bit header length (or padding, equal to 0x0000) */
    if (!wtap_read_bytes(fh, &tmp, 2, err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ)
            return -1;
        return 0;
    }
    hdr_size = pletoh16(&tmp);
    read_sofar = 4;

    /* ensure buffer is large enough for all versions */
    buffer = (guint8 *) g_malloc(sizeof(*log_entry_v2) + payload_length);
    log_entry_v2 = (struct logger_entry_v2 *)(void *) buffer;
    log_entry = (struct logger_entry *)(void *) buffer;

    /* cannot rely on __pad being 0 for v1, use heuristics to find out what
     * version is in use. First assume the smallest msg. */
    for (version = 1; version <= 2; ++version) {
        if (version == 1) {
            msg_payload = (guint8 *) (log_entry + 1);
            entry_len = sizeof(*log_entry) + payload_length;
        } else if (version == 2) {
            /* v2 is 4 bytes longer */
            msg_payload = (guint8 *) (log_entry_v2 + 1);
            entry_len = sizeof(*log_entry_v2) + payload_length;
            if (hdr_size != sizeof(*log_entry_v2))
                continue;
        } else {
            continue;
        }

        if (!wtap_read_bytes(fh, buffer + read_sofar, entry_len - read_sofar, err, err_info)) {
            g_free(buffer);
            if (*err != WTAP_ERR_SHORT_READ)
                return -1;
            return 0;
        }
        read_sofar += entry_len - read_sofar;

        /* A v2 msg has a 32-bit userid instead of v1 priority */
        if (get_priority(msg_payload[0]) == '?')
            continue;

        /* Is there a terminating '\0' for the tag? */
        msg_part = (guint8 *) memchr(msg_payload, '\0', payload_length - 1);
        if (msg_part == NULL)
            continue;

        /* if msg is '\0'-terminated, is it equal to the payload len? */
        ++msg_part;
        msg_len = (guint16)(payload_length - (msg_part - msg_payload));
        msg_end = (guint8 *) memchr(msg_part, '\0', msg_len);
        /* is the end of the buffer (-1) equal to the end of msg? */
        if (msg_end && (msg_payload + payload_length - 1 != msg_end))
            continue;

        g_free(buffer);
        return version;
    }

    /* No version number is valid */
    g_free(buffer);
    return 0;
}

gint logcat_exported_pdu_length(const guint8 *pd) {
    const guint16  *tag;
    const guint16  *tag_length;
    gint            length = 0;

    tag = (const guint16 *)(const void *) pd;

    while(GINT16_FROM_BE(*tag)) {
        tag_length = (const guint16 *)(const void *) (pd + 2);
        length += 2 + 2 + GINT16_FROM_BE(*tag_length);

        pd += 2 + 2 + GINT16_FROM_BE(*tag_length);
        tag = (const guint16 *)(const void *) pd;
    }

    length += 2 + 2;

    return length;
}

static gboolean logcat_read_packet(struct logcat_phdr *logcat, FILE_T fh,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
    gint                 packet_size;
    guint16              payload_length;
    guint                tmp[2];
    guint8              *pd;
    struct logger_entry *log_entry;

    if (!wtap_read_bytes_or_eof(fh, &tmp, 2, err, err_info)) {
        return FALSE;
    }
    payload_length = pletoh16(tmp);

    if (logcat->version == 1) {
        packet_size = (gint)sizeof(struct logger_entry) + payload_length;
    } else if (logcat->version == 2) {
        packet_size = (gint)sizeof(struct logger_entry_v2) + payload_length;
    } else {
        return FALSE;
    }
    /*
     * The maximum value of payload_length is 65535, which, even after
     * the size of the logger entry structure is added to it, is less
     * than WTAP_MAX_PACKET_SIZE will ever be, so we don't need to check
     * it.
     */

    ws_buffer_assure_space(buf, packet_size);
    pd = ws_buffer_start_ptr(buf);
    log_entry = (struct logger_entry *)(void *) pd;

    /* Copy the first two bytes of the packet. */
    memcpy(pd, tmp, 2);

    /* Read the rest of the packet. */
    if (!wtap_read_bytes(fh, pd + 2, packet_size - 2, err, err_info)) {
        return FALSE;
    }

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = WTAP_HAS_TS;
    phdr->ts.secs = (time_t) GINT32_FROM_LE(log_entry->sec);
    phdr->ts.nsecs = GINT32_FROM_LE(log_entry->nsec);
    phdr->caplen = packet_size;
    phdr->len = packet_size;

    phdr->pseudo_header.logcat.version = logcat->version;

    return TRUE;
}

static gboolean logcat_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return logcat_read_packet((struct logcat_phdr *) wth->priv, wth->fh,
        &wth->phdr, wth->frame_buffer, err, err_info);
}

static gboolean logcat_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    if (!logcat_read_packet((struct logcat_phdr *) wth->priv, wth->random_fh,
         phdr, buf, err, err_info)) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    return TRUE;
}

wtap_open_return_val logcat_open(wtap *wth, int *err, gchar **err_info)
{
    gint                version;
    gint                tmp_version;
    struct logcat_phdr *logcat;

    /* check first 3 packets (or 2 or 1 if EOF) versions to check file format is correct */
    version = detect_version(wth->fh, err, err_info); /* first packet */
    if (version == -1)
        return WTAP_OPEN_ERROR; /* I/O error */
    if (version == 0)
        return WTAP_OPEN_NOT_MINE;  /* not a logcat file */
    if (version == -2)
        return WTAP_OPEN_NOT_MINE;  /* empty file, so not any type of file */

    tmp_version = detect_version(wth->fh, err, err_info); /* second packet */
    if (tmp_version == -1)
        return WTAP_OPEN_ERROR; /* I/O error */
    if (tmp_version == 0)
        return WTAP_OPEN_NOT_MINE;  /* not a logcat file */
    if (tmp_version != -2) {
        /* we've read two packets; do they have the same version? */
        if (tmp_version != version) {
            /* no, so this is presumably not a logcat file */
            return WTAP_OPEN_NOT_MINE;
        }

        tmp_version = detect_version(wth->fh, err, err_info); /* third packet */
        if (tmp_version < 0)
            return WTAP_OPEN_ERROR; /* I/O error */
        if (tmp_version == 0)
            return WTAP_OPEN_NOT_MINE;  /* not a logcat file */
        if (tmp_version != -2) {
            /*
             * we've read three packets and the first two have the same
             * version; does the third have the same version?
             */
            if (tmp_version != version) {
                /* no, so this is presumably not a logcat file */
                return WTAP_OPEN_NOT_MINE;
            }
        }
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    logcat = (struct logcat_phdr *) g_malloc(sizeof(struct logcat_phdr));
    logcat->version = version;

    wth->priv = logcat;

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT;
    wth->file_encap = WTAP_ENCAP_LOGCAT;
    wth->snapshot_length = 0;

    wth->subtype_read = logcat_read;
    wth->subtype_seek_read = logcat_seek_read;
    wth->file_tsprec = WTAP_TSPREC_USEC;

    return WTAP_OPEN_MINE;
}

int logcat_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap != WTAP_ENCAP_LOGCAT && encap != WTAP_ENCAP_WIRESHARK_UPPER_PDU)
        return WTAP_ERR_UNWRITABLE_ENCAP;

    return 0;
}

static gboolean logcat_binary_dump(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err, gchar **err_info _U_)
{
    int caplen;

    /* We can only write packet records. */
    if (phdr->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return FALSE;
    }

    caplen = phdr->caplen;

    /* Skip EXPORTED_PDU*/
    if (wdh->encap == WTAP_ENCAP_WIRESHARK_UPPER_PDU) {
        gint skipped_length;

        skipped_length = logcat_exported_pdu_length(pd);
        pd += skipped_length;
        caplen -= skipped_length;
    }

    if (!wtap_dump_file_write(wdh, pd, caplen, err))
        return FALSE;

    wdh->bytes_dumped += caplen;

    return TRUE;
}

gboolean logcat_binary_dump_open(wtap_dumper *wdh, int *err)
{
    wdh->subtype_write = logcat_binary_dump;

    switch (wdh->encap) {
        case WTAP_ENCAP_LOGCAT:
        case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
            wdh->tsprecision = WTAP_TSPREC_USEC;
            break;

        default:
            *err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
            return FALSE;
    }

    return TRUE;
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
