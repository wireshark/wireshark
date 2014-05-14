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
#include <time.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/buffer.h>

#include "logcat.h"

/* Returns '?' for invalid priorities */
static gchar get_priority(const guint8 priority) {
    static gchar priorities[] = "??VDIWEFS";

    if (priority >= (guint8) sizeof(priorities))
        return '?';

    return priorities[priority];
}

static gint detect_version(wtap *wth, int *err, gchar **err_info)
{
    gint                     bytes_read;
    guint16                  payload_length;
    guint16                  hdr_size;
    guint16                  read_sofar;
    guint16                  entry_len;
    gint                     version;
    struct logger_entry     *log_entry;
    struct logger_entry_v2  *log_entry_v2;
    guint8                  *buffer;
    guint16                  tmp;
    guint8                  *msg_payload, *msg_part, *msg_end;
    guint16                  msg_len;

    /* 16-bit payload length */
    bytes_read = file_read(&tmp, 2, wth->fh);
    if (bytes_read != 2) {
        *err = file_error(wth->fh, err_info);
        if (*err == 0 && bytes_read != 0)
            *err = WTAP_ERR_SHORT_READ;
        return -1;
    }
    payload_length = pletoh16(&tmp);

    /* 16-bit header length (or padding, equal to 0x0000) */
    bytes_read = file_read(&tmp, 2, wth->fh);
    if (bytes_read != 2) {
        *err = file_error(wth->fh, err_info);
        if (*err == 0 && bytes_read != 0)
            *err = WTAP_ERR_SHORT_READ;
        return -1;
    }
    hdr_size = pletoh16(&tmp);
    read_sofar = 4;

    /* must contain at least priority and two nulls as separator */
    if (payload_length < 3)
        return -1;
    /* payload length may not exceed the maximum payload size */
    if (payload_length > LOGGER_ENTRY_MAX_PAYLOAD)
        return -1;

    /* ensure buffer is large enough for all versions */
    buffer = (guint8 *) g_malloc(sizeof(*log_entry_v2) + payload_length);
    log_entry_v2 = (struct logger_entry_v2 *) buffer;
    log_entry = (struct logger_entry *) buffer;

    /* cannot rely on __pad being 0 for v1, use heuristics to find out what
     * version is in use. First assume the smallest msg. */
    for (version = 1; version <= 2; ++version) {
        if (version == 1) {
            msg_payload = log_entry->msg;
            entry_len = sizeof(*log_entry) + payload_length;
        } else if (version == 2) {
            /* v2 is 4 bytes longer */
            msg_payload = log_entry_v2->msg;
            entry_len = sizeof(*log_entry_v2) + payload_length;
            if (hdr_size != sizeof(*log_entry_v2))
                continue;
        }

        bytes_read = file_read(buffer + read_sofar, entry_len - read_sofar,
                wth->fh);
        if (bytes_read != entry_len - read_sofar) {
            *err = file_error(wth->fh, err_info);
            if (*err == 0 && bytes_read != 0)
                *err = WTAP_ERR_SHORT_READ;
            /* short read, end of file? Whatever, this cannot be valid. */
            break;
        }
        read_sofar += bytes_read;

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

    g_free(buffer);
    return -1;
}

gint logcat_exported_pdu_length(const guint8 *pd) {
    guint16 *tag;
    guint16 *tag_length;
    gint     length = 0;

    tag = (guint16 *) pd;

    while(GINT16_FROM_BE(*tag)) {
        tag_length = (guint16 *) (pd + 2);
        length += 2 + 2 + GINT16_FROM_BE(*tag_length);

        pd += 2 + 2 + GINT16_FROM_BE(*tag_length);
        tag = (guint16 *) pd;
    }

    length += 2 + 2;

    return length;
}

static gboolean logcat_read_packet(struct logcat_phdr *logcat, FILE_T fh,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
    gint                 bytes_read;
    gint                 packet_size;
    guint16              payload_length;
    guint                tmp[2];
    guint8              *pd;
    struct logger_entry *log_entry;

    bytes_read = file_read(&tmp, 2, fh);
    if (bytes_read != 2) {
        *err = file_error(fh, err_info);
        if (*err == 0 && bytes_read != 0)
            *err = WTAP_ERR_SHORT_READ;
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

    ws_buffer_assure_space(buf, packet_size);
    pd = ws_buffer_start_ptr(buf);
    log_entry = (struct logger_entry *) pd;

    /* Copy the first two bytes of the packet. */
    memcpy(pd, tmp, 2);

    /* Read the rest of the packet. */
    bytes_read = file_read(pd + 2, packet_size - 2, fh);
    if (bytes_read != packet_size - 2) {
        *err = file_error(fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
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

int logcat_open(wtap *wth, int *err, gchar **err_info _U_)
{
    int                 local_err;
    gchar              *local_err_info;
    gint                version;
    gint                tmp_version;
    struct logcat_phdr *logcat;

    /* check first 3 packets (or 2 or 1 if EOF) versions to check file format is correct */
    version = detect_version(wth, &local_err, &local_err_info);
    if (version <= 0)
        return 0;

    tmp_version = detect_version(wth, &local_err, &local_err_info);
    if (tmp_version < 0 && !file_eof(wth->fh)) {
        return 0;
    } else if (tmp_version > 0) {
        if (tmp_version != version)
            return 0;

        tmp_version = detect_version(wth, &local_err, &local_err_info);
        if (tmp_version != version && !file_eof(wth->fh))
            return 0;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return -1;

    logcat = (struct logcat_phdr *) g_malloc(sizeof(struct logcat_phdr));
    logcat->version = version;

    wth->priv = logcat;

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT;
    wth->file_encap = WTAP_ENCAP_LOGCAT;
    wth->snapshot_length = 0;

    wth->subtype_read = logcat_read;
    wth->subtype_seek_read = logcat_seek_read;
    wth->tsprecision = WTAP_FILE_TSPREC_USEC;

    return 1;
}

int logcat_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap != WTAP_ENCAP_LOGCAT && encap != WTAP_ENCAP_WIRESHARK_UPPER_PDU)
        return WTAP_ERR_UNSUPPORTED_ENCAP;

    return 0;
}

static gboolean logcat_binary_dump(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err)
{
    int caplen;

    /* We can only write packet records. */
    if (phdr->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
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
    wdh->subtype_close = NULL;

    switch (wdh->encap) {
        case WTAP_ENCAP_LOGCAT:
        case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
            wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
            break;

        default:
            *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
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
