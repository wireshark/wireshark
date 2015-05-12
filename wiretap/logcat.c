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

enum dump_type_t {
    DUMP_BINARY,
    DUMP_BRIEF,
    DUMP_PROCESS,
    DUMP_TAG,
    DUMP_TIME,
    DUMP_THREAD,
    DUMP_THREADTIME,
    DUMP_LONG
};

struct dumper_t {
    enum dump_type_t type;
};

/* The log format can be found on:
 * https://android.googlesource.com/platform/system/core/+/master/include/log/logger.h
 * Log format is assumed to be little-endian (Android platform).
 */
/* maximum size of a message payload in a log entry */
#define LOGGER_ENTRY_MAX_PAYLOAD 4076

struct logger_entry {
    guint16 len;    /* length of the payload */
    guint16 __pad;  /* no matter what, we get 2 bytes of padding */
    gint32  pid;    /* generating process's pid */
    gint32  tid;    /* generating process's tid */
    gint32  sec;    /* seconds since Epoch */
    gint32  nsec;   /* nanoseconds */
/*    char    msg[0]; *//* the entry's payload */
};

struct logger_entry_v2 {
    guint16 len;    /* length of the payload */
    guint16 hdr_size; /* sizeof(struct logger_entry_v2) */
    gint32  pid;    /* generating process's pid */
    gint32  tid;    /* generating process's tid */
    gint32  sec;    /* seconds since Epoch */
    gint32  nsec;   /* nanoseconds */
    union {
                        /* v1: not present */
        guint32 euid;   /* v2: effective UID of logger */
        guint32 lid;    /* v3: log id of the payload */
    } id;
/*    char    msg[0]; *//* the entry's payload */
};

/* Returns '?' for invalid priorities */
static gchar get_priority(const guint8 priority) {
    static gchar priorities[] = "??VDIWEFS";

    if (priority >= (guint8) sizeof(priorities))
        return '?';

    return priorities[priority];
}

static gchar *logcat_log(const struct dumper_t *dumper, guint32 seconds,
        gint milliseconds, gint pid, gint tid, gchar priority, const gchar *tag,
        const gchar *log)
{
    gchar  time_buffer[15];
    time_t datetime;

    datetime = (time_t) seconds;

    switch (dumper->type) {
        case DUMP_BRIEF:
            return g_strdup_printf("%c/%-8s(%5i): %s\n",
                    priority, tag, pid, log);
        case DUMP_PROCESS:
            /* NOTE: Last parameter should be "process name", not tag;
                     Unfortunately, we do not have process name */
            return g_strdup_printf("%c(%5i) %s  (%s)\n",
                    priority, pid, log, "");
        case DUMP_TAG:
            return g_strdup_printf("%c/%-8s: %s\n",
                   priority, tag, log);
        case DUMP_THREAD:
            return g_strdup_printf("%c(%5i:0x%02x) %s\n",
                    priority, pid, tid, log);
        case DUMP_TIME:
            strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                    gmtime(&datetime));
            return g_strdup_printf("%s.%03i %c/%-8s(%5i): %s\n",
                    time_buffer, milliseconds, priority, tag, pid, log);
        case DUMP_THREADTIME:
            strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                    gmtime(&datetime));
            return g_strdup_printf("%s.%03i %5i %5i %c %-8s: %s\n",
                    time_buffer, milliseconds, pid, tid, priority, tag, log);
        case DUMP_LONG:
            strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                    gmtime(&datetime));
            return g_strdup_printf("[ %s.%03i %5i:0x%02x %c/%s ]\n%s\n\n",
                    time_buffer, milliseconds, pid, tid, priority, tag, log);
        default:
            return NULL;
    }

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
    guint8                  *msg_payload;
    guint8                  *msg_part;
    guint8                  *msg_end;
    guint16                  msg_len;

    /* 16-bit payload length */
    bytes_read = file_read(&tmp, 2, fh);
    if (bytes_read != 2) {
        *err = file_error(fh, err_info);
        if (*err == 0) {
            if (bytes_read == 0) {
                /*
                 * Got an EOF at the beginning.
                 */
                return -2;
            }
            *err = WTAP_ERR_SHORT_READ;
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
    bytes_read = file_read(&tmp, 2, fh);
    if (bytes_read != 2) {
        *err = file_error(fh, err_info);
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
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
        }

        bytes_read = file_read(buffer + read_sofar, entry_len - read_sofar,
                fh);
        if (bytes_read != entry_len - read_sofar) {
            *err = file_error(fh, err_info);
            g_free(buffer);
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
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

    buffer_assure_space(buf, packet_size);
    pd = buffer_start_ptr(buf);
    log_entry = (struct logger_entry *)(void *) pd;

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
    gint                version;
    gint                tmp_version;
    struct logcat_phdr *logcat;

    /* check first 3 packets (or 2 or 1 if EOF) versions to check file format is correct */
    version = detect_version(wth->fh, err, err_info); /* first packet */
    if (version == -1)
        return -1; /* I/O error */
    if (version == 0)
        return 0;  /* not a logcat file */
    if (version == -2)
        return 0;  /* empty file, so not any type of file */

    tmp_version = detect_version(wth->fh, err, err_info); /* second packet */
    if (tmp_version == -1)
        return -1; /* I/O error */
    if (tmp_version == 0)
        return 0;  /* not a logcat file */
    if (tmp_version != -2) {
        /* we've read two packets; do they have the same version? */
        if (tmp_version != version) {
            /* no, so this is presumably not a logcat file */
            return 0;
        }

        tmp_version = detect_version(wth->fh, err, err_info); /* third packet */
        if (tmp_version < 0)
            return -1; /* I/O error */
        if (tmp_version == 0)
            return 0;  /* not a logcat file */
        if (tmp_version != -2) {
            /*
             * we've read three packets and the first two have the same
             * version; does the third have the same version?
             */
            if (tmp_version != version) {
                /* no, so this is presumably not a logcat file */
                return 0;
            }
        }
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

    if (encap != WTAP_ENCAP_LOGCAT)
        return WTAP_ERR_UNSUPPORTED_ENCAP;

    return 0;
}

static gboolean logcat_binary_dump(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err)
{
    /* We can only write packet records. */
    if (phdr->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
        return FALSE;
    }

    if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
        return FALSE;

    wdh->bytes_dumped += phdr->caplen;

    return TRUE;
}

gboolean logcat_binary_dump_open(wtap_dumper *wdh, int *err)
{
    wdh->subtype_write = logcat_binary_dump;
    wdh->subtype_close = NULL;

    switch (wdh->file_type_subtype) {
        case WTAP_FILE_TYPE_SUBTYPE_LOGCAT:
            wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
            break;

        default:
            *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
            return FALSE;
    }

    return TRUE;
}

static gboolean logcat_dump_text(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err)
{
    gchar                          *buf;
    gint                            length;
    gchar                           priority;
    const struct logger_entry      *log_entry = (struct logger_entry *) pd;
    const struct logger_entry_v2   *log_entry_v2 = (struct logger_entry_v2 *) pd;
    gint                            payload_length;
    const gchar                    *tag;
    gint32                          pid;
    gint32                          tid;
    gint32                          seconds;
    gint32                          milliseconds;
    const guint8                   *msg_payload = NULL;
    const gchar                    *msg_begin;
    gint                            msg_pre_skip;
    gchar                          *log;
    gchar                          *log_part;
    gchar                          *log_next;
    const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
    const struct dumper_t          *dumper        = (const struct dumper_t *) wdh->priv;

    /* We can only write packet records. */
    if (phdr->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
        return FALSE;
    }

    payload_length = GINT32_FROM_LE(log_entry->len);
    pid = GINT32_FROM_LE(log_entry->pid);
    tid = GINT32_FROM_LE(log_entry->tid);
    seconds = GINT32_FROM_LE(log_entry->sec);
    milliseconds = GINT32_FROM_LE(log_entry->nsec) / 1000000;

    /* msg: <prio:1><tag:N>\0<msg:N>\0 with N >= 0, last \0 can be missing */
    if (pseudo_header->logcat.version == 1) {
        msg_payload = (const guint8 *) (log_entry + 1);

        priority = get_priority(msg_payload[0]);
        tag = msg_payload + 1;
        msg_pre_skip = 1 + (gint) strlen(tag) + 1;
        msg_begin = msg_payload + msg_pre_skip;
    } else if (pseudo_header->logcat.version == 2) {
        msg_payload = (const guint8 *) (log_entry_v2 + 1);

        priority = get_priority(msg_payload[0]);
        tag = msg_payload + 1;
        msg_pre_skip = 1 + (gint) strlen(tag) + 1;
        msg_begin = msg_payload + msg_pre_skip;
    } else {
        *err = WTAP_ERR_UNSUPPORTED_ENCAP;
        return FALSE;
    }

    /* copy the message part. If a nul byte was missing, it will be added. */
    log = g_strndup(msg_begin, payload_length - msg_pre_skip);

    /* long format: display one header followed by the whole message (which may
     * contain new lines). Other formats: include tag, etc. with each line */
    log_next = log;
    do {
        log_part = log_next;
        if (dumper->type == DUMP_LONG) {
            /* read until end, there is no next string */
            log_next = NULL;
        } else {
            /* read until next newline */
            log_next = strchr(log_part, '\n');
            if (log_next != NULL) {
                *log_next = '\0';
                ++log_next;
                /* ignore trailing newline */
                if (*log_next == '\0') {
                    log_next = NULL;
                }
            }
        }

        buf = logcat_log(dumper, seconds, milliseconds, pid, tid,
                priority, tag, log_part);
        if (!buf) {
            g_free(log);
            return FALSE;
        }
        length = (guint32)strlen(buf);

        if (!wtap_dump_file_write(wdh, buf, length, err)) {
            g_free(log);
            return FALSE;
        }

        wdh->bytes_dumped += length;
    } while (log_next != NULL);

    g_free(log);
    return TRUE;
}

gboolean logcat_text_brief_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_BRIEF;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_process_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_PROCESS;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_tag_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_TAG;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_time_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_TIME;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_thread_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_THREAD;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_threadtime_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_THREADTIME;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_long_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_LONG;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_dump_text;
    wdh->subtype_close = NULL;

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
