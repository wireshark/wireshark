/* logcat_text.c
 *
 * Copyright 2014, Michal Orynicz for Tieto Corporation
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

#include "logcat_text.h"
#include "logcat.h"

struct dumper_t {
    int type;
};

/* Returns '?' for invalid priorities */
static gchar get_priority(const guint8 priority) {
    static gchar priorities[] = "??VDIWEFS";

    if (priority >= (guint8) sizeof(priorities))
        return '?';

    return priorities[priority];
}

static gint buffered_detect_version(const guint8 *pd)
{
    const struct logger_entry     *log_entry;
    const struct logger_entry_v2  *log_entry_v2;
    gint                     version;
    const guint8            *msg_payload = NULL;
    guint8                  *msg_part;
    guint8                  *msg_end;
    guint16                  msg_len;

    log_entry    = (const struct logger_entry *)(const void *) pd;
    log_entry_v2 = (const struct logger_entry_v2 *)(const void *) pd;

    /* must contain at least priority and two nulls as separator */
    if (log_entry->len < 3)
        return -1;

    /* payload length may not exceed the maximum payload size */
    if (log_entry->len > LOGGER_ENTRY_MAX_PAYLOAD)
        return -1;

    /* cannot rely on __pad being 0 for v1, use heuristics to find out what
     * version is in use. First assume the smallest msg. */
    for (version = 1; version <= 2; ++version) {
        if (version == 1) {
            msg_payload = (const guint8 *) (log_entry + 1);
        } else if (version == 2) {
            /* v2 is 4 bytes longer */
            msg_payload = (const guint8 *) (log_entry_v2 + 1);
            if (log_entry_v2->hdr_size != sizeof(*log_entry_v2))
                continue;
        }

        /* A v2 msg has a 32-bit userid instead of v1 priority */
        if (get_priority(msg_payload[0]) == '?')
            continue;

        /* Is there a terminating '\0' for the tag? */
        msg_part = (guint8 *) memchr(msg_payload, '\0', log_entry->len - 1);
        if (msg_part == NULL)
            continue;

        /* if msg is '\0'-terminated, is it equal to the payload len? */
        ++msg_part;
        msg_len = (guint16)(log_entry->len - (msg_part - msg_payload));
        msg_end = (guint8 *) memchr(msg_part, '\0', msg_len);
        /* is the end of the buffer (-1) equal to the end of msg? */
        if (msg_end && (msg_payload + log_entry->len - 1 != msg_end))
            continue;

        return version;
    }

    return -1;
}

static gchar *logcat_log(const struct dumper_t *dumper, guint32 seconds,
        gint milliseconds, gint pid, gint tid, gchar priority, const gchar *tag,
        const gchar *log)
{
    gchar  time_buffer[15];
    time_t datetime;
    struct tm *tm;

    datetime = (time_t) seconds;

    switch (dumper->type) {
        case WTAP_ENCAP_LOGCAT_BRIEF:
            return g_strdup_printf("%c/%-8s(%5i): %s\n",
                    priority, tag, pid, log);
        case WTAP_ENCAP_LOGCAT_PROCESS:
            /* NOTE: Last parameter should be "process name", not tag;
                     Unfortunately, we do not have process name */
            return g_strdup_printf("%c(%5i) %s  (%s)\n",
                    priority, pid, log, "");
        case WTAP_ENCAP_LOGCAT_TAG:
            return g_strdup_printf("%c/%-8s: %s\n",
                   priority, tag, log);
        case WTAP_ENCAP_LOGCAT_THREAD:
            return g_strdup_printf("%c(%5i:%5i) %s\n",
                    priority, pid, tid, log);
        case WTAP_ENCAP_LOGCAT_TIME:
            tm = gmtime(&datetime);
            if (tm != NULL) {
                strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                        tm);
                return g_strdup_printf("%s.%03i %c/%-8s(%5i): %s\n",
                        time_buffer, milliseconds, priority, tag, pid, log);
            } else {
                return g_strdup_printf("Not representable %c/%-8s(%5i): %s\n",
                        priority, tag, pid, log);
            }
        case WTAP_ENCAP_LOGCAT_THREADTIME:
            tm = gmtime(&datetime);
            if (tm != NULL) {
                strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                        tm);
                return g_strdup_printf("%s.%03i %5i %5i %c %-8s: %s\n",
                        time_buffer, milliseconds, pid, tid, priority, tag, log);
            } else {
                return g_strdup_printf("Not representable %5i %5i %c %-8s: %s\n",
                        pid, tid, priority, tag, log);
            }
        case WTAP_ENCAP_LOGCAT_LONG:
            tm = gmtime(&datetime);
            if (tm != NULL) {
                strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                        tm);
                return g_strdup_printf("[ %s.%03i %5i:%5i %c/%-8s ]\n%s\n\n",
                        time_buffer, milliseconds, pid, tid, priority, tag, log);
            } else {
                return g_strdup_printf("[ Not representable %5i:%5i %c/%-8s ]\n%s\n\n",
                        pid, tid, priority, tag, log);
            }
        default:
            return NULL;
    }

}

static void get_time(gchar *string, struct wtap_pkthdr *phdr) {
    gint ms;
    struct tm date;
    time_t seconds;

    if (6 == sscanf(string, "%d-%d %d:%d:%d.%d", &date.tm_mon, &date.tm_mday, &date.tm_hour,
                    &date.tm_min, &date.tm_sec, &ms)) {
        date.tm_year = 70;
        date.tm_mon -= 1;
        seconds = mktime(&date);
        phdr->ts.secs = (time_t) seconds;
        phdr->ts.nsecs = (int) (ms * 1e6);
        phdr->presence_flags = WTAP_HAS_TS;
    } else {
        phdr->presence_flags = 0;
        phdr->ts.secs = (time_t) 0;
        phdr->ts.nsecs = (int) 0;
    }
}

static gboolean logcat_text_read_packet(FILE_T fh, struct wtap_pkthdr *phdr,
        Buffer *buf, gint file_type) {
    gint8 *pd;
    gchar cbuff[WTAP_MAX_PACKET_SIZE];
    gchar *ret = NULL;

    do {
        ret = file_gets(cbuff, WTAP_MAX_PACKET_SIZE, fh);
    } while (NULL != ret && 3 > strlen(cbuff) && !file_eof(fh));

    if (NULL == ret || 3 > strlen(cbuff)) {
        return FALSE;
    }

    if (WTAP_FILE_TYPE_SUBTYPE_LOGCAT_LONG == file_type &&
            !g_regex_match_simple(SPECIAL_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW), G_REGEX_MATCH_NOTEMPTY)) {
        gint64 file_off = 0;
        gchar lbuff[WTAP_MAX_PACKET_SIZE];
        int err;
        gchar *ret2 = NULL;

        file_off = file_tell(fh);
        ret2 = file_gets(lbuff,WTAP_MAX_PACKET_SIZE, fh);
        while (NULL != ret2 && 2 < strlen(lbuff) && !file_eof(fh)) {
            g_strlcat(cbuff,lbuff,WTAP_MAX_PACKET_SIZE);
            file_off = file_tell(fh);
            ret2 = file_gets(lbuff,WTAP_MAX_PACKET_SIZE, fh);
        }

        if(NULL == ret2 || 2 < strlen(lbuff)) {
            return FALSE;
        }

        file_seek(fh,file_off,SEEK_SET,&err);
    }

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->caplen = (guint32)strlen(cbuff);
    phdr->len = phdr->caplen;

    ws_buffer_assure_space(buf, phdr->caplen + 1);
    pd = ws_buffer_start_ptr(buf);
    if ((WTAP_FILE_TYPE_SUBTYPE_LOGCAT_TIME == file_type
            || WTAP_FILE_TYPE_SUBTYPE_LOGCAT_THREADTIME == file_type
            || WTAP_FILE_TYPE_SUBTYPE_LOGCAT_LONG == file_type)
            && '-' != cbuff[0]) { /* the last part filters out the -- beginning of... lines */
        if (WTAP_FILE_TYPE_SUBTYPE_LOGCAT_LONG == file_type) {
            get_time(cbuff+2, phdr);
        } else {
            get_time(cbuff, phdr);
        }
    } else {
        phdr->presence_flags = 0;
        phdr->ts.secs = (time_t) 0;
        phdr->ts.nsecs = (int) 0;
    }
    memcpy(pd, cbuff, phdr->caplen + 1);
    return TRUE;
}

static gboolean logcat_text_read(wtap *wth, int *err _U_ , gchar **err_info _U_,
        gint64 *data_offset) {
    *data_offset = file_tell(wth->fh);

    return logcat_text_read_packet(wth->fh, &wth->phdr, wth->frame_buffer,
            wth->file_type_subtype);
}

static gboolean logcat_text_seek_read(wtap *wth, gint64 seek_off,
        struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info _U_) {
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    if (!logcat_text_read_packet(wth->random_fh, phdr, buf,
            wth->file_type_subtype)) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    return TRUE;
}

wtap_open_return_val logcat_text_open(wtap *wth, int *err, gchar **err_info _U_) {
    gchar cbuff[WTAP_MAX_PACKET_SIZE];
    gchar *ret = NULL;

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    do {
        ret = file_gets(cbuff, WTAP_MAX_PACKET_SIZE, wth->fh);
    } while (NULL != ret && !file_eof(wth->fh)
            && ((3 > strlen(cbuff))
                    || g_regex_match_simple(SPECIAL_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW),
                            G_REGEX_MATCH_NOTEMPTY)));

    if (g_regex_match_simple(BRIEF_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT_BRIEF;
        wth->file_encap = WTAP_ENCAP_LOGCAT_BRIEF;
    } else if (g_regex_match_simple(TAG_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT_TAG;
        wth->file_encap = WTAP_ENCAP_LOGCAT_TAG;
    } else if (g_regex_match_simple(PROCESS_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT_PROCESS;
        wth->file_encap = WTAP_ENCAP_LOGCAT_PROCESS;
    } else if (g_regex_match_simple(TIME_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT_TIME;
        wth->file_encap = WTAP_ENCAP_LOGCAT_TIME;
    } else if (g_regex_match_simple(THREAD_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT_THREAD;
        wth->file_encap = WTAP_ENCAP_LOGCAT_THREAD;
    } else if (g_regex_match_simple(THREADTIME_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT_THREADTIME;
        wth->file_encap = WTAP_ENCAP_LOGCAT_THREADTIME;
    } else if (g_regex_match_simple(LONG_STRING, cbuff, (GRegexCompileFlags)((gint) G_REGEX_ANCHORED | (gint) G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT_LONG;
        wth->file_encap = WTAP_ENCAP_LOGCAT_LONG;
    } else {
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    wth->snapshot_length = 0;

    wth->subtype_read = logcat_text_read;
    wth->subtype_seek_read = logcat_text_seek_read;
    wth->file_tsprec = WTAP_TSPREC_USEC;
    return WTAP_OPEN_MINE;
}

int logcat_text_brief_dump_can_write_encap(int encap) {
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    switch (encap) {
    case WTAP_ENCAP_LOGCAT:
    case WTAP_ENCAP_LOGCAT_BRIEF:
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        return 0;
    default:
        return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}

int logcat_text_process_dump_can_write_encap(int encap) {
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    switch (encap) {
    case WTAP_ENCAP_LOGCAT:
    case WTAP_ENCAP_LOGCAT_PROCESS:
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        return 0;
    default:
        return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}

int logcat_text_tag_dump_can_write_encap(int encap) {
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    switch (encap) {
    case WTAP_ENCAP_LOGCAT:
    case WTAP_ENCAP_LOGCAT_TAG:
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        return 0;
    default:
        return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}

int logcat_text_time_dump_can_write_encap(int encap) {
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    switch (encap) {
    case WTAP_ENCAP_LOGCAT:
    case WTAP_ENCAP_LOGCAT_TIME:
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        return 0;
    default:
        return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}

int logcat_text_thread_dump_can_write_encap(int encap) {
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    switch (encap) {
    case WTAP_ENCAP_LOGCAT:
    case WTAP_ENCAP_LOGCAT_THREAD:
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        return 0;
    default:
        return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}

int logcat_text_threadtime_dump_can_write_encap(int encap) {
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    switch (encap) {
    case WTAP_ENCAP_LOGCAT:
    case WTAP_ENCAP_LOGCAT_THREADTIME:
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        return 0;
    default:
        return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}

int logcat_text_long_dump_can_write_encap(int encap) {
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    switch (encap) {
    case WTAP_ENCAP_LOGCAT:
    case WTAP_ENCAP_LOGCAT_LONG:
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        return 0;
    default:
        return WTAP_ERR_UNWRITABLE_ENCAP;
    }
}

static gboolean logcat_text_dump_text(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err, gchar **err_info)
{
    gchar                          *buf;
    gint                            length;
    gchar                           priority;
    const struct logger_entry      *log_entry;
    const struct logger_entry_v2   *log_entry_v2;
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
    gint                           logcat_version;
    const struct dumper_t          *dumper        = (const struct dumper_t *) wdh->priv;

    /* We can only write packet records. */
    if (phdr->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return FALSE;
    }

    switch (wdh->encap) {
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        {
            gint skipped_length;

            skipped_length = logcat_exported_pdu_length(pd);
            pd += skipped_length;

            if (!wtap_dump_file_write(wdh, (const gchar*) pd, phdr->caplen - skipped_length, err)) {
                return FALSE;
            }
        }
        break;
    case WTAP_ENCAP_LOGCAT:
        /* Skip EXPORTED_PDU*/
        if (wdh->encap == WTAP_ENCAP_WIRESHARK_UPPER_PDU) {
            gint skipped_length;

            skipped_length = logcat_exported_pdu_length(pd);
            pd += skipped_length;

            logcat_version = buffered_detect_version(pd);
        } else {
            const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;

            logcat_version = pseudo_header->logcat.version;
        }

        log_entry    = (const struct logger_entry *)(const void *) pd;
        log_entry_v2 = (const struct logger_entry_v2 *)(const void *) pd;

        payload_length = GINT32_FROM_LE(log_entry->len);
        pid = GINT32_FROM_LE(log_entry->pid);
        tid = GINT32_FROM_LE(log_entry->tid);
        seconds = GINT32_FROM_LE(log_entry->sec);
        milliseconds = GINT32_FROM_LE(log_entry->nsec) / 1000000;

        /* msg: <prio:1><tag:N>\0<msg:N>\0 with N >= 0, last \0 can be missing */
        if (logcat_version == 1) {
            msg_payload = (const guint8 *) (log_entry + 1);

            priority = get_priority(msg_payload[0]);
            tag = msg_payload + 1;
            msg_pre_skip = 1 + (gint) strlen(tag) + 1;
            msg_begin = msg_payload + msg_pre_skip;
        } else if (logcat_version == 2) {
            msg_payload = (const guint8 *) (log_entry_v2 + 1);

            priority = get_priority(msg_payload[0]);
            tag = msg_payload + 1;
            msg_pre_skip = 1 + (gint) strlen(tag) + 1;
            msg_begin = msg_payload + msg_pre_skip;
        } else {
            *err = WTAP_ERR_UNWRITABLE_REC_DATA;
            *err_info = g_strdup_printf("logcat: version %d isn't supported",
                                        logcat_version);
            return FALSE;
        }

        /* copy the message part. If a nul byte was missing, it will be added. */
        log = g_strndup(msg_begin, payload_length - msg_pre_skip);

        /* long format: display one header followed by the whole message (which may
         * contain new lines). Other formats: include tag, etc. with each line */
        log_next = log;
        do {
            log_part = log_next;
            if (dumper->type == WTAP_ENCAP_LOGCAT_LONG) {
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

            buf = logcat_log(dumper, seconds, milliseconds, pid, tid, priority, tag, log_part);
            if (!buf) {
                g_free(log);
                return FALSE;
            }
            length = (guint32) strlen(buf);

            if (!wtap_dump_file_write(wdh, buf, length, err)) {
                g_free(log);
                return FALSE;
            }

            wdh->bytes_dumped += length;
        } while (log_next != NULL );

        g_free(log);

        break;
    case WTAP_ENCAP_LOGCAT_BRIEF:
    case WTAP_ENCAP_LOGCAT_TAG:
    case WTAP_ENCAP_LOGCAT_PROCESS:
    case WTAP_ENCAP_LOGCAT_TIME:
    case WTAP_ENCAP_LOGCAT_THREAD:
    case WTAP_ENCAP_LOGCAT_THREADTIME:
    case WTAP_ENCAP_LOGCAT_LONG:
        if (dumper->type == wdh->encap) {
            if (!wtap_dump_file_write(wdh, (const gchar*) pd, phdr->caplen, err)) {
                return FALSE;
            }
        } else {
            *err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean logcat_text_dump_open(wtap_dumper *wdh, guint dump_type, int *err _U_) {
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = dump_type;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_dump_text;

    return TRUE;
}

gboolean logcat_text_brief_dump_open(wtap_dumper *wdh, int *err) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_BRIEF, err);
}

gboolean logcat_text_process_dump_open(wtap_dumper *wdh, int *err) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_PROCESS, err);
}

gboolean logcat_text_tag_dump_open(wtap_dumper *wdh, int *err) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_TAG, err);
}

gboolean logcat_text_time_dump_open(wtap_dumper *wdh, int *err) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_TIME, err);
}

gboolean logcat_text_thread_dump_open(wtap_dumper *wdh, int *err) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_THREAD, err);
}

gboolean logcat_text_threadtime_dump_open(wtap_dumper *wdh, int *err) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_THREADTIME, err);
}

gboolean logcat_text_long_dump_open(wtap_dumper *wdh, int *err) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_LONG, err);
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
