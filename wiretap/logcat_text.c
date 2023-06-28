/* logcat_text.c
 *
 * Copyright 2014, Michal Orynicz for Tieto Corporation
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "logcat_text.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include "logcat.h"

struct dumper_t {
    int type;
};

static int logcat_text_brief_file_type_subtype = -1;
static int logcat_text_process_file_type_subtype = -1;
static int logcat_text_tag_file_type_subtype = -1;
static int logcat_text_thread_file_type_subtype = -1;
static int logcat_text_time_file_type_subtype = -1;
static int logcat_text_threadtime_file_type_subtype = -1;
static int logcat_text_long_file_type_subtype = -1;

void register_logcat_text(void);

/* Returns '?' for invalid priorities */
static char get_priority(const uint8_t priority) {
    static char priorities[] = "??VDIWEFS";

    if (priority >= (uint8_t) sizeof(priorities))
        return '?';

    return priorities[priority];
}

static int buffered_detect_version(const uint8_t *pd)
{
    const struct logger_entry     *log_entry;
    const struct logger_entry_v2  *log_entry_v2;
    int                      version;
    const uint8_t           *msg_payload = NULL;
    uint8_t                 *msg_part;
    uint8_t                 *msg_end;
    uint16_t                 msg_len;

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
            msg_payload = (const uint8_t *) (log_entry + 1);
        } else if (version == 2) {
            /* v2 is 4 bytes longer */
            msg_payload = (const uint8_t *) (log_entry_v2 + 1);
            if (log_entry_v2->hdr_size != sizeof(*log_entry_v2))
                continue;
        }

        /* A v2 msg has a 32-bit userid instead of v1 priority */
        if (get_priority(msg_payload[0]) == '?')
            continue;

        /* Is there a terminating '\0' for the tag? */
        msg_part = (uint8_t *) memchr(msg_payload, '\0', log_entry->len - 1);
        if (msg_part == NULL)
            continue;

        /* if msg is '\0'-terminated, is it equal to the payload len? */
        ++msg_part;
        msg_len = (uint16_t)(log_entry->len - (msg_part - msg_payload));
        msg_end = (uint8_t *) memchr(msg_part, '\0', msg_len);
        /* is the end of the buffer (-1) equal to the end of msg? */
        if (msg_end && (msg_payload + log_entry->len - 1 != msg_end))
            continue;

        return version;
    }

    return -1;
}

static char *logcat_log(const struct dumper_t *dumper, uint32_t seconds,
        int milliseconds, int pid, int tid, char priority, const char *tag,
        const char *log)
{
    char   time_buffer[15];
    time_t datetime;
    struct tm *tm;

    datetime = (time_t) seconds;

    switch (dumper->type) {
        case WTAP_ENCAP_LOGCAT_BRIEF:
            return ws_strdup_printf("%c/%-8s(%5i): %s\n",
                    priority, tag, pid, log);
        case WTAP_ENCAP_LOGCAT_PROCESS:
            /* NOTE: Last parameter should be "process name", not tag;
                     Unfortunately, we do not have process name */
            return ws_strdup_printf("%c(%5i) %s  (%s)\n",
                    priority, pid, log, "");
        case WTAP_ENCAP_LOGCAT_TAG:
            return ws_strdup_printf("%c/%-8s: %s\n",
                   priority, tag, log);
        case WTAP_ENCAP_LOGCAT_THREAD:
            return ws_strdup_printf("%c(%5i:%5i) %s\n",
                    priority, pid, tid, log);
        case WTAP_ENCAP_LOGCAT_TIME:
            tm = gmtime(&datetime);
            if (tm != NULL) {
                strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                        tm);
                return ws_strdup_printf("%s.%03i %c/%-8s(%5i): %s\n",
                        time_buffer, milliseconds, priority, tag, pid, log);
            } else {
                return ws_strdup_printf("Not representable %c/%-8s(%5i): %s\n",
                        priority, tag, pid, log);
            }
        case WTAP_ENCAP_LOGCAT_THREADTIME:
            tm = gmtime(&datetime);
            if (tm != NULL) {
                strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                        tm);
                return ws_strdup_printf("%s.%03i %5i %5i %c %-8s: %s\n",
                        time_buffer, milliseconds, pid, tid, priority, tag, log);
            } else {
                return ws_strdup_printf("Not representable %5i %5i %c %-8s: %s\n",
                        pid, tid, priority, tag, log);
            }
        case WTAP_ENCAP_LOGCAT_LONG:
            tm = gmtime(&datetime);
            if (tm != NULL) {
                strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                        tm);
                return ws_strdup_printf("[ %s.%03i %5i:%5i %c/%-8s ]\n%s\n\n",
                        time_buffer, milliseconds, pid, tid, priority, tag, log);
            } else {
                return ws_strdup_printf("[ Not representable %5i:%5i %c/%-8s ]\n%s\n\n",
                        pid, tid, priority, tag, log);
            }
        default:
            return NULL;
    }

}

static void get_time(char *string, wtap_rec *rec) {
    int ms;
    struct tm date;
    time_t seconds;

    if (6 == sscanf(string, "%d-%d %d:%d:%d.%d", &date.tm_mon, &date.tm_mday, &date.tm_hour,
                    &date.tm_min, &date.tm_sec, &ms)) {
        date.tm_year = 70;
        date.tm_mon -= 1;
        date.tm_isdst = -1;
        seconds = mktime(&date);
        rec->ts.secs = seconds;
        rec->ts.nsecs = (int) (ms * 1e6);
        rec->presence_flags = WTAP_HAS_TS;
    } else {
        rec->presence_flags = 0;
        rec->ts.secs = (time_t) 0;
        rec->ts.nsecs = 0;
    }
}

static bool logcat_text_read_packet(FILE_T fh, wtap_rec *rec,
        Buffer *buf, int file_type) {
    int8_t *pd;
    char *cbuff;
    char *ret = NULL;

    cbuff = (char*)g_malloc(WTAP_MAX_PACKET_SIZE_STANDARD);
    do {
        ret = file_gets(cbuff, WTAP_MAX_PACKET_SIZE_STANDARD, fh);
    } while (NULL != ret && 3 > strlen(cbuff) && !file_eof(fh));

    if (NULL == ret || 3 > strlen(cbuff)) {
        g_free(cbuff);
        return false;
    }

    if (logcat_text_long_file_type_subtype == file_type &&
            !g_regex_match_simple(SPECIAL_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW), G_REGEX_MATCH_NOTEMPTY)) {
        int64_t file_off = 0;
        char *lbuff;
        int err;
        char *ret2 = NULL;

        lbuff = (char*)g_malloc(WTAP_MAX_PACKET_SIZE_STANDARD);
        file_off = file_tell(fh);
        ret2 = file_gets(lbuff,WTAP_MAX_PACKET_SIZE_STANDARD, fh);
        while (NULL != ret2 && 2 < strlen(lbuff) && !file_eof(fh)) {
            (void) g_strlcat(cbuff,lbuff,WTAP_MAX_PACKET_SIZE_STANDARD);
            file_off = file_tell(fh);
            ret2 = file_gets(lbuff,WTAP_MAX_PACKET_SIZE_STANDARD, fh);
        }

        if(NULL == ret2 || 2 < strlen(lbuff)) {
            g_free(cbuff);
            g_free(lbuff);
            return false;
        }

        file_seek(fh,file_off,SEEK_SET,&err);
        g_free(lbuff);
    }

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->rec_header.packet_header.caplen = (uint32_t)strlen(cbuff);
    rec->rec_header.packet_header.len = rec->rec_header.packet_header.caplen;

    ws_buffer_assure_space(buf, rec->rec_header.packet_header.caplen + 1);
    pd = ws_buffer_start_ptr(buf);
    if ((logcat_text_time_file_type_subtype == file_type
            || logcat_text_threadtime_file_type_subtype == file_type
            || logcat_text_long_file_type_subtype == file_type)
            && '-' != cbuff[0]) { /* the last part filters out the -- beginning of... lines */
        if (logcat_text_long_file_type_subtype == file_type) {
            get_time(cbuff+2, rec);
        } else {
            get_time(cbuff, rec);
        }
    } else {
        rec->presence_flags = 0;
        rec->ts.secs = (time_t) 0;
        rec->ts.nsecs = 0;
    }
    memcpy(pd, cbuff, rec->rec_header.packet_header.caplen + 1);
    g_free(cbuff);
    return true;
}

static bool logcat_text_read(wtap *wth, wtap_rec *rec,
        Buffer *buf, int *err _U_ , char **err_info _U_, int64_t *data_offset) {
    *data_offset = file_tell(wth->fh);

    return logcat_text_read_packet(wth->fh, rec, buf, wth->file_type_subtype);
}

static bool logcat_text_seek_read(wtap *wth, int64_t seek_off,
        wtap_rec *rec, Buffer *buf, int *err, char **err_info _U_) {
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    if (!logcat_text_read_packet(wth->random_fh, rec, buf,
            wth->file_type_subtype)) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return false;
    }
    return true;
}

wtap_open_return_val logcat_text_open(wtap *wth, int *err, char **err_info _U_) {
    char *cbuff;
    char *ret = NULL;

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    cbuff = (char*)g_malloc(WTAP_MAX_PACKET_SIZE_STANDARD);
    do {
        ret = file_gets(cbuff, WTAP_MAX_PACKET_SIZE_STANDARD, wth->fh);
    } while (NULL != ret && !file_eof(wth->fh)
            && ((3 > strlen(cbuff))
                    || g_regex_match_simple(SPECIAL_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW),
                            G_REGEX_MATCH_NOTEMPTY)));

    if (g_regex_match_simple(BRIEF_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = logcat_text_brief_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_LOGCAT_BRIEF;
    } else if (g_regex_match_simple(TAG_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = logcat_text_tag_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_LOGCAT_TAG;
    } else if (g_regex_match_simple(PROCESS_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = logcat_text_process_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_LOGCAT_PROCESS;
    } else if (g_regex_match_simple(TIME_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = logcat_text_time_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_LOGCAT_TIME;
    } else if (g_regex_match_simple(THREAD_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = logcat_text_thread_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_LOGCAT_THREAD;
    } else if (g_regex_match_simple(THREADTIME_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = logcat_text_threadtime_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_LOGCAT_THREADTIME;
    } else if (g_regex_match_simple(LONG_STRING, cbuff, (GRegexCompileFlags)(G_REGEX_ANCHORED | G_REGEX_RAW),
            G_REGEX_MATCH_NOTEMPTY)) {
        wth->file_type_subtype = logcat_text_long_file_type_subtype;
        wth->file_encap = WTAP_ENCAP_LOGCAT_LONG;
    } else {
        g_free(cbuff);
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        g_free(cbuff);
        return WTAP_OPEN_ERROR;
    }
    wth->snapshot_length = 0;

    wth->subtype_read = logcat_text_read;
    wth->subtype_seek_read = logcat_text_seek_read;
    wth->file_tsprec = WTAP_TSPREC_USEC;
    g_free(cbuff);
    return WTAP_OPEN_MINE;
}

static int logcat_text_brief_dump_can_write_encap(int encap) {
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

static int logcat_text_process_dump_can_write_encap(int encap) {
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

static int logcat_text_tag_dump_can_write_encap(int encap) {
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

static int logcat_text_time_dump_can_write_encap(int encap) {
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

static int logcat_text_thread_dump_can_write_encap(int encap) {
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

static int logcat_text_threadtime_dump_can_write_encap(int encap) {
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

static int logcat_text_long_dump_can_write_encap(int encap) {
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

static bool logcat_text_dump_text(wtap_dumper *wdh,
    const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info)
{
    char                           *buf;
    int                             length;
    char                            priority;
    const struct logger_entry      *log_entry;
    const struct logger_entry_v2   *log_entry_v2;
    int                             payload_length;
    const char                     *tag;
    int32_t                         pid;
    int32_t                         tid;
    int32_t                         seconds;
    int32_t                         milliseconds;
    const uint8_t                  *msg_payload = NULL;
    const char                     *msg_begin;
    int                             msg_pre_skip;
    char                           *log;
    char                           *log_part;
    char                           *log_next;
    int                            logcat_version;
    const struct dumper_t          *dumper        = (const struct dumper_t *) wdh->priv;

    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return false;
    }

    /*
     * Make sure this packet doesn't have a link-layer type that
     * differs from the one for the file.
     */
    if (wdh->file_encap != rec->rec_header.packet_header.pkt_encap) {
        *err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
        return false;
    }

    switch (wdh->file_encap) {
    case WTAP_ENCAP_WIRESHARK_UPPER_PDU:
        {
            int skipped_length;

            skipped_length = logcat_exported_pdu_length(pd);
            pd += skipped_length;

            if (!wtap_dump_file_write(wdh, (const char*) pd, rec->rec_header.packet_header.caplen - skipped_length, err)) {
                return false;
            }
        }
        break;
    case WTAP_ENCAP_LOGCAT:
        /* Skip EXPORTED_PDU*/
        if (wdh->file_encap == WTAP_ENCAP_WIRESHARK_UPPER_PDU) {
            int skipped_length;

            skipped_length = logcat_exported_pdu_length(pd);
            pd += skipped_length;

            logcat_version = buffered_detect_version(pd);
        } else {
            const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;

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
            msg_payload = (const uint8_t *) (log_entry + 1);

            priority = get_priority(msg_payload[0]);
            tag = msg_payload + 1;
            msg_pre_skip = 1 + (int) strlen(tag) + 1;
            msg_begin = msg_payload + msg_pre_skip;
        } else if (logcat_version == 2) {
            msg_payload = (const uint8_t *) (log_entry_v2 + 1);

            priority = get_priority(msg_payload[0]);
            tag = msg_payload + 1;
            msg_pre_skip = 1 + (int) strlen(tag) + 1;
            msg_begin = msg_payload + msg_pre_skip;
        } else {
            *err = WTAP_ERR_UNWRITABLE_REC_DATA;
            *err_info = ws_strdup_printf("logcat: version %d isn't supported",
                                        logcat_version);
            return false;
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
                return false;
            }
            length = (uint32_t) strlen(buf);

            if (!wtap_dump_file_write(wdh, buf, length, err)) {
                g_free(log);
                return false;
            }
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
        if (dumper->type == wdh->file_encap) {
            if (!wtap_dump_file_write(wdh, (const char*) pd, rec->rec_header.packet_header.caplen, err)) {
                return false;
            }
        } else {
            *err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
            return false;
        }
    }

    return true;
}

static bool logcat_text_dump_open(wtap_dumper *wdh, unsigned dump_type) {
    struct dumper_t *dumper;

    dumper = g_new(struct dumper_t, 1);
    dumper->type = dump_type;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_dump_text;

    return true;
}

static bool logcat_text_brief_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_BRIEF);
}

static bool logcat_text_process_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_PROCESS);
}

static bool logcat_text_tag_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_TAG);
}

static bool logcat_text_time_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_TIME);
}

static bool logcat_text_thread_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_THREAD);
}

static bool logcat_text_threadtime_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_THREADTIME);
}

static bool logcat_text_long_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_) {
    return logcat_text_dump_open(wdh, WTAP_ENCAP_LOGCAT_LONG);
}

static const struct supported_block_type logcat_text_brief_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info logcat_text_brief_info = {
    "Android Logcat Brief text format", "logcat-brief", NULL, NULL,
    false, BLOCKS_SUPPORTED(logcat_text_brief_blocks_supported),
    logcat_text_brief_dump_can_write_encap, logcat_text_brief_dump_open, NULL
};

static const struct supported_block_type logcat_text_process_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info logcat_text_process_info = {
    "Android Logcat Process text format", "logcat-process", NULL, NULL,
    false, BLOCKS_SUPPORTED(logcat_text_process_blocks_supported),
    logcat_text_process_dump_can_write_encap, logcat_text_process_dump_open, NULL
};

static const struct supported_block_type logcat_text_tag_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info logcat_text_tag_info = {
    "Android Logcat Tag text format", "logcat-tag", NULL, NULL,
    false, BLOCKS_SUPPORTED(logcat_text_tag_blocks_supported),
    logcat_text_tag_dump_can_write_encap, logcat_text_tag_dump_open, NULL
};

static const struct supported_block_type logcat_text_thread_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info logcat_text_thread_info = {
    "Android Logcat Thread text format", "logcat-thread", NULL, NULL,
    false, BLOCKS_SUPPORTED(logcat_text_thread_blocks_supported),
    logcat_text_thread_dump_can_write_encap, logcat_text_thread_dump_open, NULL
};

static const struct supported_block_type logcat_text_time_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info logcat_text_time_info = {
    "Android Logcat Time text format", "logcat-time", NULL, NULL,
    false, BLOCKS_SUPPORTED(logcat_text_time_blocks_supported),
    logcat_text_time_dump_can_write_encap, logcat_text_time_dump_open, NULL
};

static const struct supported_block_type logcat_text_threadtime_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info logcat_text_threadtime_info = {
    "Android Logcat Threadtime text format", "logcat-threadtime", NULL, NULL,
    false, BLOCKS_SUPPORTED(logcat_text_threadtime_blocks_supported),
    logcat_text_threadtime_dump_can_write_encap, logcat_text_threadtime_dump_open, NULL
};

static const struct supported_block_type logcat_text_long_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info logcat_text_long_info = {
    "Android Logcat Long text format", "logcat-long", NULL, NULL,
    false, BLOCKS_SUPPORTED(logcat_text_long_blocks_supported),
    logcat_text_long_dump_can_write_encap, logcat_text_long_dump_open, NULL
};

void register_logcat_text(void)
{
    logcat_text_brief_file_type_subtype = wtap_register_file_type_subtype(&logcat_text_brief_info);
    logcat_text_process_file_type_subtype = wtap_register_file_type_subtype(&logcat_text_process_info);
    logcat_text_tag_file_type_subtype = wtap_register_file_type_subtype(&logcat_text_tag_info);
    logcat_text_thread_file_type_subtype = wtap_register_file_type_subtype(&logcat_text_thread_info);
    logcat_text_time_file_type_subtype = wtap_register_file_type_subtype(&logcat_text_time_info);
    logcat_text_threadtime_file_type_subtype = wtap_register_file_type_subtype(&logcat_text_threadtime_info);
    logcat_text_long_file_type_subtype = wtap_register_file_type_subtype(&logcat_text_long_info);

    /*
     * Register names for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("LOGCAT_BRIEF",
                                                   logcat_text_brief_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("LOGCAT_PROCESS",
                                                   logcat_text_process_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("LOGCAT_TAG",
                                                   logcat_text_tag_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("LOGCAT_THREAD",
                                                   logcat_text_thread_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("LOGCAT_TIME",
                                                   logcat_text_time_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("LOGCAT_THREADTIME",
                                                   logcat_text_threadtime_file_type_subtype);
    wtap_register_backwards_compatibility_lua_name("LOGCAT_LONG",
                                                   logcat_text_long_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
