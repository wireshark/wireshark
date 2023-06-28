/* logcat.c
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "logcat.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

static int logcat_file_type_subtype = -1;

void register_logcat(void);

/* Returns '?' for invalid priorities */
static char get_priority(const uint8_t priority) {
    static char priorities[] = "??VDIWEFS";

    if (priority >= (uint8_t) sizeof(priorities))
        return '?';

    return priorities[priority];
}

/*
 * Returns:
 *
 *  -2 if we get an EOF at the beginning;
 *  -1 on an I/O error;
 *  0 if the record doesn't appear to be valid;
 *  1-{max int} as a version number if we got a valid record.
 */
static int detect_version(FILE_T fh, int *err, char **err_info)
{
    uint16_t                 payload_length;
    uint16_t                 hdr_size;
    uint16_t                 read_sofar;
    uint16_t                 entry_len;
    int                      version;
    struct logger_entry     *log_entry;
    struct logger_entry_v2  *log_entry_v2;
    uint8_t                 *buffer;
    uint16_t                 tmp;
    uint8_t                 *msg_payload;
    uint8_t                 *msg_part;
    uint8_t                 *msg_end;
    uint16_t                 msg_len;

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
    buffer = (uint8_t *) g_malloc(sizeof(*log_entry_v2) + payload_length);
    log_entry_v2 = (struct logger_entry_v2 *)(void *) buffer;
    log_entry = (struct logger_entry *)(void *) buffer;

    /* cannot rely on __pad being 0 for v1, use heuristics to find out what
     * version is in use. First assume the smallest msg. */
    for (version = 1; version <= 2; ++version) {
        if (version == 1) {
            msg_payload = (uint8_t *) (log_entry + 1);
            entry_len = sizeof(*log_entry) + payload_length;
        } else if (version == 2) {
            /* v2 is 4 bytes longer */
            msg_payload = (uint8_t *) (log_entry_v2 + 1);
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
        msg_part = (uint8_t *) memchr(msg_payload, '\0', payload_length - 1);
        if (msg_part == NULL)
            continue;

        /* if msg is '\0'-terminated, is it equal to the payload len? */
        ++msg_part;
        msg_len = (uint16_t)(payload_length - (msg_part - msg_payload));
        msg_end = (uint8_t *) memchr(msg_part, '\0', msg_len);
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

int logcat_exported_pdu_length(const uint8_t *pd) {
    const uint16_t *tag;
    const uint16_t *tag_length;
    int             length = 0;

    tag = (const uint16_t *)(const void *) pd;

    while(GINT16_FROM_BE(*tag)) {
        tag_length = (const uint16_t *)(const void *) (pd + 2);
        length += 2 + 2 + GINT16_FROM_BE(*tag_length);

        pd += 2 + 2 + GINT16_FROM_BE(*tag_length);
        tag = (const uint16_t *)(const void *) pd;
    }

    length += 2 + 2;

    return length;
}

static bool logcat_read_packet(struct logcat_phdr *logcat, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    int                  packet_size;
    uint16_t             payload_length;
    unsigned             tmp[2];
    uint8_t             *pd;
    struct logger_entry *log_entry;

    if (!wtap_read_bytes_or_eof(fh, &tmp, 2, err, err_info)) {
        return false;
    }
    payload_length = pletoh16(tmp);

    if (logcat->version == 1) {
        packet_size = (int)sizeof(struct logger_entry) + payload_length;
    } else if (logcat->version == 2) {
        packet_size = (int)sizeof(struct logger_entry_v2) + payload_length;
    } else {
        return false;
    }
    /*
     * The maximum value of payload_length is 65535, which, even after
     * the size of the logger entry structure is added to it, is less
     * than WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check
     * it.
     */

    ws_buffer_assure_space(buf, packet_size);
    pd = ws_buffer_start_ptr(buf);
    log_entry = (struct logger_entry *)(void *) pd;

    /* Copy the first two bytes of the packet. */
    memcpy(pd, tmp, 2);

    /* Read the rest of the packet. */
    if (!wtap_read_bytes(fh, pd + 2, packet_size - 2, err, err_info)) {
        return false;
    }

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;
    rec->ts.secs = (time_t) GINT32_FROM_LE(log_entry->sec);
    rec->ts.nsecs = GINT32_FROM_LE(log_entry->nsec);
    rec->rec_header.packet_header.caplen = packet_size;
    rec->rec_header.packet_header.len = packet_size;

    rec->rec_header.packet_header.pseudo_header.logcat.version = logcat->version;

    return true;
}

static bool logcat_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return logcat_read_packet((struct logcat_phdr *) wth->priv, wth->fh,
        rec, buf, err, err_info);
}

static bool logcat_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf,
    int *err, char **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    if (!logcat_read_packet((struct logcat_phdr *) wth->priv, wth->random_fh,
         rec, buf, err, err_info)) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return false;
    }
    return true;
}

wtap_open_return_val logcat_open(wtap *wth, int *err, char **err_info)
{
    int                 version;
    int                 tmp_version;
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

        /*
         * we've read three packets and the first two have the same
         * version; does the third have the same version?
         */
        if (tmp_version != version) {
            /* no, so this is presumably not a logcat file */
            return WTAP_OPEN_NOT_MINE;
        }
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    logcat = g_new(struct logcat_phdr, 1);
    logcat->version = version;

    wth->priv = logcat;

    wth->file_type_subtype = logcat_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_LOGCAT;
    wth->snapshot_length = 0;

    wth->subtype_read = logcat_read;
    wth->subtype_seek_read = logcat_seek_read;
    wth->file_tsprec = WTAP_TSPREC_USEC;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

static int logcat_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap != WTAP_ENCAP_LOGCAT && encap != WTAP_ENCAP_WIRESHARK_UPPER_PDU)
        return WTAP_ERR_UNWRITABLE_ENCAP;

    return 0;
}

static bool logcat_binary_dump(wtap_dumper *wdh,
    const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info _U_)
{
    int caplen;

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

    caplen = rec->rec_header.packet_header.caplen;

    /* Skip EXPORTED_PDU*/
    if (wdh->file_encap == WTAP_ENCAP_WIRESHARK_UPPER_PDU) {
        int skipped_length;

        skipped_length = logcat_exported_pdu_length(pd);
        pd += skipped_length;
        caplen -= skipped_length;
    }

    if (!wtap_dump_file_write(wdh, pd, caplen, err))
        return false;

    return true;
}

static bool logcat_binary_dump_open(wtap_dumper *wdh, int *err _U_,
    char **err_info _U_)
{
    wdh->subtype_write = logcat_binary_dump;

    return true;
}

static const struct supported_block_type logcat_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info logcat_info = {
    "Android Logcat Binary format", "logcat", "logcat", NULL,
    false, BLOCKS_SUPPORTED(logcat_blocks_supported),
    logcat_dump_can_write_encap, logcat_binary_dump_open, NULL
};

void register_logcat(void)
{
    logcat_file_type_subtype = wtap_register_file_type_subtype(&logcat_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("LOGCAT",
                                                   logcat_file_type_subtype);
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
