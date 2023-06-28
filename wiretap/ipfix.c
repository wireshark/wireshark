/* ipfix.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for ipfix file format
 * Copyright (c) 2010 by Hadriel Kaplan <hadrielk@yahoo.com>
 *   with generous copying from other wiretaps, such as pcapng
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* File format reference:
 *   RFC 5655 and 5101
 *   https://tools.ietf.org/rfc/rfc5655
 *   https://tools.ietf.org/rfc/rfc5101
 *
 * This wiretap is for an ipfix file format reader, per RFC 5655/5101.
 * All "records" in the file are IPFIX messages, beginning with an IPFIX
 *  message header of 16 bytes as follows from RFC 5101:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Version Number          |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Export Time                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Sequence Number                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Observation Domain ID                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Figure F: IPFIX Message Header Format

 * which is then followed by one or more "Sets": Data Sets, Template Sets,
 * and Options Template Sets.  Each Set then has one or more Records in
 * it.
 *
 * All IPFIX files are recorded in big-endian form (network byte order),
 * per the RFCs.  That means if we're on a little-endian system, all
 * hell will break loose if we don't g_ntohX.
 *
 * Since wireshark already has an IPFIX dissector (implemented in
 * packet-netflow.c), this reader will just set that dissector upon
 * reading each message.  Thus, an IPFIX Message is treated as a packet
 * as far as the dissector is concerned.
 */

#include "config.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP
#include "ipfix.h"

#include <stdlib.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>

#define RECORDS_FOR_IPFIX_CHECK 20

static bool
ipfix_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
    char **err_info, int64_t *data_offset);
static bool
ipfix_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);

#define IPFIX_VERSION 10

/* ipfix: message header */
typedef struct ipfix_message_header_s {
    uint16_t version;
    uint16_t message_length;
    uint32_t export_time_secs;
    uint32_t sequence_number;
    uint32_t observation_id; /* might be 0 for none */
    /* x bytes msg_body */
} ipfix_message_header_t;
#define IPFIX_MSG_HDR_SIZE 16

/* ipfix: common Set header for every Set type */
typedef struct ipfix_set_header_s {
    uint16_t set_type;
    uint16_t set_length;
    /* x bytes set_body */
} ipfix_set_header_t;
#define IPFIX_SET_HDR_SIZE 4


static int ipfix_file_type_subtype = -1;

void register_ipfix(void);

/* Read IPFIX message header from file.  Return true on success.  Set *err to
 * 0 on EOF, any other value for "real" errors (EOF is ok, since return
 * value is still false)
 */
static bool
ipfix_read_message_header(ipfix_message_header_t *pfx_hdr, FILE_T fh, int *err, char **err_info)
{
    if (!wtap_read_bytes_or_eof(fh, pfx_hdr, IPFIX_MSG_HDR_SIZE, err, err_info))
        return false;

    /* fix endianness, because IPFIX files are always big-endian */
    pfx_hdr->version = g_ntohs(pfx_hdr->version);
    pfx_hdr->message_length = g_ntohs(pfx_hdr->message_length);
    pfx_hdr->export_time_secs = g_ntohl(pfx_hdr->export_time_secs);
    pfx_hdr->sequence_number = g_ntohl(pfx_hdr->sequence_number);
    pfx_hdr->observation_id = g_ntohl(pfx_hdr->observation_id);

    /* is the version number one we expect? */
    if (pfx_hdr->version != IPFIX_VERSION) {
        /* Not an ipfix file. */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("ipfix: wrong version %d", pfx_hdr->version);
        return false;
    }

    if (pfx_hdr->message_length < 16) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("ipfix: message length %u is too short", pfx_hdr->message_length);
        return false;
    }

    /* go back to before header */
    if (file_seek(fh, 0 - IPFIX_MSG_HDR_SIZE, SEEK_CUR, err) == -1) {
        ws_debug("couldn't go back in file before header");
        return false;
    }

    return true;
}


/* Read IPFIX message header from file and fill in the struct wtap_rec
 * for the packet, and, if that succeeds, read the packet data.
 * Return true on success.  Set *err to 0 on EOF, any other value for "real"
 * errors (EOF is ok, since return value is still false).
 */
static bool
ipfix_read_message(FILE_T fh, wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    ipfix_message_header_t msg_hdr;

    if (!ipfix_read_message_header(&msg_hdr, fh, err, err_info))
        return false;
    /*
     * The maximum value of msg_hdr.message_length is 65535, which is
     * less than WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need
     * to check it.
     */

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;
    rec->rec_header.packet_header.len = msg_hdr.message_length;
    rec->rec_header.packet_header.caplen = msg_hdr.message_length;
    rec->ts.secs = msg_hdr.export_time_secs;
    rec->ts.nsecs = 0;

    return wtap_read_packet_bytes(fh, buf, msg_hdr.message_length, err, err_info);
}



/* classic wtap: open capture file.  Return WTAP_OPEN_MINE on success,
 * WTAP_OPEN_NOT_MINE on normal failure like malformed format,
 * WTAP_OPEN_ERROR on bad error like file system
 */
wtap_open_return_val
ipfix_open(wtap *wth, int *err, char **err_info)
{
    int i, n, records_for_ipfix_check = RECORDS_FOR_IPFIX_CHECK;
    char *s;
    uint16_t checked_len;
    ipfix_message_header_t msg_hdr;
    ipfix_set_header_t set_hdr;

    ws_debug("opening file");

    /* number of records to scan before deciding if this really is IPFIX */
    if ((s = getenv("IPFIX_RECORDS_TO_CHECK")) != NULL) {
        if (ws_strtoi32(s, NULL, &n) && n > 0 && n < 101) {
            records_for_ipfix_check = n;
        }
    }

    /*
     * IPFIX is a little hard because there's no magic number; we look at
     * the first few records and see if they look enough like IPFIX
     * records.
     */
    for (i = 0; i < records_for_ipfix_check; i++) {
        /* read first message header to check version */
        if (!ipfix_read_message_header(&msg_hdr, wth->fh, err, err_info)) {
            ws_debug("couldn't read message header #%d with err code #%d (%s)",
                         i, *err, *err_info);
            if (*err == WTAP_ERR_BAD_FILE) {
                *err = 0;            /* not actually an error in this case */
                g_free(*err_info);
                *err_info = NULL;
                return WTAP_OPEN_NOT_MINE;
            }
            if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
                return WTAP_OPEN_ERROR; /* real failure */
            /* else it's EOF */
            if (i < 1) {
                /* we haven't seen enough to prove this is a ipfix file */
                return WTAP_OPEN_NOT_MINE;
            }
            /*
             * If we got here, it's EOF and we haven't yet seen anything
             * that doesn't look like an IPFIX record - i.e. everything
             * we've seen looks like an IPFIX record - so we assume this
             * is an IPFIX file.
             */
            break;
        }
        if (file_seek(wth->fh, IPFIX_MSG_HDR_SIZE, SEEK_CUR, err) == -1) {
            ws_debug("failed seek to next message in file, %d bytes away",
                         msg_hdr.message_length);
            return WTAP_OPEN_NOT_MINE;
        }
        checked_len = IPFIX_MSG_HDR_SIZE;

        /* check each Set in IPFIX Message for sanity */
        while (checked_len < msg_hdr.message_length) {
            if (!wtap_read_bytes(wth->fh, &set_hdr, IPFIX_SET_HDR_SIZE,
                                 err, err_info)) {
                if (*err == WTAP_ERR_SHORT_READ) {
                    /* Not a valid IPFIX Set, so not an IPFIX file. */
                    ws_debug("error %d reading set", *err);
                    return WTAP_OPEN_NOT_MINE;
                }

                /* A real I/O error; fail. */
                return WTAP_OPEN_ERROR;
            }
            set_hdr.set_length = g_ntohs(set_hdr.set_length);
            if ((set_hdr.set_length < IPFIX_SET_HDR_SIZE) ||
                ((set_hdr.set_length + checked_len) > msg_hdr.message_length))  {
                ws_debug("found invalid set_length of %d",
                             set_hdr.set_length);
                return WTAP_OPEN_NOT_MINE;
            }

            if (file_seek(wth->fh, set_hdr.set_length - IPFIX_SET_HDR_SIZE,
                 SEEK_CUR, err) == -1)
            {
                ws_debug("failed seek to next set in file, %d bytes away",
                             set_hdr.set_length - IPFIX_SET_HDR_SIZE);
                return WTAP_OPEN_ERROR;
            }
            checked_len += set_hdr.set_length;
        }
    }

    /* go back to beginning of file */
    if (file_seek (wth->fh, 0, SEEK_SET, err) != 0)
    {
        return WTAP_OPEN_ERROR;
    }

    /* all's good, this is a IPFIX file */
    wth->file_encap = WTAP_ENCAP_RAW_IPFIX;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_SEC;
    wth->subtype_read = ipfix_read;
    wth->subtype_seek_read = ipfix_seek_read;
    wth->file_type_subtype = ipfix_file_type_subtype;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}


/* classic wtap: read packet */
static bool
ipfix_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
    char **err_info, int64_t *data_offset)
{
    *data_offset = file_tell(wth->fh);
    ws_debug("offset is initially %" PRId64, *data_offset);

    if (!ipfix_read_message(wth->fh, rec, buf, err, err_info)) {
        ws_debug("couldn't read message header with code: %d\n, and error '%s'",
                     *err, *err_info);
        return false;
    }

    return true;
}


/* classic wtap: seek to file position and read packet */
static bool
ipfix_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info)
{
    /* seek to the right file position */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
        ws_debug("couldn't read message header with code: %d\n, and error '%s'",
                     *err, *err_info);
        return false;   /* Seek error */
    }

    ws_debug("reading at offset %" PRIu64, seek_off);

    if (!ipfix_read_message(wth->random_fh, rec, buf, err, err_info)) {
        ws_debug("couldn't read message header");
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return false;
    }
    return true;
}

static const struct supported_block_type ipfix_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info ipfix_info = {
    "IPFIX File Format", "ipfix", "pfx", "ipfix",
    false, BLOCKS_SUPPORTED(ipfix_blocks_supported),
    NULL, NULL, NULL
};

void register_ipfix(void)
{
    ipfix_file_type_subtype = wtap_register_file_type_subtype(&ipfix_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("IPFIX",
                                                   ipfix_file_type_subtype);
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
