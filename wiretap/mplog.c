/* mplog.c
 *
 * File format support for Micropross mplog files
 * Copyright (c) 2016 by Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


/*
   The mplog file format logs the communication between a contactless
   smartcard and a card reader. Such files contain information about the
   physical layer as well as the bytes exchanged between devices.
   Some commercial logging and testing tools by the French company Micropross
   use this format.

   The information used for implementing this wiretap module were
   obtained from reverse-engineering. There is no publicly available
   documentation of the mplog file format.

   Mplog files start with the string "MPCSII". This string is part of
   the header which is in total 0x80 bytes long.

   Following the header, the file is a sequence of 8 byte-blocks.
        data       (one byte)
        block type (one byte)
        timestamp  (six bytes)

   The timestamp is a counter in little-endian format. The counter is in
   units of 10ns.
*/

#include "config.h"

#include <string.h>
#include <wtap-int.h>
#include <file_wrappers.h>

#include "mplog.h"

/* the block types */
#define TYPE_PCD_PICC_A  0x70
#define TYPE_PICC_PCD_A  0x71
#define TYPE_PCD_PICC_B  0x72
#define TYPE_PICC_PCD_B  0x73
#define TYPE_UNKNOWN     0xFF

#define KNOWN_TYPE(x) \
( \
  ((x) == TYPE_PCD_PICC_A) || \
  ((x) == TYPE_PICC_PCD_A) || \
  ((x) == TYPE_PCD_PICC_B) || \
  ((x) == TYPE_PICC_PCD_B) \
)

#define MPLOG_BLOCK_SIZE 8

/* ISO14443 pseudo-header, see http://www.kaiser.cx/pcap-iso14443.html */
#define ISO14443_PSEUDO_HDR_VER  0
#define ISO14443_PSEUDO_HDR_LEN  4
/*  the two transfer events are the types that include a trailing CRC
    the CRC is always present in mplog files */
#define ISO14443_PSEUDO_HDR_PICC_TO_PCD  0xFF
#define ISO14443_PSEUDO_HDR_PCD_TO_PICC  0xFE


#define ISO14443_MAX_PKT_LEN     256

#define PKT_BUF_LEN   (ISO14443_PSEUDO_HDR_LEN + ISO14443_MAX_PKT_LEN)


/* read the next packet, starting at the current position of fh
   as we know very little about the file format, our approach is rather simple:
   - we read block-by-block until a known block-type is found
        - this block's type is the type of the next packet
        - this block's timestamp will become the packet's timestamp
        - the data byte will be our packet's first byte
   - we carry on reading blocks and add the data bytes
     of all blocks of "our" type
   - if a different well-known block type is found, this is the end of
     our packet, we go back one block so that this block can be picked
     up as the start of the next packet
   - if two blocks of our packet's block type are more than 200us apart,
     we treat this as a packet boundary as described above
   */
static gboolean mplog_read_packet(FILE_T fh, struct wtap_pkthdr *phdr,
        Buffer *buf, int *err, gchar **err_info)
{
    guint8 *p, *start_p;
    /* --- the last block of a known type --- */
    guint64 last_ctr = 0;
    /* --- the current block --- */
    guint8 block[MPLOG_BLOCK_SIZE]; /* the entire block */
    guint8 data, type; /* its data and block type bytes */
    guint64 ctr; /* its timestamp counter */
    /* --- the packet we're assembling --- */
    gint pkt_bytes = 0;
    guint8 pkt_type = TYPE_UNKNOWN;
    /* the timestamp of the packet's first block,
       this will become the packet's timestamp */
    guint64 pkt_ctr = 0;


    ws_buffer_assure_space(buf, PKT_BUF_LEN);
    p = ws_buffer_start_ptr(buf);
    start_p = p;

    /* leave space for the iso14443 pseudo header
       we can't create it until we've seen the entire packet */
    p += ISO14443_PSEUDO_HDR_LEN;

    do {
        if (!wtap_read_bytes_or_eof(fh, block, sizeof(block), err, err_info)) {
            /* If we've already read some data, if this failed with an EOF,
               so that *err is 0, it's a short read. */
            if (pkt_bytes != 0) {
                if (*err == 0)
                    *err = WTAP_ERR_SHORT_READ;
            }
            break;
        }
        data = block[0];
        type = block[1];
        ctr = pletoh48(&block[2]);

        if (pkt_type == TYPE_UNKNOWN) {
            if (KNOWN_TYPE(type)) {
                pkt_type = type;
                pkt_ctr = ctr;
            }
        }

        if (type == pkt_type) {
            if (last_ctr != 0) {
                /* if the distance to the last byte of the
                   same type is larger than 200us, this is very likely the
                   first byte of a new packet -> go back one block and exit
                   ctr and last_ctr are in units of 10ns
                   at 106kbit/s, it takes approx 75us to send one byte */
                if (ctr - last_ctr > 200*100) {
                    file_seek(fh, -MPLOG_BLOCK_SIZE, SEEK_CUR, err);
                    break;
                }
            }

            *p++ = data;
            pkt_bytes++;
            last_ctr = ctr;
        }
        else if (KNOWN_TYPE(type)) {
            file_seek(fh, -MPLOG_BLOCK_SIZE, SEEK_CUR, err);
            break;
        }
    } while (pkt_bytes < ISO14443_MAX_PKT_LEN);

    if (pkt_type == TYPE_UNKNOWN)
        return FALSE;

    start_p[0] = ISO14443_PSEUDO_HDR_VER;

    if (pkt_type==TYPE_PCD_PICC_A || pkt_type==TYPE_PCD_PICC_B)
        start_p[1] = ISO14443_PSEUDO_HDR_PCD_TO_PICC;
    else
        start_p[1] = ISO14443_PSEUDO_HDR_PICC_TO_PCD;

    start_p[2] = pkt_bytes >> 8;
    start_p[3] = pkt_bytes & 0xFF;

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->pkt_encap = WTAP_ENCAP_ISO14443;
    phdr->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    phdr->ts.secs = (time_t)((pkt_ctr*10)/(1000*1000*1000));
    phdr->ts.nsecs = (int)((pkt_ctr*10)%(1000*1000*1000));
    phdr->caplen = ISO14443_PSEUDO_HDR_LEN + pkt_bytes;
    phdr->len = phdr->caplen;

    return TRUE;
}


static gboolean
mplog_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return mplog_read_packet(
            wth->fh, &wth->phdr, wth->frame_buffer, err, err_info);
}


static gboolean
mplog_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *pkthdr,
        Buffer *buf, int *err, gchar **err_info)
{
    if (-1 == file_seek(wth->random_fh, seek_off, SEEK_SET, err))
        return FALSE;

    if (!mplog_read_packet(wth->random_fh, pkthdr, buf, err, err_info)) {
        /* Even if we got an immediate EOF, that's an error. */
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    return TRUE;
}


wtap_open_return_val mplog_open(wtap *wth, int *err, gchar **err_info)
{
    gboolean ok;
    guint8 magic[6];

    ok = wtap_read_bytes(wth->fh, magic, 6, err, err_info);
    if (!ok) {
        if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }
    if (memcmp(magic, "MPCSII", 6) != 0)
        return WTAP_OPEN_NOT_MINE;

    wth->file_encap = WTAP_ENCAP_ISO14443;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_NSEC;

    wth->priv = NULL;

    wth->subtype_read = mplog_read;
    wth->subtype_seek_read = mplog_seek_read;
    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_MPLOG;

    /* skip the file header */
    if (-1 == file_seek(wth->fh, 0x80, SEEK_SET, err))
        return WTAP_OPEN_ERROR;

    *err = 0;
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
