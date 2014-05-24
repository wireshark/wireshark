/* camins.c
 *
 * File format support for Rabbit Labs CAM Inspector files
 * Copyright (c) 2013 by Martin Kaiser <martin@kaiser.cx>
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


/* CAM Inspector is a commercial log tool for DVB-CI
   it stores recorded packets between a CI module and a DVB receiver,
   using a proprietary file format

   a CAM Inspector file consists of 16bit blocks
   the first byte contains payload data,
   the second byte contains a "transaction type"

   we currently support the following transaction types

   0x20 == data transfer from CI module to host
   0x22 == host reads the lower byte of the size register
   0x23 == host reads the higher byte of the size register
   0x2A == host writes the lower byte of the size register
   0x2B == host writes the higher byte of the size register
   0x28 == data transfer from host to CI module

   using these transaction types, we can identify and assemble data transfers
   from the host to the CAM and vice versa

   a host->module data transfer will use the following transactions
      one 0x2A and one 0x2B transaction to write the 16bit size
      <size> 0x28 transactions to transfer one byte at a time
   this will be assembled into one packet

   the module->host transfer is similar

   error handling
   when we run into an error while assembling a data transfer, the
   primary goal is to recover so that we can handle the next transfer
   correctly (all files I used for testing contained errors where
   apparently the logging hardware missed some bytes)
*/

#include "config.h"

#include <string.h>
#include <glib.h>
#include <wtap.h>
#include <wtap-int.h>
#include <file_wrappers.h>
#include <buffer.h>

#include "camins.h"


#define TRANS_CAM_HOST        0x20
#define TRANS_READ_SIZE_LOW   0x22
#define TRANS_READ_SIZE_HIGH  0x23
#define TRANS_HOST_CAM        0x28
#define TRANS_WRITE_SIZE_LOW  0x2A
#define TRANS_WRITE_SIZE_HIGH 0x2B

#define IS_TRANS_SIZE(x) \
    ((x)==TRANS_WRITE_SIZE_LOW || (x)==TRANS_WRITE_SIZE_HIGH || \
     (x)==TRANS_READ_SIZE_LOW || (x)==TRANS_READ_SIZE_HIGH)

typedef enum {
    SIZE_HAVE_NONE,
    SIZE_HAVE_LOW,
    SIZE_HAVE_HIGH,
    SIZE_HAVE_ALL
} size_read_t;

#define RESET_STAT_VALS \
{ \
    *dat_trans_type = 0x00; \
    *dat_len = 0x00; \
    size_stat = SIZE_HAVE_NONE; \
}

#define SIZE_ADD_LOW \
{ size_stat = (size_stat==SIZE_HAVE_HIGH ? SIZE_HAVE_ALL : SIZE_HAVE_LOW); }

#define SIZE_ADD_HIGH \
{ size_stat = (size_stat==SIZE_HAVE_LOW ? SIZE_HAVE_ALL : SIZE_HAVE_HIGH); }

/* PCAP DVB-CI pseudo-header, see http://www.kaiser.cx/pcap-dvbci.html */
#define DVB_CI_PSEUDO_HDR_VER 0
#define DVB_CI_PSEUDO_HDR_LEN 4
#define DVB_CI_PSEUDO_HDR_CAM_TO_HOST 0xFF
#define DVB_CI_PSEUDO_HDR_HOST_TO_CAM 0xFE


/* read a block of data from the camins file and handle the errors */
static gboolean
read_block(FILE_T fh, guint8 *buf, guint16 buf_len, int *err, gchar **err_info)
{
    int bytes_read;

    bytes_read = file_read((void *)buf, buf_len, fh);
    if (bytes_read != buf_len) {
        *err = file_error(fh, err_info);
        /* bytes_read==0 is end of file */
        if (bytes_read>0 && *err == 0) {
            *err = WTAP_ERR_SHORT_READ;
        }
        return FALSE;
    }

    return TRUE;
}


/* find the transaction type for the data bytes of the next packet
    and the number of data bytes in that packet
   the fd is moved such that it can be used in a subsequent call
    to retrieve the data */
static gboolean
find_next_pkt_dat_type_len(FILE_T fh,
        guint8 *dat_trans_type, /* transaction type used for the data bytes */
        guint16 *dat_len,       /* the number of data bytes in the packet */
        int *err, gchar **err_info)
{
    guint8       block[2];
    size_read_t  size_stat;

    if (!dat_trans_type || !dat_len)
        return FALSE;

    RESET_STAT_VALS;

    do {
        if (read_block(fh, block, sizeof(block), err, err_info) == FALSE) {
            RESET_STAT_VALS;
            return FALSE;
        }

        /* our strategy is to continue reading until we have a high and a
           low size byte for the same direction, duplicates or spurious data
           bytes are ignored */

        switch (block[1]) {
            case TRANS_READ_SIZE_LOW:
                if (*dat_trans_type != TRANS_CAM_HOST)
                    RESET_STAT_VALS;
                *dat_trans_type = TRANS_CAM_HOST;
                *dat_len |= block[0];
                SIZE_ADD_LOW;
                break;
            case TRANS_READ_SIZE_HIGH:
                if (*dat_trans_type != TRANS_CAM_HOST)
                    RESET_STAT_VALS;
                *dat_trans_type = TRANS_CAM_HOST;
                *dat_len |= (block[0] << 8);
                SIZE_ADD_HIGH;
                break;
            case TRANS_WRITE_SIZE_LOW:
                if (*dat_trans_type != TRANS_HOST_CAM)
                    RESET_STAT_VALS;
                *dat_trans_type = TRANS_HOST_CAM;
                *dat_len |= block[0];
                SIZE_ADD_LOW;
                break;
            case TRANS_WRITE_SIZE_HIGH:
                if (*dat_trans_type != TRANS_HOST_CAM)
                    RESET_STAT_VALS;
                *dat_trans_type = TRANS_HOST_CAM;
                *dat_len |= (block[0] << 8);
                SIZE_ADD_HIGH;
                break;
            default:
                break;
        }
    } while (size_stat != SIZE_HAVE_ALL);

    return TRUE;
}


/* buffer allocated by the caller, must be long enough to hold
   dat_len bytes, ... */
static gint
read_packet_data(FILE_T fh, guint8 dat_trans_type, guint8 *buf, guint16 dat_len,
                 int *err, gchar **err_info)
{
    guint8  *p;
    guint8   block[2];
    guint16  bytes_count = 0;

    if (!buf)
        return -1;

    /* we're not checking for end-of-file here, we read as many bytes as
       we can get (up to dat_len) and return those
       end-of-file will be detected when we search for the next packet */

    p = buf;
    while (bytes_count < dat_len) {
        if (read_block(fh, block, sizeof(block), err, err_info) == FALSE)
            break;

        if (block[1] == dat_trans_type) {
            *p++ = block[0];
            bytes_count++;
        }
        else if (IS_TRANS_SIZE(block[1])) {
            /* go back before the size transaction block
               the next packet should be able to pick up this block */
            if (-1 == file_seek(fh, -(gint64)sizeof(block), SEEK_CUR, err))
                return -1;
            break;
        }
    }

    return bytes_count;
}


/* create a DVB-CI pseudo header
   return its length or -1 for error */
static gint
create_pseudo_hdr(guint8 *buf, guint8 dat_trans_type, guint16 dat_len)
{
    if (!buf)
        return -1;

    buf[0] = DVB_CI_PSEUDO_HDR_VER;

    if (dat_trans_type==TRANS_CAM_HOST)
        buf[1] = DVB_CI_PSEUDO_HDR_CAM_TO_HOST;
    else if (dat_trans_type==TRANS_HOST_CAM)
        buf[1] = DVB_CI_PSEUDO_HDR_HOST_TO_CAM;
    else
        return -1;

    buf[2] = (dat_len>>8) & 0xFF;
    buf[3] = dat_len & 0xFF;

    return DVB_CI_PSEUDO_HDR_LEN;
}


static gboolean
camins_read_packet(FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
    guint8      dat_trans_type;
    guint16     dat_len;
    guint8     *p;
    gint        offset, bytes_read;

    if (!find_next_pkt_dat_type_len(fh, &dat_trans_type, &dat_len, err, err_info))
        return FALSE;

    buffer_assure_space(buf, DVB_CI_PSEUDO_HDR_LEN+dat_len);
    p = buffer_start_ptr(buf);
    /* NULL check for p is done in create_pseudo_hdr() */
    offset = create_pseudo_hdr(p, dat_trans_type, dat_len);
    if (offset<0) {
        /* shouldn't happen, all invalid packets must be detected by
           find_next_pkt_dat_type_len() */
        *err = WTAP_ERR_INTERNAL;
        return FALSE;
    }

    bytes_read = read_packet_data(fh, dat_trans_type,
            &p[offset], dat_len, err, err_info);
    /* 0<=bytes_read<=dat_len is very likely a corrupted packet
       we let the dissector handle this */
    if (bytes_read < 0)
        return FALSE;
    offset += bytes_read;

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->pkt_encap = WTAP_ENCAP_DVBCI;
    /* timestamps aren't supported for now */
    phdr->caplen = offset;
    phdr->len = offset;

    return TRUE;
}


static gboolean
camins_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return camins_read_packet(wth->fh, &wth->phdr, wth->frame_buffer, err,
        err_info);
}


static gboolean
camins_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *pkthdr, Buffer *buf, int *err, gchar **err_info)
{
    if (-1 == file_seek(wth->random_fh, seek_off, SEEK_SET, err))
        return FALSE;

    return camins_read_packet(wth->random_fh, pkthdr, buf, err, err_info);
}



int camins_open(wtap *wth, int *err, gchar **err_info _U_)
{
    guint8  found_start_blocks = 0;
    guint8  count = 0;
    guint8  block[2];
    int     bytes_read;

    /* all CAM Inspector files I've looked at have at least two blocks of
       0x00 0xE1 within the first 20 bytes */
    do {
        bytes_read = file_read(block, sizeof(block), wth->fh);
        if (bytes_read != sizeof(block))
            break;

        if (block[0]==0x00 && block[1] == 0xE1)
            found_start_blocks++;

        count++;
    } while (count<20);

    if (found_start_blocks < 2)
        return 0;   /* no CAM Inspector file */

    /* rewind the fh so we re-read from the beginning */
    if (-1 == file_seek(wth->fh, 0, SEEK_SET, err))
        return -1;

   wth->file_encap = WTAP_ENCAP_DVBCI;
   wth->snapshot_length = 0;
   wth->tsprecision = WTAP_FILE_TSPREC_MSEC;

   wth->priv = NULL;

   wth->subtype_read = camins_read;
   wth->subtype_seek_read = camins_seek_read;
   wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_CAMINS;

   *err = 0;
   return 1;
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
