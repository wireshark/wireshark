/* camins.c
 *
 * File format support for Rabbit Labs CAM Inspector files
 * Copyright (c) 2013 by Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

   a CAM Inspector file uses a 44-bit time counter to keep track of the
   time. the counter is in units of 1us. a timestamp block in the file
   updates a part of the global time counter. a timestamp contains a 2-bit
   relative position within the time counter and an 11-bit value for
   this position.

   error handling
   when we run into an error while assembling a data transfer, the
   primary goal is to recover so that we can handle the next transfer
   correctly (all files I used for testing contained errors where
   apparently the logging hardware missed some bytes)
*/

#include "config.h"
#include "camins.h"

#include <glib.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"


#define TRANS_CAM_HOST        0x20
#define TRANS_READ_SIZE_LOW   0x22
#define TRANS_READ_SIZE_HIGH  0x23
#define TRANS_HOST_CAM        0x28
#define TRANS_WRITE_SIZE_LOW  0x2A
#define TRANS_WRITE_SIZE_HIGH 0x2B

#define IS_TRANS_SIZE(x) \
    ((x)==TRANS_WRITE_SIZE_LOW || (x)==TRANS_WRITE_SIZE_HIGH || \
     (x)==TRANS_READ_SIZE_LOW || (x)==TRANS_READ_SIZE_HIGH)

/* a block contains a timestamp if the upper three bits are 0 */
#define IS_TIMESTAMP(x) (((x) & 0xE0) == 0x00)

/* a timestamp consists of a 2-bit position, followed by an 11-bit value. */
#define TS_VALUE_SHIFT  11
#define TS_POS_MASK     (0x3 << TS_VALUE_SHIFT)
#define TS_VALUE_MASK   (UINT64_C((1 << TS_VALUE_SHIFT) - 1))

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

/* PCAP DVB-CI pseudo-header, see https://www.kaiser.cx/pcap-dvbci.html */
#define DVB_CI_PSEUDO_HDR_VER 0
#define DVB_CI_PSEUDO_HDR_LEN 4
#define DVB_CI_PSEUDO_HDR_CAM_TO_HOST 0xFF
#define DVB_CI_PSEUDO_HDR_HOST_TO_CAM 0xFE

/* Maximum number of bytes to read before making a heuristic decision
 * of whether this is our file type or not. Arbitrary. */
#define CAMINS_BYTES_TO_CHECK 0x3FFFFFFFU

static int camins_file_type_subtype = -1;

void register_camins(void);

/* Detect a camins file by looking at the blocks that access the 16bit
   size register. The matching blocks to access the upper and lower 8bit
   must be no further than 5 blocks apart.
   A file may have errors that affect the size blocks. Therefore, we
   read CAMINS_BYTES_TO_CHECK bytes and require that we have many more
   valid pairs than errors. */
static wtap_open_return_val detect_camins_file(FILE_T fh)
{
    int      err;
    char    *err_info;
    uint8_t  block[2];
    uint8_t  search_block = 0;
    uint8_t  gap_count = 0;
    uint32_t valid_pairs = 0, invalid_pairs = 0;
    uint64_t read_bytes = 0;

    while (wtap_read_bytes(fh, block, sizeof(block), &err, &err_info)) {
       if (search_block != 0) {
           /* We're searching for a matching block to complete the pair. */

            if (block[1] == search_block) {
                /* We found it */
                valid_pairs++;
                search_block = 0;
            }
            else {
                /* We didn't find it. */
                gap_count++;
                if (gap_count > 5) {
                    /* Give up the search, we have no pair. */
                    invalid_pairs++;
                    search_block = 0;
                }
            }
        }
        else {
            /* We're not searching for a matching block at the moment.
               If we see a size read/write block of one type, the matching
               block is the other type and we can start searching. */

            if (block[1] == TRANS_READ_SIZE_LOW) {
                search_block = TRANS_READ_SIZE_HIGH;
                gap_count = 0;
            }
            else if (block[1] == TRANS_READ_SIZE_HIGH) {
                search_block = TRANS_READ_SIZE_LOW;
                gap_count = 0;
            }
            else if (block[1] == TRANS_WRITE_SIZE_LOW) {
                search_block = TRANS_WRITE_SIZE_HIGH;
                gap_count = 0;
            }
            else if (block[1] == TRANS_WRITE_SIZE_HIGH) {
                search_block = TRANS_WRITE_SIZE_LOW;
                gap_count = 0;
            }
        }
        read_bytes += sizeof(block);
        if (read_bytes > CAMINS_BYTES_TO_CHECK) {
            err = 0;
            break;
        }
    }

    if ((err != 0) && (err != WTAP_ERR_SHORT_READ)) {
        /* A real read error. */
        return WTAP_OPEN_ERROR;
    }

    /* For valid_pairs == invalid_pairs == 0, this isn't a camins file.
       Don't change > into >= */
    if (valid_pairs > 10 * invalid_pairs)
        return WTAP_OPEN_MINE;

    return WTAP_OPEN_NOT_MINE;
}


/* update the current time counter with infos from a timestamp block */
static void process_timestamp(uint16_t timestamp, uint64_t *time_us)
{
    uint8_t pos, shift;
    uint64_t val;

    if (!time_us)
        return;

    val = timestamp & TS_VALUE_MASK;
    pos = (timestamp & TS_POS_MASK) >> TS_VALUE_SHIFT;
    shift = TS_VALUE_SHIFT * pos;

    *time_us &= ~(TS_VALUE_MASK << shift);
    *time_us |= (val << shift);
}


/* find the transaction type for the data bytes of the next packet
   and the number of data bytes in that packet
   the fd is moved such that it can be used in a subsequent call
   to retrieve the data
   if requested by the caller, we increment the time counter as we
   walk through the file */
static bool
find_next_pkt_info(FILE_T fh,
        uint8_t *dat_trans_type, /* transaction type used for the data bytes */
        uint16_t *dat_len,       /* the number of data bytes in the packet */
        uint64_t *time_us,
        int *err, char **err_info)
{
    uint8_t      block[2];
    size_read_t  size_stat;

    if (!dat_trans_type || !dat_len)
        return false;

    RESET_STAT_VALS;

    do {
        if (!wtap_read_bytes_or_eof(fh, block, sizeof(block), err, err_info)) {
            RESET_STAT_VALS;
            return false;
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
                if (IS_TIMESTAMP(block[1]))
                    process_timestamp(pletoh16(block), time_us);
                break;
        }
    } while (size_stat != SIZE_HAVE_ALL);

    return true;
}


/* buffer allocated by the caller, must be long enough to hold
   dat_len bytes, ... */
static int
read_packet_data(FILE_T fh, uint8_t dat_trans_type, uint8_t *buf, uint16_t dat_len,
                 uint64_t *time_us, int *err, char **err_info)
{
    uint8_t *p;
    uint8_t  block[2];
    uint16_t bytes_count = 0;

    if (!buf)
        return -1;

    /* we're not checking for end-of-file here, we read as many bytes as
       we can get (up to dat_len) and return those
       end-of-file will be detected when we search for the next packet */

    p = buf;
    while (bytes_count < dat_len) {
        if (!wtap_read_bytes_or_eof(fh, block, sizeof(block), err, err_info))
            break;

        if (block[1] == dat_trans_type) {
            *p++ = block[0];
            bytes_count++;
        }
        else if (IS_TIMESTAMP(block[1])) {
                process_timestamp(pletoh16(block), time_us);
        }
        else if (IS_TRANS_SIZE(block[1])) {
            /* go back before the size transaction block
               the next packet should be able to pick up this block */
            if (-1 == file_seek(fh, -(int64_t)sizeof(block), SEEK_CUR, err))
                return -1;
            break;
        }
    }

    return bytes_count;
}


/* create a DVB-CI pseudo header
   return its length or -1 for error */
static int
create_pseudo_hdr(uint8_t *buf, uint8_t dat_trans_type, uint16_t dat_len,
    char **err_info)
{
    buf[0] = DVB_CI_PSEUDO_HDR_VER;

    if (dat_trans_type==TRANS_CAM_HOST)
        buf[1] = DVB_CI_PSEUDO_HDR_CAM_TO_HOST;
    else if (dat_trans_type==TRANS_HOST_CAM)
        buf[1] = DVB_CI_PSEUDO_HDR_HOST_TO_CAM;
    else {
        *err_info = ws_strdup_printf("camins: invalid dat_trans_type %u", dat_trans_type);
        return -1;
    }

    buf[2] = (dat_len>>8) & 0xFF;
    buf[3] = dat_len & 0xFF;

    return DVB_CI_PSEUDO_HDR_LEN;
}


static bool
camins_read_packet(FILE_T fh, wtap_rec *rec, Buffer *buf,
    uint64_t *time_us, int *err, char **err_info)
{
    uint8_t     dat_trans_type;
    uint16_t    dat_len;
    uint8_t    *p;
    int         offset, bytes_read;

    if (!find_next_pkt_info(
                fh, &dat_trans_type, &dat_len, time_us, err, err_info))
        return false;
    /*
     * The maximum value of length is 65535, which, even after
     * DVB_CI_PSEUDO_HDR_LEN is added to it, is less than
     * WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check
     * it.
     */

    ws_buffer_assure_space(buf, DVB_CI_PSEUDO_HDR_LEN+dat_len);
    p = ws_buffer_start_ptr(buf);
    offset = create_pseudo_hdr(p, dat_trans_type, dat_len, err_info);
    if (offset<0) {
        /* shouldn't happen, all invalid packets must be detected by
           find_next_pkt_info() */
        *err = WTAP_ERR_INTERNAL;
        /* create_pseudo_hdr() set err_info appropriately */
        return false;
    }

    bytes_read = read_packet_data(fh, dat_trans_type,
            &p[offset], dat_len, time_us, err, err_info);
    /* 0<=bytes_read<=dat_len is very likely a corrupted packet
       we let the dissector handle this */
    if (bytes_read < 0)
        return false;
    offset += bytes_read;

    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = 0; /* we may or may not have a time stamp */
    rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_DVBCI;
    if (time_us) {
        rec->presence_flags = WTAP_HAS_TS;
        rec->ts.secs = (time_t)(*time_us / (1000 * 1000));
        rec->ts.nsecs = (int)(*time_us % (1000 *1000) * 1000);
    }
    rec->rec_header.packet_header.caplen = offset;
    rec->rec_header.packet_header.len = offset;

    return true;
}


static bool
camins_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
    char **err_info, int64_t *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return camins_read_packet(wth->fh, rec, buf, (uint64_t *)(wth->priv),
                              err, err_info);
}


static bool
camins_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, Buffer *buf,
                 int *err, char **err_info)
{
    if (-1 == file_seek(wth->random_fh, seek_off, SEEK_SET, err))
        return false;

    return camins_read_packet(wth->random_fh, rec, buf, NULL, err, err_info);
}


wtap_open_return_val camins_open(wtap *wth, int *err, char **err_info _U_)
{
    wtap_open_return_val status;

    status = detect_camins_file(wth->fh);
    if (status != WTAP_OPEN_MINE) {
        /* A read error or a failed heuristic. */
        return status;
    }

    /* rewind the fh so we re-read from the beginning */
    if (-1 == file_seek(wth->fh, 0, SEEK_SET, err))
        return WTAP_OPEN_ERROR;

   wth->file_encap = WTAP_ENCAP_DVBCI;
   wth->snapshot_length = 0;
   wth->file_tsprec = WTAP_TSPREC_USEC;

   /* wth->priv stores a pointer to the global time counter. we update
      it as we go through the file sequentially. */
   wth->priv = g_new0(uint64_t, 1);

   wth->subtype_read = camins_read;
   wth->subtype_seek_read = camins_seek_read;
   wth->file_type_subtype = camins_file_type_subtype;

   *err = 0;

   /*
    * Add an IDB; we don't know how many interfaces were
    * involved, so we just say one interface, about which
    * we only know the link-layer type, snapshot length,
    * and time stamp resolution.
    */
   wtap_add_generated_idb(wth);

   return WTAP_OPEN_MINE;
}

static const struct supported_block_type camins_blocks_supported[] = {
   /*
    * We support packet blocks, with no comments or other options.
    */
   { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info camins_info = {
   "CAM Inspector file", "camins", "camins", NULL,
   false, BLOCKS_SUPPORTED(camins_blocks_supported),
   NULL, NULL, NULL
};

void register_camins(void)
{
   camins_file_type_subtype = wtap_register_file_type_subtype(&camins_info);

   /*
    * Register name for backwards compatibility with the
    * wtap_filetypes table in Lua.
    */
   wtap_register_backwards_compatibility_lua_name("CAMINS",
                                                  camins_file_type_subtype);
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
