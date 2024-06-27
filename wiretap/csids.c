/* csids.c
 *
 * Copyright (c) 2000 by Mike Hall <mlh@io.com>
 * Copyright (c) 2000 by Cisco Systems
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "csids.h"
#include "wtap-int.h"
#include "file_wrappers.h"

#include <stdlib.h>
#include <string.h>

/*
 * This module reads the output from the Cisco Secure Intrusion Detection
 * System iplogging facility. The term iplogging is misleading since this
 * logger will only output TCP. There is no link layer information.
 * Packet format is 4 byte timestamp (seconds since epoch), and a 4 byte size
 * of data following for that packet.
 *
 * For a time there was an error in iplogging and the ip length, flags, and id
 * were byteswapped. We will check for this and handle it before handing to
 * wireshark.
 */

typedef struct {
  bool byteswapped;
} csids_t;

static bool csids_read(wtap *wth, wtap_rec *rec, Buffer *buf,
        int *err, char **err_info, int64_t *data_offset);
static bool csids_seek_read(wtap *wth, int64_t seek_off,
        wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static bool csids_read_packet(FILE_T fh, csids_t *csids,
        wtap_rec *rec, Buffer *buf, int *err, char **err_info);

struct csids_header {
  uint32_t seconds; /* seconds since epoch */
  uint16_t zeropad; /* 2 byte zero'ed pads */
  uint16_t caplen;  /* the capture length  */
};

static int csids_file_type_subtype = -1;

void register_csids(void);

wtap_open_return_val csids_open(wtap *wth, int *err, char **err_info)
{
  /* There is no file header. There is only a header for each packet
   * so we read a packet header and compare the caplen with iplen. They
   * should always be equal except with the weird byteswap version.
   *
   * THIS IS BROKEN-- anytime the caplen is 0x0101 or 0x0202 up to 0x0505
   * this will byteswap it. I need to fix this. XXX --mlh
   */

  int tmp,iplen;

  bool byteswap = false;
  struct csids_header hdr;
  csids_t *csids;

  /* check the file to make sure it is a csids file. */
  if( !wtap_read_bytes( wth->fh, &hdr, sizeof( struct csids_header), err, err_info ) ) {
    if( *err != WTAP_ERR_SHORT_READ ) {
      return WTAP_OPEN_ERROR;
    }
    return WTAP_OPEN_NOT_MINE;
  }
  if( hdr.zeropad != 0 || hdr.caplen == 0 ) {
    return WTAP_OPEN_NOT_MINE;
  }
  hdr.seconds = pntoh32( &hdr.seconds );
  hdr.caplen = pntoh16( &hdr.caplen );
  if( !wtap_read_bytes( wth->fh, &tmp, 2, err, err_info ) ) {
    if( *err != WTAP_ERR_SHORT_READ ) {
      return WTAP_OPEN_ERROR;
    }
    return WTAP_OPEN_NOT_MINE;
  }
  if( !wtap_read_bytes(wth->fh, &iplen, 2, err, err_info ) ) {
    if( *err != WTAP_ERR_SHORT_READ ) {
      return WTAP_OPEN_ERROR;
    }
    return WTAP_OPEN_NOT_MINE;
  }
  iplen = pntoh16(&iplen);

  if ( iplen == 0 )
    return WTAP_OPEN_NOT_MINE;

  /* if iplen and hdr.caplen are equal, default to no byteswap. */
  if( iplen > hdr.caplen ) {
    /* maybe this is just a byteswapped version. the iplen ipflags */
    /* and ipid are swapped. We cannot use the normal swaps because */
    /* we don't know the host */
    iplen = GUINT16_SWAP_LE_BE(iplen);
    if( iplen <= hdr.caplen ) {
      /* we know this format */
      byteswap = true;
    } else {
      /* don't know this one */
      return WTAP_OPEN_NOT_MINE;
    }
  } else {
    byteswap = false;
  }

  /* no file header. So reset the fh to 0 so we can read the first packet */
  if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    return WTAP_OPEN_ERROR;

  csids = g_new(csids_t, 1);
  wth->priv = (void *)csids;
  csids->byteswapped = byteswap;
  wth->file_encap = WTAP_ENCAP_RAW_IP;
  wth->file_type_subtype = csids_file_type_subtype;
  wth->snapshot_length = 0; /* not known */
  wth->subtype_read = csids_read;
  wth->subtype_seek_read = csids_seek_read;
  wth->file_tsprec = WTAP_TSPREC_SEC;

  /*
   * Add an IDB; we don't know how many interfaces were
   * involved, so we just say one interface, about which
   * we only know the link-layer type, snapshot length,
   * and time stamp resolution.
   */
  wtap_add_generated_idb(wth);

  return WTAP_OPEN_MINE;
}

/* Find the next packet and parse it; called from wtap_read(). */
static bool csids_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
  csids_t *csids = (csids_t *)wth->priv;

  *data_offset = file_tell(wth->fh);

  return csids_read_packet( wth->fh, csids, rec, buf, err, err_info );
}

/* Used to read packets in random-access fashion */
static bool
csids_seek_read(wtap *wth,
                int64_t seek_off,
                wtap_rec *rec,
                Buffer *buf,
                int *err,
                char **err_info)
{
  csids_t *csids = (csids_t *)wth->priv;

  if( file_seek( wth->random_fh, seek_off, SEEK_SET, err ) == -1 )
    return false;

  if( !csids_read_packet( wth->random_fh, csids, rec, buf, err, err_info ) ) {
    if( *err == 0 )
      *err = WTAP_ERR_SHORT_READ;
    return false;
  }
  return true;
}

static bool
csids_read_packet(FILE_T fh, csids_t *csids, wtap_rec *rec,
                  Buffer *buf, int *err, char **err_info)
{
  struct csids_header hdr;
  uint8_t *pd;

  if( !wtap_read_bytes_or_eof( fh, &hdr, sizeof( struct csids_header), err, err_info ) )
    return false;
  hdr.seconds = pntoh32(&hdr.seconds);
  hdr.caplen = pntoh16(&hdr.caplen);
  /*
   * The maximum value of hdr.caplen is 65535, which is less than
   * WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check
   * it.
   */

  rec->rec_type = REC_TYPE_PACKET;
  rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
  rec->presence_flags = WTAP_HAS_TS;
  rec->rec_header.packet_header.len = hdr.caplen;
  rec->rec_header.packet_header.caplen = hdr.caplen;
  rec->ts.secs = hdr.seconds;
  rec->ts.nsecs = 0;

  if( !wtap_read_packet_bytes( fh, buf, rec->rec_header.packet_header.caplen, err, err_info ) )
    return false;

  pd = ws_buffer_start_ptr( buf );
  if( csids->byteswapped ) {
    if( rec->rec_header.packet_header.caplen >= 2 ) {
      PBSWAP16(pd);   /* the ip len */
      if( rec->rec_header.packet_header.caplen >= 4 ) {
        PBSWAP16(pd+2); /* ip id */
        if( rec->rec_header.packet_header.caplen >= 6 )
          PBSWAP16(pd+4); /* ip flags and fragoff */
      }
    }
  }

  return true;
}

static const struct supported_block_type csids_blocks_supported[] = {
  /*
   * We support packet blocks, with no comments or other options.
   */
  { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info csids_info = {
  "CSIDS IPLog", "csids", NULL, NULL,
  false, BLOCKS_SUPPORTED(csids_blocks_supported),
  NULL, NULL, NULL
};

void register_csids(void)
{
  csids_file_type_subtype = wtap_register_file_type_subtype(&csids_info);

  /*
   * Register name for backwards compatibility with the
   * wtap_filetypes table in Lua.
   */
  wtap_register_backwards_compatibility_lua_name("CSIDS",
                                                 csids_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
