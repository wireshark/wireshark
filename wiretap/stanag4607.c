/* stanag4607.c
 *
 * STANAG 4607 file reading
 *
 * http://www.nato.int/structur/AC/224/standard/4607/4607e_JAS_ED3.pdf
 * That is now missing from that site, but is available on the Wayback
 * Machine:
 *
 * https://web.archive.org/web/20130223054955/http://www.nato.int/structur/AC/224/standard/4607/4607.htm
 *
 * https://nso.nato.int/nso/zPublic/ap/aedp-7(2).pdf
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "stanag4607.h"

#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/buffer.h>

typedef struct {
  time_t base_secs;
} stanag4607_t;

#define PKT_HDR_SIZE  32 /* size of a packet header */
#define SEG_HDR_SIZE  5  /* size of a segment header */

static int stanag4607_file_type_subtype = -1;

void register_stanag4607(void);

static bool is_valid_id(uint16_t version_id)
{
#define VERSION_21 0x3231
#define VERSION_30 0x3330
  if ((version_id != VERSION_21) &&
      (version_id != VERSION_30))
     /* Not a stanag4607 file */
     return false;
  return true;
}

static bool stanag4607_read_file(wtap *wth, FILE_T fh, wtap_rec *rec,
                               Buffer *buf, int *err, char **err_info)
{
  stanag4607_t *stanag4607 = (stanag4607_t *)wth->priv;
  uint32_t millisecs, secs, nsecs;
  int64_t offset = 0;
  uint8_t stanag_pkt_hdr[PKT_HDR_SIZE+SEG_HDR_SIZE];
  uint32_t packet_size;

  *err = 0;

  /* Combined packet header and segment header */
  if (!wtap_read_bytes_or_eof(fh, stanag_pkt_hdr, sizeof stanag_pkt_hdr, err, err_info))
    return false;
  offset += sizeof stanag_pkt_hdr;

  if (!is_valid_id(pntoh16(&stanag_pkt_hdr[0]))) {
    *err = WTAP_ERR_BAD_FILE;
    *err_info = g_strdup("Bad version number");
    return false;
  }

  rec->rec_type = REC_TYPE_PACKET;
  rec->block = wtap_block_create(WTAP_BLOCK_PACKET);

  /* The next 4 bytes are the packet length */
  packet_size = pntoh32(&stanag_pkt_hdr[2]);
  if (packet_size > WTAP_MAX_PACKET_SIZE_STANDARD) {
    /*
     * Probably a corrupt capture file; don't blow up trying
     * to allocate space for an immensely-large packet.
     */
    *err = WTAP_ERR_BAD_FILE;
    *err_info = ws_strdup_printf("stanag4607: File has %" PRIu32 "d-byte packet, "
      "bigger than maximum of %u", packet_size, WTAP_MAX_PACKET_SIZE_STANDARD);
    return false;
  }
  if (packet_size < PKT_HDR_SIZE+SEG_HDR_SIZE) {
    /*
     * Probably a corrupt capture file; don't, for example, loop
     * infinitely if the size is zero.
     */
    *err = WTAP_ERR_BAD_FILE;
    *err_info = ws_strdup_printf("stanag4607: File has %" PRIu32 "d-byte packet, "
      "smaller than minimum of %u", packet_size, PKT_HDR_SIZE+SEG_HDR_SIZE);
    return false;
  }
  rec->rec_header.packet_header.caplen = packet_size;
  rec->rec_header.packet_header.len = packet_size;

  /* Sadly, the header doesn't contain times; but some segments do */
  /* So, get the segment header, which is just past the 32-byte header. */
  rec->presence_flags = WTAP_HAS_TS;

  /* If no time specified, it's the last baseline time */
  rec->ts.secs = stanag4607->base_secs;
  rec->ts.nsecs = 0;
  millisecs = 0;

#define MISSION_SEGMENT 1
#define DWELL_SEGMENT 2
#define JOB_DEFINITION_SEGMENT 5
#define PLATFORM_LOCATION_SEGMENT 13
  if (MISSION_SEGMENT == stanag_pkt_hdr[32]) {
    uint8_t mseg[39];
    struct tm tm;

    if (!wtap_read_bytes(fh, &mseg, sizeof mseg, err, err_info))
      return false;
    offset += sizeof mseg;

    tm.tm_year = pntoh16(&mseg[35]) - 1900;
    tm.tm_mon = mseg[37] - 1;
    tm.tm_mday = mseg[38];
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    tm.tm_isdst = -1;
    stanag4607->base_secs = mktime(&tm);
    rec->ts.secs = stanag4607->base_secs;
  }
  else if (PLATFORM_LOCATION_SEGMENT == stanag_pkt_hdr[32]) {
    if (!wtap_read_bytes(fh, &millisecs, sizeof millisecs, err, err_info))
      return false;
    offset += sizeof millisecs;
    millisecs = g_ntohl(millisecs);
  }
  else if (DWELL_SEGMENT == stanag_pkt_hdr[32]) {
    uint8_t dseg[19];
    if (!wtap_read_bytes(fh, &dseg, sizeof dseg, err, err_info))
      return false;
    offset += sizeof dseg;
    millisecs = pntoh32(&dseg[15]);
  }
  if (0 != millisecs) {
    secs = millisecs/1000;
    nsecs = (millisecs - 1000 * secs) * 1000000;
    rec->ts.secs = stanag4607->base_secs + secs;
    rec->ts.nsecs = nsecs;
  }

  /* wind back to the start of the packet ... */
  if (file_seek(fh, - offset, SEEK_CUR, err) == -1)
    return false;

  return wtap_read_packet_bytes(fh, buf, packet_size, err, err_info);
}

static bool stanag4607_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                                int *err, char **err_info, int64_t *data_offset)
{
  *data_offset = file_tell(wth->fh);

  return stanag4607_read_file(wth, wth->fh, rec, buf, err, err_info);
}

static bool stanag4607_seek_read(wtap *wth, int64_t seek_off,
                               wtap_rec *rec,
                               Buffer *buf, int *err, char **err_info)
{
  if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    return false;

  return stanag4607_read_file(wth, wth->random_fh, rec, buf, err, err_info);
}

wtap_open_return_val stanag4607_open(wtap *wth, int *err, char **err_info)
{
  uint16_t version_id;
  stanag4607_t *stanag4607;

  if (!wtap_read_bytes(wth->fh, &version_id, sizeof version_id, err, err_info))
    return (*err != WTAP_ERR_SHORT_READ) ? WTAP_OPEN_ERROR : WTAP_OPEN_NOT_MINE;

  if (!is_valid_id(GUINT16_TO_BE(version_id)))
     /* Not a stanag4607 file */
     return WTAP_OPEN_NOT_MINE;

  /* seek back to the start of the file  */
  if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    return WTAP_OPEN_ERROR;

  wth->file_type_subtype = stanag4607_file_type_subtype;
  wth->file_encap = WTAP_ENCAP_STANAG_4607;
  wth->snapshot_length = 0; /* not known */

  stanag4607 = g_new(stanag4607_t, 1);
  wth->priv = (void *)stanag4607;
  stanag4607->base_secs = 0; /* unknown as of yet */

  wth->subtype_read = stanag4607_read;
  wth->subtype_seek_read = stanag4607_seek_read;
  wth->file_tsprec = WTAP_TSPREC_MSEC;

  /*
   * Add an IDB; we don't know how many interfaces were
   * involved, so we just say one interface, about which
   * we only know the link-layer type, snapshot length,
   * and time stamp resolution.
   */
  wtap_add_generated_idb(wth);

  return WTAP_OPEN_MINE;
}

static const struct supported_block_type stanag4607_blocks_supported[] = {
  /*
   * We support packet blocks, with no comments or other options.
   */
  { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info stanag4607_info = {
  "STANAG 4607 Format", "stanag4607", NULL, NULL,
  false, BLOCKS_SUPPORTED(stanag4607_blocks_supported),
  NULL, NULL, NULL
};

void register_stanag4607(void)
{
  stanag4607_file_type_subtype = wtap_register_file_type_subtype(&stanag4607_info);

  /*
   * Register name for backwards compatibility with the
   * wtap_filetypes table in Lua.
   */
  wtap_register_backwards_compatibility_lua_name("STANAG_4607",
                                                 stanag4607_file_type_subtype);
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
