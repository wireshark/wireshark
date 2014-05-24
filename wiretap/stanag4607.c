/* stanag4607.c
 *
 * STANAG 4607 file reading
 *
 * http://www.nato.int/structur/AC/224/standard/4607/4607e_JAS_ED3.pdf
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

#include <glib.h>
#include <errno.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "stanag4607.h"

typedef struct {
  time_t base_secs;
} stanag4607_t;

static gboolean is_valid_id(guint16 version_id)
{
#define VERSION_21 0x3231
#define VERSION_30 0x3330
  if ((version_id != VERSION_21) &&
      (version_id != VERSION_30))
     /* Not a stanag4607 file */
     return FALSE;
  return TRUE;
}

static gboolean stanag4607_read_file(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
                               Buffer *buf, int *err, gchar **err_info)
{
  stanag4607_t *stanag4607 = (stanag4607_t *)wth->priv;
  guint32 millisecs, secs, nsecs;
  gint64 offset = 0;
  guint8 stanag_pkt_hdr[37];
  int bytes_read;
  guint32 packet_size;

  *err = 0;

  /* Combined packet header and segment header */
  bytes_read = file_read(stanag_pkt_hdr, sizeof stanag_pkt_hdr, fh);
  if (bytes_read != sizeof stanag_pkt_hdr)
    goto fail;
  offset += bytes_read;

  if (!is_valid_id(pntoh16(&stanag_pkt_hdr[0]))) {
    *err = WTAP_ERR_BAD_FILE;
    *err_info = g_strdup("Bad version number");
    return FALSE;
  }

  phdr->rec_type = REC_TYPE_PACKET;

  /* The next 4 bytes are the packet length */
  packet_size = pntoh32(&stanag_pkt_hdr[2]);
  phdr->caplen = packet_size;
  phdr->len = packet_size;

  /* Sadly, the header doesn't contain times; but some segments do */
  /* So, get the segment header, which is just past the 32-byte header. */
  phdr->presence_flags = WTAP_HAS_TS;

  /* If no time specified, it's the last baseline time */
  phdr->ts.secs = stanag4607->base_secs;
  phdr->ts.nsecs = 0;
  millisecs = 0;

#define MISSION_SEGMENT 1
#define DWELL_SEGMENT 2
#define JOB_DEFINITION_SEGMENT 5
#define PLATFORM_LOCATION_SEGMENT 13
  if (MISSION_SEGMENT == stanag_pkt_hdr[32]) {
    guint8 mseg[39];
    struct tm tm;

    bytes_read = file_read(&mseg, sizeof mseg, fh);
    if (bytes_read != sizeof mseg)
      goto fail;
    offset += bytes_read;

    tm.tm_year = pntoh16(&mseg[35]) - 1900;
    tm.tm_mon = mseg[37] - 1;
    tm.tm_mday = mseg[38];
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    tm.tm_isdst = -1;
    stanag4607->base_secs = mktime(&tm);
    phdr->ts.secs = stanag4607->base_secs;
  }
  else if (PLATFORM_LOCATION_SEGMENT == stanag_pkt_hdr[32]) {
    bytes_read = file_read(&millisecs, sizeof millisecs, fh);
    if (bytes_read != sizeof millisecs)
      goto fail;
    offset += bytes_read;
    millisecs = g_ntohl(millisecs);
  }
  else if (DWELL_SEGMENT == stanag_pkt_hdr[32]) {
    guint8 dseg[19];
    bytes_read = file_read(&dseg, sizeof dseg, fh);
    if (bytes_read != sizeof dseg)
      goto fail;
    offset += bytes_read;
    millisecs = pntoh32(&dseg[15]);
  }
  if (0 != millisecs) {
    secs = millisecs/1000;
    nsecs = (millisecs - 1000 * secs) * 1000000;
    phdr->ts.secs = stanag4607->base_secs + secs;
    phdr->ts.nsecs = nsecs;
  }

  /* wind back to the start of the packet ... */
  if (file_seek(fh, - offset, SEEK_CUR, err) == -1)
    return FALSE;

  return wtap_read_packet_bytes(fh, buf, packet_size, err, err_info);

fail:
  *err = file_error(wth->fh, err_info);
  return FALSE;
}

static gboolean stanag4607_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
  gint64 offset;

  *err = 0;

  offset = file_tell(wth->fh);

  *data_offset = offset;

  return stanag4607_read_file(wth, wth->fh, &wth->phdr, wth->frame_buffer, err, err_info);
}

static gboolean stanag4607_seek_read(wtap *wth, gint64 seek_off,
                               struct wtap_pkthdr *phdr,
                               Buffer *buf, int *err, gchar **err_info)
{
  if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    return FALSE;

  return stanag4607_read_file(wth, wth->random_fh, phdr, buf, err, err_info);
}

int stanag4607_open(wtap *wth, int *err, gchar **err_info)
{
  int bytes_read;
  guint16 version_id;
  stanag4607_t *stanag4607;

  bytes_read = file_read(&version_id, sizeof version_id, wth->fh);
  if (bytes_read != sizeof version_id) {
    *err = file_error(wth->fh, err_info);
    return (*err != 0) ? -1 : 0;
  }

  if (!is_valid_id(GUINT16_TO_BE(version_id)))
     /* Not a stanag4607 file */
     return 0;

  /* seek back to the start of the file  */
  if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    return -1;

  wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_STANAG_4607;
  wth->file_encap = WTAP_ENCAP_STANAG_4607;
  wth->snapshot_length = 0; /* not known */

  stanag4607 = (stanag4607_t *)g_malloc(sizeof(stanag4607_t));
  wth->priv = (void *)stanag4607;
  stanag4607->base_secs = 0; /* unknown as of yet */

  wth->subtype_read = stanag4607_read;
  wth->subtype_seek_read = stanag4607_seek_read;
  wth->tsprecision = WTAP_FILE_TSPREC_MSEC;

  return 1;
}
