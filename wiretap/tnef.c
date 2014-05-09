/* tnef.c
 *
 * Transport-Neutral Encapsulation Format (TNEF) file reading
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

#include <errno.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "wftap-int.h"
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "tnef.h"

static gboolean tnef_read_file(wftap *wfth, FILE_T fh, struct wtap_pkthdr *phdr,
                               Buffer *buf, int *err, gchar **err_info)
{
  gint64 file_size;
  int packet_size;

  if ((file_size = wftap_file_size(wfth, err)) == -1)
    return FALSE;

  if (file_size > WTAP_MAX_PACKET_SIZE) {
    /*
     * Probably a corrupt capture file; don't blow up trying
     * to allocate space for an immensely-large packet.
     */
    *err = WTAP_ERR_BAD_FILE;
    *err_info = g_strdup_printf("tnef: File has %" G_GINT64_MODIFIER "d-byte packet, bigger than maximum of %u",
                                file_size, WTAP_MAX_PACKET_SIZE);
    return FALSE;
  }
  packet_size = (int)file_size;

  phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */

  phdr->caplen = packet_size;
  phdr->len = packet_size;

  phdr->ts.secs = 0;
  phdr->ts.nsecs = 0;

  return wtap_read_packet_bytes(fh, buf, packet_size, err, err_info);
}

static gboolean tnef_read(wftap *wfth, int *err, gchar **err_info, gint64 *data_offset)
{
  gint64 offset;
  wtap* wth = (wtap*)wfth->tap_specific_data;

  *err = 0;

  offset = file_tell(wfth->fh);

  /* there is only ever one packet */
  if (offset)
    return FALSE;

  *data_offset = offset;

  return tnef_read_file(wfth, wfth->fh, &wth->phdr, wfth->frame_buffer, err, err_info);
}

static gboolean tnef_seek_read(wftap *wfth, gint64 seek_off,
                               void* header,
                               Buffer *buf, int *err, gchar **err_info)
{
  struct wtap_pkthdr *phdr = (struct wtap_pkthdr *)header;

  /* there is only one packet */
  if(seek_off > 0) {
    *err = 0;
    return FALSE;
  }

  if (file_seek(wfth->random_fh, seek_off, SEEK_SET, err) == -1)
    return FALSE;

  return tnef_read_file(wfth, wfth->random_fh, phdr, buf, err, err_info);
}

int tnef_open(wftap *wfth, int *err, gchar **err_info)
{
  int bytes_read;
  guint32 magic;

  bytes_read = file_read(&magic, sizeof magic, wfth->fh);
  if (bytes_read != sizeof magic) {
    *err = file_error(wfth->fh, err_info);
    return (*err != 0) ? -1 : 0;
  }

  if (GUINT32_TO_LE(magic) != TNEF_SIGNATURE)
     /* Not a tnef file */
     return 0;

  /* seek back to the start of the file  */
  if (file_seek(wfth->fh, 0, SEEK_SET, err) == -1)
    return -1;

  wfth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_TNEF;
  wfth->file_encap = WTAP_ENCAP_TNEF;
  wfth->snapshot_length = 0;

  wfth->subtype_read = tnef_read;
  wfth->subtype_seek_read = tnef_seek_read;
  wfth->tsprecision = WTAP_FILE_TSPREC_SEC;

  return 1;
}
