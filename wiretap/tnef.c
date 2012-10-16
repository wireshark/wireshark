/* tnef.c
 *
 * Transport-Neutral Encapsulation Format (TNEF) file reading
 *
 * $Id$
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

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "tnef.h"


static gboolean tnef_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
  gint64 offset;
  guint8 *buf;
  gint64 file_size;
  int packet_size;

  *err = 0;

  offset = file_tell(wth->fh);

  /* there is only ever one packet */
  if (offset)
    return FALSE;

  *data_offset = offset;

  if ((file_size = wtap_file_size(wth, err)) == -1)
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

  buffer_assure_space(wth->frame_buffer, packet_size);
  buf = buffer_start_ptr(wth->frame_buffer);

  wtap_file_read_expected_bytes(buf, packet_size, wth->fh, err, err_info);

  wth->phdr.presence_flags = 0; /* no time stamp, no "real length" */

  wth->phdr.caplen = packet_size;
  wth->phdr.len = packet_size;

  wth->phdr.ts.secs = 0;
  wth->phdr.ts.nsecs = 0;

  return TRUE;
}

static gboolean tnef_seek_read(wtap *wth, gint64 seek_off,
                               struct wtap_pkthdr *phdr _U_,
                               guint8 *pd, int length, int *err, gchar **err_info)
{
  int packet_size = length;

  /* there is only one packet */
  if(seek_off > 0) {
    *err = 0;
    return FALSE;
  }

  if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    return FALSE;

  wtap_file_read_expected_bytes(pd, packet_size, wth->random_fh, err, err_info);

  return TRUE;
}

int tnef_open(wtap *wth, int *err, gchar **err_info)
{
  int bytes_read;
  guint32 magic;

  bytes_read = file_read(&magic, sizeof magic, wth->fh);
  if (bytes_read != sizeof magic) {
    *err = file_error(wth->fh, err_info);
    return (*err != 0) ? -1 : 0;
  }

  if (htolel(magic) != TNEF_SIGNATURE)
     /* Not a tnef file */
     return 0;

  /* seek back to the start of the file  */
  if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    return -1;

  wth->file_type = WTAP_FILE_TNEF;
  wth->file_encap = WTAP_ENCAP_TNEF;
  wth->snapshot_length = 0;

  wth->subtype_read = tnef_read;
  wth->subtype_seek_read = tnef_seek_read;
  wth->tsprecision = WTAP_FILE_TSPREC_SEC;

  return 1;
}
