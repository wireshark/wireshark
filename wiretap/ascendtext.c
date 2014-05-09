/* ascendtext.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include "wtap-int.h"
#include "buffer.h"
#include "ascendtext.h"
#include "ascend-int.h"
#include "file_wrappers.h"
#include <wsutil/file_util.h>

#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>
#include <string.h>

/* Last updated: Feb 03 2005: Josh Bailey (joshbailey@lucent.com).

   This module reads the text hex dump output of various TAOS
   (Lucent/Ascend Max, Max TNT, APX, etc) debug commands, including:

   * pridisplay		traces primary rate ISDN
   * ether-display	traces Ethernet packets (dangerous! CPU intensive)
   * wanopening, wandisplay, wannext, wandsess
			traces PPP or other WAN connections

   Please see ascend.y for examples.

   Detailed documentation on TAOS products is at http://support.lucent.com.

   Support for other commands will be added on an ongoing basis. */

typedef struct _ascend_magic_string {
  guint        type;
  const gchar   *strptr;
} ascend_magic_string;

#define ASCEND_MAGIC_STRINGS	11
#define ASCEND_DATE		"Date:"

/* these magic strings signify the headers of a supported debug commands */
static const ascend_magic_string ascend_magic[] = {
  { ASCEND_PFX_ISDN_X,	"PRI-XMIT-" },
  { ASCEND_PFX_ISDN_R,	"PRI-RCV-" },
  { ASCEND_PFX_WDS_X,	"XMIT-" },
  { ASCEND_PFX_WDS_R,	"RECV-" },
  { ASCEND_PFX_WDS_X,	"XMIT:" },
  { ASCEND_PFX_WDS_R,	"RECV:" },
  { ASCEND_PFX_WDS_X,   "PPP-OUT" },
  { ASCEND_PFX_WDS_R,   "PPP-IN" },
  { ASCEND_PFX_WDD,	ASCEND_DATE },
  { ASCEND_PFX_WDD,	"WD_DIALOUT_DISP:" },
  { ASCEND_PFX_ETHER,	"ETHER" },
};

static gboolean ascend_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);
static gboolean ascend_seek_read(wtap *wth, gint64 seek_off,
	struct wtap_pkthdr *phdr, Buffer *buf,
	int *err, gchar **err_info);

/* Seeks to the beginning of the next packet, and returns the
   byte offset at which the header for that packet begins.
   Returns -1 on failure. */
static gint64 ascend_seek(wtap *wth, int *err, gchar **err_info)
{
  int byte;
  gint64 date_off = -1, cur_off, packet_off;
  size_t string_level[ASCEND_MAGIC_STRINGS];
  guint string_i = 0, type = 0;
  guint excessive_read_count = 262144;

  memset(&string_level, 0, sizeof(string_level));

  while (((byte = file_getc(wth->fh)) != EOF)) {
    excessive_read_count--;

    if (!excessive_read_count) {
      *err = 0;
      return -1;
    }

    for (string_i = 0; string_i < ASCEND_MAGIC_STRINGS; string_i++) {
      const gchar *strptr = ascend_magic[string_i].strptr;
      size_t len          = strlen(strptr);

      if (byte == *(strptr + string_level[string_i])) {
        string_level[string_i]++;
        if (string_level[string_i] >= len) {
          cur_off = file_tell(wth->fh);
          if (cur_off == -1) {
            /* Error. */
            *err = file_error(wth->fh, err_info);
            return -1;
          }

          /* Date: header is a special case. Remember the offset,
             but keep looking for other headers. */
	  if (strcmp(strptr, ASCEND_DATE) == 0) {
            date_off = cur_off - len;
          } else {
            if (date_off == -1) {
              /* Back up over the header we just read; that's where a read
                 of this packet should start. */
              packet_off = cur_off - len;
            } else {
              /* This packet has a date/time header; a read of it should
                 start at the beginning of *that* header. */
              packet_off = date_off;
            }

            type = ascend_magic[string_i].type;
            goto found;
          }
        }
      } else {
        string_level[string_i] = 0;
      }
    }
  }

  *err = file_error(wth->fh, err_info);
  return -1;

found:
  /*
   * Move to where the read for this packet should start, and return
   * that seek offset.
   */
  if (file_seek(wth->fh, packet_off, SEEK_SET, err) == -1)
    return -1;

  wth->phdr.pseudo_header.ascend.type = type;

  return packet_off;
}

int ascend_open(wtap *wth, int *err, gchar **err_info)
{
  gint64 offset;
  ws_statb64 statbuf;
  ascend_t *ascend;

  /* We haven't yet allocated a data structure for our private stuff;
     set the pointer to null, so that "ascend_seek()" knows not to
     fill it in. */
  wth->priv = NULL;

  offset = ascend_seek(wth, err, err_info);
  if (offset == -1) {
    if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
      return -1;
    return 0;
  }

  /* Do a trial parse of the first packet just found to see if we might really have an Ascend file */
  init_parse_ascend();
  if (!check_ascend(wth->fh, &wth->phdr)) {
    return 0;
  }

  wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_ASCEND;

  switch(wth->phdr.pseudo_header.ascend.type) {
    case ASCEND_PFX_ISDN_X:
    case ASCEND_PFX_ISDN_R:
      wth->file_encap = WTAP_ENCAP_ISDN;
      break;

    case ASCEND_PFX_ETHER:
      wth->file_encap = WTAP_ENCAP_ETHERNET;
      break;

    default:
      wth->file_encap = WTAP_ENCAP_ASCEND;
  }

  wth->snapshot_length = ASCEND_MAX_PKT_LEN;
  wth->subtype_read = ascend_read;
  wth->subtype_seek_read = ascend_seek_read;
  ascend = (ascend_t *)g_malloc(sizeof(ascend_t));
  wth->priv = (void *)ascend;

  /* The first packet we want to read is the one that "ascend_seek()"
     just found; start searching for it at the offset at which it
     found it. */
  ascend->next_packet_seek_start = offset;

  /* MAXen and Pipelines report the time since reboot.  In order to keep
     from reporting packet times near the epoch, we subtract the first
     packet's timestamp from the capture file's ctime, which gives us an
     offset that we can apply to each packet.
   */
  if (wtap_fstat(wth, &statbuf, err) == -1) {
    return -1;
  }
  ascend->inittime = statbuf.st_ctime;
  ascend->adjusted = FALSE;
  wth->tsprecision = WTAP_FILE_TSPREC_USEC;

  init_parse_ascend();

  return 1;
}

/* Read the next packet; called from wtap_read(). */
static gboolean ascend_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset)
{
  ascend_t *ascend = (ascend_t *)wth->priv;
  gint64 offset;

  /* parse_ascend() will advance the point at which to look for the next
     packet's header, to just after the last packet's header (ie. at the
     start of the last packet's data). We have to get past the last
     packet's header because we might mistake part of it for a new header. */
  if (file_seek(wth->fh, ascend->next_packet_seek_start,
                SEEK_SET, err) == -1)
    return FALSE;

  offset = ascend_seek(wth, err, err_info);
  if (offset == -1)
    return FALSE;
  if (parse_ascend(ascend, wth->fh, &wth->phdr, wth->frame_buffer,
                   wth->snapshot_length) != PARSED_RECORD) {
    *err = WTAP_ERR_BAD_FILE;
    *err_info = g_strdup((ascend_parse_error != NULL) ? ascend_parse_error : "parse error");
    return FALSE;
  }

  *data_offset = offset;
  return TRUE;
}

static gboolean ascend_seek_read(wtap *wth, gint64 seek_off,
	struct wtap_pkthdr *phdr, Buffer *buf,
	int *err, gchar **err_info)
{
  ascend_t *ascend = (ascend_t *)wth->priv;

  if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    return FALSE;
  if (parse_ascend(ascend, wth->random_fh, phdr, buf,
                   wth->snapshot_length) != PARSED_RECORD) {
    *err = WTAP_ERR_BAD_FILE;
    *err_info = g_strdup((ascend_parse_error != NULL) ? ascend_parse_error : "parse error");
    return FALSE;
  }

  return TRUE;
}
