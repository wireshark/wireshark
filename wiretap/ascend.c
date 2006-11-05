/* ascend.c
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap-int.h"
#include "buffer.h"
#include "ascend.h"
#include "ascend-int.h"
#include "file_wrappers.h"
#include "file_util.h"

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

   Please see ascend-grammar.y for examples.

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
	union wtap_pseudo_header *pseudo_head, guint8 *pd, int len,
	int *err, gchar **err_info);
static void ascend_close(wtap *wth);

/* Seeks to the beginning of the next packet, and returns the
   byte offset at which the header for that packet begins.
   Returns -1 on failure. */
static gint64 ascend_seek(wtap *wth, int *err)
{
  int byte;
  gint64 date_off = -1, cur_off, packet_off;
  guint string_level[ASCEND_MAGIC_STRINGS];
  guint string_i = 0, type = 0;

  memset(&string_level, 0, sizeof(string_level));

  while (((byte = file_getc(wth->fh)) != EOF)) {

    for (string_i = 0; string_i < ASCEND_MAGIC_STRINGS; string_i++) {
      const gchar *strptr = ascend_magic[string_i].strptr;
      guint len           = strlen(strptr);
      
      if (byte == *(strptr + string_level[string_i])) {
        string_level[string_i]++;
        if (string_level[string_i] >= len) {
          cur_off = file_tell(wth->fh);
          if (cur_off == -1) {
            /* Error. */
            *err = file_error(wth->fh);
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

  if (byte != EOF || file_eof(wth->fh)) {
    /* Either we didn't find the offset, or we got an EOF. */
    *err = 0;
  } else {
    /* We (presumably) got an error (there's no equivalent to "ferror()"
       in zlib, alas, so we don't have a wrapper to check for an error). */
    *err = file_error(wth->fh);
  }
  return -1;

found:
  /*
   * Move to where the read for this packet should start, and return
   * that seek offset.
   */
  if (file_seek(wth->fh, packet_off, SEEK_SET, err) == -1)
    return -1;

  wth->pseudo_header.ascend.type = type;

  return packet_off;
}

int ascend_open(wtap *wth, int *err, gchar **err_info _U_)
{
  gint64 offset;
  struct stat statbuf;

  /* We haven't yet allocated a data structure for our private stuff;
     set the pointer to null, so that "ascend_seek()" knows not to
     fill it in. */
  wth->capture.ascend = NULL;

  offset = ascend_seek(wth, err);
  if (offset == -1) {
    if (*err == 0)
      return 0;
    else
      return -1;
  }

  wth->data_offset = offset;
  wth->file_type = WTAP_FILE_ASCEND;

  switch(wth->pseudo_header.ascend.type) {
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
  wth->subtype_close = ascend_close;
  wth->capture.ascend = g_malloc(sizeof(ascend_t));

  /* The first packet we want to read is the one that "ascend_seek()"
     just found; start searching for it at the offset at which it
     found it. */
  wth->capture.ascend->next_packet_seek_start = offset;

  /* MAXen and Pipelines report the time since reboot.  In order to keep
     from reporting packet times near the epoch, we subtract the first
     packet's timestamp from the capture file's ctime, which gives us an
     offset that we can apply to each packet.
   */
  if (fstat(wth->fd, &statbuf) == -1) {
    *err = errno;
    g_free(wth->capture.ascend);
    return -1;
  }
  wth->capture.ascend->inittime = statbuf.st_ctime;
  wth->capture.ascend->adjusted = 0;
  wth->tsprecision = WTAP_FILE_TSPREC_USEC;

  init_parse_ascend();

  return 1;
}

static void config_pseudo_header(union wtap_pseudo_header *pseudo_head)
{
  switch(pseudo_head->ascend.type) {
    case ASCEND_PFX_ISDN_X:
      pseudo_head->isdn.uton = TRUE;
      pseudo_head->isdn.channel = 0;
      break;

    case ASCEND_PFX_ISDN_R:
      pseudo_head->isdn.uton = FALSE;
      pseudo_head->isdn.channel = 0;
      break;

    case ASCEND_PFX_ETHER:
      pseudo_head->eth.fcs_len = 0;
      break;
  }
}

/* Read the next packet; called from wtap_read(). */
static gboolean ascend_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset)
{
  gint64 offset;
  guint8 *buf = buffer_start_ptr(wth->frame_buffer);
  ascend_pkthdr header;

  /* parse_ascend() will advance the point at which to look for the next
     packet's header, to just after the last packet's header (ie. at the
     start of the last packet's data). We have to get past the last
     packet's header because we might mistake part of it for a new header. */
  if (file_seek(wth->fh, wth->capture.ascend->next_packet_seek_start,
                SEEK_SET, err) == -1)
    return FALSE;

    offset = ascend_seek(wth, err);
    if (offset == -1)
      return FALSE;
  if (! parse_ascend(wth->fh, buf, &wth->pseudo_header.ascend, &header, &(wth->capture.ascend->next_packet_seek_start))) {
    *err = WTAP_ERR_BAD_RECORD;
    *err_info = g_strdup((ascend_parse_error != NULL) ? ascend_parse_error : "parse error");
    return FALSE;
  }

  buffer_assure_space(wth->frame_buffer, wth->snapshot_length);

  config_pseudo_header(&wth->pseudo_header);

  if (! wth->capture.ascend->adjusted) {
    wth->capture.ascend->adjusted = 1;
    if (header.start_time != 0) {
      /*
       * Capture file contained a date and time.
       * We do this only if this is the very first packet we've seen -
       * i.e., if "wth->capture.ascend->adjusted" is false - because
       * if we get a date and time after the first packet, we can't
       * go back and adjust the time stamps of the packets we've already
       * processed, and basing the time stamps of this and following
       * packets on the time stamp from the file text rather than the
       * ctime of the capture file means times before this and after
       * this can't be compared.
       */
      wth->capture.ascend->inittime = header.start_time;
    }
    if (wth->capture.ascend->inittime > header.secs)
      wth->capture.ascend->inittime -= header.secs;
  }
  wth->phdr.ts.secs = header.secs + wth->capture.ascend->inittime;
  wth->phdr.ts.nsecs = header.usecs * 1000;
  wth->phdr.caplen = header.caplen;
  wth->phdr.len = header.len;
  wth->data_offset = offset;

  *data_offset = offset;
  return TRUE;
}

static gboolean ascend_seek_read(wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_head, guint8 *pd, int len,
	int *err, gchar **err_info)
{
  /* don't care for length. */
  (void) len;

  if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    return FALSE;
  if (! parse_ascend(wth->random_fh, pd, &pseudo_head->ascend, NULL, &(wth->capture.ascend->next_packet_seek_start))) {
    *err = WTAP_ERR_BAD_RECORD;
    *err_info = g_strdup((ascend_parse_error != NULL) ? ascend_parse_error : "parse error");
    return FALSE;
  }

  config_pseudo_header(pseudo_head);
  return TRUE;
}

static void ascend_close(wtap *wth)
{
  g_free(wth->capture.ascend);
}
