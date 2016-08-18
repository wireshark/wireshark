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
#include "ascendtext.h"
#include "ascend-int.h"
#include "file_wrappers.h"

#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>

/* Last updated: Feb 03 2005: Josh Bailey (joshbailey@lucent.com).

   This module reads the text hex dump output of various TAOS
   (Lucent/Ascend Max, Max TNT, APX, etc) debug commands, including:

   * pridisplay         traces primary rate ISDN
   * ether-display      traces Ethernet packets (dangerous! CPU intensive)
   * wanopening, wandisplay, wannext, wandsess
                        traces PPP or other WAN connections

   Please see ascend.y for examples.

   Detailed documentation on TAOS products is at http://support.lucent.com.

   Support for other commands will be added on an ongoing basis. */

typedef struct _ascend_magic_string {
  guint        type;
  const gchar *strptr;
  size_t       strlength;
} ascend_magic_string;

/* these magic strings signify the headers of a supported debug commands */
#define ASCEND_MAGIC_ENTRY(type, string) \
  { type, string, sizeof string - 1 } /* strlen of a constant string */
static const ascend_magic_string ascend_magic[] = {
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_ISDN_X,  "PRI-XMIT-"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_ISDN_R,  "PRI-RCV-"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_WDS_X,   "XMIT-"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_WDS_R,   "RECV-"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_WDS_X,   "XMIT:"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_WDS_R,   "RECV:"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_WDS_X,   "PPP-OUT"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_WDS_R,   "PPP-IN"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_WDD,     "WD_DIALOUT_DISP:"),
  ASCEND_MAGIC_ENTRY(ASCEND_PFX_ETHER,   "ETHER"),
};

#define ASCEND_MAGIC_STRINGS    G_N_ELEMENTS(ascend_magic)

#define ASCEND_DATE             "Date:"

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
  static const gchar ascend_date[] = ASCEND_DATE;
  size_t ascend_date_len           = sizeof ascend_date - 1; /* strlen of a constant string */
  size_t ascend_date_string_level;
  guint excessive_read_count = 262144;

  memset(&string_level, 0, sizeof(string_level));
  ascend_date_string_level = 0;

  while (((byte = file_getc(wth->fh)) != EOF)) {
    excessive_read_count--;

    if (!excessive_read_count) {
      *err = 0;
      return -1;
    }

    /*
     * See whether this is the string_level[string_i]th character of
     * Ascend magic string string_i.
     */
    for (string_i = 0; string_i < ASCEND_MAGIC_STRINGS; string_i++) {
      const gchar *strptr = ascend_magic[string_i].strptr;
      size_t len          = ascend_magic[string_i].strlength;

      if (byte == *(strptr + string_level[string_i])) {
        /*
         * Yes, it is, so we need to check for the next character of
         * that string.
         */
        string_level[string_i]++;

        /*
         * Have we matched the entire string?
         */
        if (string_level[string_i] >= len) {
          /*
           * Yes.
           */
          cur_off = file_tell(wth->fh);
          if (cur_off == -1) {
            /* Error. */
            *err = file_error(wth->fh, err_info);
            return -1;
          }

          /* We matched some other type of header. */
          if (date_off == -1) {
            /* We haven't yet seen a date header, so this packet
               doesn't have one.
               Back up over the header we just read; that's where a read
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
      } else {
        /*
         * Not a match for this string, so reset the match process.
         */
        string_level[string_i] = 0;
      }
    }

    /*
     * See whether this is the date_string_level'th character of
     * ASCEND_DATE.
     */
    if (byte == *(ascend_date + ascend_date_string_level)) {
      /*
       * Yes, it is, so we need to check for the next character of
       * that string.
       */
      ascend_date_string_level++;

      /*
       * Have we matched the entire string?
       */
      if (ascend_date_string_level >= ascend_date_len) {
        /* We matched a Date: header.  It's a special case;
           remember the offset, but keep looking for other
           headers.

           Reset the amount of Date: header that we've matched,
           so that we start the process of matching a Date:
           header all over again.

           XXX - what if we match multiple Date: headers before
           matching some other header? */
        cur_off = file_tell(wth->fh);
        if (cur_off == -1) {
          /* Error. */
          *err = file_error(wth->fh, err_info);
          return -1;
        }

        date_off = cur_off - ascend_date_len;
        ascend_date_string_level = 0;
      }
    } else {
      /*
       * Not a match for the Date: string, so reset the match process.
       */
      ascend_date_string_level = 0;
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

wtap_open_return_val ascend_open(wtap *wth, int *err, gchar **err_info)
{
  gint64 offset;
  guint8 buf[ASCEND_MAX_PKT_LEN];
  ascend_state_t parser_state;
  ws_statb64 statbuf;
  ascend_t *ascend;

  /* We haven't yet allocated a data structure for our private stuff;
     set the pointer to null, so that "ascend_seek()" knows not to
     fill it in. */
  wth->priv = NULL;

  offset = ascend_seek(wth, err, err_info);
  if (offset == -1) {
    if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
      return WTAP_OPEN_ERROR;
    return WTAP_OPEN_NOT_MINE;
  }

  /* Do a trial parse of the first packet just found to see if we might
     really have an Ascend file.  If it fails with an actual error,
     fail; those will be I/O errors. */
  if (run_ascend_parser(wth->fh, &wth->phdr, buf, &parser_state, err,
                        err_info) != 0 && *err != 0) {
      /* An I/O error. */
      return WTAP_OPEN_ERROR;
  }

  /* Either the parse succeeded, or it failed but didn't get an I/O
     error.

     If we got at least some data, return success even if the parser
     reported an error. This is because the debug header gives the
     number of bytes on the wire, not actually how many bytes are in
     the trace.  We won't know where the data ends until we run into
     the next packet. */
  if (parser_state.caplen == 0) {
    /* We read no data, so this presumably isn't an Ascend file. */
    return WTAP_OPEN_NOT_MINE;
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
    return WTAP_OPEN_ERROR;
  }
  ascend->inittime = statbuf.st_ctime;
  ascend->adjusted = FALSE;
  wth->file_tsprec = WTAP_TSPREC_USEC;

  return WTAP_OPEN_MINE;
}

/* Parse the capture file.
   Returns TRUE if we got a packet, FALSE otherwise. */
static gboolean
parse_ascend(ascend_t *ascend, FILE_T fh, struct wtap_pkthdr *phdr, Buffer *buf,
             guint length, int *err, gchar **err_info)
{
  ascend_state_t parser_state;
  int retval;

  ws_buffer_assure_space(buf, length);
  retval = run_ascend_parser(fh, phdr, ws_buffer_start_ptr(buf), &parser_state,
                             err, err_info);

  /* did we see any data (hex bytes)? if so, tip off ascend_seek()
     as to where to look for the next packet, if any. If we didn't,
     maybe this record was broken. Advance so we don't get into
     an infinite loop reading a broken trace. */
  if (parser_state.first_hexbyte) {
    ascend->next_packet_seek_start = parser_state.first_hexbyte;
  } else {
    /* Sometimes, a header will be printed but the data will be omitted, or
       worse -- two headers will be printed, followed by the data for each.
       Because of this, we need to be fairly tolerant of what we accept
       here.  If we didn't find any hex bytes, skip over what we've read so
       far so we can try reading a new packet. */
    ascend->next_packet_seek_start = file_tell(fh);
    retval = 0;
  }

  /* if we got at least some data, return success even if the parser
     reported an error. This is because the debug header gives the number
     of bytes on the wire, not actually how many bytes are in the trace.
     We won't know where the data ends until we run into the next packet. */
  if (parser_state.caplen) {
    if (! ascend->adjusted) {
      ascend->adjusted = TRUE;
      if (parser_state.saw_timestamp) {
        /*
         * Capture file contained a date and time.
         * We do this only if this is the very first packet we've seen -
         * i.e., if "ascend->adjusted" is false - because
         * if we get a date and time after the first packet, we can't
         * go back and adjust the time stamps of the packets we've already
         * processed, and basing the time stamps of this and following
         * packets on the time stamp from the file text rather than the
         * ctime of the capture file means times before this and after
         * this can't be compared.
         */
        ascend->inittime = parser_state.timestamp;
      }
      if (ascend->inittime > parser_state.secs)
        ascend->inittime -= parser_state.secs;
    }
    phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    phdr->ts.secs = parser_state.secs + ascend->inittime;
    phdr->ts.nsecs = parser_state.usecs * 1000;
    phdr->caplen = parser_state.caplen;
    phdr->len = parser_state.wirelen;

    /*
     * For these types, the encapsulation we use is not WTAP_ENCAP_ASCEND,
     * so set the pseudo-headers appropriately for the type (WTAP_ENCAP_ISDN
     * or WTAP_ENCAP_ETHERNET).
     */
    switch(phdr->pseudo_header.ascend.type) {
      case ASCEND_PFX_ISDN_X:
        phdr->pseudo_header.isdn.uton = TRUE;
        phdr->pseudo_header.isdn.channel = 0;
        break;

      case ASCEND_PFX_ISDN_R:
        phdr->pseudo_header.isdn.uton = FALSE;
        phdr->pseudo_header.isdn.channel = 0;
        break;

      case ASCEND_PFX_ETHER:
        phdr->pseudo_header.eth.fcs_len = 0;
        break;
    }
    return TRUE;
  }

  /* Didn't see any data. Still, perhaps the parser was happy.  */
  if (retval) {
    if (*err == 0) {
      /* Parser failed, but didn't report an I/O error, so a parse error.
         Return WTAP_ERR_BAD_FILE, with the parse error as the error string. */
      *err = WTAP_ERR_BAD_FILE;
      *err_info = g_strdup((parser_state.ascend_parse_error != NULL) ? parser_state.ascend_parse_error : "parse error");
    }
  } else {
    if (*err == 0) {
      /* Parser succeeded, but got no data, and didn't report an I/O error.
         Return WTAP_ERR_BAD_FILE, with a "got no data" error string. */
      *err = WTAP_ERR_BAD_FILE;
      *err_info = g_strdup("no data returned by parse");
    }
  }
  return FALSE;
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
  if (!parse_ascend(ascend, wth->fh, &wth->phdr, wth->frame_buffer,
                   wth->snapshot_length, err, err_info))
    return FALSE;

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
  if (!parse_ascend(ascend, wth->random_fh, phdr, buf,
                   wth->snapshot_length, err, err_info))
    return FALSE;

  return TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
