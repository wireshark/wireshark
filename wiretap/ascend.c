/* ascend.c
 *
 * $Id: ascend.c,v 1.24 2001/07/13 00:55:57 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap-int.h"
#include "buffer.h"
#include "ascend.h"
#include "ascend-int.h"
#include "file_wrappers.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>
#include <string.h>

/* This module reads the output of the 'wandsession', 'wannext',
   'wandisplay', and similar commands available on Lucent/Ascend access
   equipment.  The output is text, with a header line followed by the
   packet data.  Usage instructions for the commands can be found by
   searching http://aos.ascend.com .  Ascend likes to move their pages
   around quite a bit, otherwise I'd put a more specific URL here.

   Example 'wandsess' output data:
   
RECV-iguana:241:(task: B02614C0, time: 1975432.85) 49 octets @ 8003BD94
  [0000]: FF 03 00 3D C0 06 CA 22 2F 45 00 00 28 6A 3B 40 
  [0010]: 00 3F 03 D7 37 CE 41 62 12 CF 00 FB 08 20 27 00 
  [0020]: 50 E4 08 DD D7 7C 4C 71 92 50 10 7D 78 67 C8 00 
  [0030]: 00 
XMIT-iguana:241:(task: B04E12C0, time: 1975432.85) 53 octets @ 8009EB16
  [0000]: FF 03 00 3D C0 09 1E 31 21 45 00 00 2C 2D BD 40 
  [0010]: 00 7A 06 D8 B1 CF 00 FB 08 CE 41 62 12 00 50 20 
  [0020]: 29 7C 4C 71 9C 9A 6A 93 A4 60 12 22 38 3F 10 00 
  [0030]: 00 02 04 05 B4 

    Example 'wdd' output data:

Date: 01/12/1990.  Time: 12:22:33
Cause an attempt to place call to 14082750382
WD_DIALOUT_DISP: chunk 2515EE type IP.
(task: 251790, time: 994953.28) 44 octets @ 2782B8
  [0000]: 00 C0 7B 71 45 6C 00 60 08 16 AA 51 08 00 45 00
  [0010]: 00 2C 66 1C 40 00 80 06 53 F6 AC 14 00 18 CC 47
  [0020]: C8 45 0A 31 00 50 3B D9 5B 75 00 00

    (note that the capture whence this came dates back to January
    *1999*; I presume that either the person who sent it to me
    hadn't bothered keeping its internal clock set, or that its
    internal clock or the date it displays in those messages
    is only loosely connected to reality)

  Note that a maximum of eight rows will be displayed (for a maximum of
  128 bytes), no matter what the octet count is.
  
  When reading a packet, the module prepends an ascend_pkt_hdr to the 
  data.

 */

/* How far into the file we should look for packet headers */
#define ASCEND_MAX_SEEK 100000

/* XXX  Should we replace this with a more generalized array? */
/* Magic numbers for Ascend wandsession/wanopening/ether-display data */
static const char ascend_xmagic[]  = { 'X', 'M', 'I', 'T', '-' };
static const char ascend_rmagic[]  = { 'R', 'E', 'C', 'V', '-' };
static const char ascend_w1magic[] = { 'D', 'a', 't', 'e', ':',  };
static const char ascend_w2magic[] = { 'W', 'D', '_', 'D', 'I', 'A', 'L', 'O', 'U', 'T', '_', 'D', 'I', 'S', 'P', ':' };

#define ASCEND_X_SIZE  (sizeof ascend_xmagic  / sizeof ascend_xmagic[0])
#define ASCEND_R_SIZE  (sizeof ascend_rmagic  / sizeof ascend_rmagic[0])
#define ASCEND_W1_SIZE (sizeof ascend_w1magic / sizeof ascend_w1magic[0])
#define ASCEND_W2_SIZE (sizeof ascend_w2magic / sizeof ascend_w2magic[0])

static gboolean ascend_read(wtap *wth, int *err, int *data_offset);
static int ascend_seek_read (wtap *wth, int seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len);
static void ascend_close(wtap *wth);

/* Seeks to the beginning of the next packet, and returns the
   byte offset at which the heade for that packet begins.
   Returns -1 on failure.

   If it finds a packet, then, if "wth->capture.ascend" is non-null,
   it sets "wth->capture.ascend->next_packet_seek_start" to the point
   at which the seek pointer should be set before this routine is called
   to find the packet *after* the packet it finds. */
/* XXX - Handle I/O errors. */
static int ascend_seek(wtap *wth, int max_seek)
{
  int byte, bytes_read = 0, date_off = -1, cur_off, packet_off;
  unsigned int r_level = 0, x_level = 0, w1_level = 0, w2_level = 0;

  while (((byte = file_getc(wth->fh)) != EOF) && bytes_read < max_seek) {
    if (byte == ascend_xmagic[x_level]) {
      x_level++;
      if (x_level >= ASCEND_X_SIZE) {
        /* At what offset are we now? */
        cur_off = file_tell(wth->fh);

        /* Back up over the header we just read; that's where a read
           of this packet should start. */
        packet_off = cur_off - ASCEND_X_SIZE;
        goto found;
      }
    } else {
      x_level = 0;
    }
    if (byte == ascend_rmagic[r_level]) {
      r_level++;
      if (r_level >= ASCEND_R_SIZE) {
        /* At what offset are we now? */
        cur_off = file_tell(wth->fh);

        /* Back up over the header we just read; that's where a read
           of this packet should start. */
        packet_off = cur_off - ASCEND_R_SIZE;
        goto found;
      }
    } else {
      r_level = 0;
    }
    if (byte == ascend_w1magic[w1_level]) {
      w1_level++;
      if (w1_level >= ASCEND_W1_SIZE) {
        /* Get the offset at which the "Date:" header started. */
        date_off = file_tell(wth->fh) - ASCEND_W1_SIZE;
      }
    } else {
      w1_level = 0;
    }
    if (byte == ascend_w2magic[w2_level]) {
      w2_level++;
      if (w2_level >= ASCEND_W2_SIZE) {
        /* At what offset are we now? */
        cur_off = file_tell(wth->fh);
        if (date_off != -1) {
          /* This packet has a date/time header; a read of it should
             start at the beginning of *that* header. */
          packet_off = date_off;
        } else {
          /* This packet has only a per-packet header.
             Back up over that header, which we just read; that's where
             a read of this packet should start. */
          packet_off = cur_off - ASCEND_W2_SIZE;
        }
        goto found;
      }
    } else {
      w2_level = 0;
    }
    bytes_read++;
  }
  return -1;

found:
  /*
   * The search for the packet after this one should start right
   * after the header for this packet.  (Ideally, it should
   * start after the *data* for this one, but we haven't
   * read that yet.)
   */
  if (wth->capture.ascend != NULL)
    wth->capture.ascend->next_packet_seek_start = cur_off + 1;

  /*
   * Move to where the read for this packet should start, and return
   * that seek offset.
   */
  file_seek(wth->fh, packet_off, SEEK_SET);
  return packet_off;
}

/* XXX - return -1 on I/O error and actually do something with 'err'. */
int ascend_open(wtap *wth, int *err)
{
  int offset;
  struct stat statbuf;

  /* We haven't yet allocated a data structure for our private stuff;
     set the pointer to null, so that "ascend_seek()" knows not to
     fill it in. */
  wth->capture.ascend = NULL;

  offset = ascend_seek(wth, ASCEND_MAX_SEEK);
  if (offset == -1) {
    return 0;
  }

  wth->data_offset = offset;
  wth->file_encap = WTAP_ENCAP_ASCEND;
  wth->file_type = WTAP_FILE_ASCEND;
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
  fstat(wtap_fd(wth), &statbuf);
  wth->capture.ascend->inittime = statbuf.st_ctime;
  wth->capture.ascend->adjusted = 0;

  init_parse_ascend();

  return 1;
}

/* Read the next packet; called from wtap_loop(). */
static gboolean ascend_read(wtap *wth, int *err, int *data_offset)
{
  int offset;
  guint8 *buf = buffer_start_ptr(wth->frame_buffer);
  ascend_pkthdr header;

  /* (f)lex reads large chunks of the file into memory, so file_tell() doesn't
     give us the correct location of the packet.  Instead, we seek to the 
     offset after the header of the previous packet and try to find the next
     packet.  */
  file_seek(wth->fh, wth->capture.ascend->next_packet_seek_start, SEEK_SET);
  offset = ascend_seek(wth, ASCEND_MAX_SEEK);
  if (offset == -1) {
    *err = 0;		/* XXX - assume, for now, that it's an EOF */
    return FALSE;
  }
  if (! parse_ascend(wth->fh, buf, &wth->pseudo_header.ascend, &header, 0)) {
    *err = WTAP_ERR_BAD_RECORD;
    return FALSE;
  }

  buffer_assure_space(wth->frame_buffer, wth->snapshot_length);

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
  wth->phdr.ts.tv_sec = header.secs + wth->capture.ascend->inittime;
  wth->phdr.ts.tv_usec = header.usecs;
  wth->phdr.caplen = header.caplen;
  wth->phdr.len = header.len;
  wth->phdr.pkt_encap = wth->file_encap;
  wth->data_offset = offset;

  *data_offset = offset;
  return TRUE;
}

static int ascend_seek_read (wtap *wth, int seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len)
{
  file_seek(wth->random_fh, seek_off, SEEK_SET);
  return parse_ascend(wth->random_fh, pd, &pseudo_header->ascend, NULL, len);
}

static void ascend_close(wtap *wth)
{
  g_free(wth->capture.ascend);
}
