/* ascend.c
 *
 * $Id: ascend.c,v 1.9 1999/10/28 01:42:43 gerald Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@verdict.uthscsa.edu>
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
#include "wtap.h"
#include "buffer.h"
#include "ascend.h"
#include "ascend-int.h"
#include "file.h"

#include <sys/stat.h>
#include <unistd.h>
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

static int ascend_read(wtap *wth, int *err);

/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure.  A valid offset is 0; since
   that causes problems with wtap_loop, offsets are incremented by one. */
/* XXX - Handle I/O errors. */
static int ascend_seek(wtap *wth, int max_seek)
{
  int byte, bytes_read = 0, date_off = 0;
  int x_level = 0, r_level = 0, w1_level = 0, w2_level = 0;

  while (((byte = file_getc(wth->fh)) != EOF) && bytes_read < max_seek) {
    if (byte == ascend_xmagic[x_level]) {
      x_level++;
      if (x_level >= ASCEND_X_SIZE) {
        file_seek(wth->fh, -(ASCEND_X_SIZE), SEEK_CUR);
        return file_tell(wth->fh) + 1;
      }
    } else {
      x_level = 0;
    }
    if (byte == ascend_rmagic[r_level]) {
      r_level++;
      if (r_level >= ASCEND_R_SIZE) {
        file_seek(wth->fh, -(ASCEND_R_SIZE), SEEK_CUR);
        return file_tell(wth->fh) + 1;
      }
    } else {
      r_level = 0;
    }
    if (byte == ascend_w1magic[w1_level]) {
      w1_level++;
      if (w1_level >= ASCEND_W1_SIZE) {
        date_off = file_tell(wth->fh) - ASCEND_W1_SIZE + 1;
      }
    } else {
      w1_level = 0;
    }
    if (byte == ascend_w2magic[w2_level]) {
      w2_level++;
      if (w2_level >= ASCEND_W2_SIZE && date_off) {
        file_seek(wth->fh, date_off - 1, SEEK_SET);
        return date_off;
      }
    } else {
      w2_level = 0;
    }
    bytes_read++;
  }
  return -1;
}

/* XXX - return -1 on I/O error and actually do something with 'err'. */
int ascend_open(wtap *wth, int *err)
{
  int offset;

  file_seek(wth->fh, 0, SEEK_SET);
  offset = ascend_seek(wth, ASCEND_MAX_SEEK);
  if (offset < 1) {
    return 0;
  }

  wth->data_offset = offset;
  wth->file_encap = WTAP_ENCAP_ASCEND;
  wth->file_type = WTAP_FILE_ASCEND;
  wth->snapshot_length = ASCEND_MAX_PKT_LEN;
  wth->subtype_read = ascend_read;
  wth->capture.ascend = g_malloc(sizeof(ascend_t));

  /* MAXen and Pipelines report the time since reboot.  In order to keep 
     from reporting packet times near the epoch, we subtract the first
     packet's timestamp from the capture file's ctime, which gives us an
     offset that we can apply to each packet.

     NOTE: Since we can't fstat a compressed file, assume that the first
     packet time is 0 and other packets are relative to this.
   */
  wth->capture.ascend->inittime = 0;
  wth->capture.ascend->adjusted = 0;
  wth->capture.ascend->seek_add = -1;

  init_parse_ascend();

  return 1;
}

/* Read the next packet; called from wtap_loop(). */
static int ascend_read(wtap *wth, int *err)
{
  int offset;
  guint8 *buf = buffer_start_ptr(wth->frame_buffer);
  ascend_pkthdr header;

  /* (f)lex reads large chunks of the file into memory, so file_tell() doesn't
     give us the correct location of the packet.  Instead, we seek to the 
     location of the last packet and try to find the next packet.  In
     addition, we fool around with the seek offset in case a valid packet
     starts at the beginning of the file.  */  
  file_seek(wth->fh, wth->data_offset + wth->capture.ascend->seek_add, SEEK_SET);
  wth->capture.ascend->seek_add = 0;
  offset = ascend_seek(wth, ASCEND_MAX_SEEK);
  if (offset < 1) {
    return 0;
  }
  if (! parse_ascend(wth->fh, buf, &wth->phdr.pseudo_header.ascend, &header, 0)) {
    *err = WTAP_ERR_BAD_RECORD;
    return -1;
  }

  buffer_assure_space(wth->frame_buffer, wth->snapshot_length);

  if (! wth->capture.ascend->adjusted) {
    wth->capture.ascend->adjusted = 1;
    wth->capture.ascend->inittime = -header.secs;
  }
  wth->phdr.ts.tv_sec = header.secs + wth->capture.ascend->inittime;
  wth->phdr.ts.tv_usec = header.usecs;
  wth->phdr.caplen = header.caplen;
  wth->phdr.len = header.len;
  wth->phdr.pkt_encap = wth->file_encap;
  wth->data_offset = offset;

  return offset;
}

int ascend_seek_read (FILE *fh, int seek_off, guint8 *pd, int len)
{
  file_seek(fh, seek_off - 1, SEEK_SET);
  return parse_ascend(fh, pd, NULL, NULL, len);
}
