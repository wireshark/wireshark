/* file.h
 * Definitions for file structures and routines
 *
 * $Id: file.h,v 1.11 1999/03/23 03:14:34 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __FILE_H__
#define __FILE_H__

#include <sys/types.h>
#include <sys/time.h>

#ifdef WITH_WIRETAP
 #include <wtap.h>
 #include <pcap.h>
#else
 #include <pcap.h>

  /* Data file formats */
  #define CD_UNKNOWN    0
  #define CD_WIRE       1
  #define CD_SNOOP      2
  #define CD_PCAP_BE    3
  #define CD_PCAP_LE    4
  #define CD_NA_UNCOMPR 5

  /* Data file magic info */
  #define SNOOP_MAGIC_1 0x736e6f6f /* 'snoop' in ASCII */
  #define SNOOP_MAGIC_2 0x70000000
  #define PCAP_MAGIC    0xa1b2c3d4

  /* Data file format versions we can handle */
  #define SNOOP_MIN_VERSION 2
  #define SNOOP_MAX_VERSION 2

  /* Link types (removed in favor of the DLT_* defines from bpf.h */
#endif

typedef struct bpf_program bpf_prog;

typedef struct _capture_file {
  FILE       *fh;        /* Capture file */
  gchar      *filename;  /* filename */
  long        f_len;     /* File length */
  int         swap;      /* Swap data bytes? */
  guint16     cd_t;      /* Capture data type */
  guint32     vers;      /* Version.  For tcpdump minor is appended to major */
#ifndef WITH_WIRETAP
  guint32     lnk_t;     /* Network link type */
#endif
  guint32     count;     /* Packet count */
  guint32     drops;     /* Dropped packets */
  guint32     esec;      /* Elapsed seconds */
  guint32     eusec;     /* Elapsed microseconds */
  guint32     snap;      /* Captured packet length */
  gchar      *iface;     /* Interface */
  gchar      *save_file; /* File to write capture data */
#ifdef WITH_WIRETAP
  wtap     *wth;         /* Wiretap session */
#else
  pcap_t     *pfh;       /* Pcap session */
#endif
  gchar      *dfilter;   /* Display filter string */
  gchar      *cfilter;   /* Capture filter string */
  bpf_prog    fcode;     /* Compiled filter program */
  /* XXX - I'm cheating for now. I'll hardcode 65536 here until I re-arrange
   * more header files so that ethereal.h is split up into two files, a
   * generic header and a gtk+-speficic header (or the gtk+ definitions are
   * moved to different header files) --gilbert
   */
  /*guint8      pd[MAX_PACKET_SIZE];*/  /* Packet data */
  guint8      pd[65536];  /* Packet data */
  GList      *plist;     /* Packet list */
  frame_data *cur;       /* Current list item */
  column_info  cinfo;    /* Column formatting information */
} capture_file;

/* Taken from RFC 1761 */

#ifndef WITH_WIRETAP
typedef struct _snoop_file_hdr {
  guint32 magic1;
  guint32 magic2;
  guint32 vers;
  guint32 s_lnk_t;
} snoop_file_hdr;

typedef struct _snoop_frame_hdr {
  guint32 orig_len;
  guint32 inc_len;
  guint32 pr_len;
  guint32 drops;
  guint32 secs;
  guint32 usecs;
} snoop_frame_hdr;
#endif

int  open_cap_file(char *, capture_file *);
void close_cap_file(capture_file *, void *, guint);
int  load_cap_file(char *, capture_file *);
/* size_t read_frame_header(capture_file *); */

#endif /* file.h */
