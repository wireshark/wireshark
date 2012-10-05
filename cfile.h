/* cfile.h
 * capture_file definition & GUI-independent manipulation
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef __CFILE_H__
#define __CFILE_H__

#include <epan/dfilter/dfilter.h>
#include <epan/frame_data.h>
#include "frame_data_sequence.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Current state of file. */
typedef enum {
  FILE_CLOSED,	                /* No file open */
  FILE_READ_IN_PROGRESS,        /* Reading a file we've opened */
  FILE_READ_ABORTED,            /* Read aborted by user */
  FILE_READ_DONE                /* Read completed */
} file_state;

/* Character set for text search. */
typedef enum {
  SCS_ASCII_AND_UNICODE,
  SCS_ASCII,
  SCS_UNICODE
  /* add EBCDIC when it's implemented */
} search_charset_t;

typedef enum {
  SD_FORWARD,
  SD_BACKWARD
} search_direction;

/*
 * We store the frame_data structures in a radix tree, with 1024
 * elements per level.  The leaf nodes are arrays of 1024 frame_data
 * structures; the nodes above them are arrays of 1024 pointers to
 * the nodes below them.  The capture_file structure has a pointer
 * to the root node.
 *
 * As frame numbers are 32 bits, and as 1024 is 2^10, that gives us
 * up to 4 levels of tree.
 */
#define LOG2_NODES_PER_LEVEL	10
#define NODES_PER_LEVEL		(1<<LOG2_NODES_PER_LEVEL)

typedef struct _capture_file {
  file_state   state;           /* Current state of capture file */
  gchar       *filename;        /* Name of capture file */
  gchar       *source;          /* Temp file source, e.g. "Pipe from elsewhere" */
  gboolean     is_tempfile;     /* Is capture file a temporary file? */
  gboolean     unsaved_changes; /* Does the capture file have changes that have not been saved? */
  gint64       f_datalen;       /* Size of capture file data (uncompressed) */
  guint16      cd_t;            /* File type of capture file */
  gboolean     iscompressed;    /* TRUE if the file is compressed */
  int          lnk_t;           /* File link-layer type; could be WTAP_ENCAP_PER_PACKET */
  GArray      *linktypes;       /* Array of packet link-layer types */
  guint32      count;           /* Total number of frames */
  guint64      packet_comment_count; /* Number of comments in frames (could be >1 per frame... */
  guint32      displayed_count; /* Number of displayed frames */
  guint32      marked_count;    /* Number of marked frames */
  guint32      ignored_count;   /* Number of ignored frames */
  guint32      ref_time_count;  /* Number of time referenced frames */
  gboolean     drops_known;     /* TRUE if we know how many packets were dropped */
  guint32      drops;           /* Dropped packets */
  nstime_t     elapsed_time;    /* Elapsed time */
  gboolean     has_snap;        /* TRUE if maximum capture packet length is known */
  int          snap;            /* Maximum captured packet length */
  wtap        *wth;             /* Wiretap session */
  dfilter_t   *rfcode;          /* Compiled read (display) filter program */
  gchar       *dfilter;         /* Display filter string */
  gboolean     redissecting;    /* TRUE if currently redissecting (cf_redissect_packets) */
  /* search */
  gchar       *sfilter;         /* Filter, hex value, or string being searched */
  gboolean     hex;             /* TRUE if "Hex value" search was last selected */
  gboolean     string;          /* TRUE if "String" search was last selected */
  gboolean     summary_data;    /* TRUE if "String" search in "Packet list" (Info column) was last selected */
  gboolean     decode_data;     /* TRUE if "String" search in "Packet details" was last selected */
  gboolean     packet_data;     /* TRUE if "String" search in "Packet data" was last selected */
  guint32      search_pos;      /* Byte position of last byte found in a hex search */
  gboolean     case_type;       /* TRUE if case-insensitive text search */
  search_charset_t scs_type;    /* Character set for text search */
  search_direction dir;         /* Direction in which to do searches */
  gboolean     search_in_progress; /* TRUE if user just clicked OK in the Find dialog or hit <control>N/B */
  /* packet data */
  union wtap_pseudo_header pseudo_header; /* Packet pseudo_header */
  guint8       pd[WTAP_MAX_PACKET_SIZE];  /* Packet data */
  /* frames */
  frame_data_sequence *frames;  /* Sequence of frames, if we're keeping that information */
  guint32      first_displayed; /* Frame number of first frame displayed */
  guint32      last_displayed;  /* Frame number of last frame displayed */
  column_info  cinfo;           /* Column formatting information */
  gboolean     columns_changed; /**< Have the columns been changed in the prefs? */
  frame_data  *current_frame;   /* Frame data for current frame */
  gint         current_row;     /* Row number for current frame */
  epan_dissect_t *edt;          /* Protocol dissection for currently selected packet */
  field_info  *finfo_selected;	/* Field info for currently selected field */
#ifdef WANT_PACKET_EDITOR
  GTree       *edited_frames;   /* BST with modified frames */
#endif
  gpointer     window;		/* Top-level window associated with file */
} capture_file;

extern void cap_file_init(capture_file *cf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* cfile.h */
