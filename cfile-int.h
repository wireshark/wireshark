/* cfile-int.h
 * Definition of capture_file structure.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __CFILE_INT_H__
#define __CFILE_INT_H__

#include <epan/epan.h>
#include <epan/column-info.h>
#include <epan/dfilter/dfilter.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/frame_set.h>
#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _capture_file {
  epan_t      *epan;
  file_state   state;                /* Current state of capture file */
  gchar       *filename;             /* Name of capture file */
  gchar       *source;               /* Temp file source, e.g. "Pipe from elsewhere" */
  gboolean     is_tempfile;          /* Is capture file a temporary file? */
  gboolean     unsaved_changes;      /* Does the capture file have changes that have not been saved? */
  gboolean     stop_flag;            /* Stop current processing (loading, searching, etc.) */

  gint64       f_datalen;            /* Size of capture file data (uncompressed) */
  guint16      cd_t;                 /* File type of capture file */
  unsigned int open_type;            /* open_routine index+1 used, if selected, or WTAP_TYPE_AUTO */
  gboolean     iscompressed;         /* TRUE if the file is compressed */
  int          lnk_t;                /* File link-layer type; could be WTAP_ENCAP_PER_PACKET */
  GArray      *linktypes;            /* Array of packet link-layer types */
  guint32      count;                /* Total number of frames */
  guint64      packet_comment_count; /* Number of comments in frames (could be >1 per frame... */
  guint32      displayed_count;      /* Number of displayed frames */
  guint32      marked_count;         /* Number of marked frames */
  guint32      ignored_count;        /* Number of ignored frames */
  guint32      ref_time_count;       /* Number of time referenced frames */
  gboolean     drops_known;          /* TRUE if we know how many packets were dropped */
  guint32      drops;                /* Dropped packets */
  nstime_t     elapsed_time;         /* Elapsed time */
  int          snap;                 /* Maximum captured packet length; 0 if unknown */
  dfilter_t   *rfcode;               /* Compiled read filter program */
  dfilter_t   *dfcode;               /* Compiled display filter program */
  gchar       *dfilter;              /* Display filter string */
  gboolean     redissecting;         /* TRUE if currently redissecting (cf_redissect_packets) */
  /* search */
  gchar       *sfilter;              /* Filter, hex value, or string being searched */
  gboolean     hex;                  /* TRUE if "Hex value" search was last selected */
  gboolean     string;               /* TRUE if "String" search was last selected */
  gboolean     summary_data;         /* TRUE if "String" search in "Packet list" (Info column) was last selected */
  gboolean     decode_data;          /* TRUE if "String" search in "Packet details" was last selected */
  gboolean     packet_data;          /* TRUE if "String" search in "Packet data" was last selected */
  guint32      search_pos;           /* Byte position of last byte found in a hex search */
  guint32      search_len;           /* Length of bytes matching the search */
  gboolean     case_type;            /* TRUE if case-insensitive text search */
  GRegex      *regex;                /* Set if regular expression search */
  search_charset_t scs_type;         /* Character set for text search */
  search_direction dir;              /* Direction in which to do searches */
  gboolean     search_in_progress;   /* TRUE if user just clicked OK in the Find dialog or hit <control>N/B */
  /* packet data */
  struct wtap_pkthdr phdr;           /* Packet header */
  Buffer       buf;                  /* Packet data */
  /* frames */
  frame_set    frame_set_info;       /* fjfff */
  guint32      first_displayed;      /* Frame number of first frame displayed */
  guint32      last_displayed;       /* Frame number of last frame displayed */
  column_info  cinfo;                /* Column formatting information */
  gboolean     columns_changed;      /**< Have the columns been changed in the prefs? (GTK+ only) */
  frame_data  *current_frame;        /* Frame data for current frame */
  gint         current_row;          /* Row number for current frame */
  epan_dissect_t *edt;               /* Protocol dissection for currently selected packet */
  field_info  *finfo_selected;       /* Field info for currently selected field */
  gpointer     window;               /* Top-level window associated with file */
  gulong       computed_elapsed;     /* Elapsed time to load the file (in msec). */

  guint32      cum_bytes;
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* cfile-int.h */

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
