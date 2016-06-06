/* summary.h
 * Definitions for capture file summary data
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

#ifndef __SUMMARY_H__
#define __SUMMARY_H__

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct iface_options_tag {
  char     *name;
  char     *descr;
  char     *cfilter;
  char     *isb_comment;
  guint64   drops;                 /**< number of packet drops */
  gboolean  drops_known;           /**< TRUE if number of packet drops is known */
  gboolean  has_snap;              /**< TRUE if maximum capture packet length is known */
  int       snap;                  /**< Maximum captured packet length */
  int       encap_type;            /**< wiretap encapsulation type */
} iface_options;

typedef struct _summary_tally {
  guint64      bytes;              /**< total bytes */
  double       start_time;         /**< seconds, with msec resolution */
  double       stop_time;          /**< seconds, with msec resolution */
  double       elapsed_time;       /**< seconds, with msec resolution,
                                     includes time before first packet
                                     and after last packet */
  guint32      marked_count;       /**< number of marked packets */
  guint32      marked_count_ts;    /**< number of time-stamped marked packets */
  guint64      marked_bytes;       /**< total bytes in the marked packets */
  double       marked_start;       /**< time in seconds, with msec resolution */
  double       marked_stop;        /**< time in seconds, with msec resolution */
  guint32      ignored_count;      /**< number of ignored packets */
  guint32      packet_count;       /**< total number of packets in trace */
  guint32      packet_count_ts;    /**< total number of time-stamped packets in trace */
  guint32      filtered_count;     /**< number of filtered packets */
  guint32      filtered_count_ts;  /**< number of time-stamped filtered packets */
  guint64      filtered_bytes;     /**< total bytes in the filtered packets */
  double       filtered_start;     /**< time in seconds, with msec resolution */
  double       filtered_stop;      /**< time in seconds, with msec resolution */
  const char  *filename;
  gint64       file_length;        /**< file length in bytes */
  int          file_type;          /**< wiretap file type */
  int          iscompressed;       /**< TRUE if file is compressed */
  int          file_encap_type;    /**< wiretap encapsulation type for file */
  GArray      *packet_encap_types; /**< wiretap encapsulation types for packets */
  gboolean     has_snap;           /**< TRUE if maximum capture packet length is known */
  int          snap;               /**< Maximum captured packet length */
  gboolean     drops_known;        /**< TRUE if number of packet drops is known */
  guint64      drops;              /**< number of packet drops */
  const char  *dfilter;            /**< display filter */
  gboolean     is_tempfile;
  /* capture related, use summary_fill_in_capture() to get values */
  GArray      *ifaces;
  gboolean     legacy;
} summary_tally;

extern void
summary_fill_in(capture_file *cf, summary_tally *st);

#ifdef HAVE_LIBPCAP
extern void
summary_fill_in_capture(capture_file *cf, capture_options *capture_opts, summary_tally *st);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* summary.h */

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
