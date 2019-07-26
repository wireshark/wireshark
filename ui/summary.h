/* summary.h
 * Definitions for capture file summary data
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SUMMARY_H__
#define __SUMMARY_H__

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct iface_summary_info_tag {
  char     *name;
  char     *descr;
  char     *cfilter;
  char     *isb_comment;
  guint64   drops;                 /**< number of packet drops */
  gboolean  drops_known;           /**< TRUE if number of packet drops is known */
  int       snap;                  /**< Maximum captured packet length; 0 if not known */
  int       encap_type;            /**< wiretap encapsulation type */
} iface_summary_info;

#define HASH_STR_SIZE (65) /* Max hash size * 2 + '\0' */

typedef struct _summary_tally {
  guint64               bytes;              /**< total bytes */
  double                start_time;         /**< seconds, with msec resolution */
  double                stop_time;          /**< seconds, with msec resolution */
  double                elapsed_time;       /**< seconds, with msec resolution,
                                              includes time before first packet
                                              and after last packet */
  guint32               marked_count;       /**< number of marked packets */
  guint32               marked_count_ts;    /**< number of time-stamped marked packets */
  guint64               marked_bytes;       /**< total bytes in the marked packets */
  double                marked_start;       /**< time in seconds, with msec resolution */
  double                marked_stop;        /**< time in seconds, with msec resolution */
  guint32               ignored_count;      /**< number of ignored packets */
  guint32               packet_count;       /**< total number of packets in trace */
  guint32               packet_count_ts;    /**< total number of time-stamped packets in trace */
  guint32               filtered_count;     /**< number of filtered packets */
  guint32               filtered_count_ts;  /**< number of time-stamped filtered packets */
  guint64               filtered_bytes;     /**< total bytes in the filtered packets */
  double                filtered_start;     /**< time in seconds, with msec resolution */
  double                filtered_stop;      /**< time in seconds, with msec resolution */
  const char           *filename;           /**< path of capture file */
  gint64                file_length;        /**< file length in bytes */
  gchar                 file_sha256[HASH_STR_SIZE];  /**< SHA256 hash of capture file */
  gchar                 file_rmd160[HASH_STR_SIZE];  /**< RIPEMD160 hash of capture file */
  gchar                 file_sha1[HASH_STR_SIZE];    /**< SHA1 hash of capture file */
  int                   file_type;          /**< wiretap file type */
  wtap_compression_type compression_type;   /**< compression type of file, or uncompressed */
  int                   file_encap_type;    /**< wiretap encapsulation type for file */
  GArray               *packet_encap_types; /**< wiretap encapsulation types for packets */
  int                   snap;               /**< Maximum captured packet length; 0 if not known */
  gboolean              drops_known;        /**< TRUE if number of packet drops is known */
  guint64               drops;              /**< number of packet drops */
  const char           *dfilter;            /**< display filter */
  gboolean              is_tempfile;
  /* capture related, use summary_fill_in_capture() to get values */
  GArray               *ifaces;
  gboolean              legacy;
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
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
