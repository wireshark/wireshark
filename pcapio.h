/* pcapio.h
 * Declarations of our own routins for writing libpcap files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Derived from code in the Wiretap Library
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

/* Writing pcap files */

/** Write the file header to a dump file.
   Returns TRUE on success, FALSE on failure.
   Sets "*err" to an error code, or 0 for a short write, on failure*/
extern gboolean
libpcap_write_file_header(FILE* pfile, int linktype, int snaplen,
                          gboolean ts_nsecs, guint64 *bytes_written, int *err);

/** Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
extern gboolean
libpcap_write_packet(FILE* pfile,
                     time_t sec, guint32 usec,
                     guint32 caplen, guint32 len,
                     const guint8 *pd,
                     guint64 *bytes_written, int *err);

/* Writing pcap-ng files */

/** Write a section header block (SHB)
 *
 */
extern gboolean
pcapng_write_session_header_block(FILE* pfile,  /**< Write information */
                                  const char *comment,  /**< Comment on the section, Optinon 1 opt_comment
                                                         * A UTF-8 string containing a comment that is associated to the current block.
                                                         */
                                  const char *hw,       /**< HW, Optinon 2 shb_hardware
                                                         * An UTF-8 string containing the description of the hardware  used to create this section.
                                                         */
                                  const char *os,       /**< Operating system name, Optinon 3 shb_os
                                                         * An UTF-8 string containing the name of the operating system used to create this section.
                                                         */
                                  const char *appname,  /**< Application name, Optinon 4 shb_userappl
                                                         * An UTF-8 string containing the name of the application  used to create this section.
                                                         */
                                  guint64 section_length, /**< Length of section */
                                  guint64 *bytes_written, /**< Number of written bytes */
                                  int *err /**< Error type */
                                  );

extern gboolean
pcapng_write_interface_description_block(FILE* pfile,
                                         const char *comment,  /* OPT_COMMENT           1 */
                                         const char *name,     /* IDB_NAME              2 */
                                         const char *descr,    /* IDB_DESCRIPTION       3 */
                                         const char *filter,   /* IDB_FILTER           11 */
                                         const char *os,       /* IDB_OS               12 */
                                         int link_type,
                                         int snap_len,
                                         guint64 *bytes_written,
                                         guint64 if_speed,     /* IDB_IF_SPEED          8 */
                                         guint8 tsresol,       /* IDB_TSRESOL           9 */
                                         int *err);

extern gboolean
pcapng_write_interface_statistics_block(FILE* pfile,
                                        guint32 interface_id,
                                        guint64 *bytes_written,
                                        const char *comment,   /* OPT_COMMENT           1 */
                                        guint64 isb_starttime, /* ISB_STARTTIME         2 */
                                        guint64 isb_endtime,   /* ISB_ENDTIME           3 */
                                        guint64 isb_ifrecv,    /* ISB_IFRECV            4 */
                                        guint64 isb_ifdrop,    /* ISB_IFDROP            5 */
                                        int *err);

extern gboolean
pcapng_write_enhanced_packet_block(FILE* pfile,
                                   const char *comment,
                                   time_t sec, guint32 usec,
                                   guint32 caplen, guint32 len,
                                   guint32 interface_id,
                                   guint ts_mul,
                                   const guint8 *pd,
                                   guint32 flags,
                                   guint64 *bytes_written,
                                   int *err);
