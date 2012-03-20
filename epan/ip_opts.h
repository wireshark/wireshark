/* ip_opts.h
 * Definitions of structures and routines for dissection of options that
 * work like IPv4 options
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __IP_OPTS_H__
#define __IP_OPTS_H__

/** @file
 */

typedef enum {
  NO_LENGTH,                        /**< option has no data, hence no length */
  FIXED_LENGTH,                     /**< option always has the same length */
  VARIABLE_LENGTH                   /**< option is variable-length - optlen is minimum */
} opt_len_type;

/** Member of table of IP or TCP options. */
typedef struct ip_tcp_opt {
  int   optcode;                    /**< code for option */
  const char  *name;                /**< name of option */
  int   *subtree_index;             /**< pointer to subtree index for option */
  opt_len_type len_type;            /**< type of option length field */
  int   optlen;                     /**< value length should be (minimum if VARIABLE) */
  void  (*dissect)(const struct ip_tcp_opt *,
                   tvbuff_t *,
                   int,
                   guint,
                   packet_info *,
                   proto_tree *);   /**< routine to dissect option */
} ip_tcp_opt;

/** Routine to dissect options that work like IPv4 options, where the
   length field in the option, if present, includes the type and
   length bytes. */
extern void dissect_ip_tcp_options(tvbuff_t *, int, guint,
                                   const ip_tcp_opt *, int, int,
                                   packet_info *, proto_tree *, proto_item *);

/* Quick-Start option, as defined by RFC4782 */
#define QS_FUNC_MASK        0xf0
#define QS_RATE_MASK        0x0f
#define QS_RATE_REQUEST     0
#define QS_RATE_REPORT      8

static const value_string qs_func_vals[] = {
  {QS_RATE_REQUEST, "Rate request"},
  {QS_RATE_REPORT,  "Rate report"},
  {0,               NULL}
};

static const value_string qs_rate_vals[] = {
  { 0, "0 bit/s"},
  { 1, "80 Kbit/s"},
  { 2, "160 Kbit/s"},
  { 3, "320 Kbit/s"},
  { 4, "640 Kbit/s"},
  { 5, "1.28 Mbit/s"},
  { 6, "2.56 Mbit/s"},
  { 7, "5.12 Mbit/s"},
  { 8, "10.24 Mbit/s"},
  { 9, "20.48 Mbit/s"},
  {10, "40.96 Mbit/s"},
  {11, "81.92 Mbit/s"},
  {12, "163.84 Mbit/s"},
  {13, "327.68 Mbit/s"},
  {14, "655.36 Mbit/s"},
  {15, "1.31072 Gbit/s"},
  {0, NULL}
};


#endif
