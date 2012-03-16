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

#endif
