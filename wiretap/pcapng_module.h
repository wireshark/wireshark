/* pcap_module.h
 *
 * Wiretap Library
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

#ifndef __PCAP_MODULE_H__
#define __PCAP_MODULE_H__

/*
 * Reader and writer routines for pcap-ng block types.
 */
typedef gboolean (*block_reader)(FILE_T, int, gboolean, struct wtap_pkthdr *,
                                 Buffer *, int *, gchar **);
typedef gboolean (*block_writer)(wtap_dumper *, const struct wtap_pkthdr *,
                                 const guint8 *, int *);

/*
 * Register a handler for a pcap-ng block type.
 */
WS_DLL_PUBLIC
void register_pcapng_block_type_handler(guint block_type, block_reader read,
                                        block_writer write);

#endif /* __PCAP_MODULE_H__ */

