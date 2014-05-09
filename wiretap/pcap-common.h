/* pcap-common.h
 * Declarations for code common to libpcap and pcap-NG file formats
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for pcap-ng file format
 * Copyright (c) 2007 by Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __W_PCAP_COMMON_H__
#define __W_PCAP_COMMON_H__

#include <glib.h>
#include <wtap.h>
#include "ws_symbol_export.h"

extern int pcap_process_pseudo_header(FILE_T fh, int file_type, int wtap_encap,
    guint packet_size, gboolean check_packet_size,
    struct wtap_pkthdr *phdr, int *err, gchar **err_info);

extern void pcap_read_post_process(int file_type, int wtap_encap,
    struct wtap_pkthdr *phdr, guint8 *pd, gboolean bytes_swapped, int fcs_len);

extern int pcap_get_phdr_size(int encap,
    const union wtap_pseudo_header *pseudo_header);

extern gboolean pcap_write_phdr(wtap_dumper *wdh, int wtap_encap,
    const union wtap_pseudo_header *pseudo_header, int *err);

#endif
