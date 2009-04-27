/* pcap-common.h
 * Declarations for code common to libpcap and pcap-NG file formats
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

struct encap_map {
	int	dlt_value;
	int	wtap_encap_value;
};

extern const struct encap_map pcap_to_wtap_map[];

extern int wtap_wtap_encap_to_pcap_encap(int encap);

extern int pcap_process_pseudo_header(wtap *wth, FILE_T fh, guint packet_size,
    struct wtap_pkthdr *phdr, union wtap_pseudo_header *pseudo_header,
    int *err, gchar **err_info);

extern int pcap_get_phdr_size(int encap,
    const union wtap_pseudo_header *pseudo_header);

extern gboolean pcap_write_phdr(wtap_dumper *wdh,
    const union wtap_pseudo_header *pseudo_header, int *err);
