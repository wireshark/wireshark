/* wtap_capture.h
 *
 * $Id: wtap-capture.h,v 1.2 2002/07/29 06:09:59 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __WTAP_CAPTURE_H__
#define __WTAP_CAPTURE_H__

/* XXX - needed until "wiretap" can do live packet captures */
int wtap_pcap_encap_to_wtap_encap(int encap);
const guchar *wtap_process_pcap_packet(gint linktype,
    const struct pcap_pkthdr *phdr, const guchar *pd,
    union wtap_pseudo_header *pseudo_header, struct wtap_pkthdr *whdr,
    int *err);

#endif /* __WTAP_CAPTURE_H__ */
