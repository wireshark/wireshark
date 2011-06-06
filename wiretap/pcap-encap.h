/* pcap-encap.h
 * Declarations for routines to handle libpcap/pcap-NG linktype values
 *
 * $Id: pcap-common.h 28863 2009-06-27 16:08:18Z tuexen $
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

#ifndef __W_PCAP_ENCAP_H__
#define __W_PCAP_ENCAP_H__

#include <glib.h>
#include <wiretap/wtap.h>

extern int wtap_pcap_encap_to_wtap_encap(int encap);
extern int wtap_wtap_encap_to_pcap_encap(int encap);

#endif
