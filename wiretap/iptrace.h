/* iptrace.h
 *
 * $Id: iptrace.h,v 1.1 1999/01/03 04:30:13 gram Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@verdict.uthscsa.edu>
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
 *
 */
 
/* the iptrace 2.0 packet header, as guessed */
#if 0
struct iptrace_pkt_hdr {
	guint16		unknown;
	guint16		pkt_length; /* packet length + 32 */
	guint32		tv_sec;
	char		if_name[4]; /* not null-terminated */
	guint16		if_num;
	char		if_desc[12]; /* interface description. why? */
	guint32		tv_sec;
	guint32		tv_usec;
};
#endif


int iptrace_open(wtap *wth);
int iptrace_read(wtap *wth);
