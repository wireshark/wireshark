/* nettl.h
 *
 * $Id: nettl.h,v 1.4 2000/02/17 21:08:15 oabad Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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

#define NETTL_SUBSYS_NS_LS_LOGGING	0x00
#define NETTL_SUBSYS_NS_LS_NFT		0x01
#define NETTL_SUBSYS_NS_LS_LOOPBACK	0x02
#define NETTL_SUBSYS_NS_LS_NI		0x03
#define NETTL_SUBSYS_NS_LS_IPC		0x04
#define NETTL_SUBSYS_NS_LS_SOCKREGD	0x05
#define NETTL_SUBSYS_NS_LS_TCP		0x06
#define NETTL_SUBSYS_NS_LS_PXP		0x07
#define NETTL_SUBSYS_NS_LS_UDP		0x08
#define NETTL_SUBSYS_NS_LS_IP		0x09
#define NETTL_SUBSYS_NS_LS_PROBE	0x0A
#define NETTL_SUBSYS_NS_LS_DRIVER	0x0B
#define NETTL_SUBSYS_NS_LS_RLBD		0x0C
#define NETTL_SUBSYS_NS_LS_BUFS		0x0D
#define NETTL_SUBSYS_NS_LS_CASE21	0x0E
#define NETTL_SUBSYS_NS_LS_ROUTER21	0x0F
#define NETTL_SUBSYS_NS_LS_NFS		0x10
#define NETTL_SUBSYS_NS_LS_NETISR	0x11
#define NETTL_SUBSYS_NS_LS_NSE		0x13
#define NETTL_SUBSYS_NS_LS_STRLOG	0x14
#define NETTL_SUBSYS_NS_LS_TIRDWR	0x15
#define NETTL_SUBSYS_NS_LS_TIMOD	0x16
#define NETTL_SUBSYS_NS_LS_ICMP		0x17
#define NETTL_SUBSYS_FILTER		0x1A
#define NETTL_SUBSYS_NAME		0x1B
#define NETTL_SUBSYS_IGMP		0x1D
#define NETTL_SUBSYS_SX25L2		0x22
#define NETTL_SUBSYS_SX25L3		0x23
#define NETTL_SUBSYS_FTAM_INIT		0x40
#define NETTL_SUBSYS_FTAM_RESP		0x41
#define NETTL_SUBSYS_FTAM_VFS		0x46
#define NETTL_SUBSYS_FTAM_USER		0x48
#define NETTL_SUBSYS_OTS		0x5A
#define NETTL_SUBSYS_NETWORK		0x5B
#define NETTL_SUBSYS_TRANSPORT		0x5C
#define NETTL_SUBSYS_SESSION		0x5D
#define NETTL_SUBSYS_ACSE_PRES		0x5E
#define NETTL_SUBSYS_SHM		0x74
#define NETTL_SUBSYS_ACSE_US		0x77
#define NETTL_SUBSYS_HPS		0x79
#define NETTL_SUBSYS_CM			0x7A
#define NETTL_SUBSYS_ULA_UTILS		0x7B
#define NETTL_SUBSYS_EM			0x7C

int nettl_open(wtap *wth, int *err);
