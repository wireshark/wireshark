/* netscaler.h
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 2006 by Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
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

#ifndef _NETSCALER_H
#define _NETSCALER_H

#include <glib.h>
#include <wiretap/wtap.h>

/* Physical Device full packet trace */
#define	NSPR_PDPKTRACEFULLTX_V10	0x0310	/* Transmitted */
#define	NSPR_PDPKTRACEFULLTX_V20	0xC0	/* Transmitted */
#define	NSPR_PDPKTRACEFULLTXB_V10	0x0311	/* In transmit buffer */
#define	NSPR_PDPKTRACEFULLTXB_V20	0xC1	/* In transmit buffer */
#define	NSPR_PDPKTRACEFULLRX_V10	0x0312	/* Received */
#define	NSPR_PDPKTRACEFULLRX_V20	0xC2	/* Received */

/* Physical Device partial packet trace */

#define	NSPR_PDPKTRACEPARTTX_V10	0x0314	/* Transmitted */
#define	NSPR_PDPKTRACEPARTTX_V20	0xC4	/* Transmitted */
#define	NSPR_PDPKTRACEPARTTXB_V10	0x0315	/* In transmit buffer */
#define	NSPR_PDPKTRACEPARTTXB_V20	0xC5	/* In transmit buffer */
#define	NSPR_PDPKTRACEPARTRX_V10	0x0316	/* Received */
#define	NSPR_PDPKTRACEPARTRX_V20	0xC6	/* Received */

/* pcb devno support (c.f. REQ16549) */
#define	NSPR_PDPKTRACEFULLTX_V21	0xD0	/* Transmitted */
#define	NSPR_PDPKTRACEFULLTXB_V21	0xD1	/* In transmit buffer */
#define	NSPR_PDPKTRACEFULLRX_V21	0xD2	/* Received */
#define	NSPR_PDPKTRACEPARTTX_V21	0xD4	/* Transmitted */
#define	NSPR_PDPKTRACEPARTTXB_V21	0xD5	/* In transmit buffer */
#define	NSPR_PDPKTRACEPARTRX_V21	0xD6	/* Received */

/* vlan tag support (c.f. REQ24791) */
#define	NSPR_PDPKTRACEFULLTX_V22	0xE0	/* Transmitted */
#define	NSPR_PDPKTRACEFULLTXB_V22	0xE1	/* In transmit buffer */
#define	NSPR_PDPKTRACEFULLRX_V22	0xE2	/* Received */
#define	NSPR_PDPKTRACEPARTTX_V22	0xE4	/* Transmitted */
#define	NSPR_PDPKTRACEPARTTXB_V22	0xE5	/* In transmit buffer */
#define	NSPR_PDPKTRACEPARTRX_V22	0xE6	/* Received */

/* Per core tracing */
#define	NSPR_PDPKTRACEFULLTX_V23	0xF0	/* Transmitted */
#define	NSPR_PDPKTRACEFULLTXB_V23	0xF1	/* In transmit buffer */
#define	NSPR_PDPKTRACEFULLRX_V23	0xF2	/* Received */
#define	NSPR_PDPKTRACEPARTTX_V23	0xF4	/* Transmitted */
#define	NSPR_PDPKTRACEPARTTXB_V23	0xF5	/* In transmit buffer */
#define	NSPR_PDPKTRACEPARTRX_V23	0xF6	/* Received */

/* cluster tracing*/
#define NSPR_PDPKTRACEFULLTX_V24    0xF8    /* Transmitted */
#define NSPR_PDPKTRACEFULLTXB_V24   0xF9    /* In transmit buffer */
#define NSPR_PDPKTRACEFULLRX_V24    0xFA    /* Received packets before NIC pipelining */
#define NSPR_PDPKTRACEFULLNEWRX_V24	0xfB	/* Received packets after NIC pipelining */
#define NSPR_PDPKTRACEPARTTX_V24    0xFC    /* Transmitted */
#define NSPR_PDPKTRACEPARTTXB_V24   0xFD    /* In transmit buffer */
#define NSPR_PDPKTRACEPARTRX_V24    0xFE    /* Received packets before NIC pipelining */
#define NSPR_PDPKTRACEPARTNEWRX_V24	0xFF    /* Received packets after NIC pipelining */

/* Record types */
#define	NSPR_HEADER_VERSION100 0x10
#define	NSPR_HEADER_VERSION200 0x20
#define	NSPR_HEADER_VERSION201 0x21
#define	NSPR_HEADER_VERSION202 0x22
#define NSPR_HEADER_VERSION203 0x23
#define NSPR_HEADER_VERSION204 0x24
int nstrace_open(wtap *wth, int *err, gchar **err_info);
int nstrace_10_dump_can_write_encap(int encap);
int nstrace_20_dump_can_write_encap(int encap);

gboolean nstrace_dump_open(wtap_dumper *wdh, int *err);


#endif /* _NETSCALER_H */
