/* packet-ntp.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet-ntp.h,v 1.1 1999/10/14 05:10:30 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer <jmayer@telemation.de>
 *
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

/* This is from yahoolib.h from gtkyahoo */

#ifndef PACKET_NTP_H
#define PACKET_NTP_H

/* packet structure based on one in xntp package */
/* to satisfy it's requirements, even though the code isn't copied
directly: */

/***********************************************************************
 *                                                                     *
 * Copyright (c) David L. Mills 1992, 1993, 1994, 1995, 1996           *
 *                                                                     *
 * Permission to use, copy, modify, and distribute this software and   *
 * its documentation for any purpose and without fee is hereby         *
 * granted, provided that the above copyright notice appears in all    *
 * copies and that both the copyright notice and this permission       *
 * notice appear in supporting documentation, and that the name        *
 * University of Delaware not be used in advertising or publicity      *
 * pertaining to distribution of the software without specific,        *
 * written prior permission. The University of Delaware makes no       *
 * representations about the suitability this software for any         *
 * purpose. It is provided "as is" without express or implied          *
 * warranty.                                                           *
 **********************************************************************/

struct ntp_packet
{
        unsigned char flags[1];    /* leap indicator, version and mode */ /* 0 */
        unsigned char stratum[1];   /* peer's stratum */					
        unsigned char ppoll[1];     /* the peer polling interval */
        char precision[1];           /* peer clock precision */
        unsigned char rootdelay[4];  /* distance to primary clock */   /* 4 */
        unsigned char rootdispersion[4];  /* clock dispersion */ /* 8 */
        unsigned char refid[4];    /* reference clock ID */ /* 12-15 */
        unsigned char reftime[8];    /* time peer clock was last updated */  /* 16-23 */
        unsigned char org[8];      /* originate time stamp */  /* 24 */
        unsigned char rec[8];      /* receive time stamp */  /* 32 */
        unsigned char xmt[8];     /* transmit time stamp */
        unsigned char keyid[4];          /* key identification */ /* 48 */
        unsigned char mac[16];   /* message-authentication code */ /* 52 - 60 */
			/* can also be 16, if MD5 instead of DES */
};

#endif
