/* packet-esl.h
 *
 * $Id$
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
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

#ifndef _PACKET_ESL_H_
#define _PACKET_ESL_H_

typedef union _EslFlagsUnion
{
	struct
	{
		guint16				port7	: 1;		
		guint16				port6	: 1;		
		guint16				port5	: 1;		
		guint16				port4	: 1;		
		guint16				port3	: 1;			
		guint16				port2	: 1;					
		guint16				port1	: 1;				
		guint16				port0	: 1;				
		guint16				extended		: 1;				
		guint16				reserved		: 2;
		guint16				crcError		: 1;
		guint16				alignError	: 1;			
		guint16				timeStampEna: 1;						
		guint16				port9	: 1;			
		guint16				port8	: 1;				
	}d;
	struct
	{
		guint8				loPorts			: 1;
		guint8				flagsHiPorts	: 1;
	}lo_hi_flags;
	guint	flags;
}EslFlagsUnion;

/*
typedef struct _EslHeader
{	
	guint8					eslCookie[6];		// 01 01 05 10 00 00
	EslFlagsUnion			flags;
	guint64					timeStamp;
} EslHeader, *PEslHeader;*/


#define SIZEOF_ESLHEADER 16
#endif /* _PACKET_ESL_H_*/
