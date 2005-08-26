/*
*
* Copyright (c) 2003 Endace Technology Ltd, Hamilton, New Zealand.
* All rights reserved.
*
* This software and documentation has been developed by Endace Technology Ltd.
* along with the DAG PCI network capture cards. For further information please
* visit http://www.endace.com/.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*  1. Redistributions of source code must retain the above copyright notice,
*  this list of conditions and the following disclaimer.
*
*  2. Redistributions in binary form must reproduce the above copyright
*  notice, this list of conditions and the following disclaimer in the
*  documentation and/or other materials provided with the distribution.
*
*  3. The name of Endace Technology Ltd may not be used to endorse or promote
*  products derived from this software without specific prior written
*  permission.
*
* THIS SOFTWARE IS PROVIDED BY ENDACE TECHNOLOGY LTD ``AS IS'' AND ANY EXPRESS
* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
* EVENT SHALL ENDACE TECHNOLOGY LTD BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
* BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
* IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* $Id$
*/

#ifndef __W_ERF_H__
#define __W_ERF_H__

/* Record type defines */
#define TYPE_LEGACY	0
#define TYPE_HDLC_POS	1
#define TYPE_ETH	2
#define TYPE_ATM	3
#define TYPE_AAL5	4

 /*
  * The timestamp is 64bit unsigned fixed point little-endian value with
  * 32 bits for second and 32 bits for fraction.
  */
typedef guint64 erf_timestamp_t;

typedef struct erf_record {
	erf_timestamp_t	ts;
	guint8		type;
	guint8		flags;
	guint16		rlen;
	guint16		lctr;
	guint16		wlen;
} erf_header_t;

#define MAX_RECORD_LEN	0x10000 /* 64k */
#define RECORDS_FOR_ERF_CHECK	3
#define FCS_BITS	32

#ifndef min
#define min(a, b) ((a) > (b) ? (b) : (a))
#endif

/*
 * ATM snaplength
 */
#define ATM_SNAPLEN		48

/*
 * Size of ATM payload 
 */
#define ATM_SLEN(h, e)		ATM_SNAPLEN
#define ATM_WLEN(h, e)		ATM_SNAPLEN

/*
 * Size of Ethernet payload
 */
#define ETHERNET_WLEN(h, e)	(g_htons((h)->wlen))
#define ETHERNET_SLEN(h, e)	min(ETHERNET_WLEN(h, e), g_htons((h)->rlen) - sizeof(*(h)) - 2)

/*
 * Size of HDLC payload
 */
#define HDLC_WLEN(h, e)		(g_htons((h)->wlen))
#define HDLC_SLEN(h, e)		min(HDLC_WLEN(h, e), g_htons((h)->rlen) - sizeof(*(h)))

int erf_open(wtap *wth, int *err, gchar **err_info);

#endif /* __W_ERF_H__ */
