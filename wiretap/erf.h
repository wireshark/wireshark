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
*/

#ifndef __W_ERF_H__
#define __W_ERF_H__

#include <glib.h>
#include <wiretap/wtap.h>
#include "ws_symbol_export.h"

/* Record type defines */
#define ERF_TYPE_LEGACY             0
#define ERF_TYPE_HDLC_POS           1
#define ERF_TYPE_ETH                2
#define ERF_TYPE_ATM                3
#define ERF_TYPE_AAL5               4
#define ERF_TYPE_MC_HDLC            5
#define ERF_TYPE_MC_RAW             6
#define ERF_TYPE_MC_ATM             7
#define ERF_TYPE_MC_RAW_CHANNEL     8
#define ERF_TYPE_MC_AAL5            9
#define ERF_TYPE_COLOR_HDLC_POS     10
#define ERF_TYPE_COLOR_ETH          11
#define ERF_TYPE_MC_AAL2            12
#define ERF_TYPE_IP_COUNTER         13
#define ERF_TYPE_TCP_FLOW_COUNTER   14
#define ERF_TYPE_DSM_COLOR_HDLC_POS 15
#define ERF_TYPE_DSM_COLOR_ETH      16
#define ERF_TYPE_COLOR_MC_HDLC_POS  17
#define ERF_TYPE_AAL2               18
#define ERF_TYPE_INFINIBAND         21
#define ERF_TYPE_IPV4               22
#define ERF_TYPE_IPV6               23
#define ERF_TYPE_RAW_LINK           24
#define ERF_TYPE_INFINIBAND_LINK    25

#define ERF_TYPE_PAD                48

#define ERF_TYPE_MIN  1   /* sanity checking */
#define ERF_TYPE_MAX  48  /* sanity checking */

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

typedef struct erf_mc_hdr {
	guint32	mc;
} erf_mc_header_t;

typedef struct erf_eth_hdr {
	guint16	eth;
} erf_eth_header_t;

union erf_subhdr {
  struct erf_mc_hdr mc_hdr;
  struct erf_eth_hdr eth_hdr;
};

#define MIN_RECORDS_FOR_ERF_CHECK 3
#define RECORDS_FOR_ERF_CHECK 20
#define FCS_BITS	32

int erf_open(wtap *wth, int *err, gchar **err_info);
int erf_dump_can_write_encap(int encap);
int erf_dump_open(wtap_dumper *wdh, int *err);

int erf_populate_interfaces(wtap *wth);

#endif /* __W_ERF_H__ */
