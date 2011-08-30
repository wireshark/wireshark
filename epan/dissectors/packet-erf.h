/* packet-erf.h
 * Routines for ERF encapsulation dissection
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __PACKET_ERF_H_
#define __PACKET_ERF_H_

#define EXT_HDR_TYPE_CLASSIFICATION 3
#define EXT_HDR_TYPE_INTERCEPTID    4 
#define EXT_HDR_TYPE_RAW_LINK       5 
#define EXT_HDR_TYPE_BFS            6 
#define EXT_HDR_TYPE_CHANNELISED	12
#define EXT_HDR_TYPE_NEW_BFS  14 

#define DECHAN_MAX_AUG_INDEX 4

void proto_reg_handoff_erf(void);
void proto_register_erf(void);

struct erf_mc_hdlc_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_mc_raw_hdrx {
  guint8 byte0;
  guint16 byte12;
  guint8 byte3;
};

struct erf_mc_atm_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_mc_aal5_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_mc_aal2_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_aal2_hdrx {
  guint8 byte0;
  guint8 byte1;
  guint16 byte23;
};

struct erf_mc_rawl_hdrx {
  guint16 byte01;
  guint8 byte2;
  guint8 byte3;
};

struct erf_eth_hdrx {
  guint8 byte0;
  guint8 byte1;
};

typedef struct sdh_g707_format_s                                                                              
{
  guint8 m_sdh_line_rate;
  guint8 m_vc_size ;
    gint8 m_vc_index_array[DECHAN_MAX_AUG_INDEX];
        /*  i = 4 --> ITU-T letter #E - index of AUG-64
        * i = 3 --> ITU-T letter #D - index of AUG-16
        * i = 2 --> ITU-T letter #C - index of AUG-4,
        * i = 1 --> ITU-T letter #B  -index of AUG-1
        * i = 0 --> ITU-T letter #A  - index of AU3*/
}sdh_g707_format_t;

#endif
