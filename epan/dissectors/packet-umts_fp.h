/* packet-fp.h
 *
 * Martin Mathieson
 * $Id: packet-rtcp.h 18196 2006-05-21 04:49:01Z sahlberg $
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

/* Channel types */
#define CHANNEL_RACH_FDD     1
#define CHANNEL_RACH_TDD     2
#define CHANNEL_FACH_FDD     3
#define CHANNEL_FACH_TDD     4
#define CHANNEL_DSCH_FDD     5
#define CHANNEL_DSCH_TDD     6
#define CHANNEL_USCH_TDD_384 8
#define CHANNEL_USCH_TDD_128 24
#define CHANNEL_PCH          9
#define CHANNEL_CPCH         10
#define CHANNEL_BCH          11
#define CHANNEL_DCH          12
#define CHANNEL_HSDSCH       13
#define CHANNEL_IUR_CPCHF    14
#define CHANNEL_IUR_FACH     15
#define CHANNEL_IUR_DSCH     16
#define CHANNEL_EDCH         17
#define CHANNEL_RACH_TDD_128 18

/* Info attached to each FP packet */
struct _fp_info
{
    gboolean is_uplink;
    gint channel;
    gint node_type;
    gboolean dch_crc_present;
    gint paging_indications;
    gint num_chans;
#define MAX_FP_CHANS  64
    gint chan_tf_size[MAX_FP_CHANS];
    gint chan_num_tbs[MAX_FP_CHANS];

    /* TODO: EDCH info */
};

