/* packet-mpeg-sect.h
 * Declarations of exported routines from mpeg-sect dissector
 * Copyright 2012, Weston Schmidt <weston_schmidt@alumni.purdue.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_MPEG_SECT_H__
#define __PACKET_MPEG_SECT_H__

/* From ISO/IEC 13818-1 */
#define MPEG_PAT_TID            0x00 /* packet-mpeg-pat.c */
#define MPEG_CA_TID             0x01 /* packet-mpeg-ca.c */
#define MPEG_PMT_TID            0x02 /* packet-mpeg-pmt.c */

/* From ISO/IEC 13818-6 */
#define DSMCC_TID_LLCSNAP       0x3A /* packet-mpeg-dsmcc.c */
#define DSMCC_TID_UN_MSG        0x3B /* packet-mpeg-dsmcc.c */
#define DSMCC_TID_DD_MSG        0x3C /* packet-mpeg-dsmcc.c */
#define DSMCC_TID_DESC_LIST     0x3D /* packet-mpeg-dsmcc.c */
#define DSMCC_TID_PRIVATE       0x3E /* packet-mpeg-dsmcc.c */

/* From ETSI EN 300 468 */
#define DVB_NIT_TID             0x40 /* packet-dvb-nit.c */
#define DVB_NIT_TID_OTHER       0x41 /* packet-dvb-nit.c */
#define DVB_SDT_TID_ACTUAL      0x42 /* packet-dvb-sdt.c */
#define DVB_SDT_TID_OTHER       0x46 /* packet-dvb-sdt.c */
#define DVB_BAT_TID             0x4A /* packet-dvb-bat.c */
#define DVB_EIT_TID_MIN         0x4E /* packet-dvb-eit.c */
#define DVB_EIT_TID_MAX         0x6F /* packet-dvb-eit.c */
#define DVB_TDT_TID             0x70 /* packet-dvb-tdt.c */
#define DVB_TOT_TID             0x73 /* packet-dvb-tot.c */

/* From ETSI TS 102 899 */
#define DVB_AIT_TID             0x74 /* packet-dvb-ait.c */

/* From ETSI EN 301 192 */
#define DVB_DATA_MPE_TID        0x3E /* packet-dvb-data-mpe.c */

/* From OC-SP-ETV-AM 1.0-IO5 */
#define EISS_SECTION_TID        0xE0 /* packet-eiss.c */
#define ETV_TID_DII_SECTION     0xE3 /* packet-etv.c */
#define ETV_TID_DDB_SECTION     0xE4 /* packet-etv.c */

#define PACKET_MPEG_SECT_PI__TABLE_ID	0
#define PACKET_MPEG_SECT_PI__SSI	1
#define PACKET_MPEG_SECT_PI__RESERVED	2
#define PACKET_MPEG_SECT_PI__LENGTH	3
#define PACKET_MPEG_SECT_PI__SIZE	4

/* convert a byte that contains two 4bit BCD digits into a decimal value */
#define MPEG_SECT_BCD44_TO_DEC(x)  ((((x)&0xf0) >> 4) * 10 + ((x)&0x0f))

/*
 * Used to read a date provided in MJD format into a utc_time structure
 */
extern gint
packet_mpeg_sect_mjd_to_utc_time(tvbuff_t *tvb, gint offset, nstime_t *utc_time);

/*
 *  Used to process the 'standard' mpeg section header that is described below
 *  and populate the data into the tree
 */
extern guint
packet_mpeg_sect_header(tvbuff_t *tvb, guint offset,
			proto_tree *tree, guint *sect_len, gboolean *ssi);

/*
 *  Used to return all the values & items for 'strict' processing of the
 *  sub-dissectors that make use of this dissector
 */
extern guint
packet_mpeg_sect_header_extra(tvbuff_t *tvb, guint offset, proto_tree *tree,
				guint *sect_len, guint *reserved, gboolean *ssi,
				proto_item **items);

/*
 *  Used to process the mpeg CRC information & report erorrs found with it.
 */
extern guint
packet_mpeg_sect_crc(tvbuff_t *tvb, packet_info *pinfo,
						proto_tree *tree, guint start, guint end);
#endif
