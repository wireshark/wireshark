/* crc.c
 * crc checksum generation and calculation functions: crc.c
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Mike Harvey <michael.harvey@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include "crc.h"

#define WMAX_MAC_CRC32_POLYNOMIAL 0x04c11db7U /* polynomial used in calculating the CRC-32 checksum */
#define CCITT_X25_CRC16_POLYNOMIAL 0x1021     /* polynomial used in calculating the CRC-16 checksum */
#define WMAX_MAC_CRC8_POLYNOMIAL  0x07	      /* polynomial used in calculating the CRC-8 checksum */
#define CRC32_INITIAL_VALUE       0xFFFFFFFF
#define CRC16_INITIAL_VALUE       0xFFFF

#ifndef STATIC_DATA
static guint8  crc8_table[256];
static guint32 crc32_table[256];

extern guint16 crc16_table[256];

/*
  void wimax_mac_gen_crc32_table(void)

  REQUIRES: The functions must be called only once to initialze CRC table

  DESCRIPTION:  Generate the table of CRC remainders
                for all possible bytes

  ARGS:

  RETURNS:

  SIDE EFFECTS:

*/
void wimax_mac_gen_crc32_table(void)
{
  guint32 index, bit;
  guint32 crc;

  /* little-endian (reflected) algorithm */
  for ( index = 0;  index < G_N_ELEMENTS(crc32_table);  index++ )
  {
    crc = ( index << 24 );
    for ( bit = 0;  bit < 8;  bit++ )
    {
      if ( crc & 0x80000000U )
        crc = ( crc << 1 ) ^ WMAX_MAC_CRC32_POLYNOMIAL;
      else
        crc = ( crc << 1 );
    }
    crc32_table[index] = crc;
  }
}

/*
  void wimax_mac_gen_crc8_table(void)

  REQUIRES: The functions must be called only once to initialze CRC table

  DESCRIPTION:  Generate the table of CRC remainders
                for all possible bytes

  ARGS:

  RETURNS:

  SIDE EFFECTS:

*/
void wimax_mac_gen_crc8_table(void)
{
  guint  index, bit;
  guint8 crc;

  for ( index = 0;  index < G_N_ELEMENTS(crc8_table);  index++ )
  {
    crc = index;
    for ( bit = 0;  bit < 8;  bit++ )
    {
      if ( crc & 0x80 )
        crc = ( crc << 1 ) ^ WMAX_MAC_CRC8_POLYNOMIAL;
      else
        crc = ( crc << 1 );
    }
    crc8_table[index] = crc;
  }
}
#endif

/*

  guint32 wimax_mac_calc_crc32(guint8 *data, guint data_len)

  REQUIRES: wimax_mac_gen_crc32_table() must be called before

  DESCRIPTION: Calculate the 32-bit CRC from a given data block

  ARGS:  data - pointer to data
         data_len - length of data (in bytes)

  RETURNS:  calculated crc32

  SIDE EFFECTS:

*/
guint32 wimax_mac_calc_crc32(const guint8 *data, guint data_len)
{
  guint32 crc=CRC32_INITIAL_VALUE;
  guint i, j;

  for ( j = 0;  j < data_len;  j++ )
  {
    i = ( (guint8)(crc>>24) ^ data[j] ) & 0xff;
    crc = ( crc<<8 ) ^ crc32_table[i];
  }
  return ~crc;
}

/*

  guint16 wimax_mac_calc_crc16(guint8 *data, guint data_len)

  REQUIRES: crc16_table[] in crc_data.c

  DESCRIPTION: Calculate the 16-bit CRC from a given data block

  ARGS:  data - pointer to data
         data_len - length of data (in bytes)

  RETURNS:  calculated crc16

  SIDE EFFECTS:

*/
guint16 wimax_mac_calc_crc16(const guint8 *data, guint data_len)
{
  guint32 crc=CRC16_INITIAL_VALUE;
  guint j;

  for ( j = 0;  j < data_len;  j++ )
  {
    crc ^= data[j] << 8;
    crc = (crc << 8) ^ crc16_table[(crc & 0xff00) >> 8];
  }
  crc ^= 0xFFFF;	/* Invert the output. */
  crc &= 0xFFFF;
  return crc;
}

/*

  guint8 wimax_mac_calc_crc8(guint8 *data, guint data_len)

  REQUIRES: wimax_mac_gen_crc8_table() must be called before

  DESCRIPTION: Calculate the 8-bit CRC from a given data block

  ARGS:  data - pointer to data
         data_len - length of data (in bytes)

  RETURNS:  calculated crc8

  SIDE EFFECTS:

*/
guint8 wimax_mac_calc_crc8(const guint8 *data, guint data_len)
{
  guint8 crc=0;
  guint i;

  for(i = 0; i < data_len; i++)
  {
    crc = crc8_table[data[i]^crc];
  }
  return crc;
}
