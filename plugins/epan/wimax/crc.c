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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "crc.h"

#define WMAX_MAC_CRC32_POLYNOMIAL 0x04c11db7U /* polynomial used in calculating the CRC-32 checksum */
#define CCITT_X25_CRC16_POLYNOMIAL 0x1021     /* polynomial used in calculating the CRC-16 checksum */
#define WMAX_MAC_CRC8_POLYNOMIAL  0x07        /* polynomial used in calculating the CRC-8 checksum */
#define CRC32_INITIAL_VALUE       0xFFFFFFFF
#define CRC16_INITIAL_VALUE       0xFFFF

#ifndef STATIC_DATA
static uint8_t crc8_table[256];
static uint32_t crc32_table[256];

extern uint16_t crc16_table[256];

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
  uint32_t i, bit;
  uint32_t crc;

  /* little-endian (reflected) algorithm */
  for ( i = 0;  i < G_N_ELEMENTS(crc32_table);  i++ )
  {
    crc = ( i << 24 );
    for ( bit = 0;  bit < 8;  bit++ )
    {
      if ( crc & 0x80000000U )
        crc = ( crc << 1 ) ^ WMAX_MAC_CRC32_POLYNOMIAL;
      else
        crc = ( crc << 1 );
    }
    crc32_table[i] = crc;
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
  unsigned  i, bit;
  uint8_t crc;

  for ( i = 0;  i < G_N_ELEMENTS(crc8_table);  i++ )
  {
    crc = i;
    for ( bit = 0;  bit < 8;  bit++ )
    {
      if ( crc & 0x80 )
        crc = ( crc << 1 ) ^ WMAX_MAC_CRC8_POLYNOMIAL;
      else
        crc = ( crc << 1 );
    }
    crc8_table[i] = crc;
  }
}
#endif

/*

  uint32_t wimax_mac_calc_crc32(uint8_t *data, unsigned data_len)

  REQUIRES: wimax_mac_gen_crc32_table() must be called before

  DESCRIPTION: Calculate the 32-bit CRC from a given data block

  ARGS:  data - pointer to data
         data_len - length of data (in bytes)

  RETURNS:  calculated crc32

  SIDE EFFECTS:

*/
uint32_t wimax_mac_calc_crc32(const uint8_t *data, unsigned data_len)
{
  uint32_t crc=CRC32_INITIAL_VALUE;
  unsigned i, j;

  for ( j = 0;  j < data_len;  j++ )
  {
    i = ( (uint8_t)(crc>>24) ^ data[j] ) & 0xff;
    crc = ( crc<<8 ) ^ crc32_table[i];
  }
  return ~crc;
}

/*

  uint16_t wimax_mac_calc_crc16(uint8_t *data, unsigned data_len)

  REQUIRES: crc16_table[] in crc_data.c

  DESCRIPTION: Calculate the 16-bit CRC from a given data block

  ARGS:  data - pointer to data
         data_len - length of data (in bytes)

  RETURNS:  calculated crc16

  SIDE EFFECTS:

*/
uint16_t wimax_mac_calc_crc16(const uint8_t *data, unsigned data_len)
{
  uint32_t crc=CRC16_INITIAL_VALUE;
  unsigned j;

  for ( j = 0;  j < data_len;  j++ )
  {
    crc ^= data[j] << 8;
    crc = (crc << 8) ^ crc16_table[(crc & 0xff00) >> 8];
  }
  crc ^= 0xFFFF;        /* Invert the output. */
  crc &= 0xFFFF;
  return crc;
}

/*

  uint8_t wimax_mac_calc_crc8(uint8_t *data, unsigned data_len)

  REQUIRES: wimax_mac_gen_crc8_table() must be called before

  DESCRIPTION: Calculate the 8-bit CRC from a given data block

  ARGS:  data - pointer to data
         data_len - length of data (in bytes)

  RETURNS:  calculated crc8

  SIDE EFFECTS:

*/
uint8_t wimax_mac_calc_crc8(const uint8_t *data, unsigned data_len)
{
  uint8_t crc=0;
  unsigned i;

  for(i = 0; i < data_len; i++)
  {
    crc = crc8_table[data[i]^crc];
  }
  return crc;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
