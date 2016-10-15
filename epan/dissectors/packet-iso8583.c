/* packet-iso8583.c
 * Routines for ISO-8583 Protocol dissection
 * Copyright 2015, Paulo Roberto Brandao <brandao@ubiqua.inf.br>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * ISO 8583 Financial transaction card originated messages - Interchange
 * message specifications is the International Organization for Standardization
 * standard for systems that exchange electronic transactions made by
 * cardholders using payment cards.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/wmem/wmem.h>
#include <epan/dissectors/packet-tcp.h>


/* bitmap length */
#define BM_LEN 8

/* Endianness */
#define BIGEND 1
#define LITEND 2

/* conversion types */
enum bin2hex_enum {
  TYPE_BCD, /* nibble */
  TYPE_BIN  /* raw data */
};


/* ISO bits content types */
typedef enum {
  ISO_TNONE,
  ISO_TA,
  ISO_TN,
  ISO_TXN,
  ISO_TS,
  ISO_TAS,
  ISO_TAN,
  ISO_TANS,
  ISO_TNS,
  ISO_TB,
  ISO_TZ
} iso_srt_types;

struct iso_type {
  guint32 type;
  guint32 maxsize;
  guint32 varlen;
};

/* ISO 8583-1 version 1987 Bit type specification */
static struct iso_type iso_1987[128] = {
  { ISO_TB, 0, 0 }, /*Bit 1*/
  { ISO_TN, 19, 2 }, /*Bit 2*/
  { ISO_TN, 6, 0 }, /*Bit 3*/
  { ISO_TN, 12, 0 }, /*Bit 4*/
  { ISO_TN, 12, 0 }, /*Bit 5*/
  { ISO_TN, 12, 0 }, /*Bit 6*/
  { ISO_TN, 10, 0 }, /*Bit 7*/
  { ISO_TN, 8, 0 }, /*Bit 8*/
  { ISO_TN, 8, 0 }, /*Bit 9*/
  { ISO_TN, 8, 0 }, /*Bit 10*/
  { ISO_TN, 6, 0 }, /*Bit 11*/
  { ISO_TN, 6, 0 }, /*Bit 12*/
  { ISO_TN, 4, 0 }, /*Bit 13*/
  { ISO_TN, 4, 0 }, /*Bit 14*/
  { ISO_TN, 6, 0 }, /*Bit 15*/
  { ISO_TN, 4, 0 }, /*Bit 16*/
  { ISO_TN, 4, 0 }, /*Bit 17*/
  { ISO_TN, 4, 0 }, /*Bit 18*/
  { ISO_TN, 3, 0 }, /*Bit 19*/
  { ISO_TN, 3, 0 }, /*Bit 20*/
  { ISO_TN, 3, 0 }, /*Bit 21*/
  { ISO_TN, 3, 0 }, /*Bit 22*/
  { ISO_TN, 3, 0 }, /*Bit 23*/
  { ISO_TN, 3, 0 }, /*Bit 24*/
  { ISO_TN, 2, 0 }, /*Bit 25*/
  { ISO_TN, 2, 0 }, /*Bit 26*/
  { ISO_TN, 1, 0 }, /*Bit 27*/
  { ISO_TXN, 9, 0 }, /*Bit 28*/
  { ISO_TXN, 9, 0 }, /*Bit 29*/
  { ISO_TXN, 9, 0 }, /*Bit 30*/
  { ISO_TXN, 9, 0 }, /*Bit 31*/
  { ISO_TN, 11, 2 }, /*Bit 32*/
  { ISO_TN, 11, 2 }, /*Bit 33*/
  { ISO_TNS, 28, 2 }, /*Bit 34*/
  { ISO_TZ, 37, 2 }, /*Bit 35*/
  { ISO_TAN, 104, 3 }, /*Bit 36*/
  { ISO_TAN, 12, 0 }, /*Bit 37*/
  { ISO_TAN, 6, 0 }, /*Bit 38*/
  { ISO_TAN, 2, 0 }, /*Bit 39*/
  { ISO_TANS, 3, 0 }, /*Bit 40*/
  { ISO_TANS, 8, 0 }, /*Bit 41*/
  { ISO_TANS, 15, 0 }, /*Bit 42*/
  { ISO_TANS, 40, 0 }, /*Bit 43*/
  { ISO_TANS, 25, 2 }, /*Bit 44*/
  { ISO_TANS, 76, 2 }, /*Bit 45*/
  { ISO_TANS, 999, 3 }, /*Bit 46*/
  { ISO_TANS, 999, 3 }, /*Bit 47*/
  { ISO_TANS, 999, 3 }, /*Bit 48*/
  { ISO_TANS, 3, 0 }, /*Bit 49*/
  { ISO_TAN, 3, 0 }, /*Bit 50*/
  { ISO_TAN, 3, 0 }, /*Bit 51*/
  /*{ ISO_TB, 64, 0 },*/ /*Bit 52*/
  { ISO_TB, 8, 0 }, /*Bit 52*/
  { ISO_TN, 8, 0 }, /*Bit 53*/
  { ISO_TAN, 120, 3 }, /*Bit 54*/
  { ISO_TANS, 999, 3 }, /*Bit 55*/
  { ISO_TANS, 999, 3 }, /*Bit 56*/
  { ISO_TANS, 999, 3 }, /*Bit 57*/
  { ISO_TANS, 999, 3 }, /*Bit 58*/
  { ISO_TANS, 999, 3 }, /*Bit 59*/
  { ISO_TANS, 999, 3 }, /*Bit 60*/
  { ISO_TANS, 999, 3 }, /*Bit 61*/
  { ISO_TANS, 999, 3 }, /*Bit 62*/
  { ISO_TANS, 999, 3 }, /*Bit 63*/
  { ISO_TB, 8, 0 }, /*Bit 64*/
  { ISO_TB, 0, 0 }, /*Bit 65*/
  { ISO_TN, 1, 0 }, /*Bit 66*/
  { ISO_TN, 2, 0 }, /*Bit 67*/
  { ISO_TN, 3, 0 }, /*Bit 68*/
  { ISO_TN, 3, 0 }, /*Bit 69*/
  { ISO_TN, 3, 0 }, /*Bit 70*/
  { ISO_TN, 4, 0 }, /*Bit 71*/
  { ISO_TN, 4, 0 }, /*Bit 72*/
  { ISO_TN, 6, 0 }, /*Bit 73*/
  { ISO_TN, 10, 0 }, /*Bit 74*/
  { ISO_TN, 10, 0 }, /*Bit 75*/
  { ISO_TN, 10, 0 }, /*Bit 76*/
  { ISO_TN, 10, 0 }, /*Bit 77*/
  { ISO_TN, 10, 0 }, /*Bit 78*/
  { ISO_TN, 10, 0 }, /*Bit 79*/
  { ISO_TN, 10, 0 }, /*Bit 80*/
  { ISO_TN, 10, 0 }, /*Bit 81*/
  { ISO_TN, 12, 0 }, /*Bit 82*/
  { ISO_TN, 12, 0 }, /*Bit 83*/
  { ISO_TN, 12, 0 }, /*Bit 84*/
  { ISO_TN, 12, 0 }, /*Bit 85*/
  { ISO_TN, 15, 0 }, /*Bit 86*/
  { ISO_TN, 15, 0 }, /*Bit 87*/
  { ISO_TN, 15, 0 }, /*Bit 88*/
  { ISO_TN, 15, 0 }, /*Bit 89*/
  { ISO_TN, 42, 0 }, /*Bit 90*/
  { ISO_TANS, 1, 0 }, /*Bit 91*/
  { ISO_TN, 2, 0 }, /*Bit 92*/
  { ISO_TN, 5, 0 }, /*Bit 93*/
  { ISO_TANS, 7, 0 }, /*Bit 94*/
  { ISO_TANS, 42, 0 }, /*Bit 95*/
  { ISO_TB, 8, 0 }, /*Bit 96*/
  { ISO_TXN, 17, 0 }, /*Bit 97*/
  { ISO_TANS, 25, 0 }, /*Bit 98*/
  { ISO_TN, 11, 2 }, /*Bit 99*/
  { ISO_TN, 11, 2 }, /*Bit 100*/
  { ISO_TANS, 17, 2 }, /*Bit 101*/
  { ISO_TANS, 28, 2 }, /*Bit 102*/
  { ISO_TANS, 28, 2 }, /*Bit 103*/
  { ISO_TANS, 100, 3 }, /*Bit 104*/
  { ISO_TANS, 999, 3 }, /*Bit 105*/
  { ISO_TANS, 999, 3 }, /*Bit 106*/
  { ISO_TANS, 999, 3 }, /*Bit 107*/
  { ISO_TANS, 999, 3 }, /*Bit 108*/
  { ISO_TANS, 999, 3 }, /*Bit 109*/
  { ISO_TANS, 999, 3 }, /*Bit 110*/
  { ISO_TANS, 999, 3 }, /*Bit 111*/
  { ISO_TANS, 999, 3 }, /*Bit 112*/
  { ISO_TANS, 999, 3 }, /*Bit 113*/
  { ISO_TANS, 999, 3 }, /*Bit 114*/
  { ISO_TANS, 999, 3 }, /*Bit 115*/
  { ISO_TANS, 999, 3 }, /*Bit 116*/
  { ISO_TANS, 999, 3 }, /*Bit 117*/
  { ISO_TANS, 999, 3 }, /*Bit 118*/
  { ISO_TANS, 999, 3 }, /*Bit 119*/
  { ISO_TANS, 999, 3 }, /*Bit 120*/
  { ISO_TANS, 999, 3 }, /*Bit 121*/
  { ISO_TANS, 999, 3 }, /*Bit 122*/
  { ISO_TANS, 999, 3 }, /*Bit 123*/
  { ISO_TANS, 999, 3 }, /*Bit 124*/
  { ISO_TANS, 999, 3 }, /*Bit 125*/
  { ISO_TANS, 999, 3 }, /*Bit 126*/
  { ISO_TANS, 999, 3 }, /*Bit 127*/
  { ISO_TB, 8, 0 } /*Bit 128*/
};

/* ISO 8583-1 version 1993 Bit type specification */
static struct iso_type  iso_1993[128] = {
  { ISO_TB, 0, 0 }, /*Bit 1*/
  { ISO_TN, 19, 2 }, /*Bit 2*/
  { ISO_TN, 6, 0 }, /*Bit 3*/
  { ISO_TN, 12, 0 }, /*Bit 4*/
  { ISO_TN, 12, 0 }, /*Bit 5*/
  { ISO_TN, 12, 0 }, /*Bit 6*/
  { ISO_TN, 10, 0 }, /*Bit 7*/
  { ISO_TN, 8, 0 }, /*Bit 8*/
  { ISO_TN, 8, 0 }, /*Bit 9*/
  { ISO_TN, 8, 0 }, /*Bit 10*/
  { ISO_TN, 6, 0 }, /*Bit 11*/
  { ISO_TN, 12, 0 }, /*Bit 12*/
  { ISO_TN, 4, 0 }, /*Bit 13*/
  { ISO_TN, 4, 0 }, /*Bit 14*/
  { ISO_TN, 6, 0 }, /*Bit 15*/
  { ISO_TN, 4, 0 }, /*Bit 16*/
  { ISO_TN, 4, 0 }, /*Bit 17*/
  { ISO_TN, 4, 0 }, /*Bit 18*/
  { ISO_TN, 3, 0 }, /*Bit 19*/
  { ISO_TN, 3, 0 }, /*Bit 20*/
  { ISO_TN, 3, 0 }, /*Bit 21*/
  { ISO_TAN, 12, 0 }, /*Bit 22*/
  { ISO_TN, 3, 0 }, /*Bit 23*/
  { ISO_TN, 3, 0 }, /*Bit 24*/
  { ISO_TN, 4, 0 }, /*Bit 25*/
  { ISO_TN, 4, 0 }, /*Bit 26*/
  { ISO_TN, 1, 0 }, /*Bit 27*/
  { ISO_TN, 6, 0 }, /*Bit 28*/
  { ISO_TN, 3, 0 }, /*Bit 29*/
  { ISO_TN, 24, 0 }, /*Bit 30*/
  { ISO_TANS, 99, 2 }, /*Bit 31*/
  { ISO_TN, 11, 2 }, /*Bit 32*/
  { ISO_TN, 11, 2 }, /*Bit 33*/
  { ISO_TNS, 28, 2 }, /*Bit 34*/
  { ISO_TZ, 37, 2 }, /*Bit 35*/
  { ISO_TZ, 104, 3 }, /*Bit 36*/
  { ISO_TAN, 12, 0 }, /*Bit 37*/
  { ISO_TAN, 6, 0 }, /*Bit 38*/
  { ISO_TN, 3, 0 }, /*Bit 39*/
  { ISO_TN, 3, 0 }, /*Bit 40*/
  { ISO_TANS, 8, 0 }, /*Bit 41*/
  { ISO_TANS, 15, 0 }, /*Bit 42*/
  { ISO_TANS, 99, 2 }, /*Bit 43*/
  { ISO_TANS, 99, 2 }, /*Bit 44*/
  { ISO_TANS, 76, 2 }, /*Bit 45*/
  { ISO_TANS, 204, 3 }, /*Bit 46*/
  { ISO_TANS, 999, 3 }, /*Bit 47*/
  { ISO_TANS, 999, 3 }, /*Bit 48*/
  { ISO_TAN, 3, 0 }, /*Bit 49*/
  { ISO_TAN, 3, 0 }, /*Bit 50*/
  { ISO_TAN, 3, 0 }, /*Bit 51*/
  /*{ ISO_TB, 64, 0 },*/ /*Bit 52*/
  { ISO_TB, 8, 0 }, /*Bit 52*/
  { ISO_TB, 48, 0 }, /*Bit 53*/
  { ISO_TANS, 120, 3 }, /*Bit 54*/
  { ISO_TB, 255, 3 }, /*Bit 55*/
  { ISO_TN, 35, 2 }, /*Bit 56*/
  { ISO_TN, 3, 0 }, /*Bit 57*/
  { ISO_TN, 11, 2 }, /*Bit 58*/
  { ISO_TANS, 999, 3 }, /*Bit 59*/
  { ISO_TANS, 999, 3 }, /*Bit 60*/
  { ISO_TANS, 999, 3 }, /*Bit 61*/
  { ISO_TANS, 999, 3 }, /*Bit 62*/
  { ISO_TANS, 999, 3 }, /*Bit 63*/
  { ISO_TB, 8, 0 }, /*Bit 64*/
  { ISO_TB, 0, 0 }, /*Bit 65*/
  { ISO_TANS, 204, 3 }, /*Bit 66*/
  { ISO_TN, 2, 0 }, /*Bit 67*/
  { ISO_TN, 3, 0 }, /*Bit 68*/
  { ISO_TN, 3, 0 }, /*Bit 69*/
  { ISO_TN, 3, 0 }, /*Bit 70*/
  { ISO_TN, 6, 0 }, /*Bit 71*/
  { ISO_TANS, 999, 3 }, /*Bit 72*/
  { ISO_TN, 6, 0 }, /*Bit 73*/
  { ISO_TN, 10, 0 }, /*Bit 74*/
  { ISO_TN, 10, 0 }, /*Bit 75*/
  { ISO_TN, 10, 0 }, /*Bit 76*/
  { ISO_TN, 10, 0 }, /*Bit 77*/
  { ISO_TN, 10, 0 }, /*Bit 78*/
  { ISO_TN, 10, 0 }, /*Bit 79*/
  { ISO_TN, 10, 0 }, /*Bit 80*/
  { ISO_TN, 10, 0 }, /*Bit 81*/
  { ISO_TN, 10, 0 }, /*Bit 82*/
  { ISO_TN, 10, 0 }, /*Bit 83*/
  { ISO_TN, 10, 0 }, /*Bit 84*/
  { ISO_TN, 10, 0 }, /*Bit 85*/
  { ISO_TN, 16, 0 }, /*Bit 86*/
  { ISO_TN, 16, 0 }, /*Bit 87*/
  { ISO_TN, 16, 0 }, /*Bit 88*/
  { ISO_TN, 16, 0 }, /*Bit 89*/
  { ISO_TN, 10, 0 }, /*Bit 90*/
  { ISO_TN, 3, 0 }, /*Bit 91*/
  { ISO_TN, 3, 0 }, /*Bit 92*/
  { ISO_TN, 11, 2 }, /*Bit 93*/
  { ISO_TN, 11, 2 }, /*Bit 94*/
  { ISO_TANS, 99, 2 }, /*Bit 95*/
  { ISO_TB, 999, 3 }, /*Bit 96*/
  { ISO_TXN, 17, 0 }, /*Bit 97*/
  { ISO_TANS, 25, 0 }, /*Bit 98*/
  { ISO_TAN, 11, 2 }, /*Bit 99*/
  { ISO_TN, 11, 2 }, /*Bit 100*/
  { ISO_TANS, 17, 2 }, /*Bit 101*/
  { ISO_TANS, 28, 2 }, /*Bit 102*/
  { ISO_TANS, 28, 2 }, /*Bit 103*/
  { ISO_TANS, 100, 3 }, /*Bit 104*/
  { ISO_TN, 16, 0 }, /*Bit 105*/
  { ISO_TN, 16, 0 }, /*Bit 106*/
  { ISO_TN, 10, 0 }, /*Bit 107*/
  { ISO_TN, 10, 0 }, /*Bit 108*/
  { ISO_TANS, 84, 2 }, /*Bit 109*/
  { ISO_TANS, 84, 2 }, /*Bit 110*/
  { ISO_TANS, 999, 3 }, /*Bit 111*/
  { ISO_TANS, 999, 3 }, /*Bit 112*/
  { ISO_TANS, 999, 3 }, /*Bit 113*/
  { ISO_TANS, 999, 3 }, /*Bit 114*/
  { ISO_TANS, 999, 3 }, /*Bit 115*/
  { ISO_TANS, 999, 3 }, /*Bit 116*/
  { ISO_TANS, 999, 3 }, /*Bit 117*/
  { ISO_TANS, 999, 3 }, /*Bit 118*/
  { ISO_TANS, 999, 3 }, /*Bit 119*/
  { ISO_TANS, 999, 3 }, /*Bit 120*/
  { ISO_TANS, 999, 3 }, /*Bit 121*/
  { ISO_TANS, 999, 3 }, /*Bit 122*/
  { ISO_TANS, 999, 3 }, /*Bit 123*/
  { ISO_TANS, 999, 3 }, /*Bit 124*/
  { ISO_TANS, 999, 3 }, /*Bit 125*/
  { ISO_TANS, 999, 3 }, /*Bit 126*/
  { ISO_TANS, 999, 3 }, /*Bit 127*/
  { ISO_TB, 8, 0 } /*Bit 128*/
};

void proto_reg_handoff_iso8583(void);
void proto_register_iso8583(void);

static int proto_iso8583 = -1;

static int hf_iso8583_len = -1;
static int hf_iso8583_mti = -1;
static int hf_iso8583_bitmap1 = -1;
static int hf_iso8583_bitmap2 = -1;

static int iso8583_data_bit[128] = {
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

static gint ett_iso8583 = -1;

static expert_field ei_iso8583_MALFORMED = EI_INIT;

static struct iso_type *data_array = NULL;

/* Global port preference */
#define iso8583_TCP_PORT 0

/* Types definitions */
#define ASCII_CHARSET 1
#define NUM_NIBBLE_CHARSET 2
#define BIN_ASCII_ENC 1
#define BIN_BIN_ENC 2

/* Global preference */
static guint tcp_port_pref = iso8583_TCP_PORT;
static gint charset_pref = ASCII_CHARSET;
static gint bin_encode_pref = BIN_ASCII_ENC;

static gint iso8583_len=-1; /* # of bytes captured by the dissector */
static gint len_byte_order = LITEND;

/*
 * Functions that check field type against specification.
 */

/*
 * Macro used by functions that check correctness of
 * the message type. Go through string checking the
 * condition passed as argument.
 */
#define char_cond( cond )\
  const char *c;\
const char *end= string + size;\
for(c=string; c< end && ( cond ) ; c++);\
return size && c==end

/* Hexa representation of Binary field */
static int ishex_str(const char* string, guint size)
{
  /*char_cond(g_ascii_isdigit(*c) || ( g_ascii_toupper(*c)>= 'A' && g_ascii_toupper(*c)<= 'F'));*/
  char_cond(g_ascii_isxdigit(*c));
}

/* ISO_TN */
static int isnum_str(const char* string, unsigned int size)
{
  char_cond( g_ascii_isdigit(*c) );
}

/* ISO_TAS */
static int isalspec_str(const char* string, unsigned int size)
{
  char_cond(g_ascii_isalpha(*c) || g_ascii_isspace(*c) || g_ascii_ispunct(*c));
}

/* ISO_TA */
static int isalpha_str(const char* string, unsigned int size)
{
  char_cond( g_ascii_isalpha(*c));
}

/* ISO_TAN */
static int isalnum_str(const char* string, unsigned int size)
{
  char_cond( g_ascii_isalnum(*c));
}

/* ISO_ANS */
static int isalnumspec_str(const char* string, unsigned int size)
{
  char_cond(g_ascii_isalnum(*c) || g_ascii_isspace(*c) || g_ascii_ispunct(*c));
}

/* ISO_NS */
static int isnumspec_str(const char* string, unsigned int size)
{
  char_cond(g_ascii_isdigit(*c) || g_ascii_isspace(*c) || g_ascii_ispunct(*c));
}

/* ISO_S */
static int isspec_str(const char* string, unsigned int size)
{
  char_cond(g_ascii_isspace(*c) || g_ascii_ispunct(*c));
}

static gboolean isstrtype_ok( int type, const char* string, unsigned int size)
{
  switch(type)
  {
    case ISO_TA:
      return isalpha_str(string, size);
    case ISO_TN:
      return isnum_str(string, size);
    case ISO_TXN:
      return ishex_str(string, size);
    case ISO_TS:
      return isspec_str(string, size);
    case ISO_TAS:
      return isalspec_str(string, size);
    case ISO_TAN:
      return isalnum_str(string, size);
    case ISO_TANS:
      return isalnumspec_str(string, size);
    case ISO_TNS:
      return isnumspec_str(string, size);
    case ISO_TB:
      return ishex_str(string, size);
    case ISO_TZ:
      if(charset_pref == ASCII_CHARSET)
        return isalnumspec_str(string, size);
      else
        return ishex_str(string, size);
  }
  return 0;
}

/* Endianness */
static const enum_val_t enumendians[] = {
  { "bigendian", "Big endian", BIGEND},
  { "littleendian", "Little endian", LITEND},
  { NULL, NULL, 0}
};

/* Charset */
static const enum_val_t enum_charset[] = {
  {"ascii", "Digits represented as ASCII Characters", ASCII_CHARSET},
  {"bcd", "Digits represented in nibbles", NUM_NIBBLE_CHARSET},
  {NULL, NULL, 0}
};

/* Encoding */
static const enum_val_t enum_bin_encode[] = {
  {"ascii", "Bin data represented as Hex Ascii characters", BIN_ASCII_ENC},
  {"bin", "Bin data not encoded", BIN_BIN_ENC},
  {NULL, NULL, 0}
};


#define iso8583_MIN_LENGTH 22 /* 2 (len) + 4 (mti) + 16 (fst bitmap in hexa) */


/* ISO standard version */
static const value_string packetversionnames[] = {
  { 48, ":1987"}, /*48 == '0'*/
  { 49, ":1993"}, /*49 == '1'*/
  { 50, ":2003"}, /*50 == '2'*/
  { 0, NULL }
};

static const value_string packettypenames[] = {
  { 48, "Reserved by ISO"},         /*48 == '0'*/
  { 49, "Authorization Message"},   /*49 == '1'*/
  { 50, "Financial Messages"},      /*50 == '2'*/
  { 51, "File Actions Message"},    /*51 == '3'*/
  { 52, "Reversal and Chargeback"}, /*52 == '4'*/
  { 53, "Reconciliation Message"},  /*53 == '5'*/
  { 54, "Administrative Message"},  /*54 == '6'*/
  { 55, "Fee Collection Messages"}, /*54 == '7'*/
  { 56, "Network Management"},      /*56 == '8'*/
  { 57, "Reserved by ISO"},         /*57 == '9'*/
  { 0, NULL }
};
#define FRAME_HEADER_LEN 2

static guint get_iso8583_msg_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  const guint enc = (len_byte_order == BIGEND)?ENC_BIG_ENDIAN:ENC_LITTLE_ENDIAN;

  iso8583_len = tvb_get_guint16(tvb, offset, enc) + 2;
  return iso8583_len;
}

#define NIBBLE_2_ASCHEX(nibble)\
  ( ((nibble)>9) ? (((nibble)-10))+'A' : ((nibble)+'0') )

/*
 * Convert a sequence of nibbles to a string of ASCII characters
 * corresponding to the hex digits in those nibbles.
 */
static gchar* bin2hex(const guint8 *bin, enum bin2hex_enum type, guint32 len)
{
  gchar* ret;
  guint8 ch;
  const guint8* str = bin;
  guint32 size = len;
  gchar* buff;

  /* "size" characters, plus terminating NUL */
  ret = (gchar *)wmem_alloc(wmem_packet_scope(), size + 1);
  buff = ret;
  if(type == TYPE_BCD)
  {
    if(size % 2) /* odd */
    {
      ch = *str & 0x0f;
      *buff++ = NIBBLE_2_ASCHEX(ch);
      str++;
      size--;
    }
    size = len/=2;
  }

  while(size-- > 0)
  {
    ch = (*str >> 4) & 0x0f;
    *buff++ = NIBBLE_2_ASCHEX(ch);
    ch = *str & 0x0f;
    *buff++ = NIBBLE_2_ASCHEX(ch);
    str++;
  }
  *buff = '\0';
  return ret;
}

static guint64 hex2bin(const char* hexstr, int len)
{
  char nibble;
  int i;
  guint64 bin= 0;

  for(i=0; i< len && i<16; i++)
  {
    nibble = hexstr[i];
    bin <<= 4;
    if (g_ascii_isdigit(nibble))
      bin |=  nibble - 48;
    else
      bin |= g_ascii_toupper(nibble) - 55; /* nibble - ('A') + 10 ; */
  }

  return bin;
}

#define checksize(len)\
      if((offset -2 + len) > iso8583_len)\
        return NULL

static gchar *get_bit(guint ind, tvbuff_t *tvb, gint *off_set, proto_tree *tree, proto_item **exp, gint *length )
{
  gchar aux[1024];
  gchar* ret=NULL;
  gint len;
  gint offset = *off_set;
  gboolean str_input = FALSE;

  /* Check if it is a fixed or variable length
   * data field */

  if(data_array[ind].varlen == 0)
    len = data_array[ind].maxsize; /* fixed len */
  else
  {
    /* var len*/
    len = data_array[ind].varlen;

    switch(charset_pref)
    {
      case ASCII_CHARSET:
      {
        gchar* sizestr;
        checksize(len);

        sizestr = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset,
              len , ENC_ASCII);
        if(!isnum_str(sizestr,len))
        {
          return NULL;
        }
        offset+=len;
        len = atoi(sizestr);
        break;
      }
      case NUM_NIBBLE_CHARSET:
      {
        gint sizestr =0;
        gchar* tmp;
        if(len%2)
          len++;

        tvb_memcpy(tvb, aux, offset, len);
        tmp = aux;

        checksize((len/2));

        offset+=len/2;
        while(len > 0)
        {
          sizestr = sizestr*100 + (((guint8)(*tmp)>>4) & 0x0f)*10 +
            (((guint8)(*tmp)) & 0x0f);
          len-=2;
          tmp++;
        }
        len = sizestr;
        break;
      }
    }
  }

  *off_set = offset;

  if(len > 0)
  {
    if((guint)len > data_array[ind].maxsize)
      return NULL;

    if(data_array[ind].type == ISO_TN || data_array[ind].type == ISO_TXN)
    {
      if(charset_pref == ASCII_CHARSET)
      {
        checksize(len);
        ret = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset,
          len , ENC_ASCII);
        *length = len;
      }
      else if(charset_pref == NUM_NIBBLE_CHARSET)
      {
        gint tlen = (len%2)? len/2 + 1 : len/2;
        checksize(tlen);
        tvb_memcpy(tvb, aux, offset, tlen);
        if((ret = bin2hex((guint8 *)aux, TYPE_BCD, len)) == NULL)
          return NULL;
        *length = (gint)strlen(ret);
        len = tlen;
        str_input = TRUE;
      }
      /* else */
    }
    else if(data_array[ind].type == ISO_TB || data_array[ind].type == ISO_TZ)
    {
      if( bin_encode_pref == BIN_ASCII_ENC)
      {
        if(data_array[ind].type == ISO_TB)
          len*=2;
        *length = len;
        checksize(len);
        ret = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset,
          len, ENC_ASCII);
      }
      else
      {
        checksize(len);
        tvb_memcpy(tvb, aux, offset, len);
        if((ret = bin2hex((guint8 *)aux, TYPE_BIN, len)) == NULL)
          return NULL;
        *length = (gint)strlen(ret);
        str_input = TRUE;
      }
      /* else */
    }
    else
    {
      checksize(len);
      ret = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset,
        len , ENC_ASCII);
      *length = len;
    }
    /* TODO: check type of ret content */
    if(str_input && tree != NULL)
        *exp = proto_tree_add_string(tree, iso8583_data_bit[ind], tvb, offset, len, ret);
    else if (tree != NULL)
        *exp = proto_tree_add_item(tree, iso8583_data_bit[ind], tvb,
              offset, len, ENC_ASCII);

    *off_set = offset + len;
  }
  else
  {
    *length = 0;
    ret = "";
  }

  return ret;
}


static int get_bitmap(tvbuff_t *tvb, guint64* bitmap, gint offset, gint* nbitmaps)
{
  gchar* hexbit;
  gint i;
  gboolean isbreak = FALSE;

  *nbitmaps=0;

  for(i=0; i<2; i++)
  {
    if(bin_encode_pref == BIN_BIN_ENC)
    {
      if((offset -2 + 8) > iso8583_len)
        return -1;

      (*nbitmaps)++;
      bitmap[i] = tvb_get_bits64(tvb, offset*8, 64, ENC_BIG_ENDIAN);
      offset+= BM_LEN;
    }
    else
    {
      gint len = BM_LEN*2;
      if((offset -2 + len) > iso8583_len)
        return -1;
      (*nbitmaps)++;
      hexbit = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len , ENC_ASCII);
      offset+= len;

      if(!ishex_str(hexbit, len))
        return 0;

      bitmap[i] = hex2bin(hexbit, len);
    }

    if(! (bitmap[i] & (((guint64)1) << 63))) /*bit 1 is set; there is a second bitmap*/
    {
      isbreak = TRUE;
      break;
    }
  }
  if(!isbreak)
    (*nbitmaps)++;

  return 0;
}

static int dissect_databits(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int nofbitmaps, guint64 *bitmap)
{
  proto_item *exp;
  gint nofbits = nofbitmaps*64, i;
  guint64 bit;
  gchar* cod;
  gint len;

  if(!pinfo)
    return 0;

  for(i=0; i < nofbits; i++)
  {
    exp = NULL;
    bit = i%64;
    if( !bit)
      continue;

    if(bitmap[i/64] & (((guint64)1)<< (63 -bit)))
    {
      cod = get_bit(i, tvb, &offset, tree, &exp, &len);
      if(cod == NULL || ! isstrtype_ok(data_array[i].type, cod, len ))
      {
        if(!exp)
          exp = proto_tree_add_string(tree, iso8583_data_bit[i], tvb, offset, 0, "");
        expert_add_info(pinfo, exp, &ei_iso8583_MALFORMED);
        return offset;
      }

      if( i == 2 || i == 69) /*Processing code or Net. info code*/
      {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s. cod: %s", ((i==2)?"Proc":"Net"), cod);
        continue;
      }

      /*test if exp is of type expected*/
      if(exp)
      {
      }
    }
  }
  return tvb_captured_length(tvb);
}

static int dissect_iso8583_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
  proto_item *ti, *exp;
  proto_tree *iso8583_tree;
  guint       offset = 0;
  int         len    = 0;
  gchar *msg_type, *msg_bitmap;
  gchar aux[24];
  guint64 bitmap[3]= {0,0,0};
  int nofbitmaps=0;
  guint ret;


  /* Check that the packet is long enough for it to belong to ISO 8583-1. */
  if (tvb_reported_length(tvb) < iso8583_MIN_LENGTH)
  {
    return 0;
  }

  /* Heuristic: 4 bytes MTI - all digits */
  if(charset_pref == ASCII_CHARSET) /* ASCII NUMBER REPRESENTATION */
  {
    len = 4;
    msg_type = (gchar*) tvb_get_string_enc(wmem_packet_scope(), tvb, 2, len, ENC_ASCII);
  }
  else /* NUMBERS REPRESENTED IN NIBBLES */
  {
    len = 2;
    tvb_memcpy(tvb, aux, 2, len);
    if((msg_type = bin2hex((guint8 *)aux, TYPE_BCD, len*2)) == NULL)
      return 0;
  }

  if(strlen(msg_type) == 4 && !isnum_str(msg_type,4)) /*MTI is composed of 4 digits*/
  {
    return 0;
  }

  /* Heuristic: 16 bytes Bitmap1 - all HEX digits */

  if(bin_encode_pref == BIN_BIN_ENC) /* ASCII NUMBER REPRESENTATION */
    msg_bitmap = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, 6, BM_LEN*2 , ENC_ASCII);
  else
  {
    tvb_memcpy(tvb, aux, 6, BM_LEN);
    if((msg_bitmap = bin2hex((guint8 *)aux, TYPE_BCD, BM_LEN)) == NULL)
      return 0;
  }

  if(strlen(msg_bitmap) == 16 && !ishex_str(msg_bitmap, BM_LEN*2)) /*MTI is composed of 4 digits*/
  {
    return 0;
  }

  /* check for message type format */
  if(msg_type[0] == '0')
    data_array = iso_1987;
  else if (msg_type[0] == '1')
    data_array = iso_1993;
  else
  {
    return 0;
  }


  /* Set the Protocol column */
  col_clear(pinfo->cinfo, COL_PROTOCOL);
  col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "ISO 8583-1%s",
      val_to_str((guint)msg_type[0], packetversionnames, " Unknown VERSION"));
  col_clear(pinfo->cinfo, COL_INFO);
  /* print version of the packet*/
  col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s - %s", msg_type,
      val_to_str((guint)msg_type[1], packettypenames, "Unknown type"));

  /*** PROTOCOL TREE ***/

  /* create display subtree for the protocol */
  ti = proto_tree_add_item(tree, proto_iso8583, tvb, 0, -1, ENC_NA);
  proto_item_append_text(ti, ":  Type %s - %s", msg_type,
      val_to_str((guint)msg_type[1], packettypenames, "Unknown type"));

  iso8583_tree = proto_item_add_subtree(ti, ett_iso8583);

  /*Length of the package*/
  len=2;
  proto_tree_add_item(iso8583_tree, hf_iso8583_len, tvb,
      offset, len, (len_byte_order == BIGEND)?ENC_BIG_ENDIAN:ENC_LITTLE_ENDIAN);
  offset += len;

  /*MTI*/
  /* TODO: check BCD or ASCII */
  if(charset_pref == ASCII_CHARSET) /* ASCII NUMBER REPRESENTATION */
  {
    len=4;
    proto_tree_add_item(iso8583_tree, hf_iso8583_mti, tvb,
        offset, len, ENC_ASCII | ENC_NA);
  }
  else
  {
    len=2;
    proto_tree_add_string(iso8583_tree, hf_iso8583_mti, tvb, offset, len, msg_type);
  }

  /*BITMAPS*/
  offset+=len;

  get_bitmap(tvb, bitmap, offset, &nofbitmaps);

  if(nofbitmaps == 0)
  {
      expert_add_info(pinfo, ti, &ei_iso8583_MALFORMED);
      return offset;
  }

  /*BITMAP 1*/
  if(bin_encode_pref == BIN_ASCII_ENC)
  {
    len = BM_LEN*2;
    exp = proto_tree_add_item(iso8583_tree, hf_iso8583_bitmap1, tvb,
        offset, len, ENC_ASCII|ENC_NA);
    if(!ishex_str((gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len , ENC_ASCII), len))
    {
      expert_add_info(pinfo, exp, &ei_iso8583_MALFORMED);
      return offset + len;
    }
  }
  else
  {
    gchar* hexstr;
    len = BM_LEN;
    hexstr = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, len);
    exp = proto_tree_add_string(iso8583_tree, hf_iso8583_bitmap1, tvb, offset, len, hexstr);
  }
  offset+=len;

  /*BITMAP 2*/
  if(nofbitmaps > 1)
  {
    if(bin_encode_pref == BIN_ASCII_ENC)
    {
      exp = proto_tree_add_item(iso8583_tree, hf_iso8583_bitmap2, tvb,
          offset, len, ENC_ASCII|ENC_NA);
      if(!ishex_str((gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len , ENC_ASCII), len))
      {
        expert_add_info(pinfo, exp, &ei_iso8583_MALFORMED);
        return offset + len;
      }
    }
    else
    {
      gchar* hexstr = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, len);
      exp = proto_tree_add_string(iso8583_tree, hf_iso8583_bitmap2, tvb, offset, len, hexstr);
    }
    offset+=len;
  }

  /*BITMAP 3*/
  if(nofbitmaps > 2)
  {
    expert_add_info(pinfo, exp, &ei_iso8583_MALFORMED);
    return offset;
  }

  /*DISSECT BITS*/
  ret = dissect_databits(tvb, pinfo, iso8583_tree, offset, nofbitmaps, bitmap);

  return ret;
}

static int dissect_iso8583(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_iso8583_msg_len, dissect_iso8583_msg, data);

  return tvb_captured_length(tvb);
}



void
proto_register_iso8583(void)
{
  module_t        *iso8583_module;
  expert_module_t *expert_iso8583;
  int              i;

  static hf_register_info hf[] = {
    { &hf_iso8583_len,
      { "Message length", "iso8583.len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Message length field", HFILL }
    },
    { &hf_iso8583_mti,
      { "MTI", "iso8583.mti",
        FT_STRING, STR_ASCII, NULL , 0,
        "Message Type Idicator (MTI)", HFILL }
    },
    { &hf_iso8583_bitmap1,
      { "Bitmap 1", "iso8583.map1",
        FT_STRING, STR_ASCII, NULL , 0,
        "First Bitmap (hex representation)", HFILL }
    },
    { &hf_iso8583_bitmap2,
      { "Bitmap 2", "iso8583.map2",
        FT_STRING, STR_ASCII, NULL , 0,
        "Second Bitmap (hex representation)", HFILL }
    }
  };

  static hf_register_info hf_data[128];

  static const char *hf_data_blurb[128] = {
    /* Bit 1 */
    "Second Bit map present",
    /* Bit 2 */
    "Primary account number (PAN)",
    /* Bit 3 */
    "Processing code",
    /* Bit 4 */
    "Amount, transaction",
    /* Bit 5 */
    "Amount, settlement",
    /* Bit 6 */
    "Amount, cardholder billing",
    /* Bit 7 */
    "Transmission date &amp",
    /* Bit 8 */
    "Amount, cardholder billing fee",
    /* Bit 9 */
    "Conversion rate, settlement",
    /* Bit 10 */
    "Conversion rate, cardholder billing",
    /* Bit 11 */
    "System trace audit number",
    /* Bit 12 */
    "Time, local transaction (hhmmss)",
    /* Bit 13 */
    "Date, local transaction (MMDD)",
    /* Bit 14 */
    "Date, expiration",
    /* Bit 15 */
    "Date, settlement",
    /* Bit 16 */
    "Date, conversion",
    /* Bit 17 */
    "Date, capture",
    /* Bit 18 */
    "Merchant type",
    /* Bit 19 */
    "Acquiring institution country code",
    /* Bit 20 */
    "PAN extended, country code",
    /* Bit 21 */
    "Forwarding institution. country code",
    /* Bit 22 */
    "Point of service entry mode",
    /* Bit 23 */
    "Application PAN sequence number",
    /* Bit 24 */
    "Function code (ISO 8583:1993)/Network International identifier (NII)",
    /* Bit 25 */
    "Point of service condition code",
    /* Bit 26 */
    "Point of service capture code",
    /* Bit 27 */
    "Authorizing identification response length",
    /* Bit 28 */
    "Amount, transaction fee",
    /* Bit 29 */
    "Amount, settlement fee",
    /* Bit 30 */
    "Amount, transaction processing fee",
    /* Bit 31 */
    "Amount, settlement processing fee",
    /* Bit 32 */
    "Acquiring institution identification code",
    /* Bit 33 */
    "Forwarding institution identification code",
    /* Bit 34 */
    "Primary account number, extended",
    /* Bit 35 */
    "Track 2 data",
    /* Bit 36 */
    "Track 3 data",
    /* Bit 37 */
    "Retrieval reference number",
    /* Bit 38 */
    "Authorization identification response",
    /* Bit 39 */
    "Response code",
    /* Bit 40 */
    "Service restriction code",
    /* Bit 41 */
    "Card acceptor terminal identification",
    /* Bit 42 */
    "Card acceptor identification code",
    /* Bit 43 */
    "Card acceptor name/location (1-23 address 24-36 city 37-38 state 39-40 country)",
    /* Bit 44 */
    "Additional response data",
    /* Bit 45 */
    "Track 1 data",
    /* Bit 46 */
    "Additional data - ISO",
    /* Bit 47 */
    "Additional data - national",
    /* Bit 48 */
    "Additional data - private",
    /* Bit 49 */
    "Currency code, transaction",
    /* Bit 50 */
    "Currency code, settlement",
    /* Bit 51 */
    "Currency code, cardholder billing",
    /* Bit 52 */
    "Personal identification number data",
    /* Bit 53 */
    "Security related control information",
    /* Bit 54 */
    "Additional amounts",
    /* Bit 55 */
    "Reserved ISO",
    /* Bit 56 */
    "Reserved ISO",
    /* Bit 57 */
    "Reserved national",
    /* Bit 58 */
    "Reserved national",
    /* Bit 59 */
    "Reserved national",
    /* Bit 60 */
    "Reserved national",
    /* Bit 61 */
    "Reserved private",
    /* Bit 62 */
    "Reserved private",
    /* Bit 63 */
    "Reserved private",
    /* Bit 64 */
    "Message authentication code (MAC)",
    /* Bit 65 */
    "Third Bitmap, extended",
    /* Bit 66 */
    "Settlement code",
    /* Bit 67 */
    "Extended payment code",
    /* Bit 68 */
    "Receiving institution country code",
    /* Bit 69 */
    "Settlement institution country code",
    /* Bit 70 */
    "Network management information code",
    /* Bit 71 */
    "Message number",
    /* Bit 72 */
    "Message number, last",
    /* Bit 73 */
    "Date, action (YYMMDD)",
    /* Bit 74 */
    "Credits, number",
    /* Bit 75 */
    "Credits, reversal number",
    /* Bit 76 */
    "Debits, number",
    /* Bit 77 */
    "Debits, reversal number",
    /* Bit 78 */
    "Transfer number",
    /* Bit 79 */
    "Transfer, reversal number",
    /* Bit 80 */
    "Inquiries number",
    /* Bit 81 */
    "Authorizations, number",
    /* Bit 82 */
    "Credits, processing fee amount",
    /* Bit 83 */
    "Credits, transaction fee amount",
    /* Bit 84 */
    "Debits, processing fee amount",
    /* Bit 85 */
    "Debits, transaction fee amount",
    /* Bit 86 */
    "Credits, amount",
    /* Bit 87 */
    "Credits, reversal amount",
    /* Bit 88 */
    "Debits, amount",
    /* Bit 89 */
    "Debits, reversal amount",
    /* Bit 90 */
    "Original data elements",
    /* Bit 91 */
    "File update code",
    /* Bit 92 */
    "File security code",
    /* Bit 93 */
    "Response indicator",
    /* Bit 94 */
    "Service indicator",
    /* Bit 95 */
    "Replacement amounts",
    /* Bit 96 */
    "Message security code",
    /* Bit 97 */
    "Amount, net settlement",
    /* Bit 98 */
    "Payee",
    /* Bit 99 */
    "Settlement institution identification code",
    /* Bit 100 */
    "Receiving institution identification code",
    /* Bit 101 */
    "File name",
    /* Bit 102 */
    "Account identification 1",
    /* Bit 103 */
    "Account identification 2",
    /* Bit 104 */
    "Transaction description",
    /* Bit 105 */
    "Reserved for ISO use",
    /* Bit 106 */
    "Reserved for ISO use",
    /* Bit 107 */
    "Reserved for ISO use",
    /* Bit 108 */
    "Reserved for ISO use",
    /* Bit 109 */
    "Reserved for ISO use",
    /* Bit 110 */
    "Reserved for ISO use",
    /* Bit 111 */
    "Reserved for ISO use",
    /* Bit 112 */
    "Reserved for national use",
    /* Bit 113 */
    "Reserved for national use",
    /* Bit 114 */
    "Reserved for national use",
    /* Bit 115 */
    "Reserved for national use",
    /* Bit 116 */
    "Reserved for national use",
    /* Bit 117 */
    "Reserved for national use",
    /* Bit 118 */
    "Reserved for national use",
    /* Bit 119 */
    "Reserved for national use",
    /* Bit 120 */
    "Reserved for private use",
    /* Bit 121 */
    "Reserved for private use",
    /* Bit 122 */
    "Reserved for private use",
    /* Bit 123 */
    "Reserved for private use",
    /* Bit 124 */
    "Reserved for private use",
    /* Bit 125 */
    "Reserved for private use",
    /* Bit 126 */
    "Reserved for private use",
    /* Bit 127 */
    "Reserved for private use",
    /* Bit 128 */
    "Message authentication code"
  };

  static gint *ett[] = {
    &ett_iso8583
  };

  static ei_register_info ei[] = {
    { &ei_iso8583_MALFORMED,
      { "iso8583.MALFORMED", PI_MALFORMED, PI_ERROR,
        "MALFORMED", EXPFILL }
    }
  };

  proto_iso8583 = proto_register_protocol("ISO 8583-1", "ISO 8583", "iso8583");

  /* Function calls to register the header fields and subtrees */
  proto_register_field_array(proto_iso8583, hf, array_length(hf));
  for (i = 0; i < 128; i++) {
    HFILL_INIT(hf_data[i]);
    hf_data[i].p_id = &iso8583_data_bit[i];
    hf_data[i].hfinfo.name = wmem_strdup_printf(wmem_epan_scope(), "Bit %d", i + 1);
    hf_data[i].hfinfo.abbrev = wmem_strdup_printf(wmem_epan_scope(), "iso8583.bit%d", i + 1);
    if(! i%64 ) /* bit 1 and bit 65 */
    {
      hf_data[i].hfinfo.type = FT_BOOLEAN;
      hf_data[i].hfinfo.display = 8;
    }
    else
    {
      hf_data[i].hfinfo.type = FT_STRING;
      hf_data[i].hfinfo.display = STR_ASCII;
    }
    hf_data[i].hfinfo.strings = NULL;
    hf_data[i].hfinfo.bitmask = 0;
    hf_data[i].hfinfo.blurb = hf_data_blurb[i];
  }
  proto_register_field_array(proto_iso8583, hf_data, array_length(hf_data));
  proto_register_subtree_array(ett, array_length(ett));

  expert_iso8583 = expert_register_protocol(proto_iso8583);
  expert_register_field_array(expert_iso8583, ei, array_length(ei));

  /* Register preferences module */
  iso8583_module = prefs_register_protocol(proto_iso8583,
      proto_reg_handoff_iso8583);

  prefs_register_enum_preference(iso8583_module, "len_endian",
      "Length field endian",
      "Endian of the length field. Big endian or Little endian",
      &len_byte_order,
      enumendians, TRUE);

  /* Register port preference */
  prefs_register_uint_preference(iso8583_module, "tcp.port",
      "iso8583 TCP Port",
      " iso8583 TCP port",
      10, &tcp_port_pref);

  prefs_register_enum_preference(iso8583_module, "charset",
      "Charset for numbers",
      " charset for numbers",
      &charset_pref, enum_charset, TRUE);

  prefs_register_enum_preference(iso8583_module, "binencode",
      "Binary encode",
      " binary data representation",
      &bin_encode_pref, enum_bin_encode, TRUE);
}

void proto_reg_handoff_iso8583(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t iso8583_handle;
  static int current_port;

  if (!initialized) {
    iso8583_handle = create_dissector_handle(dissect_iso8583,
        proto_iso8583);
    initialized = TRUE;

  } else {
    dissector_delete_uint("tcp.port", current_port, iso8583_handle);
  }

  current_port = tcp_port_pref;

  dissector_add_uint("tcp.port", current_port, iso8583_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
