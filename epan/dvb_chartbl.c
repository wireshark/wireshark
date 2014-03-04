/* dvb_chartbl.c
 * Routines for handling DVB-SI character tables (as defined in EN 300 468)
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

#include "config.h"

#include <glib.h>

#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/value_string.h>

#include "dvb_chartbl.h"


static const value_string dvb_string_encoding_vals[] = {
   { DVB_ENCODING_INVALID,  "Incorrect length for encoding" },
   { DVB_ENCODING_RESERVED, "Reserved for future use" },
   { DVB_ENCODING_UNKNOWN,  "Unknown/undefined encoding" },

   { DVB_ENCODING_LATIN,    "Latin (default table)" },

   { DVB_ENCODING_ISO_8859_1,         "ISO/IEC 8859-1 (West European)" },
   { DVB_ENCODING_ISO_8859_2,         "ISO/IEC 8859-2 (East European)" },
   { DVB_ENCODING_ISO_8859_3,         "ISO/IEC 8859-3 (South European)" },
   { DVB_ENCODING_ISO_8859_4,         "ISO/IEC 8859-4 (North and North-East European)" },
   { DVB_ENCODING_ISO_8859_5,         "ISO/IEC 8859-5 (Latin/Cyrillic)" },
   { DVB_ENCODING_ISO_8859_6,         "ISO/IEC 8859-6 (Latin/Arabic)" },
   { DVB_ENCODING_ISO_8859_7,         "ISO/IEC 8859-7 (Latin/Greek)" },
   { DVB_ENCODING_ISO_8859_8,         "ISO/IEC 8859-8 (Latin/Hebrew)" },
   { DVB_ENCODING_ISO_8859_9,         "ISO/IEC 8859-9 (West European & Turkish)" },
   { DVB_ENCODING_ISO_8859_10,        "ISO/IEC 8859-10 (North European)" },
   { DVB_ENCODING_ISO_8859_11,        "ISO/IEC 8859-11 (Thai)" },
   { DVB_ENCODING_ISO_8859_13,        "ISO/IEC 8859-13 (Baltic)" },
   { DVB_ENCODING_ISO_8859_14,        "ISO/IEC 8859-14 (Celtic)" },
   { DVB_ENCODING_ISO_8859_15,        "ISO/IEC 8859-15 (West European)" },
   { DVB_ENCODING_ISO_10646_BMP,      "ISO/IEC 10646 Basic Multilingual Plane" },
   { DVB_ENCODING_KSX_1001,           "KSX 1001-2004 (Korean character set)" },
   { DVB_ENCODING_GB_2312,            "GB-2312-1980 (Simplified Chinese)" },
   { DVB_ENCODING_ISO_10646_BIG5,     "ISO/IEC 10646 BIG5 subset" },
   { DVB_ENCODING_ISO_10646_UTF8_BMP,
       "ISO/IEC 10646 Basic Multilingual Plane, UTF-8 encoded" },

   { 0, NULL }
};


static dvb_encoding_e
dvb_analyze_string_charset0(guint8 byte0)
{
    switch (byte0) {
        case 0x01:
            return DVB_ENCODING_ISO_8859_5;
        case 0x02:
            return DVB_ENCODING_ISO_8859_6;
        case 0x03:
            return DVB_ENCODING_ISO_8859_7;
        case 0x04:
            return DVB_ENCODING_ISO_8859_8;
        case 0x05:
            return DVB_ENCODING_ISO_8859_9;
        case 0x06:
            return DVB_ENCODING_ISO_8859_10;
        case 0x07:
            return DVB_ENCODING_ISO_8859_11;
        case 0x08:
            return DVB_ENCODING_RESERVED; /* was reserved for ISO-8859-12 */
        case 0x09:
            return DVB_ENCODING_ISO_8859_13;
        case 0x0A:
            return DVB_ENCODING_ISO_8859_14;
        case 0x0B:
            return DVB_ENCODING_ISO_8859_15;
        case 0x11:
            return DVB_ENCODING_ISO_10646_BMP;
        case 0x12:
            return DVB_ENCODING_KSX_1001;
        case 0x13:
            return DVB_ENCODING_GB_2312;
        case 0x14:
            return DVB_ENCODING_ISO_10646_BIG5;
        case 0x15:
            return DVB_ENCODING_ISO_10646_UTF8_BMP;

        default:
            return DVB_ENCODING_UNKNOWN;
    }
}


static dvb_encoding_e
dvb_analyze_string_charset0_10(guint16 byte12)
{
    switch (byte12) {
        case 0x0000:
             return DVB_ENCODING_RESERVED;
        case 0x0001:
         return DVB_ENCODING_ISO_8859_1;
        case 0x0002:
         return DVB_ENCODING_ISO_8859_2;
        case 0x0003:
         return DVB_ENCODING_ISO_8859_3;
        case 0x0004:
         return DVB_ENCODING_ISO_8859_4;
        case 0x0005:
         return DVB_ENCODING_ISO_8859_5;
        case 0x0006:
         return DVB_ENCODING_ISO_8859_6;
        case 0x0007:
         return DVB_ENCODING_ISO_8859_7;
        case 0x0008:
         return DVB_ENCODING_ISO_8859_8;
        case 0x0009:
         return DVB_ENCODING_ISO_8859_9;
        case 0x000A:
         return DVB_ENCODING_ISO_8859_10;
        case 0x000B:
         return DVB_ENCODING_ISO_8859_11;
        case 0x000C:
         return DVB_ENCODING_RESERVED;
        case 0x000D:
         return DVB_ENCODING_ISO_8859_13;
        case 0x000E:
         return DVB_ENCODING_ISO_8859_14;
        case 0x000F:
         return DVB_ENCODING_ISO_8859_15;

        default: /* 0x10 XX XX */
            return DVB_ENCODING_UNKNOWN;
    }
}


static dvb_encoding_e
dvb_analyze_string_charset0_1F(guint8 byte1)
{
   /* http://www.dvbservices.com/identifiers/encoding_type_id */

    switch (byte1) {
       case 0x00: /* 0x1F 0x00 */
          return DVB_ENCODING_RESERVED;
       case 0x01:
       case 0x02:
       case 0x03:
       case 0x04:
          /* XXX: BBC */
          return DVB_ENCODING_RESERVED;
       case 0x05:
       case 0x06:
          /* XXX: Malaysian Technical Standards Forum Bhd */
          return DVB_ENCODING_RESERVED;

       default: /* 0x1F XX */
          return DVB_ENCODING_RESERVED;
    }
}


guint
dvb_analyze_string_charset(tvbuff_t *tvb, int offset, int length, dvb_encoding_e *encoding)
{
   if (length >= 1) {
      guint8 byte0 = tvb_get_guint8(tvb, offset + 0);

      if (byte0 >= 0x20) {
         /* the first byte is a normal character, not the number of a character table */
         *encoding = DVB_ENCODING_LATIN;
         return 0;

      } else if (byte0 == 0x1F) {
         if (length >= 2) {
            *encoding = dvb_analyze_string_charset0_1F(tvb_get_guint8(tvb, offset + 1));
            return 2;
         }
         *encoding = DVB_ENCODING_INVALID;
         return 1;

      } else if (byte0 >= 0x16) { /* 16 ... 1E */
         *encoding = DVB_ENCODING_RESERVED;
         return 1;

      } else if (byte0 == 0x10) {
         if (length >= 3) {
            *encoding = dvb_analyze_string_charset0_10(tvb_get_ntohs(tvb, offset + 1));
            return 3;
         }
         *encoding = DVB_ENCODING_INVALID;
         return 1;

      } else if ((byte0 >= 0x0C && byte0 <= 0x0F)) {
         *encoding = DVB_ENCODING_RESERVED;
         return 1;
      } else {
         *encoding = dvb_analyze_string_charset0(byte0);
         return 1;
      }
   } else
      *encoding = DVB_ENCODING_LATIN;

   return 0;
}


guint
dvb_enc_to_item_enc(dvb_encoding_e encoding)
{
   /* XXX: take ISO control codes into account,
      e.g. 0x86 - turn emphasis on ; 0x87 - turn emphasis off */

   switch (encoding) {
      case DVB_ENCODING_ISO_8859_1:
         return ENC_ISO_8859_1 | ENC_NA;

      case DVB_ENCODING_ISO_8859_2:
         return ENC_ISO_8859_2 | ENC_NA;

      case DVB_ENCODING_ISO_8859_3:
         return ENC_ISO_8859_3 | ENC_NA;

      case DVB_ENCODING_ISO_8859_4:
         return ENC_ISO_8859_4 | ENC_NA;

      case DVB_ENCODING_ISO_8859_5:
         return ENC_ISO_8859_5 | ENC_NA;

      case DVB_ENCODING_ISO_8859_6:
         return ENC_ISO_8859_6 | ENC_NA;

      case DVB_ENCODING_ISO_8859_7:
         return ENC_ISO_8859_7 | ENC_NA;

      case DVB_ENCODING_ISO_8859_8:
         return ENC_ISO_8859_8 | ENC_NA;

      case DVB_ENCODING_ISO_8859_9:
         return ENC_ISO_8859_9 | ENC_NA;

      case DVB_ENCODING_ISO_8859_10:
         return ENC_ISO_8859_10 | ENC_NA;

      case DVB_ENCODING_ISO_8859_11:
         return ENC_ISO_8859_11 | ENC_NA;

      case DVB_ENCODING_ISO_8859_13:
         return ENC_ISO_8859_13 | ENC_NA;

      case DVB_ENCODING_ISO_8859_14:
         return ENC_ISO_8859_14 | ENC_NA;

      case DVB_ENCODING_ISO_8859_15:
         return ENC_ISO_8859_15 | ENC_NA;

      case DVB_ENCODING_ISO_10646_UTF8_BMP:
         return ENC_UTF_8 | ENC_NA;

      default: /* not supported */
         return ENC_ASCII | ENC_NA;
   }
}


void
dvb_add_chartbl(proto_tree *tree, int hf,
        tvbuff_t *tvb, gint offset, gint length, dvb_encoding_e encoding)
{
    if (length==0) {
        proto_item *pi;

        pi = proto_tree_add_text(tree, NULL, 0, 0,
                "Default character table (Latin)");
        PROTO_ITEM_SET_GENERATED(pi);
    }
    else {
        proto_tree_add_bytes_format_value(tree, hf,
            tvb, offset, length, NULL, "%s (%s)",
            val_to_str_const(encoding, dvb_string_encoding_vals, "Unknown"),
            bytes_to_ep_str_punct(
                tvb_get_ptr(tvb, offset, length), length, ' '));
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
