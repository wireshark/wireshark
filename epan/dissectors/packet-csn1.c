/* packet-csn1.c
 * Routines for CSN1 dissection in wireshark.
 * By Vincent Helfre, based on original code by Jari Sassi
 * with the gracious authorization of STE
 * Copyright (c) 2011 ST-Ericsson
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
#include <epan/packet.h>
#include <epan/to_str.h>
#include "packet-csn1.h"

#define pvDATA(_pv, _offset) ((void*) ((unsigned char*)_pv + _offset))
#define pui8DATA(_pv, _offset) ((guint8*) pvDATA(_pv, _offset))
#define pui16DATA(_pv, _offset) ((guint16*) pvDATA(_pv, _offset))
#define pui32DATA(_pv, _offset) ((guint32*) pvDATA(_pv, _offset))

/* used to tag existence of next element in variable length lists */
#define STANDARD_TAG 1
#define REVERSED_TAG 0


static const unsigned char ixBitsTab[] = {0, 1, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5};


/* Returns no_of_bits (up to 8) masked with 0x2B */
static guint8
tvb_get_masked_bits8(tvbuff_t *tvb, gint bit_offset,  const gint no_of_bits)
{
  static const guint8 maskBits[] = {0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF};
  gint byte_offset = bit_offset >> 3;          /* divide by 8 */
  gint relative_bit_offset = bit_offset & 0x07;  /* modulo 8 */
  guint8 result;
  gint bit_shift = 8 - relative_bit_offset - (gint) no_of_bits;

  if (bit_shift >= 0)
  {
    result = (0x2B ^ tvb_get_guint8(tvb, byte_offset)) >> bit_shift;
    result &= maskBits[no_of_bits];
  }
  else
  {
    guint8 hight_part = (0x2B ^ tvb_get_guint8(tvb, byte_offset)) & maskBits[8 - relative_bit_offset];
    hight_part = (guint8) (hight_part << (-bit_shift));
    result =  (0x2B ^ tvb_get_guint8(tvb, byte_offset+1)) >> (8 + bit_shift);
    result |= hight_part;
  }
  return result;
}

/**
 * ================================================================================================
 * set initial/start values in help data structure used for packing/unpacking operation
 * ================================================================================================
 */
void
csnStreamInit(csnStream_t* ar, gint bit_offset, gint remaining_bits_len)
{
  ar->remaining_bits_len  = remaining_bits_len;
  ar->bit_offset          = bit_offset;
}

static const char* ErrCodes[] =
{
  "General 0",
  "General -1",
  "DATA_NOT VALID",
  "IN SCRIPT",
  "INVALID UNION INDEX",
  "NEED_MORE BITS TO UNPACK",
  "ILLEGAL BIT VALUE",
  "Internal",
  "STREAM_NOT_SUPPORTED",
  "MESSAGE_TOO_LONG"
};

static gint16
ProcessError(proto_tree *tree, tvbuff_t *tvb, gint bit_offset, const unsigned char* sz, gint16 err, const CSN_DESCR* pDescr)
{
  gint16 i = MIN(-err, ((gint16) ElementsOf(ErrCodes)-1));
  if (i >= 0)
  {
    proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "ERROR %s %s (%s)", sz, ErrCodes[i], pDescr?pDescr->sz:"-");
  }
  else
  {
    proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "ERROR %s (%s)", sz, pDescr?pDescr->sz:"-");
  }

  return err;
}

#if 0
static const char* CSN_DESCR_type[]=
{
  "CSN_END",
  "CSN_BIT",
  "CSN_UINT",
  "CSN_TYPE",
  "CSN_CHOICE",
  "CSN_UNION",
  "CSN_UNION_LH",
  "CSN_UINT_ARRAY",
  "CSN_TYPE_ARRAY",
  "CSN_BITMAP",
  "CSN_VARIABLE_BITMAP",
  "CSN_VARIABLE_BITMAP_1",
  "CSN_LEFT_ALIGNED_VAR_BMP",
  "CSN_LEFT_ALIGNED_VAR_BMP_1",
  "CSN_VARIABLE_ARRAY",
  "CSN_VARIABLE_TARRAY",
  "CSN_VARIABLE_TARRAY_OFFSET",
  "CSN_RECURSIVE_ARRAY",
  "CSN_RECURSIVE_TARRAY",
  "CSN_RECURSIVE_TARRAY_1",
  "CSN_RECURSIVE_TARRAY_2",
  "CSN_EXIST",
  "CSN_EXIST_LH",
  "CSN_NEXT_EXIST",
  "CSN_NEXT_EXIST_LH",
  "CSN_NULL",
  "CSN_FIXED",
  "CSN_CALLBACK",
  "CSN_UINT_OFFSET",
  "CSN_UINT_LH",
  "CSN_SERIALIZE",
  "CSN_TRAP_ERROR"
  "CSN_???"
};
#endif

/**
 * ================================================================================================
 * Return TRUE if tag in bit stream indicates existence of next list element,
 * otherwise return FALSE.
 * Will work for tag values equal to both 0 and 1.
 * ================================================================================================
 */

static gboolean
existNextElement(tvbuff_t *tvb, gint bit_offset, guint8 Tag)
{
  guint8 res = tvb_get_bits8(tvb, bit_offset, 1);
  if (Tag == STANDARD_TAG)
  {
    return (res > 0);
  }
  return (res == 0);
}


gint16
csnStreamDissector(proto_tree *tree, csnStream_t* ar, const CSN_DESCR* pDescr, tvbuff_t *tvb, void* data, int ett_csn1)
{
  gint  remaining_bits_len = ar->remaining_bits_len;
  gint  bit_offset         = ar->bit_offset;
  guint8*  pui8 = NULL;
  guint16* pui16;
  guint32* pui32;
  guint8 Tag = STANDARD_TAG;

  if (remaining_bits_len <= 0)
  {
    return 0;
  }

  do
  {
    switch (pDescr->type)
    {
      case CSN_BIT:
      {
        if (remaining_bits_len > 0)
        {
          pui8  = pui8DATA(data, pDescr->offset);

          *pui8 = tvb_get_bits8(tvb, bit_offset, 1);
          proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s %s",
                                     decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)),
                                     pDescr->sz);

          /* end add the bit value to protocol tree */
        }
        else if(pDescr->may_be_null)
        {
            *pui8 = 0;
            proto_tree_add_text(tree, tvb, 0, 0, "[NULL data]: %s Not Present", pDescr->sz);
        }
        else
        {
          return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        pDescr++;
        remaining_bits_len--;
        bit_offset++;
        break;
      }

      case CSN_NULL:
      { /* Empty member! */
        bit_offset += pDescr->i;
        pDescr++;
        break;
      }

      case CSN_UINT:
      {
        guint8 no_of_bits = (guint8) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
            guint8 ui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = ui8;
            proto_tree_add_bits_item(tree, *(pDescr->format_p.hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else if (no_of_bits <= 16)
          {
            guint16 ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
            pui16       = pui16DATA(data, pDescr->offset);
            *pui16      = ui16;
            proto_tree_add_bits_item(tree, *(pDescr->format_p.hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else if (no_of_bits <= 32)
          {
            guint32 ui32 = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
            pui32       = pui32DATA(data, pDescr->offset);
            *pui32      = ui32;
            proto_tree_add_bits_item(tree, *(pDescr->format_p.hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
          }
        remaining_bits_len -= no_of_bits;
        bit_offset += no_of_bits;
        }
        else if(pDescr->may_be_null)
        {
            if (no_of_bits <= 8)
            {
              pui8      = pui8DATA(data, pDescr->offset);
              *pui8     = 0;
            }
            else if (no_of_bits <= 16)
            {
              pui16      = pui16DATA(data, pDescr->offset);
              *pui16     = 0;
            }
            else if (no_of_bits <= 32)
            {
              pui32      = pui32DATA(data, pDescr->offset);
              *pui32     = 0;
            }
            proto_tree_add_text(tree, tvb, 0, 0, "[NULL data]: %s Not Present", pDescr->sz);
        }
        else
        {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        pDescr++;
        break;
      }

      case CSN_UINT_OFFSET:
      {
        guint8 no_of_bits = (guint8) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
            guint8 ui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = ui8 + (guint8)pDescr->descr.value;

            proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s (%d)",
                                       decode_bits_in_field(bit_offset, no_of_bits, ui8),
                                       pDescr->sz, ui8);

          }
          else if (no_of_bits <= 16)
          {
            guint16 ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
            pui16       = pui16DATA(data, pDescr->offset);
            *pui16      = ui16 + (guint16)pDescr->descr.value;

            proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s (%d)",
                                       decode_bits_in_field(bit_offset, no_of_bits, ui16),
                                       pDescr->sz, ui16);
          }
          else if (no_of_bits <= 32)
          {
            guint32 ui32 = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
            pui32       = pui32DATA(data, pDescr->offset);
            *pui32      = ui32 + (guint16)pDescr->descr.value;

            proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s (%d)",
                                       decode_bits_in_field(bit_offset, no_of_bits, ui32),
                                       pDescr->sz, ui32);
          }
          else
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
          }
        }
        else
        {
          return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        remaining_bits_len -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

      case CSN_UINT_LH:
      {
        guint8 no_of_bits = (guint8) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
            guint8 ui8 = tvb_get_masked_bits8(tvb, bit_offset, no_of_bits);
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = ui8;
            proto_tree_add_bits_item(tree, *(pDescr->format_p.hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);

          }
          else
          {/* Maybe we should support more than 8 bits ? */
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
          }
        }
        else
        {
          return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        remaining_bits_len -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

        case CSN_SPLIT_BITS:
        {
          guint8 no_of_value_bits = (guint8) pDescr->i;
          guint64 value;

          proto_tree_add_split_bits_item_ret_val(tree, *pDescr->format_p.hf_ptr, tvb, bit_offset, pDescr->descr.crumb_spec, &value);
          if (no_of_value_bits <= 8)
          {
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = (guint8)value;
          }
          else if (no_of_value_bits <= 16)
          {
            pui16       = pui16DATA(data, pDescr->offset);
            *pui16      = (guint16)value;
          }
          else if (no_of_value_bits <= 32)
          {
            pui32       = pui32DATA(data, pDescr->offset);
            *pui32      = (guint32)value;
          }
          else
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
          }

          pDescr++;
          break;
        }

        case CSN_SPLIT_BITS_CRUMB:
        {
          if (remaining_bits_len >= pDescr->descr.crumb_spec[pDescr->i].crumb_bit_length)
          {
             proto_tree_add_split_bits_crumb(tree, *pDescr->format_p.hf_ptr, tvb, bit_offset,
                                             pDescr->descr.crumb_spec, pDescr->i);

          remaining_bits_len -= pDescr->descr.crumb_spec[pDescr->i].crumb_bit_length;
          bit_offset += pDescr->descr.crumb_spec[pDescr->i].crumb_bit_length;
          }
          else
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          pDescr++;
          break;
        }

      case CSN_UINT_ARRAY:
      {
        guint8  no_of_bits  = (guint8) pDescr->i;
        guint16 nCount = (guint16)pDescr->descr.value; /* nCount supplied by value i.e. M_UINT_ARRAY(...) */
        int i =0;

        if (pDescr->format_p.value != 0)
        { /* nCount specified by a reference to field holding value i.e. M_VAR_UINT_ARRAY(...) */
          nCount = *pui16DATA(data, nCount);
        }

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
            pui8 = pui8DATA(data, pDescr->offset);
            do
            {
              *pui8++ = tvb_get_bits8(tvb, bit_offset, no_of_bits);

              proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s[%d]",
                                         decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits8(tvb, bit_offset, no_of_bits)),
                                         pDescr->sz,
                                         i++);
              remaining_bits_len -= no_of_bits;
              bit_offset += no_of_bits;
            } while (--nCount > 0);
          }
          else if (no_of_bits <= 16)
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector NOTIMPLEMENTED", 999, pDescr);
          }
          else if (no_of_bits <= 32)
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector NOTIMPLEMENTED", 999, pDescr);
          }
          else
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
          }
        }
        else
        {
          return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }
        pDescr++;
        break;
      }

      case CSN_VARIABLE_TARRAY_OFFSET:
      case CSN_VARIABLE_TARRAY:
      case CSN_TYPE_ARRAY:
      {
        gint16      Status;
        csnStream_t arT    = *ar;
        gint16      nCount = pDescr->i;
        guint16      nSize  = (guint16)(gint32)pDescr->format_p.value;
        int i =0;

        pui8 = pui8DATA(data, pDescr->offset);
        if (pDescr->type == CSN_VARIABLE_TARRAY)
        { /* Count specified in field */
          nCount = *pui8DATA(data, pDescr->i);
        }
        else if (pDescr->type == CSN_VARIABLE_TARRAY_OFFSET)
        { /* Count specified in field */
          nCount = *pui8DATA(data, pDescr->i);
          /*  nCount--; the 1 offset is already taken into account in CSN_UINT_OFFSET */
        }

        while (nCount > 0)
        { /* resulting array of length 0 is possible
           * but no bits shall be read from bitstream
           */
          proto_item   *ti;
          proto_tree   *test_tree;

          ti = proto_tree_add_text(tree, tvb, bit_offset>>3, 1,  "%s[%d]",pDescr->sz, i++);
          test_tree = proto_item_add_subtree(ti, ett_csn1);

          csnStreamInit(&arT, bit_offset, remaining_bits_len);
          Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR*)pDescr->descr.ptr, tvb, pui8, ett_csn1);
          if (Status >= 0)
          {
            pui8    += nSize;
            proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
            remaining_bits_len = arT.remaining_bits_len;
            bit_offset         = arT.bit_offset;

          }
          else
          {
            return Status;
          }
          nCount--;
        }

        pDescr++;
        break;
      }

      case CSN_BITMAP:
      { /* bitmap with given length. The result is left aligned! */
        guint8 no_of_bits = (guint8) pDescr->i; /* length of bitmap */

        if (no_of_bits > 0)
        {

          if (no_of_bits <= 32)
          {
            proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s",
                                     decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN)),
                                     pDescr->sz);
          }
          else if (no_of_bits <= 64)
          {
            proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s",
                                     decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits64(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN)),
                                     pDescr->sz);
          }
          else
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector NOT IMPLEMENTED", 999, pDescr);
          }

          remaining_bits_len -= no_of_bits;
          DISSECTOR_ASSERT(remaining_bits_len >= 0);
          bit_offset += no_of_bits;
        }
        /* bitmap was successfully extracted or it was empty */

        pDescr++;
        break;
      }

      case CSN_TYPE:
      {
        gint16      Status;
        csnStream_t arT = *ar;
        proto_item   *ti;
        proto_tree   *test_tree;

        ti = proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s", pDescr->sz);
        test_tree = proto_item_add_subtree(ti, ett_csn1);

        csnStreamInit(&arT, bit_offset, remaining_bits_len);
        Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR*)pDescr->descr.ptr, tvb, pvDATA(data, pDescr->offset), ett_csn1);

        if (Status >= 0)
        {
          proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
          remaining_bits_len  = arT.remaining_bits_len;
          bit_offset          = arT.bit_offset;
          pDescr++;
        }
        else
        {
          /* Has already been processed: ProcessError("csnStreamDissector", Status, pDescr);  */
          return Status;
        }

        break;
      }

      case CSN_CHOICE:
      {
        gint16 count = pDescr->i;
        guint8 i     = 0;
        const CSN_ChoiceElement_t* pChoice = (const CSN_ChoiceElement_t*) pDescr->descr.ptr;

        while (count > 0)
        {
          guint8 no_of_bits = pChoice->bits;
          guint8 value = tvb_get_bits8(tvb, bit_offset, no_of_bits);

          if (value == pChoice->value)
          {
            CSN_DESCR   descr[2];
            gint16      Status;
            csnStream_t arT = *ar;
            proto_item   *ti = NULL;
            proto_tree   *test_tree;

            descr[0]      = pChoice->descr;
            memset(&descr[1], 0x00, sizeof(CSN_DESCR));
            descr[1].type = CSN_END;
            pui8          = pui8DATA(data, pDescr->offset);
            *pui8         = i;

            if (pDescr->sz) {
              proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s Choice: %s (%d)",
                                         decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits8(tvb, bit_offset, no_of_bits)),
                                         pDescr->sz, value);
            }

            if (!pChoice->keep_bits) {
              bit_offset += no_of_bits;
              remaining_bits_len -= no_of_bits;
            }

            if (pDescr->sz) {
              ti = proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s", pDescr->sz);
              test_tree = proto_item_add_subtree(ti, ett_csn1);
            } else {
              test_tree = tree;
            }

            csnStreamInit(&arT, bit_offset, remaining_bits_len);
            Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR*)descr, tvb, data, ett_csn1);

            if (Status >= 0)
            {
              if (ti)
                proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
              remaining_bits_len = arT.remaining_bits_len;
              bit_offset         = arT.bit_offset;
            }
            else
            {
              return Status;
            }
            break;
          }

          count--;
          pChoice++;
          i++;
        }

        pDescr++;
        break;
      }

      case CSN_SERIALIZE:
      {
        StreamSerializeFcn_t serialize = (StreamSerializeFcn_t)pDescr->aux_fn;
        csnStream_t          arT       = *ar;
        guint length_len = pDescr->i;
        gint16               Status = -1;
        proto_item   *ti;
        proto_tree   *test_tree;
        guint8 length = 0;

        if (length_len) {
          length = tvb_get_bits8(tvb, bit_offset, length_len);

          proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+length_len-1)>>3)-(bit_offset>>3)+1, "%s %s length: %d",
                              decode_bits_in_field(bit_offset, length_len, length),
                              pDescr->sz, length);

          bit_offset += length_len;
          remaining_bits_len -= length_len;

          ti = proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+length-1)>>3)-(bit_offset>>3) + 1, "%s", pDescr->sz);
        } else {
          ti = proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s", pDescr->sz);
        }

        test_tree = proto_item_add_subtree(ti, ett_csn1);

        csnStreamInit(&arT, bit_offset, length > 0 ? length : remaining_bits_len);
        Status = serialize(test_tree, &arT, tvb, pvDATA(data, pDescr->offset), ett_csn1);

        if (Status >= 0)
        {
          if (length > 0) {
            remaining_bits_len -= length;
            bit_offset         += length;
          } else {
            proto_item_set_len(ti,((arT.bit_offset - bit_offset)>>3)+1);
            remaining_bits_len = arT.remaining_bits_len;
            bit_offset         = arT.bit_offset;
          }
          pDescr++;
        }
        else
        {
          /* Has already been processed: */
          return Status;
        }

        break;
      }

      case CSN_UNION_LH:
      case CSN_UNION:
      {
        gint16           Bits;
        guint8           t_index;
        gint16           count      = pDescr->i;
        const CSN_DESCR* pDescrNext = pDescr;

        pDescrNext += count + 1; /* now this is next after the union */
        if ((count <= 0) || (count > 16))
        {
          return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_INVALID_UNION_INDEX, pDescr);
        }

        /* Now get the bits to extract the index */
        Bits = ixBitsTab[count];
        proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+Bits-1)>>3)-(bit_offset>>3)+1, "%s Union:%s",
                                   decode_bits_in_field(bit_offset, Bits, tvb_get_bits8(tvb, bit_offset, Bits)),
                                   pDescr->sz);
        t_index = 0;

        while (Bits > 0)
        {
          t_index <<= 1;

          if (CSN_UNION_LH == pDescr->type)
          {
            t_index |= tvb_get_masked_bits8(tvb, bit_offset, 1);
          }
          else
          {
            t_index |= tvb_get_bits8(tvb, bit_offset, 1);
          }

          remaining_bits_len--;
          bit_offset++;
          Bits--;
        }

        /* Assign UnionType */
        pui8  = pui8DATA(data, pDescr->offset);
        *pui8 = t_index;


        /* script index to continue on, limited in case we do not have a power of 2 */
        pDescr += (MIN(t_index + 1, count));


        switch (pDescr->type)
        { /* get the right element of the union based on computed index */

          case CSN_BIT:
          {
            pui8  = pui8DATA(data, pDescr->offset);

            proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s %s",
                                   decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)),
                                   pDescr->sz);

            *pui8 = 0x00;
            if (tvb_get_bits8(tvb, bit_offset, 1) > 0)
            {
              *pui8 = 0x01;
            }
            remaining_bits_len --;
            bit_offset++;
            pDescr++;
            break;
          }

          case CSN_NULL:
          { /* Empty member! */
            bit_offset += pDescr->i;
            pDescr++;
            break;
          }

          case CSN_UINT:
          {
            guint8 no_of_bits = (guint8) pDescr->i;
            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
                guint8 ui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
                pui8      = pui8DATA(data, pDescr->offset);
                *pui8     = ui8;
                proto_tree_add_bits_item(tree, *(pDescr->format_p.hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);

              }
              else if (no_of_bits <= 16)
              {
                guint16 ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
                pui16       = pui16DATA(data, pDescr->offset);
                *pui16      = ui16;
                proto_tree_add_bits_item(tree, *(pDescr->format_p.hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
              }
              else if (no_of_bits <= 32)
              {
                guint32 ui32 = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
                pui32       = pui32DATA(data, pDescr->offset);
                *pui32      = ui32;
                proto_tree_add_bits_item(tree, *(pDescr->format_p.hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);

              }
              else
              {
                return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
              }
            }
            else
            {
              return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_OFFSET:
          {
            guint8 no_of_bits = (guint8) pDescr->i;

            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
            {
              guint8 ui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
              pui8      = pui8DATA(data, pDescr->offset);
              *pui8     = ui8 + (guint8)pDescr->descr.value;
              proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s (%d)",
                                         decode_bits_in_field(bit_offset, no_of_bits, ui8),
                                         pDescr->sz, ui8);
            }
            else if (no_of_bits <= 16)
            {
              guint16 ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
              pui16       = pui16DATA(data, pDescr->offset);
              *pui16      = ui16 + (guint16)pDescr->descr.value;
              proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s (%d)",
                                         decode_bits_in_field(bit_offset, no_of_bits, ui16),
                                         pDescr->sz, ui16);
            }
              else if (no_of_bits <= 32)
            {
              guint32 ui32 = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
              pui32       = pui32DATA(data, pDescr->offset);
              *pui32      = ui32 + (guint16)pDescr->descr.value;
              proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s (%d)",
                                         decode_bits_in_field(bit_offset, no_of_bits, ui32),
                                         pDescr->sz, ui32);
              }
              else
              {
                return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
              }
            }
            else
            {
              return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_LH:
          {
            guint8 no_of_bits = (guint8) pDescr->i;

            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
                guint8 ui8 = tvb_get_masked_bits8(tvb, bit_offset, no_of_bits);
                pui8      = pui8DATA(data, pDescr->offset);
                *pui8     = ui8;
                proto_tree_add_bits_item(tree, *(pDescr->format_p.hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
              }
              else
              { /* Maybe we should support more than 8 bits ? */
                return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
              }
            }
            else
            {
              return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_ARRAY:
          {
            guint8  no_of_bits  = (guint8) pDescr->i;
            guint16 nCount = (guint16)pDescr->descr.value; /* nCount supplied by value i.e. M_UINT_ARRAY(...) */
            gint i = 0;

            if (pDescr->format_p.value != 0)
            { /* nCount specified by a reference to field holding value i.e. M_VAR_UINT_ARRAY(...) */
              nCount = *pui16DATA(data, nCount);
            }

            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
                pui8 = pui8DATA(data, pDescr->offset);

                while (nCount > 0)
                {
                  *pui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
                  proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s[%d]",
                                             decode_bits_in_field(bit_offset, no_of_bits, *pui8),
                                             pDescr->sz,
                                             i++);
                  pui8++;
                  remaining_bits_len -= no_of_bits;
                  bit_offset += no_of_bits;
                  nCount--;
                }
              }
              else if (no_of_bits <= 16)
              {
                pui16 = pui16DATA(data, pDescr->offset);

                while (nCount > 0)
                {
                  *pui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
                  proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s[%d]",
                                             decode_bits_in_field(bit_offset, no_of_bits, *pui16),
                                             pDescr->sz,
                                             i++);
                  remaining_bits_len -= no_of_bits;
                  bit_offset += no_of_bits;
                  nCount--;
                }
              }
              else if (no_of_bits <= 32)
              { /* not supported */
                return ProcessError(tree, tvb, bit_offset,"csnStreamDissector NOT IMPLEMENTED", 999, pDescr);
              }
              else
              {
                return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_GENERAL, pDescr);
              }
            }
            else
            {
              return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
            }

            pDescr++;
            break;
          }

          case CSN_VARIABLE_TARRAY_OFFSET:
          case CSN_VARIABLE_TARRAY:
          case CSN_TYPE_ARRAY:
          {
            gint16      Status;
            csnStream_t arT    = *ar;
            guint16      nCount = (guint16) pDescr->i;
            guint16      nSize  = (guint16)(guint32)pDescr->format_p.value;
            gint i = 0;

            pui8  = pui8DATA(data, pDescr->offset);

            if (CSN_VARIABLE_TARRAY == pDescr->type)
            { /* Count specified in field */
              nCount = *pui8DATA(data, pDescr->i);
            }
            else if (CSN_VARIABLE_TARRAY_OFFSET == pDescr->type)
            { /* Count specified in field */
              nCount = *pui8DATA(data, pDescr->i);
              nCount--; /* Offset 1 */
            }

            while (nCount--)    /* Changed to handle length = 0.  */
            {
              proto_item   *ti;
              proto_tree   *test_tree;

              ti = proto_tree_add_text(tree, tvb, bit_offset>>3, 1,  "%s[%d]",pDescr->sz, i++);
              test_tree = proto_item_add_subtree(ti, ett_csn1);

              csnStreamInit(&arT, bit_offset, remaining_bits_len);
              Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR *)pDescr->descr.ptr, tvb, pui8, ett_csn1);
              if (Status >= 0)
              {
                pui8    += nSize;
                proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
                remaining_bits_len = arT.remaining_bits_len;
                bit_offset         = arT.bit_offset;
              }
              else
              {
                return Status;
              }
            }

            pDescr++;
            break;
          }

          case CSN_BITMAP:
          { /* bitmap with given length. The result is left aligned! */
            guint8 no_of_bits = (guint8) pDescr->i; /* length of bitmap */

            if (no_of_bits > 0)
            { /* a non empty bitmap */
              proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s",
                                         decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits8(tvb, bit_offset, no_of_bits)),
                                         pDescr->sz);
              remaining_bits_len -= no_of_bits;
              bit_offset += no_of_bits;

              if (remaining_bits_len < 0)
              {
                return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
              }

            }
            /* bitmap was successfully extracted or it was empty */

            pDescr++;
            break;
          }

          case CSN_TYPE:
          {
            gint16      Status;
            csnStream_t arT = *ar;
            proto_item   *ti;
            proto_tree   *test_tree;

            ti = proto_tree_add_text(tree, tvb, bit_offset>>3, 1,  "%s",pDescr->sz);
            test_tree = proto_item_add_subtree(ti, ett_csn1);

            csnStreamInit(&arT, bit_offset, remaining_bits_len);
            Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR *)pDescr->descr.ptr, tvb, pvDATA(data, pDescr->offset), ett_csn1);
            if (Status >= 0)
            {
              proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
              remaining_bits_len = arT.remaining_bits_len;
              bit_offset         = arT.bit_offset;
              pDescr++;
            }
            else
            { /* return error code Has already been processed:  */
              return Status;
            }

            break;
          }

          default:
          { /* descriptions of union elements other than above are illegal */
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_IN_SCRIPT, pDescr);
          }
        }

        pDescr = pDescrNext;
        break;
      }

      case CSN_EXIST:
      case CSN_EXIST_LH:
      {
        guint8 fExist;

        pui8  = pui8DATA(data, pDescr->offset);

        proto_tree_add_text(tree, tvb, bit_offset>>3, 1,  "Exist:%s",pDescr->sz);

        if (CSN_EXIST_LH == pDescr->type)
        {
          fExist = tvb_get_masked_bits8(tvb, bit_offset, 1);
        }
        else
        {
          fExist = tvb_get_bits8(tvb, bit_offset, 1);
        }

        *pui8 = fExist;
        remaining_bits_len --;
        bit_offset++;
        pDescr++;

        if (!fExist)
        {
          ar->remaining_bits_len  = remaining_bits_len;
          ar->bit_offset          = bit_offset;
          return remaining_bits_len;
        }

        break;
      }

      case CSN_NEXT_EXIST:
      {
        guint8 fExist;

        pui8  = pui8DATA(data, pDescr->offset);

        /* this if-statement represents the M_NEXT_EXIST_OR_NULL description element */
        if ((pDescr->may_be_null) && (remaining_bits_len == 0))
        { /* no more bits to decode is fine here - end of message detected and allowed */

          /* Skip i entries + this entry */
          pDescr += pDescr->i + 1;

          /* Set the data member to "not exist" */
          *pui8 = 0;
          break;
        }

        /* the "regular" M_NEXT_EXIST description element */
        proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s %s",
                                   decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)),
                                   pDescr->sz);

        fExist = 0x00;
        if (tvb_get_bits8(tvb, bit_offset, 1))
        {
          fExist = 0x01;
        }

        *pui8     = fExist;

        remaining_bits_len --;
        bit_offset++;

        if (fExist == 0)
        { /* Skip 'i' entries */
          pDescr += pDescr->i;
        }

        pDescr++;
        break;
      }

      case CSN_NEXT_EXIST_LH:
      {
        guint8 fExist;
        pui8  = pui8DATA(data, pDescr->offset);

        /* this if-statement represents the M_NEXT_EXIST_OR_NULL_LH description element */
        if ((pDescr->descr.ptr != NULL) && (remaining_bits_len == 0))
        { /* no more bits to decode is fine here - end of message detected and allowed */

          /* skip 'i' entries + this entry */
          pDescr += pDescr->i + 1;

          /* set the data member to "not exist" */
          *pui8 = 0;
          break;
        }

        /* the "regular" M_NEXT_EXIST_LH description element */
        proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s %s",
                                   decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)),
                                   pDescr->sz);

        fExist = tvb_get_masked_bits8(tvb, bit_offset, 1);

        *pui8++   = fExist;

        remaining_bits_len --;
        bit_offset++;

        if (fExist == 0)
        { /* Skip 'i' entries */
          pDescr += pDescr->i;
        }
        pDescr++;

        break;
      }

      case CSN_VARIABLE_BITMAP_1:
      { /* Bitmap from here and to the end of message */

        *pui8DATA(data, (gint16)pDescr->descr.value) = (guint8) remaining_bits_len; /* length of bitmap == remaining bits */

        /*no break -
         * with a length set we have a regular variable length bitmap so we continue */
      }

      case CSN_VARIABLE_BITMAP:
      { /* {CSN_VARIABLE_BITMAP, 0, offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * <N: bit (5)> <bitmap: bit(N + offset)>
         * Bit array with length (in bits) specified in parameter (pDescr->descr)
         * The result is right aligned!
         */
        gint16 no_of_bits = *pui8DATA(data, (gint16)pDescr->descr.value);

        no_of_bits += pDescr->i; /* adjusted by offset */

        if (no_of_bits > 0)
        {
          proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s",
                                     decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)));

          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          { /* extract bits */
            guint8* t_pui8 = pui8DATA(data, pDescr->offset);
            gint16 nB1  = no_of_bits & 0x07;/* no_of_bits Mod 8 */

            if (nB1 > 0)
            { /* take care of the first byte - it will be right aligned */
              *t_pui8++ = tvb_get_bits8(tvb, bit_offset, nB1);
              no_of_bits  -= nB1;
              bit_offset += nB1; /* (nB1 is no_of_bits Mod 8) */
              remaining_bits_len -= nB1;
            }

            /* remaining no_of_bits is a multiple of 8 or 0 */
            while (no_of_bits > 0)
            {
              *t_pui8++ = tvb_get_bits8(tvb, bit_offset, 8);
              no_of_bits -= 8;
              remaining_bits_len -= 8;
            }
          }
        }
        pDescr++;
        break;
      }

      case CSN_LEFT_ALIGNED_VAR_BMP_1:
      { /* Bitmap from here and to the end of message */

        *pui8DATA(data, (gint16)pDescr->descr.value) = (guint8) remaining_bits_len; /* length of bitmap == remaining bits */

        /* no break -
         * with a length set we have a regular left aligned variable length bitmap so we continue
         */
      }

      case CSN_LEFT_ALIGNED_VAR_BMP:
      { /* {CSN_LEFT_ALIGNED_VAR_BMP, _OFFSET, (void*)offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * <N: bit (5)> <bitmap: bit(N + offset)>
         * bit array with length (in bits) specified in parameter (pDescr->descr)
         */
        gint16 no_of_bits = *pui8DATA(data, (gint16)pDescr->descr.value);/* Size of bitmap */

        no_of_bits += pDescr->i;/* size adjusted by offset */

        if (no_of_bits > 0)
        {
          if (no_of_bits <= 32)
          {
            proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s",
                                     decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN)),
                                     pDescr->sz);
          }
          else if (no_of_bits <= 64)
          {
            proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s",
                                     decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits64(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN)),
                                     pDescr->sz);
          }
          else
          {
            proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %u bits",
                                     pDescr->sz, no_of_bits);
          }
          bit_offset += no_of_bits;
          remaining_bits_len -= no_of_bits;

          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }
        }

        /* bitmap was successfully extracted or it was empty */
        pDescr++;
        break;
      }


       case CSN_PADDING_BITS:
       { /* Padding from here and to the end of message */

         if (remaining_bits_len > 0)
         {
            proto_item *ti = proto_tree_add_text(tree, tvb, bit_offset>>3, -1,  "Padding Bits");
            proto_tree *padding_tree = proto_item_add_subtree(ti, ett_csn1);
            while (remaining_bits_len > 0)
            {
              gint bits_to_handle = remaining_bits_len + (bit_offset%8);
              if (bits_to_handle > 32)
              {
                 bits_to_handle = 32 - (bit_offset%8);
              }
              else
              {
                 bits_to_handle -= (bit_offset%8);
              }
              proto_tree_add_text(padding_tree, tvb, bit_offset>>3, ((bit_offset+bits_to_handle-1)>>3)-(bit_offset>>3)+1, "%s %s",
                                       decode_bits_in_field(bit_offset, bits_to_handle, tvb_get_bits(tvb, bit_offset, bits_to_handle, ENC_BIG_ENDIAN)),
                                       pDescr->sz);
              bit_offset += bits_to_handle;
              remaining_bits_len -= bits_to_handle;
            }
         }
         if (remaining_bits_len < 0)
         {
           return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
         }

         /* Padding was successfully extracted or it was empty */
         pDescr++;
         break;
       }

      case CSN_VARIABLE_ARRAY:
      { /* {int type; int i; void* descr; int offset; const char* sz; } CSN_DESCR;
         * {CSN_VARIABLE_ARRAY, _OFFSET, (void*)offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * Array with length specified in parameter:
         *  <count: bit (x)>
         *  <list: octet(count + offset)>
         */
        gint16 count = *pui8DATA(data, (gint16)pDescr->descr.value);

        count += pDescr->i; /* Adjusted by offset */

        if (count > 0)
        {
          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          pui8 = pui8DATA(data, pDescr->offset);

          while (count > 0)
          {
            proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s %s",
                                       decode_bits_in_field(bit_offset, 8, tvb_get_bits8(tvb, bit_offset, 8)),
                                       pDescr->sz);
            *pui8++ = tvb_get_bits8(tvb, bit_offset, 8);
            bit_offset += 8;
            remaining_bits_len -= 8;
            count--;
          }
        }

        pDescr++;
        break;
      }

      case CSN_RECURSIVE_ARRAY:
      { /* Recursive way to specify an array: <list> ::= {1 <number: bit (4)> <list> | 0}
         *  or more generally:                <list> ::= { <tag> <element> <list> | <EndTag> }
         *  where <element> ::= bit(value)
         *        <tag>     ::= 0 | 1
         *        <EndTag>  ::= reversed tag i.e. tag == 1 -> EndTag == 0 and vice versa
         * {CSN_RECURSIVE_ARRAY, _BITS, (void*)offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * REMARK: recursive way to specify an array but an iterative implementation!
         */
        gint16 no_of_bits        = pDescr->i;
        guint8  ElementCount = 0;

        pui8  = pui8DATA(data, pDescr->offset);

        while (existNextElement(tvb, bit_offset, Tag))
        { /* tag control shows existence of next list elements */
          proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s Exist:%s",
                                     decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)),
                                     pDescr->sz);
          bit_offset++;
          remaining_bits_len--;

          /* extract and store no_of_bits long element from bitstream */
          *pui8++   = tvb_get_bits8(tvb, bit_offset, no_of_bits);
          ElementCount++;

          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s",
                                     decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits8(tvb, bit_offset, no_of_bits)),
                                     pDescr->sz);
          bit_offset += no_of_bits;
          remaining_bits_len -= no_of_bits;
        }

        proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s Exist:%s",
                                   decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)),
                                   pDescr->sz);

        /* existNextElement() returned FALSE, 1 bit consumed */
        bit_offset++;
        remaining_bits_len--;


        /* Store the counted number of elements of the array */
        *pui8DATA(data, (gint16)pDescr->descr.value) = ElementCount;

        pDescr++;
        break;
      }

      case CSN_RECURSIVE_TARRAY:
      { /* Recursive way to specify an array of type: <lists> ::= { 1 <type> } ** 0 ;
         *  M_REC_TARRAY(_STRUCT, _MEMBER, _MEMBER_TYPE, _ElementCountField)
         * {t, offsetof(_STRUCT, _ElementCountField), (void*)CSNDESCR_##_MEMBER_TYPE, offsetof(_STRUCT, _MEMBER), #_MEMBER, (StreamSerializeFcn_t)sizeof(_MEMBER_TYPE)}
         */
        gint16 nSizeElement = (gint16)(gint32)pDescr->format_p.value;
        guint8  ElementCount = 0;

        while (existNextElement(tvb, bit_offset, Tag))
        { /* tag control shows existence of next list elements */
          proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s Exist:%s",
                                     decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)),
                                     pDescr->sz);

          /* existNextElement() returned TRUE, 1 bit consumed */
          bit_offset++;
          remaining_bits_len--;
          ElementCount++;

          { /* unpack the following data structure */
            csnStream_t arT = *ar;
            gint16      Status;
            proto_item   *ti;
            proto_tree   *test_tree;

            ti = proto_tree_add_text(tree, tvb, bit_offset>>3, 1,  "%s",pDescr->sz);
            test_tree = proto_item_add_subtree(ti, ett_csn1);

            csnStreamInit(&arT, bit_offset, remaining_bits_len);
            Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR *)pDescr->descr.ptr, tvb, pvDATA(data, pDescr->offset), ett_csn1);

            if (Status >= 0)
            { /* successful completion */
              pui8    += nSizeElement;  /* -> to next data element */
              proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
              remaining_bits_len = arT.remaining_bits_len;
              bit_offset         = arT.bit_offset;
            }
            else
            { /* something went awry */
              return Status;
            }
          }

          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }
        }

        /* existNextElement() returned FALSE, 1 bit consumed */
        bit_offset++;
        remaining_bits_len --;

        /* Store the counted number of elements of the array */
        *pui8DATA(data, (gint16)(gint32)pDescr->i) = ElementCount;

        pDescr++;
        break;
      }

      case CSN_RECURSIVE_TARRAY_2:
      { /* Recursive way to specify an array of type: <list> ::= <type> { 0 <type> } ** 1 ; */

        Tag = REVERSED_TAG;

        /* NO break -
         * handling is exactly the same as for CSN_RECURSIVE_TARRAY_1 so we continue
         */
      }

      case CSN_RECURSIVE_TARRAY_1:
      { /* Recursive way to specify an array of type: <lists> ::= <type> { 1 <type> } ** 0 ;
         * M_REC_TARRAY(_STRUCT, _MEMBER, _MEMBER_TYPE, _ElementCountField)
         * {t, offsetof(_STRUCT, _ElementCountField), (void*)CSNDESCR_##_MEMBER_TYPE, offsetof(_STRUCT, _MEMBER), #_MEMBER, (StreamSerializeFcn_t)sizeof(_MEMBER_TYPE)}
         */
        gint16      nSizeElement = (gint16)(gint32)pDescr->format_p.value;
        guint8       ElementCount = 0;
        csnStream_t arT          = *ar;
        gboolean     EndOfList    = FALSE;
        gint16      Status;
        proto_item   *ti;
        proto_tree   *test_tree;


        do
        { /* get data element */
          ElementCount++;

          ti = proto_tree_add_text(tree, tvb, bit_offset>>3, 1,  "%s[%d]",pDescr->sz, ElementCount-1);
          test_tree = proto_item_add_subtree(ti, ett_csn1);

          csnStreamInit(&arT, bit_offset, remaining_bits_len);
          Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR *)pDescr->descr.ptr, tvb, pvDATA(data, pDescr->offset), ett_csn1);

          if (Status >= 0)
          { /* successful completion */
            pui8    += nSizeElement;  /* -> to next */
            proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
            remaining_bits_len = arT.remaining_bits_len;
            bit_offset         = arT.bit_offset;
          }
          else
          { /* something went awry */
            return Status;
          }

          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          /* control of next element's tag */
          proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s Exist:%s[%d]",
                                     decode_bits_in_field(bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1)),
                                     pDescr->sz, ElementCount);
          EndOfList         = !(existNextElement(tvb, bit_offset, Tag));

          bit_offset++;
          remaining_bits_len--; /* 1 bit consumed (tag) */
        } while (!EndOfList);


        /* Store the count of the array */
        *pui8DATA(data, pDescr->i) = ElementCount;
        Tag = STANDARD_TAG; /* in case it was set to "reversed" */
        pDescr++;
        break;
      }

      case CSN_FIXED:
      { /* Verify the fixed bits */
        guint8  no_of_bits = (guint8) pDescr->i;
        guint32 ui32;

        if (no_of_bits <= 8)
        {
          ui32 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
        }
        else if (no_of_bits <= 16)
        {
          ui32 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
        }
        else if (no_of_bits <= 32)
        {
          ui32  = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
        }
        else
        {
          return ProcessError(tree, tvb, bit_offset,"no_of_bits > 32", -1, pDescr);
        }
        if (ui32 != (unsigned)(gint32)pDescr->offset)
        {
          return ProcessError(tree, tvb, bit_offset,"csnStreamDissector FIXED value does not match", -1, pDescr);
        }
        proto_tree_add_text(tree, tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, "%s %s",
                                   decode_bits_in_field(bit_offset, no_of_bits, tvb_get_bits8(tvb, bit_offset, no_of_bits)),
                                   pDescr->sz);

        remaining_bits_len   -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

      case CSN_CALLBACK:
      {
        guint16  no_of_bits;
        DissectorCallbackFcn_t callback = (DissectorCallbackFcn_t)pDescr->aux_fn;

        no_of_bits = callback(tree, tvb, pvDATA(data, pDescr->i), pvDATA(data, pDescr->offset), bit_offset, ett_csn1);
        bit_offset += no_of_bits;

        pDescr++;
        break;
      }

      case CSN_TRAP_ERROR:
      {
        return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", pDescr->i, pDescr);
      }

      case CSN_END:
      {
        ar->remaining_bits_len  = remaining_bits_len;
        ar->bit_offset = bit_offset;
        return remaining_bits_len;
      }

      default:
      {
        DISSECTOR_ASSERT(0);
      }


    }

  } while (remaining_bits_len >= 0);

  return ProcessError(tree, tvb, bit_offset,"csnStreamDissector", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
}


