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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include "packet-csn1.h"

void proto_register_csn1(void);

static int hf_null_data;

static expert_field ei_csn1_more_bits_to_unpack;
static expert_field ei_csn1_general;
static expert_field ei_csn1_not_implemented;
static expert_field ei_csn1_union_index;
static expert_field ei_csn1_script_error;
static expert_field ei_csn1_more32bits;
static expert_field ei_csn1_fixed_not_matched;
static expert_field ei_csn1_stream_not_supported;

#define pvDATA(_pv, _offset) ((void*) ((unsigned char*)_pv + _offset))
#define pui8DATA(_pv, _offset) ((uint8_t*) pvDATA(_pv, _offset))
#define pui16DATA(_pv, _offset) ((uint16_t*) pvDATA(_pv, _offset))
#define pui32DATA(_pv, _offset) ((uint32_t*) pvDATA(_pv, _offset))

/* used to tag existence of next element in variable length lists */
#define STANDARD_TAG 1
#define REVERSED_TAG 0

static const unsigned char ixBitsTab[] = {0, 1, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5};

static int proto_csn1;

/* Returns no_of_bits (up to 8) masked with 0x2B */
static uint8_t
tvb_get_masked_bits8(tvbuff_t *tvb, int bit_offset,  const int no_of_bits)
{
  static const uint8_t maskBits[] = {0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF};
  int byte_offset = bit_offset >> 3;          /* divide by 8 */
  int relative_bit_offset = bit_offset & 0x07;  /* modulo 8 */
  uint8_t result;
  int bit_shift = 8 - relative_bit_offset - (int) no_of_bits;

  if (bit_shift >= 0)
  {
    result = (0x2B ^ tvb_get_uint8(tvb, byte_offset)) >> bit_shift;
    result &= maskBits[no_of_bits];
  }
  else
  {
    uint8_t hight_part = (0x2B ^ tvb_get_uint8(tvb, byte_offset)) & maskBits[8 - relative_bit_offset];
    hight_part = (uint8_t) (hight_part << (-bit_shift));
    result =  (0x2B ^ tvb_get_uint8(tvb, byte_offset+1)) >> (8 + bit_shift);
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
csnStreamInit(csnStream_t* ar, int bit_offset, int remaining_bits_len, packet_info* pinfo)
{
  ar->remaining_bits_len  = remaining_bits_len;
  ar->bit_offset          = bit_offset;
  ar->pinfo               = pinfo;
}

static int16_t
ProcessError(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, int bit_offset, int16_t err, expert_field* err_field, const CSN_DESCR* pDescr)
{
  if (err_field != NULL)
    proto_tree_add_expert_format(tree, pinfo, err_field, tvb, bit_offset>>3, 1, "%s (%s)", expert_get_summary(err_field), pDescr?pDescr->sz:"-");

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
 * Return true if tag in bit stream indicates existence of next list element,
 * otherwise return false.
 * Will work for tag values equal to both 0 and 1.
 * ================================================================================================
 */

static bool
existNextElement(tvbuff_t *tvb, int bit_offset, uint8_t Tag)
{
  uint8_t res = tvb_get_bits8(tvb, bit_offset, 1);
  if (Tag == STANDARD_TAG)
  {
    return (res > 0);
  }
  return (res == 0);
}


int16_t
// NOLINTNEXTLINE(misc-no-recursion)
csnStreamDissector(proto_tree *tree, csnStream_t* ar, const CSN_DESCR* pDescr, tvbuff_t *tvb, void* data, int ett_csn1)
{
  int   remaining_bits_len = ar->remaining_bits_len;
  int   bit_offset         = ar->bit_offset;
  uint8_t*  pui8 = NULL;
  uint16_t* pui16;
  uint32_t* pui32;
  uint8_t Tag = STANDARD_TAG;

  /* Negative number definitely indicates an error */
  if (remaining_bits_len < 0)
  {
    return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
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
          proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);

          /* end add the bit value to protocol tree */
        }
        else if(pDescr->may_be_null)
        {
          pui8  = pui8DATA(data, pDescr->offset);
          *pui8 = 0;
          proto_tree_add_none_format(tree, hf_null_data, tvb, 0, 0, "[NULL data]: %s Not Present", proto_registrar_get_name(*(pDescr->hf_ptr)));
        }
        else
        {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
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
        uint8_t no_of_bits = (uint8_t) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
            uint8_t ui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
            pui8  = pui8DATA(data, pDescr->offset);
            *pui8 = ui8;
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else if (no_of_bits <= 16)
          {
            uint16_t ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
            pui16  = pui16DATA(data, pDescr->offset);
            memcpy(pui16, &ui16, 2);
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else if (no_of_bits <= 32)
          {
            uint32_t ui32 = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
            pui32  = pui32DATA(data, pDescr->offset);
            memcpy(pui32, &ui32, 4);
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
          }
          remaining_bits_len -= no_of_bits;
          bit_offset += no_of_bits;
        }
        else if(pDescr->may_be_null)
        {
            if (no_of_bits <= 8)
            {
              pui8  = pui8DATA(data, pDescr->offset);
              *pui8 = 0;
            }
            else if (no_of_bits <= 16)
            {
              pui16  = pui16DATA(data, pDescr->offset);
              memset(pui16, 0, 2);
            }
            else if (no_of_bits <= 32)
            {
              pui32  = pui32DATA(data, pDescr->offset);
              memset(pui32, 0, 4);
            }
            proto_tree_add_none_format(tree, hf_null_data, tvb, 0, 0, "[NULL data]: %s Not Present", proto_registrar_get_name(*(pDescr->hf_ptr)));
        }
        else
        {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
        }

        pDescr++;
        break;
      }

      case CSN_UINT_OFFSET:
      {
        uint8_t no_of_bits = (uint8_t) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
            uint8_t ui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = ui8 + (uint8_t)pDescr->descr.value;

            proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits,
                                                  *pui8, ENC_BIG_ENDIAN, "%u (Raw %u + Offset %u)", *pui8, ui8,
                                                  (uint8_t) pDescr->descr.value);
          }
          else if (no_of_bits <= 16)
          {
            uint16_t ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN) + (uint16_t)pDescr->descr.value;
            pui16       = pui16DATA(data, pDescr->offset);
            memcpy(pui16, &ui16, 2);

            proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits,
                                                  *pui16, ENC_BIG_ENDIAN, "%u (Raw %u + Offset %u)", *pui16, ui16,
                                                  (uint16_t) pDescr->descr.value);
          }
          else if (no_of_bits <= 32)
          {
            uint32_t ui32 = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN) + (uint16_t)pDescr->descr.value;
            pui32       = pui32DATA(data, pDescr->offset);
            memcpy(pui32, &ui32, 4);

            proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits,
                                                  *pui32, ENC_BIG_ENDIAN, "%u (Raw %u + Offset %u)", *pui32, ui32,
                                                  (uint16_t) pDescr->descr.value);
          }
          else
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
          }
        }
        else
        {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
        }

        remaining_bits_len -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

      case CSN_UINT_LH:
      {
        uint8_t no_of_bits = (uint8_t) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
            uint8_t ui8 = tvb_get_masked_bits8(tvb, bit_offset, no_of_bits);
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = ui8;
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);

          }
          else
          {/* Maybe we should support more than 8 bits ? */
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
          }
        }
        else
        {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
        }

        remaining_bits_len -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

        case CSN_SPLIT_BITS:
        {
          uint8_t no_of_value_bits = (uint8_t) pDescr->i;
          uint64_t value;

          proto_tree_add_split_bits_item_ret_val(tree, *pDescr->hf_ptr, tvb, bit_offset, pDescr->descr.crumb_spec, &value);
          if (no_of_value_bits <= 8)
          {
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = (uint8_t)value;
          }
          else if (no_of_value_bits <= 16)
          {
            uint16_t ui16 = (uint16_t) value;
            pui16       = pui16DATA(data, pDescr->offset);
            memcpy(pui16, &ui16, 2);
          }
          else if (no_of_value_bits <= 32)
          {
            uint32_t ui32 = (uint32_t) value;
            pui32       = pui32DATA(data, pDescr->offset);
            memcpy(pui32, &ui32, 4);
          }
          else
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
          }

          pDescr++;
          break;
        }

        case CSN_SPLIT_BITS_CRUMB:
        {
          if (remaining_bits_len >= pDescr->descr.crumb_spec[pDescr->i].crumb_bit_length)
          {
            proto_tree_add_split_bits_crumb(tree, *pDescr->hf_ptr, tvb, bit_offset,
                                            pDescr->descr.crumb_spec, pDescr->i);

            remaining_bits_len -= pDescr->descr.crumb_spec[pDescr->i].crumb_bit_length;
            bit_offset += pDescr->descr.crumb_spec[pDescr->i].crumb_bit_length;
          }
          else
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
          }

          pDescr++;
          break;
        }

      case CSN_UINT_ARRAY:
      {
        uint8_t no_of_bits  = (uint8_t) pDescr->i;
        uint16_t nCount = (uint16_t)pDescr->descr.value; /* nCount supplied by value i.e. M_UINT_ARRAY(...) */
        int i = 0;

        if (pDescr->value != 0)
        { /* nCount specified by a reference to field holding value i.e. M_VAR_UINT_ARRAY(...) */
          memcpy(&nCount, pui16DATA(data, nCount), 2);
        }

        if (remaining_bits_len >= (no_of_bits * nCount))
        {
          remaining_bits_len -= (no_of_bits * nCount);
          if (no_of_bits <= 8)
          {
            pui8 = pui8DATA(data, pDescr->offset);
            do
            {
              *pui8++ = tvb_get_bits8(tvb, bit_offset, no_of_bits);
              proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, *pui8, ENC_BIG_ENDIAN, " (Count %d)", i++);
              bit_offset += no_of_bits;
            } while (--nCount > 0);
          }
          else if (no_of_bits <= 16)
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, 999, &ei_csn1_not_implemented, pDescr);
          }
          else if (no_of_bits <= 32)
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, 999, &ei_csn1_not_implemented, pDescr);
          }
          else
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
          }
        }
        else
        {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
        }
        pDescr++;
        break;
      }

      case CSN_VARIABLE_TARRAY_OFFSET:
      case CSN_VARIABLE_TARRAY:
      case CSN_TYPE_ARRAY:
      {
        int16_t     Status;
        csnStream_t arT    = *ar;
        int16_t     nCount = pDescr->i;
        uint16_t     nSize  = (uint16_t)(int32_t)pDescr->value;
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

          test_tree = proto_tree_add_subtree_format(tree, tvb, bit_offset>>3, 1, ett_csn1, &ti, "%s[%d]",pDescr->sz, i++);

          csnStreamInit(&arT, bit_offset, remaining_bits_len, ar->pinfo);
          increment_dissection_depth(ar->pinfo);
          Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR*)pDescr->descr.ptr, tvb, pui8, ett_csn1);
          decrement_dissection_depth(ar->pinfo);
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
        uint8_t no_of_bits = (uint8_t) pDescr->i; /* length of bitmap */

        if (no_of_bits > 0)
        {
          if (no_of_bits > remaining_bits_len)
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
          }

          if (no_of_bits <= 32)
          {
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else if (no_of_bits <= 64)
          {
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, 999, &ei_csn1_not_implemented, pDescr);
          }

          remaining_bits_len -= no_of_bits;
          bit_offset += no_of_bits;
        }
        /* bitmap was successfully extracted or it was empty */

        pDescr++;
        break;
      }

      case CSN_TYPE:
      {
        int16_t     Status;
        csnStream_t arT = *ar;
        proto_item   *ti;
        proto_tree   *test_tree;
        if (pDescr->may_be_null && remaining_bits_len == 0)
        {
          proto_tree_add_none_format(tree, hf_null_data, tvb, 0, 0, "[NULL data]: %s Not Present", pDescr->sz);
        } else {
          test_tree = proto_tree_add_subtree_format(tree, tvb, bit_offset>>3, 1, ett_csn1, &ti, "%s", pDescr->sz);
          csnStreamInit(&arT, bit_offset, remaining_bits_len, ar->pinfo);
          increment_dissection_depth(ar->pinfo);
          Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR*)pDescr->descr.ptr, tvb, pvDATA(data, pDescr->offset), ett_csn1);
          decrement_dissection_depth(ar->pinfo);
          if (Status >= 0)
          {
            proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
            remaining_bits_len  = arT.remaining_bits_len;
            bit_offset          = arT.bit_offset;
          }
          else
          {
            /* Has already been processed: ProcessError("csnStreamDissector", Status, pDescr);  */
            return Status;
          }
        }
        pDescr++;
        break;
      }

      case CSN_CHOICE:
      {
        int16_t count = pDescr->i;
        uint8_t i     = 0;
        const CSN_ChoiceElement_t* pChoice = (const CSN_ChoiceElement_t*) pDescr->descr.ptr;

        /* Make sure that the list of choice items is not empty */
        if (!count)
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_IN_SCRIPT, &ei_csn1_script_error, pDescr);

        while (count > 0)
        {
          uint8_t no_of_bits = pChoice->bits;
          uint8_t value = tvb_get_bits8(tvb, bit_offset, no_of_bits);

          if (value == pChoice->value)
          {
            CSN_DESCR   descr[2];
            int16_t     Status;
            csnStream_t arT = *ar;
            proto_item   *ti = NULL;
            proto_tree   *test_tree;

            descr[0]      = pChoice->descr;
            memset(&descr[1], 0x00, sizeof(CSN_DESCR));
            descr[1].type = CSN_END;
            pui8          = pui8DATA(data, pDescr->offset);
            *pui8         = i;

            if (pDescr->sz)
            {
              proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
            }

            if (!pChoice->keep_bits)
            {
              bit_offset += no_of_bits;
              remaining_bits_len -= no_of_bits;
            }

            if (pDescr->sz)
            {
              test_tree = proto_tree_add_subtree(tree, tvb, bit_offset>>3, 1, ett_csn1, &ti, pDescr->sz);
            } else {
              test_tree = tree;
            }

            csnStreamInit(&arT, bit_offset, remaining_bits_len, ar->pinfo);
            increment_dissection_depth(ar->pinfo);
            Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR*)descr, tvb, data, ett_csn1);
            decrement_dissection_depth(ar->pinfo);

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

        /* Neither of the choice items matched => unknown value */
        if (!count) {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset,
                              CSN_ERROR_STREAM_NOT_SUPPORTED,
                              &ei_csn1_stream_not_supported, pDescr);
        }

        pDescr++;
        break;
      }

      case CSN_SERIALIZE:
      {
        StreamSerializeFcn_t serialize = (StreamSerializeFcn_t)pDescr->aux_fn;
        csnStream_t          arT       = *ar;
        unsigned length_len = pDescr->i;
        int16_t              Status = -1;
        proto_item   *ti;
        proto_tree   *test_tree;
        uint8_t length = 0;

        if (length_len)
        {
          length = tvb_get_bits8(tvb, bit_offset, length_len);

          proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, length_len, ENC_BIG_ENDIAN);

          bit_offset += length_len;
          remaining_bits_len -= length_len;

          test_tree = proto_tree_add_subtree(tree, tvb, bit_offset>>3, ((bit_offset+length-1)>>3)-(bit_offset>>3) + 1, ett_csn1, &ti, pDescr->sz);
        } else {
          test_tree = proto_tree_add_subtree(tree, tvb, bit_offset>>3, 1, ett_csn1, &ti, pDescr->sz);
        }

        csnStreamInit(&arT, bit_offset, length > 0 ? length : remaining_bits_len, ar->pinfo);
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
        int16_t          Bits;
        uint8_t          t_index;
        int16_t          count      = pDescr->i;
        const CSN_DESCR* pDescrNext = pDescr;

        pDescrNext += count + 1; /* now this is next after the union */
        if ((count <= 0) || (count > 16))
        {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_INVALID_UNION_INDEX, &ei_csn1_union_index, pDescr);
        }

        /* Now get the bits to extract the index */
        Bits = ixBitsTab[count];
        proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, Bits, tvb_get_bits8(tvb, bit_offset, Bits), ENC_BIG_ENDIAN, " (Union)");
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

            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);

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
            uint8_t no_of_bits = (uint8_t) pDescr->i;
            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
                uint8_t ui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
                pui8      = pui8DATA(data, pDescr->offset);
                *pui8     = ui8;
                proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);

              }
              else if (no_of_bits <= 16)
              {
                uint16_t ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
                pui16       = pui16DATA(data, pDescr->offset);
                memcpy(pui16, &ui16, 2);
                proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
              }
              else if (no_of_bits <= 32)
              {
                uint32_t ui32 = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
                pui32       = pui32DATA(data, pDescr->offset);
                memcpy(pui32, &ui32, 4);
                proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);

              }
              else
              {
                return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
              }
            }
            else
            {
              return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_OFFSET:
          {
            uint8_t no_of_bits = (uint8_t) pDescr->i;

            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
                uint8_t ui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
                pui8      = pui8DATA(data, pDescr->offset);
                *pui8     = ui8 + (uint8_t)pDescr->descr.value;
                proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ui8, ENC_BIG_ENDIAN, "%d", ui8);
              }
              else if (no_of_bits <= 16)
              {
                uint16_t ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN) + (uint16_t)pDescr->descr.value;
                pui16       = pui16DATA(data, pDescr->offset);
                memcpy(pui16, &ui16, 2);
                proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ui16, ENC_BIG_ENDIAN, "%d", ui16);
              }
              else if (no_of_bits <= 32)
              {
                uint32_t ui32 = tvb_get_bits32(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN) + (uint16_t)pDescr->descr.value;
                pui32       = pui32DATA(data, pDescr->offset);
                memcpy(pui32, &ui32, 4);
                proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ui32, ENC_BIG_ENDIAN, "%d", ui32);
              }
              else
              {
                return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
              }
            }
            else
            {
              return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_LH:
          {
            uint8_t no_of_bits = (uint8_t) pDescr->i;

            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
                uint8_t ui8 = tvb_get_masked_bits8(tvb, bit_offset, no_of_bits);
                pui8      = pui8DATA(data, pDescr->offset);
                *pui8     = ui8;
                proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
              }
              else
              { /* Maybe we should support more than 8 bits ? */
                ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
              }
            }
            else
            {
              return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_ARRAY:
          {
            uint8_t no_of_bits  = (uint8_t) pDescr->i;
            uint16_t nCount = (uint16_t)pDescr->descr.value; /* nCount supplied by value i.e. M_UINT_ARRAY(...) */
            int i = 0;

            if (pDescr->value != 0)
            { /* nCount specified by a reference to field holding value i.e. M_VAR_UINT_ARRAY(...) */
              memcpy(&nCount, pui16DATA(data, nCount), 2);
            }

            if (remaining_bits_len >= (no_of_bits * nCount))
            {
              remaining_bits_len -= (no_of_bits * nCount);
              if (no_of_bits <= 8)
              {
                pui8 = pui8DATA(data, pDescr->offset);

                while (nCount > 0)
                {
                  *pui8 = tvb_get_bits8(tvb, bit_offset, no_of_bits);
                  proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, *pui8, ENC_BIG_ENDIAN, " (Count %d)", i++);
                  pui8++;
                  bit_offset += no_of_bits;
                  nCount--;
                }
              }
              else if (no_of_bits <= 16)
              {
                pui16 = pui16DATA(data, pDescr->offset);

                while (nCount > 0)
                {
                  uint16_t ui16;
                  ui16 = tvb_get_bits16(tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
                  proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ui16, ENC_BIG_ENDIAN, " (Count %d)", i++);
                  memcpy(pui16++, &ui16, sizeof(ui16));
                  bit_offset += no_of_bits;
                  nCount--;
                }
              }
              else if (no_of_bits <= 32)
              { /* not supported */
                return ProcessError(tree, ar->pinfo, tvb, bit_offset, 999, &ei_csn1_not_implemented, pDescr);
              }
              else
              {
                return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_GENERAL, &ei_csn1_general, pDescr);
              }
            }
            else
            {
              return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
            }

            pDescr++;
            break;
          }

          case CSN_VARIABLE_TARRAY_OFFSET:
          case CSN_VARIABLE_TARRAY:
          case CSN_TYPE_ARRAY:
          {
            int16_t     Status;
            csnStream_t arT    = *ar;
            uint16_t     nCount = (uint16_t) pDescr->i;
            uint16_t     nSize  = (uint16_t)(uint32_t)pDescr->value;
            int i = 0;

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

              test_tree = proto_tree_add_subtree_format(tree, tvb, bit_offset>>3, 1, ett_csn1, &ti, "%s[%d]",pDescr->sz, i++);

              csnStreamInit(&arT, bit_offset, remaining_bits_len, ar->pinfo);
              increment_dissection_depth(ar->pinfo);
              Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR *)pDescr->descr.ptr, tvb, pui8, ett_csn1);
              decrement_dissection_depth(ar->pinfo);
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
            uint8_t no_of_bits = (uint8_t) pDescr->i; /* length of bitmap */

            if (no_of_bits > 0)
            { /* a non empty bitmap */
              proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
              remaining_bits_len -= no_of_bits;
              bit_offset += no_of_bits;

              if (remaining_bits_len < 0)
              {
                return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
              }

            }
            /* bitmap was successfully extracted or it was empty */

            pDescr++;
            break;
          }

          case CSN_TYPE:
          {
            int16_t     Status;
            csnStream_t arT = *ar;
            proto_item   *ti;
            proto_tree   *test_tree;

            if (pDescr->may_be_null && remaining_bits_len == 0)
            {
              proto_tree_add_none_format(tree, hf_null_data, tvb, 0, 0, "[NULL data]: %s Not Present", pDescr->sz);
            } else {
              test_tree = proto_tree_add_subtree(tree, tvb, bit_offset>>3, 1, ett_csn1, &ti, pDescr->sz);
              csnStreamInit(&arT, bit_offset, remaining_bits_len, ar->pinfo);
              increment_dissection_depth(ar->pinfo);
              Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR *)pDescr->descr.ptr, tvb, pvDATA(data, pDescr->offset), ett_csn1);
              decrement_dissection_depth(ar->pinfo);
              if (Status >= 0)
              {
                proto_item_set_len(ti,((arT.bit_offset-1)>>3) - (bit_offset>>3)+1);
                remaining_bits_len = arT.remaining_bits_len;
                bit_offset         = arT.bit_offset;
              }
              else
              { /* return error code Has already been processed:  */
                return Status;
              }
            }
            pDescr++;
            break;
          }

          default:
          { /* descriptions of union elements other than above are illegal */
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_IN_SCRIPT, &ei_csn1_script_error, pDescr);
          }
        }

        pDescr = pDescrNext;
        break;
      }

      case CSN_EXIST:
      case CSN_EXIST_LH:
      {
        uint8_t fExist;

        pui8  = pui8DATA(data, pDescr->offset);

        if (CSN_EXIST_LH == pDescr->type)
        {
          fExist = tvb_get_masked_bits8(tvb, bit_offset, 1);
          proto_tree_add_uint(tree, *(pDescr->hf_ptr), tvb, bit_offset>>3, 1, fExist);
        }
        else
        {
          fExist = tvb_get_bits8(tvb, bit_offset, 1);
          proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);
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
        uint8_t isnull;

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
        proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);

        isnull = 1;
        if (tvb_get_bits8(tvb, bit_offset, 1))
        {
          if (remaining_bits_len == 1)
          {
             /* If { 1 < end > } and all next items may be null, store it as { 0 } */
            const CSN_DESCR* pDescrNext = pDescr + 1;
            uint8_t i;
            for (i = 0; i < pDescr->i; i++, pDescrNext++)
            {
              if (!pDescrNext->may_be_null)
                isnull = 0;
            }
          } else {
            isnull = 0;
          }
        }

        *pui8     = isnull ? 0 : 1;

        remaining_bits_len --;
        bit_offset++;

        if (isnull)
        { /* Skip 'i' entries */
          pDescr += pDescr->i;
        }

        pDescr++;
        break;
      }

      case CSN_NEXT_EXIST_LH:
      {
        uint8_t isnull;
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
        proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);

        isnull = 1;
        if (tvb_get_masked_bits8(tvb, bit_offset, 1))
        {
          if (remaining_bits_len == 1) {
             /* If { 1 < end > } and all next items may be null, store it as { 0 } */
            const CSN_DESCR* pDescrNext = pDescr + 1;
            uint8_t i;
            for (i = 0; i < pDescr->i; i++, pDescrNext++)
            {
              if (!pDescrNext->may_be_null)
                isnull = 0;
            }
          } else {
            isnull = 0;
          }
        }

        *pui8++   = isnull ? 0 : 1;

        remaining_bits_len --;
        bit_offset++;

        if (isnull)
        { /* Skip 'i' entries */
          pDescr += pDescr->i;
        }
        pDescr++;

        break;
      }

      case CSN_VARIABLE_BITMAP_1:
      { /* Bitmap from here and to the end of message */

        *pui8DATA(data, (int16_t)pDescr->descr.value) = (uint8_t) remaining_bits_len; /* length of bitmap == remaining bits */

        /*no break -
         * with a length set we have a regular variable length bitmap so we continue */
      }
      /* FALL THROUGH */
      case CSN_VARIABLE_BITMAP:
      { /* {CSN_VARIABLE_BITMAP, 0, offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * <N: bit (5)> <bitmap: bit(N + offset)>
         * Bit array with length (in bits) specified in parameter (pDescr->descr)
         * The result is right aligned!
         */
        int16_t no_of_bits = *pui8DATA(data, (int16_t)pDescr->descr.value);

        no_of_bits += pDescr->i; /* adjusted by offset */

        while (no_of_bits > 0)
        {
          proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);
          bit_offset++;
          no_of_bits--;
          remaining_bits_len--;

          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
          }
        }
        pDescr++;
        break;
      }

      case CSN_LEFT_ALIGNED_VAR_BMP_1:
      { /* Bitmap from here and to the end of message */

        *pui8DATA(data, (int16_t)pDescr->descr.value) = (uint8_t) remaining_bits_len; /* length of bitmap == remaining bits */

        /* no break -
         * with a length set we have a regular left aligned variable length bitmap so we continue
         */
      }
      /* FALL THROUGH */
      case CSN_LEFT_ALIGNED_VAR_BMP:
      { /* {CSN_LEFT_ALIGNED_VAR_BMP, _OFFSET, (void*)offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * <N: bit (5)> <bitmap: bit(N + offset)>
         * bit array with length (in bits) specified in parameter (pDescr->descr)
         */
        int16_t no_of_bits = *pui8DATA(data, (int16_t)pDescr->descr.value);/* Size of bitmap */

        no_of_bits += pDescr->i;/* size adjusted by offset */

        if (no_of_bits > 0)
        {
          if (no_of_bits <= 32)
          {
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else if (no_of_bits <= 64)
          {
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          }
          else
          {
            proto_tree_add_uint64_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset>>3, ((bit_offset+no_of_bits-1)>>3)-(bit_offset>>3)+1, no_of_bits, "%u bits",
                                     no_of_bits);
          }
          bit_offset += no_of_bits;
          remaining_bits_len -= no_of_bits;

          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
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
          proto_tree *padding_tree = proto_tree_add_subtree(tree, tvb, bit_offset>>3, -1, ett_csn1, NULL, "Padding Bits");
          while (remaining_bits_len > 0)
          {
            int bits_to_handle = remaining_bits_len + (bit_offset%8);
            if (bits_to_handle > 32)
            {
               bits_to_handle = 32 - (bit_offset%8);
            }
            else
            {
               bits_to_handle -= (bit_offset%8);
            }
            proto_tree_add_bits_item(padding_tree, *(pDescr->hf_ptr), tvb, bit_offset, bits_to_handle, ENC_BIG_ENDIAN);
            bit_offset += bits_to_handle;
            remaining_bits_len -= bits_to_handle;
          }
        }
        if (remaining_bits_len < 0)
        {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
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
        int16_t count = *pui8DATA(data, (int16_t)pDescr->descr.value);

        count += pDescr->i; /* Adjusted by offset */

        if (count > 0)
        {
          pui8 = pui8DATA(data, pDescr->offset);

          while (count > 0)
          {
            proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, 8, ENC_BIG_ENDIAN);
            *pui8++ = tvb_get_bits8(tvb, bit_offset, 8);
            bit_offset += 8;
            count--;
            remaining_bits_len -= 8;
            if (remaining_bits_len < 0)
            {
              return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
            }
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
        int16_t no_of_bits        = pDescr->i;
        uint8_t ElementCount = 0;

        pui8  = pui8DATA(data, pDescr->offset);

        while (existNextElement(tvb, bit_offset, Tag))
        { /* tag control shows existence of next list elements */
          proto_tree_add_bits_item(tree, *(pDescr->hf_exist_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);
          bit_offset++;
          remaining_bits_len--;

          /* extract and store no_of_bits long element from bitstream */
          *pui8++   = tvb_get_bits8(tvb, bit_offset, no_of_bits);
          ElementCount++;

          if (remaining_bits_len < 0)
          {
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
          }

          proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);
          bit_offset += no_of_bits;
          remaining_bits_len -= no_of_bits;
        }

        proto_tree_add_bits_item(tree, *(pDescr->hf_exist_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);

        /* existNextElement() returned false, 1 bit consumed */
        bit_offset++;
        remaining_bits_len--;

        /* Store the counted number of elements of the array */
        *pui8DATA(data, (int16_t)pDescr->descr.value) = ElementCount;

        pDescr++;
        break;
      }

      case CSN_RECURSIVE_TARRAY:
      { /* Recursive way to specify an array of type: <lists> ::= { 1 <type> } ** 0 ;
         *  M_REC_TARRAY(_STRUCT, _MEMBER, _MEMBER_TYPE, _ElementCountField)
         * {t, offsetof(_STRUCT, _ElementCountField), (void*)CSNDESCR_##_MEMBER_TYPE, offsetof(_STRUCT, _MEMBER), #_MEMBER, (StreamSerializeFcn_t)sizeof(_MEMBER_TYPE), NULL, NULL, (void_fn_t)array_length(((_STRUCT*)0)->_MEMBER)}
         */
        int16_t nSizeElement = (int16_t)(int32_t)pDescr->value;
        uint32_t nSizeArray = (uint32_t)((guintptr)pDescr->aux_fn);
        uint8_t ElementCount = 0;

        while (existNextElement(tvb, bit_offset, Tag))
        { /* tag control shows existence of next list elements */
          proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, 1, ENC_BIG_ENDIAN);

          /* existNextElement() returned true, 1 bit consumed */
          bit_offset++;
          remaining_bits_len--;
          ElementCount++;

          if (ElementCount > nSizeArray)
          {
            /* error: too many elements in recursive array. Increase its size! */
            return ProcessError(tree , ar->pinfo, tvb, bit_offset, CSN_ERROR_STREAM_NOT_SUPPORTED, &ei_csn1_stream_not_supported, pDescr);
          }

          { /* unpack the following data structure */
            csnStream_t arT = *ar;
            int16_t     Status;
            proto_item   *ti;
            proto_tree   *test_tree;

            test_tree = proto_tree_add_subtree(tree, tvb, bit_offset>>3, 1, ett_csn1, &ti, pDescr->sz);

            csnStreamInit(&arT, bit_offset, remaining_bits_len, ar->pinfo);
            increment_dissection_depth(ar->pinfo);
            Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR *)pDescr->descr.ptr, tvb, pvDATA(data, pDescr->offset), ett_csn1);
            decrement_dissection_depth(ar->pinfo);

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
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
          }
        }

        /* existNextElement() returned false, 1 bit consumed */
        bit_offset++;
        remaining_bits_len --;

        /* Store the counted number of elements of the array */
        *pui8DATA(data, (int16_t)(int32_t)pDescr->i) = ElementCount;

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
      /* FALL THROUGH */
      case CSN_RECURSIVE_TARRAY_1:
      { /* Recursive way to specify an array of type: <lists> ::= <type> { 1 <type> } ** 0 ;
         * M_REC_TARRAY(_STRUCT, _MEMBER, _MEMBER_TYPE, _ElementCountField)
         * {t, offsetof(_STRUCT, _ElementCountField), (void*)CSNDESCR_##_MEMBER_TYPE, offsetof(_STRUCT, _MEMBER), #_MEMBER, (StreamSerializeFcn_t)sizeof(_MEMBER_TYPE), NULL, NULL, (void_fn_t)array_length(((_STRUCT*)0)->_MEMBER)}
         */
        int16_t     nSizeElement = (int16_t)(int32_t)pDescr->value;
        uint32_t    nSizeArray = (uint32_t)((guintptr)pDescr->aux_fn);
        uint8_t      ElementCount = 0;
        csnStream_t arT          = *ar;
        bool         EndOfList    = false;
        int16_t     Status;
        proto_item   *ti;
        proto_tree   *test_tree;

        do
        { /* get data element */
          ElementCount++;

        if (ElementCount >= nSizeArray)
        {
          /* error: too many elements in recursive array. Increase its size! */
          return ProcessError(tree , ar->pinfo, tvb, bit_offset, CSN_ERROR_STREAM_NOT_SUPPORTED, &ei_csn1_stream_not_supported, pDescr);
        }

          test_tree = proto_tree_add_subtree_format(tree, tvb, bit_offset>>3, 1, ett_csn1, &ti, "%s[%d]", pDescr->sz, ElementCount-1);

          csnStreamInit(&arT, bit_offset, remaining_bits_len, ar->pinfo);
          increment_dissection_depth(ar->pinfo);
          Status = csnStreamDissector(test_tree, &arT, (const CSN_DESCR *)pDescr->descr.ptr, tvb, pvDATA(data, pDescr->offset), ett_csn1);
          decrement_dissection_depth(ar->pinfo);

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
            return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
          }

          /* control of next element's tag */
          proto_tree_add_uint_bits_format_value(tree, *(pDescr->hf_ptr), tvb, bit_offset, 1, tvb_get_bits8(tvb, bit_offset, 1), ENC_BIG_ENDIAN, "%s[%d]",
                                     proto_registrar_get_name(*(pDescr->hf_ptr)), ElementCount);
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
        uint8_t no_of_bits = (uint8_t) pDescr->i;
        uint32_t ui32;

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
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, -1, &ei_csn1_more32bits, pDescr);
        }
        if (ui32 != (unsigned)(int32_t)pDescr->offset)
        {
          return ProcessError(tree, ar->pinfo, tvb, bit_offset, -1, &ei_csn1_fixed_not_matched, pDescr);
        }
        proto_tree_add_bits_item(tree, *(pDescr->hf_ptr), tvb, bit_offset, no_of_bits, ENC_BIG_ENDIAN);

        remaining_bits_len   -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

      case CSN_CALLBACK:
      {
        uint16_t no_of_bits;
        DissectorCallbackFcn_t callback = (DissectorCallbackFcn_t)pDescr->aux_fn;

        no_of_bits = callback(tree, tvb, pvDATA(data, pDescr->i), pvDATA(data, pDescr->offset), bit_offset, ett_csn1, ar->pinfo);
        bit_offset += no_of_bits;
        remaining_bits_len -= no_of_bits;

        pDescr++;
        break;
      }

      case CSN_TRAP_ERROR:
      {
        return ProcessError(tree, ar->pinfo, tvb, bit_offset, -1, pDescr->error, pDescr);
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

  return ProcessError(tree, ar->pinfo, tvb, bit_offset, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, &ei_csn1_more_bits_to_unpack, pDescr);
}

void
proto_register_csn1(void)
{
    static hf_register_info hf[] = {
        { &hf_null_data,
            { "NULL data", "csn1.null_data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_csn1_more_bits_to_unpack, { "csn1.more_bits_to_unpack", PI_MALFORMED, PI_ERROR, "NEED_MORE BITS TO UNPACK", EXPFILL }},
        { &ei_csn1_general, { "csn1.general_error", PI_PROTOCOL, PI_WARN, "General -1", EXPFILL }},
        { &ei_csn1_not_implemented, { "csn1.not_implemented", PI_UNDECODED, PI_WARN, "NOT IMPLEMENTED", EXPFILL }},
        { &ei_csn1_union_index, { "csn1.union_index_invalid", PI_PROTOCOL, PI_WARN, "INVALID UNION INDEX", EXPFILL }},
        { &ei_csn1_script_error, { "csn1.script_error", PI_MALFORMED, PI_ERROR, "ERROR IN SCRIPT", EXPFILL }},
        { &ei_csn1_more32bits, { "csn1.more32bits", PI_PROTOCOL, PI_WARN, "no_of_bits > 32", EXPFILL }},
        { &ei_csn1_fixed_not_matched, { "csn1.fixed_not_matched", PI_PROTOCOL, PI_WARN, "FIXED value does not match", EXPFILL }},
        { &ei_csn1_stream_not_supported, { "csn1.stream_not_supported", PI_PROTOCOL, PI_WARN, "STREAM NOT SUPPORTED", EXPFILL }},
    };

    expert_module_t* expert_csn1;

    proto_csn1 = proto_register_protocol("CSN.1", "CSN1", "csn1");

	proto_register_field_array(proto_csn1, hf, array_length(hf));
    expert_csn1 = expert_register_protocol(proto_csn1);
    expert_register_field_array(expert_csn1, ei, array_length(ei));

    proto_set_cant_toggle(proto_csn1);
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
