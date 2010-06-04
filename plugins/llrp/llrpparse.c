/* EPCglobal Low-Level Reader Protocol Packet Dissector
 *
 * Copyright 2008, Intermec Technologies Corp. <matt.poduska@intermec.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h> /* For NULL */
#include "llrpparsetypes.h"
#include "llrpparse.h"

/* ------------------------------------------------------------------------------- */
/* Local Function Declarations                                                     */

static void llrp_ParseParameter(t_llrp_parse_context *context, unsigned short usType,
 int bImpliedLength, unsigned short usLength);
static void llrp_ParseCustomParameter(t_llrp_parse_context *context, unsigned short usType,
 unsigned short usLength);

static void llrp_ParseCompoundItem(t_llrp_parse_context *context,
 t_llrp_compound_item *pCompoundItem, unsigned long ulTotalLength);

static int llrp_ParseFixedItems(t_llrp_parse_context *context, t_llrp_item *pItemList,
 unsigned short usTotalItems, unsigned short *pusParsedItems, unsigned long ulTotalLength,
 unsigned long *pulConsumedBytes);
static int llrp_ParseVariableItems(t_llrp_parse_context *context, t_llrp_item *pItemList,
 unsigned short usTotalItems, unsigned long ulTotalLength);

static int llrp_HandleField(t_llrp_parse_context *context, t_llrp_item *pItem,
 unsigned short usFieldIndex, unsigned long ulTotalLength, unsigned char *pucBitAccumulator,
 unsigned char *pucAccumulatedBits);

static int llrp_ParseGetParameterContentLength(const t_llrp_compound_item *pItem,
 unsigned short *pusLength);

#define llrp_ReportError(pContext, parameterList) \
{ if((pContext)->parse_error_handler != NULL) (pContext)->parse_error_handler parameterList; }

#define llrp_ReportMessage(pContext, parameterList) \
{ if((pContext)->debug_message_handler != NULL) (pContext)->debug_message_handler parameterList; }

#define llrp_StreamRead(pContext, readLength, readWaitForever, pReadResult) \
    (pContext)->stream_read_handler(pContext, readLength, readWaitForever, pReadResult)

#define llrp_StreamGetOffset(pContext) \
    (pContext)->stream_get_offset_handler(pContext)

/* ------------------------------------------------------------------------------- */
/* Parsing                                                                         */

int llrp_ParseMessage(t_llrp_parse_context *context)
{
    unsigned char ucVersion;
    unsigned short *pusData, usValidatorIndex, usMessageIndex, usType;
    unsigned long *pulData, ulLength, ulID, ulReadBytes;
    t_llrp_parse_validator *validator;
    int bContinueParse;

    /* Make sure the context is valid */
    if(context->stream_read_handler == NULL || context->stream_get_offset_handler == NULL)
    {
        llrp_ReportError(context, (context, LLRP_CONTEXT_ERROR, 0, "llrp_ParseMessage",
         "Invalid context"));
        return LLRP_PARSE_RESULT_FAILURE;
    }

    /* Ensure the stream starts at offset 0 */
    if(llrp_StreamGetOffset(context) != 0)
    {
        llrp_ReportError(context, (context, LLRP_CONTEXT_ERROR, 0, "llrp_ParseMessage",
         "Stream not starting at offset zero (current offset %lu)", llrp_StreamGetOffset(context)));
        return LLRP_PARSE_RESULT_FAILURE;
    }

    context->depth = 0; /* Messages always begin at parse depth 0 */

    /* Bytes 0-1: Type and version */
    pusData= (unsigned short *) llrp_StreamRead(context, 2, 1, &ulReadBytes);
    if(ulReadBytes != 2)
    {
        /* No error here - this happens when the stream read timed out */
        return LLRP_PARSE_RESULT_NO_PARSE;
    }
    ucVersion = (unsigned char) (((unsigned char)((llrp_ntohs(*pusData)) >> 10)) & 0x07);
    usType = (unsigned short) (llrp_ntohs(*pusData) & 0x3FF);

    /* Bytes 2-5: Message length */
    pulData = (unsigned long *) llrp_StreamRead(context, 4, 0, &ulReadBytes);
    if(ulReadBytes != 4)
    {
        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_MESSAGE_DATA_UNDERFLOW, 0,
         "llrp_ParseMessage", "Failed to read message length bytes"));
        return LLRP_PARSE_RESULT_PARSE_FAILED;
    }
    ulLength = llrp_ntohl(*pulData);

    /* Bytes 6-9: Message ID */
    pulData = (unsigned long *) llrp_StreamRead(context, 4, 0, &ulReadBytes);
    if(ulReadBytes != 4)
    {
        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_MESSAGE_DATA_UNDERFLOW, 0, 
         "llrp_ParseMessage", "Failed to read message ID bytes"));
        return LLRP_PARSE_RESULT_PARSE_FAILED;
    }
    ulID = llrp_ntohl(*pulData);

    /* TODO: Use the message version to select the proper validator */
    for(usValidatorIndex = 0; usValidatorIndex < context->validator_count; usValidatorIndex++)
    {
        validator = context->validator_list[usValidatorIndex];
        for(usMessageIndex = 0; usMessageIndex < validator->message_count; usMessageIndex++)
        {
            if(validator->message_list[usMessageIndex].number == usType)
            {
                llrp_ReportMessage(context, (context, "llrp_ParseMessage", 
                 "Message header parsed: version %u, type %u, length %u, ID %u",
                 ucVersion, usType, ulLength, ulID));
                
                if(context->message_start_handler != NULL)
                {
                    bContinueParse= context->message_start_handler(context, ucVersion, usType,
                     ulLength, ulID, (validator->message_list[usMessageIndex].item)->name);
                }
                else
                    bContinueParse = 1;

                if(bContinueParse)
                {
                    llrp_ParseCompoundItem(context, validator->message_list[usMessageIndex].item,
                     ulLength-LLRP_HEADER_LENGTH);
                }
                else
                {
                    llrp_ReportMessage(context, (context, "llrp_ParseMessage", "Skipping message parse"));

                    /* Consume/discard all remaining message data */
                    (void)llrp_StreamRead(context, ulLength-LLRP_HEADER_LENGTH, 0, &ulReadBytes);
                }

                if(context->message_finished_handler != NULL)
                {
                    (void)context->message_finished_handler(context, ucVersion, usType,
                     ulLength, ulID, (validator->message_list[usMessageIndex].item)->name);
                }

                return LLRP_PARSE_RESULT_SUCCESS;
            }
            if(validator->message_list[usMessageIndex].number > usType)
                break;
        }
    }
    
    llrp_ReportError(context, (context, LLRP_PARSE_ERROR_MESSAGE_TYPE_UNKNOWN, usType,
     "llrp_ParseMessage", "Unknown message type (%u)", usType));

    /* Consume/discard all remaining message data */
    (void)llrp_StreamRead(context, ulLength-LLRP_HEADER_LENGTH, 0, &ulReadBytes);

    return LLRP_PARSE_RESULT_PARSE_FAILED;
}

static void llrp_ParseParameter(t_llrp_parse_context *context, unsigned short usType,
 int bImpliedLength, unsigned short usLength)
{
    unsigned short usTypeIndex, usValidatorIndex;
    unsigned long ulReadBytes;
    t_llrp_parse_validator *validator;
    t_llrp_standard_map_item *pMapItem;
    t_llrp_compound_item *pItem;

    for(usValidatorIndex = 0; usValidatorIndex < context->validator_count; usValidatorIndex++)
    {
        validator = context->validator_list[usValidatorIndex];
        for(usTypeIndex = 0; usTypeIndex < validator->parameter_count; usTypeIndex++)
        {
            if(validator->parameter_list[usTypeIndex].number == usType)
            {
                pMapItem = &(validator->parameter_list[usTypeIndex]);
                pItem = pMapItem->item;

                if(bImpliedLength)
                {
                    /* Calculate the length of all parameter contents. Normally this means
                     *  the parameter is TV encoded, containing only fixed-length fields
                     *  and no sub-parameters. */
                    if(!llrp_ParseGetParameterContentLength(pItem, &usLength))
                    {
                        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_TV_NOT_FOUND,
                         usType, "llrp_ParseParameter", "Failed to determine content size of parameter '%s' (ID %u)",
                         pItem->name, usType));
                        break;
                    }
                }

                if(context->parameter_start_handler!= NULL)
                    context->parameter_start_handler(context, usType, pItem->name, usLength);

                llrp_ParseCompoundItem(context, pItem, usLength);

                if(context->parameter_finished_handler!= NULL)
                    context->parameter_finished_handler(context, usType, pItem->name, usLength);
                return;
            }

            /* Since the parameter list is ordered (ascending), break out of the loop
               once we've passed the usType we're looking for. */
            if(validator->parameter_list[usTypeIndex].number > usType)
                break;
        }
    }

    llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_TYPE_UNKNOWN, usType,
     "llrp_ParseParameter", "Unknown parameter type (%u)", usType));

    /* Discard the bytes in this unknown parameter */
    (void)llrp_StreamRead(context, usLength, 0, &ulReadBytes);
    if(ulReadBytes != usLength)
    {
        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW, usType,
         "llrp_ParseParameter", "Failed to read %u discarded bytes (%u read)",
         usLength, ulReadBytes));
    }
}

static void llrp_ParseCustomParameter(t_llrp_parse_context *context, unsigned short usType,
 unsigned short usLength)
{
    unsigned short usTypeIndex, usValidatorIndex;
    unsigned long *pulData, ulReadBytes, ulVendorID, ulSubtype;
    t_llrp_parse_validator *validator;
    t_llrp_custom_map_item *pMapItem;
    t_llrp_compound_item *pItem;

    if(usLength < 8)
    {
        llrp_ReportMessage(context, (context, "llrp_ParseCustomParameter", "Invalid content length for custom parameter"));
    }
    else
    {
        /* Actual parameter length doesn't include the vendor ID or subtype */
        usLength = usLength - 8;

        pulData = (unsigned long *)llrp_StreamRead(context, 4, 0, &ulReadBytes);
        if(ulReadBytes == 4)
            ulVendorID = llrp_ntohl(*pulData);
        else
        {
                llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW, usType,
                            "llrp_ParseCustomParameter", "Failed to read vendor ID"));
                return;
        }

        pulData = (unsigned long *)llrp_StreamRead(context, 4, 0, &ulReadBytes);
        if(ulReadBytes == 4)
            ulSubtype = llrp_ntohl(*pulData);
        else
        {
                llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW, usType,
             "llrp_ParseCustomParameter", "Failed to read subtype"));
                return;
        }

        for(usValidatorIndex = 0; usValidatorIndex < context->validator_count; usValidatorIndex++)
        {
            validator = context->validator_list[usValidatorIndex];
            for(usTypeIndex = 0; usTypeIndex < validator->custom_parameter_count; usTypeIndex++)
            {
                pMapItem = &(validator->custom_parameter_list[usTypeIndex]);
                if(pMapItem->vendor_id == ulVendorID && pMapItem->subtype == ulSubtype)
                {
                    pItem = pMapItem->item;

                    if(context->custom_parameter_start_handler!= NULL)
                    {
                        context->custom_parameter_start_handler(context, usType, ulVendorID,
                         ulSubtype, pItem->name, usLength);
                    }

                    llrp_ParseCompoundItem(context, pItem, usLength);

                    if(context->custom_parameter_finished_handler!= NULL)
                    {
                        context->custom_parameter_finished_handler(context, usType, ulVendorID,
                         ulSubtype, pItem->name, usLength);
                    }
                    return;  
                }
            }
        }

        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_TYPE_UNKNOWN, usType,
         "llrp_ParseCustomParameter", "Unknown custom parameter (type %u, vendor %lu, subtype %lu)",
         usType, ulVendorID, ulSubtype));
    }

    /* Discard the bytes in this unknown parameter */
    (void)llrp_StreamRead(context, usLength, 0, &ulReadBytes);
    if(ulReadBytes != usLength)
    {
        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW, usType,
         "llrp_ParseCustomParameter", "Failed to read %u discarded bytes (%u read)",
         usLength, ulReadBytes));
    }
}

static void llrp_ParseCompoundItem(t_llrp_parse_context *context,
 t_llrp_compound_item *pCompoundItem, unsigned long ulTotalLength)
{
    unsigned short usParsedItems, usItemsRemaining;
    unsigned long ulStartOffset, ulConsumedBytes, ulLengthRemaining;

    ulStartOffset = llrp_StreamGetOffset(context);

    llrp_ReportMessage(context, (context, "llrp_ParseCompoundItem", 
     "Beginning parse of compound item '%s', type '%s', containing %u item%s, length %u bytes, stream offset %u",
     pCompoundItem->name, llrp_compound_item_name[pCompoundItem->type], pCompoundItem->item_count,
     (pCompoundItem->item_count == 1) ? "" : "s", ulTotalLength, ulStartOffset));

    /* Each time a compound item is parsed, increase the depth. */
    (context->depth)++;

    /* Parse all fixed-length items. These must occur first. */
    if(!llrp_ParseFixedItems(context, (t_llrp_item *) pCompoundItem->item_list,
     pCompoundItem->item_count, &usParsedItems, ulTotalLength, &ulConsumedBytes))
    {
        llrp_ReportMessage(context, (context, "llrp_ParseCompoundItem", 
         "Error while parsing fixed items in '%s'", pCompoundItem->name));
    }
    else
    {
        ulLengthRemaining = (unsigned long) (ulTotalLength - ulConsumedBytes);
        usItemsRemaining = (unsigned short) ((pCompoundItem->item_count) - usParsedItems);

        llrp_ReportMessage(context, (context, "llrp_ParseCompoundItem",
         "Finished parsing fixed items. Length remaining %lu, items remaining %u, stream offset %u",
         ulLengthRemaining, usItemsRemaining, llrp_StreamGetOffset(context)));

        /* Parse all remaining data in the message */
        if(usItemsRemaining > 0)
        {
            (void)llrp_ParseVariableItems(context, &((t_llrp_item *) pCompoundItem->item_list)[usParsedItems],
             usItemsRemaining, ulLengthRemaining);
        }
    }

    ulConsumedBytes = (unsigned long) (llrp_StreamGetOffset(context) - ulStartOffset);

    llrp_ReportMessage(context, (context, "llrp_ParseCompoundItems",
     "Finished parsing compound item '%s'. Buffer offset %lu, consumed bytes %lu",
     pCompoundItem->name, llrp_StreamGetOffset(context), ulConsumedBytes));
	
    /* Make sure we've consumed the exact number of expected bytes */
    if(ulConsumedBytes < ulTotalLength)
    {
        unsigned long ulReadLength;

        ulLengthRemaining = (unsigned long) (ulTotalLength - ulConsumedBytes);
        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_OVERFLOW,
         pCompoundItem->type, "llrp_ParseCompoundItem", "%u leftover bytes in parameter %s",
         ulLengthRemaining, pCompoundItem->name));
        (void)llrp_StreamRead(context, ulLengthRemaining, 0, &ulReadLength);
        if(ulReadLength != ulLengthRemaining)
        {
            llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW,
             pCompoundItem->type, "llrp_ParseCompoundItem",
             "Failed to read %u leftover bytes (%u read)", ulLengthRemaining, ulReadLength));
        }
    }
    else if(ulConsumedBytes > ulTotalLength)
    {
        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_OVERFLOW,
         pCompoundItem->type, "llrp_ParseCompoundItem",
         "Buffer read overflow while parsing parameter %s (total: %u, consumed %u)",
         pCompoundItem->name, ulTotalLength, ulConsumedBytes));
    }

    (context->depth)--;

    llrp_ReportMessage(context, (context, "llrp_ParseCompoundItem",
     "Finished parsing compound item '%s'", pCompoundItem->name));
}

static int llrp_ParseFixedItems(t_llrp_parse_context *context, t_llrp_item *pItemList,
 unsigned short usTotalItems, unsigned short *pusParsedItems, unsigned long ulTotalLength,
 unsigned long *pulConsumedBytes)
{
    t_llrp_item *pItem = pItemList;
    int bDone = 0, bSuccess = 1;
    unsigned short usItemIndex, usFieldIndex;
    unsigned char ucAccumulatedBits, ucBitAccumulator;
    unsigned long ulStartOffset, ulConsumedBytes;

    usFieldIndex = 0;
    usItemIndex = 0;
    ucAccumulatedBits = 0;
    ulConsumedBytes = 0;
    ulStartOffset = llrp_StreamGetOffset(context);
    while(!bDone)
    {
        ulConsumedBytes = (unsigned long) (llrp_StreamGetOffset(context) - ulStartOffset);

        if(usItemIndex >= usTotalItems)
            bDone = 1;
        else
        {
            llrp_ReportMessage(context, (context, "llrp_ParseFixedItems",
             "Parsing fixed item index %u of %u, type %u, consumed bytes %lu, offset %lu",
             usItemIndex, usTotalItems, pItem->item_type, ulConsumedBytes,
             llrp_StreamGetOffset(context)));

            switch(pItem->item_type)
            {
                case LLRP_ITEM_FIELD:
                    if(!llrp_HandleField(context, pItem, usFieldIndex, 
                     (unsigned long) (ulTotalLength-ulConsumedBytes), &ucBitAccumulator,
                     &ucAccumulatedBits))
                    {
                        bSuccess = 0;
                        bDone = 1;
                    }
                    usFieldIndex++;
                    break;
                case LLRP_ITEM_RESERVED:
                    if((pItem->min_repeat_count)%8 > ucAccumulatedBits)
                    {
                        llrp_ReportError(context, (context, LLRP_PARSE_ERROR_FIELD_DATA_UNDERFLOW,
                         usFieldIndex, "llrp_ParseFixedItems",
                         "Only %u accumulated bits remaining for %u bit reserved field",
                         ucAccumulatedBits, pItem->min_repeat_count));
                        ucAccumulatedBits = 0;  /* Try to zero the accumulator, problems will likely follow */
                    }
                    else
                    {
                        if(pItem->min_repeat_count >= 8)
                        {
                            unsigned long ulReadBytes;

                            /* Discard whole bytes... */
                            (void)llrp_StreamRead(context, (pItem->min_repeat_count)/8, 0, &ulReadBytes);
                            if(ulReadBytes != (unsigned long)((pItem->min_repeat_count)/8))
                            {
                                llrp_ReportError(context, (context, LLRP_PARSE_ERROR_FIELD_DATA_UNDERFLOW,
                                 usFieldIndex, "llrp_ParseFixedItems",
                                 "Failed to consume %u reserved bytes from message stream for reserved field of %u bits",
                                 (pItem->min_repeat_count)/8, pItem->min_repeat_count));
                            }
                        }                                

                        ucAccumulatedBits = (unsigned char) (ucAccumulatedBits-((pItem->min_repeat_count)%8));
                        llrp_ReportMessage(context, (context, "llrp_ParseFixedItems", 
                         "Consumed %u reserved bits (accumulator now %u)", pItem->min_repeat_count,
                         ucAccumulatedBits));
                    }                        
                    break;
                case LLRP_ITEM_PARAMETER:
                case LLRP_ITEM_CHOICE:
                    /* When we encounter the first variable-length item, we're done parsing
                       the fixed-length items. */
                    bDone = 1;
                    break;
                default:
                    llrp_ReportError(context, (context, LLRP_PARSE_ERROR_FIELD_TYPE_UNKNOWN,
                     usFieldIndex, "llrp_ParseFixedItems", "Unknown fixed item field type (%u)",
                     pItem->item_type));
                    break;
            }

            if(!bDone)
            {
                usItemIndex++;
                pItem++;
            }
        }
    }

    if(context->field_complete_handler != NULL)
        context->field_complete_handler(context, usFieldIndex);
	
    if(pusParsedItems != NULL)
        *pusParsedItems = usItemIndex;
    if(pulConsumedBytes != NULL)
        *pulConsumedBytes = ulConsumedBytes;

    return bSuccess;
}

static int llrp_HandleField(t_llrp_parse_context *context, t_llrp_item *pItem,
 unsigned short usFieldIndex, unsigned long ulTotalLength,
 unsigned char *pucBitAccumulator, unsigned char *pucAccumulatedBits)
{
    unsigned long ulItemBits, ulItemBytes, ulLeftoverBits, ulReadBytes, ulLengthRemaining;
    unsigned char *pucData, ucUsedAccumulator;

    if(LLRP_FIELDTYPE_IS_VARIABLE(pItem->field_type))
    {
        unsigned short *pusData;

        if(ulTotalLength < 2)
        {
            llrp_ReportError(context, (context, LLRP_PARSE_ERROR_FIELD_DATA_UNDERFLOW, usFieldIndex,
             "llrp_HandleField", "Buffer underrun while reading length of variable field '%s', index %u",
             pItem->name, usFieldIndex));
            return 0; /* Failed to handle this field */
        }

        pusData = (unsigned short *) llrp_StreamRead(context, 2, 0, &ulReadBytes);
        if(ulReadBytes != 2)
        {
            llrp_ReportError(context, (context, LLRP_PARSE_ERROR_FIELD_DATA_UNDERFLOW,
             usFieldIndex, "llrp_HandleField",
             "Failed to read the length of variable field '%s', index %u", pItem->name, usFieldIndex));
            return 0; /* Failed to handle this field */
        }
        ulItemBits = (unsigned long) (llrp_ntohs(*pusData)*
         llrp_variable_field_bitlength[LLRP_FIELDTYPE_INDEX_VARIABLE(pItem->field_type)]);
        ulLengthRemaining = (unsigned long) (ulTotalLength-2);
    }
    else if(pItem->field_type == LLRP_FIELDTYPE_bytesToEnd)
    {
        ulLengthRemaining = ulTotalLength;  /* Consume the entire remaining length */
        ulItemBits = (unsigned long) (ulLengthRemaining*8);
    }
    else
    {
        ulItemBits = llrp_fixed_field_bitlength[pItem->field_type];
        ulLengthRemaining = ulTotalLength;
    }

    ulItemBytes = (unsigned long) ((ulItemBits/8) + ((ulItemBits%8) ? 1 : 0));
    ulLeftoverBits = (unsigned long) ((ulItemBytes*8) - ulItemBits);

    /* Is there enough data stored in the accumulator? */
    if(ulItemBits <= *pucAccumulatedBits)
    {
        /* LLRP is bitwise big-endian; extract the topmost ulItemBits bits from the accumulator */
        ucUsedAccumulator = (unsigned char) ((*pucBitAccumulator) >> ((*pucAccumulatedBits)-ulItemBits));
        ucUsedAccumulator &= ((1 << ulItemBits)-1); /* Mask off unwanted bits */
        pucData = &ucUsedAccumulator;
        /* No need to clear the used bits from the accumulator. They're invalidated by
         *  an update to pucAccumulatedBits. */
        *pucAccumulatedBits = (unsigned char) ((*pucAccumulatedBits)-ulItemBits);
        ulLeftoverBits = 0;
    }
    else /* No, we must get the data from the message */
    {
        if(ulItemBytes > ulLengthRemaining)
        {
            llrp_ReportError(context, (context, LLRP_PARSE_ERROR_FIELD_DATA_UNDERFLOW,
             usFieldIndex, "llrp_HandleField",
             "Data underrun for field '%s', index %u (expected %u bytes, %u remain)",
             pItem->name, usFieldIndex, ulItemBytes, ulLengthRemaining));
            return 0; /* Failed to handle this field */
        }
        pucData= llrp_StreamRead(context, ulItemBytes, 0, &ulReadBytes);
        if(ulReadBytes!= ulItemBytes)
        {
            llrp_ReportError(context, (context, LLRP_PARSE_ERROR_FIELD_DATA_UNDERFLOW,
             usFieldIndex, "llrp_HandleField",
             "Failed to read %u data bytes of field '%s', index %u (%u read)",
             ulItemBytes, pItem->name, usFieldIndex, ulReadBytes));
            return 0; /* Failed to handle this field */
        }
    }

    if(ulLeftoverBits > 0)
    {
        /* If there is any data that has been read from the message, but doesn't belong to */
        /*  this field, add it to the accumulator. */
        if((ulLeftoverBits+*pucAccumulatedBits) >= 8)
        {
            llrp_ReportError(context, (context, LLRP_PARSE_ERROR_FIELD_DATA_OVERFLOW,
             usFieldIndex, "llrp_HandleField",
             "Leftover bit accumulator overflow (accumulator bits: %u, new leftover bits: %u)",
             *pucAccumulatedBits, ulLeftoverBits));
        }
        else
        {
            /* Bits are always added to the accumulator from the right (least significant bit) side */
            *pucBitAccumulator<<= ulLeftoverBits;
            *pucBitAccumulator|= pucData[ulItemBytes-1] & ((1 << ulLeftoverBits)-1);
            *pucAccumulatedBits= (unsigned char) ((*pucAccumulatedBits)+ulLeftoverBits);
        }

        /* Always mask-off the bits that don't belong to this field */
        if(ulItemBits <= 8)
        {
            ucUsedAccumulator= (unsigned char) (((*pucData) >> (8-ulItemBits)) & ((1 << ulItemBits)-1));
            pucData= &ucUsedAccumulator;
        }
    }

    llrp_ReportMessage(context, (context, "llrp_HandleField",
     "Field '%s' parsed: fieldtype %u, bitlength %u, accumulator %u",
     pItem->name, pItem->field_type, ulItemBits, *pucAccumulatedBits));
    if(context->field_handler!= NULL)
    {
        context->field_handler(context, usFieldIndex, pItem->field_type, pItem->name,
         ulItemBits, pucData, pItem->data);
    }

    return 1; /* Successfully handled */
}

/* Function: llrp_ParseVariableItems */
/* Description: Parse all remaining data in the current compound item (message or parameter).
 *  Parsing is completed only when all data has been exhausted from the current compound item.
 *  It is assumed that no fixed-length items remain in the current compound item, they have
 *  already been parsed. */
/* Returns: nonzero upon successful parsing of all variable items in the compound item,
 *  zero upon failure. */
#define LLRP_VARIABLE_ITEM_MIN_HEADER_LENGTH  1 /* TV parameters require only one byte */
static int llrp_ParseVariableItems(t_llrp_parse_context *context, t_llrp_item *pItemList,
 unsigned short usTotalItems, unsigned long ulTotalLength)
{
    t_llrp_item *pItem = pItemList;
    int bDone = 0, bImpliedLength;
    unsigned long ulReadBytes, ulConsumedLength, ulStartOffset;
    unsigned char *pucReadByte, ucHeaderLength;
    unsigned short *pusLength, usType, usLength;

    pItem=pItem; usTotalItems=usTotalItems;

    ulStartOffset = llrp_StreamGetOffset(context);
    while(!bDone)
    {
        ulConsumedLength = (unsigned long) (llrp_StreamGetOffset(context) - ulStartOffset);

        /* Make sure we can at least read the minimum header length */
        if((ulConsumedLength+LLRP_VARIABLE_ITEM_MIN_HEADER_LENGTH) > ulTotalLength)
            bDone = 1;
        else
        {
            /* Determine the type and length */
            ucHeaderLength = LLRP_VARIABLE_ITEM_MIN_HEADER_LENGTH;
            pucReadByte = (unsigned char *) llrp_StreamRead(context, 1, 0, &ulReadBytes);
            if(ulReadBytes != 1)
            {
                llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW,
                 0, "llrp_ParseVariableItems", "Failed to read first type byte of parameter"));
                return 0; /* Failed to parse */
            }
            usType = *pucReadByte;
            if(usType & 0x80) /* Is this a TV encoded parameter? */
            {
                usType &= ~0x80;
                usLength = 0;
                bImpliedLength = 1; /* Length is implied - make llrp_ParseParameter() derive it */
            }
            else
            {
                ucHeaderLength = 4; /* TLV parameter headers have 2 type bytes, 2 length bytes */
                bImpliedLength = 0;

                /* Get the second byte of the TLV parameter's type */
                pucReadByte = (unsigned char *) llrp_StreamRead(context, 1, 0, &ulReadBytes);
                if(ulReadBytes != 1)
                {
                    llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW,
                     0, "llrp_ParseVariableItems", "Failed to read second type byte of TLV parameter"));
                    return 0; /* Failed to parse the variable item */
                }
                usType <<= 8;
                usType = (unsigned short) (usType+(*pucReadByte));

                /* TLV parameters have 2 bytes for the length */
                pusLength = (unsigned short *) llrp_StreamRead(context, 2, 0, &ulReadBytes);
                if(ulReadBytes != 2)
                {
                    llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW,
                     usType, "llrp_ParseVariableItems", "Failed to read length bytes of TLV parameter"));
                    return 0; /* Failed to parse the variable item */
                }
                usLength = llrp_ntohs(*pusLength);
			
                /* A rather pedantic test... */
                if(usLength < ucHeaderLength)
                {
                    llrp_ReportError(context, (context, LLRP_PARSE_ERROR_PARAMETER_DATA_UNDERFLOW,
                     usType, "llrp_ParseVariableItems",
                     "Length underflow for variable item type %u (requires %u bytes, %u in header)",
                     usType, usLength, ucHeaderLength));
                    return 0; /* Failed to parse the variable item */
                }
                usLength = (unsigned short) (usLength-ucHeaderLength);
            }

            llrp_ReportMessage(context, (context, "llrp_ParseVariableItems",
             "Parsing variable item: type %u, header length %u, data length %u",
             usType, ucHeaderLength, usLength));

            /* TODO: Validate the parameter found against pItem */

            if(usType == 1023) /* v1.0 Custom parameter type */
                llrp_ParseCustomParameter(context, usType, usLength);
            else
                llrp_ParseParameter(context, usType, bImpliedLength, usLength);
        }
    }

    if(context->all_parameters_complete_handler!= NULL)
        context->all_parameters_complete_handler(context);

    return 1; /* Variable item parsed successfully */
}

/* Determine the length of the contents of the specified compound item. This will only succeed
 *  when the compound item contains nothing more than fixed-length fields. */
static int llrp_ParseGetParameterContentLength(const t_llrp_compound_item *pItem,
 unsigned short *pusLength)
{
    unsigned short usIndex, usLength;
    t_llrp_item *pField;

    usLength= 0;
    for(usIndex= 0; usIndex< pItem->item_count; usIndex++)
    {
        pField= &((t_llrp_item *) (pItem->item_list))[usIndex];
        switch(pField->item_type)
        {
            case LLRP_ITEM_FIELD:
                if(LLRP_FIELDTYPE_IS_VARIABLE(pField->field_type))
                    return 0; /* Not a constant content length, can't calculate content length */
                usLength= (unsigned short) (usLength+((llrp_fixed_field_bitlength[pField->field_type])/8));
                break;
            default:
                return 0; /* Contains items that are not fields, can't calculate content length */
        }
    }

    if(pusLength!= NULL)
        *pusLength= usLength;
    return 1; /* Length calculated successfully */
}
