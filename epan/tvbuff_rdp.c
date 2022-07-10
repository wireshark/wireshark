/* tvbuff_rdp.c
 * Decompression routines used in RDP
 * Copyright 2021, David Fort
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <glib.h>
#include <stdbool.h>

#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/tvbuff_rdp.h>

enum {
	ZGFX_SEGMENTED_SINGLE = 0xe0,
	ZGFX_SEGMENTED_MULTIPART = 0xe1,

	ZGX_PACKET_COMPRESSED = 0x20,
};


typedef struct {
	tvbuff_t *input;
	guint offset;
	guint remainingBits;
	guint32 currentValue;
	guint currentBits;
} bitstream_t;

static void
bitstream_init(bitstream_t *b, tvbuff_t *input, guint blen) {
	b->input = input;
	b->offset = 0;
	b->remainingBits = blen;
	b->currentValue = 0;
	b->currentBits = 0;
}

static guint32
bitstream_getbits(bitstream_t *b, guint8 nbits, gboolean *ok) {
	guint32 ret = 0;

	if (nbits > b->remainingBits) {
		*ok = FALSE;
		return 0;
	}

	while (b->currentBits < nbits) {
		if (!tvb_reported_length_remaining(b->input, b->offset)) {
			*ok = FALSE;
			return 0;
		}

		b->currentValue <<= 8;
		b->currentValue += tvb_get_guint8(b->input, b->offset++);

		b->currentBits += 8;
	}

	*ok = TRUE;
	ret = b->currentValue >> (b->currentBits-nbits);
	b->currentBits -= nbits;
	b->remainingBits -= nbits;
	b->currentValue &= (1 << b->currentBits) - 1;

	return ret;
}

static gboolean
bitstream_copyraw(bitstream_t *b, guint8 *dest, gint nbytes)
{
	if (tvb_captured_length_remaining(b->input, b->offset) < nbytes)
		return FALSE;

	tvb_memcpy(b->input, dest, b->offset, nbytes);

	return TRUE;
}

static gboolean
bitstream_copyraw_advance(bitstream_t *b, guint8 *dest, guint nbytes)
{
	if (!bitstream_copyraw(b, dest, nbytes))
		return FALSE;

	b->offset += nbytes;
	return TRUE;
}


static void
bitstream_realign(bitstream_t *b) {
	b->remainingBits -= b->currentBits;
	b->currentBits = 0;
	b->currentValue = 0;
}

typedef struct {
	guint32 prefixLength;
	guint32 prefixCode;
	guint32 valueBits;
	guint32 valueBase;
} zgfx_token_t;

static const zgfx_token_t ZGFX_LITTERAL_TABLE[] = {
	// prefixLength prefixCode valueBits valueBase
	{ 5,  24, 0, 0x00 },   // 11000
	{ 5,  25, 0, 0x01 },   // 11001
	{ 6,  52, 0, 0x02 },   // 110100
	{ 6,  53, 0, 0x03 },   // 110101
	{ 6,  54, 0, 0xFF },   // 110110
	{ 7, 110, 0, 0x04 },   // 1101110
	{ 7, 111, 0, 0x05 },   // 1101111
	{ 7, 112, 0, 0x06 },   // 1110000
	{ 7, 113, 0, 0x07 },   // 1110001
	{ 7, 114, 0, 0x08 },   // 1110010
	{ 7, 115, 0, 0x09 },   // 1110011
	{ 7, 116, 0, 0x0A },   // 1110100
	{ 7, 117, 0, 0x0B },   // 1110101
	{ 7, 118, 0, 0x3A },   // 1110110
	{ 7, 119, 0, 0x3B },   // 1110111
	{ 7, 120, 0, 0x3C },   // 1111000
	{ 7, 121, 0, 0x3D },   // 1111001
	{ 7, 122, 0, 0x3E },   // 1111010
	{ 7, 123, 0, 0x3F },   // 1111011
	{ 7, 124, 0, 0x40 },   // 1111100
	{ 7, 125, 0, 0x80 },   // 1111101
	{ 8, 252, 0, 0x0C },   // 11111100
	{ 8, 253, 0, 0x38 },   // 11111101
	{ 8, 254, 0, 0x39 },   // 11111110
	{ 8, 255, 0, 0x66 },   // 11111111
};

static const zgfx_token_t ZGFX_MATCH_TABLE[] = {
	// prefixLength prefixCode valueBits tokenType valueBase
	{ 5, 17, 5, 0 },          // 10001
	{ 5, 18, 7, 32 },         // 10010
	{ 5, 19, 9, 160 },        // 10011
	{ 5, 20, 10, 672 },       // 10100
	{ 5, 21, 12, 1696 },      // 10101
	{ 6, 44, 14, 5792 },      // 101100
	{ 6, 45, 15, 22176 },     // 101101
	{ 7, 92, 18, 54944 },     // 1011100
	{ 7, 93, 20, 317088 },    // 1011101
	{ 8, 188, 20, 1365664 },  // 10111100
	{ 8, 189, 21, 2414240 },  // 10111101
	{ 9, 380, 22, 4511392 },  // 101111100
	{ 9, 381, 23, 8705696 },  // 101111101
	{ 9, 382, 24, 17094304 }, // 101111110
};


struct _zgfx_context_t{
	guint8 historyBuffer[2500000];
	guint32 historyIndex;
	guint32 historyBufferSize;

	guint32 outputCount;
	guint8 outputSegment[65536];
};

zgfx_context_t *zgfx_context_new(wmem_allocator_t *allocator) {
	zgfx_context_t *ret = wmem_alloc0(allocator, sizeof(*ret));
	ret->historyBufferSize = sizeof(ret->historyBuffer);
	return ret;
}

static void
zgfx_write_history_litteral(zgfx_context_t *zgfx, guint8 c)
{
	zgfx->historyBuffer[zgfx->historyIndex] = c;
	zgfx->historyIndex = (zgfx->historyIndex + 1) % zgfx->historyBufferSize;
}

static void
zgfx_write_history_buffer_tvb(zgfx_context_t *zgfx, tvbuff_t *src, guint32 count)
{
	gint src_offset = 0;
	guint32 front;

	if (count > zgfx->historyBufferSize) {
		const guint32 residue = count - zgfx->historyBufferSize;
		count = zgfx->historyBufferSize;
		src_offset += residue;
		zgfx->historyIndex = (zgfx->historyIndex + residue) % zgfx->historyBufferSize;
	}

	if (zgfx->historyIndex + count <= zgfx->historyBufferSize)
	{
		tvb_memcpy(src, &(zgfx->historyBuffer[zgfx->historyIndex]), src_offset, count);
	}
	else
	{
		front = zgfx->historyBufferSize - zgfx->historyIndex;
		tvb_memcpy(src, &(zgfx->historyBuffer[zgfx->historyIndex]), src_offset, front);
		tvb_memcpy(src, &(zgfx->historyBuffer), src_offset + count, count - front);
	}

	zgfx->historyIndex = (zgfx->historyIndex + count) % zgfx->historyBufferSize;
}


static void
zgfx_write_history_buffer(zgfx_context_t *zgfx, const guint8 *src, guint32 count)
{
	guint32 front;

	if (count > zgfx->historyBufferSize) {
		const guint32 residue = count - zgfx->historyBufferSize;
		count = zgfx->historyBufferSize;
		zgfx->historyIndex = (zgfx->historyIndex + residue) % zgfx->historyBufferSize;
	}

	if (zgfx->historyIndex + count <= zgfx->historyBufferSize)
	{
		memcpy(&(zgfx->historyBuffer[zgfx->historyIndex]), src, count);
	}
	else
	{
		front = zgfx->historyBufferSize - zgfx->historyIndex;
		memcpy(&(zgfx->historyBuffer[zgfx->historyIndex]), src, front);
		memcpy(&(zgfx->historyBuffer), src + front, count - front);
	}

	zgfx->historyIndex = (zgfx->historyIndex + count) % zgfx->historyBufferSize;
}


static gboolean
zgfx_write_litteral(zgfx_context_t *zgfx, guint8 c)
{
	if (zgfx->outputCount == 65535)
		return FALSE;

	zgfx->outputSegment[zgfx->outputCount++] = c;

	zgfx_write_history_litteral(zgfx, c);
	return TRUE;
}

static gboolean
zgfx_write_raw(zgfx_context_t *zgfx, bitstream_t *b, guint32 count)
{
	guint32 rest, tocopy;

	/* first copy in the output buffer */
	if (zgfx->outputCount > 65535 - count)
		return FALSE;

	if (!bitstream_copyraw(b, &(zgfx->outputSegment[zgfx->outputCount]), count))
		return FALSE;

	/* then update the history buffer */
	rest = (zgfx->historyBufferSize - zgfx->historyIndex);
	tocopy = count;
	if (rest < count)
		tocopy = rest;

	if (!bitstream_copyraw_advance(b, &(zgfx->historyBuffer[zgfx->historyIndex]), tocopy))
		return FALSE;

	zgfx->historyIndex = (zgfx->historyIndex + tocopy) % zgfx->historyBufferSize;
	count -= tocopy;
	if (count) {
		if (!bitstream_copyraw_advance(b, &(zgfx->historyBuffer[zgfx->historyIndex]), tocopy))
			return FALSE;

		zgfx->historyIndex = (zgfx->historyIndex + tocopy) % zgfx->historyBufferSize;
	}

	return TRUE;
}

static gboolean
zgfx_write_from_history(zgfx_context_t *zgfx, guint32 distance, guint32 count)
{
	guint idx;
	guint32 remainingCount, copyTemplateSize, toCopy;
	guint8 *outputPtr;

	if (zgfx->outputCount > 65535 - count)
		return FALSE;

	remainingCount = count;
	idx = (zgfx->historyIndex + zgfx->historyBufferSize - distance) % zgfx->historyBufferSize;
	copyTemplateSize = (distance > count) ? count : distance;

	/* first do copy a single copy in output */
	outputPtr = &(zgfx->outputSegment[zgfx->outputCount]);
	toCopy = copyTemplateSize;
	if (idx + toCopy < zgfx->historyBufferSize) {
		memcpy(outputPtr, &(zgfx->historyBuffer[idx]), toCopy);
	} else {
		guint32 partial = zgfx->historyBufferSize - idx;
		memcpy(outputPtr, &(zgfx->historyBuffer[idx]), partial);
		memcpy(outputPtr + partial, zgfx->historyBuffer, toCopy - partial);
	}
	outputPtr += toCopy;
	remainingCount -= toCopy;

	/* then duplicate output as much as needed by count, at each loop turn we double
	 * the size of the template we can copy */
	while (remainingCount) {
		toCopy = (remainingCount < copyTemplateSize) ? remainingCount : copyTemplateSize;
		memcpy(outputPtr, &(zgfx->outputSegment[zgfx->outputCount]), toCopy);

		outputPtr += toCopy;
		remainingCount -= toCopy;
		copyTemplateSize *= 2;
	}

	/* let's update the history from output and update counters */
	zgfx_write_history_buffer(zgfx, &(zgfx->outputSegment[zgfx->outputCount]), count);
	zgfx->outputCount += count;
	return TRUE;
}


static gboolean
rdp8_decompress_segment(zgfx_context_t *zgfx, tvbuff_t *tvb)
{
	bitstream_t bitstream;
	gint offset = 0;
	gint len = tvb_reported_length(tvb);
	guint8 flags = tvb_get_guint8(tvb, offset);
	guint8 v;
	offset++;
	len--;

	if (!(flags & ZGX_PACKET_COMPRESSED)) {
		tvbuff_t *raw = tvb_new_subset_remaining(tvb, 1);
		zgfx_write_history_buffer_tvb(zgfx, raw, len);
		return TRUE;
	}

	v = tvb_get_guint8(tvb, offset + len - 1);
	if (v > 7)
		return FALSE;
	len--;

	bitstream_init(&bitstream, tvb_new_subset_length(tvb, offset, len), (len * 8) - v);
	while (bitstream.remainingBits) {
		gboolean ok, ismatch, found;
		guint32 bits_val = bitstream_getbits(&bitstream, 1, &ok);
		guint32 inPrefix;
		const zgfx_token_t *tokens;
		gint ntokens, i;
		guint32 prefixBits;

		if (!ok)
			return FALSE;

		// 0 - litteral
		if (bits_val == 0) {

			bits_val = bitstream_getbits(&bitstream, 8, &ok);
			if (!zgfx_write_litteral(zgfx, bits_val))
				return FALSE;
			continue;
		}

		// 1x - match or litteral branch
		bits_val = bitstream_getbits(&bitstream, 1, &ok);
		if (bits_val == 0) {
			// 10 - match
			ismatch = true;
			tokens = ZGFX_MATCH_TABLE;
			ntokens = sizeof(ZGFX_MATCH_TABLE) / sizeof(ZGFX_MATCH_TABLE[0]);
			inPrefix = 2;
		} else {
			// 11 - litteral
			ismatch = false;
			tokens = ZGFX_LITTERAL_TABLE;
			ntokens = sizeof(ZGFX_LITTERAL_TABLE) / sizeof(ZGFX_LITTERAL_TABLE[0]);
			inPrefix = 3;
		}

		prefixBits = 2;
		found = FALSE;
		for (i = 0; i < ntokens; i++) {
			if (prefixBits != tokens[i].prefixLength) {
				guint32 missingBits = (tokens[i].prefixLength - prefixBits);
				inPrefix <<= missingBits;
				inPrefix |= bitstream_getbits(&bitstream, missingBits, &ok);
				if (!ok)
					return FALSE;
				prefixBits = tokens[i].prefixLength;
			}

			if (inPrefix == tokens[i].prefixCode) {
				found = TRUE;
				break;
			}
		}

		if (!found) // TODO: is it an error ?
			continue;

		if (ismatch) {
			/* It's a match */
			guint32 count, distance, extra = 0;

			distance = tokens[i].valueBase + bitstream_getbits(&bitstream, tokens[i].valueBits, &ok);
			if (!ok)
				return FALSE;

			if (distance != 0) {
				bits_val = bitstream_getbits(&bitstream, 1, &ok);
				if (!ok)
					return FALSE;

				if (bits_val == 0) {
					count = 3;
				} else {
					count = 4;
					extra = 2;

					bits_val = bitstream_getbits(&bitstream, 1, &ok);
					if (!ok)
						return FALSE;

					while (bits_val == 1) {
						count *= 2;
						extra ++;
						bits_val = bitstream_getbits(&bitstream, 1, &ok);
						if (!ok)
							return FALSE;
					}

					count += bitstream_getbits(&bitstream, extra, &ok);
					if (!ok)
						return FALSE;
				}

				if (!zgfx_write_from_history(zgfx, distance, count))
					return FALSE;
			} else {
				/* Unencoded */
				count = bitstream_getbits(&bitstream, 15, &ok);
				if (!ok)
					return FALSE;

				bitstream_realign(&bitstream);
				if (!zgfx_write_raw(zgfx, &bitstream, count))
					return FALSE;
			}
		} else {
			/* Litteral */
			bits_val = tokens[i].valueBase;
			if (!zgfx_write_litteral(zgfx, bits_val))
				return FALSE;
		}
	}

	return TRUE;
}



tvbuff_t *
rdp8_decompress(zgfx_context_t *zgfx, wmem_allocator_t *allocator, tvbuff_t *tvb, guint offset)
{
	void *output;
	guint8 descriptor;

	descriptor = tvb_get_guint8(tvb, offset);
	offset++;

	switch (descriptor) {
	case ZGFX_SEGMENTED_SINGLE:
		zgfx->outputCount = 0;
		if (!rdp8_decompress_segment(zgfx, tvb_new_subset_remaining(tvb, offset)))
			return NULL;

		output = wmem_alloc(allocator, zgfx->outputCount);
		memcpy(output, zgfx->outputSegment, zgfx->outputCount);
		return tvb_new_real_data(output, zgfx->outputCount, zgfx->outputCount);

	case ZGFX_SEGMENTED_MULTIPART: {
		guint16 segment_count, i;
		guint32 output_consumed, uncompressed_size;
		guint8 *output_ptr;

		segment_count = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
		offset += 2;
		uncompressed_size = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
		offset += 4;

		output = output_ptr = wmem_alloc(allocator, uncompressed_size);
		output_consumed = 0;
		for (i = 0; i < segment_count; i++) {
			guint32 segment_size = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
			offset += 4;

			zgfx->outputCount = 0;
			if (!rdp8_decompress_segment(zgfx, tvb_new_subset_length(tvb, offset, segment_size)))
				return NULL;

			output_consumed += zgfx->outputCount;
			if (output_consumed > uncompressed_size) {
				// TODO: error message ?
				return NULL;
			}
			memcpy(output_ptr, zgfx->outputSegment, zgfx->outputCount);

			offset += segment_size;
			output_ptr += zgfx->outputCount;
		}
		return tvb_new_real_data(output, uncompressed_size, uncompressed_size);
	}
	default:
		return tvb;
	}
}
