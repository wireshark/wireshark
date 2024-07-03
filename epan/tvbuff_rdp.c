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
#include <wsutil/array.h>

enum {
	ZGFX_SEGMENTED_SINGLE = 0xe0,
	ZGFX_SEGMENTED_MULTIPART = 0xe1,

	ZGX_PACKET_COMPRESSED = 0x20,
};


typedef struct {
	tvbuff_t *input;
	unsigned offset;
	unsigned remainingBits;
	uint32_t currentValue;
	unsigned currentBits;
} bitstream_t;

static void
bitstream_init(bitstream_t *b, tvbuff_t *input, unsigned blen) {
	b->input = input;
	b->offset = 0;
	b->remainingBits = blen;
	b->currentValue = 0;
	b->currentBits = 0;
}

static uint32_t
bitstream_getbits(bitstream_t *b, uint8_t nbits, bool *ok) {
	uint32_t ret = 0;

	if (nbits > b->remainingBits) {
		*ok = false;
		return 0;
	}

	while (b->currentBits < nbits) {
		if (!tvb_reported_length_remaining(b->input, b->offset)) {
			*ok = false;
			return 0;
		}

		b->currentValue <<= 8;
		b->currentValue += tvb_get_guint8(b->input, b->offset++);

		b->currentBits += 8;
	}

	*ok = true;
	ret = b->currentValue >> (b->currentBits-nbits);
	b->currentBits -= nbits;
	b->remainingBits -= nbits;
	b->currentValue &= (1 << b->currentBits) - 1;

	return ret;
}

static bool
bitstream_copyraw(bitstream_t *b, uint8_t *dest, int nbytes)
{
	if (tvb_captured_length_remaining(b->input, b->offset) < nbytes)
		return false;

	tvb_memcpy(b->input, dest, b->offset, nbytes);

	return true;
}

static bool
bitstream_copyraw_advance(bitstream_t *b, uint8_t *dest, unsigned nbytes)
{
	if (!bitstream_copyraw(b, dest, nbytes))
		return false;

	b->offset += nbytes;
	b->remainingBits -= (nbytes * 8);
	return true;
}


static void
bitstream_realign(bitstream_t *b) {
	b->remainingBits -= b->currentBits;
	b->currentBits = 0;
	b->currentValue = 0;
}

typedef struct {
	uint32_t prefixLength;
	uint32_t prefixCode;
	uint32_t valueBits;
	uint32_t valueBase;
} zgfx_token_t;

static const zgfx_token_t ZGFX_LITERAL_TABLE[] = {
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
	uint8_t historyBuffer[2500000];
	uint32_t historyIndex;
	uint32_t historyBufferSize;

	uint32_t outputCount;
	uint8_t outputSegment[65536];
};

zgfx_context_t *zgfx_context_new(wmem_allocator_t *allocator) {
	zgfx_context_t *ret = wmem_alloc0(allocator, sizeof(*ret));
	ret->historyBufferSize = sizeof(ret->historyBuffer);
	return ret;
}

static void
zgfx_write_history_literal(zgfx_context_t *zgfx, uint8_t c)
{
	zgfx->historyBuffer[zgfx->historyIndex] = c;
	zgfx->historyIndex = (zgfx->historyIndex + 1) % zgfx->historyBufferSize;
}

static void
zgfx_write_history_buffer_tvb(zgfx_context_t *zgfx, tvbuff_t *src, uint32_t count)
{
	int src_offset = 0;
	uint32_t front;

	if (count > zgfx->historyBufferSize) {
		const uint32_t residue = count - zgfx->historyBufferSize;
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
zgfx_write_history_buffer(zgfx_context_t *zgfx, const uint8_t *src, uint32_t count)
{
	uint32_t front;

	if (count > zgfx->historyBufferSize) {
		const uint32_t residue = count - zgfx->historyBufferSize;
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


static bool
zgfx_write_literal(zgfx_context_t *zgfx, uint8_t c)
{
	if (zgfx->outputCount == 65535)
		return false;

	zgfx->outputSegment[zgfx->outputCount++] = c;

	zgfx_write_history_literal(zgfx, c);
	return true;
}

static bool
zgfx_write_raw(zgfx_context_t *zgfx, bitstream_t *b, uint32_t count)
{
	uint32_t rest, tocopy;

	/* first copy in the output buffer */
	if (zgfx->outputCount > 65535 - count)
		return false;

	if (!bitstream_copyraw(b, &(zgfx->outputSegment[zgfx->outputCount]), count))
		return false;

	zgfx->outputCount += count;

	/* then update the history buffer */
	rest = (zgfx->historyBufferSize - zgfx->historyIndex);
	tocopy = count;
	if (rest < count)
		tocopy = rest;

	if (!bitstream_copyraw_advance(b, &(zgfx->historyBuffer[zgfx->historyIndex]), tocopy))
		return false;

	zgfx->historyIndex = (zgfx->historyIndex + tocopy) % zgfx->historyBufferSize;
	count -= tocopy;
	if (count) {
		if (!bitstream_copyraw_advance(b, &(zgfx->historyBuffer[zgfx->historyIndex]), tocopy))
			return false;

		zgfx->historyIndex = (zgfx->historyIndex + tocopy) % zgfx->historyBufferSize;
	}

	return true;
}

static bool
zgfx_write_from_history(zgfx_context_t *zgfx, uint32_t distance, uint32_t count)
{
	unsigned idx;
	uint32_t remainingCount, copyTemplateSize, toCopy;
	uint8_t *outputPtr;

	if (zgfx->outputCount > 65535 - count)
		return false;

	remainingCount = count;
	idx = (zgfx->historyIndex + zgfx->historyBufferSize - distance) % zgfx->historyBufferSize;
	copyTemplateSize = (distance > count) ? count : distance;

	/* first do copy a single copy in output */
	outputPtr = &(zgfx->outputSegment[zgfx->outputCount]);
	toCopy = copyTemplateSize;
	if (idx + toCopy < zgfx->historyBufferSize) {
		memcpy(outputPtr, &(zgfx->historyBuffer[idx]), toCopy);
	} else {
		uint32_t partial = zgfx->historyBufferSize - idx;
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
	return true;
}


static bool
rdp8_decompress_segment(zgfx_context_t *zgfx, tvbuff_t *tvb)
{
	bitstream_t bitstream;
	int offset = 0;
	int len = tvb_reported_length(tvb);
	uint8_t flags = tvb_get_guint8(tvb, offset);
	uint8_t v;
	offset++;
	len--;

	if (!(flags & ZGX_PACKET_COMPRESSED)) {
		tvbuff_t *raw = tvb_new_subset_remaining(tvb, 1);
		zgfx_write_history_buffer_tvb(zgfx, raw, len);

		tvb_memcpy(tvb, zgfx->outputSegment, 1, len);
		zgfx->outputCount += len;
		return true;
	}

	v = tvb_get_guint8(tvb, offset + len - 1);
	if (v > 7)
		return false;
	len--;

	bitstream_init(&bitstream, tvb_new_subset_length(tvb, offset, len), (len * 8) - v);
	while (bitstream.remainingBits) {
		bool ok, ismatch, found;
		uint32_t bits_val = bitstream_getbits(&bitstream, 1, &ok);
		uint32_t inPrefix;
		const zgfx_token_t *tokens;
		int ntokens, i;
		uint32_t prefixBits;

		if (!ok)
			return false;

		// 0 - literal
		if (bits_val == 0) {

			bits_val = bitstream_getbits(&bitstream, 8, &ok);
			if (!zgfx_write_literal(zgfx, bits_val))
				return false;
			continue;
		}

		// 1x - match or literal branch
		bits_val = bitstream_getbits(&bitstream, 1, &ok);
		if (bits_val == 0) {
			// 10 - match
			ismatch = true;
			tokens = ZGFX_MATCH_TABLE;
			ntokens = array_length(ZGFX_MATCH_TABLE);
			inPrefix = 2;
		} else {
			// 11 - literal
			ismatch = false;
			tokens = ZGFX_LITERAL_TABLE;
			ntokens = array_length(ZGFX_LITERAL_TABLE);
			inPrefix = 3;
		}

		prefixBits = 2;
		found = false;
		for (i = 0; i < ntokens; i++) {
			if (prefixBits != tokens[i].prefixLength) {
				uint32_t missingBits = (tokens[i].prefixLength - prefixBits);
				inPrefix <<= missingBits;
				inPrefix |= bitstream_getbits(&bitstream, missingBits, &ok);
				if (!ok)
					return false;
				prefixBits = tokens[i].prefixLength;
			}

			if (inPrefix == tokens[i].prefixCode) {
				found = true;
				break;
			}
		}

		if (!found) // TODO: is it an error ?
			continue;

		if (ismatch) {
			/* It's a match */
			uint32_t count, distance, extra = 0;

			distance = tokens[i].valueBase + bitstream_getbits(&bitstream, tokens[i].valueBits, &ok);
			if (!ok)
				return false;

			if (distance != 0) {
				bits_val = bitstream_getbits(&bitstream, 1, &ok);
				if (!ok)
					return false;

				if (bits_val == 0) {
					count = 3;
				} else {
					count = 4;
					extra = 2;

					bits_val = bitstream_getbits(&bitstream, 1, &ok);
					if (!ok)
						return false;

					while (bits_val == 1) {
						count *= 2;
						extra ++;
						bits_val = bitstream_getbits(&bitstream, 1, &ok);
						if (!ok)
							return false;
					}

					count += bitstream_getbits(&bitstream, extra, &ok);
					if (!ok)
						return false;
				}

				if (count > sizeof(zgfx->outputSegment) - zgfx->outputCount)
					return false;

				if (!zgfx_write_from_history(zgfx, distance, count))
					return false;
			} else {
				/* Unencoded */
				count = bitstream_getbits(&bitstream, 15, &ok);
				if (!ok)
					return false;

				bitstream_realign(&bitstream);
				if (!zgfx_write_raw(zgfx, &bitstream, count))
					return false;
			}
		} else {
			/* literal */
			bits_val = tokens[i].valueBase;
			if (!zgfx_write_literal(zgfx, bits_val))
				return false;
		}
	}

	return true;
}



tvbuff_t *
rdp8_decompress(zgfx_context_t *zgfx, wmem_allocator_t *allocator, tvbuff_t *tvb, unsigned offset)
{
	void *output;
	uint8_t descriptor;

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
		uint16_t segment_count, i;
		uint32_t output_consumed, uncompressed_size;
		uint8_t *output_ptr;

		segment_count = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
		offset += 2;
		uncompressed_size = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
		offset += 4;

		output = output_ptr = wmem_alloc(allocator, uncompressed_size);
		output_consumed = 0;
		for (i = 0; i < segment_count; i++) {
			uint32_t segment_size = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
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
