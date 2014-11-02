/*
 * Copyright (C) Matthieu Suiche 2008
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "lzxpress.h"

#define __BUF_POS_CONST(buf,ofs)(((const guint8 *)buf)+(ofs))
#define __PULL_BYTE(buf,ofs) \
	((guint8)((*__BUF_POS_CONST(buf,ofs)) & 0xFF))

#ifndef PULL_LE_UINT16
#define PULL_LE_UINT16(buf,ofs) ((guint16)( \
	((guint16)(((guint16)(__PULL_BYTE(buf,(ofs)+0))) << 0)) | \
	((guint16)(((guint16)(__PULL_BYTE(buf,(ofs)+1))) << 8)) \
))
#endif

#ifndef PULL_LE_UINT32
#define PULL_LE_UINT32(buf,ofs) ((guint32)( \
	((guint32)(((guint32)(__PULL_BYTE(buf,(ofs)+0))) <<  0)) | \
	((guint32)(((guint32)(__PULL_BYTE(buf,(ofs)+1))) <<  8)) | \
	((guint32)(((guint32)(__PULL_BYTE(buf,(ofs)+2))) << 16)) | \
	((guint32)(((guint32)(__PULL_BYTE(buf,(ofs)+3))) << 24)) \
))
#endif

gssize lzxpress_decompress(const guint8 *input,
			    guint32 input_size,
			    guint8 *output,
			    guint32 max_output_size)
{
	guint32 output_index, input_index;
	guint32 indicator, indicator_bit;
	guint32 length;
	guint32 offset;
	guint32 nibble_index;

	output_index = 0;
	input_index = 0;
	indicator = 0;
	indicator_bit = 0;
	nibble_index = 0;

	do {
		if (indicator_bit == 0) {
			indicator = PULL_LE_UINT32(input, input_index);
			input_index += (guint32)sizeof(guint32);
			indicator_bit = 32;
		}
		indicator_bit--;

		/*
		 * check whether the bit specified by indicator_bit is set or not
		 * set in indicator. For example, if indicator_bit has value 4
		 * check whether the 4th bit of the value in indicator is set
		 */
		if (((indicator >> indicator_bit) & 1) == 0) {
			output[output_index] = input[input_index];
			input_index += (guint32)sizeof(guint8);
			output_index += (guint32)sizeof(guint8);
		} else {
			length = PULL_LE_UINT16(input, input_index);
			input_index += (guint32)sizeof(guint16);
			offset = length / 8;
			length = length % 8;

			if (length == 7) {
				if (nibble_index == 0) {
					nibble_index = input_index;
					length = input[input_index] % 16;
					input_index += (guint32)sizeof(guint8);
				} else {
					length = input[nibble_index] / 16;
					nibble_index = 0;
				}

				if (length == 15) {
					length = input[input_index];
					input_index += (guint32)sizeof(guint8);
					if (length == 255) {
						length = PULL_LE_UINT16(input, input_index);
						input_index += (guint32)sizeof(guint16);
						length -= (15 + 7);
					}
					length += 15;
				}
				length += 7;
			}

			length += 3;

			do {
				if ((output_index >= max_output_size) || ((offset + 1) > output_index)) break;

				output[output_index] = output[output_index - offset - 1];

				output_index += (guint32)sizeof(guint8);
				length -= (guint32)sizeof(guint8);
			} while (length != 0);
		}
	} while ((output_index < max_output_size) && (input_index < (input_size)));

	return output_index;
}
