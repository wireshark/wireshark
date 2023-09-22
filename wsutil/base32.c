/* base32.c
 * Base-32 conversion
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "base32.h"

#include <string.h>

/*
 * Cjdns style base32 encoding
 */

/** Returned by ws_base32_encode() if the input is not valid base32. */
#define Base32_BAD_INPUT -1
/** Returned by ws_base32_encode() if the output buffer is too small. */
#define Base32_TOO_BIG -2

int ws_base32_decode(uint8_t* output, const uint32_t outputLength,
						const uint8_t* in, const uint32_t inputLength)
{
	uint32_t outIndex = 0;
	uint32_t inIndex = 0;
	uint32_t work = 0;
	uint32_t bits = 0;
	static const uint8_t* kChars = (uint8_t*) "0123456789bcdfghjklmnpqrstuvwxyz";
	while (inIndex < inputLength) {
		work |= ((unsigned) in[inIndex++]) << bits;
		bits += 8;
		while (bits >= 5) {
			if (outIndex >= outputLength) {
				return Base32_TOO_BIG;
			}
			output[outIndex++] = kChars[work & 31];
			bits -= 5;
			work >>= 5;
		}
	}
	if (bits) {
		if (outIndex >= outputLength) {
			return Base32_TOO_BIG;
		}
		output[outIndex++] = kChars[work & 31];
	}
	if (outIndex < outputLength) {
		output[outIndex] = '\0';
	}
	return outIndex;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
