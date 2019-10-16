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

#include <glib.h>

#include <string.h>
#include "base32.h"

/*
 * Cjdns style base32 encoding
 */

/** Returned by ws_base32_encode() if the input is not valid base32. */
#define Base32_BAD_INPUT -1
/** Returned by ws_base32_encode() if the output buffer is too small. */
#define Base32_TOO_BIG -2

int ws_base32_decode(guint8* output, const guint32 outputLength,
						const guint8* in, const guint32 inputLength)
{
	guint32 outIndex = 0;
	guint32 inIndex = 0;
	guint32 work = 0;
	guint32 bits = 0;
	static const guint8* kChars = (guint8*) "0123456789bcdfghjklmnpqrstuvwxyz";
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
