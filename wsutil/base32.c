/* base32.c
 * Stub for removed base-32 conversion
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

int ws_base32_decode(uint8_t* output, const uint32_t outputLength,
						const uint8_t* in, const uint32_t inputLength)
{
	(void)output;
	(void)outputLength;
	(void)in;
	(void)inputLength;
	return -1;
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
