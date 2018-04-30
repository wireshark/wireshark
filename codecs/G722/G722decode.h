/* G722decode.h
 * Definitions for G.722 codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CODECS_G722DECODE_H__
#define __CODECS_G722DECODE_H__

void *codec_g722_init(void);
void  codec_g722_release(void *ctx);
unsigned codec_g722_get_channels(void *ctx);
unsigned codec_g722_get_frequency(void *ctx);
size_t codec_g722_decode(void *ctx, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes);

#endif /* G722decode.h */

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
