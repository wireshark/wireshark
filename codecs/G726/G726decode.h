/* G726decode.h
 * Definitions for G.726 codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CODECS_G726DECODE_H__
#define __CODECS_G726DECODE_H__

void *codec_g726_16_init(void);
void *codec_g726_24_init(void);
void *codec_g726_32_init(void);
void *codec_g726_40_init(void);
void *codec_aal2_g726_16_init(void);
void *codec_aal2_g726_24_init(void);
void *codec_aal2_g726_32_init(void);
void *codec_aal2_g726_40_init(void);
void  codec_g726_release(void *ctx);
unsigned codec_g726_get_channels(void *ctx);
unsigned codec_g726_get_frequency(void *ctx);
size_t codec_g726_decode(void *ctx, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes);

#endif /* G726decode.h */

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
