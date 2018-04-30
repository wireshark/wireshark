/* sbc.h
 * Definitions for Bluetooth SBC codec
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CODECS_SBC_H__
#define __CODECS_SBC_H__

void *codec_sbc_init(void);
void  codec_sbc_release(void *ctx);
unsigned codec_sbc_get_channels(void *ctx);
unsigned codec_sbc_get_frequency(void *ctx);
size_t codec_sbc_decode(void *ctx, const void *input, size_t inputSizeBytes, void *output,
        size_t *outputSizeBytes);

#endif /* sbc.h */

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
