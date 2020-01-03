/* G711adecode.c
 * A-law G.711 codec
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "wsutil/codecs.h"
#include "ws_attributes.h"

static gint16 ulaw_exp_table[256] = {
   -32124,-31100,-30076,-29052,-28028,-27004,-25980,-24956,
   -23932,-22908,-21884,-20860,-19836,-18812,-17788,-16764,
   -15996,-15484,-14972,-14460,-13948,-13436,-12924,-12412,
   -11900,-11388,-10876,-10364, -9852, -9340, -8828, -8316,
    -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
    -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
    -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
    -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
    -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
    -1372, -1308, -1244, -1180, -1116, -1052,  -988,  -924,
     -876,  -844,  -812,  -780,  -748,  -716,  -684,  -652,
     -620,  -588,  -556,  -524,  -492,  -460,  -428,  -396,
     -372,  -356,  -340,  -324,  -308,  -292,  -276,  -260,
     -244,  -228,  -212,  -196,  -180,  -164,  -148,  -132,
     -120,  -112,  -104,   -96,   -88,   -80,   -72,   -64,
      -56,   -48,   -40,   -32,   -24,   -16,    -8,     0,
    32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
    23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
    15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
    11900, 11388, 10876, 10364,  9852,  9340,  8828,  8316,
     7932,  7676,  7420,  7164,  6908,  6652,  6396,  6140,
     5884,  5628,  5372,  5116,  4860,  4604,  4348,  4092,
     3900,  3772,  3644,  3516,  3388,  3260,  3132,  3004,
     2876,  2748,  2620,  2492,  2364,  2236,  2108,  1980,
     1884,  1820,  1756,  1692,  1628,  1564,  1500,  1436,
     1372,  1308,  1244,  1180,  1116,  1052,   988,   924,
      876,   844,   812,   780,   748,   716,   684,   652,
      620,   588,   556,   524,   492,   460,   428,   396,
      372,   356,   340,   324,   308,   292,   276,   260,
      244,   228,   212,   196,   180,   164,   148,   132,
      120,   112,   104,    96,    88,    80,    72,    64,
       56,    48,    40,    32,    24,    16,     8,     0
};

static gint16 alaw_exp_table[256] = {
      -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736,
      -7552, -7296, -8064, -7808, -6528, -6272, -7040, -6784,
      -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368,
      -3776, -3648, -4032, -3904, -3264, -3136, -3520, -3392,
     -22016,-20992,-24064,-23040,-17920,-16896,-19968,-18944,
     -30208,-29184,-32256,-31232,-26112,-25088,-28160,-27136,
     -11008,-10496,-12032,-11520, -8960, -8448, -9984, -9472,
     -15104,-14592,-16128,-15616,-13056,-12544,-14080,-13568,
       -344,  -328,  -376,  -360,  -280,  -264,  -312,  -296,
       -472,  -456,  -504,  -488,  -408,  -392,  -440,  -424,
        -88,   -72,  -120,  -104,   -24,    -8,   -56,   -40,
       -216,  -200,  -248,  -232,  -152,  -136,  -184,  -168,
      -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184,
      -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696,
       -688,  -656,  -752,  -720,  -560,  -528,  -624,  -592,
       -944,  -912, -1008,  -976,  -816,  -784,  -880,  -848,
       5504,  5248,  6016,  5760,  4480,  4224,  4992,  4736,
       7552,  7296,  8064,  7808,  6528,  6272,  7040,  6784,
       2752,  2624,  3008,  2880,  2240,  2112,  2496,  2368,
       3776,  3648,  4032,  3904,  3264,  3136,  3520,  3392,
      22016, 20992, 24064, 23040, 17920, 16896, 19968, 18944,
      30208, 29184, 32256, 31232, 26112, 25088, 28160, 27136,
      11008, 10496, 12032, 11520,  8960,  8448,  9984,  9472,
      15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568,
        344,   328,   376,   360,   280,   264,   312,   296,
        472,   456,   504,   488,   408,   392,   440,   424,
         88,    72,   120,   104,    24,     8,    56,    40,
        216,   200,   248,   232,   152,   136,   184,   168,
       1376,  1312,  1504,  1440,  1120,  1056,  1248,  1184,
       1888,  1824,  2016,  1952,  1632,  1568,  1760,  1696,
        688,   656,   752,   720,   560,   528,   624,   592,
        944,   912,  1008,   976,   816,   784,   880,   848
};

static void *
codec_g711u_init(void)
{
    return NULL;
}

static void
codec_g711u_release(void *ctx _U_)
{

}

static unsigned
codec_g711u_get_channels(void *ctx _U_)
{
    return 1;
}

static unsigned
codec_g711u_get_frequency(void *ctx _U_)
{
    return 8000;
}

static size_t
codec_g711u_decode(void *ctx _U_, const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize)
{
    const guint8 *dataIn = (const guint8 *) inputBytes;
    gint16       *dataOut = (gint16 *) outputSamples;
    size_t       i;

    if (!outputSamples || !outputSamplesSize) {
        return inputBytesSize * 2;
    }

    for (i = 0; i < inputBytesSize; i++)
    {
        dataOut[i] = ulaw_exp_table[dataIn[i]];
    }

    *outputSamplesSize = inputBytesSize * 2;
    return inputBytesSize * 2;
}

static void *
codec_g711a_init(void)
{
    return NULL;
}

static void
codec_g711a_release(void *ctx _U_)
{

}

static unsigned
codec_g711a_get_channels(void *ctx _U_)
{
    return 1;
}

static unsigned
codec_g711a_get_frequency(void *ctx _U_)
{
    return 8000;
}

static size_t
codec_g711a_decode(void *ctx _U_, const void *inputBytes, size_t inputBytesSize,
        void *outputSamples, size_t *outputSamplesSize)
{
    const guint8 *dataIn = (const guint8 *) inputBytes;
    gint16       *dataOut = (gint16 *) outputSamples;
    size_t       i;

    if (!outputSamples || !outputSamplesSize) {
        return inputBytesSize * 2;
    }

    for (i = 0; i < inputBytesSize; i++)
    {
        dataOut[i] = alaw_exp_table[dataIn[i]];
    }

    *outputSamplesSize = inputBytesSize * 2;
    return inputBytesSize * 2;
}

void
codec_register_g711(void)
{
    register_codec("g711U", codec_g711u_init, codec_g711u_release,
            codec_g711u_get_channels, codec_g711u_get_frequency, codec_g711u_decode);
    register_codec("g711A", codec_g711a_init, codec_g711a_release,
            codec_g711a_get_channels, codec_g711a_get_frequency, codec_g711a_decode);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
