/* 802_11-utils.c
 * 802.11 utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "802_11-utils.h"
#include <wsutil/array.h>

typedef struct freq_cvt_s {
    unsigned fmin;         /* Minimum frequency in MHz */
    unsigned fmax;         /* Maximum frequency in MHz */
    int cmin;          /* Minimum/base channel */
    bool is_bg;     /* B/G channel? */
} freq_cvt_t;

#define FREQ_STEP 5     /* MHz. This seems to be consistent, thankfully */

/*
 * XXX - Japanese channels 182 through 196 actually have center
 * frequencies that are off by 2.5 MHz from these values, according
 * to the IEEE standard, although the table in ARIB STD T-71 version 5.2:
 *
 *     http://www.arib.or.jp/english/html/overview/doc/1-STD-T71v5_2.pdf
 *
 * section 5.3.8.3.3 doesn't show that.
 *
 * XXX - what about the U.S. public safety 4.9 GHz band?
 *
 * XXX - what about 802.11ad?
 */
static freq_cvt_t freq_cvt[] = {
    { 2412, 2472,   1, true },  /* IEEE Std 802.11-2020: Section 15.4.4.3 and Annex E */
    { 2484, 2484,  14, true },  /* IEEE Std 802.11-2020: Section 15.4.4.3 and Annex E */
    { 5000, 5925,   0, false }, /* IEEE Std 802.11-2020: Annex E */
    { 5950, 7125,   0, false }, /* IEEE Std 802.11ax-2021: Annex E */
    { 4910, 4980, 182, false },
};

#define NUM_FREQ_CVT array_length(freq_cvt)
#define MAX_CHANNEL(fc) ( (int) ((fc.fmax - fc.fmin) / FREQ_STEP) + fc.cmin )

/*
 * Get channel number given a Frequency
 */
int
ieee80211_mhz_to_chan(unsigned freq) {
    unsigned i;

    for (i = 0; i < NUM_FREQ_CVT; i++) {
        if (freq >= freq_cvt[i].fmin && freq <= freq_cvt[i].fmax) {
            return ((freq - freq_cvt[i].fmin) / FREQ_STEP) + freq_cvt[i].cmin;
        }
    }
    return -1;
}

/*
 * Get Frequency given a Channel number
 *
 * XXX - Because channel numbering schemes for 2.4 and 5 overlap with 6 GHz,
 * this function may not return the correct channel. For example, the frequency
 * for channel 1 in 2.4 GHz band is 2412 MHz, while the frequency for channel 1
 * in the 6 GHz band is 5955 MHz. To resolve this problem, this function needs
 * to take a starting frequency to convert channel to frequencies correctly.
 * Unfortunately, this is not possible in some cases, so for now, the order on
 * which frequency ranges are defined will favor 2.4 and 5 GHz over 6 GHz.
 */
unsigned
ieee80211_chan_to_mhz(int chan, bool is_bg) {
    unsigned i;

    for (i = 0; i < NUM_FREQ_CVT; i++) {
        if (is_bg == freq_cvt[i].is_bg &&
                chan >= freq_cvt[i].cmin && chan <= MAX_CHANNEL(freq_cvt[i])) {
            return ((chan - freq_cvt[i].cmin) * FREQ_STEP) + freq_cvt[i].fmin;
        }
    }
    return 0;
}

/*
 * Get Frequency given a Channel number and band.
 */
unsigned
ieee80211_chan_band_to_mhz(int chan, bool is_bg, bool is_6ghz) {
    unsigned i;

    int start_idx = 0;
    if (is_6ghz) {
        start_idx = 3;
    }
    for (i = start_idx; i < NUM_FREQ_CVT; i++) {
        if (is_bg == freq_cvt[i].is_bg &&
                chan >= freq_cvt[i].cmin && chan <= MAX_CHANNEL(freq_cvt[i])) {
            return ((chan - freq_cvt[i].cmin) * FREQ_STEP) + freq_cvt[i].fmin;
        }
    }
    return 0;
}

/*
 * Get channel representation string given a Frequency
 */
char*
ieee80211_mhz_to_str(unsigned freq){
    int chan = ieee80211_mhz_to_chan(freq);
    const char* band;
    if (FREQ_IS_BG(freq)) {
        band = "2.4 GHz";
    } else if (FREQ_IS_6G(freq)) {
        band = "6 GHz";
    } else {
        band = "5 GHz";
    }

    if (chan < 0) {
        return ws_strdup_printf("%u", freq);
    } else {
        return ws_strdup_printf("%u [%s %u]", freq, band,
            chan);
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
