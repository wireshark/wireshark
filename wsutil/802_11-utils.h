/* 802_11-utils.h
 * 802.11 utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __802_11_UTILS_H__
#define __802_11_UTILS_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * 802.11 utilities.
 */

/**
 * Given a center frequency in MHz, return a channel number.
 * @param freq Frequency in MHz.
 * @return The equivalent channel or -1 if no match is found.
 */
WS_DLL_PUBLIC
int
ieee80211_mhz_to_chan(unsigned freq);

/**
 * Given an 802.11 channel number and a band type, return a center frequency.
 * @param chan Channel number
 * @param is_bg true if the channel is a b/g channel, false otherwise.
 * @return The equivalent frequency or 0 if no match is found.
 */
WS_DLL_PUBLIC
unsigned
ieee80211_chan_to_mhz(int chan, bool is_bg);

/**
 * Given an 802.11 channel center frequency in MHz, return a string
 * representation.
 * @param freq Frequench in MHz.
 * @return A string showing the frequency, channel number, and type.
 * The string must be freed with g_free() after use.
 */
WS_DLL_PUBLIC
char*
ieee80211_mhz_to_str(unsigned freq);

/*
 * Get Frequency given a Channel number and band.
 */
WS_DLL_PUBLIC
unsigned
ieee80211_chan_band_to_mhz(int chan, bool is_bg, bool is_6ghz);

/* Should this be "(freq < 4920)", or something else? */
#define FREQ_IS_BG(freq) ((freq) <= 2484)
#define CHAN_IS_BG(chan) ((chan) <= 14)

#define FREQ_IS_6G(freq) (5950 <= (freq) && (freq) <= 7125)

/*
 * Test whether a data rate is an {HR}/DSSS (legacy DSSS/11b) data rate
 * and whether it's an OFDM (11a/11g OFDM mode) data rate.
 *
 * rate is in units of 500 Kb/s.
 *
 * The 22 and 33 Mb/s rates for DSSS use Packet Binary Convolutional
 * Coding (PBCC).  That was provided by Texas Instruments as 11b+,
 * and was in section 19.6 "ERP-PBCC operation specifications" of
 * IEEE Std 802.11g-2003, and sections 18.4.6.6 "DSSS/PBCC data modulation
 * and modulation rate (optional)" and 19.6 "ERP-PBCC operation
 * specifications" of IEEE Std 802.11-2007, and sections 17.4.6.7 "DSSS/PBCC
 * data modulation and modulation rate (optional)" and 19.6 "ERP-PBCC
 * operation specifications" of IEEE Std 802.11-2012, marked as optional
 * in both cases, but is not present in IEEE Std 802.11-2016.
 *
 * (Note: not to be confused with "peanut butter and chocolate chips":
 *
 *    https://www.bigoven.com/recipe/peanut-butter-chocolate-chip-cookies-pbcc-cookies/186266
 *
 * :-))
 */
#define RATE_IS_DSSS(rate) \
    ((rate) == 2 /* 1 Mb/s */ || \
     (rate) == 4 /* 2 Mb/s */ || \
     (rate) == 11 /* 5.5 Mb/s */ || \
     (rate) == 22 /* 11 Mb/s */ || \
     (rate) == 44 /* 22 Mb/s */ || \
     (rate) == 66 /* 33 Mb/s */)

#define RATE_IS_OFDM(rate) \
    ((rate) == 12 /* 6 Mb/s */ || \
     (rate) == 18 /* 9 Mb/s */ || \
     (rate) == 24 /* 12 Mb/s */ || \
     (rate) == 36 /* 18 Mb/s */ || \
     (rate) == 48 /* 24 Mb/s */ || \
     (rate) == 72 /* 36 Mb/s */ || \
     (rate) == 96 /* 48 Mb/s */ || \
     (rate) == 108 /* 54 Mb/s */)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __802_11_UTILS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
