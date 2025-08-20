/** @file
 *
 * Copyright 2012, Pontus Fuchs <pontus.fuchs@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS80211_UTILS_H__
#define __WS80211_UTILS_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum ws80211_channel_type {
	WS80211_CHAN_NO_HT,
	WS80211_CHAN_HT20,
	WS80211_CHAN_HT40MINUS,
	WS80211_CHAN_HT40PLUS,
	WS80211_CHAN_VHT80,
	WS80211_CHAN_VHT80P80,
	WS80211_CHAN_VHT160,
	WS80211_CHAN_EHT320
};

#define CHAN_NO_HT	"NOHT"
#define CHAN_HT20	"HT20"
#define CHAN_HT40MINUS	"HT40-"
#define CHAN_HT40PLUS	"HT40+"
#define CHAN_VHT80	"VHT80"
#define CHAN_VHT80P80	"VHT80+80"
#define CHAN_VHT160	"VHT160"
#define CHAN_EHT320	"EHT320"

/* These are *not* the same values as the Linux NL80211_BAND_* enum,
 * because we don't support the 60 GHz or 900 MHz (S1G, HaLow) bands,
 * which have different channel widths. */
enum ws80211_band_type {
	WS80211_BAND_2GHZ,
	WS80211_BAND_5GHZ,
	WS80211_BAND_6GHZ
};

enum ws80211_fcs_validation {
	WS80211_FCS_ALL,
	WS80211_FCS_VALID,
	WS80211_FCS_INVALID
};

struct ws80211_frequency
{
	uint32_t freq; // MHz
	int channel_mask; /* Bitmask of ws80211_channel_types *not* supported for this frequency (e.g., for regulatory reasons) even if supported by the PHY for this band */
};

struct ws80211_band
{
	GArray *frequencies; /* Array of uint32_t (MHz) (lazily created, can be NULL) */
	int channel_types; /* Bitmask of ws80211_channel_types supported by the PHY on this band */
};

struct ws80211_interface
{
	char *ifname;
	bool can_set_freq;
	bool can_check_fcs;
	GArray *bands; /* Array of struct ws80211_band, indexed by
			  ws80211_band_type. (array always exists but might
			  be shorter than the number of possible bands.) */
	int cap_monitor;
};

struct ws80211_iface_info {
	int current_freq;
	enum ws80211_channel_type current_chan_type;
	int current_center_freq1;
	int current_center_freq2;
	enum ws80211_fcs_validation current_fcs_validation;
};

/*
 * List of error types.
 * WS80211_ERROR is a generic error that might have a platform-specific
 * error mssage that depends on the last failed operation.
 */
#define WS80211_OK                  0
#define WS80211_ERROR_NOT_SUPPORTED 1
#define WS80211_ERROR               2

/** Retrieve an 802.11 error message based on the most recent returned
 * error.
 */
const char *ws80211_geterror(int error);

/** Initialize the 802.11 environment.
 * On Linux this initializes an nl80211_state struct.
 *
 * @return WS80211_OK on success, WS80211_ERROR_NOT_SUPPORTED if the
 * 802.11 environment isn't supported, or WS80211_ERROR for other errors.
 */
int ws80211_init(void);

/** Build a list of 802.11 interfaces.
 *
 * @return A GArray of pointers to struct ws80211_interface on success, NULL on failure.
 */
/* XXX Should we make this an array of structs instead of an array of struct pointers?
 * It'd save a bit of mallocing and freeing. */
GArray* ws80211_find_interfaces(void);

int ws80211_get_iface_info(const char *name, struct ws80211_iface_info *iface_info);

/** Free an interface list.
 *
 * @param interfaces A list of interfaces created with ws80211_find_interfaces().
 */
void ws80211_free_interfaces(GArray *interfaces);

void ws80211_clear_band(struct ws80211_band *band);

/** Set the frequency and channel width for an interface.
 *
 * @param name The interface name.
 * @param freq The frequency in MHz.
 * @param chan_type The HT channel type (no, 20Mhz, 40Mhz...).
 * @param center_freq The center frequency in MHz (if 80MHz, 80+80MHz or 160MHz).
 * @param center_freq2 The 2nd center frequency in MHz (if 80+80MHz).
 * @return WS80211_OK on success, other values on failure.
 */
int ws80211_set_freq(const char *name, uint32_t freq, int chan_type, uint32_t _U_ center_freq, uint32_t _U_ center_freq2);

int ws80211_str_to_chan_type(const char *s);
const char *ws80211_chan_type_to_str(enum ws80211_channel_type type);

const char *ws80211_band_type_to_str(enum ws80211_band_type type);

/** Check to see if we have FCS filtering.
 *
 * @return true if FCS filtering is supported on this platform.
 */
bool ws80211_has_fcs_filter(void);

/** Set the FCS validation behavior for an interface.
 *
 * @param name The interface name.
 * @param fcs_validation The desired validation behavior.
 * @return WS80211_OK on success, other values on failure.
 */
int ws80211_set_fcs_validation(const char *name, enum ws80211_fcs_validation fcs_validation);


/** Get the path to a helper application.
 * Return the path to a separate 802.11 helper application, e.g.
 * the GNOME Network Manager.
 *
 * @return The path to the helper on success, NULL on failure.
 */
const char *ws80211_get_helper_path(void);


/** Return center frequency of an 80M/160M/320M channel.
 *
 * @param control_frequency Control channel frequency in MHz.
 * @param channel_type The channel type.
 * @return Center frequency of the channel in MHz or -1 on failure.
 *
 * @note -1 is returned for channel types smaller than 80MHz, where
 * ws80211_set_freq does not need a center frequency.
 */
int ws80211_get_center_frequency(int control_frequency, enum ws80211_channel_type channel_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS80211_UTILS_H__ */
