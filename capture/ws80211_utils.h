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

/* For our (monitor mode tuning) purposes we shouldn't care about 20 MHz
 * non HT vs 20 MHz HT. We do care about HT40- vs HT40+ vs HE40 (whether
 * the center freq must be provided, */

/**
 * @brief IEEE 802.11 channel width/type for monitor mode configuration.
 */
enum ws80211_channel_type {
    WS80211_CHAN_NO_HT,     /**< Legacy 20 MHz, no High Throughput (non-HT) */
    WS80211_CHAN_HT20,      /**< 20 MHz High Throughput (HT20) */
    WS80211_CHAN_HT40MINUS, /**< 40 MHz HT, secondary channel below primary (HT40-) */
    WS80211_CHAN_HT40PLUS,  /**< 40 MHz HT, secondary channel above primary (HT40+) */
    WS80211_CHAN_HE40,      /**< 40 MHz High Efficiency (HE/Wi-Fi 6) with explicit center frequency */
    WS80211_CHAN_VHT80,     /**< 80 MHz Very High Throughput (VHT/Wi-Fi 5) */
    WS80211_CHAN_VHT80P80,  /**< 80+80 MHz VHT with two non-contiguous 80 MHz segments */
    WS80211_CHAN_VHT160,    /**< 160 MHz VHT contiguous channel */
    WS80211_CHAN_EHT320     /**< 320 MHz Extremely High Throughput (EHT/Wi-Fi 7) */
};

/** @brief String token for WS80211_CHAN_NO_HT; used in channel type serialization. */
#define CHAN_NO_HT    "NOHT"
/** @brief String token for WS80211_CHAN_HT20. */
#define CHAN_HT20     "HT20"
/** @brief String token for WS80211_CHAN_HT40MINUS. */
#define CHAN_HT40MINUS "HT40-"
/** @brief String token for WS80211_CHAN_HT40PLUS. */
#define CHAN_HT40PLUS  "HT40+"
/** @brief String token for WS80211_CHAN_HE40. */
#define CHAN_HE40     "HE40"
/** @brief String token for WS80211_CHAN_VHT80. */
#define CHAN_VHT80    "VHT80"
/** @brief String token for WS80211_CHAN_VHT80P80. */
#define CHAN_VHT80P80  "VHT80+80"
/** @brief String token for WS80211_CHAN_VHT160. */
#define CHAN_VHT160   "VHT160"
/** @brief String token for WS80211_CHAN_EHT320. */
#define CHAN_EHT320   "EHT320"

/* These are *not* the same values as the Linux NL80211_BAND_* enum,
 * because we don't support the 60 GHz or 900 MHz (S1G, HaLow) bands,
 * which have different channel widths. */

/**
 * @brief Supported RF band identifiers (not equivalent to Linux NL80211_BAND_*).
 */
enum ws80211_band_type {
    WS80211_BAND_2GHZ, /**< 2.4 GHz band */
    WS80211_BAND_5GHZ, /**< 5 GHz band */
    WS80211_BAND_6GHZ  /**< 6 GHz band (Wi-Fi 6E/7) */
};

/**
 * @brief FCS (Frame Check Sequence) capture filter policy.
 */
enum ws80211_fcs_validation {
    WS80211_FCS_ALL,     /**< Capture all frames regardless of FCS validity */
    WS80211_FCS_VALID,   /**< Capture only frames with a valid FCS */
    WS80211_FCS_INVALID  /**< Capture only frames with an invalid FCS */
};

/**
 * @brief Describes a single frequency and its channel-type constraints.
 */
struct ws80211_frequency
{
    uint32_t freq;   /**< Center frequency in MHz */
    int channel_mask; /**< Bitmask of ws80211_channel_type values *not* supported
                       *   for this frequency (e.g., due to regulatory restrictions),
                       *   even if the PHY supports them for the band */
};

/**
 * @brief Describes the channel capabilities of a single RF band on a PHY.
 */
struct ws80211_band
{
    GArray *frequencies;  /**< Lazily-created array of ws80211_frequency entries
                           *   for this band; may be NULL if not yet populated */
    int channel_types;    /**< Bitmask of ws80211_channel_type values supported
                           *   by the PHY on this band */
};

/**
 * @brief Represents a wireless network interface and its capture capabilities.
 */
struct ws80211_interface
{
    char *ifname;        /**< Interface name (e.g., "wlan0") */
    bool can_set_freq;   /**< True if the interface supports setting the operating frequency */
    bool can_check_fcs;  /**< True if the interface supports FCS validation filtering */
    GArray *bands;       /**< Array of ws80211_band structs indexed by ws80211_band_type;
                          *   always non-NULL but may contain fewer entries than the total
                          *   number of defined band types */
    int cap_monitor;     /**< Non-zero if the interface supports monitor mode capture */
};

/**
 * @brief Snapshot of the current configuration of a wireless interface.
 */
struct ws80211_iface_info {
    int current_freq;                            /**< Current operating frequency in MHz */
    enum ws80211_channel_type current_chan_type; /**< Current channel width/type */
    int current_center_freq1;                    /**< Primary center frequency in MHz (used for VHT/HE/EHT) */
    int current_center_freq2;                    /**< Secondary center frequency in MHz (used for VHT 80+80) */
    enum ws80211_fcs_validation current_fcs_validation; /**< Current FCS capture filter policy */
};

/*
 * List of error types.
 * WS80211_ERROR is a generic error that might have a platform-specific
 * error message that depends on the last failed operation.
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

/**
 * @brief Finds and returns a list of wireless network interfaces.
 *
 * @return A GArray containing pointers to struct ws80211_interface, each representing a wireless interface. The caller is responsible for freeing the returned array and its contents.
 */
GArray* ws80211_find_interfaces(void);

/**
 * @brief Get information about a wireless interface.
 *
 * @param name The name of the interface to query.
 * @param iface_info A pointer to a structure where the interface information will be stored.
 * @return 0 on success, non-zero on failure.
 */
int ws80211_get_iface_info(const char *name, struct ws80211_iface_info *iface_info);

/**
 * @brief Free an interface list.
 *
 * @param interfaces A list of interfaces created with ws80211_find_interfaces().
 */
void ws80211_free_interfaces(GArray *interfaces);

/**
 * @brief Clear the frequencies array in a ws80211_band structure.
 *
 * @param band The pointer to the ws80211_band structure whose frequencies array is to be cleared.
 */
void ws80211_clear_band(struct ws80211_band *band);

/**
 * @brief Set the frequency and channel width for an interface.
 *
 * @param name The interface name.
 * @param freq The frequency in MHz.
 * @param chan_type The HT channel type (no, 20Mhz, 40Mhz...).
 * @param center_freq The center frequency in MHz (if 80MHz, 80+80MHz or 160MHz).
 * @param center_freq2 The 2nd center frequency in MHz (if 80+80MHz).
 * @return WS80211_OK on success, other values on failure.
 */
int ws80211_set_freq(const char *name, uint32_t freq, int chan_type, uint32_t _U_ center_freq, uint32_t _U_ center_freq2);

/**
 * @brief Convert a string representation of a channel type to its corresponding enum value.
 *
 * @param s The string representation of the channel type.
 * @return int The corresponding enum value, or -1 if the string is invalid.
 */
int ws80211_str_to_chan_type(const char *s);

/**
 * @brief Convert a Wi-Fi channel type to its string representation.
 *
 * @param type The Wi-Fi channel type to convert.
 * @return const char* The string representation of the channel type, or NULL if unknown.
 */
const char *ws80211_chan_type_to_str(enum ws80211_channel_type type);

/**
 * @brief Convert a Wi-Fi band type to its string representation.
 *
 * @param type The Wi-Fi band type to convert.
 * @return String representation of the band type, or NULL if invalid.
 */
const char *ws80211_band_type_to_str(enum ws80211_band_type type);

/**
 * @brief Check to see if we have FCS filtering.
 *
 * @return true if FCS filtering is supported on this platform.
 */
bool ws80211_has_fcs_filter(void);

/**
 * @brief Set the FCS validation behavior for an interface.
 *
 * @param name The interface name.
 * @param fcs_validation The desired validation behavior.
 * @return WS80211_OK on success, other values on failure.
 */
int ws80211_set_fcs_validation(const char *name, enum ws80211_fcs_validation fcs_validation);


/**
 * @brief Get the path to a helper application.
 *
 * Return the path to a separate 802.11 helper application, e.g.
 * the GNOME Network Manager.
 *
 * @return The path to the helper on success, NULL on failure.
 */
const char *ws80211_get_helper_path(void);


/**
 * @brief Return center frequency of an 80M/160M/320M channel.
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
