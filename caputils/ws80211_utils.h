/*
 * Copyright 2012, Pontus Fuchs <pontus.fuchs@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __WS80211_UTILS_H__
#define __WS80211_UTILS_H__

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
	WS80211_CHAN_VHT160
};

#define CHAN_NO_HT	"NOHT"
#define CHAN_HT20	"HT20"
#define CHAN_HT40MINUS	"HT40-"
#define CHAN_HT40PLUS	"HT40+"
#define CHAN_VHT80	"VHT80"
#define CHAN_VHT80P80	"VHT80+80"
#define CHAN_VHT160	"VHT160"

/* XXX This doesn't match AirpcapValidationType. Should it? */
enum ws80211_fcs_validation {
	WS80211_FCS_ALL,
	WS80211_FCS_VALID,
	WS80211_FCS_INVALID
};

struct ws80211_interface
{
	char *ifname;
	gboolean can_set_freq;
	gboolean can_check_fcs;
	GArray *frequencies; /* Array of guint32? */
	int channel_types; /* Union for all bands */
	int cap_monitor;
};

struct ws80211_iface_info {
	int current_freq;
	enum ws80211_channel_type current_chan_type;
	int current_center_freq1;
	int current_center_freq2;
	enum ws80211_fcs_validation current_fcs_validation;
};

/** Initialize the 802.11 environment.
 * On Linux this initializes an nl80211_state struct.
 * On Windows this checks the AirPcap status. It does *not* load the
 * AirPcap DLL. That happens when the program starts.
 *
 * @return 0 on success, an error value on failure.
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

/** Set the frequency and channel width for an interface.
 *
 * @param name The interface name.
 * @param freq The frequency in MHz.
 * @param chan_type The HT channel type (no, 20Mhz, 40Mhz...).
 * @param center_freq The center frequency in MHz (if 80MHz, 80+80MHz or 160MHz).
 * @param center_freq2 The 2nd center frequency in MHz (if 80+80MHz).
 * @return Zero on success, nonzero on failure.
 */
int ws80211_set_freq(const char *name, int freq, int chan_type, int _U_ center_freq, int _U_ center_freq2);

int ws80211_str_to_chan_type(const gchar *s); /* GTK+ only? */
const gchar *ws80211_chan_type_to_str(int type); /* GTK+ only? */

/** Check to see if we have FCS filtering.
 *
 * @return TRUE if FCS filtering is supported on this platform.
 */
gboolean ws80211_has_fcs_filter(void);

/** Set the FCS validation behavior for an interface.
 *
 * @param name The interface name.
 * @param fcs_validation The desired validation behavior.
 * @return Zero on success, nonzero on failure.
 */
int ws80211_set_fcs_validation(const char *name, enum ws80211_fcs_validation fcs_validation);


/** Get the path to a helper application.
 * Return the path to a separate 802.11 helper application, e.g.
 * the AirPcap control panel or the GNOME Network Manager.
 *
 * @return The path to the helper on success, NULL on failure.
 */
const char *ws80211_get_helper_path(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS80211_UTILS_H__ */
