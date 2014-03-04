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

enum ws80211_channel_type {
	WS80211_CHAN_NO_HT,
	WS80211_CHAN_HT20,
	WS80211_CHAN_HT40MINUS,
	WS80211_CHAN_HT40PLUS
};

#define CHAN_NO_HT	"NOHT"
#define CHAN_HT20	"HT20"
#define CHAN_HT40MINUS	"HT40-"
#define CHAN_HT40PLUS	"HT40+"

struct ws80211_interface
{
	char *ifname;
	gboolean can_set_freq;
	GArray *frequencies;
	int channel_types; /* Union for all bands */
};

struct ws80211_iface_info {
	int current_freq;
	enum ws80211_channel_type current_chan_type;
};


int ws80211_init(void);
GArray* ws80211_find_interfaces(void);
int ws80211_get_iface_info(const char *name, struct ws80211_iface_info *iface_info);
void ws80211_free_interfaces(GArray *interfaces);
int ws80211_frequency_to_channel(int freq);
int ws80211_set_freq(const char *name, int freq, int chan_type);
int ws80211_str_to_chan_type(const gchar *s);
const gchar *ws80211_chan_type_to_str(int type);

#endif /* __WS80211_UTILS_H__ */
