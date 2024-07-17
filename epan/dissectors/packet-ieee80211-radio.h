/* packet-ieee80211-radio.h
 * Routines for pseudo 802.11 header dissection and radio packet timing calculation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copyright 2012 Parc Inc and Samsung Electronics
 * Copyright 2015, 2016 & 2017 Cisco Inc
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WLAN_RADIO_H__
#define __WLAN_RADIO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct aggregate {
  unsigned phy;
  union ieee_802_11_phy_info phy_info;
  int8_t rssi; /* sometimes only available on the last frame */
  unsigned duration; /* total duration of data in microseconds (without preamble) */
};

struct wlan_radio {
  struct aggregate *aggregate; /* if this frame is part of an aggregate, point to it, otherwise NULL */
  unsigned prior_aggregate_data; /* length of all prior data in this aggregate
                                 used for calculating duration of this subframe */
  uint64_t start_tsf;
  uint64_t end_tsf;

  int64_t ifs; /* inter frame space in microseconds */

  uint16_t nav; /* Duration from the frame header */
  int8_t rssi;
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WLAN_RADIO_H__ */
