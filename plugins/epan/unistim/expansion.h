/* expansion.h
 * header field declarations, value_string def and true_false_string
 * definitions for basic manager messages
 * Copyright 2007 Don Newton <dnewton@cypresscom.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef UNISTIM_EXPANSION_H
#define UNISTIM_EXPANSION_H

static int hf_expansion_softlabel_number;

static const value_string expansion_switch_msgs[]={
  {0x17,"Next Display/Write command regards expansion module"},
  {0x57,"Display Data Write"},
  {0x59,"Icon Update"},
  {0,NULL}
};
static const value_string expansion_phone_msgs[]={
  {0x59,"Expansion Key Pressed"},
  {0,NULL}
};
#endif
