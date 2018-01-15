/* expansion.h
  * header field declarations, value_string def and true_false_string
  * definitions for basic manager messages
  * Copyright 2007 Don Newton <dnewton@cypresscom.net>
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
#ifndef UNISTIM_EXPANSION_H
#define UNISTIM_EXPANSION_H

static int hf_expansion_softlabel_number=-1;

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
