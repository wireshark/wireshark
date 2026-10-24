
/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MIDI_H__
#define __PACKET_MIDI_H__

#include <wsutil/value_string.h>

extern value_string_ext midi_note_values_ext;
extern value_string_ext midi_controller_values_ext;
extern const value_string midi_channels[];

int dissect_midi1_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned int offset, uint8_t *runningstatus, bool first_command);

unsigned int
dissect_midi_ump_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, unsigned int offset, const unsigned int encoding);

#endif /* __PACKET_MIDI_H__ */
