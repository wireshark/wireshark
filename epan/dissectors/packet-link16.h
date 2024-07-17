/* packet-link16.h
 * Routines for Link 16 message dissection (MIL-STD-6016)
 * William Robertson <aliask@gmail.com>
 * Peter Ross <peter.ross@dsto.defence.gov.au>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_LINK16_H__
#define __PACKET_LINK16_H__

extern const value_string Link16_NPG_Strings[];

typedef struct {
    int label;
    int sublabel;
    int extension;
} Link16State;

#endif /* __PACKET_LINK16_H__ */
