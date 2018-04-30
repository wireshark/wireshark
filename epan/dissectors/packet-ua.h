/* packet-ua.h
 * Routines for UA (Universal Alcatel) packet dissection.
 * Copyright 2011, Marek Tews <marek@trx.com.pl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

extern gboolean is_ua(tvbuff_t *tvb);
