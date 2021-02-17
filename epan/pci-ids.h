/* pci-ids.h
 *
 * By Caleb Chiu <caleb.chiu@macnica.com>
 * Copyright 2019
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h> //For g* types

extern const char *pci_id_str(guint16 vid, guint16 did, guint16 svid, guint16 ssid);
