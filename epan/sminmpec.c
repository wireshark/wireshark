/* sminmpec.h
 * SMI Network Management Private Enterprise Codes for organizations
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2004 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/value_string.h>
#include <epan/sminmpec.h>

/*
 * SMI Network Management Private Enterprise Codes for organizations.
 *
 * XXX - these also appear in FreeRadius dictionary files, with items such
 * as
 *
 *	VENDOR          Cisco           9
 */
const value_string sminmpec_values[] = {
  {0,				"None"},
  {VENDOR_ACC,			"ACC"},
  {VENDOR_CISCO,		"Cisco"},
  {VENDOR_HEWLETT_PACKARD,	"Hewlett Packard"},
  {VENDOR_SUN_MICROSYSTEMS,	"Sun Microsystems"},
  {VENDOR_MERIT,		"Merit"},
  {VENDOR_SHIVA,		"Shiva"},
  {VENDOR_ERICSSON_BUSINESS_COMUNICATIONS,	"Ericsson Business Communications"},
  {VENDOR_CISCO_VPN5000,	"Cisco VPN 5000"},
  {VENDOR_LIVINGSTON,		"Livingston"},
  {VENDOR_MICROSOFT,		"Microsoft"},
  {VENDOR_3COM,			"3Com"},
  {VENDOR_ASCEND,		"Ascend"},
  {VENDOR_BAY,			"Bay Networks"},
  {VENDOR_FOUNDRY,		"Foundry"},
  {VENDOR_VERSANET,		"Versanet"},
  {VENDOR_REDBACK,		"Redback"},
  {VENDOR_JUNIPER,		"Juniper Networks"},
  {VENDOR_APTIS,		"Aptis"},
  {VENDOR_CISCO_VPN3000,	"Cisco VPN 3000"},
  {VENDOR_COSINE,		"CoSine Communications"},
  {VENDOR_SHASTA,		"Shasta"},
  {VENDOR_NOMADIX,		"Nomadix"},
  {VENDOR_SIEMENS,		"SIEMENS"},
  {VENDOR_CABLELABS,		"CableLabs"},
  {VENDOR_UNISPHERE,		"Unisphere Networks"},
  {VENDOR_CISCO_BBSM,		"Cisco BBSM"},
  {VENDOR_THE3GPP2,		"3rd Generation Partnership Project 2 (3GPP2)"},
  {VENDOR_IP_UNPLUGGED,		"ipUnplugged"},
  {VENDOR_ISSANNI,		"Issanni Communications"},
  {VENDOR_QUINTUM,		"Quintum"},
  {VENDOR_INTERLINK,		"Interlink"},
  {VENDOR_COLUBRIS,		"Colubris"},
  {VENDOR_COLUMBIA_UNIVERSITY,	"Columbia University"},
  {VENDOR_THE3GPP,		"3GPP"},
  {VENDOR_GEMTEK_SYSTEMS,	"Gemtek-Systems"},
  {VENDOR_WIFI_ALLIANCE,	"Wi-Fi Alliance"},
  {0, NULL}
};
