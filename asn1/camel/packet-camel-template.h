/* packet-camel-template.h
 * Routines for Camel
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Copyright 2005, Olivier Jacques <olivier.jacques@hp.com>
 * Built from the gsm-map dissector Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 * References: ETSI 300 374
 */
/* 
 * Indentation logic: this file is indented with 2 spaces indentation. 
 *                    there are no tabs.
 */


#ifndef PACKET_CAMEL_H
#define PACKET_CAMEL_H

void proto_reg_handoff_camel(void);
void proto_register_camel(void);

/* Defines for the camel taps */
#define	camel_MAX_NUM_OPR_CODES	256


WS_VAR_IMPORT const value_string camel_opr_code_strings[];
/* #include "packet-camel-exp.h"*/

#endif  /* PACKET_camel_H */
