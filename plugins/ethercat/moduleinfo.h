/* Copyright (c) 2007 by Beckhoff Automation GmbH
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
/* Included *after* config.h, in order to re-define these macros */

#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "EtherCAT"

#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
/*#define VERSION "0.0.6"  /* firstversion   */
/*#define VERSION "0.0.7"  /* new dissector for mailbox inserted*/
/*#define VERSION "0.0.9"  /* nv-protocol inserted*/
/*#define VERSION "0.0.10"
/*#define VERSION "0.0.11" /* support of AoE protocol */
/*#define VERSION "0.0.12" /* port to Wireshark */
#define VERSION "0.1.0"    /* First version integrated into the Wireshark sources*/
/* Included *after* config.h, in order to re-define these macros */

#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "mikey"


#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
#define VERSION "0.0.1"


