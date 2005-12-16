/* log.h
 * log output definitions
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __LOG_H__
#define __LOG_H__

/* capture domain (except for capture child, see below) */
#define LOG_DOMAIN_CAPTURE          "Capture"

/* capture child domain (the capture child might also contain file domain messages!) */
#define LOG_DOMAIN_CAPTURE_CHILD 	"CaptureChild"

/* main domain */
#define LOG_DOMAIN_MAIN				"Main"

/* enable very verbose capture log debug output */
/* (might slightly degrade performance) */
/*#define LOG_CAPTURE_VERBOSE*/


#endif
