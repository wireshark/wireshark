/* uftp.h
  * header field declarations, value_string def and true_false_string
  * definitions for uftp commands and messages
  * Copyright 2007 Chad Singer <csinger@cypresscom.net>
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

#ifndef UNISTIM_UFTP_H
#define UNISTIM_UFTP_H

static int hf_uftp_datablock_size=-1;
static int hf_uftp_datablock_limit=-1;
static int hf_uftp_filename=-1;
static int hf_uftp_datablock=-1;
static int hf_uftp_command=-1;

static const value_string uftp_commands[]={
	{0x00,"Connection Granted"},
	{0x01,"Connection Denied"},
	{0x02,"File Data Block"},
	{0x80,"Connection Request"},
	{0x81,"Connection Details"},
	{0x82,"Flow Control Off"},
        {0,NULL}
};

#endif


