/* uftp.h
 * header field declarations, value_string def and true_false_string
 * definitions for uftp commands and messages
 * Copyright 2007 Chad Singer <csinger@cypresscom.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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


