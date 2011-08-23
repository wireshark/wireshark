/* stat_cmd_args.h
 * Declarations of routines to register "-z" command-line argument handlers
 * for stats
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __STAT_CMD_ARGS_H__
#define __STAT_CMD_ARGS_H__

extern void register_stat_cmd_arg(const char *cmd,
    void (*func)(const char *arg,void* userdata), void* userdata);
extern gboolean process_stat_cmd_arg(char *optstr);
extern void list_stat_cmd_args(void);
extern void start_requested_stats(void);

#endif
