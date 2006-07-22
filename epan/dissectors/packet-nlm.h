/* packet-nlm.h (c) 1999 Uwe Girlich */
/* $Id$ 
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
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

#ifndef __PACKET_NLM_H__
#define __PACKET_NLM_H__

#define NLM_PROGRAM 100021

/* synchronous procedures */
#define NLM_NULL		0
#define NLM_TEST		1
#define NLM_LOCK		2
#define NLM_CANCEL		3
#define NLM_UNLOCK		4
#define NLM_GRANTED		5

/* asynchronous requests */
#define NLM_TEST_MSG		6
#define NLM_LOCK_MSG		7
#define NLM_CANCEL_MSG		8
#define NLM_UNLOCK_MSG		9
#define NLM_GRANTED_MSG		10

/* asynchronous responses */
#define NLM_TEST_RES		11
#define NLM_LOCK_RES		12
#define NLM_CANCEL_RES		13
#define NLM_UNLOCK_RES		14
#define NLM_GRANTED_RES		15

/* 16-19 not assigned */

/* DOS file sharing */
#define NLM_SHARE		20
#define NLM_UNSHARE		21
#define NLM_NM_LOCK		22
#define NLM_FREE_ALL		23

#endif /* packet-nlm.h */

