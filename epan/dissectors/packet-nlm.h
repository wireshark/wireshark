/* packet-nlm.h (c) 1999 Uwe Girlich */
/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

