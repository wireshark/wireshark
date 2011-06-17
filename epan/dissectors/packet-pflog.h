/* packet-pflog.h
 *
 * $Id$
 *
 * Copyright 2001 Mike Frantzen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PACKET_PFLOG_H__
#define __PACKET_PFLOG_H__

/* The header in OpenBSD pflog files. */

struct pfloghdr {
	guchar	length;
	guchar	af;
	guchar	action;
	guchar	reason;
	char	ifname[16];
	char	ruleset[16];
	guint32	rulenr;
	guint32	subrulenr;
	guchar	dir;
	guchar	pad[3];
};

#define PFLOG_HDRLEN		sizeof(struct pfloghdr)
/* minus pad, also used as a signature */
#define PFLOG_REAL_HDRLEN	offsetof(struct pfloghdr, pad);
#define MIN_PFLOG_HDRLEN	45

struct old_pfloghdr {
  guint32       af;
  char          ifname[16];
  gint16        rnr;
  guint16       reason;
  guint16       action;
  guint16       dir;
};
#define OLD_PFLOG_HDRLEN	sizeof(struct old_pfloghdr)

/* Actions */
#define PF_PASS  0
#define PF_DROP  1
#define PF_SCRUB 2

/* Directions */
#define PF_OLD_IN  0
#define PF_OLD_OUT 1

#define PF_INOUT 0
#define PF_IN    1
#define PF_OUT   2

#endif /* __PACKET_PFLOG_H__ */
