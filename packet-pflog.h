/* packet-pflog.h
 *
 * $Id: packet-pflog.h,v 1.2 2002/01/29 10:44:43 guy Exp $
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
  guint32       af;
  char          ifname[16];
  gint16        rnr;
  guint16       reason;
  guint16       action;
  guint16       dir;
};
#define PFLOG_HDRLEN    sizeof(struct pfloghdr)

/* Named reasons */
#define PFRES_NAMES  { \
  "match", \
  "bad-offset", \
  "fragment", \
  "short", \
  "normalize", \
  "memory", \
  NULL \
}
#define PFRES_MAX 6

/* Actions */
#define PF_PASS  0
#define PF_DROP  1
#define PF_SCRUB 2

/* Directions */
#define PF_IN  0
#define PF_OUT 1

/* BSDisms */
#ifndef NTOHL
# define NTOHL(x)       x = ntohl(x)
#endif
#ifndef NTOHS
# define NTOHS(x)       x = ntohs(x)
#endif
#ifndef HTONL
# define HTONL(x)       x = htonl(x)
#endif
#ifndef HTONS
# define HTONS(x)       x = htons(x)
#endif

# define BSD_PF_INET    2
# define BSD_PF_INET6   24

#endif /* __PACKET_PFLOG_H__ */
