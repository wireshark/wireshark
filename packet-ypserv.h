/* packet-ypserv.h */
/* $Id: packet-ypserv.h,v 1.1 1999/11/10 17:23:54 nneul Exp $ */

#ifndef PACKET_YPSERV_H
#define PACKET_YPSERV_H

#define YPSERV_PROGRAM  100004

#define YPPROC_NULL 0
#define YPPROC_DOMAIN 1
#define YPPROC_DOMAIN_NONACK 2
#define YPPROC_MATCH 3
#define YPPROC_FIRST 4
#define YPPROC_NEXT 5
#define YPPROC_XFR 6
#define YPPROC_CLEAR 7
#define YPPROC_ALL 8
#define YPPROC_MASTER 9
#define YPPROC_ORDER 10
#define YPPROC_MAPLIST 11

#endif
