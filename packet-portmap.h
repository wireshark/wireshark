/* packet-portmap.h */
/* $Id: packet-portmap.h,v 1.2 1999/11/10 21:05:10 nneul Exp $ */

#ifndef PACKET_PORTMAP_H
#define PACKET_PORTMAP_H

#define PORTMAP_PROGRAM  100000

#define PORTMAPPROC_NULL     0
#define PORTMAPPROC_SET      1
#define PORTMAPPROC_UNSET    2
#define PORTMAPPROC_GETPORT  3
#define PORTMAPPROC_DUMP     4
#define PORTMAPPROC_CALLIT   5

struct pmap {
        guint32 pm_prog;
        guint32 pm_vers;
        guint32 pm_prot;
        guint32 pm_port;
};

#endif
