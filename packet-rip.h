/* packet-rip.h (c) 1998 Hannes Boehm */

/* $Id: packet-rip.h,v 1.4 2000/02/15 21:02:59 gram Exp $ */

#define	RIPv1	1
#define	RIPv2	2

#define RIP_HEADER_LENGTH 4
#define RIP_ENTRY_LENGTH 20

typedef struct _e_riphdr {
    guint8	command;
    guint8	version;
    guint16	domain;
} e_riphdr;

typedef struct _e_rip_vektor {
    guint16	family;
    guint16	tag;
    guint32	ip;
    guint32	mask;
    guint32	next_hop;
    guint32	metric;
} e_rip_vektor;

typedef struct _e_rip_authentication {
    guint16	family;
    guint16	authtype;
    guint8	authentication[16];
} e_rip_authentication;

typedef union _e_rip_entry {
    e_rip_vektor	vektor;
    e_rip_authentication authentication;
} e_rip_entry;

void dissect_rip(const u_char *, int, frame_data *, proto_tree *);
