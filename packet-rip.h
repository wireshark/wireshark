/* packet-rip.h (c) 1998 Hannes Boehm */

#define	RIPv1	1
#define	RIPv2	2

#define RIP_HEADER_LENGTH 8
#define RIP_VEKTOR_LENGTH 16

typedef struct _e_riphdr {
    guint8	command;
    guint8	version;
    guint16	domain;
    guint16	family;
    guint16	tag;
} e_riphdr;


typedef struct _e_rip_vektor {
    guint32	ip;
    guint32	mask;
    guint32	next_hop;
    guint32	metric;
} e_rip_vektor;
