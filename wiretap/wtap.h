/*
 * wtap.h
 * ------
 * Wiretap Library for Packet Capturing and Filtering
 * 
 * Gilbert Ramirez
 */

/* Encapsulation types */
#define WTAP_ENCAP_NONE				0
#define WTAP_ENCAP_ETHERNET			1
#define WTAP_ENCAP_TR				2
#define WTAP_ENCAP_SLIP				3
#define WTAP_ENCAP_PPP				4
#define WTAP_ENCAP_FDDI				5
#define WTAP_ENCAP_RAW_IP			6

/* File types that can be read by wiretap */
#define WTAP_FILE_UNKNOWN			0
#define WTAP_FILE_WTAP				1
#define WTAP_FILE_PCAP				2
#define WTAP_FILE_LANALYZER			3
#define WTAP_FILE_NGSNIFFER			4
#define WTAP_FILE_SNOOP				6
#define WTAP_FILE_IPTRACE			7

#include <sys/types.h>
#include <sys/time.h>
#include <glib.h>
#include <pcap.h>
#include <buffer.h>

struct wtap_pkthdr {
	struct timeval ts;
	guint32	caplen;
	guint32 len;
};

typedef void (*wtap_handler)(u_char*, const struct wtap_pkthdr*,
		const u_char *);

typedef struct _wtap {
	FILE*			fh;
	int				file_type;
	unsigned long	frame_number;
	unsigned long	file_byte_offset;
	Buffer			frame_buffer;
	struct wtap_pkthdr	phdr;

	pcap_t			*pcap;
	char			err_str[PCAP_ERRBUF_SIZE];
	int				encapsulation;
} wtap;


wtap* wtap_open_offline(char *filename, int filetype);
void wtap_loop(wtap *wth, int, wtap_handler, u_char*);

FILE* wtap_file(wtap *wth);
int wtap_snapshot_length(wtap *wth); /* per file */
int wtap_file_type(wtap *wth);
int wtap_encapsulation(wtap *wth); /* per file */
void wtap_close(wtap *wth);

/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletoh[sl] versions return the little-endian representation.
 */

#define pntohs(p)  ((guint16)                       \
                    ((guint16)*((guint8 *)p+0)<<8|  \
                     (guint16)*((guint8 *)p+1)<<0))

#define pntohl(p)  ((guint32)*((guint8 *)p+0)<<24|  \
                    (guint32)*((guint8 *)p+1)<<16|  \
                    (guint32)*((guint8 *)p+2)<<8|   \
                    (guint32)*((guint8 *)p+3)<<0)

#define pletohs(p) ((guint16)                       \
                    ((guint16)*((guint8 *)p+1)<<8|  \
                     (guint16)*((guint8 *)p+0)<<0))

#define pletohl(p) ((guint32)*((guint8 *)p+3)<<24|  \
                    (guint32)*((guint8 *)p+2)<<16|  \
                    (guint32)*((guint8 *)p+1)<<8|   \
                    (guint32)*((guint8 *)p+0)<<0)



#define DLT_NULL	0	/* no link-layer encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* IEEE 802 Networks */
#define DLT_ARCNET	7	/* ARCNET */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */
#define DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define DLT_RAW		12	/* raw IP */
#define DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */
