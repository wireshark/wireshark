#ifndef __ACN_H__
#define __ACN_H__

#define ACN_PDU_MIN_SIZE	2

#define ACN_PDU_DES		0xC0
#define ACN_PDU_DES_SAME	0x00
#define ACN_PDU_DES_PS		0x40
#define ACN_PDU_DES_CID		0x80
#define ACN_PDU_DES_ALL		0xC0
#define ACN_PDU_SRC		0x30
#define ACN_PDU_SRC_SAME	0x00
#define ACN_PDU_SRC_PS		0x10
#define ACN_PDU_SRC_CID		0x20
#define ACN_PDU_SRC_UM		0x30
#define ACN_PDU_FLAG_P		0x08
#define ACN_PDU_FLAG_T		0x04
#define ACN_PDU_FLAG_RES	0x02
#define ACN_PDU_FLAG_Z		0x01

typedef struct acn_pdu_history_s 
{
	guint8 source_type;
	union {
		guint16 ps;
		guint8 cid[16];
	} source;

	guint8 destination_type;
	union {
		guint16 ps;
		guint8 cid[16];	
	} destination;
	
	guint16 protocol;
	guint16 type;
} acn_pdu_history_t;


#define ACN_PDU_PROTO_UNKNOWN	0
#define ACN_PDU_PROTO_SDT	1
#define ACN_PDU_PROTO_DMP	2

#define ACN_PDU_TYPE_UNKNOWN	0

/* SDT */
#define ACN_SDT_TYPE_UNKNOWN		0
#define ACN_SDT_TYPE_RELSEQDATA		1
#define ACN_SDT_TYPE_UNRELSEQDATA	2
#define ACN_SDT_TYPE_UNSEQDATA		3
#define ACN_SDT_TYPE_JOIN		4
#define ACN_SDT_TYPE_TRANSFER		5
#define ACN_SDT_TYPE_JOINREF		6
#define ACN_SDT_TYPE_JOINACC		7
#define ACN_SDT_TYPE_LEAVEREQ		8
#define ACN_SDT_TYPE_LEAVE		9
#define ACN_SDT_TYPE_LEAVING		10
#define ACN_SDT_TYPE_NAKUPON		11
#define ACN_SDT_TYPE_NAKUPOFF		12
#define ACN_SDT_TYPE_NAKDOWNON		13
#define ACN_SDT_TYPE_NAKDOWNOFF		14
#define ACN_SDT_TYPE_REPLOSTSEQON	15
#define ACN_SDT_TYPE_REPLOSTSEQOFF	16
#define ACN_SDT_TYPE_SESSEXPIRY		17
#define ACN_SDT_TYPE_MAK		18
#define ACN_SDT_TYPE_ACK		19
#define ACN_SDT_TYPE_NAK		20
#define ACN_SDT_TYPE_SEQLOST		21
#define ACN_SDT_TYPE_NAKPARAMS		22


/* DMP */
#define ACN_DMP_TYPE_UNKNOWN	0

#endif /* !__ACN_H__ */
