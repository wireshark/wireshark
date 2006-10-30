/* packet-scsi.h
 * Author: Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002 Gerald Combs
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

#ifndef __PACKET_SCSI_H_
#define __PACKET_SCSI_H_


/* Structure containing itl nexus data :
 * The itlq nexus is a structure containing data specific
 * for a initiator target lun combination.
 */
typedef struct _itl_nexus_t {
#define SCSI_CMDSET_DEFAULT	0x80
#define SCSI_CMDSET_MASK	0x7f
    guint8 cmdset;         /* This is a bitfield.
			    * The MSB (0x80) represents whether 
			    * 0: the commandset is known from a INQ PDU
			    * 1: is using the "default" from preferences.
			    * The lower 7 bits represent the commandset used
			    * for decoding commands on this itl nexus.
			    * The field is initialized to 0xff == unknown.
			    */
    conversation_t *conversation;
} itl_nexus_t;

/* Structure containing itlq nexus data :
 * The itlq nexus is a structure containing data specific
 * for a initiator target lun queue/commandid combination.
 */
typedef struct _itlq_nexus_t {
    guint32 first_exchange_frame;
    guint32 last_exchange_frame;
    guint16 lun;         /* initialized to 0xffff == unknown */
    guint16 scsi_opcode; /* initialized to 0xffff == unknown */
    guint16 flags;

#define SCSI_DATA_READ	0x0001
#define SCSI_DATA_WRITE	0x0002
    guint16 task_flags; /* Flags set by the transport for this
			 * scsi task.
			 * 
			 * If there is no data being transferred both flags
			 * are 0 and both data lengths below are undefined.
			 *
			 * If one of the flags are set the amount of
			 * data being transferred is held in data_length
			 * and bidir_data_length is undefined.
			 *
			 * If both flags are set (a bidirectional transfer) 
			 * data_length specifies the amount of DATA-OUT and
			 * bidir_data_length specifies the amount of DATA-IN
			 */
    guint32 data_length;
    guint32 bidir_data_length;

    guint32 alloc_len;	/* we need to track alloc_len between the CDB and 
			 * the DATA pdus for some opcodes. 
			 */
    nstime_t fc_time;


    void *extra_data;     /* extra data that that is task specific */
} itlq_nexus_t;


#define SCSI_PDU_TYPE_CDB       1
#define SCSI_PDU_TYPE_DATA      2
#define SCSI_PDU_TYPE_RSP       4
#define SCSI_PDU_TYPE_SNS       5
typedef struct _scsi_task_data {
    int type;
    itlq_nexus_t *itlq;
    itl_nexus_t *itl;
} scsi_task_data_t;


/* list of commands for each commandset */
typedef void (*scsi_dissector_t)(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree, guint offset,
		gboolean isreq, gboolean iscdb,
                guint32 payload_len, scsi_task_data_t *cdata);

typedef struct _scsi_cdb_table_t {
	scsi_dissector_t	func;
} scsi_cdb_table_t;


/* SPC and SPC-2 Commands */
#define SCSI_SPC_CHANGE_DEFINITION       0x40
#define SCSI_SPC_COMPARE                 0x39
#define SCSI_SPC_COPY                    0x18
#define SCSI_SPC_COPY_AND_VERIFY         0x3A
#define SCSI_SPC2_INQUIRY                0x12
#define SCSI_SPC2_EXTCOPY                0x83
#define SCSI_SPC2_LOGSELECT              0x4C
#define SCSI_SPC2_LOGSENSE               0x4D
#define SCSI_SPC2_MODESELECT6            0x15
#define SCSI_SPC2_MODESELECT10           0x55
#define SCSI_SPC2_MODESENSE6             0x1A
#define SCSI_SPC2_MODESENSE10            0x5A
#define SCSI_SPC2_PERSRESVIN             0x5E
#define SCSI_SPC2_PERSRESVOUT            0x5F
#define SCSI_SPC2_PREVMEDREMOVAL         0x1E
#define SCSI_SPC2_READBUFFER             0x3C
#define SCSI_SPC2_RCVCOPYRESULTS         0x84
#define SCSI_SPC2_RCVDIAGRESULTS         0x1C
#define SCSI_SPC2_RELEASE6               0x17
#define SCSI_SPC2_RELEASE10              0x57
#define SCSI_SPC2_REPORTDEVICEID         0xA3
#define SCSI_SPC2_REPORTLUNS             0xA0
#define SCSI_SPC2_REQSENSE               0x03
#define SCSI_SPC2_RESERVE6               0x16
#define SCSI_SPC2_RESERVE10              0x56
#define SCSI_SPC2_SENDDIAG               0x1D
#define SCSI_SPC2_SETDEVICEID            0xA4
#define SCSI_SBC2_STARTSTOPUNIT          0x1B
#define SCSI_SPC2_TESTUNITRDY            0x00
#define SCSI_SPC2_WRITEBUFFER            0x3B
#define SCSI_SPC2_VARLENCDB              0x7F

void dissect_spc3_inquiry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint32 payload_len, scsi_task_data_t *cdata);
void dissect_spc3_logselect(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_spc3_logsense(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_spc3_modeselect10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len, scsi_task_data_t *cdata);
void dissect_spc3_modesense10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len, scsi_task_data_t *cdata);
void dissect_spc3_persistentreservein(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len, scsi_task_data_t *cdata);
void dissect_spc3_persistentreserveout(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_spc3_reportluns(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_spc3_testunitready (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_spc3_requestsense (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc2_startstopunit (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq _U_, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_spc3_preventallowmediaremoval (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc2_readwrite12 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc2_readwrite10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_sbc2_readcapacity10 (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb, guint payload_len _U_, scsi_task_data_t *cdata _U_);
void dissect_spc3_writebuffer (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint offset, gboolean isreq, gboolean iscdb _U_, guint payload_len _U_, scsi_task_data_t *cdata _U_);




extern const value_string scsi_status_val[];

/*
 * SCSI Device Types.
 *
 * These can be supplied to the dissection routines if the caller happens
 * to know the device type (e.g., NDMP assumes that a "jukebox" is a
 * media changer, SCSI_DEV_SMC, and a "tape" is a sequential access device,
 * SCSI_DEV_SSC).
 *
 * If the caller doesn't know the device type, it supplies SCSI_DEV_UNKNOWN.
 */
#define SCSI_DEV_UNKNOWN   -1
#define SCSI_DEV_SBC       0x0
#define SCSI_DEV_SSC       0x1
#define SCSI_DEV_PRNT      0x2
#define SCSI_DEV_PROC      0x3
#define SCSI_DEV_WORM      0x4
#define SCSI_DEV_CDROM     0x5
#define SCSI_DEV_SCAN      0x6
#define SCSI_DEV_OPTMEM    0x7
#define SCSI_DEV_SMC       0x8
#define SCSI_DEV_COMM      0x9
#define SCSI_DEV_RAID      0xC
#define SCSI_DEV_SES       0xD
#define SCSI_DEV_RBC       0xE
#define SCSI_DEV_OCRW      0xF
#define SCSI_DEV_OSD       0x11
#define SCSI_DEV_ADC       0x12
#define SCSI_DEV_NOLUN     0x1F

#define SCSI_DEV_BITS      0x1F /* the lower 5 bits indicate device type */
#define SCSI_MS_PCODE_BITS 0x3F /* Page code bits in Mode Sense */

/* Function Decls; functions invoked by SAM-2 transport protocols such as
 * FCP/iSCSI
 */
void dissect_scsi_cdb (tvbuff_t *, packet_info *, proto_tree *,
                       gint, itlq_nexus_t *, itl_nexus_t *);
void dissect_scsi_rsp (tvbuff_t *, packet_info *, proto_tree *, itlq_nexus_t *, itl_nexus_t *, guint8);
void dissect_scsi_payload (tvbuff_t *, packet_info *, proto_tree *,
                           gboolean, itlq_nexus_t *, itl_nexus_t *,
                           guint32 relative_offset);
void dissect_scsi_snsinfo (tvbuff_t *, packet_info *, proto_tree *, guint, guint, itlq_nexus_t *, itl_nexus_t *);

WS_VAR_IMPORT const value_string scsi_sbc2_vals[];
WS_VAR_IMPORT const value_string scsi_mmc_vals[];
WS_VAR_IMPORT const value_string scsi_ssc2_vals[];

extern int hf_scsi_control;
extern int hf_scsi_alloclen16;




/* These two defines are used to handle cases where data coming back from
 * the device is truncated due to a too short allocation_length specified
 * in the command CDB.
 * This is semi-common in SCSI and it would be wrong to mark these packets
 * as [malformed packets].
 * These macros will reset the reported length to what the data pdu specified
 * and if a ReportedBoundsError is generated we will instead throw
 * ScsiBoundsError
 *
 * Please see dissect_spc3_inquiry() for an example how to use these
 * macros.
 */
#define TRY_SCSI_CDB_ALLOC_LEN(pinfo, tvb, offset, length)		\
    {									\
	gboolean short_packet;						\
	tvbuff_t *new_tvb;						\
	guint32 end_data_offset=0;					\
									\
	short_packet=pinfo->fd->cap_len<pinfo->fd->pkt_len;		\
	new_tvb=tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), length);\
	tvb=new_tvb;							\
	offset=0;							\
	TRY {

#define END_TRY_SCSI_CDB_ALLOC_LEN 					\
		    if(end_data_offset){				\
			/* just verify we can read all the bytes we were\
			 * supposed to.					\
			 */						\
			tvb_get_guint8(tvb,end_data_offset);		\
	    	}							\
	    } /* TRY */							\
	CATCH(BoundsError) {						\
		if(short_packet){					\
			/* this was a short packet */			\
			RETHROW;					\
		} else {						\
			/* We probably tried to dissect beyond the end	\
			 * of the alloc len reported in the data	\
			 * pdu. This is not an error so dont flag it as	\
			 * one						\
			 * it is the alloc_len in the CDB that is the	\
			 * important one				\
			 */						\
		}							\
	    }								\
	CATCH(ReportedBoundsError) {					\
		if(short_packet){					\
			/* this was a short packet */			\
			RETHROW;					\
		} else {						\
			/* this packet was not really short but limited	\
			 * due to a short SCSI allocation length	\
			 */						\
			THROW(ScsiBoundsError);				\
		}							\
	    }								\
	CATCH_ALL {							\
		RETHROW;						\
	}								\
	ENDTRY;								\
    }

/* If the data pdu contains an alloc_len as well, this macro can be set
 * to registe this offset for the TRY section above.
 * At the end of the TRY section we will, if set, verify that the data
 * pdu contained all bytes that was specified in the data alloc len.
 *
 * This macro does currently not do anything but we might enhance it in
 * the future. There is no harm in teaching the dissector about how long
 * the data pdu is supposed to be according to alloc_len in the data pdu
 */
#define SET_SCSI_DATA_END(offset)					\
	end_data_offset=offset;


#endif
