/* packet-socketcan.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SOCKETCAN_H__
#define __PACKET_SOCKETCAN_H__

#include <epan/tvbuff.h>
#include <epan/packet_info.h>
#include <epan/proto.h>

/*
 * Flags for CAN FD frames.
 * They are in the FD Flags field of a CAN FD frame.
 *
 * CANFD_FDF is in that field. and always set, as well as being present
 * but *never* set in what's at the location corresponding to that field
 * in a CAN classic frame, so we can distinguish between CAN classic and
 * CAN FD frames by testing that bit.
 */
#define CANFD_BRS 0x01 /* Bit Rate Switch (second bitrate for payload data) */
#define CANFD_ESI 0x02 /* Error State Indicator of the transmitting node */
#define CANFD_FDF 0x04 /* FD flag - if set, this is an FD frame */

/*
 * Flags for CAN XL frames.
 * They are in the Flags field of a CAN XL frame.
 *
 * CANXL_XLF is in that field, and always set. as well as being present
 * but *never* set in what's the location corresponding to that field
 * in a CAN classic or CAN FD frame, so we can distinguish between CAN
 * XL and CAN classic/CAN FD frames by testing that bit.
 */
#define CANXL_XLF 0x80 /* XL flag - if set, this is an XL frame */
#define CANXL_SEC 0x01 /* Simple Extended Content */

/*
 * CAN frame type.
 *
 * CAN_TYPE_CAN_CLASSIC is 0, and CAN_TYPE_CAN_FD is 1, so that the
 * fd field behaves, for CAN classic and CAN FD frames, the same way
 * that it did when it was a bool field that was false for CAN classic
 * frames and true for CAN FD frames.
 */
#define CAN_TYPE_CAN_CLASSIC 0
#define CAN_TYPE_CAN_FD      1
#define CAN_TYPE_CAN_XL      2

/* Structure that gets passed between dissectors. */
typedef struct can_info {
    uint32_t id;
    uint32_t len;
    unsigned fd;
    uint16_t bus_id;
} can_info_t;

/* controller area network (CAN) kernel definitions
 * These masks are usually defined within <linux/can.h> but are not
 * available on non-Linux platforms; that's the reason for the
 * redefinitions below
 *
 * special address description flags for the CAN_ID */
#define CAN_EFF_FLAG 0x80000000 /* EFF/SFF is set in the MSB */
#define CAN_RTR_FLAG 0x40000000 /* remote transmission request */
#define CAN_ERR_FLAG 0x20000000 /* error frame */

#define CAN_FLAG_MASK (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG)

#define CAN_EFF_MASK 0x1FFFFFFF /* extended frame format (EFF) has a 29 bit identifier */
#define CAN_SFF_MASK 0x000007FF /* standard frame format (SFF) has a 11 bit identifier */

#define CAN_ERR_DLC 8 /* dlc for error message frames */

/* error class (mask) in can_id */
#define CAN_ERR_TX_TIMEOUT   0x00000001U /* TX timeout (by netdevice driver) */
#define CAN_ERR_LOSTARB      0x00000002U /* lost arbitration    / data[0]    */
#define CAN_ERR_CTRL         0x00000004U /* controller problems / data[1]    */
#define CAN_ERR_PROT         0x00000008U /* protocol violations / data[2..3] */
#define CAN_ERR_TRX          0x00000010U /* transceiver status  / data[4]    */
#define CAN_ERR_ACK          0x00000020U /* received no ACK on transmission */
#define CAN_ERR_BUSOFF       0x00000040U /* bus off */
#define CAN_ERR_BUSERROR     0x00000080U /* bus error (may flood!) */
#define CAN_ERR_RESTARTED    0x00000100U /* controller restarted */
#define CAN_ERR_RESERVED     0x1FFFFE00U /* reserved bits */

/* error in CAN protocol (type) / data[2] */
#define CAN_ERR_PROT_UNSPEC      0x00 /* unspecified */
#define CAN_ERR_PROT_BIT         0x01 /* single bit error */
#define CAN_ERR_PROT_FORM        0x02 /* frame format error */
#define CAN_ERR_PROT_STUFF       0x04 /* bit stuffing error */
#define CAN_ERR_PROT_BIT0        0x08 /* unable to send dominant bit */
#define CAN_ERR_PROT_BIT1        0x10 /* unable to send recessive bit */
#define CAN_ERR_PROT_OVERLOAD    0x20 /* bus overload */
#define CAN_ERR_PROT_ACTIVE      0x40 /* active error announcement */
#define CAN_ERR_PROT_TX          0x80 /* error occurred on transmission */

/* error in CAN protocol (location) / data[3] */
#define CAN_ERR_PROT_LOC_UNSPEC  0x00 /* unspecified */
#define CAN_ERR_PROT_LOC_SOF     0x03 /* start of frame */
#define CAN_ERR_PROT_LOC_ID28_21 0x02 /* ID bits 28 - 21 (SFF: 10 - 3) */
#define CAN_ERR_PROT_LOC_ID20_18 0x06 /* ID bits 20 - 18 (SFF: 2 - 0 )*/
#define CAN_ERR_PROT_LOC_SRTR    0x04 /* substitute RTR (SFF: RTR) */
#define CAN_ERR_PROT_LOC_IDE     0x05 /* identifier extension */
#define CAN_ERR_PROT_LOC_ID17_13 0x07 /* ID bits 17-13 */
#define CAN_ERR_PROT_LOC_ID12_05 0x0F /* ID bits 12-5 */
#define CAN_ERR_PROT_LOC_ID04_00 0x0E /* ID bits 4-0 */
#define CAN_ERR_PROT_LOC_RTR     0x0C /* RTR */
#define CAN_ERR_PROT_LOC_RES1    0x0D /* reserved bit 1 */
#define CAN_ERR_PROT_LOC_RES0    0x09 /* reserved bit 0 */
#define CAN_ERR_PROT_LOC_DLC     0x0B /* data length code */
#define CAN_ERR_PROT_LOC_DATA    0x0A /* data section */
#define CAN_ERR_PROT_LOC_CRC_SEQ 0x08 /* CRC sequence */
#define CAN_ERR_PROT_LOC_CRC_DEL 0x18 /* CRC delimiter */
#define CAN_ERR_PROT_LOC_ACK     0x19 /* ACK slot */
#define CAN_ERR_PROT_LOC_ACK_DEL 0x1B /* ACK delimiter */
#define CAN_ERR_PROT_LOC_EOF     0x1A /* end of frame */
#define CAN_ERR_PROT_LOC_INTERM  0x12 /* intermission */

bool socketcan_call_subdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, struct can_info *can_info, const bool use_heuristics_first);
bool socketcan_set_source_and_destination_columns(packet_info* pinfo, can_info_t *caninfo);

/*
 * CAN XL SDU types from CAN CiA 611-1
 */
#define CANXL_SDU_TYPE_CONTENT_BASED_ADDRESSING 0x01
#define CANXL_SDU_TYPE_CAN_CC_CAN_FD            0x03
#define CANXL_SDU_TYPE_IEEE_802_3               0x04
#define CANXL_SDU_TYPE_IEEE_802_3_EXTENDED      0x05
#define CANXL_SDU_TYPE_CAN_CC                   0x06
#define CANXL_SDU_TYPE_CAN_FD                   0x07
#define CANXL_SDU_TYPE_CIA_611_2                0x08
#define CANXL_SDU_TYPE_AUTOSAR_MPDU             0x09
#define CANXL_SDU_TYPE_CIA_613_2                0x0A

#endif /* __PACKET_SOCKETCAN_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
