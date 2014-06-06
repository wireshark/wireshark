/* packet-mausb.c
 * Routines for Media Agnostic USB dissection
 * Copyright 2014, Intel Corporation
 * Author: Sean O. Stalley <sean.stalley@intel.com>
 *
 * Dedicated to Robert & Dorothy Stalley
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-llc.h"
#include "packet-usb.h"

void proto_reg_handoff_mausb(void);
void proto_register_mausb(void);
void proto_register_mausb_oui(void);

/* For SNAP Packets */
static int hf_llc_mausb_pid = -1;

/* Initialize the protocol and registered fields */
static int proto_mausb = -1;
static int hf_mausb_version = -1;
static int hf_mausb_flags = -1;
static int hf_mausb_flag_host = -1;
static int hf_mausb_flag_retry = -1;
static int hf_mausb_flag_timestamp = -1;
static int hf_mausb_flag_reserved = -1;
static int hf_mausb_type = -1;
static int hf_mausb_length = -1;
static int hf_mausb_dev_handle = -1;
static int hf_mausb_ep_handle = -1;
static int hf_mausb_ep_handle_d = -1;
static int hf_mausb_ep_handle_ep_num = -1;
static int hf_mausb_ep_handle_dev_addr = -1;
static int hf_mausb_ep_handle_bus_num = -1;
static int hf_mausb_ma_dev_addr = -1;
static int hf_mausb_ssid = -1;
static int hf_mausb_status = -1;

/* managment packet specific */
static int hf_mausb_token = -1;
static int hf_mausb_mgmt_pad = -1;
static int hf_mausb_mgmt_ep_handle_num = -1;
static int hf_mausb_mgmt_ep_handle_pad = -1;
static int hf_mausb_mgmt_ep_des_num = -1;
static int hf_mausb_mgmt_ep_des_size = -1;
static int hf_mausb_mgmt_ep_des_pad = -1;
static int hf_mausb_mgmt_type_spec = -1;
static int hf_mausb_mgmt_type_spec_generic = -1;

/* EPHandleReq & Resp packet specific */
static int hf_mausb_ep_handle_req_pad = -1;
static int hf_mausb_ep_handle_resp_dir = -1;
static int hf_mausb_ep_handle_resp_iso = -1;
static int hf_mausb_ep_handle_resp_lman = -1;
static int hf_mausb_ep_handle_resp_valid = -1;
static int hf_mausb_ep_handle_resp_ccu = -1;
static int hf_mausb_ep_handle_resp_buf_size = -1;
static int hf_mausb_ep_handle_resp_iso_prog_dly = -1;
static int hf_mausb_ep_handle_resp_iso_resp_dly = -1;

/* data packet specific */
static int hf_mausb_eps = -1;
static int hf_mausb_eps_rsvd = -1;
static int hf_mausb_tflags = -1;
static int hf_mausb_tflag_arq = -1;
static int hf_mausb_tflag_neg = -1;
static int hf_mausb_tflag_eot = -1;
static int hf_mausb_tflag_type = -1;
static int hf_mausb_tflag_rsvd = -1;
static int hf_mausb_stream_id = -1;
static int hf_mausb_seq_num = -1;
static int hf_mausb_req_id = -1;
static int hf_mausb_rem_size_credit = -1;
static int hf_mausb_payload = -1;

/* expert info fields */
static expert_field ei_ep_handle_len = EI_INIT;
static expert_field ei_len = EI_INIT;
static expert_field ei_mgmt_type_undef = EI_INIT;
static expert_field ei_mgmt_type_spec_len_long = EI_INIT;
static expert_field ei_mgmt_type_spec_len_short = EI_INIT;

/* MAUSB Version, per 6.2.1.1 */
#define MAUSB_VERSION_1_0     0x0
#define MAUSB_VERSION_MASK    0x0F

/* for dissecting snap packets */
/*
 * TODO: determine assigned OUI & PID value
 * (yet to be assigned as of Earth Day 2014)
 */
#define OUI_MAUSB 0xdead54
#define PID_MAUSB 0xf539

static const value_string mausb_pid_string[] = {
    { PID_MAUSB, "MAUSB" },
    { 0, NULL}
};

static const value_string mausb_version_string[] = {
    { MAUSB_VERSION_1_0, "MAUSB protocol version 1.0" },
    { 0, NULL}
};

/* Packet flags, per 6.2.1.2 */
#define MAUSB_FLAG_MASK       0xF0
#define MAUSB_FLAG_HOST       (1 << 0)
#define MAUSB_FLAG_RETRY      (1 << 1)
#define MAUSB_FLAG_TIMESTAMP  (1 << 2)
#define MAUSB_FLAG_RESERVED   (1 << 3)
#define MAUSB_FLAG_OFFSET     4


static const value_string mausb_flag_string[] = {
    { 0,                                                         "(None)"                   },
    { MAUSB_FLAG_HOST,                                           "(Host)"                   },
    { MAUSB_FLAG_RETRY,                                          "(Retry)"                  },
    { MAUSB_FLAG_TIMESTAMP,                                      "(Timestamp)"              },
    { MAUSB_FLAG_HOST  | MAUSB_FLAG_RETRY,                       "(Host, Retry)"            },
    { MAUSB_FLAG_HOST  | MAUSB_FLAG_TIMESTAMP,                   "(Host, Timestamp)"        },
    { MAUSB_FLAG_RETRY | MAUSB_FLAG_TIMESTAMP,                   "(Retry, Timestamp)"       },
    { MAUSB_FLAG_HOST | MAUSB_FLAG_RETRY | MAUSB_FLAG_TIMESTAMP, "(Host, Retry, Timestamp)" },
    { 0, NULL}
};

/* Packet Types, per 6.2.1.3 */
#define MAUSB_PKT_TYPE_MASK       0xC0
#define MAUSB_PKT_TYPE_MGMT       (0 << 6)
#define MAUSB_PKT_TYPE_CTRL       (1 << 6)
#define MAUSB_PKT_TYPE_DATA       (2 << 6)

/* Packet Subtypes, per 6.2.1.3 */
#define MAUSB_SUBTYPE_MASK        0x3F

enum mausb_pkt_type {
    /* Management packets */
    CapReq = 0x00 | MAUSB_PKT_TYPE_MGMT,
    CapResp               ,
    USBDevHandleReq       ,
    USBDevHandleResp      ,

    EPHandleReq           ,
    EPHandleResp          ,
    EPActivateReq         ,
    EPActivateResp        ,
    EPInactivateReq       ,
    EPInactivateResp      ,
    EPRestartReq          ,
    EPRestartResp         ,
    EPClearTransferReq    ,
    EPClearTransferResp   ,
    EPHandleDeleteReq     ,
    EPHandleDeleteResp    ,

    MAUSBDevResetReq      ,
    MAUSBDevResetResp     ,
    ModifyEP0Req          ,
    ModifyEP0Resp         ,
    SetDevAddrReq         ,
    SetDevAddrResp        ,
    UpdateDevReq          ,
    UpdateDevResp         ,
    DisconnectDevReq      ,
    DisconnectDevResp     ,

    MAUSBDevSleepReq      ,
    MAUSBDevSleepResp     ,
    MAUSBDevWakeReq       ,
    MAUSBDevWakeResp      ,
    MAUSBDevInitSleepReq  , /* Transmitted by Device */
    MAUSBDevInitSleepResp , /* Transmitted by Host   */
    MAUSBDevRemoteWakeReq , /* Transmitted by Device */
    MAUSBDevRemoteWakeResp, /* Transmitted by Host   */
    PingReq               , /* Transmitted by either */
    PingResp              , /* Transmitted by either */
    MAUSBDevDisconnectReq ,
    MAUSBDevDisconnectResp,
    MAUSBDevInitDisconReq , /* Transmitted by Device */
    MAUSBDevInitDisconResp, /* Transmitted by Host   */
    MAUSBSyncReq          ,
    MAUSBSyncResp         ,

    CancelTransferReq     ,
    CancelTransferResp    ,
    EPOpenStreamReq       ,
    EPOpenStreamResp      ,
    EPCloseStreamReq      ,
    EPCloseStreamResp     ,
    USBDevResetReq        ,
    USBDevResetResp       ,

    /* Vendor-Specific Management Packets */
    /* Transmitted by either */
    VendorSpecificReq = 0x3E | MAUSB_PKT_TYPE_MGMT,
    VendorSpecificResp    ,

    /* Control Packets */ /* Transmitter not defined! */
    TransferSetupReq = 0x00 | MAUSB_PKT_TYPE_CTRL,
    TransferSetupResp     ,
    TransferTearDownConf  ,

    /* Data Packets */
    TransferReq = 0x00 | MAUSB_PKT_TYPE_DATA,
    TransferResp = 0x01 | MAUSB_PKT_TYPE_DATA,
    TransferAck           , /* Transmitted by Host   */
    IsochTransferReq      , /* Transmitter not defined! */
    IsochTransferResp       /* Transmitter not defined! */
};


/**
 * Type & Subtype values for MAUSB packet variants, per 6.2.1.3, Table 5
 */
static const value_string mausb_type_string[] = {
    /* Management packets */
    { MAUSB_PKT_TYPE_MGMT | 0x00 , "CapReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x01 , "CapResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x02 , "USBDevHandleReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x03 , "USBDevHandleResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x04 , "EPHandleReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x05 , "EPHandleResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x06 , "EPActivateReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x07 , "EPActivateResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x08 , "EPInactivateReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x09 , "EPInactivateResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x0a , "EPResetReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x0b , "EPResetResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x0c , "EPClearTransferReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x0d , "EPClearTransferResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x0e , "EPHandleDeleteReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x0f , "EPHandleDeleteResp" },

    { MAUSB_PKT_TYPE_MGMT | 0x10 , "MADevResetReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x11 , "MADevResetResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x12 , "ModifyEP0Req" },
    { MAUSB_PKT_TYPE_MGMT | 0x13 , "ModifyEP0Resp" },
    { MAUSB_PKT_TYPE_MGMT | 0x14 , "SetDevAddrReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x15 , "SetDevAddrResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x16 , "UpdateDevReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x17 , "UpdateDevResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x18 , "DisconnectDevReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x19 , "DisconnectDevResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x1a , "USBSuspendReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x1b , "USBSuspendResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x1c , "USBResumeReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x1d , "USBResumeResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x1e , "RemoteWakeReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x1f , "RemoteWakeResp" },

    { MAUSB_PKT_TYPE_MGMT | 0x20 , "PingReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x21 , "PingResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x22 , "MADevDisconnectReq " },
    { MAUSB_PKT_TYPE_MGMT | 0x23 , "MADevDisconnectResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x24 , "MADevInitDisconReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x25 , "MADevInitDisconResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x26 , "SyncReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x27 , "SyncResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x28 , "CancelTransferReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x29 , "CancelTransferResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x2a , "EPOpenStreamReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x2b , "EPOpenStreamResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x2c , "EPCloseStreamReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x2d , "EPCloseStreamResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x2e , "USBDevResetReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x2f , "USBDevResetResp" },

    { MAUSB_PKT_TYPE_MGMT | 0x30 , "DevNotificationReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x31 , "DevNotificationResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x32 , "EPSetKeepAliveReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x33 , "EPSetKeepAliveResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x34 , "GetPortBWReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x35 , "GetPortBWResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x36 , "SleepReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x37 , "SleepResp" },
    { MAUSB_PKT_TYPE_MGMT | 0x38 , "WakeReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x39 , "WakeResp" },

    /* Vendor-Specific Management Packets */
    { MAUSB_PKT_TYPE_MGMT | 0x3e, "VendorSpecificReq" },
    { MAUSB_PKT_TYPE_MGMT | 0x3f, "VendorSpecificResp" },

    /* Control Packets */
    { MAUSB_PKT_TYPE_CTRL | 0x00, "TransferSetupReq" },
    { MAUSB_PKT_TYPE_CTRL | 0x01, "TransferSetupResp" },
    { MAUSB_PKT_TYPE_CTRL | 0x02, "TransferTearDownConf" },

    /* Data Packets */
    { MAUSB_PKT_TYPE_DATA | 0x00, "TransferReq" },
    { MAUSB_PKT_TYPE_DATA | 0x01, "TransferResp" },
    { MAUSB_PKT_TYPE_DATA | 0x02, "TransferAck" },
    { MAUSB_PKT_TYPE_DATA | 0x03, "IsochTransferReq" },
    { MAUSB_PKT_TYPE_DATA | 0x04, "IsochTransferResp" },
    { 0, NULL}
};

#define MAUSB_EP_HANDLE_D        0x0001
#define MAUSB_EP_HANDLE_EP_NUM   0x001e
#define MAUSB_EP_HANDLE_DEV_ADDR 0x0fe0
#define MAUSB_EP_HANDLE_BUS_NUM  0xf000

#define MAUSB_EP_HANDLE_D_OFFSET        0
#define MAUSB_EP_HANDLE_EP_NUM_OFFSET   1
#define MAUSB_EP_HANDLE_DEV_ADDR_OFFSET 5
#define MAUSB_EP_HANDLE_BUS_NUM_OFFSET  12

static const value_string mausb_status_string[] = {
    {   0, "SUCCESS (NO_ERROR)" },
    { 128, "UNSUCCESSFUL" },
    { 129, "INVALID_MA_USB_SESSION_STATE" },
    { 130, "INVALID_DEVICE_HANDLE" },
    { 131, "INVALID_EP_HANDLE" },
    { 132, "INVALID_EP_HANDLE_STATE" },
    { 133, "INVALID_REQUEST" },
    { 134, "MISSING_SEQUENCE_NUMBER" },
    { 135, "TRANSFER_PENDING" },
    { 136, "TRANSFER_EP_STALL" },
    { 137, "TRANSFER_SIZE_ERROR" },
    { 138, "TRANSFER_DATA_BUFFER_ERROR" },
    { 139, "TRANSFER_BABBLE_DETECTED" },
    { 140, "TRANSFER_TRANSACTION_ERROR" },
    { 141, "TRANSFER_SHORT_TRANSFER" },
    { 142, "TRANSFER_CANCELLED" },
    { 143, "INSUFFICENT_RESOURCES" },
    { 144, "NOT_SUFFICENT_BANDWIDTH" },
    { 145, "INTERNAL_ERROR" },
    { 146, "DATA_OVERRUN" },
    { 147, "DEVICE_NOT_ACCESSED" },
    { 148, "BUFFER_OVERRUN" },
    { 149, "BUSY" },
    { 150, "DROPPED_PACKET" },
    { 151, "ISOC_TIME_EXPIRED" },
    { 152, "ISOCH_TIME_INVALID" },
    { 153, "NO_USB_PING_RESPONSE" },
    { 154, "NOT_SUPPORTED" },
    { 155, "REQUEST_DENIED" },
    { 0, NULL}
};

#define MAUSB_TOKEN_MASK  0x03ff
#define MAUSB_MGMT_PAD_MASK  0xfffc
#define MAUSB_MGMT_NUM_EP_DES_MASK 0x001f
#define MAUSB_MGMT_SIZE_EP_DES_OFFSET 5
#define MAUSB_MGMT_SIZE_EP_DES_MASK (0x003f << MAUSB_MGMT_SIZE_EP_DES_OFFSET)

#define DWORD_MASK 0xffffffff
#define MAUSB_MGMT_NUM_EP_HANDLE_PAD_MASK \
            (DWORD_MASK & !(MAUSB_MGMT_NUM_EP_DES_MASK))
#define MAUSB_MGMT_EP_DES_PAD_MASK \
            ((DWORD_MASK & !(MAUSB_MGMT_NUM_EP_DES_MASK | \
                           MAUSB_MGMT_SIZE_EP_DES_MASK)) >> 8)


/* EPHandleResp Bitfield Masks */
#define MAUSB_EP_HANDLE_RESP_DIR_MASK   (1 << 0)
#define MAUSB_EP_HANDLE_RESP_ISO_MASK   (1 << 1)
#define MAUSB_EP_HANDLE_RESP_LMAN_MASK  (1 << 2)
#define MAUSB_EP_HANDLE_RESP_VALID_MASK (1 << 3)

static const value_string mausb_eps_string[] = {
    { 0, "Unassigned" },
    { 1, "Active" },
    { 2, "Inactive" },
    { 3, "Halted" },
    { 0, NULL}
};

#define MAUSB_EPS_MASK 0x03

#define MAUSB_TFLAG_MASK   0xfc

#define MAUSB_TX_TYPE_CTRL (0 << 3)
#define MAUSB_TX_TYPE_ISOC (1 << 3)
#define MAUSB_TX_TYPE_BULK (2 << 3)
#define MAUSB_TX_TYPE_INTR (3 << 3)

#define MAUSB_TFLAG_OFFSET     2
#define MAUSB_TFLAG_ARQ  (1 << 0)
#define MAUSB_TFLAG_NEG  (1 << 1)
#define MAUSB_TFLAG_EOT  (1 << 2)
#define MAUSB_TFLAG_TRANSFER_TYPE (3 << 3)
#define MAUSB_TFLAG_RSVD (1 << 5)

static const value_string mausb_transfer_type_string[] = {
    { 0, "Control" },
    { 1, "Isochronous" },
    { 2, "Bulk" },
    { 3, "Interrupt" },
    { 0, NULL},
};

static const value_string mausb_tflag_string[] = {
    { MAUSB_TX_TYPE_CTRL,                                     "Control"                 },
    { MAUSB_TX_TYPE_CTRL | MAUSB_TFLAG_ARQ,                   "Control (ARQ)"           },
    { MAUSB_TX_TYPE_CTRL | MAUSB_TFLAG_NEG,                   "Control (NEG)"           },
    { MAUSB_TX_TYPE_CTRL | MAUSB_TFLAG_EOT,                   "Control (EoT)"           },
    { MAUSB_TX_TYPE_CTRL | MAUSB_TFLAG_ARQ | MAUSB_TFLAG_NEG, "Control (ARQ, NEG)"      },
    { MAUSB_TX_TYPE_CTRL | MAUSB_TFLAG_ARQ | MAUSB_TFLAG_EOT, "Control (ARQ, EoT)"      },
    { MAUSB_TX_TYPE_CTRL | MAUSB_TFLAG_NEG | MAUSB_TFLAG_EOT, "Control (NEG, EoT)"      },
    { MAUSB_TX_TYPE_CTRL | MAUSB_TFLAG_ARQ
       | MAUSB_TFLAG_NEG | MAUSB_TFLAG_EOT,                   "Control (ARQ, NEG, EoT)" },

    { MAUSB_TX_TYPE_ISOC,                                     "Isochronous"                 },
    { MAUSB_TX_TYPE_ISOC | MAUSB_TFLAG_ARQ,                   "Isochronous (ARQ)"           },
    { MAUSB_TX_TYPE_ISOC | MAUSB_TFLAG_NEG,                   "Isochronous (NEG)"           },
    { MAUSB_TX_TYPE_ISOC | MAUSB_TFLAG_EOT,                   "Isochronous (EoT)"           },
    { MAUSB_TX_TYPE_ISOC | MAUSB_TFLAG_ARQ | MAUSB_TFLAG_NEG, "Isochronous (ARQ, NEG)"      },
    { MAUSB_TX_TYPE_ISOC | MAUSB_TFLAG_ARQ | MAUSB_TFLAG_EOT, "Isochronous (ARQ, EoT)"      },
    { MAUSB_TX_TYPE_ISOC | MAUSB_TFLAG_NEG | MAUSB_TFLAG_EOT, "Isochronous (NEG, EoT)"      },
    { MAUSB_TX_TYPE_ISOC | MAUSB_TFLAG_ARQ
       | MAUSB_TFLAG_NEG | MAUSB_TFLAG_EOT,                   "Isochronous (ARQ, NEG, EoT)" },

    { MAUSB_TX_TYPE_BULK,                                     "Bulk"                 },
    { MAUSB_TX_TYPE_BULK | MAUSB_TFLAG_ARQ,                   "Bulk (ARQ)"           },
    { MAUSB_TX_TYPE_BULK | MAUSB_TFLAG_NEG,                   "Bulk (NEG)"           },
    { MAUSB_TX_TYPE_BULK | MAUSB_TFLAG_EOT,                   "Bulk (EoT)"           },
    { MAUSB_TX_TYPE_BULK | MAUSB_TFLAG_ARQ | MAUSB_TFLAG_NEG, "Bulk (ARQ, NEG)"      },
    { MAUSB_TX_TYPE_BULK | MAUSB_TFLAG_ARQ | MAUSB_TFLAG_EOT, "Bulk (ARQ, EoT)"      },
    { MAUSB_TX_TYPE_BULK | MAUSB_TFLAG_NEG | MAUSB_TFLAG_EOT, "Bulk (NEG, EoT)"      },
    { MAUSB_TX_TYPE_BULK | MAUSB_TFLAG_ARQ
       | MAUSB_TFLAG_NEG | MAUSB_TFLAG_EOT,                   "Bulk (ARQ, NEG, EoT)" },

    { MAUSB_TX_TYPE_INTR,                                     "Interrupt"                 },
    { MAUSB_TX_TYPE_INTR | MAUSB_TFLAG_ARQ,                   "Interrupt (ARQ)"           },
    { MAUSB_TX_TYPE_INTR | MAUSB_TFLAG_NEG,                   "Interrupt (NEG)"           },
    { MAUSB_TX_TYPE_INTR | MAUSB_TFLAG_EOT,                   "Interrupt (EoT)"           },
    { MAUSB_TX_TYPE_INTR | MAUSB_TFLAG_ARQ | MAUSB_TFLAG_NEG, "Interrupt (ARQ, NEG)"      },
    { MAUSB_TX_TYPE_INTR | MAUSB_TFLAG_ARQ | MAUSB_TFLAG_EOT, "Interrupt (ARQ, EoT)"      },
    { MAUSB_TX_TYPE_INTR | MAUSB_TFLAG_NEG | MAUSB_TFLAG_EOT, "Interrupt (NEG, EoT)"      },
    { MAUSB_TX_TYPE_INTR | MAUSB_TFLAG_ARQ
       | MAUSB_TFLAG_NEG | MAUSB_TFLAG_EOT,                   "Interrupt (ARQ, NEG, EoT)" },
    { 0, NULL}
};


const true_false_string tfs_ep_handle_resp_dir = { "IN", "OUT or Control" };

#define MAUSB_TRANSFER_TYPE_OFFSET 3 /* Offset from start of TFlags Field */
                                     /* (EPS not included) */
#define MAUSB_TRANSFER_TYPE_CTRL      (0 << MAUSB_TRANSFER_TYPE_OFFSET)
#define MAUSB_TRANSFER_TYPE_ISO       (1 << MAUSB_TRANSFER_TYPE_OFFSET)
#define MAUSB_TRANSFER_TYPE_BULK      (2 << MAUSB_TRANSFER_TYPE_OFFSET)
#define MAUSB_TRANSFER_TYPE_INTERRUPT (3 << MAUSB_TRANSFER_TYPE_OFFSET)

/** Common header fields, per section 6.2.1 */
struct mausb_header {
    /* DWORD 0 */
    guint8   ver_flags;
    guint8   type;
    guint16  length;
    /* DWORD 1 */
    guint16  handle;
    guint8   ma_dev_addr;
    guint8   mass_id;
    /* DWORD 2 */
    guint8   status;
    union {
        guint16 token;
        struct {
            guint8   eps_tflags;
            guint16  stream_id;
            /* DWORD 3 */
            guint32  seq_num; /* Note: only 24 bits used */
            guint8   req_id;
            /* DWORD 4 */
            guint32  credit;
        } s;
    } u;
};

/* We need at least the first DWORD to determine the packet length (for TCP) */
#define MAUSB_MIN_LENGTH 4

#define MAUSB_MIN_MGMT_LENGTH 12
#define MAUSB_MIN_DATA_LENGTH 20
#define MAUSB_COMMON_LEN 9


/*** Packet parsing helper functions ***/

static gboolean mausb_is_from_host(struct mausb_header *header)
{
    return (MAUSB_FLAG_HOST << MAUSB_FLAG_OFFSET) & header->ver_flags;
}

static gboolean mausb_is_mgmt_pkt(struct mausb_header *header)
{
    return MAUSB_PKT_TYPE_MGMT == (header->type & MAUSB_PKT_TYPE_MASK);
}

static gboolean mausb_is_data_pkt(struct mausb_header *header)
{
    return MAUSB_PKT_TYPE_DATA == (header->type & MAUSB_PKT_TYPE_MASK);
}

static gboolean mausb_is_transfer_req(struct mausb_header *header)
{
    return TransferReq == header->type;
}

static gint8 mausb_tx_type(struct mausb_header *header)
{
    return (header->u.s.eps_tflags >> MAUSB_TFLAG_OFFSET) & MAUSB_TFLAG_TRANSFER_TYPE;
}

static gboolean mausb_has_setup_data(struct mausb_header *header)
{
    if ((TransferReq == header->type ) &&
        (mausb_is_from_host(header)) &&
        (0 == header->u.s.seq_num) &&
        (MAUSB_TX_TYPE_CTRL == mausb_tx_type(header))) {

        return TRUE;
    }
    return FALSE;
}

/*** EP Handle parsing helper functions */

static guint8 mausb_ep_handle_ep_num(guint16 handle) {
    return (handle & MAUSB_EP_HANDLE_EP_NUM) >> MAUSB_EP_HANDLE_EP_NUM_OFFSET;
}

static guint8 mausb_ep_handle_dev_addr(guint16 handle) {
    return (handle & MAUSB_EP_HANDLE_DEV_ADDR) >> MAUSB_EP_HANDLE_DEV_ADDR_OFFSET;
}

/* returns the length field of the MAUSB packet */
static guint mausb_get_pkt_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    return tvb_get_letohs(tvb, offset + 2);
}

/* Global Port Preference */
static unsigned int gPORT_PREF = 0;

/* Initialize the subtree pointers */
static gint ett_mausb = -1;
static gint ett_mausb_flags = -1;
static gint ett_mausb_ep_handle = -1;
static gint ett_mausb_tflags = -1;
static gint ett_mgmt = -1;


#define USB_DT_EP_SIZE              7
#define USB_DT_SS_EP_COMP_SIZE      6
#define USB_DT_ISO_SSP_EP_COMP_SIZE 8

/* Size of EPHandleReq Descriptors */
#define MAUSB_EP_DES_SIZE 8
#define MAUSB_SS_EP_DES_SIZE 16
#define MAUSB_ISO_SSP_EP_DES_SIZE 24

/* EPHandleReq Descriptor Padding */
#define MAUSB_EP_DES_PAD         (MAUSB_EP_DES_SIZE - USB_DT_EP_SIZE)

#define MAUSB_SS_EP_DES_PAD      (MAUSB_SS_EP_DES_SIZE - \
        (USB_DT_EP_SIZE + USB_DT_SS_EP_COMP_SIZE))

#define MAUSB_ISO_SSP_EP_DES_PAD (MAUSB_ISO_SSP_EP_DES_SIZE - \
        (USB_DT_EP_SIZE + USB_DT_SS_EP_COMP_SIZE + USB_DT_ISO_SSP_EP_COMP_SIZE))


/* Size of EPHandleResp Descriptor */
#define MAUSB_SIZE_MAUSB_EP_DES 16


/* Size of EPHandleResp Descriptor */
#define MAUSB_SIZE_EP_HANDLE 2


/* Dissects a MAUSB endpoint handle */
static gint dissect_ep_handle(proto_tree *tree, tvbuff_t *tvb, gint offset)
{

    proto_item *ti;
    proto_tree *ep_handle_tree;

    ti = proto_tree_add_item(tree, hf_mausb_ep_handle, tvb,
        offset, MAUSB_SIZE_EP_HANDLE, ENC_LITTLE_ENDIAN);

    ep_handle_tree = proto_item_add_subtree(ti, ett_mausb_ep_handle);
    proto_tree_add_item(ep_handle_tree, hf_mausb_ep_handle_d, tvb,
        offset, MAUSB_SIZE_EP_HANDLE, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ep_handle_tree, hf_mausb_ep_handle_ep_num, tvb,
        offset, MAUSB_SIZE_EP_HANDLE, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ep_handle_tree, hf_mausb_ep_handle_dev_addr, tvb,
        offset, MAUSB_SIZE_EP_HANDLE, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ep_handle_tree, hf_mausb_ep_handle_bus_num, tvb,
        offset, MAUSB_SIZE_EP_HANDLE, ENC_LITTLE_ENDIAN);

    return MAUSB_SIZE_EP_HANDLE;

}


/* gets the size of the endpoint descriptors in a EPHandleReq packet */
static guint8 mausb_get_size_ep_des(tvbuff_t *tvb, gint offset)
{
    guint8 size_ep_des = 0;
    guint16 temp_buffer = 0; /* for storing the offset data */

    /* grab the 2 bytes with the size field */
    temp_buffer = tvb_get_letohs(tvb, offset);

    /* mask & shift the size field */
    temp_buffer = temp_buffer & MAUSB_MGMT_SIZE_EP_DES_MASK;
    size_ep_des = (temp_buffer >> MAUSB_MGMT_SIZE_EP_DES_OFFSET);

    return size_ep_des;
}

/* dissects portions of a MA USB packet specific to Endpoint Handle Request packets */
static guint16 dissect_mausb_mgmt_pkt_ep_handle( proto_tree *tree, tvbuff_t *tvb,
            packet_info *pinfo, gint16 start, gboolean req, gboolean del)
{
    usb_trans_info_t usb_trans_info;
    usb_conv_info_t usb_conv_info;
    proto_item *size_field = NULL;
    guint16 offset = start;
    guint16 loop_offset;
    guint8 num_ep;
    guint8 size_ep_des;
    int i;

    memset(&usb_trans_info, 0, sizeof(usb_trans_info_t));
    memset(&usb_conv_info,  0, sizeof(usb_conv_info_t));

    num_ep = tvb_get_guint8(tvb, offset) & MAUSB_MGMT_NUM_EP_DES_MASK;

    if (!del) {
        proto_tree_add_item(tree, hf_mausb_mgmt_ep_des_num, tvb,
            offset, 1, ENC_LITTLE_ENDIAN); /* really 5 bits */
    } else {
        proto_tree_add_item(tree, hf_mausb_mgmt_ep_handle_num, tvb,
            offset, 1, ENC_LITTLE_ENDIAN); /* really 5 bits */
    }

     if (req && !del) {

        size_ep_des = mausb_get_size_ep_des(tvb, offset);
        size_field = proto_tree_add_item(tree, hf_mausb_mgmt_ep_des_size, tvb,
            offset, 2, ENC_LITTLE_ENDIAN); /* really 6 bits over a byte boundry */
        offset += 1;

        /* Padding to DWORD */
        proto_tree_add_item(tree, hf_mausb_mgmt_ep_des_pad, tvb,
            offset, 3, ENC_NA);
        offset += 3;

    } else if (!req && !del) {
        size_ep_des = MAUSB_SIZE_MAUSB_EP_DES;
        proto_tree_add_item(tree, hf_mausb_mgmt_ep_handle_pad, tvb,
            offset, 4, ENC_NA); /* really 5 bits */
        /* Padding to DWORD */
        offset += 4;

    } else { /* If it is an EPHandleDelete Req or Resp */
        size_ep_des = MAUSB_SIZE_EP_HANDLE;
        /* Padding to DWORD */
        proto_tree_add_item(tree, hf_mausb_mgmt_ep_handle_pad, tvb,
            offset, 4, ENC_NA);
        offset += 4; /* Padding to DWORD */

    }

    /* For every entry */
    for (i = 0; i < num_ep; ++i) {
        loop_offset = offset;

        /* If it is an EPHandleDelete Req or Resp */
        if (del) {
            loop_offset += dissect_ep_handle(tree, tvb, loop_offset);

        } else if (req && !del) {

            /* Standard USB Endpoint Descriptor */
            dissect_usb_endpoint_descriptor(pinfo, tree, tvb, loop_offset,
                    &usb_trans_info, &usb_conv_info);
            loop_offset += USB_DT_EP_SIZE;

            /* If there are more descriptors to read */
            if (MAUSB_EP_DES_SIZE < size_ep_des) {
                /* TODO: Dissector for SS EP Companion Descriptors */
                dissect_usb_unknown_descriptor(pinfo, tree,
                        tvb, loop_offset, &usb_trans_info, &usb_conv_info);
                loop_offset += USB_DT_SS_EP_COMP_SIZE;

                if (MAUSB_SS_EP_DES_SIZE < size_ep_des) {
                    /* TODO: Dissector for SSP ISO EP Companion Descriptors */
                    loop_offset += dissect_usb_unknown_descriptor(pinfo, tree,
                            tvb, loop_offset, &usb_trans_info, &usb_conv_info);

                    /* Pad to a DWORD */
                    proto_tree_add_item(tree, hf_mausb_ep_handle_req_pad, tvb,
                        loop_offset, MAUSB_ISO_SSP_EP_DES_PAD, ENC_NA);
                    loop_offset += MAUSB_ISO_SSP_EP_DES_PAD;

                } else {
                    /* Pad to a DWORD */
                    proto_tree_add_item(tree, hf_mausb_ep_handle_req_pad, tvb,
                        loop_offset, MAUSB_SS_EP_DES_PAD, ENC_NA);
                    loop_offset += MAUSB_SS_EP_DES_PAD;
                }

            } else {
                /* Pad to a DWORD */
                proto_tree_add_item(tree, hf_mausb_ep_handle_req_pad, tvb,
                    loop_offset, MAUSB_EP_DES_PAD, ENC_NA);
                loop_offset += MAUSB_EP_DES_PAD;
            }

        } else { /* IE: it's a EPHandleResp */
            /* EP Handle */
            loop_offset += dissect_ep_handle(tree, tvb, loop_offset);

            /* direction */
            proto_tree_add_item(tree, hf_mausb_ep_handle_resp_dir, tvb,
                loop_offset, 1, ENC_LITTLE_ENDIAN);

            /* isochronous */
            proto_tree_add_item(tree, hf_mausb_ep_handle_resp_iso, tvb,
                loop_offset, 1, ENC_LITTLE_ENDIAN);

            /* L-managed transfers */
            proto_tree_add_item(tree, hf_mausb_ep_handle_resp_lman, tvb,
                loop_offset, 1, ENC_LITTLE_ENDIAN);

            /* valid handle bit */
            proto_tree_add_item(tree, hf_mausb_ep_handle_resp_valid, tvb,
                loop_offset, 1, ENC_LITTLE_ENDIAN);
            loop_offset += 2; /* 4 bit flags + 12 reserved bits */

            /* credit consumption unit */
            proto_tree_add_item(tree, hf_mausb_ep_handle_resp_ccu, tvb,
                loop_offset, 2, ENC_LITTLE_ENDIAN);
            loop_offset += 2;

            loop_offset += 2; /* 2 bytes reserved */

            /* buffer size (in bytes) */
            proto_tree_add_item(tree, hf_mausb_ep_handle_resp_buf_size, tvb,
                loop_offset, 4, ENC_LITTLE_ENDIAN);
            loop_offset += 4;


            /* max iso programming delay (in uSec) */
            proto_tree_add_item(tree, hf_mausb_ep_handle_resp_iso_prog_dly, tvb,
                loop_offset, 2, ENC_LITTLE_ENDIAN);
            loop_offset += 2;

            /* max iso response delay (in uSec) */
            proto_tree_add_item(tree, hf_mausb_ep_handle_resp_iso_resp_dly, tvb,
                loop_offset, 2, ENC_LITTLE_ENDIAN);
            loop_offset += 2;
        }


        offset += size_ep_des;

        if (req && !del && loop_offset != offset){
            expert_add_info(pinfo, size_field, &ei_ep_handle_len);
        }

    }

    return offset;

}

/* dissects portions of a MA USB packet specific to particaular management packets */
static guint16 dissect_mausb_mgmt_pkt_flds(struct mausb_header *header,
        proto_tree *tree, tvbuff_t *tvb,
        packet_info *pinfo, gint16 start)
{

    proto_item *ti;
    proto_tree *mgmt_tree;
    guint16 offset = start;
    gint type_spec_len = tvb_reported_length(tvb) - start;

    if (0 > type_spec_len) {
        expert_add_info(pinfo, tree, &ei_mgmt_type_spec_len_short);
        return offset;
    }

    ti = proto_tree_add_item(tree, hf_mausb_mgmt_type_spec, tvb,
                             offset, type_spec_len, ENC_NA);

    mgmt_tree = proto_item_add_subtree(ti, ett_mgmt);

    switch (header->type) {

    /* subtypes with variable length additional data */
    case EPHandleReq:
        offset = dissect_mausb_mgmt_pkt_ep_handle(mgmt_tree, tvb, pinfo,
                                                  offset, TRUE, FALSE);
    break;

    case EPHandleResp:
        offset = dissect_mausb_mgmt_pkt_ep_handle(mgmt_tree, tvb, pinfo,
                                                  offset, FALSE, FALSE);
    break;

    /* TODO: Dissect type-specific managment packet fields */
    case EPActivateReq:
    case EPActivateResp:
    case EPInactivateReq:
    case EPInactivateResp:
    case EPRestartReq:
    case EPRestartResp:
    case EPClearTransferReq:
    case EPClearTransferResp:
    case EPHandleDeleteReq:
        offset = dissect_mausb_mgmt_pkt_ep_handle(mgmt_tree, tvb, pinfo,
                                                  offset, TRUE, TRUE);
    break;
    case EPHandleDeleteResp:
        offset = dissect_mausb_mgmt_pkt_ep_handle(mgmt_tree, tvb, pinfo,
                                                  offset, FALSE, TRUE);
    break;
    case ModifyEP0Resp:
    case EPCloseStreamResp:
    case USBDevResetReq:
    case USBDevResetResp:
    case EPOpenStreamResp:
    case VendorSpecificReq:
    case VendorSpecificResp:
        /* FALLTHROUGH */

    /* subtypes with constant length additional data */
    case CapReq:
    case CapResp:
    case USBDevHandleReq:
    case USBDevHandleResp:
    case ModifyEP0Req:
    case SetDevAddrReq:
    case SetDevAddrResp:
    case UpdateDevReq:
    case MAUSBSyncReq:
    case EPCloseStreamReq:
    case CancelTransferReq:
    case CancelTransferResp:
    case EPOpenStreamReq:

        proto_tree_add_item(mgmt_tree, hf_mausb_mgmt_type_spec_generic,
                            tvb, offset, type_spec_len, ENC_NA);
        offset += type_spec_len;
        break;


    /* Managment packets with no additional data */
    case MAUSBDevResetReq:
    case MAUSBDevResetResp:
    case UpdateDevResp:
    case DisconnectDevReq:
    case DisconnectDevResp:
    case MAUSBDevSleepReq:
    case MAUSBDevSleepResp:
    case MAUSBDevWakeReq:
    case MAUSBDevWakeResp:
    case MAUSBDevInitSleepReq:
    case MAUSBDevInitSleepResp:
    case MAUSBDevRemoteWakeReq:
    case MAUSBDevRemoteWakeResp:
    case PingReq:
    case PingResp:
    case MAUSBDevDisconnectReq:
    case MAUSBDevDisconnectResp:
    case MAUSBDevInitDisconReq:
    case MAUSBDevInitDisconResp:
    case MAUSBSyncResp:
    break;

    default:
        expert_add_info(pinfo, mgmt_tree, &ei_mgmt_type_undef);
    break;

    }


    if (offset < tvb_reported_length(tvb)) {
        expert_add_info(pinfo, mgmt_tree, &ei_mgmt_type_spec_len_long);
    }

    return offset;
}

static conversation_t
*get_mausb_conversation(packet_info *pinfo, guint16 handle,
                        gboolean is_data, gboolean req)
{
    conversation_t *conversation = NULL;
    static usb_address_t  src_addr, dst_addr; /* has to be static due to SET_ADDRESS */
    guint16 device_address;
    int endpoint;

    /* Treat data packets the same as URBs */
    if (is_data) {
        device_address = mausb_ep_handle_dev_addr(handle);
        endpoint = mausb_ep_handle_ep_num(handle);

        usb_set_addr(pinfo, &src_addr, &dst_addr, device_address, endpoint,
                     req);
        conversation = get_usb_conversation(pinfo, &pinfo->src, &pinfo->dst,
                                            pinfo->srcport, pinfo->destport);
    }
    /* TODO: track control & managment packet conversations */

    return conversation;
}

/* Used to detect multiple MA Packets in a single TCP packet */
/* Not used for MA Packets in SNAP Packets */
static gint mausb_num_pdus = 0;

/* Code to actually dissect the packets */
static int
dissect_mausb_pkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_item *len_field;
    proto_tree *mausb_tree;
    proto_tree *flags_tree;
    proto_tree *tflags_tree;
    proto_tree *setup_tree;
    /* Other misc. local variables. */
    struct mausb_header header;
    gint offset = 0;
    gint payload_len;

    /* Variables needed to follow the conversation */
    usb_conv_info_t      *usb_conv_info = NULL;
    usb_trans_info_t     *usb_trans_info = NULL;
    conversation_t       *conversation;


    memset(&header, 0, sizeof(struct mausb_header));

    /* Set the Protocol column to the constant string of mausb */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAUSB");

    mausb_num_pdus++;

    col_add_str(pinfo->cinfo, COL_INFO, "[");
    col_set_fence(pinfo->cinfo, COL_INFO);

    /*** PROTOCOL TREE ***/

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_mausb, tvb, 0,
                mausb_get_pkt_len(pinfo, tvb, offset), ENC_NA);

    mausb_tree = proto_item_add_subtree(ti, ett_mausb);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */

    /* MAUSB Protocol Version */
    header.ver_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mausb_tree, hf_mausb_version, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);

    /* Flags */
    ti = proto_tree_add_item(mausb_tree, hf_mausb_flags, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);

    flags_tree = proto_item_add_subtree(ti, ett_mausb_flags);
        proto_tree_add_item(flags_tree, hf_mausb_flag_host, tvb,
             offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(flags_tree, hf_mausb_flag_retry, tvb,
             offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(flags_tree, hf_mausb_flag_timestamp, tvb,
             offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(flags_tree, hf_mausb_flag_reserved, tvb,
             offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Packet Type */
    header.type = tvb_get_guint8(tvb, offset);
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(header.type, mausb_type_string, "%d"));
    proto_tree_add_item(mausb_tree, hf_mausb_type, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Packet Length */
    header.length = tvb_get_letohs(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Length=%u", header.length);
    len_field = proto_tree_add_item(mausb_tree, hf_mausb_length, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Check to see if length field is valid */
    if (tvb_reported_length(tvb) != header.length) {
        expert_add_info(pinfo, len_field, &ei_len);
    }


    /* Is the next field a device handle or an endpoint handle */
    header.handle = tvb_get_letohs(tvb, offset);

    /* Once we have the endpoint/device handle,
     * we can find the right conversation */
    conversation = get_mausb_conversation(pinfo, header.handle,
                                          mausb_is_data_pkt(&header),
                                          mausb_is_from_host(&header));

    /* If there is a usb conversation, find it */
    if (mausb_is_data_pkt(&header)) {

        usb_conv_info = get_usb_conv_info(conversation);

        /* TODO: set all the usb_conv_info values */
        usb_conv_info->is_request = mausb_is_transfer_req(&header);

        usb_trans_info = usb_get_trans_info(tvb, pinfo, tree, 0, usb_conv_info);
        usb_conv_info->usb_trans_info = usb_trans_info;
    }


    if (mausb_is_mgmt_pkt(&header)) {

        proto_tree_add_item(mausb_tree, hf_mausb_dev_handle, tvb,
              offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

    } else {
        offset += dissect_ep_handle(mausb_tree, tvb, offset);

    }

    /* MA Device Address */
    header.ma_dev_addr = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mausb_tree, hf_mausb_ma_dev_addr, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* SSID */
    header.mass_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mausb_tree, hf_mausb_ssid, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Status */
    header.status = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mausb_tree, hf_mausb_status, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    if (mausb_is_mgmt_pkt(&header)) {

        /* Dialog Token */
        header.u.token = tvb_get_letohs(tvb, 9) & MAUSB_TOKEN_MASK;
        col_append_fstr(pinfo->cinfo, COL_INFO, " Token=%u", header.u.token);
        proto_tree_add_item(mausb_tree, hf_mausb_token, tvb,
            offset, 2, ENC_LITTLE_ENDIAN); /* Really 10 bits */
        offset += 1; /* token */

        /* Padding to a DWORD */
        proto_tree_add_item(mausb_tree, hf_mausb_mgmt_pad, tvb,
            offset, 2, ENC_LITTLE_ENDIAN); /* Really 14 bits */

        offset += 2; /* DWORD*/

        /* Dissect additional management fields (when applicable) */
        if (offset < header.length) {

            offset = dissect_mausb_mgmt_pkt_flds(&header, mausb_tree, tvb,
                        pinfo, offset);
        }


    }
    else if (mausb_is_data_pkt(&header)) {
        /* TODO: Isochronous Packet Fields */

        /* EPS */
        header.u.s.eps_tflags = tvb_get_guint8(tvb, offset);
        if (mausb_is_from_host(&header)) {
            proto_tree_add_item(mausb_tree, hf_mausb_eps_rsvd, tvb,
                offset, 1, ENC_LITTLE_ENDIAN);
        } else {
            proto_tree_add_item(mausb_tree, hf_mausb_eps, tvb,
                offset, 1, ENC_LITTLE_ENDIAN);
        }


        /* T-Flags */
        ti = proto_tree_add_item(mausb_tree, hf_mausb_tflags, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);

        tflags_tree = proto_item_add_subtree(ti, ett_mausb_tflags);
            proto_tree_add_item(tflags_tree, hf_mausb_tflag_arq, tvb,
                offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tflags_tree, hf_mausb_tflag_neg, tvb,
                offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tflags_tree, hf_mausb_tflag_eot, tvb,
                offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tflags_tree, hf_mausb_tflag_type, tvb,
                offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tflags_tree, hf_mausb_tflag_rsvd, tvb,
                offset, 1, ENC_LITTLE_ENDIAN);

        offset += 1;

        /* Stream ID (non-iso) */
        header.u.s.stream_id = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(mausb_tree, hf_mausb_stream_id, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* Number of Headers (iso) */
        /* I-Flags (iso) */

        /* Sequence Number */
        header.u.s.seq_num = tvb_get_letoh24(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " SeqNum=%u", header.u.s.seq_num);
        proto_tree_add_item(mausb_tree, hf_mausb_seq_num, tvb,
            offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        /* Request ID */
        header.u.s.req_id = tvb_get_guint8(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " ReqID=%u", header.u.s.req_id);
        proto_tree_add_item(mausb_tree, hf_mausb_req_id, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        /* Remaining Size/Credit (non-iso) */
        header.u.s.credit = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(mausb_tree, hf_mausb_rem_size_credit, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* Presentation Time (iso) */
        /* Number of Segments (iso) */

        /* If this packet contains USB Setup Data */
        if (mausb_has_setup_data(&header)) {
            offset = dissect_usb_setup_request(pinfo, mausb_tree, tvb, offset,
                                               usb_conv_info, &setup_tree);
        }

        /*
         * TODO: dissect MA USB Payload with USB class dissectors
         *       (ex: MBIM, USB Audio, etc.)
         */

        /* Everything after the header is payload */
        payload_len = header.length - offset;

        if (0 < payload_len) {
            proto_tree_add_item(mausb_tree, hf_mausb_payload, tvb,
                offset, payload_len, ENC_NA);
            offset += payload_len;
        }
    }

    col_append_str(pinfo->cinfo, COL_INFO, "]");
    col_set_fence(pinfo->cinfo, COL_INFO);

    return offset;

}

/* Code to dissect the stream */
static int
dissect_mausb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    mausb_num_pdus = 0;

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MAUSB_MIN_LENGTH,
            mausb_get_pkt_len, dissect_mausb_pkt, data);

    if (1 < mausb_num_pdus) {
        col_clear_fence(pinfo->cinfo, COL_INFO);
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "[%i packets] ", mausb_num_pdus);
    }

    return tvb_reported_length(tvb);
}


/* Register the protocol with Wireshark.
 */
void
proto_register_mausb(void)
{

    static hf_register_info hf[] = {
        { &hf_mausb_version,
            { "Version", "mausb.version", FT_UINT8, BASE_DEC,
              VALS(mausb_version_string), MAUSB_VERSION_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_flags,
            { "Flags", "mausb.flags", FT_UINT8, BASE_HEX,
              VALS(mausb_flag_string), MAUSB_FLAG_MASK, NULL, HFILL
            }
        },

        /* Flag Subfields */
        { &hf_mausb_flag_host,
            { "Host", "mausb.flags.host", FT_BOOLEAN, 4,
              TFS(&tfs_set_notset), MAUSB_FLAG_HOST,
              NULL, HFILL
            }
        },
        { &hf_mausb_flag_retry,
            { "Retry", "mausb.flags.retry", FT_BOOLEAN, 4,
              TFS(&tfs_yes_no), MAUSB_FLAG_RETRY,
              NULL, HFILL
            }
        },
        { &hf_mausb_flag_timestamp,
            { "Timestamp", "mausb.flags.timestamp", FT_BOOLEAN, 4,
              TFS(&tfs_present_not_present),
              MAUSB_FLAG_TIMESTAMP,
              NULL, HFILL
            }
        },
        { &hf_mausb_flag_reserved,
            { "Reserved", "mausb.flags.reserved", FT_BOOLEAN, 4,
              TFS(&tfs_set_notset), MAUSB_FLAG_RESERVED,
              NULL, HFILL
            }
        },


        { &hf_mausb_type,
            { "Type", "mausb.type", FT_UINT8, BASE_HEX,
              VALS(mausb_type_string), 0, NULL, HFILL
            }
        },
        { &hf_mausb_length,
            { "Length", "mausb.length", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_dev_handle,
            { "Device Handle", "mausb.dev_handle", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle,
            { "Endpoint Handle", "mausb.ep_handle", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL
            }
        },

        /* EP Handle Subfields */
        { &hf_mausb_ep_handle_d,
            { "Direction", "mausb.ep_handle.d", FT_BOOLEAN, 16,
              TFS(&tfs_set_notset), MAUSB_EP_HANDLE_D, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_ep_num,
            { "Endpoint Number", "mausb.ep_handle.ep_num", FT_UINT16, BASE_DEC,
              NULL, MAUSB_EP_HANDLE_EP_NUM, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_dev_addr,
            { "USB Device Address", "mausb.ep_handle.dev_addr", FT_UINT16, BASE_DEC,
              NULL, MAUSB_EP_HANDLE_DEV_ADDR, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_bus_num,
            { "USB Bus Number", "mausb.ep_handle.bus_num", FT_UINT16, BASE_DEC,
              NULL, MAUSB_EP_HANDLE_BUS_NUM, NULL, HFILL
            }
        },


        { &hf_mausb_ma_dev_addr,
            { "MA Device Address", "mausb.ma_dev_addr", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_ssid,
            { "Service Set ID", "mausb.ssid", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_status,
            { "Status", "mausb.status", FT_UINT8, BASE_DEC,
              VALS(mausb_status_string), 0, NULL, HFILL
            }
        },

        /* Managment Packets Only */
        { &hf_mausb_token,
            { "Token", "mausb.token", FT_UINT16, BASE_DEC,
              NULL, MAUSB_TOKEN_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_mgmt_pad,
            { "Padding to a DWORD", "mausb.mgmt_pad",
              FT_UINT16, BASE_HEX, NULL, MAUSB_MGMT_PAD_MASK,
              NULL, HFILL
            }
        },
        { &hf_mausb_mgmt_type_spec,
            { "Type-specific managment packet fields", "mausb.mgmt_flds",
              FT_NONE, 0, NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_mgmt_type_spec_generic,
            { "Type-specific managment packet fields", "mausb.mgmt_flds.generic",
              FT_NONE, 0, NULL, 0, NULL, HFILL
            }
        },

        /* Data Packets Only */
        { &hf_mausb_eps,
            { "EP Status", "mausb.eps", FT_UINT8, BASE_HEX,
              VALS(mausb_eps_string), MAUSB_EPS_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_eps_rsvd,
            { "EP Status", "mausb.eps.reserved", FT_UINT8, BASE_HEX,
              NULL, MAUSB_EPS_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_tflags,
            { "Transfer Flags", "mausb.tflag", FT_UINT8, BASE_HEX,
              VALS(mausb_tflag_string), MAUSB_TFLAG_MASK, NULL, HFILL
            }
        },

        /* T-Flag Subfields */
        { &hf_mausb_tflag_arq,
            { "ARQ", "mausb.tflag.arq", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), MAUSB_TFLAG_ARQ << MAUSB_TFLAG_OFFSET,
              NULL, HFILL
            }
        },
        { &hf_mausb_tflag_neg,
            { "NEG", "mausb.tflag.neg", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), MAUSB_TFLAG_NEG << MAUSB_TFLAG_OFFSET,
              NULL, HFILL
            }
        },
        { &hf_mausb_tflag_eot,
            { "EoT", "mausb.tflag.eot", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), MAUSB_TFLAG_EOT << MAUSB_TFLAG_OFFSET,
              NULL, HFILL
            }
        },
        { &hf_mausb_tflag_type,
            { "Transfer Type", "mausb.tflag.type", FT_UINT8, BASE_HEX,
              VALS(mausb_transfer_type_string),
              MAUSB_TFLAG_TRANSFER_TYPE << MAUSB_TFLAG_OFFSET,
              NULL, HFILL
            }
        },
        { &hf_mausb_tflag_rsvd,
            { "Reserved", "mausb.tflag.rsvd", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), MAUSB_TFLAG_RSVD << MAUSB_TFLAG_OFFSET,
              NULL, HFILL
            }
        },


        { &hf_mausb_stream_id,
            { "Stream ID", "mausb.streamid", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_seq_num,
            { "Sequence Number", "mausb.seqnum", FT_UINT24, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_req_id,
            { "Request ID", "mausb.reqid", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_rem_size_credit,
            { "Remaining Size/Credit", "mausb.remsize_credit", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_payload,
            { "USB Data Payload", "mausb.payload", FT_NONE, 0,
              NULL, 0, NULL, HFILL
            }
        }
    };


    /* register info for ep_handle_* specific fields */
    static hf_register_info hf_ep_handle[] = {
        { &hf_mausb_mgmt_ep_handle_num,
            { "Number of Endpoint Handles", "mausb.ep_handle_num",
              FT_UINT8, BASE_DEC,
              NULL, MAUSB_MGMT_NUM_EP_DES_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_mgmt_ep_handle_pad,
            { "Padding to a DWORD", "mausb.ep_handle_pad",
              FT_NONE, 0,
              NULL, MAUSB_MGMT_NUM_EP_HANDLE_PAD_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_mgmt_ep_des_num,
            { "Number of Endpoint Descriptors", "mausb.ep_des_num",
              FT_UINT8, BASE_DEC,
              NULL, MAUSB_MGMT_NUM_EP_DES_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_mgmt_ep_des_size,
            { "Size of Endpoint Descriptors", "mausb.ep_des_size",
              FT_UINT16, BASE_DEC,
              NULL, MAUSB_MGMT_SIZE_EP_DES_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_mgmt_ep_des_pad,
            { "Padding to a DWORD", "mausb.ep_des_pad",
              FT_NONE, 0, NULL,
              MAUSB_MGMT_EP_DES_PAD_MASK,
              NULL, HFILL
            }
        },

        { &hf_mausb_ep_handle_req_pad,
            { "Padding to a DWORD", "mausb.ep_handle_req.pad",
              FT_NONE, 0, NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_resp_dir,
            { "Direction", "mausb.ep_dir", FT_BOOLEAN, 6,
              TFS(&tfs_ep_handle_resp_dir), MAUSB_EP_HANDLE_RESP_DIR_MASK,
              NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_resp_iso,
            { "Isochronous", "mausb.ep_iso", FT_BOOLEAN, 6,
              TFS(&tfs_yes_no), MAUSB_EP_HANDLE_RESP_ISO_MASK, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_resp_lman,
            { "L-Managed", "mausb.ep_lman", FT_BOOLEAN, 6,
              TFS(&tfs_supported_not_supported), MAUSB_EP_HANDLE_RESP_LMAN_MASK,
              NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_resp_valid,
            { "Valid", "mausb.ep_valid", FT_BOOLEAN, 6,
              TFS(&tfs_invalid_valid), MAUSB_EP_HANDLE_RESP_VALID_MASK,
              NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_resp_ccu,
            { "CCU", "mausb.ep_ccu", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_resp_buf_size,
            { "Buffer Size", "mausb.ep_buf_size", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_resp_iso_prog_dly,
            { "Iso Programming Delay", "mausb.ep_iso_prog_dly", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        },
        { &hf_mausb_ep_handle_resp_iso_resp_dly,
            { "Iso Response Delay", "mausb.ep_iso_resp_dly", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL
            }
        }


    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mausb,
        &ett_mausb_flags,
        &ett_mausb_ep_handle,
        &ett_mausb_tflags,
        &ett_mgmt
    };

    static ei_register_info ei[] = {
        { &ei_ep_handle_len,
            { "mausb.ep_handle.length", PI_PROTOCOL, PI_WARN,
              "Invalid Endpoint handle length field", EXPFILL }
        },
        { &ei_len,
            { "mausb.length", PI_MALFORMED, PI_ERROR,
              "Packet length field does not match size of packet", EXPFILL }
        },
        { &ei_mgmt_type_undef,
            { "mausb.type", PI_PROTOCOL, PI_WARN,
              "Undefined managment packet type", EXPFILL }
        },
        { &ei_mgmt_type_spec_len_long,
            { "mausb.type_spec.len", PI_PROTOCOL, PI_WARN,
              "Data exists after type-specific managment packet field", EXPFILL }
        },
        { &ei_mgmt_type_spec_len_short,
            { "mausb.type_spec.len", PI_PROTOCOL, PI_WARN,
              "Expected type-specific managment packet data", EXPFILL }
        },
    };

    module_t *mausb_module;
    expert_module_t* expert_mausb;

    /* Register the protocol name and description */
    proto_mausb = proto_register_protocol("Media Agnostic USB",
            "MAUSB", "mausb");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_mausb, hf, array_length(hf));
    proto_register_field_array(proto_mausb, hf_ep_handle, array_length(hf_ep_handle));
    proto_register_subtree_array(ett, array_length(ett));

    /* for Expert info */
    expert_mausb = expert_register_protocol(proto_mausb);
    expert_register_field_array(expert_mausb, ei, array_length(ei));

    /* Register Protocol preferences */
    mausb_module = prefs_register_protocol(proto_mausb, proto_reg_handoff_mausb);

    /* Register TCP port preference */
    prefs_register_uint_preference(mausb_module, "tcp.port", "MAUSB TCP Port",
                       "Set the port for Media Agnostic Packets",
                       10, &gPORT_PREF);

}

void
proto_reg_handoff_mausb(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t mausb_tcp_handle;
    static dissector_handle_t mausb_snap_handle;

    if (!initialized) {
        /* only initialize once */
        mausb_tcp_handle = new_create_dissector_handle(dissect_mausb,
                proto_mausb);

        mausb_snap_handle = new_create_dissector_handle(dissect_mausb_pkt,
                proto_mausb);

        initialized = TRUE;

    } else {
        /* if we have already been initialized */
        dissector_delete_uint("tcp.port", gPORT_PREF, mausb_tcp_handle);
    }

    dissector_add_uint("llc.mausb_pid", PID_MAUSB, mausb_snap_handle);
    dissector_add_uint("tcp.port", gPORT_PREF, mausb_tcp_handle);
}

void
proto_register_mausb_oui(void)
{
    static hf_register_info hf[] = {
      { &hf_llc_mausb_pid,
        { "PID",    "mausb.pid",  FT_UINT16, BASE_HEX,
          VALS(mausb_pid_string), 0x0, NULL, HFILL }
      }
    };

    llc_add_oui(OUI_MAUSB, "llc.mausb_pid", "LLC MA USB OUI PID", hf);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
