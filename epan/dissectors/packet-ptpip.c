/* packet-ptpip.c
 * Routines for PTP/IP (Picture Transfer Protocol) packet dissection
 * 0xBismarck 2013
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * References:
 * [1] CIPA DC-X005-2005 - PTP-IP
 * [2] BS ISO 15740:2008 - Photography Electronic still picture imaging - Picture transfer protocol (PTP)
 * for digital still photography devices
 * [3] gPhoto's Reversed Engineered PTP/IP documentation - http://gphoto.sourceforge.net/doc/ptpip.php
 * [4] gPhoto's ptp2 header file  https://gphoto.svn.sourceforge.net/svnroot/gphoto/trunk/libgphoto2/camlibs/ptp2/ptp.h
 *
 * @todo: This is being written as 1 dissector when in reality there is PTP/IP and PTP.
 *        Future work should include splitting this into 2 so that the PTP layer may be used again for PTP/USB.
 */
#include "config.h"
#include <glib.h>
#include <epan/packet.h>
#include "packet-ptpip.h"

/* Define */
#define PTPIP_PORT            15740  /* [1] Section 2.2.3.1 */
#define PTPIP_GUID_SIZE          16  /* [1] Section 2.3.1 */
#define PTPIP_MAX_PARAM_COUNT     5  /* [1] Section 2.3.6 */

/* trees */
static gint ett_ptpIP =  -1;
static gint ett_ptpIP_hdr = -1;

/* PTP/IP Fields */
static int proto_ptpIP = -1;
static int hf_ptpIP_len = -1; /* [1] Section 2.3 */
static int hf_ptpIP_pktType = -1; /* [1] Section 2.3 */
static int hf_ptpIP_guid = -1;
static int hf_ptpIP_name = -1;
static int hf_ptpIP_version = -1;
static int hf_ptpIP_connectionNumber = -1;
static int hf_ptpIP_dataPhaseInfo = -1;

/* note: separating the fields to make it easier to divide this code later. */

/* PTP Fields */
/* picking hf_ptp for now. Might need to change later for namespace issues with Precision Time Protocol. */
static int hf_ptp_opCode = -1;
static int hf_ptp_respCode = -1;
static int hf_ptp_eventCode = -1;
static int hf_ptp_transactionID = -1;
static int hf_ptp_totalDataLength = -1;
static int hf_ptp_opCode_param_sessionID = -1;

/* function declarations */
static int dissect_ptpIP (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
void dissect_ptpIP_init_command_request (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_init_command_ack     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_init_event_request   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_init_event_ack       (               packet_info *pinfo);
void dissect_ptpIP_operation_request    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_operation_response   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_start_data           (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_data                 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_end_data             (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_event                (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_unicode_name         (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptpIP_protocol_version     (tvbuff_t *tvb,                     proto_tree *tree, guint16 *offset);
void dissect_ptpIP_guid                 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void proto_register_ptpip( void );
void proto_reg_handoff_ptpIP( void );

/* XXX: There are a number of duplicate values in the following which
        will never be found (obviously) via a linear search. (see enum
        in packet-ptpip.h). */
/* ToDo: FIXME & then create/use extended value_string */
static const value_string ptp_opcode_names[] = {
    { PTP_OC_GetDeviceInfo,                             "GetDeviceInfo" },
    { PTP_OC_OpenSession,                               "OpenSession" },
    { PTP_OC_CloseSession,                              "CloseSession" },
    { PTP_OC_GetStorageIDs,                             "GetStorageIDs" },
    { PTP_OC_GetStorageInfo,                            "GetStorageInfo" },
    { PTP_OC_GetNumObjects,                             "GetNumObjects" },
    { PTP_OC_GetObjectHandles,                          "GetObjectHandles" },
    { PTP_OC_GetObjectInfo,                             "GetObjectInfo" },
    { PTP_OC_GetObject,                                 "GetObject" },
    { PTP_OC_DeleteObject,                              "DeleteObject" },
    { PTP_OC_SendObjectInfo,                            "SendObjectInfo" },
    { PTP_OC_SendObject,                                "SendObject" },
    { PTP_OC_InitiateCapture,                           "InitiateCapture" },
    { PTP_OC_FormatStore,                               "FormatStore" },
    { PTP_OC_ResetDevice,                               "ResetDevice" },
    { PTP_OC_SelfTest,                                  "SelfTest" },
    { PTP_OC_SetObjectProtection,                       "SetObjectProtection" },
    { PTP_OC_PowerDown,                                 "PowerDown" },
    { PTP_OC_GetDevicePropDesc,                         "GetDevicePropDesc" },
    { PTP_OC_GetDevicePropValue,                        "GetDevicePropValue" },
    { PTP_OC_SetDevicePropValue,                        "SetDevicePropValue" },
    { PTP_OC_ResetDevicePropValue,                      "ResetDevicePropValue" },
    { PTP_OC_TerminateOpenCapture,                      "TerminateOpenCapture" },
    { PTP_OC_MoveObject,                                "MoveObject" },
    { PTP_OC_CopyObject,                                "CopyObject" },
    { PTP_OC_GetPartialObject,                          "GetPartialObject" },
    { PTP_OC_InitiateOpenCapture,                       "InitiateOpenCapture" },
    { PTP_OC_StartEnumHandles,                          "StartEnumHandles" },
    { PTP_OC_EnumHandles,                               "EnumHandles" },
    { PTP_OC_StopEnumHandles,                           "StopEnumHandles" },
    { PTP_OC_GetVendorExtensionMaps,                    "GetVendorExtensionMaps" },
    { PTP_OC_GetVendorDeviceInfo,                       "GetVendorDeviceInfo" },
    { PTP_OC_GetResizedImageObject,                     "GetResizedImageObject" },
    { PTP_OC_GetFilesystemManifest,                     "GetFilesystemManifest" },
    { PTP_OC_GetStreamInfo,                             "GetStreamInfo" },
    { PTP_OC_GetStream,                                 "GetStream" },
    { PTP_OC_EK_GetSerial,                              "EK_GetSerial" },
    { PTP_OC_EK_SetSerial,                              "EK_SetSerial" },
    { PTP_OC_EK_SendFileObjectInfo,                     "EK_SendFileObjectInfo" },
    { PTP_OC_EK_SendFileObject,                         "EK_SendFileObject" },
    { PTP_OC_EK_SetText,                                "EK_SetText" },
    { PTP_OC_CANON_GetPartialObjectInfo,                "CANON_GetPartialObjectInfo" },
    { PTP_OC_CANON_SetObjectArchive,                    "CANON_SetObjectArchive" },
    { PTP_OC_CANON_KeepDeviceOn,                        "CANON_KeepDeviceOn" },
    { PTP_OC_CANON_LockDeviceUI,                        "CANON_LockDeviceUI" },
    { PTP_OC_CANON_UnlockDeviceUI,                      "CANON_UnlockDeviceUI" },
    { PTP_OC_CANON_GetObjectHandleByName,               "CANON_GetObjectHandleByName" },
    { PTP_OC_CANON_InitiateReleaseControl,              "CANON_InitiateReleaseControl" },
    { PTP_OC_CANON_TerminateReleaseControl,             "CANON_TerminateReleaseControl" },
    { PTP_OC_CANON_TerminatePlaybackMode,               "CANON_TerminatePlaybackMode" },
    { PTP_OC_CANON_ViewfinderOn,                        "CANON_ViewfinderOn" },
    { PTP_OC_CANON_ViewfinderOff,                       "CANON_ViewfinderOff" },
    { PTP_OC_CANON_DoAeAfAwb,                           "CANON_DoAeAfAwb" },
    { PTP_OC_CANON_GetCustomizeSpec,                    "CANON_GetCustomizeSpec" },
    { PTP_OC_CANON_GetCustomizeItemInfo,                "CANON_GetCustomizeItemInfo" },
    { PTP_OC_CANON_GetCustomizeData,                    "CANON_GetCustomizeData" },
    { PTP_OC_CANON_SetCustomizeData,                    "CANON_SetCustomizeData" },
    { PTP_OC_CANON_GetCaptureStatus,                    "CANON_GetCaptureStatus" },
    { PTP_OC_CANON_CheckEvent,                          "CANON_CheckEvent" },
    { PTP_OC_CANON_FocusLock,                           "CANON_FocusLock" },
    { PTP_OC_CANON_FocusUnlock,                         "CANON_FocusUnlock" },
    { PTP_OC_CANON_GetLocalReleaseParam,                "CANON_GetLocalReleaseParam" },
    { PTP_OC_CANON_SetLocalReleaseParam,                "CANON_SetLocalReleaseParam" },
    { PTP_OC_CANON_AskAboutPcEvf,                       "CANON_AskAboutPcEvf" },
    { PTP_OC_CANON_SendPartialObject,                   "CANON_SendPartialObject" },
    { PTP_OC_CANON_InitiateCaptureInMemory,             "CANON_InitiateCaptureInMemory" },
    { PTP_OC_CANON_GetPartialObjectEx,                  "CANON_GetPartialObjectEx" },
    { PTP_OC_CANON_SetObjectTime,                       "CANON_SetObjectTime" },
    { PTP_OC_CANON_GetViewfinderImage,                  "CANON_GetViewfinderImage" },
    { PTP_OC_CANON_GetObjectAttributes,                 "CANON_GetObjectAttributes" },
    { PTP_OC_CANON_ChangeUSBProtocol,                   "CANON_ChangeUSBProtocol" },
    { PTP_OC_CANON_GetChanges,                          "CANON_GetChanges" },
    { PTP_OC_CANON_GetObjectInfoEx,                     "CANON_GetObjectInfoEx" },
    { PTP_OC_CANON_InitiateDirectTransfer,              "CANON_InitiateDirectTransfer" },
    { PTP_OC_CANON_TerminateDirectTransfer,             "CANON_TerminateDirectTransfer" },
    { PTP_OC_CANON_SendObjectInfoByPath,                "CANON_SendObjectInfoByPath" },
    { PTP_OC_CANON_SendObjectByPath,                    "CANON_SendObjectByPath" },
    { PTP_OC_CANON_InitiateDirectTansferEx,             "CANON_InitiateDirectTansferEx" },
    { PTP_OC_CANON_GetAncillaryObjectHandles,           "CANON_GetAncillaryObjectHandles" },
    { PTP_OC_CANON_GetTreeInfo,                         "CANON_GetTreeInfo" },
    { PTP_OC_CANON_GetTreeSize,                         "CANON_GetTreeSize" },
    { PTP_OC_CANON_NotifyProgress,                      "CANON_NotifyProgress" },
    { PTP_OC_CANON_NotifyCancelAccepted,                "CANON_NotifyCancelAccepted" },
    { PTP_OC_CANON_902C,                                "CANON_902C" },
    { PTP_OC_CANON_SetPairingInfo,                      "CANON_SetPairingInfo" },
    { PTP_OC_CANON_GetPairingInfo,                      "CANON_GetPairingInfo" },
    { PTP_OC_CANON_DeletePairingInfo,                   "CANON_DeletePairingInfo" },
    { PTP_OC_CANON_GetMACAddress,                       "CANON_GetMACAddress" },
    { PTP_OC_CANON_SetDisplayMonitor,                   "CANON_SetDisplayMonitor" },
    { PTP_OC_CANON_PairingComplete,                     "CANON_PairingComplete" },
    { PTP_OC_CANON_GetWirelessMAXChannel,               "CANON_GetWirelessMAXChannel" },
    { PTP_OC_CANON_EOS_GetStorageIDs,                   "CANON_EOS_GetStorageIDs" },
    { PTP_OC_CANON_EOS_GetStorageInfo,                  "CANON_EOS_GetStorageInfo" },
    { PTP_OC_CANON_EOS_GetObjectInfo,                   "CANON_EOS_GetObjectInfo" },
    { PTP_OC_CANON_EOS_GetObject,                       "CANON_EOS_GetObject" },
    { PTP_OC_CANON_EOS_DeleteObject,                    "CANON_EOS_DeleteObject" },
    { PTP_OC_CANON_EOS_FormatStore,                     "CANON_EOS_FormatStore" },
    { PTP_OC_CANON_EOS_GetPartialObject,                "CANON_EOS_GetPartialObject" },
    { PTP_OC_CANON_EOS_GetDeviceInfoEx,                 "CANON_EOS_GetDeviceInfoEx" },
    { PTP_OC_CANON_EOS_GetObjectInfoEx,                 "CANON_EOS_GetObjectInfoEx" },
    { PTP_OC_CANON_EOS_GetThumbEx,                      "CANON_EOS_GetThumbEx" },
    { PTP_OC_CANON_EOS_SendPartialObject,               "CANON_EOS_SendPartialObject" },
    { PTP_OC_CANON_EOS_SetObjectAttributes,             "CANON_EOS_SetObjectAttributes" },
    { PTP_OC_CANON_EOS_GetObjectTime,                   "CANON_EOS_GetObjectTime" },
    { PTP_OC_CANON_EOS_SetObjectTime,                   "CANON_EOS_SetObjectTime" },
    { PTP_OC_CANON_EOS_RemoteRelease,                   "CANON_EOS_RemoteRelease" },
    { PTP_OC_CANON_EOS_SetDevicePropValueEx,            "CANON_EOS_SetDevicePropValueEx" },
    { PTP_OC_CANON_EOS_GetRemoteMode,                   "CANON_EOS_GetRemoteMode" },
    { PTP_OC_CANON_EOS_SetRemoteMode,                   "CANON_EOS_SetRemoteMode" },
    { PTP_OC_CANON_EOS_SetEventMode,                    "CANON_EOS_SetEventMode" },
    { PTP_OC_CANON_EOS_GetEvent,                        "CANON_EOS_GetEvent" },
    { PTP_OC_CANON_EOS_TransferComplete,                "CANON_EOS_TransferComplete" },
    { PTP_OC_CANON_EOS_CancelTransfer,                  "CANON_EOS_CancelTransfer" },
    { PTP_OC_CANON_EOS_ResetTransfer,                   "CANON_EOS_ResetTransfer" },
    { PTP_OC_CANON_EOS_PCHDDCapacity,                   "CANON_EOS_PCHDDCapacity" },
    { PTP_OC_CANON_EOS_SetUILock,                       "CANON_EOS_SetUILock" },
    { PTP_OC_CANON_EOS_ResetUILock,                     "CANON_EOS_ResetUILock" },
    { PTP_OC_CANON_EOS_KeepDeviceOn,                    "CANON_EOS_KeepDeviceOn" },
    { PTP_OC_CANON_EOS_SetNullPacketMode,               "CANON_EOS_SetNullPacketMode" },
    { PTP_OC_CANON_EOS_UpdateFirmware,                  "CANON_EOS_UpdateFirmware" },
    { PTP_OC_CANON_EOS_TransferCompleteDT,              "CANON_EOS_TransferCompleteDT" },
    { PTP_OC_CANON_EOS_CancelTransferDT,                "CANON_EOS_CancelTransferDT" },
    { PTP_OC_CANON_EOS_SetWftProfile,                   "CANON_EOS_SetWftProfile" },
    { PTP_OC_CANON_EOS_GetWftProfile,                   "CANON_EOS_GetWftProfile" },
    { PTP_OC_CANON_EOS_SetProfileToWft,                 "CANON_EOS_SetProfileToWft" },
    { PTP_OC_CANON_EOS_BulbStart,                       "CANON_EOS_BulbStart" },
    { PTP_OC_CANON_EOS_BulbEnd,                         "CANON_EOS_BulbEnd" },
    { PTP_OC_CANON_EOS_RequestDevicePropValue,          "CANON_EOS_RequestDevicePropValue" },
    { PTP_OC_CANON_EOS_RemoteReleaseOn,                 "CANON_EOS_RemoteReleaseOn" },
    { PTP_OC_CANON_EOS_RemoteReleaseOff,                "CANON_EOS_RemoteReleaseOff" },
    { PTP_OC_CANON_EOS_InitiateViewfinder,              "CANON_EOS_InitiateViewfinder" },
    { PTP_OC_CANON_EOS_TerminateViewfinder,             "CANON_EOS_TerminateViewfinder" },
    { PTP_OC_CANON_EOS_GetViewFinderData,               "CANON_EOS_GetViewFinderData" },
    { PTP_OC_CANON_EOS_DoAf,                            "CANON_EOS_DoAf" },
    { PTP_OC_CANON_EOS_DriveLens,                       "CANON_EOS_DriveLens" },
    { PTP_OC_CANON_EOS_DepthOfFieldPreview,             "CANON_EOS_DepthOfFieldPreview" },
    { PTP_OC_CANON_EOS_ClickWB,                         "CANON_EOS_ClickWB" },
    { PTP_OC_CANON_EOS_Zoom,                            "CANON_EOS_Zoom" },
    { PTP_OC_CANON_EOS_ZoomPosition,                    "CANON_EOS_ZoomPosition" },
    { PTP_OC_CANON_EOS_SetLiveAfFrame,                  "CANON_EOS_SetLiveAfFrame" },
    { PTP_OC_CANON_EOS_AfCancel,                        "CANON_EOS_AfCancel" },
    { PTP_OC_CANON_EOS_FAPIMessageTX,                   "CANON_EOS_FAPIMessageTX" },
    { PTP_OC_CANON_EOS_FAPIMessageRX,                   "CANON_EOS_FAPIMessageRX" },
    { PTP_OC_NIKON_GetProfileAllData,                   "NIKON_GetProfileAllData" },
    { PTP_OC_NIKON_SendProfileData,                     "NIKON_SendProfileData" },
    { PTP_OC_NIKON_SendProfileData,                     "NIKON_SendProfileData" },
    { PTP_OC_NIKON_DeleteProfile,                       "NIKON_DeleteProfile" },
    { PTP_OC_NIKON_SetProfileData,                      "NIKON_SetProfileData" },
    { PTP_OC_NIKON_AdvancedTransfer,                    "NIKON_AdvancedTransfer" },
    { PTP_OC_NIKON_GetFileInfoInBlock,                  "NIKON_GetFileInfoInBlock" },
    { PTP_OC_NIKON_Capture,                             "NIKON_Capture" },
    { PTP_OC_NIKON_AfDrive,                             "NIKON_AfDrive" },
    { PTP_OC_NIKON_SetControlMode,                      "NIKON_SetControlMode" },
    { PTP_OC_NIKON_DelImageSDRAM,                       "NIKON_DelImageSDRAM" },
    { PTP_OC_NIKON_GetLargeThumb,                       "NIKON_GetLargeThumb" },
    { PTP_OC_NIKON_CurveDownload,                       "NIKON_CurveDownload" },
    { PTP_OC_NIKON_CurveUpload,                         "NIKON_CurveUpload" },
    { PTP_OC_NIKON_CheckEvent,                          "NIKON_CheckEvent" },
    { PTP_OC_NIKON_DeviceReady,                         "NIKON_DeviceReady" },
    { PTP_OC_NIKON_SetPreWBData,                        "NIKON_SetPreWBData" },
    { PTP_OC_NIKON_GetVendorPropCodes,                  "NIKON_GetVendorPropCodes" },
    { PTP_OC_NIKON_AfCaptureSDRAM,                      "NIKON_AfCaptureSDRAM" },
    { PTP_OC_NIKON_GetPictCtrlData,                     "NIKON_GetPictCtrlData" },
    { PTP_OC_NIKON_SetPictCtrlData,                     "NIKON_SetPictCtrlData" },
    { PTP_OC_NIKON_DelCstPicCtrl,                       "NIKON_DelCstPicCtrl" },
    { PTP_OC_NIKON_GetPicCtrlCapability,                "NIKON_GetPicCtrlCapability" },
    { PTP_OC_NIKON_GetPreviewImg,                       "NIKON_GetPreviewImg" },
    { PTP_OC_NIKON_StartLiveView,                       "NIKON_StartLiveView" },
    { PTP_OC_NIKON_EndLiveView,                         "NIKON_EndLiveView" },
    { PTP_OC_NIKON_GetLiveViewImg,                      "NIKON_GetLiveViewImg" },
    { PTP_OC_NIKON_MfDrive,                             "NIKON_MfDrive" },
    { PTP_OC_NIKON_ChangeAfArea,                        "NIKON_ChangeAfArea" },
    { PTP_OC_NIKON_AfDriveCancel,                       "NIKON_AfDriveCancel" },
    { PTP_OC_NIKON_GetDevicePTPIPInfo,                  "NIKON_GetDevicePTPIPInfo" },
    { PTP_OC_CASIO_STILL_START,                         "CASIO_STILL_START" },
    { PTP_OC_CASIO_STILL_STOP,                          "CASIO_STILL_STOP" },
    { PTP_OC_CASIO_FOCUS,                               "CASIO_FOCUS" },
    { PTP_OC_CASIO_CF_PRESS,                            "CASIO_CF_PRESS" },
    { PTP_OC_CASIO_CF_RELEASE,                          "CASIO_CF_RELEASE" },
    { PTP_OC_CASIO_GET_OBJECT_INFO,                     "CASIO_GET_OBJECT_INFO" },
    { PTP_OC_CASIO_SHUTTER,                             "CASIO_SHUTTER" },
    { PTP_OC_CASIO_GET_STILL_HANDLES,                   "CASIO_GET_STILL_HANDLES" },
    { PTP_OC_CASIO_STILL_RESET,                         "CASIO_STILL_RESET" },
    { PTP_OC_CASIO_HALF_PRESS,                          "CASIO_HALF_PRESS" },
    { PTP_OC_CASIO_HALF_RELEASE,                        "CASIO_HALF_RELEASE" },
    { PTP_OC_CASIO_CS_PRESS,                            "CASIO_CS_PRESS" },
    { PTP_OC_CASIO_CS_RELEASE,                          "CASIO_CS_RELEASE" },
    { PTP_OC_CASIO_ZOOM,                                "CASIO_ZOOM" },
    { PTP_OC_CASIO_CZ_PRESS,                            "CASIO_CZ_PRESS" },
    { PTP_OC_CASIO_CZ_RELEASE,                          "CASIO_CZ_RELEASE" },
    { PTP_OC_CASIO_MOVIE_START,                         "CASIO_MOVIE_START" },
    { PTP_OC_CASIO_MOVIE_STOP,                          "CASIO_MOVIE_STOP" },
    { PTP_OC_CASIO_MOVIE_PRESS,                         "CASIO_MOVIE_PRESS" },
    { PTP_OC_CASIO_MOVIE_RELEASE,                       "CASIO_MOVIE_RELEASE" },
    { PTP_OC_CASIO_GET_MOVIE_HANDLES,                   "CASIO_GET_MOVIE_HANDLES" },
    { PTP_OC_CASIO_MOVIE_RESET,                         "CASIO_MOVIE_RESET" },
    { PTP_OC_CASIO_GET_OBJECT,                          "CASIO_GET_OBJECT" },
    { PTP_OC_CASIO_GET_THUMBNAIL,                       "CASIO_GET_THUMBNAIL" },
    { PTP_OC_MTP_GetObjectPropsSupported,               "MTP_GetObjectPropsSupported" },
    { PTP_OC_MTP_GetObjectPropDesc,                     "MTP_GetObjectPropDesc" },
    { PTP_OC_MTP_GetObjectPropValue,                    "MTP_GetObjectPropValue" },
    { PTP_OC_MTP_SetObjectPropValue,                    "MTP_SetObjectPropValue" },
    { PTP_OC_MTP_GetObjPropList,                        "MTP_GetObjPropList" },
    { PTP_OC_MTP_SetObjPropList,                        "MTP_SetObjPropList" },
    { PTP_OC_MTP_GetInterdependendPropdesc,             "MTP_GetInterdependendPropdesc" },
    { PTP_OC_MTP_SendObjectPropList,                    "MTP_SendObjectPropList" },
    { PTP_OC_MTP_GetObjectReferences,                   "MTP_GetObjectReferences" },
    { PTP_OC_MTP_SetObjectReferences,                   "MTP_SetObjectReferences" },
    { PTP_OC_MTP_UpdateDeviceFirmware,                  "MTP_UpdateDeviceFirmware" },
    { PTP_OC_MTP_Skip,                                  "MTP_Skip" },
    { PTP_OC_MTP_WMDRMPD_GetSecureTimeChallenge,        "MTP_WMDRMPD_GetSecureTimeChallenge" },
    { PTP_OC_MTP_WMDRMPD_GetSecureTimeResponse,         "MTP_WMDRMPD_GetSecureTimeResponse" },
    { PTP_OC_MTP_WMDRMPD_SetLicenseResponse,            "MTP_WMDRMPD_SetLicenseResponse" },
    { PTP_OC_MTP_WMDRMPD_GetSyncList,                   "MTP_WMDRMPD_GetSyncList" },
    { PTP_OC_MTP_WMDRMPD_SendMeterChallengeQuery,       "MTP_WMDRMPD_SendMeterChallengeQuery" },
    { PTP_OC_MTP_WMDRMPD_GetMeterChallenge,             "MTP_WMDRMPD_GetMeterChallenge" },
    { PTP_OC_MTP_WMDRMPD_SetMeterResponse,              "MTP_WMDRMPD_SetMeterResponse" },
    { PTP_OC_MTP_WMDRMPD_CleanDataStore,                "MTP_WMDRMPD_CleanDataStore" },
    { PTP_OC_MTP_WMDRMPD_GetLicenseState,               "MTP_WMDRMPD_GetLicenseState" },
    { PTP_OC_MTP_WMDRMPD_SendWMDRMPDCommand,            "MTP_WMDRMPD_SendWMDRMPDCommand" },
    { PTP_OC_MTP_WMDRMPD_SendWMDRMPDRequest,            "MTP_WMDRMPD_SendWMDRMPDRequest" },
    { PTP_OC_MTP_WMDRMPD_SendWMDRMPDAppRequest,         "MTP_WMDRMPD_SendWMDRMPDAppRequest" },
    { PTP_OC_MTP_WMDRMPD_GetWMDRMPDAppResponse,         "MTP_WMDRMPD_GetWMDRMPDAppResponse" },
    { PTP_OC_MTP_WMDRMPD_EnableTrustedFilesOperations,  "MTP_WMDRMPD_EnableTrustedFilesOperations" },
    { PTP_OC_MTP_WMDRMPD_DisableTrustedFilesOperations, "MTP_WMDRMPD_DisableTrustedFilesOperations" },
    { PTP_OC_MTP_WMDRMPD_EndTrustedAppSession,          "MTP_WMDRMPD_EndTrustedAppSession" },
    { PTP_OC_MTP_AAVT_OpenMediaSession,                 "MTP_AAVT_OpenMediaSession" },
    { PTP_OC_MTP_AAVT_CloseMediaSession,                "MTP_AAVT_CloseMediaSession" },
    { PTP_OC_MTP_AAVT_GetNextDataBlock,                 "MTP_AAVT_GetNextDataBlock" },
    { PTP_OC_MTP_AAVT_SetCurrentTimePosition,           "MTP_AAVT_SetCurrentTimePosition" },
    { PTP_OC_MTP_WMDRMND_SendRegistrationRequest,       "MTP_WMDRMND_SendRegistrationRequest" },
    { PTP_OC_MTP_WMDRMND_GetRegistrationResponse,       "MTP_WMDRMND_GetRegistrationResponse" },
    { PTP_OC_MTP_WMDRMND_GetProximityChallenge,         "MTP_WMDRMND_GetProximityChallenge" },
    { PTP_OC_MTP_WMDRMND_SendProximityResponse,         "MTP_WMDRMND_SendProximityResponse" },
    { PTP_OC_MTP_WMDRMND_SendWMDRMNDLicenseRequest,     "MTP_WMDRMND_SendWMDRMNDLicenseRequest" },
    { PTP_OC_MTP_WMDRMND_GetWMDRMNDLicenseResponse,     "MTP_WMDRMND_GetWMDRMNDLicenseResponse" },
    { PTP_OC_MTP_WMPPD_ReportAddedDeletedItems,         "MTP_WMPPD_ReportAddedDeletedItems" },
    { PTP_OC_MTP_WMPPD_ReportAcquiredItems,             "MTP_WMPPD_ReportAcquiredItems" },
    { PTP_OC_MTP_WMPPD_PlaylistObjectPref,              "MTP_WMPPD_PlaylistObjectPref" },
    { PTP_OC_MTP_ZUNE_GETUNDEFINED001,                  "MTP_ZUNE_GETUNDEFINED001" },
    { PTP_OC_MTP_WPDWCN_ProcessWFCObject,               "MTP_WPDWCN_ProcessWFCObject" },
    { PTP_OC_OLYMPUS_Capture,                           "OLYMPUS_Capture" },
    { PTP_OC_OLYMPUS_SelfCleaning,                      "OLYMPUS_SelfCleaning" },
    { PTP_OC_OLYMPUS_SetRGBGain,                        "OLYMPUS_SetRGBGain" },
    { PTP_OC_OLYMPUS_SetPresetMode,                     "OLYMPUS_SetPresetMode" },
    { PTP_OC_OLYMPUS_SetWBBiasAll,                      "OLYMPUS_SetWBBiasAll" },
    { PTP_OC_OLYMPUS_GetCameraControlMode,              "OLYMPUS_GetCameraControlMode" },
    { PTP_OC_OLYMPUS_SetCameraControlMode,              "OLYMPUS_SetCameraControlMode" },
    { PTP_OC_OLYMPUS_SetWBRGBGain,                      "OLYMPUS_SetWBRGBGain" },
    { PTP_OC_OLYMPUS_GetDeviceInfo,                     "OLYMPUS_GetDeviceInfo" },
    { PTP_OC_OLYMPUS_Init1,                             "OLYMPUS_Init1" },
    { PTP_OC_OLYMPUS_SetDateTime,                       "OLYMPUS_SetDateTime" },
    { PTP_OC_OLYMPUS_GetDateTime,                       "OLYMPUS_GetDateTim" },
    { PTP_OC_OLYMPUS_SetCameraID,                       "OLYMPUS_SetCameraID" },
    { PTP_OC_OLYMPUS_GetCameraID,                       "OLYMPUS_GetCameraID" },
    { PTP_OC_EXTENSION_MASK,                            "EXTENSION_MASK" },
    { PTP_OC_EXTENSION,                                 "EXTENSION" },
    { PTP_OC_Undefined,                                 "Undefined" },
    { 0,                                                 NULL }

};
/* static value_string_ext ptp_opcode_names_ext = VALUE_STRING_EXT_INIT(ptp_opcode_names); */

/* XXX: There are a number of duplicate values in the following which
        will never be found (obviously) via a linear search. (see enum
        in packet-ptpip.h). */
/* ToDo: FIXME & then create/use extended value_string */
static const value_string ptp_respcode_names[] = {
    { PTP_RC_OK,                                     "OK" },
    { PTP_RC_GeneralError,                           "GeneralError" },
    { PTP_RC_SessionNotOpen,                         "SessionNotOpen" },
    { PTP_RC_InvalidTransactionID,                   "InvalidTransactionID" },
    { PTP_RC_OperationNotSupported,                  "OperationNotSupported" },
    { PTP_RC_ParameterNotSupported,                  "ParameterNotSupported" },
    { PTP_RC_IncompleteTransfer,                     "IncompleteTransfer" },
    { PTP_RC_InvalidStorageId,                       "InvalidStorageId" },
    { PTP_RC_InvalidObjectHandle,                    "InvalidObjectHandle" },
    { PTP_RC_DevicePropNotSupported,                 "DevicePropNotSupported" },
    { PTP_RC_InvalidObjectFormatCode,                "InvalidObjectFormatCode" },
    { PTP_RC_StoreFull,                              "StoreFull" },
    { PTP_RC_StoreReadOnly,                          "StoreReadOnly" },
    { PTP_RC_AccessDenied,                           "AccessDenied" },
    { PTP_RC_NoThumbnailPresent,                     "NoThumbnailPresent" },
    { PTP_RC_SelfTestFailed,                         "SelfTestFailed" },
    { PTP_RC_PartialDeletion,                        "PartialDeletion" },
    { PTP_RC_StoreNotAvailable,                      "StoreNotAvailable" },
    { PTP_RC_SpecificationByFormatUnsupported,       "SpecificationByFormatUnsupported" },
    { PTP_RC_NoValidObjectInfo,                      "NoValidObjectInfo" },
    { PTP_RC_InvalidCodeFormat,                      "InvalidCodeFormat" },
    { PTP_RC_UnknownVendorCode,                      "UnknownVendorCode" },
    { PTP_RC_CaptureAlreadyTerminated,               "CaptureAlreadyTerminated" },
    { PTP_RC_DeviceBusy,                             "DeviceBusy" },
    { PTP_RC_InvalidParentObject,                    "InvalidParentObject" },
    { PTP_RC_InvalidDevicePropFormat,                "InvalidDevicePropFormat" },
    { PTP_RC_InvalidDevicePropValue,                 "InvalidDevicePropValue" },
    { PTP_RC_InvalidParameter,                       "InvalidParameter" },
    { PTP_RC_SessionAlreadyOpened,                   "SessionAlreadyOpened" },
    { PTP_RC_TransactionCanceled,                    "TransactionCanceled" },
    { PTP_RC_SpecificationOfDestinationUnsupported,  "SpecificationOfDestinationUnsupported" },
    { PTP_RC_InvalidEnumHandle,                      "InvalidEnumHandle" },
    { PTP_RC_NoStreamEnabled,                        "NoStreamEnabled" },
    { PTP_RC_InvalidDataSet,                         "InvalidDataSet" },
    { PTP_RC_EK_FilenameRequired,                    "EK_FilenameRequired" },
    { PTP_RC_EK_FilenameConflicts,                   "EK_FilenameConflicts" },
    { PTP_RC_EK_FilenameInvalid,                     "EK_FilenameInvalid" },
    { PTP_RC_NIKON_HardwareError,                    "NIKON_HardwareError" },
    { PTP_RC_NIKON_OutOfFocus,                       "NIKON_OutOfFocus" },
    { PTP_RC_NIKON_ChangeCameraModeFailed,           "NIKON_ChangeCameraModeFailed" },
    { PTP_RC_NIKON_InvalidStatus,                    "NIKON_InvalidStatus" },
    { PTP_RC_NIKON_SetPropertyNotSupported,          "NIKON_SetPropertyNotSupported" },
    { PTP_RC_NIKON_WbResetError,                     "NIKON_WbResetError" },
    { PTP_RC_NIKON_DustReferenceError,               "NIKON_DustReferenceError" },
    { PTP_RC_NIKON_ShutterSpeedBulb,                 "NIKON_ShutterSpeedBulb" },
    { PTP_RC_NIKON_MirrorUpSequence,                 "NIKON_MirrorUpSequence" },
    { PTP_RC_NIKON_CameraModeNotAdjustFNumber,       "NIKON_CameraModeNotAdjustFNumber" },
    { PTP_RC_NIKON_NotLiveView,                      "NIKON_NotLiveView" },
    { PTP_RC_NIKON_MfDriveStepEnd,                   "NIKON_MfDriveStepEnd" },
    { PTP_RC_NIKON_MfDriveStepInsufficiency,         "NIKON_MfDriveStepInsufficiency" },
    { PTP_RC_NIKON_AdvancedTransferCancel,           "NIKON_AdvancedTransferCancel" },
    { PTP_RC_CANON_UNKNOWN_COMMAND,                  "CANON_UNKNOWN_COMMAND" },
    { PTP_RC_CANON_OPERATION_REFUSED,                "CANON_OPERATION_REFUSED" },
    { PTP_RC_CANON_LENS_COVER,                       "CANON_LENS_COVER" },
    { PTP_RC_CANON_BATTERY_LOW,                      "CANON_BATTERY_LOW" },
    { PTP_RC_CANON_NOT_READY,                        "CANON_NOT_READY" },
    { PTP_RC_CANON_A009,                             "CANON_A009" },
    { PTP_RC_MTP_Undefined,                          "MTP_Undefined" },
    { PTP_RC_MTP_Invalid_ObjectPropCode,             "MTP_Invalid_ObjectPropCode" },
    { PTP_RC_MTP_Invalid_ObjectProp_Format,          "MTP_Invalid_ObjectProp_Format" },
    { PTP_RC_MTP_Invalid_ObjectProp_Value,           "MTP_Invalid_ObjectProp_Value" },
    { PTP_RC_MTP_Invalid_ObjectReference,            "MTP_Invalid_ObjectReference" },
    { PTP_RC_MTP_Invalid_Dataset,                    "MTP_Invalid_Dataset" },
    { PTP_RC_MTP_Specification_By_Group_Unsupported, "MTP_Specification_By_Group_Unsupported" },
    { PTP_RC_MTP_Specification_By_Depth_Unsupported, "MTP_Specification_By_Depth_Unsupported" },
    { PTP_RC_MTP_Object_Too_Large,                   "MTP_Object_Too_Large" },
    { PTP_RC_MTP_ObjectProp_Not_Supported,           "MTP_ObjectProp_Not_Supported" },
    { PTP_RC_MTP_Invalid_Media_Session_ID,           "MTP_Invalid_Media_Session_ID" },
    { PTP_RC_MTP_Media_Session_Limit_Reached,        "MTP_Media_Session_Limit_Reached" },
    { PTP_RC_MTP_No_More_Data,                       "MTP_No_More_Data" },
    { PTP_RC_MTP_Invalid_WFC_Syntax,                 "MTP_Invalid_WFC_Syntax" },
    { PTP_RC_MTP_WFC_Version_Not_Supported,          "MTP_WFC_Version_Not_Supported" },
    { PTP_RC_Undefined,                              "Undefined" },
    { 0,                                                 NULL }
};
/* static value_string_ext ptp_respcode_names_ext = VALUE_STRING_EXT_INIT(ptp_respcode_names); */

/* String Names of packet types [3] & [4] */
/* PTP/IP definitions */
 /* enums reformatted from [4] */
typedef enum {
    PTPIP_INVALID                = 0,
    PTPIP_INIT_COMMAND_REQUEST   = 1,
    PTPIP_INIT_COMMAND_ACK       = 2,
    PTPIP_INIT_EVENT_REQUEST     = 3,
    PTPIP_INIT_EVENT_ACK         = 4,
    PTPIP_INIT_FAIL              = 5,
    PTPIP_CMD_REQUEST            = 6,  /* possibly Operation request in [1] 2.3.6 agrees with [3]   */
    PTPIP_CMD_RESPONSE           = 7,  /* possibly Operation response in [1] 2.3.7  agrees with [3] */
    PTPIP_EVENT                  = 8,
    PTPIP_START_DATA_PACKET      = 9,
    PTPIP_DATA_PACKET            = 10,
    PTPIP_CANCEL_TRANSACTION     = 11,
    PTPIP_END_DATA_PACKET        = 12,
    PTPIP_PING                   = 13, /* possibly Probe Request in [1] 2.3.13  */
    PTPIP_PONG                   = 14  /* possibly Probe Response in [1] 2.3.14 */
} ptpip_pktType;

/* Unless otherwise stated, names are based on info in [3] */
static const value_string ptpip_pktType_names[] = {
    { PTPIP_INVALID,                 "Invalid" },
    { PTPIP_INIT_COMMAND_REQUEST,    "Init Command Request Packet" },
    { PTPIP_INIT_COMMAND_ACK,        "Init Command ACK Packet" },
    { PTPIP_INIT_EVENT_REQUEST,      "Init Event Request Packet" },
    { PTPIP_INIT_EVENT_ACK,          "Init Event Ack Packet"},
    { PTPIP_INIT_FAIL,               "Init Fail Packet"},
    { PTPIP_CMD_REQUEST,             "Operation Request Packet"},  /* string based on [1]  */
    { PTPIP_CMD_RESPONSE,            "Operation Response Packet"}, /* string based on [1] */
    { PTPIP_EVENT,                   "Event Packet"},
    { PTPIP_START_DATA_PACKET,       "Start Data Packet"},
    { PTPIP_DATA_PACKET,             "Data Packet"},
    { PTPIP_CANCEL_TRANSACTION,      "Cancel Packet"},
    { PTPIP_END_DATA_PACKET,         "End Data Packet"},
    { PTPIP_PING,                    "Probe Request Packet"},      /* string based on [1]  */
    { PTPIP_PONG,                    "Probe Response Packet"},     /* string based on [1] */
    { 0,                             NULL }
};
static value_string_ext ptpip_pktType_names_ext = VALUE_STRING_EXT_INIT(ptpip_pktType_names);


/**
 * Primary method to dissect a PTP/IP packet. When a subtype is encounter,
 * the method will call a subdissector.
 */
static
int dissect_ptpIP (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item_ptr;
    proto_tree *ptp_tree;
    guint16     offset = 0;

    guint32 pktType;

    /* Check that there's enough data */
    if ( tvb_length_remaining(tvb, offset) < 8 )    /* ptp-photo smallest packet size is 8 */
        return (0);

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "PTP/IP");

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Picture Transfer Protocol");

    item_ptr = proto_tree_add_protocol_format(tree, proto_ptpIP, tvb, offset,
         -1, "Picture Transfer Protocol");

    /* creating the tree */
    ptp_tree = proto_item_add_subtree(item_ptr, ett_ptpIP);
    /* [1] Defines first 2 fields as length and packet type. (Section 2.3)
     * Also note: the standard lists all multibyte values in PTP-IP as little-endian
     */

    /* note: len field size included in total len */
    proto_tree_add_item(ptp_tree, hf_ptpIP_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* @todo:maybe add some length verification checks to see if len advertised matches actual len */

    pktType = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(ptp_tree, hf_ptpIP_pktType, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    switch (pktType) {
        case PTPIP_INIT_COMMAND_REQUEST:
            dissect_ptpIP_init_command_request(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_INIT_COMMAND_ACK:
            dissect_ptpIP_init_command_ack(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_INIT_EVENT_REQUEST:
            dissect_ptpIP_init_event_request(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_INIT_EVENT_ACK:
            dissect_ptpIP_init_event_ack(pinfo);
            break;
        case PTPIP_CMD_REQUEST:
            dissect_ptpIP_operation_request(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_CMD_RESPONSE:
            dissect_ptpIP_operation_response(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_EVENT:
            dissect_ptpIP_event(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_START_DATA_PACKET:
            dissect_ptpIP_start_data(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_DATA_PACKET:
            dissect_ptpIP_data(tvb, pinfo, ptp_tree, &offset);
            break;
        case PTPIP_END_DATA_PACKET:
            dissect_ptpIP_end_data(tvb, pinfo, ptp_tree, &offset);
            break;
        default:
            break;
    }

    return (offset);
}

/**
 * Method to dissect the Init Command Request sent by the Initiator
 * in the connection. This packet is defined by [1] Section 2.3.1
 */
void dissect_ptpIP_init_command_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    *offset += 0;

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Init Command Request");

    dissect_ptpIP_guid(tvb, pinfo, tree, offset);

    /* grabbing the name */
    dissect_ptpIP_unicode_name(tvb, pinfo, tree, offset);

    /* grabbing protocol version
     * Note: [3] does not list this in the packet field. . [1] 2.3.1 states its the last 4
     * bytes of the packet.
    */
    dissect_ptpIP_protocol_version(tvb, tree, offset);
    return;
}

/**
 * Method to dissect the Init Command Ack sent by the Responder
 * in the connection. This packet is defined by [1] Section 2.3.2
 */
void dissect_ptpIP_init_command_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint32 connectionNumber;

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Init Command Ack");

    /* Grabbing the Connection Number */
    connectionNumber = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_ptpIP_connectionNumber, tvb, *offset, 4,ENC_LITTLE_ENDIAN);
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " Connection #:%u",
        connectionNumber);
    *offset += 4;

    dissect_ptpIP_guid(tvb, pinfo, tree, offset);

    /* grabbing name */
    dissect_ptpIP_unicode_name(tvb,pinfo, tree, offset);

    /* grabbing protocol version. Note: like in the Init Command Request, [3] doesn't mention
     * this field, but [1] Section 2.3.2 does.
     */


    dissect_ptpIP_protocol_version(tvb, tree, offset);
}

/**
 * Dissects the Init Event Request packet specified in [1] Section 2.3.3.
 * Standard states that the packet only has 1 field.
 */
void dissect_ptpIP_init_event_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint32 connectionNumber;

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Init Event Request");

    /* Grabbing the Connection Number */
    connectionNumber = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_ptpIP_connectionNumber, tvb, *offset, 4,ENC_LITTLE_ENDIAN);
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " Connection #:%u",
        connectionNumber);
    *offset += 4;
}

/**
 * Dissects the Init Event Ack packet specified in [1] Section 2.3.4
 */
void dissect_ptpIP_init_event_ack(packet_info *pinfo)
{
    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Init Event Ack");

    /* packet has no payload. */
}

/**
 * Dissects the Operation Request Packet specified in [1] Section 2.3.6
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_operation_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint16 opcode;
    guint16 transactionID_offset = *offset; /* need to save this to output transaction id in pinfo */

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Operation Request Packet ");

    proto_tree_add_item(tree,hf_ptpIP_dataPhaseInfo, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    opcode = tvb_get_letohs(tvb, *offset);
    proto_tree_add_item(tree, hf_ptp_opCode, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    transactionID_offset = *offset; /* we'll dissect the transactionID later because
                                       opcode handling erases the column */
    *offset += 4;

    /* carving out the parameters. [1] 2.3.6 states there can be at most 5. Params are defined in [2] 10.1 & 10.4 */
    switch (opcode)
    {
        case PTP_OC_GetDeviceInfo:
            /* [1] 10.5.1 */
            col_set_str(
                pinfo->cinfo,
                COL_INFO,
                "GetDeviceInfo");
            /* No parameters */
            break;
        case PTP_OC_OpenSession:
            dissect_ptp_opCode_openSession(tvb, pinfo, tree, offset);
            break;
        case PTP_OC_CloseSession:
            /* [1] 10.5.3 */
            col_set_str(
                pinfo->cinfo,
                COL_INFO,
                "CloseSession");
            /* No parameters */
            break;
        case PTP_OC_GetStorageIDs:
            /* [2]  10.5.4 */
            col_set_str(
                pinfo->cinfo,
                COL_INFO,
                "GetStorageIDs");
            /* states data is a storage array. Needs eventual investigation. */
            break;
        default:
            break;
    }
    dissect_ptp_transactionID(tvb, pinfo, tree, &transactionID_offset);
}

/**
 * Dissects the Operation Response Packet specified in [1] Section 2.3.7
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_operation_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Operation Response Packet ");

    proto_tree_add_item(tree, hf_ptp_respCode, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);

}

/**
 * Dissects the Event Packet specified in [1] Section 2.3.8
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Event Packet ");

    proto_tree_add_item(tree, hf_ptp_eventCode, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);
}

/**
 * Dissects the Event Packet specified in [1] Section 2.3.9
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_start_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint64 dataLen;

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Start Data Packet ");

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);


    dataLen = tvb_get_letoh64(tvb, *offset);
    proto_tree_add_item(tree, hf_ptp_totalDataLength, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;
    if (dataLen == G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) /* [1] specifies in 2.3.9 if total data len
                                                              is this value then len is unknown */
    {
        col_append_str(
            pinfo->cinfo,
            COL_INFO,
            " Data Length Unknown");
    }
}

void dissect_ptpIP_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "Data Packet ");

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);

}

/**
 * Dissects the End Data specified in [1] Section 2.3.11
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 */
void dissect_ptpIP_end_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{

    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "End Data Packet ");

    dissect_ptp_transactionID(tvb, pinfo, tree, offset);
}

/**
 * Dissects the Opcode Open Session as defined by [2] 10.5.2
 */
void dissect_ptp_opCode_openSession(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    col_set_str(
        pinfo->cinfo,
        COL_INFO,
        "OpenSession");

    proto_tree_add_item(tree, hf_ptp_opCode_param_sessionID, tvb, *offset, 4 , ENC_LITTLE_ENDIAN);
    *offset += 4;
}

/**
 * The transaction ID is defined  in [2]  9.3.1
 * and used in multiple message types. This method handles
 * parsing the field and adding the value to the info
 * column.
 *
 */
void dissect_ptp_transactionID(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint32 transactionID;

    transactionID = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_ptp_transactionID, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " Transaction ID: %d",
        transactionID);
}

/**
 * This method handles dissecting the Unicode name that is
 * specificed in multiple packets.
 */
void dissect_ptpIP_unicode_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint8 *name;
    gint    nameLen;

    nameLen = tvb_unicode_strsize(tvb, *offset);
    name = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, nameLen, ENC_UTF_16|ENC_LITTLE_ENDIAN);
    proto_tree_add_string(tree, hf_ptpIP_name, tvb, *offset, nameLen, name);
    *offset += nameLen;
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " Name: %s",
        name);
}

/** Method dissects the protocol version from the packets.
 * Additional note, section 3 of [1] defines the Binary Protocol version
 * as 0x00010000 == 1.0 where the Most significant bits are the major version and the least
 * significant bits are the minor version.
 */
void dissect_ptpIP_protocol_version(tvbuff_t *tvb, proto_tree *tree, guint16 *offset)
{

    guint8  version[30];
    guint32 protoVersion;
    guint16 majorVersion, minorVersion;

    protoVersion = tvb_get_letohl(tvb, *offset);
    /* logic to format version */
    minorVersion = protoVersion & 0xFFFF;
    majorVersion = (protoVersion & 0xFFFF0000) >>16;
    g_snprintf(version, sizeof(version), "%u.%u", majorVersion, minorVersion);
    proto_tree_add_string(tree, hf_ptpIP_version, tvb, *offset, 4, version);
    *offset += 4;
}

/* Grabbing the GUID */
void dissect_ptpIP_guid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset)
{
    guint8 *guid;

    guid = tvb_bytes_to_ep_str(tvb, *offset, PTPIP_GUID_SIZE);
    proto_tree_add_item(tree, hf_ptpIP_guid, tvb, *offset, PTPIP_GUID_SIZE, ENC_NA);
    *offset += PTPIP_GUID_SIZE;
    col_append_fstr(
        pinfo->cinfo,
        COL_INFO,
        " GUID: %s",
        guid);
}

void proto_register_ptpip( void )
{
    static hf_register_info hf[] = {
        /* PTP/IP layer */
        { &hf_ptpIP_len, {
            "Length", "ptpip.len", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_pktType, {
            "Packet Type", "ptpip.pktType", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
            &ptpip_pktType_names_ext, 0, NULL, HFILL }},
        { &hf_ptpIP_guid, {
            "GUID", "ptpip.guid", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_name, {
            "Host Name", "ptpip.name", FT_STRINGZ, STR_UNICODE,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_version, {
            "Version", "ptpip.version", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_connectionNumber, {
            "Connection Number", "ptpip.connection", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_ptpIP_dataPhaseInfo, {
            "Data Phase Info", "ptpip.phaseinfo", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        /* PTP layer */
             /* leaving names with "ptpip" to try and prevent namespace issues. probably changing later. */
        { &hf_ptp_opCode, {
            "Operation Code", "ptpip.opcode", FT_UINT16, BASE_HEX,
            VALS(ptp_opcode_names), 0, NULL, HFILL }},
        { &hf_ptp_respCode, {
            "Response Code", "ptpip.respcode", FT_UINT16, BASE_HEX,
            VALS(ptp_respcode_names), 0, NULL, HFILL }},
        { &hf_ptp_eventCode, {
            "Event Code", "ptpip.eventcode", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_ptp_transactionID, {
            "Transaction ID", "ptpip.transactionID", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_ptp_totalDataLength, {
            "Total Data Length", "ptpip.datalen", FT_UINT64, BASE_DEC_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_ptp_opCode_param_sessionID, {
            "Session ID", "ptpip.opcode.param.sessionid", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},

    };
    static gint *ett[] = {
        &ett_ptpIP,
        &ett_ptpIP_hdr
    };

    proto_ptpIP = proto_register_protocol("Picture Transfer Protocol Over IP", "PTP/IP", "ptpip");

    proto_register_field_array(proto_ptpIP, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ptpIP( void ) {

    dissector_handle_t ptpIP_handle;

    /*  Use new_create_dissector_handle() to indicate that dissect_ptpIP()
    *  returns the number of bytes it dissected (or 0 if it thinks the packet
    *  does not belong to PROTONAME).
    */

    ptpIP_handle = new_create_dissector_handle(dissect_ptpIP, proto_ptpIP);
    dissector_add_uint("tcp.port", PTPIP_PORT, ptpIP_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
