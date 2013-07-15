/* packet-ptpip.h
 * Routines for PTP/IP (Picture Transfer Protocol) packet dissection
 * 0xBismarck 2013
 *
 * $Id$
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
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>


/* PTP Definitions */
/*String Names of packet types [3] & [4]
 * Opcode 0x1000 - 0x1025 defined in Table 22 of [2]
 * Remainder of Opcodes from [4]. Enums reformatted from [4] ptp.h*/
typedef enum {
    /* PTP v1.0 operation codes */
    PTP_OC_Undefined                = 0x1000,
    PTP_OC_GetDeviceInfo            = 0x1001,
    PTP_OC_OpenSession              = 0x1002,
    PTP_OC_CloseSession             = 0x1003,
    PTP_OC_GetStorageIDs            = 0x1004,
    PTP_OC_GetStorageInfo           = 0x1005,
    PTP_OC_GetNumObjects            = 0x1006,
    PTP_OC_GetObjectHandles         = 0x1007,
    PTP_OC_GetObjectInfo            = 0x1008,
    PTP_OC_GetObject                = 0x1009,
    PTP_OC_GetThumb                 = 0x100A,
    PTP_OC_DeleteObject             = 0x100B,
    PTP_OC_SendObjectInfo           = 0x100C,
    PTP_OC_SendObject               = 0x100D,
    PTP_OC_InitiateCapture          = 0x100E,
    PTP_OC_FormatStore              = 0x100F,
    PTP_OC_ResetDevice              = 0x1010,
    PTP_OC_SelfTest                 = 0x1011,
    PTP_OC_SetObjectProtection      = 0x1012,
    PTP_OC_PowerDown                = 0x1013,
    PTP_OC_GetDevicePropDesc        = 0x1014,
    PTP_OC_GetDevicePropValue       = 0x1015,
    PTP_OC_SetDevicePropValue       = 0x1016,
    PTP_OC_ResetDevicePropValue     = 0x1017,
    PTP_OC_TerminateOpenCapture     = 0x1018,
    PTP_OC_MoveObject               = 0x1019,
    PTP_OC_CopyObject               = 0x101A,
    PTP_OC_GetPartialObject         = 0x101B,
    PTP_OC_InitiateOpenCapture      = 0x101C,
    /* PTP v1.1 operation codes */
    PTP_OC_StartEnumHandles         = 0x101D,
    PTP_OC_EnumHandles                 = 0x101E,
    PTP_OC_StopEnumHandles             = 0x101F,
    PTP_OC_GetVendorExtensionMaps     = 0x1020,
    PTP_OC_GetVendorDeviceInfo         = 0x1021,
    PTP_OC_GetResizedImageObject     = 0x1022,
    PTP_OC_GetFilesystemManifest     = 0x1023,
    PTP_OC_GetStreamInfo             = 0x1024,
    PTP_OC_GetStream                 = 0x1025,

    /* Eastman Kodak extension Operation Codes */
    PTP_OC_EK_GetSerial             = 0x9003,
    PTP_OC_EK_SetSerial             = 0x9004,
    PTP_OC_EK_SendFileObjectInfo     = 0x9005,
    PTP_OC_EK_SendFileObject         = 0x9006,
    PTP_OC_EK_SetText                 = 0x9008,

    /* Canon extension Operation Codes */
    PTP_OC_CANON_GetPartialObjectInfo    = 0x9001,
    /* 9002 - sends 2 uint32, nothing back  */
    PTP_OC_CANON_SetObjectArchive        = 0x9002,
    PTP_OC_CANON_KeepDeviceOn        = 0x9003,
    PTP_OC_CANON_LockDeviceUI        = 0x9004,
    PTP_OC_CANON_UnlockDeviceUI        = 0x9005,
    PTP_OC_CANON_GetObjectHandleByName    = 0x9006,
    /* no 9007 observed yet */
    PTP_OC_CANON_InitiateReleaseControl    = 0x9008,
    PTP_OC_CANON_TerminateReleaseControl    = 0x9009,
    PTP_OC_CANON_TerminatePlaybackMode    = 0x900A,
    PTP_OC_CANON_ViewfinderOn        = 0x900B,
    PTP_OC_CANON_ViewfinderOff        = 0x900C,
    PTP_OC_CANON_DoAeAfAwb            = 0x900D,

     /* 900e - send nothing, gets 5 uint16t in 32bit entities back in 20byte datablob */
    PTP_OC_CANON_GetCustomizeSpec        = 0x900E,
    PTP_OC_CANON_GetCustomizeItemInfo    = 0x900F,
    PTP_OC_CANON_GetCustomizeData        = 0x9010,
    PTP_OC_CANON_SetCustomizeData        = 0x9011,
    PTP_OC_CANON_GetCaptureStatus        = 0x9012,
    PTP_OC_CANON_CheckEvent            = 0x9013,
    PTP_OC_CANON_FocusLock            = 0x9014,
    PTP_OC_CANON_FocusUnlock        = 0x9015,
    PTP_OC_CANON_GetLocalReleaseParam    = 0x9016,
    PTP_OC_CANON_SetLocalReleaseParam    = 0x9017,
    PTP_OC_CANON_AskAboutPcEvf        = 0x9018,
    PTP_OC_CANON_SendPartialObject        = 0x9019,
    PTP_OC_CANON_InitiateCaptureInMemory    = 0x901A,
    PTP_OC_CANON_GetPartialObjectEx        = 0x901B,
    PTP_OC_CANON_SetObjectTime        = 0x901C,
    PTP_OC_CANON_GetViewfinderImage        = 0x901D,
    PTP_OC_CANON_GetObjectAttributes    = 0x901E,
    PTP_OC_CANON_ChangeUSBProtocol        = 0x901F,
    PTP_OC_CANON_GetChanges            = 0x9020,
    PTP_OC_CANON_GetObjectInfoEx        = 0x9021,
    PTP_OC_CANON_InitiateDirectTransfer    = 0x9022,
    PTP_OC_CANON_TerminateDirectTransfer     = 0x9023,
    PTP_OC_CANON_SendObjectInfoByPath     = 0x9024,
    PTP_OC_CANON_SendObjectByPath         = 0x9025,
    PTP_OC_CANON_InitiateDirectTansferEx    = 0x9026,
    PTP_OC_CANON_GetAncillaryObjectHandles    = 0x9027,
    PTP_OC_CANON_GetTreeInfo         = 0x9028,
    PTP_OC_CANON_GetTreeSize         = 0x9029,
    PTP_OC_CANON_NotifyProgress         = 0x902A,
    PTP_OC_CANON_NotifyCancelAccepted    = 0x902B,
    /* 902c: no parms, read 3 uint32 in data, no response parms */
    PTP_OC_CANON_902C            = 0x902C,
    PTP_OC_CANON_GetDirectory        = 0x902D,
    PTP_OC_CANON_SetPairingInfo        = 0x9030,
    PTP_OC_CANON_GetPairingInfo        = 0x9031,
    PTP_OC_CANON_DeletePairingInfo        = 0x9032,
    PTP_OC_CANON_GetMACAddress        = 0x9033,
   /* 9034: 1 param, no parms returned */
    PTP_OC_CANON_SetDisplayMonitor        = 0x9034,
    PTP_OC_CANON_PairingComplete        = 0x9035,
    PTP_OC_CANON_GetWirelessMAXChannel    = 0x9036,
   /* 9101: no args, 8 byte data (01 00 00 00 00 00 00 00), no resp data. */
    PTP_OC_CANON_EOS_GetStorageIDs        = 0x9101,
   /* 9102: 1 arg (0)
    * = 0x28 bytes of data:
        00000000: 34 00 00 00 02 00 02 91 0a 00 00 00 04 00 03 00
        00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00000020: 00 00 ff ff ff ff 03 43 00 46 00 00 00 03 41 00
        00000030: 3a 00 00 00
    * no resp args
    */
    PTP_OC_CANON_EOS_GetStorageInfo        = 0x9102,
    PTP_OC_CANON_EOS_GetObjectInfo        = 0x9103,
    PTP_OC_CANON_EOS_GetObject        = 0x9104,
    PTP_OC_CANON_EOS_DeleteObject        = 0x9105,
    PTP_OC_CANON_EOS_FormatStore        = 0x9106,
    PTP_OC_CANON_EOS_GetPartialObject    = 0x9107,
    PTP_OC_CANON_EOS_GetDeviceInfoEx    = 0x9108,

   /* sample1:
    * 3 cmdargs: 1,= 0xffffffff,00 00 10 00;
    * data:
        00000000: 48 00 00 00 02 00 09 91 12 00 00 00 01 00 00 00
        00000010: 38 00 00 00 00 00 00 30 01 00 00 00 01 30 00 00
        00000020: 01 00 00 00 10 00 00 00 00 00 00 00 00 00 00 20
        00000030: 00 00 00 30 44 43 49 4d 00 00 00 00 00 00 00 00    DCIM
        00000040: 00 00 00 00 cc c3 01 46
    * 2 respargs: = 0x0, = 0x3c
    *
    * sample2:
    *
        00000000: 18 00 00 00 01 00 09 91 15 00 00 00 01 00 00 00
        00000010: 00 00 00 30 00 00 10 00

        00000000: 48 00 00 00 02 00 09 91 15 00 00 00 01 00 00 00
        00000010: 38 00 00 00 00 00 9c 33 01 00 00 00 01 30 00 00
        00000020: 01 00 00 00 10 00 00 00 00 00 00 00 00 00 00 30
        00000030: 00 00 9c 33 32 33 31 43 41 4e 4f 4e 00 00 00 00     231CANON
        00000040: 00 00 00 00 cc c3 01 46

    */
    PTP_OC_CANON_EOS_GetObjectInfoEx    = 0x9109,
    PTP_OC_CANON_EOS_GetThumbEx        = 0x910A,
    PTP_OC_CANON_EOS_SendPartialObject    = 0x910B,
    PTP_OC_CANON_EOS_SetObjectAttributes    = 0x910C,
    PTP_OC_CANON_EOS_GetObjectTime        = 0x910D,
    PTP_OC_CANON_EOS_SetObjectTime        = 0x910E,

    /* 910f: no args, no data, 1 response arg (0). */
    PTP_OC_CANON_EOS_RemoteRelease        = 0x910F,
    /* Marcus: looks more like "Set DeviceProperty" in the trace.
    *
    * no cmd args
    * data phase (= 0xc, = 0xd11c, = 0x1)
    * no resp args
    */
    PTP_OC_CANON_EOS_SetDevicePropValueEx    = 0x9110,
    PTP_OC_CANON_EOS_GetRemoteMode        = 0x9113,
    /* 9114: 1 arg (= 0x1), no data, no resp data. */
    PTP_OC_CANON_EOS_SetRemoteMode        = 0x9114,
    /* 9115: 1 arg (= 0x1), no data, no resp data. */
    PTP_OC_CANON_EOS_SetEventMode        = 0x9115,
    /* 9116: no args, data phase, no resp data. */
    PTP_OC_CANON_EOS_GetEvent        = 0x9116,
    PTP_OC_CANON_EOS_TransferComplete    = 0x9117,
    PTP_OC_CANON_EOS_CancelTransfer        = 0x9118,
    PTP_OC_CANON_EOS_ResetTransfer        = 0x9119,

    /* 911a: 3 args (= 0xfffffff7, = 0x00001000, = 0x00000001), no data, no resp data. */
    /* 911a: 3 args (= 0x001dfc60, = 0x00001000, = 0x00000001), no data, no resp data. */
    PTP_OC_CANON_EOS_PCHDDCapacity        = 0x911A,

    /* 911b: no cmd args, no data, no resp args */
    PTP_OC_CANON_EOS_SetUILock        = 0x911B,
    /* 911c: no cmd args, no data, no resp args */
    PTP_OC_CANON_EOS_ResetUILock        = 0x911C,
    PTP_OC_CANON_EOS_KeepDeviceOn        = 0x911D,
    PTP_OC_CANON_EOS_SetNullPacketMode    = 0x911E,
    PTP_OC_CANON_EOS_UpdateFirmware        = 0x911F,
    PTP_OC_CANON_EOS_TransferCompleteDT    = 0x9120,
    PTP_OC_CANON_EOS_CancelTransferDT    = 0x9121,
    PTP_OC_CANON_EOS_SetWftProfile        = 0x9122,
    PTP_OC_CANON_EOS_GetWftProfile        = 0x9122,
    PTP_OC_CANON_EOS_SetProfileToWft    = 0x9124,
    PTP_OC_CANON_EOS_BulbStart        = 0x9125,
    PTP_OC_CANON_EOS_BulbEnd        = 0x9126,
    PTP_OC_CANON_EOS_RequestDevicePropValue    = 0x9127,

    /* = 0x9128 args (= 0x1/= 0x2, = 0x0), no data, no resp args */
    PTP_OC_CANON_EOS_RemoteReleaseOn    = 0x9128,
    /* = 0x9129 args (= 0x1/= 0x2), no data, no resp args */
    PTP_OC_CANON_EOS_RemoteReleaseOff    = 0x9129,
    PTP_OC_CANON_EOS_InitiateViewfinder    = 0x9151,
    PTP_OC_CANON_EOS_TerminateViewfinder    = 0x9152,
    PTP_OC_CANON_EOS_GetViewFinderData    = 0x9153,
    PTP_OC_CANON_EOS_DoAf            = 0x9154,
    PTP_OC_CANON_EOS_DriveLens        = 0x9155,
    PTP_OC_CANON_EOS_DepthOfFieldPreview    = 0x9156,
    PTP_OC_CANON_EOS_ClickWB        = 0x9157,
    PTP_OC_CANON_EOS_Zoom            = 0x9158,
    PTP_OC_CANON_EOS_ZoomPosition        = 0x9159,
    PTP_OC_CANON_EOS_SetLiveAfFrame        = 0x915a,
    PTP_OC_CANON_EOS_AfCancel        = 0x9160,
    PTP_OC_CANON_EOS_FAPIMessageTX        = 0x91FE,
    PTP_OC_CANON_EOS_FAPIMessageRX        = 0x91FF,

    /* Nikon extension Operation Codes */
    PTP_OC_NIKON_GetProfileAllData    = 0x9006,
    PTP_OC_NIKON_SendProfileData    = 0x9007,
    PTP_OC_NIKON_DeleteProfile    = 0x9008,
    PTP_OC_NIKON_SetProfileData    = 0x9009,
    PTP_OC_NIKON_AdvancedTransfer    = 0x9010,
    PTP_OC_NIKON_GetFileInfoInBlock    = 0x9011,
    PTP_OC_NIKON_Capture        = 0x90C0,    /* 1 param,   no data */
    PTP_OC_NIKON_AfDrive        = 0x90C1,    /* no params, no data */
    PTP_OC_NIKON_SetControlMode    = 0x90C2,    /* 1 param,   no data */
    PTP_OC_NIKON_DelImageSDRAM    = 0x90C3,    /* no params, no data */
    PTP_OC_NIKON_GetLargeThumb    = 0x90C4,
    PTP_OC_NIKON_CurveDownload    = 0x90C5,    /* 1 param,   data in */
    PTP_OC_NIKON_CurveUpload    = 0x90C6,    /* 1 param,   data out */
    PTP_OC_NIKON_CheckEvent        = 0x90C7,    /* no params, data in */
    PTP_OC_NIKON_DeviceReady    = 0x90C8,    /* no params, no data */
    PTP_OC_NIKON_SetPreWBData    = 0x90C9,    /* 3 params,  data out */
    PTP_OC_NIKON_GetVendorPropCodes    = 0x90CA,    /* 0 params, data in */
    PTP_OC_NIKON_AfCaptureSDRAM    = 0x90CB,    /* no params, no data */
    PTP_OC_NIKON_GetPictCtrlData    = 0x90CC,
    PTP_OC_NIKON_SetPictCtrlData    = 0x90CD,
    PTP_OC_NIKON_DelCstPicCtrl    = 0x90CE,
    PTP_OC_NIKON_GetPicCtrlCapability    = 0x90CF,

   /* Nikon Liveview stuff */
    PTP_OC_NIKON_GetPreviewImg    = 0x9200,
    PTP_OC_NIKON_StartLiveView    = 0x9201,
    PTP_OC_NIKON_EndLiveView    = 0x9202,
    PTP_OC_NIKON_GetLiveViewImg    = 0x9203,
    PTP_OC_NIKON_MfDrive        = 0x9204,
    PTP_OC_NIKON_ChangeAfArea    = 0x9205,
    PTP_OC_NIKON_AfDriveCancel    = 0x9206,
    PTP_OC_NIKON_GetDevicePTPIPInfo    = 0x90E0,

    /* Casio EX-F1 (from http://code.google.com/p/exf1ctrl/ ) */
    PTP_OC_CASIO_STILL_START    = 0x9001,
    PTP_OC_CASIO_STILL_STOP        = 0x9002,
    PTP_OC_CASIO_FOCUS        = 0x9007,
    PTP_OC_CASIO_CF_PRESS        = 0x9009,
    PTP_OC_CASIO_CF_RELEASE        = 0x900A,
    PTP_OC_CASIO_GET_OBJECT_INFO    = 0x900C,
    PTP_OC_CASIO_SHUTTER        = 0x9024,
    PTP_OC_CASIO_GET_STILL_HANDLES    = 0x9027,
    PTP_OC_CASIO_STILL_RESET    = 0x9028,
    PTP_OC_CASIO_HALF_PRESS        = 0x9029,
    PTP_OC_CASIO_HALF_RELEASE    = 0x902A,
    PTP_OC_CASIO_CS_PRESS        = 0x902B,
    PTP_OC_CASIO_CS_RELEASE        = 0x902C,
    PTP_OC_CASIO_ZOOM        = 0x902D,
    PTP_OC_CASIO_CZ_PRESS        = 0x902E,
    PTP_OC_CASIO_CZ_RELEASE        = 0x902F,
    PTP_OC_CASIO_MOVIE_START    = 0x9041,
    PTP_OC_CASIO_MOVIE_STOP        = 0x9042,
    PTP_OC_CASIO_MOVIE_PRESS    = 0x9043,
    PTP_OC_CASIO_MOVIE_RELEASE    = 0x9044,
    PTP_OC_CASIO_GET_MOVIE_HANDLES    = 0x9045,
    PTP_OC_CASIO_MOVIE_RESET    = 0x9046,
    PTP_OC_CASIO_GET_OBJECT        = 0x9025,
    PTP_OC_CASIO_GET_THUMBNAIL    = 0x9026,

    /* Microsoft / MTP extension codes */
    PTP_OC_MTP_GetObjectPropsSupported    = 0x9801,
    PTP_OC_MTP_GetObjectPropDesc        = 0x9802,
    PTP_OC_MTP_GetObjectPropValue        = 0x9803,
    PTP_OC_MTP_SetObjectPropValue        = 0x9804,
    PTP_OC_MTP_GetObjPropList        = 0x9805,
    PTP_OC_MTP_SetObjPropList        = 0x9806,
    PTP_OC_MTP_GetInterdependendPropdesc    = 0x9807,
    PTP_OC_MTP_SendObjectPropList        = 0x9808,
    PTP_OC_MTP_GetObjectReferences        = 0x9810,
    PTP_OC_MTP_SetObjectReferences        = 0x9811,
    PTP_OC_MTP_UpdateDeviceFirmware        = 0x9812,
    PTP_OC_MTP_Skip                = 0x9820,

    /*
    * Windows Media Digital Rights Management for Portable Devices
    * Extension Codes (microsoft.com/WMDRMPD: 10.1)
    */
    PTP_OC_MTP_WMDRMPD_GetSecureTimeChallenge    = 0x9101,
    PTP_OC_MTP_WMDRMPD_GetSecureTimeResponse    = 0x9102,
    PTP_OC_MTP_WMDRMPD_SetLicenseResponse    = 0x9103,
    PTP_OC_MTP_WMDRMPD_GetSyncList        = 0x9104,
    PTP_OC_MTP_WMDRMPD_SendMeterChallengeQuery    = 0x9105,
    PTP_OC_MTP_WMDRMPD_GetMeterChallenge    = 0x9106,
    PTP_OC_MTP_WMDRMPD_SetMeterResponse        = 0x9107,
    PTP_OC_MTP_WMDRMPD_CleanDataStore        = 0x9108,
    PTP_OC_MTP_WMDRMPD_GetLicenseState        = 0x9109,
    PTP_OC_MTP_WMDRMPD_SendWMDRMPDCommand    = 0x910A,
    PTP_OC_MTP_WMDRMPD_SendWMDRMPDRequest    = 0x910B,

    /*
    * Windows Media Digital Rights Management for Portable Devices
    * Extension Codes (microsoft.com/WMDRMPD: 10.1)
    * Below are operations that have no public documented identifier
    * associated with them "Vendor-defined Command Code"
    */
    PTP_OC_MTP_WMDRMPD_SendWMDRMPDAppRequest    = 0x9212,
    PTP_OC_MTP_WMDRMPD_GetWMDRMPDAppResponse    = 0x9213,
    PTP_OC_MTP_WMDRMPD_EnableTrustedFilesOperations    = 0x9214,
    PTP_OC_MTP_WMDRMPD_DisableTrustedFilesOperations = 0x9215,
    PTP_OC_MTP_WMDRMPD_EndTrustedAppSession        = 0x9216,
    /* ^^^ guess ^^^ */

    /*
    * Microsoft Advanced Audio/Video Transfer
    * Extensions (microsoft.com/AAVT: 1.0)
    */
    PTP_OC_MTP_AAVT_OpenMediaSession        = 0x9170,
    PTP_OC_MTP_AAVT_CloseMediaSession        = 0x9171,
    PTP_OC_MTP_AAVT_GetNextDataBlock        = 0x9172,
    PTP_OC_MTP_AAVT_SetCurrentTimePosition        = 0x9173,

    /*
    * Windows Media Digital Rights Management for Network Devices
    * Extensions (microsoft.com/WMDRMND: 1.0) MTP/IP?
    */
    PTP_OC_MTP_WMDRMND_SendRegistrationRequest    = 0x9180,
    PTP_OC_MTP_WMDRMND_GetRegistrationResponse    = 0x9181,
    PTP_OC_MTP_WMDRMND_GetProximityChallenge    = 0x9182,
    PTP_OC_MTP_WMDRMND_SendProximityResponse    = 0x9183,
    PTP_OC_MTP_WMDRMND_SendWMDRMNDLicenseRequest    = 0x9184,
    PTP_OC_MTP_WMDRMND_GetWMDRMNDLicenseResponse    = 0x9185,

    /*
    * Windows Media Player Portiable Devices
    * Extension Codes (microsoft.com/WMPPD: 11.1)
    */
    PTP_OC_MTP_WMPPD_ReportAddedDeletedItems    = 0x9201,
    PTP_OC_MTP_WMPPD_ReportAcquiredItems             = 0x9202,
    PTP_OC_MTP_WMPPD_PlaylistObjectPref        = 0x9203,

    /*
    * Undocumented Zune Operation Codes
    * maybe related to WMPPD extension set?
    */
    PTP_OC_MTP_ZUNE_GETUNDEFINED001                = 0x9204,

   /* WiFi Provisioning MTP Extension Codes (microsoft.com/WPDWCN: 1.0) */
    PTP_OC_MTP_WPDWCN_ProcessWFCObject        = 0x9122,

   /* Olympus E series commands */
    PTP_OC_OLYMPUS_Capture                = 0x9101,
    PTP_OC_OLYMPUS_SelfCleaning            = 0x9103,
    PTP_OC_OLYMPUS_SetRGBGain            = 0x9106,
    PTP_OC_OLYMPUS_SetPresetMode            = 0x9107,
    PTP_OC_OLYMPUS_SetWBBiasAll            = 0x9108,
    PTP_OC_OLYMPUS_GetCameraControlMode        = 0x910a,
    PTP_OC_OLYMPUS_SetCameraControlMode        = 0x910b,
    PTP_OC_OLYMPUS_SetWBRGBGain            = 0x910c,
    PTP_OC_OLYMPUS_GetDeviceInfo            = 0x9301,
    PTP_OC_OLYMPUS_Init1                = 0x9302,
    PTP_OC_OLYMPUS_SetDateTime            = 0x9402,
    PTP_OC_OLYMPUS_GetDateTime            = 0x9482,
    PTP_OC_OLYMPUS_SetCameraID            = 0x9501,
    PTP_OC_OLYMPUS_GetCameraID            = 0x9581,

   /* Proprietary vendor extension operations mask */
    PTP_OC_EXTENSION_MASK           = 0xF000,
    PTP_OC_EXTENSION                = 0x9000
} ptp_opcodes;

static const value_string ptp_opcode_names[] = {
    { PTP_OC_GetDeviceInfo,                             "GetDeviceInfo" },
    { PTP_OC_OpenSession,                                 "OpenSession" },
    { PTP_OC_CloseSession,                                 "CloseSession" },
    { PTP_OC_GetStorageIDs,                             "GetStorageIDs" },
    { PTP_OC_GetStorageInfo,                             "GetStorageInfo" },
    { PTP_OC_GetNumObjects,                             "GetNumObjects" },
    { PTP_OC_GetObjectHandles,                             "GetObjectHandles" },
    { PTP_OC_GetObjectInfo,                             "GetObjectInfo" },
    { PTP_OC_GetObject,                                 "GetObject" },
    { PTP_OC_DeleteObject,                                 "DeleteObject" },
    { PTP_OC_SendObjectInfo,                             "SendObjectInfo" },
    { PTP_OC_SendObject,                                 "SendObject" },
    { PTP_OC_InitiateCapture,                             "InitiateCapture" },
    { PTP_OC_FormatStore,                                 "FormatStore" },
    { PTP_OC_ResetDevice,                                 "ResetDevice" },
    { PTP_OC_SelfTest,                                     "SelfTest" },
    { PTP_OC_SetObjectProtection,                         "SetObjectProtection" },
    { PTP_OC_PowerDown,                                 "PowerDown" },
    { PTP_OC_GetDevicePropDesc,                         "GetDevicePropDesc" },
    { PTP_OC_GetDevicePropValue,                         "GetDevicePropValue" },
    { PTP_OC_SetDevicePropValue,                         "SetDevicePropValue" },
    { PTP_OC_ResetDevicePropValue,                         "ResetDevicePropValue" },
    { PTP_OC_TerminateOpenCapture,                         "TerminateOpenCapture" },
    { PTP_OC_MoveObject,                                 "MoveObject" },
    { PTP_OC_CopyObject,                                 "CopyObject" },
    { PTP_OC_GetPartialObject,                             "GetPartialObject" },
    { PTP_OC_InitiateOpenCapture,                         "InitiateOpenCapture" },
    { PTP_OC_StartEnumHandles,                             "StartEnumHandles" },
    { PTP_OC_EnumHandles,                                 "EnumHandles" },
    { PTP_OC_StopEnumHandles,                             "StopEnumHandles" },
    { PTP_OC_GetVendorExtensionMaps,                    "GetVendorExtensionMaps" },
    { PTP_OC_GetVendorDeviceInfo,                         "GetVendorDeviceInfo" },
    { PTP_OC_GetResizedImageObject,                     "GetResizedImageObject" },
    { PTP_OC_GetFilesystemManifest,                     "GetFilesystemManifest" },
    { PTP_OC_GetStreamInfo,                             "GetStreamInfo" },
    { PTP_OC_GetStream,                                 "GetStream" },
    { PTP_OC_EK_GetSerial,                                 "EK_GetSerial" },
    { PTP_OC_EK_SetSerial,                                 "EK_SetSerial" },
    { PTP_OC_EK_SendFileObjectInfo,                     "EK_SendFileObjectInfo" },
    { PTP_OC_EK_SendFileObject,                         "EK_SendFileObject" },
    { PTP_OC_EK_SetText,                                 "EK_SetText" },
    { PTP_OC_CANON_GetPartialObjectInfo,                 "CANON_GetPartialObjectInfo" },
    { PTP_OC_CANON_SetObjectArchive,                    "CANON_SetObjectArchive" },
    { PTP_OC_CANON_KeepDeviceOn,                         "CANON_KeepDeviceOn" },
    { PTP_OC_CANON_LockDeviceUI,                         "CANON_LockDeviceUI" },
    { PTP_OC_CANON_UnlockDeviceUI,                         "CANON_UnlockDeviceUI" },
    { PTP_OC_CANON_GetObjectHandleByName,                 "CANON_GetObjectHandleByName" },
    { PTP_OC_CANON_InitiateReleaseControl,                 "CANON_InitiateReleaseControl" },
    { PTP_OC_CANON_TerminateReleaseControl,             "CANON_TerminateReleaseControl" },
    { PTP_OC_CANON_TerminatePlaybackMode,                 "CANON_TerminatePlaybackMode" },
    { PTP_OC_CANON_ViewfinderOn,                         "CANON_ViewfinderOn" },
    { PTP_OC_CANON_ViewfinderOff,                         "CANON_ViewfinderOff" },
    { PTP_OC_CANON_DoAeAfAwb,                             "CANON_DoAeAfAwb" },
    { PTP_OC_CANON_GetCustomizeSpec,                    "CANON_GetCustomizeSpec" },
    { PTP_OC_CANON_GetCustomizeItemInfo,                 "CANON_GetCustomizeItemInfo" },
    { PTP_OC_CANON_GetCustomizeData,                     "CANON_GetCustomizeData" },
    { PTP_OC_CANON_SetCustomizeData,                     "CANON_SetCustomizeData" },
    { PTP_OC_CANON_GetCaptureStatus,                     "CANON_GetCaptureStatus" },
    { PTP_OC_CANON_CheckEvent,                             "CANON_CheckEvent" },
    { PTP_OC_CANON_FocusLock,                             "CANON_FocusLock" },
    { PTP_OC_CANON_FocusUnlock,                         "CANON_FocusUnlock" },
    { PTP_OC_CANON_GetLocalReleaseParam,                 "CANON_GetLocalReleaseParam" },
    { PTP_OC_CANON_SetLocalReleaseParam,                 "CANON_SetLocalReleaseParam" },
    { PTP_OC_CANON_AskAboutPcEvf,                         "CANON_AskAboutPcEvf" },
    { PTP_OC_CANON_SendPartialObject,                     "CANON_SendPartialObject" },
    { PTP_OC_CANON_InitiateCaptureInMemory,             "CANON_InitiateCaptureInMemory" },
    { PTP_OC_CANON_GetPartialObjectEx,                     "CANON_GetPartialObjectEx" },
    { PTP_OC_CANON_SetObjectTime,                         "CANON_SetObjectTime" },
    { PTP_OC_CANON_GetViewfinderImage,                     "CANON_GetViewfinderImage" },
    { PTP_OC_CANON_GetObjectAttributes,                 "CANON_GetObjectAttributes" },
    { PTP_OC_CANON_ChangeUSBProtocol,                     "CANON_ChangeUSBProtocol" },
    { PTP_OC_CANON_GetChanges,                             "CANON_GetChanges" },
    { PTP_OC_CANON_GetObjectInfoEx,                     "CANON_GetObjectInfoEx" },
    { PTP_OC_CANON_InitiateDirectTransfer,                 "CANON_InitiateDirectTransfer" },
    { PTP_OC_CANON_TerminateDirectTransfer,             "CANON_TerminateDirectTransfer" },
    { PTP_OC_CANON_SendObjectInfoByPath,                 "CANON_SendObjectInfoByPath" },
    { PTP_OC_CANON_SendObjectByPath,                     "CANON_SendObjectByPath" },
    { PTP_OC_CANON_InitiateDirectTansferEx,             "CANON_InitiateDirectTansferEx" },
    { PTP_OC_CANON_GetAncillaryObjectHandles,             "CANON_GetAncillaryObjectHandles" },
    { PTP_OC_CANON_GetTreeInfo,                         "CANON_GetTreeInfo" },
    { PTP_OC_CANON_GetTreeSize,                         "CANON_GetTreeSize" },
    { PTP_OC_CANON_NotifyProgress,                         "CANON_NotifyProgress" },
    { PTP_OC_CANON_NotifyCancelAccepted,                 "CANON_NotifyCancelAccepted" },
    { PTP_OC_CANON_902C,                                 "CANON_902C" },
    { PTP_OC_CANON_SetPairingInfo,                         "CANON_SetPairingInfo" },
    { PTP_OC_CANON_GetPairingInfo,                         "CANON_GetPairingInfo" },
    { PTP_OC_CANON_DeletePairingInfo,                     "CANON_DeletePairingInfo" },
    { PTP_OC_CANON_GetMACAddress,                         "CANON_GetMACAddress" },
    { PTP_OC_CANON_SetDisplayMonitor,                     "CANON_SetDisplayMonitor" },
    { PTP_OC_CANON_PairingComplete,                     "CANON_PairingComplete" },
    { PTP_OC_CANON_GetWirelessMAXChannel,                 "CANON_GetWirelessMAXChannel" },
    { PTP_OC_CANON_EOS_GetStorageIDs,                     "CANON_EOS_GetStorageIDs" },
    { PTP_OC_CANON_EOS_GetStorageInfo,                     "CANON_EOS_GetStorageInfo" },
    { PTP_OC_CANON_EOS_GetObjectInfo,                     "CANON_EOS_GetObjectInfo" },
    { PTP_OC_CANON_EOS_GetObject,                         "CANON_EOS_GetObject" },
    { PTP_OC_CANON_EOS_DeleteObject,                     "CANON_EOS_DeleteObject" },
    { PTP_OC_CANON_EOS_FormatStore,                     "CANON_EOS_FormatStore" },
    { PTP_OC_CANON_EOS_GetPartialObject,                 "CANON_EOS_GetPartialObject" },
    { PTP_OC_CANON_EOS_GetDeviceInfoEx,                 "CANON_EOS_GetDeviceInfoEx" },
    { PTP_OC_CANON_EOS_GetObjectInfoEx,                 "CANON_EOS_GetObjectInfoEx" },
    { PTP_OC_CANON_EOS_GetThumbEx,                         "CANON_EOS_GetThumbEx" },
    { PTP_OC_CANON_EOS_SendPartialObject,                 "CANON_EOS_SendPartialObject" },
    { PTP_OC_CANON_EOS_SetObjectAttributes,             "CANON_EOS_SetObjectAttributes" },
    { PTP_OC_CANON_EOS_GetObjectTime,                     "CANON_EOS_GetObjectTime" },
    { PTP_OC_CANON_EOS_SetObjectTime,                     "CANON_EOS_SetObjectTime" },
    { PTP_OC_CANON_EOS_RemoteRelease,                     "CANON_EOS_RemoteRelease" },
    { PTP_OC_CANON_EOS_SetDevicePropValueEx,             "CANON_EOS_SetDevicePropValueEx" },
    { PTP_OC_CANON_EOS_GetRemoteMode,                     "CANON_EOS_GetRemoteMode" },
    { PTP_OC_CANON_EOS_SetRemoteMode,                     "CANON_EOS_SetRemoteMode" },
    { PTP_OC_CANON_EOS_SetEventMode,                     "CANON_EOS_SetEventMode" },
    { PTP_OC_CANON_EOS_GetEvent,                         "CANON_EOS_GetEvent" },
    { PTP_OC_CANON_EOS_TransferComplete,                 "CANON_EOS_TransferComplete" },
    { PTP_OC_CANON_EOS_CancelTransfer,                     "CANON_EOS_CancelTransfer" },
    { PTP_OC_CANON_EOS_ResetTransfer,                     "CANON_EOS_ResetTransfer" },
    { PTP_OC_CANON_EOS_PCHDDCapacity,                     "CANON_EOS_PCHDDCapacity" },
    { PTP_OC_CANON_EOS_SetUILock,                         "CANON_EOS_SetUILock" },
    { PTP_OC_CANON_EOS_ResetUILock,                     "CANON_EOS_ResetUILock" },
    { PTP_OC_CANON_EOS_KeepDeviceOn,                     "CANON_EOS_KeepDeviceOn" },
    { PTP_OC_CANON_EOS_SetNullPacketMode,                 "CANON_EOS_SetNullPacketMode" },
    { PTP_OC_CANON_EOS_UpdateFirmware,                     "CANON_EOS_UpdateFirmware" },
    { PTP_OC_CANON_EOS_TransferCompleteDT,                 "CANON_EOS_TransferCompleteDT" },
    { PTP_OC_CANON_EOS_CancelTransferDT,                 "CANON_EOS_CancelTransferDT" },
    { PTP_OC_CANON_EOS_SetWftProfile,                     "CANON_EOS_SetWftProfile" },
    { PTP_OC_CANON_EOS_GetWftProfile,                     "CANON_EOS_GetWftProfile" },
    { PTP_OC_CANON_EOS_SetProfileToWft,                 "CANON_EOS_SetProfileToWft" },
    { PTP_OC_CANON_EOS_BulbStart,                         "CANON_EOS_BulbStart" },
    { PTP_OC_CANON_EOS_BulbEnd,                         "CANON_EOS_BulbEnd" },
    { PTP_OC_CANON_EOS_RequestDevicePropValue,             "CANON_EOS_RequestDevicePropValue" },
    { PTP_OC_CANON_EOS_RemoteReleaseOn,                 "CANON_EOS_RemoteReleaseOn" },
    { PTP_OC_CANON_EOS_RemoteReleaseOff,                 "CANON_EOS_RemoteReleaseOff" },
    { PTP_OC_CANON_EOS_InitiateViewfinder,                 "CANON_EOS_InitiateViewfinder" },
    { PTP_OC_CANON_EOS_TerminateViewfinder,             "CANON_EOS_TerminateViewfinder" },
    { PTP_OC_CANON_EOS_GetViewFinderData,                 "CANON_EOS_GetViewFinderData" },
    { PTP_OC_CANON_EOS_DoAf,                             "CANON_EOS_DoAf" },
    { PTP_OC_CANON_EOS_DriveLens,                         "CANON_EOS_DriveLens" },
    { PTP_OC_CANON_EOS_DepthOfFieldPreview,             "CANON_EOS_DepthOfFieldPreview" },
    { PTP_OC_CANON_EOS_ClickWB,                             "CANON_EOS_ClickWB" },
    { PTP_OC_CANON_EOS_Zoom,                             "CANON_EOS_Zoom" },
    { PTP_OC_CANON_EOS_ZoomPosition,                     "CANON_EOS_ZoomPosition" },
    { PTP_OC_CANON_EOS_SetLiveAfFrame,                     "CANON_EOS_SetLiveAfFrame" },
    { PTP_OC_CANON_EOS_AfCancel,                         "CANON_EOS_AfCancel" },
    { PTP_OC_CANON_EOS_FAPIMessageTX,                     "CANON_EOS_FAPIMessageTX" },
    { PTP_OC_CANON_EOS_FAPIMessageRX,                     "CANON_EOS_FAPIMessageRX" },
    { PTP_OC_NIKON_GetProfileAllData,                     "NIKON_GetProfileAllData" },
    { PTP_OC_NIKON_SendProfileData,                     "NIKON_SendProfileData" },
    { PTP_OC_NIKON_SendProfileData,                     "NIKON_SendProfileData" },
    { PTP_OC_NIKON_DeleteProfile,                         "NIKON_DeleteProfile" },
    { PTP_OC_NIKON_SetProfileData,                         "NIKON_SetProfileData" },
    { PTP_OC_NIKON_AdvancedTransfer,                     "NIKON_AdvancedTransfer" },
    { PTP_OC_NIKON_GetFileInfoInBlock,                     "NIKON_GetFileInfoInBlock" },
    { PTP_OC_NIKON_Capture,                             "NIKON_Capture" },
    { PTP_OC_NIKON_AfDrive,                             "NIKON_AfDrive" },
    { PTP_OC_NIKON_SetControlMode,                         "NIKON_SetControlMode" },
    { PTP_OC_NIKON_DelImageSDRAM,                         "NIKON_DelImageSDRAM" },
    { PTP_OC_NIKON_GetLargeThumb,                         "NIKON_GetLargeThumb" },
    { PTP_OC_NIKON_CurveDownload,                         "NIKON_CurveDownload" },
    { PTP_OC_NIKON_CurveUpload,                         "NIKON_CurveUpload" },
    { PTP_OC_NIKON_CheckEvent,                             "NIKON_CheckEvent" },
    { PTP_OC_NIKON_DeviceReady,                         "NIKON_DeviceReady" },
    { PTP_OC_NIKON_SetPreWBData,                         "NIKON_SetPreWBData" },
    { PTP_OC_NIKON_GetVendorPropCodes,                     "NIKON_GetVendorPropCodes" },
    { PTP_OC_NIKON_AfCaptureSDRAM,                         "NIKON_AfCaptureSDRAM" },
    { PTP_OC_NIKON_GetPictCtrlData,                     "NIKON_GetPictCtrlData" },
    { PTP_OC_NIKON_SetPictCtrlData,                     "NIKON_SetPictCtrlData" },
    { PTP_OC_NIKON_DelCstPicCtrl,                         "NIKON_DelCstPicCtrl" },
    { PTP_OC_NIKON_GetPicCtrlCapability,                 "NIKON_GetPicCtrlCapability" },
    { PTP_OC_NIKON_GetPreviewImg,                         "NIKON_GetPreviewImg" },
    { PTP_OC_NIKON_StartLiveView,                         "NIKON_StartLiveView" },
    { PTP_OC_NIKON_EndLiveView,                         "NIKON_EndLiveView" },
    { PTP_OC_NIKON_GetLiveViewImg,                         "NIKON_GetLiveViewImg" },
    { PTP_OC_NIKON_MfDrive,                             "NIKON_MfDrive" },
    { PTP_OC_NIKON_ChangeAfArea,                         "NIKON_ChangeAfArea" },
    { PTP_OC_NIKON_AfDriveCancel,                         "NIKON_AfDriveCancel" },
    { PTP_OC_NIKON_GetDevicePTPIPInfo,                     "NIKON_GetDevicePTPIPInfo" },
    { PTP_OC_CASIO_STILL_START,                         "CASIO_STILL_START" },
    { PTP_OC_CASIO_STILL_STOP,                             "CASIO_STILL_STOP" },
    { PTP_OC_CASIO_FOCUS,                                 "CASIO_FOCUS" },
    { PTP_OC_CASIO_CF_PRESS,                             "CASIO_CF_PRESS" },
    { PTP_OC_CASIO_CF_RELEASE,                             "CASIO_CF_RELEASE" },
    { PTP_OC_CASIO_GET_OBJECT_INFO,                         "CASIO_GET_OBJECT_INFO" },
    { PTP_OC_CASIO_SHUTTER,                             "CASIO_SHUTTER" },
    { PTP_OC_CASIO_GET_STILL_HANDLES,                     "CASIO_GET_STILL_HANDLES" },
    { PTP_OC_CASIO_STILL_RESET,                         "CASIO_STILL_RESET" },
    { PTP_OC_CASIO_HALF_PRESS,                             "CASIO_HALF_PRESS" },
    { PTP_OC_CASIO_HALF_RELEASE,                         "CASIO_HALF_RELEASE" },
    { PTP_OC_CASIO_CS_PRESS,                             "CASIO_CS_PRESS" },
    { PTP_OC_CASIO_CS_RELEASE,                             "CASIO_CS_RELEASE" },
    { PTP_OC_CASIO_ZOOM,                                 "CASIO_ZOOM" },
    { PTP_OC_CASIO_CZ_PRESS,                             "CASIO_CZ_PRESS" },
    { PTP_OC_CASIO_CZ_RELEASE,                             "CASIO_CZ_RELEASE" },
    { PTP_OC_CASIO_MOVIE_START,                         "CASIO_MOVIE_START" },
    { PTP_OC_CASIO_MOVIE_STOP,                             "CASIO_MOVIE_STOP" },
    { PTP_OC_CASIO_MOVIE_PRESS,                         "CASIO_MOVIE_PRESS" },
    { PTP_OC_CASIO_MOVIE_RELEASE,                         "CASIO_MOVIE_RELEASE" },
    { PTP_OC_CASIO_GET_MOVIE_HANDLES,                     "CASIO_GET_MOVIE_HANDLES" },
    { PTP_OC_CASIO_MOVIE_RESET,                         "CASIO_MOVIE_RESET" },
    { PTP_OC_CASIO_GET_OBJECT,                             "CASIO_GET_OBJECT" },
    { PTP_OC_CASIO_GET_THUMBNAIL,                         "CASIO_GET_THUMBNAIL" },
    { PTP_OC_MTP_GetObjectPropsSupported,                 "MTP_GetObjectPropsSupported" },
    { PTP_OC_MTP_GetObjectPropDesc,                     "MTP_GetObjectPropDesc" },
    { PTP_OC_MTP_GetObjectPropValue,                     "MTP_GetObjectPropValue" },
    { PTP_OC_MTP_SetObjectPropValue,                     "MTP_SetObjectPropValue" },
    { PTP_OC_MTP_GetObjPropList,                         "MTP_GetObjPropList" },
    { PTP_OC_MTP_SetObjPropList,                         "MTP_SetObjPropList" },
    { PTP_OC_MTP_GetInterdependendPropdesc,             "MTP_GetInterdependendPropdesc" },
    { PTP_OC_MTP_SendObjectPropList,                     "MTP_SendObjectPropList" },
    { PTP_OC_MTP_GetObjectReferences,                     "MTP_GetObjectReferences" },
    { PTP_OC_MTP_SetObjectReferences,                     "MTP_SetObjectReferences" },
    { PTP_OC_MTP_UpdateDeviceFirmware,                     "MTP_UpdateDeviceFirmware" },
    { PTP_OC_MTP_Skip,                                     "MTP_Skip" },
    { PTP_OC_MTP_WMDRMPD_GetSecureTimeChallenge,        "MTP_WMDRMPD_GetSecureTimeChallenge" },
    { PTP_OC_MTP_WMDRMPD_GetSecureTimeResponse,         "MTP_WMDRMPD_GetSecureTimeResponse" },
    { PTP_OC_MTP_WMDRMPD_SetLicenseResponse,             "MTP_WMDRMPD_SetLicenseResponse" },
    { PTP_OC_MTP_WMDRMPD_GetSyncList,                     "MTP_WMDRMPD_GetSyncList" },
    { PTP_OC_MTP_WMDRMPD_SendMeterChallengeQuery,        "MTP_WMDRMPD_SendMeterChallengeQuery" },
    { PTP_OC_MTP_WMDRMPD_GetMeterChallenge,             "MTP_WMDRMPD_GetMeterChallenge" },
    { PTP_OC_MTP_WMDRMPD_SetMeterResponse,                 "MTP_WMDRMPD_SetMeterResponse" },
    { PTP_OC_MTP_WMDRMPD_CleanDataStore,                 "MTP_WMDRMPD_CleanDataStore" },
    { PTP_OC_MTP_WMDRMPD_GetLicenseState,                 "MTP_WMDRMPD_GetLicenseState" },
    { PTP_OC_MTP_WMDRMPD_SendWMDRMPDCommand,             "MTP_WMDRMPD_SendWMDRMPDCommand" },
    { PTP_OC_MTP_WMDRMPD_SendWMDRMPDRequest,             "MTP_WMDRMPD_SendWMDRMPDRequest" },
    { PTP_OC_MTP_WMDRMPD_SendWMDRMPDAppRequest,         "MTP_WMDRMPD_SendWMDRMPDAppRequest" },
    { PTP_OC_MTP_WMDRMPD_GetWMDRMPDAppResponse,         "MTP_WMDRMPD_GetWMDRMPDAppResponse" },
    { PTP_OC_MTP_WMDRMPD_EnableTrustedFilesOperations,     "MTP_WMDRMPD_EnableTrustedFilesOperations" },
    { PTP_OC_MTP_WMDRMPD_DisableTrustedFilesOperations, "MTP_WMDRMPD_DisableTrustedFilesOperations" },
    { PTP_OC_MTP_WMDRMPD_EndTrustedAppSession,             "MTP_WMDRMPD_EndTrustedAppSession" },
    { PTP_OC_MTP_AAVT_OpenMediaSession,                 "MTP_AAVT_OpenMediaSession" },
    { PTP_OC_MTP_AAVT_CloseMediaSession,                 "MTP_AAVT_CloseMediaSession" },
    { PTP_OC_MTP_AAVT_GetNextDataBlock,                 "MTP_AAVT_GetNextDataBlock" },
    { PTP_OC_MTP_AAVT_SetCurrentTimePosition,             "MTP_AAVT_SetCurrentTimePosition" },
    { PTP_OC_MTP_WMDRMND_SendRegistrationRequest,         "MTP_WMDRMND_SendRegistrationRequest" },
    { PTP_OC_MTP_WMDRMND_GetRegistrationResponse,         "MTP_WMDRMND_GetRegistrationResponse" },
    { PTP_OC_MTP_WMDRMND_GetProximityChallenge,         "MTP_WMDRMND_GetProximityChallenge" },
    { PTP_OC_MTP_WMDRMND_SendProximityResponse,         "MTP_WMDRMND_SendProximityResponse" },
    { PTP_OC_MTP_WMDRMND_SendWMDRMNDLicenseRequest,     "MTP_WMDRMND_SendWMDRMNDLicenseRequest" },
    { PTP_OC_MTP_WMDRMND_GetWMDRMNDLicenseResponse,     "MTP_WMDRMND_GetWMDRMNDLicenseResponse" },
    { PTP_OC_MTP_WMPPD_ReportAddedDeletedItems,         "MTP_WMPPD_ReportAddedDeletedItems" },
    { PTP_OC_MTP_WMPPD_ReportAcquiredItems,             "MTP_WMPPD_ReportAcquiredItems" },
    { PTP_OC_MTP_WMPPD_PlaylistObjectPref,                 "MTP_WMPPD_PlaylistObjectPref" },
    { PTP_OC_MTP_ZUNE_GETUNDEFINED001,                     "MTP_ZUNE_GETUNDEFINED001" },
    { PTP_OC_MTP_WPDWCN_ProcessWFCObject,                 "MTP_WPDWCN_ProcessWFCObject" },
    { PTP_OC_OLYMPUS_Capture,                             "OLYMPUS_Capture" },
    { PTP_OC_OLYMPUS_SelfCleaning,                         "OLYMPUS_SelfCleaning" },
    { PTP_OC_OLYMPUS_SetRGBGain,                         "OLYMPUS_SetRGBGain" },
    { PTP_OC_OLYMPUS_SetPresetMode,                     "OLYMPUS_SetPresetMode" },
    { PTP_OC_OLYMPUS_SetWBBiasAll,                         "OLYMPUS_SetWBBiasAll" },
    { PTP_OC_OLYMPUS_GetCameraControlMode,                 "OLYMPUS_GetCameraControlMode" },
    { PTP_OC_OLYMPUS_SetCameraControlMode,                 "OLYMPUS_SetCameraControlMode" },
    { PTP_OC_OLYMPUS_SetWBRGBGain,                         "OLYMPUS_SetWBRGBGain" },
    { PTP_OC_OLYMPUS_GetDeviceInfo,                     "OLYMPUS_GetDeviceInfo" },
    { PTP_OC_OLYMPUS_Init1,                             "OLYMPUS_Init1" },
    { PTP_OC_OLYMPUS_SetDateTime,                         "OLYMPUS_SetDateTime" },
    { PTP_OC_OLYMPUS_GetDateTime,                         "OLYMPUS_GetDateTim" },
    { PTP_OC_OLYMPUS_SetCameraID,                         "OLYMPUS_SetCameraID" },
    { PTP_OC_OLYMPUS_GetCameraID,                         "OLYMPUS_GetCameraID" },
    { PTP_OC_EXTENSION_MASK,                             "EXTENSION_MASK" },
    { PTP_OC_EXTENSION,                                 "EXTENSION" },
    { PTP_OC_Undefined,                                 "Undefined" },
    { 0,                                                 NULL }

};


/*
 * String Names of packet types [3] & [4]
 * Response codes 0x2000 - 0x2023 defined in Table 27 of [2]
 * Remainder of Response codes from [4]. Enums reformatted from [4] ptp.h*/
/* Response Codes */
typedef enum {
    /* PTP v1.0 response codes */
    PTP_RC_Undefined                = 0x2000,
    PTP_RC_OK                       = 0x2001,
    PTP_RC_GeneralError             = 0x2002,
    PTP_RC_SessionNotOpen           = 0x2003,
    PTP_RC_InvalidTransactionID     = 0x2004,
    PTP_RC_OperationNotSupported    = 0x2005,
    PTP_RC_ParameterNotSupported    = 0x2006,
    PTP_RC_IncompleteTransfer       = 0x2007,
    PTP_RC_InvalidStorageId         = 0x2008,
    PTP_RC_InvalidObjectHandle      = 0x2009,
    PTP_RC_DevicePropNotSupported   = 0x200A,
    PTP_RC_InvalidObjectFormatCode  = 0x200B,
    PTP_RC_StoreFull                = 0x200C,
    PTP_RC_ObjectWriteProtected     = 0x200D,
    PTP_RC_StoreReadOnly            = 0x200E,
    PTP_RC_AccessDenied             = 0x200F,
    PTP_RC_NoThumbnailPresent       = 0x2010,
    PTP_RC_SelfTestFailed           = 0x2011,
    PTP_RC_PartialDeletion          = 0x2012,
    PTP_RC_StoreNotAvailable        = 0x2013,
    PTP_RC_SpecificationByFormatUnsupported        = 0x2014,
    PTP_RC_NoValidObjectInfo        = 0x2015,
    PTP_RC_InvalidCodeFormat        = 0x2016,
    PTP_RC_UnknownVendorCode        = 0x2017,
    PTP_RC_CaptureAlreadyTerminated = 0x2018,
    PTP_RC_DeviceBusy               = 0x2019,
    PTP_RC_InvalidParentObject      = 0x201A,
    PTP_RC_InvalidDevicePropFormat  = 0x201B,
    PTP_RC_InvalidDevicePropValue   = 0x201C,
    PTP_RC_InvalidParameter         = 0x201D,
    PTP_RC_SessionAlreadyOpened     = 0x201E,
    PTP_RC_TransactionCanceled      = 0x201F,
    PTP_RC_SpecificationOfDestinationUnsupported           = 0x2020,
    /* PTP v1.1 response codes */
    PTP_RC_InvalidEnumHandle        = 0x2021,
    PTP_RC_NoStreamEnabled            = 0x2022,
    PTP_RC_InvalidDataSet            = 0x2023,

    /* Eastman Kodak extension Response Codes */
    PTP_RC_EK_FilenameRequired    = 0xA001,
    PTP_RC_EK_FilenameConflicts = 0xA002,
    PTP_RC_EK_FilenameInvalid    = 0xA003,

    /* Nikon specific response codes */
    PTP_RC_NIKON_HardwareError        = 0xA001,
    PTP_RC_NIKON_OutOfFocus            = 0xA002,
    PTP_RC_NIKON_ChangeCameraModeFailed    = 0xA003,
    PTP_RC_NIKON_InvalidStatus        = 0xA004,
    PTP_RC_NIKON_SetPropertyNotSupported    = 0xA005,
    PTP_RC_NIKON_WbResetError        = 0xA006,
    PTP_RC_NIKON_DustReferenceError        = 0xA007,
    PTP_RC_NIKON_ShutterSpeedBulb        = 0xA008,
    PTP_RC_NIKON_MirrorUpSequence        = 0xA009,
    PTP_RC_NIKON_CameraModeNotAdjustFNumber     =0xA00A,
    PTP_RC_NIKON_NotLiveView        = 0xA00B,
    PTP_RC_NIKON_MfDriveStepEnd        = 0xA00C,
    PTP_RC_NIKON_MfDriveStepInsufficiency    = 0xA00E,
    PTP_RC_NIKON_AdvancedTransferCancel    = 0xA022,

    /* Canon specific response codes */
    PTP_RC_CANON_UNKNOWN_COMMAND        = 0xA001,
    PTP_RC_CANON_OPERATION_REFUSED        = 0xA005,
    PTP_RC_CANON_LENS_COVER                = 0xA006,
    PTP_RC_CANON_BATTERY_LOW            = 0xA101,
    PTP_RC_CANON_NOT_READY                = 0xA102,
    PTP_RC_CANON_A009                    = 0xA009,
    /* Microsoft/MTP specific codes */
    PTP_RC_MTP_Undefined                = 0xA800,
    PTP_RC_MTP_Invalid_ObjectPropCode    = 0xA801,
    PTP_RC_MTP_Invalid_ObjectProp_Format    = 0xA802,
    PTP_RC_MTP_Invalid_ObjectProp_Value    = 0xA803,
    PTP_RC_MTP_Invalid_ObjectReference    = 0xA804,
    PTP_RC_MTP_Invalid_Dataset            = 0xA806,
    PTP_RC_MTP_Specification_By_Group_Unsupported        = 0xA807,
    PTP_RC_MTP_Specification_By_Depth_Unsupported        = 0xA808,
    PTP_RC_MTP_Object_Too_Large        = 0xA809,
    PTP_RC_MTP_ObjectProp_Not_Supported    = 0xA80A,

    /* Microsoft Advanced Audio/Video Transfer response codes
    (microsoft.com/AAVT 1.0) */
    PTP_RC_MTP_Invalid_Media_Session_ID        = 0xA170,
    PTP_RC_MTP_Media_Session_Limit_Reached    = 0xA171,
    PTP_RC_MTP_No_More_Data                    = 0xA172,

    /* WiFi Provisioning MTP Extension Error Codes (microsoft.com/WPDWCN: 1.0) */
    PTP_RC_MTP_Invalid_WFC_Syntax            = 0xA121,
    PTP_RC_MTP_WFC_Version_Not_Supported    = 0xA122

} ptp_respcodes;

static const value_string ptp_respcode_names[] = {
    { PTP_RC_OK,                                         "OK" },
    { PTP_RC_GeneralError,                                 "GeneralError" },
    { PTP_RC_SessionNotOpen,                             "SessionNotOpen" },
    { PTP_RC_InvalidTransactionID,                         "InvalidTransactionID" },
    { PTP_RC_OperationNotSupported,                     "OperationNotSupported" },
    { PTP_RC_ParameterNotSupported,                     "ParameterNotSupported" },
    { PTP_RC_IncompleteTransfer,                         "IncompleteTransfer" },
    { PTP_RC_InvalidStorageId,                             "InvalidStorageId" },
    { PTP_RC_InvalidObjectHandle,                         "InvalidObjectHandle" },
    { PTP_RC_DevicePropNotSupported,                     "DevicePropNotSupported" },
    { PTP_RC_InvalidObjectFormatCode,                     "InvalidObjectFormatCode" },
    { PTP_RC_StoreFull,                                 "StoreFull" },
    { PTP_RC_StoreReadOnly,                             "StoreReadOnly" },
    { PTP_RC_AccessDenied,                                 "AccessDenied" },
    { PTP_RC_NoThumbnailPresent,                         "NoThumbnailPresent" },
    { PTP_RC_SelfTestFailed,                             "SelfTestFailed" },
    { PTP_RC_PartialDeletion,                             "PartialDeletion" },
    { PTP_RC_StoreNotAvailable,                         "StoreNotAvailable" },
    { PTP_RC_SpecificationByFormatUnsupported,             "SpecificationByFormatUnsupported" },
    { PTP_RC_NoValidObjectInfo,                         "NoValidObjectInfo" },
    { PTP_RC_InvalidCodeFormat,                         "InvalidCodeFormat" },
    { PTP_RC_UnknownVendorCode,                         "UnknownVendorCode" },
    { PTP_RC_CaptureAlreadyTerminated,                     "CaptureAlreadyTerminated" },
    { PTP_RC_DeviceBusy,                                 "DeviceBusy" },
    { PTP_RC_InvalidParentObject,                         "InvalidParentObject" },
    { PTP_RC_InvalidDevicePropFormat,                     "InvalidDevicePropFormat" },
    { PTP_RC_InvalidDevicePropValue,                     "InvalidDevicePropValue" },
    { PTP_RC_InvalidParameter,                             "InvalidParameter" },
    { PTP_RC_SessionAlreadyOpened,                         "SessionAlreadyOpened" },
    { PTP_RC_TransactionCanceled,                         "TransactionCanceled" },
    { PTP_RC_SpecificationOfDestinationUnsupported,     "SpecificationOfDestinationUnsupported" },
    { PTP_RC_InvalidEnumHandle,                         "InvalidEnumHandle" },
    { PTP_RC_NoStreamEnabled,                             "NoStreamEnabled" },
    { PTP_RC_InvalidDataSet,                             "InvalidDataSet" },
    { PTP_RC_EK_FilenameRequired,                         "EK_FilenameRequired" },
    { PTP_RC_EK_FilenameConflicts,                         "EK_FilenameConflicts" },
    { PTP_RC_EK_FilenameInvalid,                         "EK_FilenameInvalid" },
    { PTP_RC_NIKON_HardwareError,                         "NIKON_HardwareError" },
    { PTP_RC_NIKON_OutOfFocus,                             "NIKON_OutOfFocus" },
    { PTP_RC_NIKON_ChangeCameraModeFailed,                 "NIKON_ChangeCameraModeFailed" },
    { PTP_RC_NIKON_InvalidStatus,                         "NIKON_InvalidStatus" },
    { PTP_RC_NIKON_SetPropertyNotSupported,             "NIKON_SetPropertyNotSupported" },
    { PTP_RC_NIKON_WbResetError,                         "NIKON_WbResetError" },
    { PTP_RC_NIKON_DustReferenceError,                     "NIKON_DustReferenceError" },
    { PTP_RC_NIKON_ShutterSpeedBulb,                     "NIKON_ShutterSpeedBulb" },
    { PTP_RC_NIKON_MirrorUpSequence,                     "NIKON_MirrorUpSequence" },
    { PTP_RC_NIKON_CameraModeNotAdjustFNumber,             "NIKON_CameraModeNotAdjustFNumber" },
    { PTP_RC_NIKON_NotLiveView,                         "NIKON_NotLiveView" },
    { PTP_RC_NIKON_MfDriveStepEnd,                         "NIKON_MfDriveStepEnd" },
    { PTP_RC_NIKON_MfDriveStepInsufficiency,             "NIKON_MfDriveStepInsufficiency" },
    { PTP_RC_NIKON_AdvancedTransferCancel,                 "NIKON_AdvancedTransferCancel" },
    { PTP_RC_CANON_UNKNOWN_COMMAND,                     "CANON_UNKNOWN_COMMAND" },
    { PTP_RC_CANON_OPERATION_REFUSED,                     "CANON_OPERATION_REFUSED" },
    { PTP_RC_CANON_LENS_COVER,                             "CANON_LENS_COVER" },
    { PTP_RC_CANON_BATTERY_LOW,                         "CANON_BATTERY_LOW" },
    { PTP_RC_CANON_NOT_READY,                             "CANON_NOT_READY" },
    { PTP_RC_CANON_A009,                                 "CANON_A009" },
    { PTP_RC_MTP_Undefined,                             "MTP_Undefined" },
    { PTP_RC_MTP_Invalid_ObjectPropCode,                 "MTP_Invalid_ObjectPropCode" },
    { PTP_RC_MTP_Invalid_ObjectProp_Format,             "MTP_Invalid_ObjectProp_Format" },
    { PTP_RC_MTP_Invalid_ObjectProp_Value,                 "MTP_Invalid_ObjectProp_Value" },
    { PTP_RC_MTP_Invalid_ObjectReference,                 "MTP_Invalid_ObjectReference" },
    { PTP_RC_MTP_Invalid_Dataset,                         "MTP_Invalid_Dataset" },
    { PTP_RC_MTP_Specification_By_Group_Unsupported,    "MTP_Specification_By_Group_Unsupported" },
    { PTP_RC_MTP_Specification_By_Depth_Unsupported,    "MTP_Specification_By_Depth_Unsupported" },
    { PTP_RC_MTP_Object_Too_Large,                         "MTP_Object_Too_Large" },
    { PTP_RC_MTP_ObjectProp_Not_Supported,                 "MTP_ObjectProp_Not_Supported" },
    { PTP_RC_MTP_Invalid_Media_Session_ID,                 "MTP_Invalid_Media_Session_ID" },
    { PTP_RC_MTP_Media_Session_Limit_Reached,             "MTP_Media_Session_Limit_Reached" },
    { PTP_RC_MTP_No_More_Data,                             "MTP_No_More_Data" },
    { PTP_RC_MTP_Invalid_WFC_Syntax,                     "MTP_Invalid_WFC_Syntax" },
    { PTP_RC_MTP_WFC_Version_Not_Supported,             "MTP_WFC_Version_Not_Supported" },
    { PTP_RC_Undefined,                                 "Undefined" },
    { 0,                                                 NULL }
};



/* function prototypes */
void dissect_ptp_opCode_openSession(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptp_transactionID(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);

