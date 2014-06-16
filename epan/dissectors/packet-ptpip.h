/* packet-ptpip.h
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
 */

/* PTP Definitions */
/* String Names of packet types [3] & [4]
 *  Opcode 0x1000 - 0x1025 defined in Table 22 of [2]
 *  Remainder of Opcodes from [4]. Enums reformatted from [4] ptp.h
 */
typedef enum {
    /* PTP v1.0 operation codes */
    PTP_OC_Undefined                                 = 0x1000,
    PTP_OC_GetDeviceInfo                             = 0x1001,
    PTP_OC_OpenSession                               = 0x1002,
    PTP_OC_CloseSession                              = 0x1003,
    PTP_OC_GetStorageIDs                             = 0x1004,
    PTP_OC_GetStorageInfo                            = 0x1005,
    PTP_OC_GetNumObjects                             = 0x1006,
    PTP_OC_GetObjectHandles                          = 0x1007,
    PTP_OC_GetObjectInfo                             = 0x1008,
    PTP_OC_GetObject                                 = 0x1009,
    PTP_OC_GetThumb                                  = 0x100A,
    PTP_OC_DeleteObject                              = 0x100B,
    PTP_OC_SendObjectInfo                            = 0x100C,
    PTP_OC_SendObject                                = 0x100D,
    PTP_OC_InitiateCapture                           = 0x100E,
    PTP_OC_FormatStore                               = 0x100F,
    PTP_OC_ResetDevice                               = 0x1010,
    PTP_OC_SelfTest                                  = 0x1011,
    PTP_OC_SetObjectProtection                       = 0x1012,
    PTP_OC_PowerDown                                 = 0x1013,
    PTP_OC_GetDevicePropDesc                         = 0x1014,
    PTP_OC_GetDevicePropValue                        = 0x1015,
    PTP_OC_SetDevicePropValue                        = 0x1016,
    PTP_OC_ResetDevicePropValue                      = 0x1017,
    PTP_OC_TerminateOpenCapture                      = 0x1018,
    PTP_OC_MoveObject                                = 0x1019,
    PTP_OC_CopyObject                                = 0x101A,
    PTP_OC_GetPartialObject                          = 0x101B,
    PTP_OC_InitiateOpenCapture                       = 0x101C,
    /* PTP v1.1 operation codes */
    PTP_OC_StartEnumHandles                          = 0x101D,
    PTP_OC_EnumHandles                               = 0x101E,
    PTP_OC_StopEnumHandles                           = 0x101F,
    PTP_OC_GetVendorExtensionMaps                    = 0x1020,
    PTP_OC_GetVendorDeviceInfo                       = 0x1021,
    PTP_OC_GetResizedImageObject                     = 0x1022,
    PTP_OC_GetFilesystemManifest                     = 0x1023,
    PTP_OC_GetStreamInfo                             = 0x1024,
    PTP_OC_GetStream                                 = 0x1025,

    /* Eastman Kodak extension Operation Codes */
    PTP_OC_EK_GetSerial                              = 0x9003,
    PTP_OC_EK_SetSerial                              = 0x9004,
    PTP_OC_EK_SendFileObjectInfo                     = 0x9005,
    PTP_OC_EK_SendFileObject                         = 0x9006,
    PTP_OC_EK_SetText                                = 0x9008,

    /* Canon extension Operation Codes */
    PTP_OC_CANON_GetPartialObjectInfo                = 0x9001,
    /* 9002 - sends 2 uint32, nothing back  */
    PTP_OC_CANON_SetObjectArchive                    = 0x9002,
    PTP_OC_CANON_KeepDeviceOn                        = 0x9003,
    PTP_OC_CANON_LockDeviceUI                        = 0x9004,
    PTP_OC_CANON_UnlockDeviceUI                      = 0x9005,
    PTP_OC_CANON_GetObjectHandleByName               = 0x9006,
    /* no 9007 observed yet */
    PTP_OC_CANON_InitiateReleaseControl              = 0x9008,
    PTP_OC_CANON_TerminateReleaseControl             = 0x9009,
    PTP_OC_CANON_TerminatePlaybackMode               = 0x900A,
    PTP_OC_CANON_ViewfinderOn                        = 0x900B,
    PTP_OC_CANON_ViewfinderOff                       = 0x900C,
    PTP_OC_CANON_DoAeAfAwb                           = 0x900D,

     /* 900e - send nothing, gets 5 uint16t in 32bit entities back in 20byte datablob */
    PTP_OC_CANON_GetCustomizeSpec                    = 0x900E,
    PTP_OC_CANON_GetCustomizeItemInfo                = 0x900F,
    PTP_OC_CANON_GetCustomizeData                    = 0x9010,
    PTP_OC_CANON_SetCustomizeData                    = 0x9011,
    PTP_OC_CANON_GetCaptureStatus                    = 0x9012,
    PTP_OC_CANON_CheckEvent                          = 0x9013,
    PTP_OC_CANON_FocusLock                           = 0x9014,
    PTP_OC_CANON_FocusUnlock                         = 0x9015,
    PTP_OC_CANON_GetLocalReleaseParam                = 0x9016,
    PTP_OC_CANON_SetLocalReleaseParam                = 0x9017,
    PTP_OC_CANON_AskAboutPcEvf                       = 0x9018,
    PTP_OC_CANON_SendPartialObject                   = 0x9019,
    PTP_OC_CANON_InitiateCaptureInMemory             = 0x901A,
    PTP_OC_CANON_GetPartialObjectEx                  = 0x901B,
    PTP_OC_CANON_SetObjectTime                       = 0x901C,
    PTP_OC_CANON_GetViewfinderImage                  = 0x901D,
    PTP_OC_CANON_GetObjectAttributes                 = 0x901E,
    PTP_OC_CANON_ChangeUSBProtocol                   = 0x901F,
    PTP_OC_CANON_GetChanges                          = 0x9020,
    PTP_OC_CANON_GetObjectInfoEx                     = 0x9021,
    PTP_OC_CANON_InitiateDirectTransfer              = 0x9022,
    PTP_OC_CANON_TerminateDirectTransfer             = 0x9023,
    PTP_OC_CANON_SendObjectInfoByPath                = 0x9024,
    PTP_OC_CANON_SendObjectByPath                    = 0x9025,
    PTP_OC_CANON_InitiateDirectTansferEx             = 0x9026,
    PTP_OC_CANON_GetAncillaryObjectHandles           = 0x9027,
    PTP_OC_CANON_GetTreeInfo                         = 0x9028,
    PTP_OC_CANON_GetTreeSize                         = 0x9029,
    PTP_OC_CANON_NotifyProgress                      = 0x902A,
    PTP_OC_CANON_NotifyCancelAccepted                = 0x902B,
    /* 902c: no parms, read 3 uint32 in data, no response parms */
    PTP_OC_CANON_902C                                = 0x902C,
    PTP_OC_CANON_GetDirectory                        = 0x902D,
    PTP_OC_CANON_SetPairingInfo                      = 0x9030,
    PTP_OC_CANON_GetPairingInfo                      = 0x9031,
    PTP_OC_CANON_DeletePairingInfo                   = 0x9032,
    PTP_OC_CANON_GetMACAddress                       = 0x9033,
   /* 9034: 1 param, no parms returned */
    PTP_OC_CANON_SetDisplayMonitor                   = 0x9034,
    PTP_OC_CANON_PairingComplete                     = 0x9035,
    PTP_OC_CANON_GetWirelessMAXChannel               = 0x9036,
   /* 9101: no args, 8 byte data (01 00 00 00 00 00 00 00), no resp data. */
    PTP_OC_CANON_EOS_GetStorageIDs                   = 0x9101,
   /* 9102: 1 arg (0)
    * = 0x28 bytes of data:
        00000000: 34 00 00 00 02 00 02 91 0a 00 00 00 04 00 03 00
        00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00000020: 00 00 ff ff ff ff 03 43 00 46 00 00 00 03 41 00
        00000030: 3a 00 00 00
    * no resp args
    */
    PTP_OC_CANON_EOS_GetStorageInfo                  = 0x9102,
    PTP_OC_CANON_EOS_GetObjectInfo                   = 0x9103,
    PTP_OC_CANON_EOS_GetObject                       = 0x9104,
    PTP_OC_CANON_EOS_DeleteObject                    = 0x9105,
    PTP_OC_CANON_EOS_FormatStore                     = 0x9106,
    PTP_OC_CANON_EOS_GetPartialObject                = 0x9107,
    PTP_OC_CANON_EOS_GetDeviceInfoEx                 = 0x9108,

   /* sample1:
    * 3 cmdargs: 1, = 0xffffffff,00 00 10 00;
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
    PTP_OC_CANON_EOS_GetObjectInfoEx                 = 0x9109,
    PTP_OC_CANON_EOS_GetThumbEx                      = 0x910A,
    PTP_OC_CANON_EOS_SendPartialObject               = 0x910B,
    PTP_OC_CANON_EOS_SetObjectAttributes             = 0x910C,
    PTP_OC_CANON_EOS_GetObjectTime                   = 0x910D,
    PTP_OC_CANON_EOS_SetObjectTime                   = 0x910E,

    /* 910f: no args, no data, 1 response arg (0). */
    PTP_OC_CANON_EOS_RemoteRelease                   = 0x910F,
    /* Marcus: looks more like "Set DeviceProperty" in the trace.
    *
    * no cmd args
    * data phase ( = 0xc, = 0xd11c, = 0x1)
    * no resp args
    */
    PTP_OC_CANON_EOS_SetDevicePropValueEx            = 0x9110,
    PTP_OC_CANON_EOS_GetRemoteMode                   = 0x9113,
    /* 9114: 1 arg (                                 = 0x1), no data, no resp data. */
    PTP_OC_CANON_EOS_SetRemoteMode                   = 0x9114,
    /* 9115: 1 arg (                                 = 0x1), no data, no resp data. */
    PTP_OC_CANON_EOS_SetEventMode                    = 0x9115,
    /* 9116: no args, data phase, no resp data. */
    PTP_OC_CANON_EOS_GetEvent                        = 0x9116,
    PTP_OC_CANON_EOS_TransferComplete                = 0x9117,
    PTP_OC_CANON_EOS_CancelTransfer                  = 0x9118,
    PTP_OC_CANON_EOS_ResetTransfer                   = 0x9119,

    /* 911a: 3 args ( = 0xfffffff7, = 0x00001000, = 0x00000001), no data, no resp data. */
    /* 911a: 3 args ( = 0x001dfc60, = 0x00001000, = 0x00000001), no data, no resp data. */
    PTP_OC_CANON_EOS_PCHDDCapacity                   = 0x911A,

    /* 911b: no cmd args, no data, no resp args */
    PTP_OC_CANON_EOS_SetUILock                       = 0x911B,
    /* 911c: no cmd args, no data, no resp args */
    PTP_OC_CANON_EOS_ResetUILock                     = 0x911C,
    PTP_OC_CANON_EOS_KeepDeviceOn                    = 0x911D,
    PTP_OC_CANON_EOS_SetNullPacketMode               = 0x911E,
    PTP_OC_CANON_EOS_UpdateFirmware                  = 0x911F,
    PTP_OC_CANON_EOS_TransferCompleteDT              = 0x9120,
    PTP_OC_CANON_EOS_CancelTransferDT                = 0x9121,
    PTP_OC_CANON_EOS_SetWftProfile                   = 0x9122,
    PTP_OC_CANON_EOS_GetWftProfile                   = 0x9123,
    PTP_OC_CANON_EOS_SetProfileToWft                 = 0x9124,
    PTP_OC_CANON_EOS_BulbStart                       = 0x9125,
    PTP_OC_CANON_EOS_BulbEnd                         = 0x9126,
    PTP_OC_CANON_EOS_RequestDevicePropValue          = 0x9127,

    /* = 0x9128 args (= 0x1/= 0x2, = 0x0), no data, no resp args */
    PTP_OC_CANON_EOS_RemoteReleaseOn                 = 0x9128,
    /* = 0x9129 args (= 0x1/= 0x2), no data, no resp args */
    PTP_OC_CANON_EOS_RemoteReleaseOff                = 0x9129,
    PTP_OC_CANON_EOS_InitiateViewfinder              = 0x9151,
    PTP_OC_CANON_EOS_TerminateViewfinder             = 0x9152,
    PTP_OC_CANON_EOS_GetViewFinderData               = 0x9153,
    PTP_OC_CANON_EOS_DoAf                            = 0x9154,
    PTP_OC_CANON_EOS_DriveLens                       = 0x9155,
    PTP_OC_CANON_EOS_DepthOfFieldPreview             = 0x9156,
    PTP_OC_CANON_EOS_ClickWB                         = 0x9157,
    PTP_OC_CANON_EOS_Zoom                            = 0x9158,
    PTP_OC_CANON_EOS_ZoomPosition                    = 0x9159,
    PTP_OC_CANON_EOS_SetLiveAfFrame                  = 0x915a,
    PTP_OC_CANON_EOS_AfCancel                        = 0x9160,
    PTP_OC_CANON_EOS_FAPIMessageTX                   = 0x91FE,
    PTP_OC_CANON_EOS_FAPIMessageRX                   = 0x91FF,

    /* Nikon extension Operation Codes */
    PTP_OC_NIKON_GetProfileAllData                   = 0x9006,
    PTP_OC_NIKON_SendProfileData                     = 0x9007,
    PTP_OC_NIKON_DeleteProfile                       = 0x9008,
    PTP_OC_NIKON_SetProfileData                      = 0x9009,
    PTP_OC_NIKON_AdvancedTransfer                    = 0x9010,
    PTP_OC_NIKON_GetFileInfoInBlock                  = 0x9011,
    PTP_OC_NIKON_Capture                             = 0x90C0,    /* 1 param,   no data */
    PTP_OC_NIKON_AfDrive                             = 0x90C1,    /* no params, no data */
    PTP_OC_NIKON_SetControlMode                      = 0x90C2,    /* 1 param,   no data */
    PTP_OC_NIKON_DelImageSDRAM                       = 0x90C3,    /* no params, no data */
    PTP_OC_NIKON_GetLargeThumb                       = 0x90C4,
    PTP_OC_NIKON_CurveDownload                       = 0x90C5,    /* 1 param,   data in */
    PTP_OC_NIKON_CurveUpload                         = 0x90C6,    /* 1 param,   data out */
    PTP_OC_NIKON_CheckEvent                          = 0x90C7,    /* no params, data in */
    PTP_OC_NIKON_DeviceReady                         = 0x90C8,    /* no params, no data */
    PTP_OC_NIKON_SetPreWBData                        = 0x90C9,    /* 3 params,  data out */
    PTP_OC_NIKON_GetVendorPropCodes                  = 0x90CA,    /* 0 params, data in */
    PTP_OC_NIKON_AfCaptureSDRAM                      = 0x90CB,    /* no params, no data */
    PTP_OC_NIKON_GetPictCtrlData                     = 0x90CC,
    PTP_OC_NIKON_SetPictCtrlData                     = 0x90CD,
    PTP_OC_NIKON_DelCstPicCtrl                       = 0x90CE,
    PTP_OC_NIKON_GetPicCtrlCapability                = 0x90CF,

   /* Nikon Liveview stuff */
    PTP_OC_NIKON_GetPreviewImg                       = 0x9200,
    PTP_OC_NIKON_StartLiveView                       = 0x9201,
    PTP_OC_NIKON_EndLiveView                         = 0x9202,
    PTP_OC_NIKON_GetLiveViewImg                      = 0x9203,
    PTP_OC_NIKON_MfDrive                             = 0x9204,
    PTP_OC_NIKON_ChangeAfArea                        = 0x9205,
    PTP_OC_NIKON_AfDriveCancel                       = 0x9206,
    PTP_OC_NIKON_GetDevicePTPIPInfo                  = 0x90E0,

    /* Casio EX-F1 (from http://code.google.com/p/exf1ctrl/ ) */
    PTP_OC_CASIO_STILL_START                         = 0x9001,
    PTP_OC_CASIO_STILL_STOP                          = 0x9002,
    PTP_OC_CASIO_FOCUS                               = 0x9007,
    PTP_OC_CASIO_CF_PRESS                            = 0x9009,
    PTP_OC_CASIO_CF_RELEASE                          = 0x900A,
    PTP_OC_CASIO_GET_OBJECT_INFO                     = 0x900C,
    PTP_OC_CASIO_SHUTTER                             = 0x9024,
    PTP_OC_CASIO_GET_STILL_HANDLES                   = 0x9027,
    PTP_OC_CASIO_STILL_RESET                         = 0x9028,
    PTP_OC_CASIO_HALF_PRESS                          = 0x9029,
    PTP_OC_CASIO_HALF_RELEASE                        = 0x902A,
    PTP_OC_CASIO_CS_PRESS                            = 0x902B,
    PTP_OC_CASIO_CS_RELEASE                          = 0x902C,
    PTP_OC_CASIO_ZOOM                                = 0x902D,
    PTP_OC_CASIO_CZ_PRESS                            = 0x902E,
    PTP_OC_CASIO_CZ_RELEASE                          = 0x902F,
    PTP_OC_CASIO_MOVIE_START                         = 0x9041,
    PTP_OC_CASIO_MOVIE_STOP                          = 0x9042,
    PTP_OC_CASIO_MOVIE_PRESS                         = 0x9043,
    PTP_OC_CASIO_MOVIE_RELEASE                       = 0x9044,
    PTP_OC_CASIO_GET_MOVIE_HANDLES                   = 0x9045,
    PTP_OC_CASIO_MOVIE_RESET                         = 0x9046,
    PTP_OC_CASIO_GET_OBJECT                          = 0x9025,
    PTP_OC_CASIO_GET_THUMBNAIL                       = 0x9026,

    /* Microsoft / MTP extension codes */
    PTP_OC_MTP_GetObjectPropsSupported               = 0x9801,
    PTP_OC_MTP_GetObjectPropDesc                     = 0x9802,
    PTP_OC_MTP_GetObjectPropValue                    = 0x9803,
    PTP_OC_MTP_SetObjectPropValue                    = 0x9804,
    PTP_OC_MTP_GetObjPropList                        = 0x9805,
    PTP_OC_MTP_SetObjPropList                        = 0x9806,
    PTP_OC_MTP_GetInterdependendPropdesc             = 0x9807,
    PTP_OC_MTP_SendObjectPropList                    = 0x9808,
    PTP_OC_MTP_GetObjectReferences                   = 0x9810,
    PTP_OC_MTP_SetObjectReferences                   = 0x9811,
    PTP_OC_MTP_UpdateDeviceFirmware                  = 0x9812,
    PTP_OC_MTP_Skip                                  = 0x9820,

    /*
    * Windows Media Digital Rights Management for Portable Devices
    * Extension Codes (microsoft.com/WMDRMPD: 10.1)
    */
    PTP_OC_MTP_WMDRMPD_GetSecureTimeChallenge        = 0x9101,
    PTP_OC_MTP_WMDRMPD_GetSecureTimeResponse         = 0x9102,
    PTP_OC_MTP_WMDRMPD_SetLicenseResponse            = 0x9103,
    PTP_OC_MTP_WMDRMPD_GetSyncList                   = 0x9104,
    PTP_OC_MTP_WMDRMPD_SendMeterChallengeQuery       = 0x9105,
    PTP_OC_MTP_WMDRMPD_GetMeterChallenge             = 0x9106,
    PTP_OC_MTP_WMDRMPD_SetMeterResponse              = 0x9107,
    PTP_OC_MTP_WMDRMPD_CleanDataStore                = 0x9108,
    PTP_OC_MTP_WMDRMPD_GetLicenseState               = 0x9109,
    PTP_OC_MTP_WMDRMPD_SendWMDRMPDCommand            = 0x910A,
    PTP_OC_MTP_WMDRMPD_SendWMDRMPDRequest            = 0x910B,

    /*
    * Windows Media Digital Rights Management for Portable Devices
    * Extension Codes (microsoft.com/WMDRMPD: 10.1)
    * Below are operations that have no public documented identifier
    * associated with them "Vendor-defined Command Code"
    */
    PTP_OC_MTP_WMDRMPD_SendWMDRMPDAppRequest         = 0x9212,
    PTP_OC_MTP_WMDRMPD_GetWMDRMPDAppResponse         = 0x9213,
    PTP_OC_MTP_WMDRMPD_EnableTrustedFilesOperations  = 0x9214,
    PTP_OC_MTP_WMDRMPD_DisableTrustedFilesOperations = 0x9215,
    PTP_OC_MTP_WMDRMPD_EndTrustedAppSession          = 0x9216,
    /* ^^^ guess ^^^ */

    /*
    * Microsoft Advanced Audio/Video Transfer
    * Extensions (microsoft.com/AAVT: 1.0)
    */
    PTP_OC_MTP_AAVT_OpenMediaSession                 = 0x9170,
    PTP_OC_MTP_AAVT_CloseMediaSession                = 0x9171,
    PTP_OC_MTP_AAVT_GetNextDataBlock                 = 0x9172,
    PTP_OC_MTP_AAVT_SetCurrentTimePosition           = 0x9173,

    /*
    * Windows Media Digital Rights Management for Network Devices
    * Extensions (microsoft.com/WMDRMND: 1.0) MTP/IP?
    */
    PTP_OC_MTP_WMDRMND_SendRegistrationRequest       = 0x9180,
    PTP_OC_MTP_WMDRMND_GetRegistrationResponse       = 0x9181,
    PTP_OC_MTP_WMDRMND_GetProximityChallenge         = 0x9182,
    PTP_OC_MTP_WMDRMND_SendProximityResponse         = 0x9183,
    PTP_OC_MTP_WMDRMND_SendWMDRMNDLicenseRequest     = 0x9184,
    PTP_OC_MTP_WMDRMND_GetWMDRMNDLicenseResponse     = 0x9185,

    /*
    * Windows Media Player Portiable Devices
    * Extension Codes (microsoft.com/WMPPD: 11.1)
    */
    PTP_OC_MTP_WMPPD_ReportAddedDeletedItems         = 0x9201,
    PTP_OC_MTP_WMPPD_ReportAcquiredItems             = 0x9202,
    PTP_OC_MTP_WMPPD_PlaylistObjectPref              = 0x9203,

    /*
    * Undocumented Zune Operation Codes
    * maybe related to WMPPD extension set?
    */
    PTP_OC_MTP_ZUNE_GETUNDEFINED001                  = 0x9204,

   /* WiFi Provisioning MTP Extension Codes (microsoft.com/WPDWCN: 1.0) */
    PTP_OC_MTP_WPDWCN_ProcessWFCObject               = 0x9122,

   /* Olympus E series commands */
    PTP_OC_OLYMPUS_Capture                           = 0x9101,
    PTP_OC_OLYMPUS_SelfCleaning                      = 0x9103,
    PTP_OC_OLYMPUS_SetRGBGain                        = 0x9106,
    PTP_OC_OLYMPUS_SetPresetMode                     = 0x9107,
    PTP_OC_OLYMPUS_SetWBBiasAll                      = 0x9108,
    PTP_OC_OLYMPUS_GetCameraControlMode              = 0x910a,
    PTP_OC_OLYMPUS_SetCameraControlMode              = 0x910b,
    PTP_OC_OLYMPUS_SetWBRGBGain                      = 0x910c,
    PTP_OC_OLYMPUS_GetDeviceInfo                     = 0x9301,
    PTP_OC_OLYMPUS_Init1                             = 0x9302,
    PTP_OC_OLYMPUS_SetDateTime                       = 0x9402,
    PTP_OC_OLYMPUS_GetDateTime                       = 0x9482,
    PTP_OC_OLYMPUS_SetCameraID                       = 0x9501,
    PTP_OC_OLYMPUS_GetCameraID                       = 0x9581,

   /* Proprietary vendor extension operations mask */
    PTP_OC_EXTENSION_MASK                            = 0xF000,
    PTP_OC_EXTENSION                                 = 0x9000
} ptp_opcodes;

/*
 * String Names of packet types [3] & [4]
 * Response codes 0x2000 - 0x2023 defined in Table 27 of [2]
 * Remainder of Response codes from [4]. Enums reformatted from [4] ptp.h */
/* Response Codes */
typedef enum {
    /* PTP v1.0 response codes */
    PTP_RC_Undefined                              = 0x2000,
    PTP_RC_OK                                     = 0x2001,
    PTP_RC_GeneralError                           = 0x2002,
    PTP_RC_SessionNotOpen                         = 0x2003,
    PTP_RC_InvalidTransactionID                   = 0x2004,
    PTP_RC_OperationNotSupported                  = 0x2005,
    PTP_RC_ParameterNotSupported                  = 0x2006,
    PTP_RC_IncompleteTransfer                     = 0x2007,
    PTP_RC_InvalidStorageId                       = 0x2008,
    PTP_RC_InvalidObjectHandle                    = 0x2009,
    PTP_RC_DevicePropNotSupported                 = 0x200A,
    PTP_RC_InvalidObjectFormatCode                = 0x200B,
    PTP_RC_StoreFull                              = 0x200C,
    PTP_RC_ObjectWriteProtected                   = 0x200D,
    PTP_RC_StoreReadOnly                          = 0x200E,
    PTP_RC_AccessDenied                           = 0x200F,
    PTP_RC_NoThumbnailPresent                     = 0x2010,
    PTP_RC_SelfTestFailed                         = 0x2011,
    PTP_RC_PartialDeletion                        = 0x2012,
    PTP_RC_StoreNotAvailable                      = 0x2013,
    PTP_RC_SpecificationByFormatUnsupported       = 0x2014,
    PTP_RC_NoValidObjectInfo                      = 0x2015,
    PTP_RC_InvalidCodeFormat                      = 0x2016,
    PTP_RC_UnknownVendorCode                      = 0x2017,
    PTP_RC_CaptureAlreadyTerminated               = 0x2018,
    PTP_RC_DeviceBusy                             = 0x2019,
    PTP_RC_InvalidParentObject                    = 0x201A,
    PTP_RC_InvalidDevicePropFormat                = 0x201B,
    PTP_RC_InvalidDevicePropValue                 = 0x201C,
    PTP_RC_InvalidParameter                       = 0x201D,
    PTP_RC_SessionAlreadyOpened                   = 0x201E,
    PTP_RC_TransactionCanceled                    = 0x201F,
    PTP_RC_SpecificationOfDestinationUnsupported  = 0x2020,
    /* PTP v1.1 response codes */
    PTP_RC_InvalidEnumHandle                      = 0x2021,
    PTP_RC_NoStreamEnabled                        = 0x2022,
    PTP_RC_InvalidDataSet                         = 0x2023,

    /* Eastman Kodak extension Response Codes */
    PTP_RC_EK_FilenameRequired                    = 0xA001,
    PTP_RC_EK_FilenameConflicts                   = 0xA002,
    PTP_RC_EK_FilenameInvalid                     = 0xA003,

    /* Nikon specific response codes */
    PTP_RC_NIKON_HardwareError                    = 0xA001,
    PTP_RC_NIKON_OutOfFocus                       = 0xA002,
    PTP_RC_NIKON_ChangeCameraModeFailed           = 0xA003,
    PTP_RC_NIKON_InvalidStatus                    = 0xA004,
    PTP_RC_NIKON_SetPropertyNotSupported          = 0xA005,
    PTP_RC_NIKON_WbResetError                     = 0xA006,
    PTP_RC_NIKON_DustReferenceError               = 0xA007,
    PTP_RC_NIKON_ShutterSpeedBulb                 = 0xA008,
    PTP_RC_NIKON_MirrorUpSequence                 = 0xA009,
    PTP_RC_NIKON_CameraModeNotAdjustFNumber       = 0xA00A,
    PTP_RC_NIKON_NotLiveView                      = 0xA00B,
    PTP_RC_NIKON_MfDriveStepEnd                   = 0xA00C,
    PTP_RC_NIKON_MfDriveStepInsufficiency         = 0xA00E,
    PTP_RC_NIKON_AdvancedTransferCancel           = 0xA022,

    /* Canon specific response codes */
    PTP_RC_CANON_UNKNOWN_COMMAND                  = 0xA001,
    PTP_RC_CANON_OPERATION_REFUSED                = 0xA005,
    PTP_RC_CANON_LENS_COVER                       = 0xA006,
    PTP_RC_CANON_BATTERY_LOW                      = 0xA101,
    PTP_RC_CANON_NOT_READY                        = 0xA102,
    PTP_RC_CANON_A009                             = 0xA009,
    /* Microsoft/MTP specific codes */
    PTP_RC_MTP_Undefined                          = 0xA800,
    PTP_RC_MTP_Invalid_ObjectPropCode             = 0xA801,
    PTP_RC_MTP_Invalid_ObjectProp_Format          = 0xA802,
    PTP_RC_MTP_Invalid_ObjectProp_Value           = 0xA803,
    PTP_RC_MTP_Invalid_ObjectReference            = 0xA804,
    PTP_RC_MTP_Invalid_Dataset                    = 0xA806,
    PTP_RC_MTP_Specification_By_Group_Unsupported = 0xA807,
    PTP_RC_MTP_Specification_By_Depth_Unsupported = 0xA808,
    PTP_RC_MTP_Object_Too_Large                   = 0xA809,
    PTP_RC_MTP_ObjectProp_Not_Supported           = 0xA80A,

    /* Microsoft Advanced Audio/Video Transfer response codes
    (microsoft.com/AAVT 1.0) */
    PTP_RC_MTP_Invalid_Media_Session_ID           = 0xA170,
    PTP_RC_MTP_Media_Session_Limit_Reached        = 0xA171,
    PTP_RC_MTP_No_More_Data                       = 0xA172,

    /* WiFi Provisioning MTP Extension Error Codes (microsoft.com/WPDWCN: 1.0) */
    PTP_RC_MTP_Invalid_WFC_Syntax                 = 0xA121,
    PTP_RC_MTP_WFC_Version_Not_Supported          = 0xA122

} ptp_respcodes;

/* function prototypes */
void dissect_ptp_opCode_openSession(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);
void dissect_ptp_transactionID     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 *offset);

