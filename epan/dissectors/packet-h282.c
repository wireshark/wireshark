/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-h282.c                                                              */
/* ../../tools/asn2wrs.py -p h282 -c ./h282.cnf -s ./packet-h282-template -D . -O ../../epan/dissectors RDC-PROTOCOL.asn */

/* Input file: packet-h282-template.c */

#line 1 "../../asn1/h282/packet-h282-template.c"
/* packet-h282.c
 * Routines for H.282 packet dissection
 * 2007  Tomas Kukosa
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-per.h"

#define PNAME  "H.282 Remote Device Control"
#define PSNAME "RDC"
#define PFNAME "rdc"

/* Initialize the protocol and registered fields */
static int proto_h282 = -1;

/*--- Included file: packet-h282-hf.c ---*/
#line 1 "../../asn1/h282/packet-h282-hf.c"
static int hf_h282_NonCollapsingCapabilities_PDU = -1;  /* NonCollapsingCapabilities */
static int hf_h282_RDCPDU_PDU = -1;               /* RDCPDU */
static int hf_h282_object = -1;                   /* OBJECT_IDENTIFIER */
static int hf_h282_h221NonStandard = -1;          /* H221NonStandardIdentifier */
static int hf_h282_key = -1;                      /* Key */
static int hf_h282_data = -1;                     /* OCTET_STRING */
static int hf_h282_h221nonStandard = -1;          /* H221NonStandardIdentifier */
static int hf_h282_camera = -1;                   /* NULL */
static int hf_h282_microphone = -1;               /* NULL */
static int hf_h282_streamPlayerRecorder = -1;     /* NULL */
static int hf_h282_slideProjector = -1;           /* NULL */
static int hf_h282_lightSource = -1;              /* NULL */
static int hf_h282_sourceCombiner = -1;           /* NULL */
static int hf_h282_nonStandardDevice = -1;        /* NonStandardIdentifier */
static int hf_h282_deviceID = -1;                 /* DeviceID */
static int hf_h282_audioSourceFlag = -1;          /* BOOLEAN */
static int hf_h282_audioSinkFlag = -1;            /* BOOLEAN */
static int hf_h282_videoSourceFlag = -1;          /* BOOLEAN */
static int hf_h282_videoSinkFlag = -1;            /* BOOLEAN */
static int hf_h282_remoteControlFlag = -1;        /* BOOLEAN */
static int hf_h282_instanceNumber = -1;           /* INTEGER_0_255 */
static int hf_h282_deviceName = -1;               /* TextString */
static int hf_h282_streamID = -1;                 /* StreamID */
static int hf_h282_videoStreamFlag = -1;          /* BOOLEAN */
static int hf_h282_sourceChangeFlag = -1;         /* BOOLEAN */
static int hf_h282_streamName = -1;               /* TextString */
static int hf_h282_standard = -1;                 /* INTEGER_0_65535 */
static int hf_h282_nonStandard = -1;              /* Key */
static int hf_h282_NonCollapsingCapabilities_item = -1;  /* NonCollapsingCapabilities_item */
static int hf_h282_capabilityID = -1;             /* CapabilityID */
static int hf_h282_applicationData = -1;          /* T_applicationData */
static int hf_h282_deviceList = -1;               /* SET_SIZE_0_127_OF_DeviceProfile */
static int hf_h282_deviceList_item = -1;          /* DeviceProfile */
static int hf_h282_streamList = -1;               /* SET_SIZE_0_127_OF_StreamProfile */
static int hf_h282_streamList_item = -1;          /* StreamProfile */
static int hf_h282_playing = -1;                  /* NULL */
static int hf_h282_recording = -1;                /* NULL */
static int hf_h282_pausedOnRecord = -1;           /* NULL */
static int hf_h282_pausedOnPlay = -1;             /* NULL */
static int hf_h282_rewinding = -1;                /* NULL */
static int hf_h282_fastForwarding = -1;           /* NULL */
static int hf_h282_searchingForwards = -1;        /* NULL */
static int hf_h282_searchingBackwards = -1;       /* NULL */
static int hf_h282_stopped = -1;                  /* NULL */
static int hf_h282_programUnavailable = -1;       /* NULL */
static int hf_h282_maxNumber = -1;                /* PresetNumber */
static int hf_h282_presetCapability = -1;         /* T_presetCapability */
static int hf_h282_presetCapability_item = -1;    /* T_presetCapability_item */
static int hf_h282_presetNumber = -1;             /* PresetNumber */
static int hf_h282_storeModeSupported = -1;       /* BOOLEAN */
static int hf_h282_presetTextLabel = -1;          /* DeviceText */
static int hf_h282_maxNumberOfFilters = -1;       /* INTEGER_2_255 */
static int hf_h282_filterTextLabel = -1;          /* T_filterTextLabel */
static int hf_h282_filterTextLabel_item = -1;     /* T_filterTextLabel_item */
static int hf_h282_filterNumber = -1;             /* INTEGER_1_255 */
static int hf_h282_filterTextLabel_01 = -1;       /* DeviceText */
static int hf_h282_maxNumberOfLens = -1;          /* INTEGER_2_255 */
static int hf_h282_accessoryTextLabel = -1;       /* T_accessoryTextLabel */
static int hf_h282_accessoryTextLabel_item = -1;  /* T_accessoryTextLabel_item */
static int hf_h282_lensNumber = -1;               /* INTEGER_1_255 */
static int hf_h282_lensTextLabel = -1;            /* DeviceText */
static int hf_h282_maxNumber_01 = -1;             /* INTEGER_1_10 */
static int hf_h282_lightTextLabel = -1;           /* T_lightTextLabel */
static int hf_h282_lightTextLabel_item = -1;      /* T_lightTextLabel_item */
static int hf_h282_lightNumber = -1;              /* INTEGER_1_10 */
static int hf_h282_lightLabel = -1;               /* DeviceText */
static int hf_h282_maxSpeed = -1;                 /* CameraPanSpeed */
static int hf_h282_minSpeed = -1;                 /* CameraPanSpeed */
static int hf_h282_speedStepSize = -1;            /* CameraPanSpeed */
static int hf_h282_maxSpeed_01 = -1;              /* CameraTiltSpeed */
static int hf_h282_minSpeed_01 = -1;              /* CameraTiltSpeed */
static int hf_h282_speedStepSize_01 = -1;         /* CameraTiltSpeed */
static int hf_h282_maxLeft = -1;                  /* INTEGER_M18000_0 */
static int hf_h282_maxRight = -1;                 /* INTEGER_0_18000 */
static int hf_h282_minStepSize = -1;              /* INTEGER_1_18000 */
static int hf_h282_maxDown = -1;                  /* INTEGER_M18000_0 */
static int hf_h282_maxUp = -1;                    /* INTEGER_0_18000 */
static int hf_h282_multiplierFactors = -1;        /* T_multiplierFactors */
static int hf_h282_multiplierFactors_item = -1;   /* INTEGER_10_1000 */
static int hf_h282_divisorFactors = -1;           /* T_divisorFactors */
static int hf_h282_divisorFactors_item = -1;      /* INTEGER_10_1000 */
static int hf_h282_numberOfDeviceInputs = -1;     /* INTEGER_2_64 */
static int hf_h282_numberOfDeviceRows = -1;       /* INTEGER_1_64 */
static int hf_h282_availableDevices = -1;         /* T_availableDevices */
static int hf_h282_availableDevices_item = -1;    /* T_availableDevices_item */
static int hf_h282_deviceClass = -1;              /* DeviceClass */
static int hf_h282_deviceIdentifier = -1;         /* DeviceID */
static int hf_h282_availableDevices_01 = -1;      /* T_availableDevices_01 */
static int hf_h282_availableDevices_item_01 = -1;  /* T_availableDevices_item_01 */
static int hf_h282_deviceStateSupported = -1;     /* NULL */
static int hf_h282_deviceDateSupported = -1;      /* NULL */
static int hf_h282_deviceTimeSupported = -1;      /* NULL */
static int hf_h282_devicePresetSupported = -1;    /* DevicePresetCapability */
static int hf_h282_irisModeSupported = -1;        /* NULL */
static int hf_h282_focusModeSupported = -1;       /* NULL */
static int hf_h282_pointingModeSupported = -1;    /* NULL */
static int hf_h282_cameraLensSupported = -1;      /* CameraLensCapability */
static int hf_h282_cameraFilterSupported = -1;    /* CameraFilterCapability */
static int hf_h282_homePositionSupported = -1;    /* NULL */
static int hf_h282_externalCameraLightSupported = -1;  /* ExternalCameraLightCapability */
static int hf_h282_clearCameraLensSupported = -1;  /* NULL */
static int hf_h282_cameraPanSpeedSupported = -1;  /* CameraPanSpeedCapability */
static int hf_h282_cameraTiltSpeedSupported = -1;  /* CameraTiltSpeedCapability */
static int hf_h282_backLightModeSupported = -1;   /* NULL */
static int hf_h282_backLightSettingSupported = -1;  /* MaxBacklight */
static int hf_h282_whiteBalanceSettingSupported = -1;  /* MaxWhiteBalance */
static int hf_h282_whiteBalanceModeSupported = -1;  /* NULL */
static int hf_h282_calibrateWhiteBalanceSupported = -1;  /* NULL */
static int hf_h282_focusImageSupported = -1;      /* NULL */
static int hf_h282_captureImageSupported = -1;    /* NULL */
static int hf_h282_panContinuousSupported = -1;   /* NULL */
static int hf_h282_tiltContinuousSupported = -1;  /* NULL */
static int hf_h282_zoomContinuousSupported = -1;  /* NULL */
static int hf_h282_focusContinuousSupported = -1;  /* NULL */
static int hf_h282_irisContinuousSupported = -1;  /* NULL */
static int hf_h282_zoomPositionSupported = -1;    /* MinZoomPositionSetSize */
static int hf_h282_focusPositionSupported = -1;   /* MinFocusPositionStepSize */
static int hf_h282_irisPositionSupported = -1;    /* MinIrisPositionStepSize */
static int hf_h282_panPositionSupported = -1;     /* PanPositionCapability */
static int hf_h282_tiltPositionSupported = -1;    /* TiltPositionCapability */
static int hf_h282_zoomMagnificationSupported = -1;  /* MinZoomMagnificationStepSize */
static int hf_h282_panViewSupported = -1;         /* NULL */
static int hf_h282_tiltViewSupported = -1;        /* NULL */
static int hf_h282_selectSlideSupported = -1;     /* MaxNumberOfSlides */
static int hf_h282_selectNextSlideSupported = -1;  /* NULL */
static int hf_h282_slideShowModeSupported = -1;   /* NULL */
static int hf_h282_playSlideShowSupported = -1;   /* NULL */
static int hf_h282_setSlideDisplayTimeSupported = -1;  /* MaxSlideDisplayTime */
static int hf_h282_continuousRewindSupported = -1;  /* NULL */
static int hf_h282_continuousFastForwardSupported = -1;  /* NULL */
static int hf_h282_searchBackwardsSupported = -1;  /* NULL */
static int hf_h282_searchForwardsSupported = -1;  /* NULL */
static int hf_h282_pauseSupported = -1;           /* NULL */
static int hf_h282_selectProgramSupported = -1;   /* MaxNumberOfPrograms */
static int hf_h282_nextProgramSupported = -1;     /* NULL */
static int hf_h282_gotoNormalPlayTimePointSupported = -1;  /* NULL */
static int hf_h282_readStreamPlayerStateSupported = -1;  /* NULL */
static int hf_h282_readProgramDurationSupported = -1;  /* NULL */
static int hf_h282_continuousPlayBackModeSupported = -1;  /* NULL */
static int hf_h282_playbackSpeedSupported = -1;   /* PlayBackSpeedCapability */
static int hf_h282_playSupported = -1;            /* NULL */
static int hf_h282_setAudioOutputStateSupported = -1;  /* NULL */
static int hf_h282_playToNormalPlayTimePointSupported = -1;  /* NULL */
static int hf_h282_recordSupported = -1;          /* NULL */
static int hf_h282_recordForDurationSupported = -1;  /* NULL */
static int hf_h282_configurableVideoInputsSupported = -1;  /* VideoInputsCapability */
static int hf_h282_videoInputsSupported = -1;     /* VideoInputsCapability */
static int hf_h282_configurableAudioInputsSupported = -1;  /* AudioInputsCapability */
static int hf_h282_audioInputsSupported = -1;     /* AudioInputsCapability */
static int hf_h282_deviceLockStateChangedSupported = -1;  /* NULL */
static int hf_h282_deviceAvailabilityChangedSupported = -1;  /* NULL */
static int hf_h282_cameraPannedToLimitSupported = -1;  /* NULL */
static int hf_h282_cameraTiltedToLimitSupported = -1;  /* NULL */
static int hf_h282_cameraZoomedToLimitSupported = -1;  /* NULL */
static int hf_h282_cameraFocusedToLimitSupported = -1;  /* NULL */
static int hf_h282_autoSlideShowFinishedSupported = -1;  /* NULL */
static int hf_h282_streamPlayerStateChangeSupported = -1;  /* NULL */
static int hf_h282_streamPlayerProgramChangeSupported = -1;  /* NULL */
static int hf_h282_nonStandardAttributeSupported = -1;  /* NonStandardParameter */
static int hf_h282_active = -1;                   /* NULL */
static int hf_h282_inactive = -1;                 /* NULL */
static int hf_h282_day = -1;                      /* Day */
static int hf_h282_month = -1;                    /* Month */
static int hf_h282_year = -1;                     /* Year */
static int hf_h282_hour = -1;                     /* Hour */
static int hf_h282_minute = -1;                   /* Minute */
static int hf_h282_mode = -1;                     /* T_mode */
static int hf_h282_store = -1;                    /* NULL */
static int hf_h282_activate = -1;                 /* NULL */
static int hf_h282_manual = -1;                   /* NULL */
static int hf_h282_auto = -1;                     /* NULL */
static int hf_h282_toggle = -1;                   /* NULL */
static int hf_h282_none = -1;                     /* NULL */
static int hf_h282_panDirection = -1;             /* T_panDirection */
static int hf_h282_left = -1;                     /* NULL */
static int hf_h282_right = -1;                    /* NULL */
static int hf_h282_stop = -1;                     /* NULL */
static int hf_h282_continue = -1;                 /* NULL */
static int hf_h282_timeOut = -1;                  /* INTEGER_50_1000 */
static int hf_h282_tiltDirection = -1;            /* T_tiltDirection */
static int hf_h282_up = -1;                       /* NULL */
static int hf_h282_down = -1;                     /* NULL */
static int hf_h282_zoomDirection = -1;            /* T_zoomDirection */
static int hf_h282_telescopic = -1;               /* NULL */
static int hf_h282_wide = -1;                     /* NULL */
static int hf_h282_focusDirection = -1;           /* T_focusDirection */
static int hf_h282_near = -1;                     /* NULL */
static int hf_h282_far = -1;                      /* NULL */
static int hf_h282_relative = -1;                 /* NULL */
static int hf_h282_absolute = -1;                 /* NULL */
static int hf_h282_zoomPosition = -1;             /* ZoomPosition */
static int hf_h282_positioningMode = -1;          /* PositioningMode */
static int hf_h282_focusPosition = -1;            /* FocusPosition */
static int hf_h282_irisPosition = -1;             /* IrisPosition */
static int hf_h282_panPosition = -1;              /* PanPosition */
static int hf_h282_tiltPosition = -1;             /* TiltPosition */
static int hf_h282_next = -1;                     /* NULL */
static int hf_h282_previous = -1;                 /* NULL */
static int hf_h282_start = -1;                    /* NULL */
static int hf_h282_pause = -1;                    /* NULL */
static int hf_h282_hours = -1;                    /* INTEGER_0_24 */
static int hf_h282_minutes = -1;                  /* INTEGER_0_59 */
static int hf_h282_seconds = -1;                  /* INTEGER_0_59 */
static int hf_h282_microseconds = -1;             /* INTEGER_0_99999 */
static int hf_h282_scaleFactor = -1;              /* INTEGER_10_1000 */
static int hf_h282_multiplyFactor = -1;           /* BOOLEAN */
static int hf_h282_inputDevices = -1;             /* T_inputDevices */
static int hf_h282_inputDevices_item = -1;        /* T_inputDevices_item */
static int hf_h282_setDeviceState = -1;           /* DeviceState */
static int hf_h282_setDeviceDate = -1;            /* DeviceDate */
static int hf_h282_setDeviceTime = -1;            /* DeviceTime */
static int hf_h282_setDevicePreset = -1;          /* DevicePreset */
static int hf_h282_setIrisMode = -1;              /* Mode */
static int hf_h282_setFocusMode = -1;             /* Mode */
static int hf_h282_setBackLightMode = -1;         /* Mode */
static int hf_h282_setPointingMode = -1;          /* PointingToggle */
static int hf_h282_selectCameraLens = -1;         /* CameraLensNumber */
static int hf_h282_selectCameraFilter = -1;       /* CameraFilterNumber */
static int hf_h282_gotoHomePosition = -1;         /* NULL */
static int hf_h282_selectExternalLight = -1;      /* SelectExternalLight */
static int hf_h282_clearCameraLens = -1;          /* NULL */
static int hf_h282_setCameraPanSpeed = -1;        /* CameraPanSpeed */
static int hf_h282_setCameraTiltSpeed = -1;       /* CameraTiltSpeed */
static int hf_h282_setBackLight = -1;             /* BackLight */
static int hf_h282_setWhiteBalance = -1;          /* WhiteBalance */
static int hf_h282_setWhiteBalanceMode = -1;      /* Mode */
static int hf_h282_calibrateWhiteBalance = -1;    /* NULL */
static int hf_h282_focusImage = -1;               /* NULL */
static int hf_h282_captureImage = -1;             /* NULL */
static int hf_h282_panContinuous = -1;            /* PanContinuous */
static int hf_h282_tiltContinuous = -1;           /* TiltContinuous */
static int hf_h282_zoomContinuous = -1;           /* ZoomContinuous */
static int hf_h282_focusContinuous = -1;          /* FocusContinuous */
static int hf_h282_setZoomPosition = -1;          /* SetZoomPosition */
static int hf_h282_setFocusPosition = -1;         /* SetFocusPosition */
static int hf_h282_setIrisPosition = -1;          /* SetIrisPosition */
static int hf_h282_setPanPosition = -1;           /* SetPanPosition */
static int hf_h282_setTiltPosition = -1;          /* SetTiltPosition */
static int hf_h282_setZoomMagnification = -1;     /* ZoomMagnification */
static int hf_h282_setPanView = -1;               /* PanView */
static int hf_h282_setTiltView = -1;              /* TiltView */
static int hf_h282_selectSlide = -1;              /* SlideNumber */
static int hf_h282_selectNextSlide = -1;          /* SelectDirection */
static int hf_h282_playAutoSlideShow = -1;        /* AutoSlideShowControl */
static int hf_h282_setAutoSlideDisplayTime = -1;  /* AutoSlideDisplayTime */
static int hf_h282_continuousRewindControl = -1;  /* BOOLEAN */
static int hf_h282_continuousFastForwardControl = -1;  /* BOOLEAN */
static int hf_h282_searchBackwardsControl = -1;   /* BOOLEAN */
static int hf_h282_searchForwardsControl = -1;    /* BOOLEAN */
static int hf_h282_pause_01 = -1;                 /* BOOLEAN */
static int hf_h282_selectProgram = -1;            /* ProgramNumber */
static int hf_h282_nextProgramSelect = -1;        /* SelectDirection */
static int hf_h282_gotoNormalPlayTimePoint = -1;  /* ProgramDuration */
static int hf_h282_continuousPlayBackMode = -1;   /* BOOLEAN */
static int hf_h282_setPlaybackSpeed = -1;         /* PlaybackSpeed */
static int hf_h282_play = -1;                     /* BOOLEAN */
static int hf_h282_setAudioOutputMute = -1;       /* BOOLEAN */
static int hf_h282_playToNormalPlayTimePoint = -1;  /* ProgramDuration */
static int hf_h282_record = -1;                   /* BOOLEAN */
static int hf_h282_recordForDuration = -1;        /* RecordForDuration */
static int hf_h282_configureVideoInputs = -1;     /* DeviceInputs */
static int hf_h282_configureAudioInputs = -1;     /* DeviceInputs */
static int hf_h282_nonStandardControl = -1;       /* NonStandardParameter */
static int hf_h282_getDeviceState = -1;           /* NULL */
static int hf_h282_getDeviceDate = -1;            /* NULL */
static int hf_h282_getDeviceTime = -1;            /* NULL */
static int hf_h282_getdevicePreset = -1;          /* NULL */
static int hf_h282_getIrisMode = -1;              /* NULL */
static int hf_h282_getFocusMode = -1;             /* NULL */
static int hf_h282_getBacklightMode = -1;         /* NULL */
static int hf_h282_getPointingMode = -1;          /* NULL */
static int hf_h282_getCameraLens = -1;            /* NULL */
static int hf_h282_getCameraFilter = -1;          /* NULL */
static int hf_h282_getExternalLight = -1;         /* NULL */
static int hf_h282_getCameraPanSpeed = -1;        /* NULL */
static int hf_h282_getCameraTiltSpeed = -1;       /* NULL */
static int hf_h282_getBackLightMode = -1;         /* NULL */
static int hf_h282_getBackLight = -1;             /* NULL */
static int hf_h282_getWhiteBalance = -1;          /* NULL */
static int hf_h282_getWhiteBalanceMode = -1;      /* NULL */
static int hf_h282_getZoomPosition = -1;          /* NULL */
static int hf_h282_getFocusPosition = -1;         /* NULL */
static int hf_h282_getIrisPosition = -1;          /* NULL */
static int hf_h282_getPanPosition = -1;           /* NULL */
static int hf_h282_getTiltPosition = -1;          /* NULL */
static int hf_h282_getSelectedSlide = -1;         /* NULL */
static int hf_h282_getAutoSlideDisplayTime = -1;  /* NULL */
static int hf_h282_getSelectedProgram = -1;       /* NULL */
static int hf_h282_getStreamPlayerState = -1;     /* NULL */
static int hf_h282_getCurrentProgramDuration = -1;  /* NULL */
static int hf_h282_getPlaybackSpeed = -1;         /* NULL */
static int hf_h282_getAudioOutputState = -1;      /* NULL */
static int hf_h282_getConfigurableVideoInputs = -1;  /* NULL */
static int hf_h282_getVideoInputs = -1;           /* NULL */
static int hf_h282_getConfigurableAudioInputs = -1;  /* NULL */
static int hf_h282_getAudioInputs = -1;           /* NULL */
static int hf_h282_getNonStandardStatus = -1;     /* NonStandardIdentifier */
static int hf_h282_deviceState = -1;              /* DeviceState */
static int hf_h282_unknown = -1;                  /* NULL */
static int hf_h282_currentDay = -1;               /* T_currentDay */
static int hf_h282_currentMonth = -1;             /* T_currentMonth */
static int hf_h282_currentYear = -1;              /* T_currentYear */
static int hf_h282_currentHour = -1;              /* T_currentHour */
static int hf_h282_currentMinute = -1;            /* T_currentMinute */
static int hf_h282_preset = -1;                   /* PresetNumber */
static int hf_h282_mode_01 = -1;                  /* Mode */
static int hf_h282_automatic = -1;                /* NULL */
static int hf_h282_lensNumber_01 = -1;            /* CameraLensNumber */
static int hf_h282_lensNumber_02 = -1;            /* CameraFilterNumber */
static int hf_h282_speed = -1;                    /* CameraPanSpeed */
static int hf_h282_speed_01 = -1;                 /* CameraTiltSpeed */
static int hf_h282_backLight = -1;                /* BackLight */
static int hf_h282_whiteBalance = -1;             /* WhiteBalance */
static int hf_h282_slide = -1;                    /* SlideNumber */
static int hf_h282_time = -1;                     /* AutoSlideDisplayTime */
static int hf_h282_program = -1;                  /* ProgramNumber */
static int hf_h282_state = -1;                    /* StreamPlayerState */
static int hf_h282_speed_02 = -1;                 /* PlaybackSpeed */
static int hf_h282_mute = -1;                     /* BOOLEAN */
static int hf_h282_currentdeviceState = -1;       /* CurrentDeviceState */
static int hf_h282_currentDeviceDate = -1;        /* CurrentDeviceDate */
static int hf_h282_currentDeviceTime = -1;        /* CurrentDeviceTime */
static int hf_h282_currentDevicePreset = -1;      /* CurrentDevicePreset */
static int hf_h282_currentIrisMode = -1;          /* CurrentMode */
static int hf_h282_currentFocusMode = -1;         /* CurrentMode */
static int hf_h282_currentBackLightMode = -1;     /* CurrentMode */
static int hf_h282_currentPointingMode = -1;      /* CurrentPointingMode */
static int hf_h282_currentCameraLens = -1;        /* CurrentCameraLensNumber */
static int hf_h282_currentCameraFilter = -1;      /* CurrentCameraFilterNumber */
static int hf_h282_currentExternalLight = -1;     /* CurrentExternalLight */
static int hf_h282_currentCameraPanSpeed = -1;    /* CurrentCameraPanSpeed */
static int hf_h282_currentCameraTiltSpeed = -1;   /* CurrentCameraTiltSpeed */
static int hf_h282_currentBackLight = -1;         /* CurrentBackLight */
static int hf_h282_currentWhiteBalance = -1;      /* CurrentWhiteBalance */
static int hf_h282_currentWhiteBalanceMode = -1;  /* CurrentMode */
static int hf_h282_currentZoomPosition = -1;      /* CurrentZoomPosition */
static int hf_h282_currentFocusPosition = -1;     /* CurrentFocusPosition */
static int hf_h282_currentIrisPosition = -1;      /* CurrentIrisPosition */
static int hf_h282_currentPanPosition = -1;       /* CurrentPanPosition */
static int hf_h282_currentTiltPosition = -1;      /* CurrentTiltPosition */
static int hf_h282_currentSlide = -1;             /* CurrentSlide */
static int hf_h282_currentAutoSlideDisplayTime = -1;  /* CurrentAutoSlideDisplayTime */
static int hf_h282_currentSelectedProgram = -1;   /* CurrentSelectedProgram */
static int hf_h282_currentstreamPlayerState = -1;  /* CurrentStreamPlayerState */
static int hf_h282_currentProgramDuration = -1;   /* ProgramDuration */
static int hf_h282_currentPlaybackSpeed = -1;     /* CurrentPlaybackSpeed */
static int hf_h282_currentAudioOutputMute = -1;   /* CurrentAudioOutputMute */
static int hf_h282_configurableVideoInputs = -1;  /* DeviceInputs */
static int hf_h282_videoInputs = -1;              /* DeviceInputs */
static int hf_h282_configurableAudioInputs = -1;  /* DeviceInputs */
static int hf_h282_audioInputs = -1;              /* DeviceInputs */
static int hf_h282_nonStandardStatus = -1;        /* NonStandardParameter */
static int hf_h282_requestDeviceLockChanged = -1;  /* NULL */
static int hf_h282_requestDeviceAvailabilityChanged = -1;  /* NULL */
static int hf_h282_requestCameraPannedToLimit = -1;  /* NULL */
static int hf_h282_requestCameraTiltedToLimit = -1;  /* NULL */
static int hf_h282_requestCameraZoomedToLimit = -1;  /* NULL */
static int hf_h282_requestCameraFocusedToLimit = -1;  /* NULL */
static int hf_h282_requestAutoSlideShowFinished = -1;  /* NULL */
static int hf_h282_requestStreamPlayerStateChange = -1;  /* NULL */
static int hf_h282_requestStreamPlayerProgramChange = -1;  /* NULL */
static int hf_h282_requestNonStandardEvent = -1;  /* NonStandardIdentifier */
static int hf_h282_deviceLockChanged = -1;        /* BOOLEAN */
static int hf_h282_deviceAvailabilityChanged = -1;  /* BOOLEAN */
static int hf_h282_cameraPannedToLimit = -1;      /* CameraPannedToLimit */
static int hf_h282_cameraTiltedToLimit = -1;      /* CameraTiltedToLimit */
static int hf_h282_cameraZoomedToLimit = -1;      /* CameraZoomedToLimit */
static int hf_h282_cameraFocusedToLimit = -1;     /* CameraFocusedToLimit */
static int hf_h282_autoSlideShowFinished = -1;    /* NULL */
static int hf_h282_streamPlayerStateChange = -1;  /* StreamPlayerState */
static int hf_h282_streamPlayerProgramChange = -1;  /* ProgramNumber */
static int hf_h282_nonStandardEvent = -1;         /* NonStandardParameter */
static int hf_h282_requestHandle = -1;            /* Handle */
static int hf_h282_streamIdentifier = -1;         /* StreamID */
static int hf_h282_result = -1;                   /* T_result */
static int hf_h282_successful = -1;               /* NULL */
static int hf_h282_requestDenied = -1;            /* NULL */
static int hf_h282_deviceUnavailable = -1;        /* NULL */
static int hf_h282_invalidStreamID = -1;          /* NULL */
static int hf_h282_currentDeviceIsLocked = -1;    /* NULL */
static int hf_h282_deviceIncompatible = -1;       /* NULL */
static int hf_h282_sourceEventNotify = -1;        /* BOOLEAN */
static int hf_h282_result_01 = -1;                /* T_result_01 */
static int hf_h282_eventsNotSupported = -1;       /* NULL */
static int hf_h282_deviceAttributeList = -1;      /* SET_OF_DeviceAttribute */
static int hf_h282_deviceAttributeList_item = -1;  /* DeviceAttribute */
static int hf_h282_result_02 = -1;                /* T_result_02 */
static int hf_h282_unknownDevice = -1;            /* NULL */
static int hf_h282_lockFlag = -1;                 /* BOOLEAN */
static int hf_h282_result_03 = -1;                /* T_result_03 */
static int hf_h282_lockingNotSupported = -1;      /* NULL */
static int hf_h282_deviceAlreadyLocked = -1;      /* NULL */
static int hf_h282_result_04 = -1;                /* T_result_04 */
static int hf_h282_lockRequired = -1;             /* NULL */
static int hf_h282_lockNotRequired = -1;          /* NULL */
static int hf_h282_controlAttributeList = -1;     /* SET_SIZE_1_8_OF_ControlAttribute */
static int hf_h282_controlAttributeList_item = -1;  /* ControlAttribute */
static int hf_h282_statusAttributeIdentifierList = -1;  /* SET_SIZE_1_16_OF_StatusAttributeIdentifier */
static int hf_h282_statusAttributeIdentifierList_item = -1;  /* StatusAttributeIdentifier */
static int hf_h282_statusAttributeList = -1;      /* SET_SIZE_1_16_OF_StatusAttribute */
static int hf_h282_statusAttributeList_item = -1;  /* StatusAttribute */
static int hf_h282_result_05 = -1;                /* T_result_05 */
static int hf_h282_deviceAttributeError = -1;     /* NULL */
static int hf_h282_deviceEventIdentifierList = -1;  /* SET_OF_DeviceEventIdentifier */
static int hf_h282_deviceEventIdentifierList_item = -1;  /* DeviceEventIdentifier */
static int hf_h282_result_06 = -1;                /* T_result_06 */
static int hf_h282_deviceEventList = -1;          /* SET_SIZE_1_8_OF_DeviceEvent */
static int hf_h282_deviceEventList_item = -1;     /* DeviceEvent */
static int hf_h282_nonStandardData = -1;          /* NonStandardParameter */
static int hf_h282_request = -1;                  /* RequestPDU */
static int hf_h282_response = -1;                 /* ResponsePDU */
static int hf_h282_indication = -1;               /* IndicationPDU */
static int hf_h282_sourceSelectRequest = -1;      /* SourceSelectRequest */
static int hf_h282_sourceEventsRequest = -1;      /* SourceEventsRequest */
static int hf_h282_deviceAttributeRequest = -1;   /* DeviceAttributeRequest */
static int hf_h282_deviceLockRequest = -1;        /* DeviceLockRequest */
static int hf_h282_deviceLockEnquireRequest = -1;  /* DeviceLockEnquireRequest */
static int hf_h282_deviceControlRequest = -1;     /* DeviceControlRequest */
static int hf_h282_deviceStatusEnquireRequest = -1;  /* DeviceStatusEnquireRequest */
static int hf_h282_configureDeviceEventsRequest = -1;  /* ConfigureDeviceEventsRequest */
static int hf_h282_nonStandardRequest = -1;       /* NonStandardPDU */
static int hf_h282_sourceSelectResponse = -1;     /* SourceSelectResponse */
static int hf_h282_sourceEventsResponse = -1;     /* SourceEventsResponse */
static int hf_h282_deviceAttributeResponse = -1;  /* DeviceAttributeResponse */
static int hf_h282_deviceLockResponse = -1;       /* DeviceLockResponse */
static int hf_h282_deviceLockEnquireResponse = -1;  /* DeviceLockEnquireResponse */
static int hf_h282_deviceStatusEnquireResponse = -1;  /* DeviceStatusEnquireResponse */
static int hf_h282_configureDeviceEventsResponse = -1;  /* ConfigureDeviceEventsResponse */
static int hf_h282_nonStandardResponse = -1;      /* NonStandardPDU */
static int hf_h282_sourceChangeEventIndication = -1;  /* SourceChangeEventIndication */
static int hf_h282_deviceLockTerminatedIndication = -1;  /* DeviceLockTerminatedIndication */
static int hf_h282_deviceEventNotifyIndication = -1;  /* DeviceEventNotifyIndication */
static int hf_h282_nonStandardIndication = -1;    /* NonStandardPDU */

/*--- End of included file: packet-h282-hf.c ---*/
#line 44 "../../asn1/h282/packet-h282-template.c"

/* Initialize the subtree pointers */
static int ett_h282 = -1;

/*--- Included file: packet-h282-ett.c ---*/
#line 1 "../../asn1/h282/packet-h282-ett.c"
static gint ett_h282_Key = -1;
static gint ett_h282_NonStandardParameter = -1;
static gint ett_h282_NonStandardIdentifier = -1;
static gint ett_h282_DeviceClass = -1;
static gint ett_h282_DeviceProfile = -1;
static gint ett_h282_StreamProfile = -1;
static gint ett_h282_CapabilityID = -1;
static gint ett_h282_NonCollapsingCapabilities = -1;
static gint ett_h282_NonCollapsingCapabilities_item = -1;
static gint ett_h282_T_applicationData = -1;
static gint ett_h282_SET_SIZE_0_127_OF_DeviceProfile = -1;
static gint ett_h282_SET_SIZE_0_127_OF_StreamProfile = -1;
static gint ett_h282_StreamPlayerState = -1;
static gint ett_h282_DevicePresetCapability = -1;
static gint ett_h282_T_presetCapability = -1;
static gint ett_h282_T_presetCapability_item = -1;
static gint ett_h282_CameraFilterCapability = -1;
static gint ett_h282_T_filterTextLabel = -1;
static gint ett_h282_T_filterTextLabel_item = -1;
static gint ett_h282_CameraLensCapability = -1;
static gint ett_h282_T_accessoryTextLabel = -1;
static gint ett_h282_T_accessoryTextLabel_item = -1;
static gint ett_h282_ExternalCameraLightCapability = -1;
static gint ett_h282_T_lightTextLabel = -1;
static gint ett_h282_T_lightTextLabel_item = -1;
static gint ett_h282_CameraPanSpeedCapability = -1;
static gint ett_h282_CameraTiltSpeedCapability = -1;
static gint ett_h282_PanPositionCapability = -1;
static gint ett_h282_TiltPositionCapability = -1;
static gint ett_h282_PlayBackSpeedCapability = -1;
static gint ett_h282_T_multiplierFactors = -1;
static gint ett_h282_T_divisorFactors = -1;
static gint ett_h282_VideoInputsCapability = -1;
static gint ett_h282_T_availableDevices = -1;
static gint ett_h282_T_availableDevices_item = -1;
static gint ett_h282_AudioInputsCapability = -1;
static gint ett_h282_T_availableDevices_01 = -1;
static gint ett_h282_T_availableDevices_item_01 = -1;
static gint ett_h282_DeviceAttribute = -1;
static gint ett_h282_DeviceState = -1;
static gint ett_h282_DeviceDate = -1;
static gint ett_h282_DeviceTime = -1;
static gint ett_h282_DevicePreset = -1;
static gint ett_h282_T_mode = -1;
static gint ett_h282_Mode = -1;
static gint ett_h282_PointingToggle = -1;
static gint ett_h282_SelectExternalLight = -1;
static gint ett_h282_PanContinuous = -1;
static gint ett_h282_T_panDirection = -1;
static gint ett_h282_TiltContinuous = -1;
static gint ett_h282_T_tiltDirection = -1;
static gint ett_h282_ZoomContinuous = -1;
static gint ett_h282_T_zoomDirection = -1;
static gint ett_h282_FocusContinuous = -1;
static gint ett_h282_T_focusDirection = -1;
static gint ett_h282_PositioningMode = -1;
static gint ett_h282_SetZoomPosition = -1;
static gint ett_h282_SetFocusPosition = -1;
static gint ett_h282_SetIrisPosition = -1;
static gint ett_h282_SetPanPosition = -1;
static gint ett_h282_SetTiltPosition = -1;
static gint ett_h282_SelectDirection = -1;
static gint ett_h282_AutoSlideShowControl = -1;
static gint ett_h282_ProgramDuration = -1;
static gint ett_h282_PlaybackSpeed = -1;
static gint ett_h282_RecordForDuration = -1;
static gint ett_h282_DeviceInputs = -1;
static gint ett_h282_T_inputDevices = -1;
static gint ett_h282_T_inputDevices_item = -1;
static gint ett_h282_ControlAttribute = -1;
static gint ett_h282_StatusAttributeIdentifier = -1;
static gint ett_h282_CurrentDeviceState = -1;
static gint ett_h282_CurrentDeviceDate = -1;
static gint ett_h282_T_currentDay = -1;
static gint ett_h282_T_currentMonth = -1;
static gint ett_h282_T_currentYear = -1;
static gint ett_h282_CurrentDeviceTime = -1;
static gint ett_h282_T_currentHour = -1;
static gint ett_h282_T_currentMinute = -1;
static gint ett_h282_CurrentDevicePreset = -1;
static gint ett_h282_CurrentMode = -1;
static gint ett_h282_CurrentPointingMode = -1;
static gint ett_h282_CurrentCameraLensNumber = -1;
static gint ett_h282_CurrentCameraFilterNumber = -1;
static gint ett_h282_CurrentExternalLight = -1;
static gint ett_h282_CurrentCameraPanSpeed = -1;
static gint ett_h282_CurrentCameraTiltSpeed = -1;
static gint ett_h282_CurrentBackLight = -1;
static gint ett_h282_CurrentWhiteBalance = -1;
static gint ett_h282_CurrentZoomPosition = -1;
static gint ett_h282_CurrentFocusPosition = -1;
static gint ett_h282_CurrentIrisPosition = -1;
static gint ett_h282_CurrentPanPosition = -1;
static gint ett_h282_CurrentTiltPosition = -1;
static gint ett_h282_CurrentSlide = -1;
static gint ett_h282_CurrentAutoSlideDisplayTime = -1;
static gint ett_h282_CurrentSelectedProgram = -1;
static gint ett_h282_CurrentStreamPlayerState = -1;
static gint ett_h282_CurrentPlaybackSpeed = -1;
static gint ett_h282_CurrentAudioOutputMute = -1;
static gint ett_h282_StatusAttribute = -1;
static gint ett_h282_DeviceEventIdentifier = -1;
static gint ett_h282_CameraPannedToLimit = -1;
static gint ett_h282_CameraTiltedToLimit = -1;
static gint ett_h282_CameraZoomedToLimit = -1;
static gint ett_h282_CameraFocusedToLimit = -1;
static gint ett_h282_DeviceEvent = -1;
static gint ett_h282_SourceSelectRequest = -1;
static gint ett_h282_SourceSelectResponse = -1;
static gint ett_h282_T_result = -1;
static gint ett_h282_SourceEventsRequest = -1;
static gint ett_h282_SourceEventsResponse = -1;
static gint ett_h282_T_result_01 = -1;
static gint ett_h282_SourceChangeEventIndication = -1;
static gint ett_h282_DeviceAttributeRequest = -1;
static gint ett_h282_DeviceAttributeResponse = -1;
static gint ett_h282_SET_OF_DeviceAttribute = -1;
static gint ett_h282_T_result_02 = -1;
static gint ett_h282_DeviceLockRequest = -1;
static gint ett_h282_DeviceLockResponse = -1;
static gint ett_h282_T_result_03 = -1;
static gint ett_h282_DeviceLockEnquireRequest = -1;
static gint ett_h282_DeviceLockEnquireResponse = -1;
static gint ett_h282_T_result_04 = -1;
static gint ett_h282_DeviceLockTerminatedIndication = -1;
static gint ett_h282_DeviceControlRequest = -1;
static gint ett_h282_SET_SIZE_1_8_OF_ControlAttribute = -1;
static gint ett_h282_DeviceStatusEnquireRequest = -1;
static gint ett_h282_SET_SIZE_1_16_OF_StatusAttributeIdentifier = -1;
static gint ett_h282_DeviceStatusEnquireResponse = -1;
static gint ett_h282_SET_SIZE_1_16_OF_StatusAttribute = -1;
static gint ett_h282_T_result_05 = -1;
static gint ett_h282_ConfigureDeviceEventsRequest = -1;
static gint ett_h282_SET_OF_DeviceEventIdentifier = -1;
static gint ett_h282_ConfigureDeviceEventsResponse = -1;
static gint ett_h282_T_result_06 = -1;
static gint ett_h282_DeviceEventNotifyIndication = -1;
static gint ett_h282_SET_SIZE_1_8_OF_DeviceEvent = -1;
static gint ett_h282_NonStandardPDU = -1;
static gint ett_h282_RDCPDU = -1;
static gint ett_h282_RequestPDU = -1;
static gint ett_h282_ResponsePDU = -1;
static gint ett_h282_IndicationPDU = -1;

/*--- End of included file: packet-h282-ett.c ---*/
#line 48 "../../asn1/h282/packet-h282-template.c"

/* Dissectors */

/* Subdissectors */


/*--- Included file: packet-h282-fn.c ---*/
#line 1 "../../asn1/h282/packet-h282-fn.c"


static int
dissect_h282_H221NonStandardIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 255, FALSE, NULL);

  return offset;
}



static int
dissect_h282_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string h282_Key_vals[] = {
  {   0, "object" },
  {   1, "h221NonStandard" },
  { 0, NULL }
};

static const per_choice_t Key_choice[] = {
  {   0, &hf_h282_object         , ASN1_NO_EXTENSIONS     , dissect_h282_OBJECT_IDENTIFIER },
  {   1, &hf_h282_h221NonStandard, ASN1_NO_EXTENSIONS     , dissect_h282_H221NonStandardIdentifier },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_Key(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_Key, Key_choice,
                                 NULL);

  return offset;
}



static int
dissect_h282_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t NonStandardParameter_sequence[] = {
  { &hf_h282_key            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_Key },
  { &hf_h282_data           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_NonStandardParameter, NonStandardParameter_sequence);

  return offset;
}



static int
dissect_h282_Handle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const value_string h282_NonStandardIdentifier_vals[] = {
  {   0, "object" },
  {   1, "h221nonStandard" },
  { 0, NULL }
};

static const per_choice_t NonStandardIdentifier_choice[] = {
  {   0, &hf_h282_object         , ASN1_NO_EXTENSIONS     , dissect_h282_OBJECT_IDENTIFIER },
  {   1, &hf_h282_h221nonStandard, ASN1_NO_EXTENSIONS     , dissect_h282_H221NonStandardIdentifier },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_NonStandardIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_NonStandardIdentifier, NonStandardIdentifier_choice,
                                 NULL);

  return offset;
}



static int
dissect_h282_TextString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          0, 255, FALSE);

  return offset;
}



static int
dissect_h282_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h282_DeviceClass_vals[] = {
  {   0, "camera" },
  {   1, "microphone" },
  {   2, "streamPlayerRecorder" },
  {   3, "slideProjector" },
  {   4, "lightSource" },
  {   5, "sourceCombiner" },
  {   6, "nonStandardDevice" },
  { 0, NULL }
};

static const per_choice_t DeviceClass_choice[] = {
  {   0, &hf_h282_camera         , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_microphone     , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_streamPlayerRecorder, ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   3, &hf_h282_slideProjector , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   4, &hf_h282_lightSource    , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   5, &hf_h282_sourceCombiner , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   6, &hf_h282_nonStandardDevice, ASN1_NO_EXTENSIONS     , dissect_h282_NonStandardIdentifier },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_DeviceClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_DeviceClass, DeviceClass_choice,
                                 NULL);

  return offset;
}



static int
dissect_h282_DeviceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_StreamID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_h282_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DeviceProfile_sequence[] = {
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { &hf_h282_audioSourceFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { &hf_h282_audioSinkFlag  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { &hf_h282_videoSourceFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { &hf_h282_videoSinkFlag  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { &hf_h282_remoteControlFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { &hf_h282_instanceNumber , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_255 },
  { &hf_h282_deviceName     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h282_TextString },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceProfile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceProfile, DeviceProfile_sequence);

  return offset;
}


static const per_sequence_t StreamProfile_sequence[] = {
  { &hf_h282_streamID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_StreamID },
  { &hf_h282_videoStreamFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { &hf_h282_sourceChangeFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { &hf_h282_streamName     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h282_TextString },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_StreamProfile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_StreamProfile, StreamProfile_sequence);

  return offset;
}



static int
dissect_h282_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string h282_CapabilityID_vals[] = {
  {   0, "standard" },
  {   1, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t CapabilityID_choice[] = {
  {   0, &hf_h282_standard       , ASN1_NO_EXTENSIONS     , dissect_h282_INTEGER_0_65535 },
  {   1, &hf_h282_nonStandard    , ASN1_NO_EXTENSIONS     , dissect_h282_Key },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CapabilityID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CapabilityID, CapabilityID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_SIZE_0_127_OF_DeviceProfile_set_of[1] = {
  { &hf_h282_deviceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceProfile },
};

static int
dissect_h282_SET_SIZE_0_127_OF_DeviceProfile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_SET_SIZE_0_127_OF_DeviceProfile, SET_SIZE_0_127_OF_DeviceProfile_set_of,
                                             0, 127, FALSE);

  return offset;
}


static const per_sequence_t SET_SIZE_0_127_OF_StreamProfile_set_of[1] = {
  { &hf_h282_streamList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_StreamProfile },
};

static int
dissect_h282_SET_SIZE_0_127_OF_StreamProfile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_SET_SIZE_0_127_OF_StreamProfile, SET_SIZE_0_127_OF_StreamProfile_set_of,
                                             0, 127, FALSE);

  return offset;
}


static const value_string h282_T_applicationData_vals[] = {
  {   0, "deviceList" },
  {   1, "streamList" },
  { 0, NULL }
};

static const per_choice_t T_applicationData_choice[] = {
  {   0, &hf_h282_deviceList     , ASN1_NO_EXTENSIONS     , dissect_h282_SET_SIZE_0_127_OF_DeviceProfile },
  {   1, &hf_h282_streamList     , ASN1_NO_EXTENSIONS     , dissect_h282_SET_SIZE_0_127_OF_StreamProfile },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_applicationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_applicationData, T_applicationData_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NonCollapsingCapabilities_item_sequence[] = {
  { &hf_h282_capabilityID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_CapabilityID },
  { &hf_h282_applicationData, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_applicationData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_NonCollapsingCapabilities_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_NonCollapsingCapabilities_item, NonCollapsingCapabilities_item_sequence);

  return offset;
}


static const per_sequence_t NonCollapsingCapabilities_set_of[1] = {
  { &hf_h282_NonCollapsingCapabilities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_NonCollapsingCapabilities_item },
};

static int
dissect_h282_NonCollapsingCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_h282_NonCollapsingCapabilities, NonCollapsingCapabilities_set_of);

  return offset;
}



static int
dissect_h282_Day(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_Month(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 12U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_Year(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1980U, 2999U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_Hour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 23U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_Minute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_DeviceText(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       0, 32, FALSE, NULL);

  return offset;
}



static int
dissect_h282_PanPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -18000, 18000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_TiltPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -18000, 18000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_ZoomPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1023, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_IrisPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_FocusPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_CameraPanSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 18000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_CameraTiltSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 18000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_BackLight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_WhiteBalance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_PresetNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string h282_StreamPlayerState_vals[] = {
  {   0, "playing" },
  {   1, "recording" },
  {   2, "pausedOnRecord" },
  {   3, "pausedOnPlay" },
  {   4, "rewinding" },
  {   5, "fastForwarding" },
  {   6, "searchingForwards" },
  {   7, "searchingBackwards" },
  {   8, "stopped" },
  {   9, "programUnavailable" },
  { 0, NULL }
};

static const per_choice_t StreamPlayerState_choice[] = {
  {   0, &hf_h282_playing        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_recording      , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_pausedOnRecord , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   3, &hf_h282_pausedOnPlay   , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   4, &hf_h282_rewinding      , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   5, &hf_h282_fastForwarding , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   6, &hf_h282_searchingForwards, ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   7, &hf_h282_searchingBackwards, ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   8, &hf_h282_stopped        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   9, &hf_h282_programUnavailable, ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_StreamPlayerState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_StreamPlayerState, StreamPlayerState_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_presetCapability_item_sequence[] = {
  { &hf_h282_presetNumber   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PresetNumber },
  { &hf_h282_storeModeSupported, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { &hf_h282_presetTextLabel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceText },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_T_presetCapability_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_T_presetCapability_item, T_presetCapability_item_sequence);

  return offset;
}


static const per_sequence_t T_presetCapability_set_of[1] = {
  { &hf_h282_presetCapability_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_presetCapability_item },
};

static int
dissect_h282_T_presetCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_presetCapability, T_presetCapability_set_of,
                                             0, 255, FALSE);

  return offset;
}


static const per_sequence_t DevicePresetCapability_sequence[] = {
  { &hf_h282_maxNumber      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PresetNumber },
  { &hf_h282_presetCapability, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h282_T_presetCapability },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DevicePresetCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DevicePresetCapability, DevicePresetCapability_sequence);

  return offset;
}



static int
dissect_h282_INTEGER_2_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_1_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_filterTextLabel_item_sequence[] = {
  { &hf_h282_filterNumber   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_1_255 },
  { &hf_h282_filterTextLabel_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceText },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_T_filterTextLabel_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_T_filterTextLabel_item, T_filterTextLabel_item_sequence);

  return offset;
}


static const per_sequence_t T_filterTextLabel_set_of[1] = {
  { &hf_h282_filterTextLabel_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_filterTextLabel_item },
};

static int
dissect_h282_T_filterTextLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_filterTextLabel, T_filterTextLabel_set_of,
                                             0, 255, FALSE);

  return offset;
}


static const per_sequence_t CameraFilterCapability_sequence[] = {
  { &hf_h282_maxNumberOfFilters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_2_255 },
  { &hf_h282_filterTextLabel, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h282_T_filterTextLabel },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_CameraFilterCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_CameraFilterCapability, CameraFilterCapability_sequence);

  return offset;
}


static const per_sequence_t T_accessoryTextLabel_item_sequence[] = {
  { &hf_h282_lensNumber     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_1_255 },
  { &hf_h282_lensTextLabel  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceText },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_T_accessoryTextLabel_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_T_accessoryTextLabel_item, T_accessoryTextLabel_item_sequence);

  return offset;
}


static const per_sequence_t T_accessoryTextLabel_set_of[1] = {
  { &hf_h282_accessoryTextLabel_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_accessoryTextLabel_item },
};

static int
dissect_h282_T_accessoryTextLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_accessoryTextLabel, T_accessoryTextLabel_set_of,
                                             0, 255, FALSE);

  return offset;
}


static const per_sequence_t CameraLensCapability_sequence[] = {
  { &hf_h282_maxNumberOfLens, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_2_255 },
  { &hf_h282_accessoryTextLabel, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h282_T_accessoryTextLabel },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_CameraLensCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_CameraLensCapability, CameraLensCapability_sequence);

  return offset;
}



static int
dissect_h282_INTEGER_1_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 10U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_lightTextLabel_item_sequence[] = {
  { &hf_h282_lightNumber    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_1_10 },
  { &hf_h282_lightLabel     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceText },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_T_lightTextLabel_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_T_lightTextLabel_item, T_lightTextLabel_item_sequence);

  return offset;
}


static const per_sequence_t T_lightTextLabel_set_of[1] = {
  { &hf_h282_lightTextLabel_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_lightTextLabel_item },
};

static int
dissect_h282_T_lightTextLabel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_lightTextLabel, T_lightTextLabel_set_of,
                                             0, 10, FALSE);

  return offset;
}


static const per_sequence_t ExternalCameraLightCapability_sequence[] = {
  { &hf_h282_maxNumber_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_1_10 },
  { &hf_h282_lightTextLabel , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h282_T_lightTextLabel },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_ExternalCameraLightCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_ExternalCameraLightCapability, ExternalCameraLightCapability_sequence);

  return offset;
}


static const per_sequence_t CameraPanSpeedCapability_sequence[] = {
  { &hf_h282_maxSpeed       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_CameraPanSpeed },
  { &hf_h282_minSpeed       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_CameraPanSpeed },
  { &hf_h282_speedStepSize  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_CameraPanSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_CameraPanSpeedCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_CameraPanSpeedCapability, CameraPanSpeedCapability_sequence);

  return offset;
}


static const per_sequence_t CameraTiltSpeedCapability_sequence[] = {
  { &hf_h282_maxSpeed_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_CameraTiltSpeed },
  { &hf_h282_minSpeed_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_CameraTiltSpeed },
  { &hf_h282_speedStepSize_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_CameraTiltSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_CameraTiltSpeedCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_CameraTiltSpeedCapability, CameraTiltSpeedCapability_sequence);

  return offset;
}



static int
dissect_h282_MaxBacklight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_MaxWhiteBalance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_MinZoomPositionSetSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_MinFocusPositionStepSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_MinIrisPositionStepSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_M18000_0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -18000, 0U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_0_18000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 18000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_1_18000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 18000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PanPositionCapability_sequence[] = {
  { &hf_h282_maxLeft        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_M18000_0 },
  { &hf_h282_maxRight       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_18000 },
  { &hf_h282_minStepSize    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_1_18000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_PanPositionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_PanPositionCapability, PanPositionCapability_sequence);

  return offset;
}


static const per_sequence_t TiltPositionCapability_sequence[] = {
  { &hf_h282_maxDown        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_M18000_0 },
  { &hf_h282_maxUp          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_18000 },
  { &hf_h282_minStepSize    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_1_18000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_TiltPositionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_TiltPositionCapability, TiltPositionCapability_sequence);

  return offset;
}



static int
dissect_h282_MinZoomMagnificationStepSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_MaxNumberOfSlides(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_MaxSlideDisplayTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_MaxNumberOfPrograms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_10_1000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            10U, 1000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_multiplierFactors_set_of[1] = {
  { &hf_h282_multiplierFactors_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_10_1000 },
};

static int
dissect_h282_T_multiplierFactors(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_multiplierFactors, T_multiplierFactors_set_of,
                                             1, 64, FALSE);

  return offset;
}


static const per_sequence_t T_divisorFactors_set_of[1] = {
  { &hf_h282_divisorFactors_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_10_1000 },
};

static int
dissect_h282_T_divisorFactors(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_divisorFactors, T_divisorFactors_set_of,
                                             1, 64, FALSE);

  return offset;
}


static const per_sequence_t PlayBackSpeedCapability_sequence[] = {
  { &hf_h282_multiplierFactors, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_multiplierFactors },
  { &hf_h282_divisorFactors , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_divisorFactors },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_PlayBackSpeedCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_PlayBackSpeedCapability, PlayBackSpeedCapability_sequence);

  return offset;
}



static int
dissect_h282_INTEGER_2_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 64U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_1_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_availableDevices_item_sequence[] = {
  { &hf_h282_deviceClass    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_T_availableDevices_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_T_availableDevices_item, T_availableDevices_item_sequence);

  return offset;
}


static const per_sequence_t T_availableDevices_set_of[1] = {
  { &hf_h282_availableDevices_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_availableDevices_item },
};

static int
dissect_h282_T_availableDevices(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_availableDevices, T_availableDevices_set_of,
                                             2, 64, FALSE);

  return offset;
}


static const per_sequence_t VideoInputsCapability_sequence[] = {
  { &hf_h282_numberOfDeviceInputs, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_2_64 },
  { &hf_h282_numberOfDeviceRows, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_1_64 },
  { &hf_h282_availableDevices, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h282_T_availableDevices },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_VideoInputsCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_VideoInputsCapability, VideoInputsCapability_sequence);

  return offset;
}


static const per_sequence_t T_availableDevices_item_01_sequence[] = {
  { &hf_h282_deviceClass    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_T_availableDevices_item_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_T_availableDevices_item_01, T_availableDevices_item_01_sequence);

  return offset;
}


static const per_sequence_t T_availableDevices_01_set_of[1] = {
  { &hf_h282_availableDevices_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_availableDevices_item_01 },
};

static int
dissect_h282_T_availableDevices_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_availableDevices_01, T_availableDevices_01_set_of,
                                             2, 64, FALSE);

  return offset;
}


static const per_sequence_t AudioInputsCapability_sequence[] = {
  { &hf_h282_numberOfDeviceInputs, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_2_64 },
  { &hf_h282_availableDevices_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_h282_T_availableDevices_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_AudioInputsCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_AudioInputsCapability, AudioInputsCapability_sequence);

  return offset;
}


static const value_string h282_DeviceAttribute_vals[] = {
  {   0, "deviceStateSupported" },
  {   1, "deviceDateSupported" },
  {   2, "deviceTimeSupported" },
  {   3, "devicePresetSupported" },
  {   4, "irisModeSupported" },
  {   5, "focusModeSupported" },
  {   6, "pointingModeSupported" },
  {   7, "cameraLensSupported" },
  {   8, "cameraFilterSupported" },
  {   9, "homePositionSupported" },
  {  10, "externalCameraLightSupported" },
  {  11, "clearCameraLensSupported" },
  {  12, "cameraPanSpeedSupported" },
  {  13, "cameraTiltSpeedSupported" },
  {  14, "backLightModeSupported" },
  {  15, "backLightSettingSupported" },
  {  16, "whiteBalanceSettingSupported" },
  {  17, "whiteBalanceModeSupported" },
  {  18, "calibrateWhiteBalanceSupported" },
  {  19, "focusImageSupported" },
  {  20, "captureImageSupported" },
  {  21, "panContinuousSupported" },
  {  22, "tiltContinuousSupported" },
  {  23, "zoomContinuousSupported" },
  {  24, "focusContinuousSupported" },
  {  25, "irisContinuousSupported" },
  {  26, "zoomPositionSupported" },
  {  27, "focusPositionSupported" },
  {  28, "irisPositionSupported" },
  {  29, "panPositionSupported" },
  {  30, "tiltPositionSupported" },
  {  31, "zoomMagnificationSupported" },
  {  32, "panViewSupported" },
  {  33, "tiltViewSupported" },
  {  34, "selectSlideSupported" },
  {  35, "selectNextSlideSupported" },
  {  36, "slideShowModeSupported" },
  {  37, "playSlideShowSupported" },
  {  38, "setSlideDisplayTimeSupported" },
  {  39, "continuousRewindSupported" },
  {  40, "continuousFastForwardSupported" },
  {  41, "searchBackwardsSupported" },
  {  42, "searchForwardsSupported" },
  {  43, "pauseSupported" },
  {  44, "selectProgramSupported" },
  {  45, "nextProgramSupported" },
  {  46, "gotoNormalPlayTimePointSupported" },
  {  47, "readStreamPlayerStateSupported" },
  {  48, "readProgramDurationSupported" },
  {  49, "continuousPlayBackModeSupported" },
  {  50, "playbackSpeedSupported" },
  {  51, "playSupported" },
  {  52, "setAudioOutputStateSupported" },
  {  53, "playToNormalPlayTimePointSupported" },
  {  54, "recordSupported" },
  {  55, "recordForDurationSupported" },
  {  56, "configurableVideoInputsSupported" },
  {  57, "videoInputsSupported" },
  {  58, "configurableAudioInputsSupported" },
  {  59, "audioInputsSupported" },
  {  60, "deviceLockStateChangedSupported" },
  {  61, "deviceAvailabilityChangedSupported" },
  {  62, "cameraPannedToLimitSupported" },
  {  63, "cameraTiltedToLimitSupported" },
  {  64, "cameraZoomedToLimitSupported" },
  {  65, "cameraFocusedToLimitSupported" },
  {  66, "autoSlideShowFinishedSupported" },
  {  67, "streamPlayerStateChangeSupported" },
  {  68, "streamPlayerProgramChangeSupported" },
  {  69, "nonStandardAttributeSupported" },
  { 0, NULL }
};

static const per_choice_t DeviceAttribute_choice[] = {
  {   0, &hf_h282_deviceStateSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_deviceDateSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_deviceTimeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   3, &hf_h282_devicePresetSupported, ASN1_EXTENSION_ROOT    , dissect_h282_DevicePresetCapability },
  {   4, &hf_h282_irisModeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   5, &hf_h282_focusModeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   6, &hf_h282_pointingModeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   7, &hf_h282_cameraLensSupported, ASN1_EXTENSION_ROOT    , dissect_h282_CameraLensCapability },
  {   8, &hf_h282_cameraFilterSupported, ASN1_EXTENSION_ROOT    , dissect_h282_CameraFilterCapability },
  {   9, &hf_h282_homePositionSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  10, &hf_h282_externalCameraLightSupported, ASN1_EXTENSION_ROOT    , dissect_h282_ExternalCameraLightCapability },
  {  11, &hf_h282_clearCameraLensSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  12, &hf_h282_cameraPanSpeedSupported, ASN1_EXTENSION_ROOT    , dissect_h282_CameraPanSpeedCapability },
  {  13, &hf_h282_cameraTiltSpeedSupported, ASN1_EXTENSION_ROOT    , dissect_h282_CameraTiltSpeedCapability },
  {  14, &hf_h282_backLightModeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  15, &hf_h282_backLightSettingSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MaxBacklight },
  {  16, &hf_h282_whiteBalanceSettingSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MaxWhiteBalance },
  {  17, &hf_h282_whiteBalanceModeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  18, &hf_h282_calibrateWhiteBalanceSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  19, &hf_h282_focusImageSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  20, &hf_h282_captureImageSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  21, &hf_h282_panContinuousSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  22, &hf_h282_tiltContinuousSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  23, &hf_h282_zoomContinuousSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  24, &hf_h282_focusContinuousSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  25, &hf_h282_irisContinuousSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  26, &hf_h282_zoomPositionSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MinZoomPositionSetSize },
  {  27, &hf_h282_focusPositionSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MinFocusPositionStepSize },
  {  28, &hf_h282_irisPositionSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MinIrisPositionStepSize },
  {  29, &hf_h282_panPositionSupported, ASN1_EXTENSION_ROOT    , dissect_h282_PanPositionCapability },
  {  30, &hf_h282_tiltPositionSupported, ASN1_EXTENSION_ROOT    , dissect_h282_TiltPositionCapability },
  {  31, &hf_h282_zoomMagnificationSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MinZoomMagnificationStepSize },
  {  32, &hf_h282_panViewSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  33, &hf_h282_tiltViewSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  34, &hf_h282_selectSlideSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MaxNumberOfSlides },
  {  35, &hf_h282_selectNextSlideSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  36, &hf_h282_slideShowModeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  37, &hf_h282_playSlideShowSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  38, &hf_h282_setSlideDisplayTimeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MaxSlideDisplayTime },
  {  39, &hf_h282_continuousRewindSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  40, &hf_h282_continuousFastForwardSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  41, &hf_h282_searchBackwardsSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  42, &hf_h282_searchForwardsSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  43, &hf_h282_pauseSupported , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  44, &hf_h282_selectProgramSupported, ASN1_EXTENSION_ROOT    , dissect_h282_MaxNumberOfPrograms },
  {  45, &hf_h282_nextProgramSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  46, &hf_h282_gotoNormalPlayTimePointSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  47, &hf_h282_readStreamPlayerStateSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  48, &hf_h282_readProgramDurationSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  49, &hf_h282_continuousPlayBackModeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  50, &hf_h282_playbackSpeedSupported, ASN1_EXTENSION_ROOT    , dissect_h282_PlayBackSpeedCapability },
  {  51, &hf_h282_playSupported  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  52, &hf_h282_setAudioOutputStateSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  53, &hf_h282_playToNormalPlayTimePointSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  54, &hf_h282_recordSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  55, &hf_h282_recordForDurationSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  56, &hf_h282_configurableVideoInputsSupported, ASN1_EXTENSION_ROOT    , dissect_h282_VideoInputsCapability },
  {  57, &hf_h282_videoInputsSupported, ASN1_EXTENSION_ROOT    , dissect_h282_VideoInputsCapability },
  {  58, &hf_h282_configurableAudioInputsSupported, ASN1_EXTENSION_ROOT    , dissect_h282_AudioInputsCapability },
  {  59, &hf_h282_audioInputsSupported, ASN1_EXTENSION_ROOT    , dissect_h282_AudioInputsCapability },
  {  60, &hf_h282_deviceLockStateChangedSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  61, &hf_h282_deviceAvailabilityChangedSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  62, &hf_h282_cameraPannedToLimitSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  63, &hf_h282_cameraTiltedToLimitSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  64, &hf_h282_cameraZoomedToLimitSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  65, &hf_h282_cameraFocusedToLimitSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  66, &hf_h282_autoSlideShowFinishedSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  67, &hf_h282_streamPlayerStateChangeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  68, &hf_h282_streamPlayerProgramChangeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  69, &hf_h282_nonStandardAttributeSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_DeviceAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_DeviceAttribute, DeviceAttribute_choice,
                                 NULL);

  return offset;
}


static const value_string h282_DeviceState_vals[] = {
  {   0, "active" },
  {   1, "inactive" },
  { 0, NULL }
};

static const per_choice_t DeviceState_choice[] = {
  {   0, &hf_h282_active         , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_inactive       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_DeviceState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_DeviceState, DeviceState_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DeviceDate_sequence[] = {
  { &hf_h282_day            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_Day },
  { &hf_h282_month          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_Month },
  { &hf_h282_year           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_Year },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceDate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceDate, DeviceDate_sequence);

  return offset;
}


static const per_sequence_t DeviceTime_sequence[] = {
  { &hf_h282_hour           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_Hour },
  { &hf_h282_minute         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_Minute },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceTime, DeviceTime_sequence);

  return offset;
}


static const value_string h282_T_mode_vals[] = {
  {   0, "store" },
  {   1, "activate" },
  { 0, NULL }
};

static const per_choice_t T_mode_choice[] = {
  {   0, &hf_h282_store          , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_activate       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_mode, T_mode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DevicePreset_sequence[] = {
  { &hf_h282_presetNumber   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PresetNumber },
  { &hf_h282_mode           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_mode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DevicePreset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DevicePreset, DevicePreset_sequence);

  return offset;
}


static const value_string h282_Mode_vals[] = {
  {   0, "manual" },
  {   1, "auto" },
  { 0, NULL }
};

static const per_choice_t Mode_choice[] = {
  {   0, &hf_h282_manual         , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_auto           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_Mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_Mode, Mode_choice,
                                 NULL);

  return offset;
}


static const value_string h282_PointingToggle_vals[] = {
  {   0, "manual" },
  {   1, "auto" },
  {   2, "toggle" },
  { 0, NULL }
};

static const per_choice_t PointingToggle_choice[] = {
  {   0, &hf_h282_manual         , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_auto           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_toggle         , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_PointingToggle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_PointingToggle, PointingToggle_choice,
                                 NULL);

  return offset;
}


static const value_string h282_SelectExternalLight_vals[] = {
  {   0, "lightNumber" },
  {   1, "none" },
  { 0, NULL }
};

static const per_choice_t SelectExternalLight_choice[] = {
  {   0, &hf_h282_lightNumber    , ASN1_NO_EXTENSIONS     , dissect_h282_INTEGER_1_10 },
  {   1, &hf_h282_none           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_SelectExternalLight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_SelectExternalLight, SelectExternalLight_choice,
                                 NULL);

  return offset;
}


static const value_string h282_T_panDirection_vals[] = {
  {   0, "left" },
  {   1, "right" },
  {   2, "stop" },
  {   3, "continue" },
  { 0, NULL }
};

static const per_choice_t T_panDirection_choice[] = {
  {   0, &hf_h282_left           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_right          , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_stop           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   3, &hf_h282_continue       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_panDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_panDirection, T_panDirection_choice,
                                 NULL);

  return offset;
}



static int
dissect_h282_INTEGER_50_1000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            50U, 1000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PanContinuous_sequence[] = {
  { &hf_h282_panDirection   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_panDirection },
  { &hf_h282_timeOut        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_50_1000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_PanContinuous(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_PanContinuous, PanContinuous_sequence);

  return offset;
}


static const value_string h282_T_tiltDirection_vals[] = {
  {   0, "up" },
  {   1, "down" },
  {   2, "stop" },
  {   3, "continue" },
  { 0, NULL }
};

static const per_choice_t T_tiltDirection_choice[] = {
  {   0, &hf_h282_up             , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_down           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_stop           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   3, &hf_h282_continue       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_tiltDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_tiltDirection, T_tiltDirection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TiltContinuous_sequence[] = {
  { &hf_h282_tiltDirection  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_tiltDirection },
  { &hf_h282_timeOut        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_50_1000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_TiltContinuous(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_TiltContinuous, TiltContinuous_sequence);

  return offset;
}


static const value_string h282_T_zoomDirection_vals[] = {
  {   0, "telescopic" },
  {   1, "wide" },
  {   2, "stop" },
  {   3, "continue" },
  { 0, NULL }
};

static const per_choice_t T_zoomDirection_choice[] = {
  {   0, &hf_h282_telescopic     , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_wide           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_stop           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   3, &hf_h282_continue       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_zoomDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_zoomDirection, T_zoomDirection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ZoomContinuous_sequence[] = {
  { &hf_h282_zoomDirection  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_zoomDirection },
  { &hf_h282_timeOut        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_50_1000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_ZoomContinuous(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_ZoomContinuous, ZoomContinuous_sequence);

  return offset;
}


static const value_string h282_T_focusDirection_vals[] = {
  {   0, "near" },
  {   1, "far" },
  {   2, "stop" },
  {   3, "continue" },
  { 0, NULL }
};

static const per_choice_t T_focusDirection_choice[] = {
  {   0, &hf_h282_near           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_far            , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_stop           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   3, &hf_h282_continue       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_focusDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_focusDirection, T_focusDirection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t FocusContinuous_sequence[] = {
  { &hf_h282_focusDirection , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_focusDirection },
  { &hf_h282_timeOut        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_50_1000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_FocusContinuous(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_FocusContinuous, FocusContinuous_sequence);

  return offset;
}


static const value_string h282_PositioningMode_vals[] = {
  {   0, "relative" },
  {   1, "absolute" },
  { 0, NULL }
};

static const per_choice_t PositioningMode_choice[] = {
  {   0, &hf_h282_relative       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_absolute       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_PositioningMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_PositioningMode, PositioningMode_choice,
                                 NULL);

  return offset;
}



static int
dissect_h282_CameraLensNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_CameraFilterNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SetZoomPosition_sequence[] = {
  { &hf_h282_zoomPosition   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_ZoomPosition },
  { &hf_h282_positioningMode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PositioningMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SetZoomPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SetZoomPosition, SetZoomPosition_sequence);

  return offset;
}


static const per_sequence_t SetFocusPosition_sequence[] = {
  { &hf_h282_focusPosition  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_FocusPosition },
  { &hf_h282_positioningMode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PositioningMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SetFocusPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SetFocusPosition, SetFocusPosition_sequence);

  return offset;
}


static const per_sequence_t SetIrisPosition_sequence[] = {
  { &hf_h282_irisPosition   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_IrisPosition },
  { &hf_h282_positioningMode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PositioningMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SetIrisPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SetIrisPosition, SetIrisPosition_sequence);

  return offset;
}


static const per_sequence_t SetPanPosition_sequence[] = {
  { &hf_h282_panPosition    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PanPosition },
  { &hf_h282_positioningMode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PositioningMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SetPanPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SetPanPosition, SetPanPosition_sequence);

  return offset;
}


static const per_sequence_t SetTiltPosition_sequence[] = {
  { &hf_h282_tiltPosition   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_TiltPosition },
  { &hf_h282_positioningMode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_PositioningMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SetTiltPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SetTiltPosition, SetTiltPosition_sequence);

  return offset;
}



static int
dissect_h282_ZoomMagnification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            10U, 1000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_PanView(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1000, 1000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_TiltView(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1000, 1000U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_SlideNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}


static const value_string h282_SelectDirection_vals[] = {
  {   0, "next" },
  {   1, "previous" },
  { 0, NULL }
};

static const per_choice_t SelectDirection_choice[] = {
  {   0, &hf_h282_next           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_previous       , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_SelectDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_SelectDirection, SelectDirection_choice,
                                 NULL);

  return offset;
}


static const value_string h282_AutoSlideShowControl_vals[] = {
  {   0, "start" },
  {   1, "stop" },
  {   2, "pause" },
  { 0, NULL }
};

static const per_choice_t AutoSlideShowControl_choice[] = {
  {   0, &hf_h282_start          , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_stop           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_pause          , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_AutoSlideShowControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_AutoSlideShowControl, AutoSlideShowControl_choice,
                                 NULL);

  return offset;
}



static int
dissect_h282_AutoSlideDisplayTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_ProgramNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_0_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 24U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_0_59(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}



static int
dissect_h282_INTEGER_0_99999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 99999U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ProgramDuration_sequence[] = {
  { &hf_h282_hours          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_24 },
  { &hf_h282_minutes        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_59 },
  { &hf_h282_seconds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_59 },
  { &hf_h282_microseconds   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_99999 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_ProgramDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_ProgramDuration, ProgramDuration_sequence);

  return offset;
}


static const per_sequence_t PlaybackSpeed_sequence[] = {
  { &hf_h282_scaleFactor    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_10_1000 },
  { &hf_h282_multiplyFactor , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_PlaybackSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_PlaybackSpeed, PlaybackSpeed_sequence);

  return offset;
}


static const per_sequence_t RecordForDuration_sequence[] = {
  { &hf_h282_hours          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_24 },
  { &hf_h282_minutes        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_59 },
  { &hf_h282_seconds        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_INTEGER_0_59 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_RecordForDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_RecordForDuration, RecordForDuration_sequence);

  return offset;
}


static const per_sequence_t T_inputDevices_item_sequence[] = {
  { &hf_h282_deviceClass    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_T_inputDevices_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_T_inputDevices_item, T_inputDevices_item_sequence);

  return offset;
}


static const per_sequence_t T_inputDevices_set_of[1] = {
  { &hf_h282_inputDevices_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_inputDevices_item },
};

static int
dissect_h282_T_inputDevices(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_T_inputDevices, T_inputDevices_set_of,
                                             2, 64, FALSE);

  return offset;
}


static const per_sequence_t DeviceInputs_sequence[] = {
  { &hf_h282_inputDevices   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_inputDevices },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceInputs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceInputs, DeviceInputs_sequence);

  return offset;
}


static const value_string h282_ControlAttribute_vals[] = {
  {   0, "setDeviceState" },
  {   1, "setDeviceDate" },
  {   2, "setDeviceTime" },
  {   3, "setDevicePreset" },
  {   4, "setIrisMode" },
  {   5, "setFocusMode" },
  {   6, "setBackLightMode" },
  {   7, "setPointingMode" },
  {   8, "selectCameraLens" },
  {   9, "selectCameraFilter" },
  {  10, "gotoHomePosition" },
  {  11, "selectExternalLight" },
  {  12, "clearCameraLens" },
  {  13, "setCameraPanSpeed" },
  {  14, "setCameraTiltSpeed" },
  {  15, "setBackLight" },
  {  16, "setWhiteBalance" },
  {  17, "setWhiteBalanceMode" },
  {  18, "calibrateWhiteBalance" },
  {  19, "focusImage" },
  {  20, "captureImage" },
  {  21, "panContinuous" },
  {  22, "tiltContinuous" },
  {  23, "zoomContinuous" },
  {  24, "focusContinuous" },
  {  25, "setZoomPosition" },
  {  26, "setFocusPosition" },
  {  27, "setIrisPosition" },
  {  28, "setPanPosition" },
  {  29, "setTiltPosition" },
  {  30, "setZoomMagnification" },
  {  31, "setPanView" },
  {  32, "setTiltView" },
  {  33, "selectSlide" },
  {  34, "selectNextSlide" },
  {  35, "playAutoSlideShow" },
  {  36, "setAutoSlideDisplayTime" },
  {  37, "continuousRewindControl" },
  {  38, "continuousFastForwardControl" },
  {  39, "searchBackwardsControl" },
  {  40, "searchForwardsControl" },
  {  41, "pause" },
  {  42, "selectProgram" },
  {  43, "nextProgramSelect" },
  {  44, "gotoNormalPlayTimePoint" },
  {  45, "continuousPlayBackMode" },
  {  46, "setPlaybackSpeed" },
  {  47, "play" },
  {  48, "setAudioOutputMute" },
  {  49, "playToNormalPlayTimePoint" },
  {  50, "record" },
  {  51, "recordForDuration" },
  {  52, "configureVideoInputs" },
  {  53, "configureAudioInputs" },
  {  54, "nonStandardControl" },
  { 0, NULL }
};

static const per_choice_t ControlAttribute_choice[] = {
  {   0, &hf_h282_setDeviceState , ASN1_EXTENSION_ROOT    , dissect_h282_DeviceState },
  {   1, &hf_h282_setDeviceDate  , ASN1_EXTENSION_ROOT    , dissect_h282_DeviceDate },
  {   2, &hf_h282_setDeviceTime  , ASN1_EXTENSION_ROOT    , dissect_h282_DeviceTime },
  {   3, &hf_h282_setDevicePreset, ASN1_EXTENSION_ROOT    , dissect_h282_DevicePreset },
  {   4, &hf_h282_setIrisMode    , ASN1_EXTENSION_ROOT    , dissect_h282_Mode },
  {   5, &hf_h282_setFocusMode   , ASN1_EXTENSION_ROOT    , dissect_h282_Mode },
  {   6, &hf_h282_setBackLightMode, ASN1_EXTENSION_ROOT    , dissect_h282_Mode },
  {   7, &hf_h282_setPointingMode, ASN1_EXTENSION_ROOT    , dissect_h282_PointingToggle },
  {   8, &hf_h282_selectCameraLens, ASN1_EXTENSION_ROOT    , dissect_h282_CameraLensNumber },
  {   9, &hf_h282_selectCameraFilter, ASN1_EXTENSION_ROOT    , dissect_h282_CameraFilterNumber },
  {  10, &hf_h282_gotoHomePosition, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  11, &hf_h282_selectExternalLight, ASN1_EXTENSION_ROOT    , dissect_h282_SelectExternalLight },
  {  12, &hf_h282_clearCameraLens, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  13, &hf_h282_setCameraPanSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_CameraPanSpeed },
  {  14, &hf_h282_setCameraTiltSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_CameraTiltSpeed },
  {  15, &hf_h282_setBackLight   , ASN1_EXTENSION_ROOT    , dissect_h282_BackLight },
  {  16, &hf_h282_setWhiteBalance, ASN1_EXTENSION_ROOT    , dissect_h282_WhiteBalance },
  {  17, &hf_h282_setWhiteBalanceMode, ASN1_EXTENSION_ROOT    , dissect_h282_Mode },
  {  18, &hf_h282_calibrateWhiteBalance, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  19, &hf_h282_focusImage     , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  20, &hf_h282_captureImage   , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  21, &hf_h282_panContinuous  , ASN1_EXTENSION_ROOT    , dissect_h282_PanContinuous },
  {  22, &hf_h282_tiltContinuous , ASN1_EXTENSION_ROOT    , dissect_h282_TiltContinuous },
  {  23, &hf_h282_zoomContinuous , ASN1_EXTENSION_ROOT    , dissect_h282_ZoomContinuous },
  {  24, &hf_h282_focusContinuous, ASN1_EXTENSION_ROOT    , dissect_h282_FocusContinuous },
  {  25, &hf_h282_setZoomPosition, ASN1_EXTENSION_ROOT    , dissect_h282_SetZoomPosition },
  {  26, &hf_h282_setFocusPosition, ASN1_EXTENSION_ROOT    , dissect_h282_SetFocusPosition },
  {  27, &hf_h282_setIrisPosition, ASN1_EXTENSION_ROOT    , dissect_h282_SetIrisPosition },
  {  28, &hf_h282_setPanPosition , ASN1_EXTENSION_ROOT    , dissect_h282_SetPanPosition },
  {  29, &hf_h282_setTiltPosition, ASN1_EXTENSION_ROOT    , dissect_h282_SetTiltPosition },
  {  30, &hf_h282_setZoomMagnification, ASN1_EXTENSION_ROOT    , dissect_h282_ZoomMagnification },
  {  31, &hf_h282_setPanView     , ASN1_EXTENSION_ROOT    , dissect_h282_PanView },
  {  32, &hf_h282_setTiltView    , ASN1_EXTENSION_ROOT    , dissect_h282_TiltView },
  {  33, &hf_h282_selectSlide    , ASN1_EXTENSION_ROOT    , dissect_h282_SlideNumber },
  {  34, &hf_h282_selectNextSlide, ASN1_EXTENSION_ROOT    , dissect_h282_SelectDirection },
  {  35, &hf_h282_playAutoSlideShow, ASN1_EXTENSION_ROOT    , dissect_h282_AutoSlideShowControl },
  {  36, &hf_h282_setAutoSlideDisplayTime, ASN1_EXTENSION_ROOT    , dissect_h282_AutoSlideDisplayTime },
  {  37, &hf_h282_continuousRewindControl, ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  38, &hf_h282_continuousFastForwardControl, ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  39, &hf_h282_searchBackwardsControl, ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  40, &hf_h282_searchForwardsControl, ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  41, &hf_h282_pause_01       , ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  42, &hf_h282_selectProgram  , ASN1_EXTENSION_ROOT    , dissect_h282_ProgramNumber },
  {  43, &hf_h282_nextProgramSelect, ASN1_EXTENSION_ROOT    , dissect_h282_SelectDirection },
  {  44, &hf_h282_gotoNormalPlayTimePoint, ASN1_EXTENSION_ROOT    , dissect_h282_ProgramDuration },
  {  45, &hf_h282_continuousPlayBackMode, ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  46, &hf_h282_setPlaybackSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_PlaybackSpeed },
  {  47, &hf_h282_play           , ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  48, &hf_h282_setAudioOutputMute, ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  49, &hf_h282_playToNormalPlayTimePoint, ASN1_EXTENSION_ROOT    , dissect_h282_ProgramDuration },
  {  50, &hf_h282_record         , ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {  51, &hf_h282_recordForDuration, ASN1_EXTENSION_ROOT    , dissect_h282_RecordForDuration },
  {  52, &hf_h282_configureVideoInputs, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceInputs },
  {  53, &hf_h282_configureAudioInputs, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceInputs },
  {  54, &hf_h282_nonStandardControl, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_ControlAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_ControlAttribute, ControlAttribute_choice,
                                 NULL);

  return offset;
}


static const value_string h282_StatusAttributeIdentifier_vals[] = {
  {   0, "getDeviceState" },
  {   1, "getDeviceDate" },
  {   2, "getDeviceTime" },
  {   3, "getdevicePreset" },
  {   4, "getIrisMode" },
  {   5, "getFocusMode" },
  {   6, "getBacklightMode" },
  {   7, "getPointingMode" },
  {   8, "getCameraLens" },
  {   9, "getCameraFilter" },
  {  10, "getExternalLight" },
  {  11, "getCameraPanSpeed" },
  {  12, "getCameraTiltSpeed" },
  {  13, "getBackLightMode" },
  {  14, "getBackLight" },
  {  15, "getWhiteBalance" },
  {  16, "getWhiteBalanceMode" },
  {  17, "getZoomPosition" },
  {  18, "getFocusPosition" },
  {  19, "getIrisPosition" },
  {  20, "getPanPosition" },
  {  21, "getTiltPosition" },
  {  22, "getSelectedSlide" },
  {  23, "getAutoSlideDisplayTime" },
  {  24, "getSelectedProgram" },
  {  25, "getStreamPlayerState" },
  {  26, "getCurrentProgramDuration" },
  {  27, "getPlaybackSpeed" },
  {  28, "getAudioOutputState" },
  {  29, "getConfigurableVideoInputs" },
  {  30, "getVideoInputs" },
  {  31, "getConfigurableAudioInputs" },
  {  32, "getAudioInputs" },
  {  33, "getNonStandardStatus" },
  { 0, NULL }
};

static const per_choice_t StatusAttributeIdentifier_choice[] = {
  {   0, &hf_h282_getDeviceState , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_getDeviceDate  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_getDeviceTime  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   3, &hf_h282_getdevicePreset, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   4, &hf_h282_getIrisMode    , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   5, &hf_h282_getFocusMode   , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   6, &hf_h282_getBacklightMode, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   7, &hf_h282_getPointingMode, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   8, &hf_h282_getCameraLens  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   9, &hf_h282_getCameraFilter, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  10, &hf_h282_getExternalLight, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  11, &hf_h282_getCameraPanSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  12, &hf_h282_getCameraTiltSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  13, &hf_h282_getBackLightMode, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  14, &hf_h282_getBackLight   , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  15, &hf_h282_getWhiteBalance, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  16, &hf_h282_getWhiteBalanceMode, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  17, &hf_h282_getZoomPosition, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  18, &hf_h282_getFocusPosition, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  19, &hf_h282_getIrisPosition, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  20, &hf_h282_getPanPosition , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  21, &hf_h282_getTiltPosition, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  22, &hf_h282_getSelectedSlide, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  23, &hf_h282_getAutoSlideDisplayTime, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  24, &hf_h282_getSelectedProgram, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  25, &hf_h282_getStreamPlayerState, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  26, &hf_h282_getCurrentProgramDuration, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  27, &hf_h282_getPlaybackSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  28, &hf_h282_getAudioOutputState, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  29, &hf_h282_getConfigurableVideoInputs, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  30, &hf_h282_getVideoInputs , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  31, &hf_h282_getConfigurableAudioInputs, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  32, &hf_h282_getAudioInputs , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {  33, &hf_h282_getNonStandardStatus, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardIdentifier },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_StatusAttributeIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_StatusAttributeIdentifier, StatusAttributeIdentifier_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentDeviceState_vals[] = {
  {   0, "deviceState" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentDeviceState_choice[] = {
  {   0, &hf_h282_deviceState    , ASN1_NO_EXTENSIONS     , dissect_h282_DeviceState },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentDeviceState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentDeviceState, CurrentDeviceState_choice,
                                 NULL);

  return offset;
}


static const value_string h282_T_currentDay_vals[] = {
  {   0, "day" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t T_currentDay_choice[] = {
  {   0, &hf_h282_day            , ASN1_NO_EXTENSIONS     , dissect_h282_Day },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_currentDay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_currentDay, T_currentDay_choice,
                                 NULL);

  return offset;
}


static const value_string h282_T_currentMonth_vals[] = {
  {   0, "month" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t T_currentMonth_choice[] = {
  {   0, &hf_h282_month          , ASN1_NO_EXTENSIONS     , dissect_h282_Month },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_currentMonth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_currentMonth, T_currentMonth_choice,
                                 NULL);

  return offset;
}


static const value_string h282_T_currentYear_vals[] = {
  {   0, "year" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t T_currentYear_choice[] = {
  {   0, &hf_h282_year           , ASN1_NO_EXTENSIONS     , dissect_h282_Year },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_currentYear(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_currentYear, T_currentYear_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CurrentDeviceDate_sequence[] = {
  { &hf_h282_currentDay     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_currentDay },
  { &hf_h282_currentMonth   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_currentMonth },
  { &hf_h282_currentYear    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_currentYear },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_CurrentDeviceDate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_CurrentDeviceDate, CurrentDeviceDate_sequence);

  return offset;
}


static const value_string h282_T_currentHour_vals[] = {
  {   0, "hour" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t T_currentHour_choice[] = {
  {   0, &hf_h282_hour           , ASN1_NO_EXTENSIONS     , dissect_h282_Hour },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_currentHour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_currentHour, T_currentHour_choice,
                                 NULL);

  return offset;
}


static const value_string h282_T_currentMinute_vals[] = {
  {   0, "minute" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t T_currentMinute_choice[] = {
  {   0, &hf_h282_minute         , ASN1_NO_EXTENSIONS     , dissect_h282_Minute },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_currentMinute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_currentMinute, T_currentMinute_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CurrentDeviceTime_sequence[] = {
  { &hf_h282_currentHour    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_currentHour },
  { &hf_h282_currentMinute  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_T_currentMinute },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_CurrentDeviceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_CurrentDeviceTime, CurrentDeviceTime_sequence);

  return offset;
}


static const value_string h282_CurrentDevicePreset_vals[] = {
  {   0, "preset" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentDevicePreset_choice[] = {
  {   0, &hf_h282_preset         , ASN1_NO_EXTENSIONS     , dissect_h282_PresetNumber },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentDevicePreset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentDevicePreset, CurrentDevicePreset_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentMode_vals[] = {
  {   0, "mode" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentMode_choice[] = {
  {   0, &hf_h282_mode_01        , ASN1_NO_EXTENSIONS     , dissect_h282_Mode },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentMode, CurrentMode_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentPointingMode_vals[] = {
  {   0, "automatic" },
  {   1, "manual" },
  {   2, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentPointingMode_choice[] = {
  {   0, &hf_h282_automatic      , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_manual         , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentPointingMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentPointingMode, CurrentPointingMode_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentCameraLensNumber_vals[] = {
  {   0, "lensNumber" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentCameraLensNumber_choice[] = {
  {   0, &hf_h282_lensNumber_01  , ASN1_NO_EXTENSIONS     , dissect_h282_CameraLensNumber },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentCameraLensNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentCameraLensNumber, CurrentCameraLensNumber_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentCameraFilterNumber_vals[] = {
  {   0, "lensNumber" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentCameraFilterNumber_choice[] = {
  {   0, &hf_h282_lensNumber_02  , ASN1_NO_EXTENSIONS     , dissect_h282_CameraFilterNumber },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentCameraFilterNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentCameraFilterNumber, CurrentCameraFilterNumber_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentExternalLight_vals[] = {
  {   0, "lightNumber" },
  {   1, "none" },
  {   2, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentExternalLight_choice[] = {
  {   0, &hf_h282_lightNumber    , ASN1_NO_EXTENSIONS     , dissect_h282_INTEGER_1_10 },
  {   1, &hf_h282_none           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   2, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentExternalLight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentExternalLight, CurrentExternalLight_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentCameraPanSpeed_vals[] = {
  {   0, "speed" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentCameraPanSpeed_choice[] = {
  {   0, &hf_h282_speed          , ASN1_NO_EXTENSIONS     , dissect_h282_CameraPanSpeed },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentCameraPanSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentCameraPanSpeed, CurrentCameraPanSpeed_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentCameraTiltSpeed_vals[] = {
  {   0, "speed" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentCameraTiltSpeed_choice[] = {
  {   0, &hf_h282_speed_01       , ASN1_NO_EXTENSIONS     , dissect_h282_CameraTiltSpeed },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentCameraTiltSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentCameraTiltSpeed, CurrentCameraTiltSpeed_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentBackLight_vals[] = {
  {   0, "backLight" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentBackLight_choice[] = {
  {   0, &hf_h282_backLight      , ASN1_NO_EXTENSIONS     , dissect_h282_BackLight },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentBackLight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentBackLight, CurrentBackLight_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentWhiteBalance_vals[] = {
  {   0, "whiteBalance" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentWhiteBalance_choice[] = {
  {   0, &hf_h282_whiteBalance   , ASN1_NO_EXTENSIONS     , dissect_h282_WhiteBalance },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentWhiteBalance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentWhiteBalance, CurrentWhiteBalance_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentZoomPosition_vals[] = {
  {   0, "zoomPosition" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentZoomPosition_choice[] = {
  {   0, &hf_h282_zoomPosition   , ASN1_NO_EXTENSIONS     , dissect_h282_ZoomPosition },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentZoomPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentZoomPosition, CurrentZoomPosition_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentFocusPosition_vals[] = {
  {   0, "focusPosition" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentFocusPosition_choice[] = {
  {   0, &hf_h282_focusPosition  , ASN1_NO_EXTENSIONS     , dissect_h282_FocusPosition },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentFocusPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentFocusPosition, CurrentFocusPosition_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentIrisPosition_vals[] = {
  {   0, "irisPosition" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentIrisPosition_choice[] = {
  {   0, &hf_h282_irisPosition   , ASN1_NO_EXTENSIONS     , dissect_h282_IrisPosition },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentIrisPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentIrisPosition, CurrentIrisPosition_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentPanPosition_vals[] = {
  {   0, "panPosition" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentPanPosition_choice[] = {
  {   0, &hf_h282_panPosition    , ASN1_NO_EXTENSIONS     , dissect_h282_PanPosition },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentPanPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentPanPosition, CurrentPanPosition_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentTiltPosition_vals[] = {
  {   0, "tiltPosition" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentTiltPosition_choice[] = {
  {   0, &hf_h282_tiltPosition   , ASN1_NO_EXTENSIONS     , dissect_h282_TiltPosition },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentTiltPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentTiltPosition, CurrentTiltPosition_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentSlide_vals[] = {
  {   0, "slide" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentSlide_choice[] = {
  {   0, &hf_h282_slide          , ASN1_NO_EXTENSIONS     , dissect_h282_SlideNumber },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentSlide(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentSlide, CurrentSlide_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentAutoSlideDisplayTime_vals[] = {
  {   0, "time" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentAutoSlideDisplayTime_choice[] = {
  {   0, &hf_h282_time           , ASN1_NO_EXTENSIONS     , dissect_h282_AutoSlideDisplayTime },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentAutoSlideDisplayTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentAutoSlideDisplayTime, CurrentAutoSlideDisplayTime_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentSelectedProgram_vals[] = {
  {   0, "program" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentSelectedProgram_choice[] = {
  {   0, &hf_h282_program        , ASN1_NO_EXTENSIONS     , dissect_h282_ProgramNumber },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentSelectedProgram(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentSelectedProgram, CurrentSelectedProgram_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentStreamPlayerState_vals[] = {
  {   0, "state" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentStreamPlayerState_choice[] = {
  {   0, &hf_h282_state          , ASN1_NO_EXTENSIONS     , dissect_h282_StreamPlayerState },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentStreamPlayerState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentStreamPlayerState, CurrentStreamPlayerState_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentPlaybackSpeed_vals[] = {
  {   0, "speed" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentPlaybackSpeed_choice[] = {
  {   0, &hf_h282_speed_02       , ASN1_NO_EXTENSIONS     , dissect_h282_PlaybackSpeed },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentPlaybackSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentPlaybackSpeed, CurrentPlaybackSpeed_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CurrentAudioOutputMute_vals[] = {
  {   0, "mute" },
  {   1, "unknown" },
  { 0, NULL }
};

static const per_choice_t CurrentAudioOutputMute_choice[] = {
  {   0, &hf_h282_mute           , ASN1_NO_EXTENSIONS     , dissect_h282_BOOLEAN },
  {   1, &hf_h282_unknown        , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CurrentAudioOutputMute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CurrentAudioOutputMute, CurrentAudioOutputMute_choice,
                                 NULL);

  return offset;
}


static const value_string h282_StatusAttribute_vals[] = {
  {   0, "currentdeviceState" },
  {   1, "currentDeviceDate" },
  {   2, "currentDeviceTime" },
  {   3, "currentDevicePreset" },
  {   4, "currentIrisMode" },
  {   5, "currentFocusMode" },
  {   6, "currentBackLightMode" },
  {   7, "currentPointingMode" },
  {   8, "currentCameraLens" },
  {   9, "currentCameraFilter" },
  {  10, "currentExternalLight" },
  {  11, "currentCameraPanSpeed" },
  {  12, "currentCameraTiltSpeed" },
  {  13, "currentBackLight" },
  {  14, "currentWhiteBalance" },
  {  15, "currentWhiteBalanceMode" },
  {  16, "currentZoomPosition" },
  {  17, "currentFocusPosition" },
  {  18, "currentIrisPosition" },
  {  19, "currentPanPosition" },
  {  20, "currentTiltPosition" },
  {  21, "currentSlide" },
  {  22, "currentAutoSlideDisplayTime" },
  {  23, "currentSelectedProgram" },
  {  24, "currentstreamPlayerState" },
  {  25, "currentProgramDuration" },
  {  26, "currentPlaybackSpeed" },
  {  27, "currentAudioOutputMute" },
  {  28, "configurableVideoInputs" },
  {  29, "videoInputs" },
  {  30, "configurableAudioInputs" },
  {  31, "audioInputs" },
  {  32, "nonStandardStatus" },
  { 0, NULL }
};

static const per_choice_t StatusAttribute_choice[] = {
  {   0, &hf_h282_currentdeviceState, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentDeviceState },
  {   1, &hf_h282_currentDeviceDate, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentDeviceDate },
  {   2, &hf_h282_currentDeviceTime, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentDeviceTime },
  {   3, &hf_h282_currentDevicePreset, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentDevicePreset },
  {   4, &hf_h282_currentIrisMode, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentMode },
  {   5, &hf_h282_currentFocusMode, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentMode },
  {   6, &hf_h282_currentBackLightMode, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentMode },
  {   7, &hf_h282_currentPointingMode, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentPointingMode },
  {   8, &hf_h282_currentCameraLens, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentCameraLensNumber },
  {   9, &hf_h282_currentCameraFilter, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentCameraFilterNumber },
  {  10, &hf_h282_currentExternalLight, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentExternalLight },
  {  11, &hf_h282_currentCameraPanSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentCameraPanSpeed },
  {  12, &hf_h282_currentCameraTiltSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentCameraTiltSpeed },
  {  13, &hf_h282_currentBackLight, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentBackLight },
  {  14, &hf_h282_currentWhiteBalance, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentWhiteBalance },
  {  15, &hf_h282_currentWhiteBalanceMode, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentMode },
  {  16, &hf_h282_currentZoomPosition, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentZoomPosition },
  {  17, &hf_h282_currentFocusPosition, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentFocusPosition },
  {  18, &hf_h282_currentIrisPosition, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentIrisPosition },
  {  19, &hf_h282_currentPanPosition, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentPanPosition },
  {  20, &hf_h282_currentTiltPosition, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentTiltPosition },
  {  21, &hf_h282_currentSlide   , ASN1_EXTENSION_ROOT    , dissect_h282_CurrentSlide },
  {  22, &hf_h282_currentAutoSlideDisplayTime, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentAutoSlideDisplayTime },
  {  23, &hf_h282_currentSelectedProgram, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentSelectedProgram },
  {  24, &hf_h282_currentstreamPlayerState, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentStreamPlayerState },
  {  25, &hf_h282_currentProgramDuration, ASN1_EXTENSION_ROOT    , dissect_h282_ProgramDuration },
  {  26, &hf_h282_currentPlaybackSpeed, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentPlaybackSpeed },
  {  27, &hf_h282_currentAudioOutputMute, ASN1_EXTENSION_ROOT    , dissect_h282_CurrentAudioOutputMute },
  {  28, &hf_h282_configurableVideoInputs, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceInputs },
  {  29, &hf_h282_videoInputs    , ASN1_EXTENSION_ROOT    , dissect_h282_DeviceInputs },
  {  30, &hf_h282_configurableAudioInputs, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceInputs },
  {  31, &hf_h282_audioInputs    , ASN1_EXTENSION_ROOT    , dissect_h282_DeviceInputs },
  {  32, &hf_h282_nonStandardStatus, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_StatusAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_StatusAttribute, StatusAttribute_choice,
                                 NULL);

  return offset;
}


static const value_string h282_DeviceEventIdentifier_vals[] = {
  {   0, "requestDeviceLockChanged" },
  {   1, "requestDeviceAvailabilityChanged" },
  {   2, "requestCameraPannedToLimit" },
  {   3, "requestCameraTiltedToLimit" },
  {   4, "requestCameraZoomedToLimit" },
  {   5, "requestCameraFocusedToLimit" },
  {   6, "requestAutoSlideShowFinished" },
  {   7, "requestStreamPlayerStateChange" },
  {   8, "requestStreamPlayerProgramChange" },
  {   9, "requestNonStandardEvent" },
  { 0, NULL }
};

static const per_choice_t DeviceEventIdentifier_choice[] = {
  {   0, &hf_h282_requestDeviceLockChanged, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_requestDeviceAvailabilityChanged, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_requestCameraPannedToLimit, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   3, &hf_h282_requestCameraTiltedToLimit, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   4, &hf_h282_requestCameraZoomedToLimit, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   5, &hf_h282_requestCameraFocusedToLimit, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   6, &hf_h282_requestAutoSlideShowFinished, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   7, &hf_h282_requestStreamPlayerStateChange, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   8, &hf_h282_requestStreamPlayerProgramChange, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   9, &hf_h282_requestNonStandardEvent, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardIdentifier },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_DeviceEventIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_DeviceEventIdentifier, DeviceEventIdentifier_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CameraPannedToLimit_vals[] = {
  {   0, "left" },
  {   1, "right" },
  { 0, NULL }
};

static const per_choice_t CameraPannedToLimit_choice[] = {
  {   0, &hf_h282_left           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_right          , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CameraPannedToLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CameraPannedToLimit, CameraPannedToLimit_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CameraTiltedToLimit_vals[] = {
  {   0, "up" },
  {   1, "down" },
  { 0, NULL }
};

static const per_choice_t CameraTiltedToLimit_choice[] = {
  {   0, &hf_h282_up             , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_down           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CameraTiltedToLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CameraTiltedToLimit, CameraTiltedToLimit_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CameraZoomedToLimit_vals[] = {
  {   0, "telescopic" },
  {   1, "wide" },
  { 0, NULL }
};

static const per_choice_t CameraZoomedToLimit_choice[] = {
  {   0, &hf_h282_telescopic     , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_wide           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CameraZoomedToLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CameraZoomedToLimit, CameraZoomedToLimit_choice,
                                 NULL);

  return offset;
}


static const value_string h282_CameraFocusedToLimit_vals[] = {
  {   0, "near" },
  {   1, "far" },
  { 0, NULL }
};

static const per_choice_t CameraFocusedToLimit_choice[] = {
  {   0, &hf_h282_near           , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  {   1, &hf_h282_far            , ASN1_NO_EXTENSIONS     , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_CameraFocusedToLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_CameraFocusedToLimit, CameraFocusedToLimit_choice,
                                 NULL);

  return offset;
}


static const value_string h282_DeviceEvent_vals[] = {
  {   0, "deviceLockChanged" },
  {   1, "deviceAvailabilityChanged" },
  {   2, "cameraPannedToLimit" },
  {   3, "cameraTiltedToLimit" },
  {   4, "cameraZoomedToLimit" },
  {   5, "cameraFocusedToLimit" },
  {   6, "autoSlideShowFinished" },
  {   7, "streamPlayerStateChange" },
  {   8, "streamPlayerProgramChange" },
  {   9, "nonStandardEvent" },
  { 0, NULL }
};

static const per_choice_t DeviceEvent_choice[] = {
  {   0, &hf_h282_deviceLockChanged, ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {   1, &hf_h282_deviceAvailabilityChanged, ASN1_EXTENSION_ROOT    , dissect_h282_BOOLEAN },
  {   2, &hf_h282_cameraPannedToLimit, ASN1_EXTENSION_ROOT    , dissect_h282_CameraPannedToLimit },
  {   3, &hf_h282_cameraTiltedToLimit, ASN1_EXTENSION_ROOT    , dissect_h282_CameraTiltedToLimit },
  {   4, &hf_h282_cameraZoomedToLimit, ASN1_EXTENSION_ROOT    , dissect_h282_CameraZoomedToLimit },
  {   5, &hf_h282_cameraFocusedToLimit, ASN1_EXTENSION_ROOT    , dissect_h282_CameraFocusedToLimit },
  {   6, &hf_h282_autoSlideShowFinished, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   7, &hf_h282_streamPlayerStateChange, ASN1_EXTENSION_ROOT    , dissect_h282_StreamPlayerState },
  {   8, &hf_h282_streamPlayerProgramChange, ASN1_EXTENSION_ROOT    , dissect_h282_ProgramNumber },
  {   9, &hf_h282_nonStandardEvent, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardParameter },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_DeviceEvent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_DeviceEvent, DeviceEvent_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SourceSelectRequest_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { &hf_h282_streamIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_StreamID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SourceSelectRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SourceSelectRequest, SourceSelectRequest_sequence);

  return offset;
}


static const value_string h282_T_result_vals[] = {
  {   0, "successful" },
  {   1, "requestDenied" },
  {   2, "deviceUnavailable" },
  {   3, "invalidStreamID" },
  {   4, "currentDeviceIsLocked" },
  {   5, "deviceIncompatible" },
  { 0, NULL }
};

static const per_choice_t T_result_choice[] = {
  {   0, &hf_h282_successful     , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_requestDenied  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_deviceUnavailable, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   3, &hf_h282_invalidStreamID, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   4, &hf_h282_currentDeviceIsLocked, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   5, &hf_h282_deviceIncompatible, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_result(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_result, T_result_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SourceSelectResponse_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_result         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_T_result },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SourceSelectResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SourceSelectResponse, SourceSelectResponse_sequence);

  return offset;
}


static const per_sequence_t SourceEventsRequest_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_streamIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_StreamID },
  { &hf_h282_sourceEventNotify, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SourceEventsRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SourceEventsRequest, SourceEventsRequest_sequence);

  return offset;
}


static const value_string h282_T_result_01_vals[] = {
  {   0, "successful" },
  {   1, "eventsNotSupported" },
  {   2, "invalidStreamID" },
  { 0, NULL }
};

static const per_choice_t T_result_01_choice[] = {
  {   0, &hf_h282_successful     , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_eventsNotSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_invalidStreamID, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_result_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_result_01, T_result_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SourceEventsResponse_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { &hf_h282_result_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_T_result_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SourceEventsResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SourceEventsResponse, SourceEventsResponse_sequence);

  return offset;
}


static const per_sequence_t SourceChangeEventIndication_sequence[] = {
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_SourceChangeEventIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_SourceChangeEventIndication, SourceChangeEventIndication_sequence);

  return offset;
}


static const per_sequence_t DeviceAttributeRequest_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceAttributeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceAttributeRequest, DeviceAttributeRequest_sequence);

  return offset;
}


static const per_sequence_t SET_OF_DeviceAttribute_set_of[1] = {
  { &hf_h282_deviceAttributeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceAttribute },
};

static int
dissect_h282_SET_OF_DeviceAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_h282_SET_OF_DeviceAttribute, SET_OF_DeviceAttribute_set_of);

  return offset;
}


static const value_string h282_T_result_02_vals[] = {
  {   0, "successful" },
  {   1, "requestDenied" },
  {   2, "unknownDevice" },
  { 0, NULL }
};

static const per_choice_t T_result_02_choice[] = {
  {   0, &hf_h282_successful     , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_requestDenied  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_unknownDevice  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_result_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_result_02, T_result_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DeviceAttributeResponse_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceAttributeList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h282_SET_OF_DeviceAttribute },
  { &hf_h282_result_02      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_T_result_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceAttributeResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceAttributeResponse, DeviceAttributeResponse_sequence);

  return offset;
}


static const per_sequence_t DeviceLockRequest_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { &hf_h282_lockFlag       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceLockRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceLockRequest, DeviceLockRequest_sequence);

  return offset;
}


static const value_string h282_T_result_03_vals[] = {
  {   0, "successful" },
  {   1, "requestDenied" },
  {   2, "unknownDevice" },
  {   3, "lockingNotSupported" },
  {   4, "deviceAlreadyLocked" },
  { 0, NULL }
};

static const per_choice_t T_result_03_choice[] = {
  {   0, &hf_h282_successful     , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_requestDenied  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_unknownDevice  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   3, &hf_h282_lockingNotSupported, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   4, &hf_h282_deviceAlreadyLocked, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_result_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_result_03, T_result_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DeviceLockResponse_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_result_03      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_T_result_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceLockResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceLockResponse, DeviceLockResponse_sequence);

  return offset;
}


static const per_sequence_t DeviceLockEnquireRequest_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceLockEnquireRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceLockEnquireRequest, DeviceLockEnquireRequest_sequence);

  return offset;
}


static const value_string h282_T_result_04_vals[] = {
  {   0, "lockRequired" },
  {   1, "lockNotRequired" },
  {   2, "unknownDevice" },
  { 0, NULL }
};

static const per_choice_t T_result_04_choice[] = {
  {   0, &hf_h282_lockRequired   , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_lockNotRequired, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_unknownDevice  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_result_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_result_04, T_result_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DeviceLockEnquireResponse_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_result_04      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_T_result_04 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceLockEnquireResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceLockEnquireResponse, DeviceLockEnquireResponse_sequence);

  return offset;
}


static const per_sequence_t DeviceLockTerminatedIndication_sequence[] = {
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceLockTerminatedIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceLockTerminatedIndication, DeviceLockTerminatedIndication_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_8_OF_ControlAttribute_set_of[1] = {
  { &hf_h282_controlAttributeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_ControlAttribute },
};

static int
dissect_h282_SET_SIZE_1_8_OF_ControlAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_SET_SIZE_1_8_OF_ControlAttribute, SET_SIZE_1_8_OF_ControlAttribute_set_of,
                                             1, 8, FALSE);

  return offset;
}


static const per_sequence_t DeviceControlRequest_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { &hf_h282_controlAttributeList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_SET_SIZE_1_8_OF_ControlAttribute },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceControlRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceControlRequest, DeviceControlRequest_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_16_OF_StatusAttributeIdentifier_set_of[1] = {
  { &hf_h282_statusAttributeIdentifierList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_StatusAttributeIdentifier },
};

static int
dissect_h282_SET_SIZE_1_16_OF_StatusAttributeIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_SET_SIZE_1_16_OF_StatusAttributeIdentifier, SET_SIZE_1_16_OF_StatusAttributeIdentifier_set_of,
                                             1, 16, FALSE);

  return offset;
}


static const per_sequence_t DeviceStatusEnquireRequest_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { &hf_h282_statusAttributeIdentifierList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_SET_SIZE_1_16_OF_StatusAttributeIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceStatusEnquireRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceStatusEnquireRequest, DeviceStatusEnquireRequest_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_16_OF_StatusAttribute_set_of[1] = {
  { &hf_h282_statusAttributeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_StatusAttribute },
};

static int
dissect_h282_SET_SIZE_1_16_OF_StatusAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_SET_SIZE_1_16_OF_StatusAttribute, SET_SIZE_1_16_OF_StatusAttribute_set_of,
                                             1, 16, FALSE);

  return offset;
}


static const value_string h282_T_result_05_vals[] = {
  {   0, "successful" },
  {   1, "requestDenied" },
  {   2, "unknownDevice" },
  {   3, "deviceUnavailable" },
  {   4, "deviceAttributeError" },
  { 0, NULL }
};

static const per_choice_t T_result_05_choice[] = {
  {   0, &hf_h282_successful     , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_requestDenied  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_unknownDevice  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   3, &hf_h282_deviceUnavailable, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   4, &hf_h282_deviceAttributeError, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_result_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_result_05, T_result_05_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DeviceStatusEnquireResponse_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_statusAttributeList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h282_SET_SIZE_1_16_OF_StatusAttribute },
  { &hf_h282_result_05      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_T_result_05 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceStatusEnquireResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceStatusEnquireResponse, DeviceStatusEnquireResponse_sequence);

  return offset;
}


static const per_sequence_t SET_OF_DeviceEventIdentifier_set_of[1] = {
  { &hf_h282_deviceEventIdentifierList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceEventIdentifier },
};

static int
dissect_h282_SET_OF_DeviceEventIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_set_of(tvb, offset, actx, tree, hf_index,
                                 ett_h282_SET_OF_DeviceEventIdentifier, SET_OF_DeviceEventIdentifier_set_of);

  return offset;
}


static const per_sequence_t ConfigureDeviceEventsRequest_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { &hf_h282_deviceEventIdentifierList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_SET_OF_DeviceEventIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_ConfigureDeviceEventsRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_ConfigureDeviceEventsRequest, ConfigureDeviceEventsRequest_sequence);

  return offset;
}


static const value_string h282_T_result_06_vals[] = {
  {   0, "successful" },
  {   1, "requestDenied" },
  {   2, "unknownDevice" },
  {   3, "deviceUnavailable" },
  {   4, "deviceAttributeError" },
  { 0, NULL }
};

static const per_choice_t T_result_06_choice[] = {
  {   0, &hf_h282_successful     , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   1, &hf_h282_requestDenied  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   2, &hf_h282_unknownDevice  , ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   3, &hf_h282_deviceUnavailable, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  {   4, &hf_h282_deviceAttributeError, ASN1_EXTENSION_ROOT    , dissect_h282_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_T_result_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_T_result_06, T_result_06_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ConfigureDeviceEventsResponse_sequence[] = {
  { &hf_h282_requestHandle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_Handle },
  { &hf_h282_result_06      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_T_result_06 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_ConfigureDeviceEventsResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_ConfigureDeviceEventsResponse, ConfigureDeviceEventsResponse_sequence);

  return offset;
}


static const per_sequence_t SET_SIZE_1_8_OF_DeviceEvent_set_of[1] = {
  { &hf_h282_deviceEventList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h282_DeviceEvent },
};

static int
dissect_h282_SET_SIZE_1_8_OF_DeviceEvent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h282_SET_SIZE_1_8_OF_DeviceEvent, SET_SIZE_1_8_OF_DeviceEvent_set_of,
                                             1, 8, FALSE);

  return offset;
}


static const per_sequence_t DeviceEventNotifyIndication_sequence[] = {
  { &hf_h282_deviceClass    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceClass },
  { &hf_h282_deviceID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_DeviceID },
  { &hf_h282_deviceEventList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_SET_SIZE_1_8_OF_DeviceEvent },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_DeviceEventNotifyIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_DeviceEventNotifyIndication, DeviceEventNotifyIndication_sequence);

  return offset;
}


static const per_sequence_t NonStandardPDU_sequence[] = {
  { &hf_h282_nonStandardData, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h282_NonStandardParameter },
  { NULL, 0, 0, NULL }
};

static int
dissect_h282_NonStandardPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h282_NonStandardPDU, NonStandardPDU_sequence);

  return offset;
}


static const value_string h282_RequestPDU_vals[] = {
  {   0, "sourceSelectRequest" },
  {   1, "sourceEventsRequest" },
  {   2, "deviceAttributeRequest" },
  {   3, "deviceLockRequest" },
  {   4, "deviceLockEnquireRequest" },
  {   5, "deviceControlRequest" },
  {   6, "deviceStatusEnquireRequest" },
  {   7, "configureDeviceEventsRequest" },
  {   8, "nonStandardRequest" },
  { 0, NULL }
};

static const per_choice_t RequestPDU_choice[] = {
  {   0, &hf_h282_sourceSelectRequest, ASN1_EXTENSION_ROOT    , dissect_h282_SourceSelectRequest },
  {   1, &hf_h282_sourceEventsRequest, ASN1_EXTENSION_ROOT    , dissect_h282_SourceEventsRequest },
  {   2, &hf_h282_deviceAttributeRequest, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceAttributeRequest },
  {   3, &hf_h282_deviceLockRequest, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceLockRequest },
  {   4, &hf_h282_deviceLockEnquireRequest, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceLockEnquireRequest },
  {   5, &hf_h282_deviceControlRequest, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceControlRequest },
  {   6, &hf_h282_deviceStatusEnquireRequest, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceStatusEnquireRequest },
  {   7, &hf_h282_configureDeviceEventsRequest, ASN1_EXTENSION_ROOT    , dissect_h282_ConfigureDeviceEventsRequest },
  {   8, &hf_h282_nonStandardRequest, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardPDU },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_RequestPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 24 "../../asn1/h282/h282.cnf"
  gint32 msg_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_RequestPDU, RequestPDU_choice,
                                 &msg_type);

#line 27 "../../asn1/h282/h282.cnf"
  p = match_strval(msg_type, VALS(h282_RequestPDU_vals));
  if (p)
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "RequestPDU/%s", p);

  return offset;
}


static const value_string h282_ResponsePDU_vals[] = {
  {   0, "sourceSelectResponse" },
  {   1, "sourceEventsResponse" },
  {   2, "deviceAttributeResponse" },
  {   3, "deviceLockResponse" },
  {   4, "deviceLockEnquireResponse" },
  {   5, "deviceStatusEnquireResponse" },
  {   6, "configureDeviceEventsResponse" },
  {   7, "nonStandardResponse" },
  { 0, NULL }
};

static const per_choice_t ResponsePDU_choice[] = {
  {   0, &hf_h282_sourceSelectResponse, ASN1_EXTENSION_ROOT    , dissect_h282_SourceSelectResponse },
  {   1, &hf_h282_sourceEventsResponse, ASN1_EXTENSION_ROOT    , dissect_h282_SourceEventsResponse },
  {   2, &hf_h282_deviceAttributeResponse, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceAttributeResponse },
  {   3, &hf_h282_deviceLockResponse, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceLockResponse },
  {   4, &hf_h282_deviceLockEnquireResponse, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceLockEnquireResponse },
  {   5, &hf_h282_deviceStatusEnquireResponse, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceStatusEnquireResponse },
  {   6, &hf_h282_configureDeviceEventsResponse, ASN1_EXTENSION_ROOT    , dissect_h282_ConfigureDeviceEventsResponse },
  {   7, &hf_h282_nonStandardResponse, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardPDU },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_ResponsePDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 35 "../../asn1/h282/h282.cnf"
  gint32 msg_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_ResponsePDU, ResponsePDU_choice,
                                 &msg_type);

#line 38 "../../asn1/h282/h282.cnf"
  p = match_strval(msg_type, VALS(h282_ResponsePDU_vals));
  if (p)
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "ResponsePDU/%s", p);

  return offset;
}


static const value_string h282_IndicationPDU_vals[] = {
  {   0, "sourceChangeEventIndication" },
  {   1, "deviceLockTerminatedIndication" },
  {   2, "deviceEventNotifyIndication" },
  {   3, "nonStandardIndication" },
  { 0, NULL }
};

static const per_choice_t IndicationPDU_choice[] = {
  {   0, &hf_h282_sourceChangeEventIndication, ASN1_EXTENSION_ROOT    , dissect_h282_SourceChangeEventIndication },
  {   1, &hf_h282_deviceLockTerminatedIndication, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceLockTerminatedIndication },
  {   2, &hf_h282_deviceEventNotifyIndication, ASN1_EXTENSION_ROOT    , dissect_h282_DeviceEventNotifyIndication },
  {   3, &hf_h282_nonStandardIndication, ASN1_EXTENSION_ROOT    , dissect_h282_NonStandardPDU },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_IndicationPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 46 "../../asn1/h282/h282.cnf"
  gint32 msg_type = -1;
  const gchar *p = NULL;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_IndicationPDU, IndicationPDU_choice,
                                 &msg_type);

#line 49 "../../asn1/h282/h282.cnf"
  p = match_strval(msg_type, VALS(h282_IndicationPDU_vals));
  if (p)
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "IndicationPDU/%s", p);

  return offset;
}


static const value_string h282_RDCPDU_vals[] = {
  {   0, "request" },
  {   1, "response" },
  {   2, "indication" },
  { 0, NULL }
};

static const per_choice_t RDCPDU_choice[] = {
  {   0, &hf_h282_request        , ASN1_NO_EXTENSIONS     , dissect_h282_RequestPDU },
  {   1, &hf_h282_response       , ASN1_NO_EXTENSIONS     , dissect_h282_ResponsePDU },
  {   2, &hf_h282_indication     , ASN1_NO_EXTENSIONS     , dissect_h282_IndicationPDU },
  { 0, NULL, 0, NULL }
};

static int
dissect_h282_RDCPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h282_RDCPDU, RDCPDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_NonCollapsingCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h282_NonCollapsingCapabilities(tvb, offset, &asn1_ctx, tree, hf_h282_NonCollapsingCapabilities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RDCPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_h282_RDCPDU(tvb, offset, &asn1_ctx, tree, hf_h282_RDCPDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-h282-fn.c ---*/
#line 54 "../../asn1/h282/packet-h282-template.c"

static int
dissect_h282(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item  *ti = NULL;
  proto_tree  *h282_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  ti = proto_tree_add_item(tree, proto_h282, tvb, 0, -1, ENC_NA);
  h282_tree = proto_item_add_subtree(ti, ett_h282);

  return dissect_RDCPDU_PDU(tvb, pinfo, h282_tree);
}

/*--- proto_register_h282 ----------------------------------------------*/
void proto_register_h282(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-h282-hfarr.c ---*/
#line 1 "../../asn1/h282/packet-h282-hfarr.c"
    { &hf_h282_NonCollapsingCapabilities_PDU,
      { "NonCollapsingCapabilities", "h282.NonCollapsingCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_RDCPDU_PDU,
      { "RDCPDU", "h282.RDCPDU",
        FT_UINT32, BASE_DEC, VALS(h282_RDCPDU_vals), 0,
        NULL, HFILL }},
    { &hf_h282_object,
      { "object", "h282.object",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h282_h221NonStandard,
      { "h221NonStandard", "h282.h221NonStandard",
        FT_BYTES, BASE_NONE, NULL, 0,
        "H221NonStandardIdentifier", HFILL }},
    { &hf_h282_key,
      { "key", "h282.key",
        FT_UINT32, BASE_DEC, VALS(h282_Key_vals), 0,
        NULL, HFILL }},
    { &hf_h282_data,
      { "data", "h282.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h282_h221nonStandard,
      { "h221nonStandard", "h282.h221nonStandard",
        FT_BYTES, BASE_NONE, NULL, 0,
        "H221NonStandardIdentifier", HFILL }},
    { &hf_h282_camera,
      { "camera", "h282.camera",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_microphone,
      { "microphone", "h282.microphone",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_streamPlayerRecorder,
      { "streamPlayerRecorder", "h282.streamPlayerRecorder",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_slideProjector,
      { "slideProjector", "h282.slideProjector",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_lightSource,
      { "lightSource", "h282.lightSource",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_sourceCombiner,
      { "sourceCombiner", "h282.sourceCombiner",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_nonStandardDevice,
      { "nonStandardDevice", "h282.nonStandardDevice",
        FT_UINT32, BASE_DEC, VALS(h282_NonStandardIdentifier_vals), 0,
        "NonStandardIdentifier", HFILL }},
    { &hf_h282_deviceID,
      { "deviceID", "h282.deviceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_audioSourceFlag,
      { "audioSourceFlag", "h282.audioSourceFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_audioSinkFlag,
      { "audioSinkFlag", "h282.audioSinkFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_videoSourceFlag,
      { "videoSourceFlag", "h282.videoSourceFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_videoSinkFlag,
      { "videoSinkFlag", "h282.videoSinkFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_remoteControlFlag,
      { "remoteControlFlag", "h282.remoteControlFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_instanceNumber,
      { "instanceNumber", "h282.instanceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h282_deviceName,
      { "deviceName", "h282.deviceName",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_h282_streamID,
      { "streamID", "h282.streamID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_videoStreamFlag,
      { "videoStreamFlag", "h282.videoStreamFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_sourceChangeFlag,
      { "sourceChangeFlag", "h282.sourceChangeFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_streamName,
      { "streamName", "h282.streamName",
        FT_STRING, BASE_NONE, NULL, 0,
        "TextString", HFILL }},
    { &hf_h282_standard,
      { "standard", "h282.standard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h282_nonStandard,
      { "nonStandard", "h282.nonStandard",
        FT_UINT32, BASE_DEC, VALS(h282_Key_vals), 0,
        "Key", HFILL }},
    { &hf_h282_NonCollapsingCapabilities_item,
      { "NonCollapsingCapabilities item", "h282.NonCollapsingCapabilities_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_capabilityID,
      { "capabilityID", "h282.capabilityID",
        FT_UINT32, BASE_DEC, VALS(h282_CapabilityID_vals), 0,
        NULL, HFILL }},
    { &hf_h282_applicationData,
      { "applicationData", "h282.applicationData",
        FT_UINT32, BASE_DEC, VALS(h282_T_applicationData_vals), 0,
        NULL, HFILL }},
    { &hf_h282_deviceList,
      { "deviceList", "h282.deviceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_0_127_OF_DeviceProfile", HFILL }},
    { &hf_h282_deviceList_item,
      { "DeviceProfile", "h282.DeviceProfile",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_streamList,
      { "streamList", "h282.streamList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_0_127_OF_StreamProfile", HFILL }},
    { &hf_h282_streamList_item,
      { "StreamProfile", "h282.StreamProfile",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_playing,
      { "playing", "h282.playing",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_recording,
      { "recording", "h282.recording",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_pausedOnRecord,
      { "pausedOnRecord", "h282.pausedOnRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_pausedOnPlay,
      { "pausedOnPlay", "h282.pausedOnPlay",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_rewinding,
      { "rewinding", "h282.rewinding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_fastForwarding,
      { "fastForwarding", "h282.fastForwarding",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_searchingForwards,
      { "searchingForwards", "h282.searchingForwards",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_searchingBackwards,
      { "searchingBackwards", "h282.searchingBackwards",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_stopped,
      { "stopped", "h282.stopped",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_programUnavailable,
      { "programUnavailable", "h282.programUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_maxNumber,
      { "maxNumber", "h282.maxNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PresetNumber", HFILL }},
    { &hf_h282_presetCapability,
      { "presetCapability", "h282.presetCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_presetCapability_item,
      { "presetCapability item", "h282.presetCapability_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_presetNumber,
      { "presetNumber", "h282.presetNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_storeModeSupported,
      { "storeModeSupported", "h282.storeModeSupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_presetTextLabel,
      { "presetTextLabel", "h282.presetTextLabel",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DeviceText", HFILL }},
    { &hf_h282_maxNumberOfFilters,
      { "maxNumberOfFilters", "h282.maxNumberOfFilters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_255", HFILL }},
    { &hf_h282_filterTextLabel,
      { "filterTextLabel", "h282.filterTextLabel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_filterTextLabel_item,
      { "filterTextLabel item", "h282.filterTextLabel_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_filterNumber,
      { "filterNumber", "h282.filterNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h282_filterTextLabel_01,
      { "filterTextLabel", "h282.filterTextLabel",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DeviceText", HFILL }},
    { &hf_h282_maxNumberOfLens,
      { "maxNumberOfLens", "h282.maxNumberOfLens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_255", HFILL }},
    { &hf_h282_accessoryTextLabel,
      { "accessoryTextLabel", "h282.accessoryTextLabel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_accessoryTextLabel_item,
      { "accessoryTextLabel item", "h282.accessoryTextLabel_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_lensNumber,
      { "lensNumber", "h282.lensNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_255", HFILL }},
    { &hf_h282_lensTextLabel,
      { "lensTextLabel", "h282.lensTextLabel",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DeviceText", HFILL }},
    { &hf_h282_maxNumber_01,
      { "maxNumber", "h282.maxNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_10", HFILL }},
    { &hf_h282_lightTextLabel,
      { "lightTextLabel", "h282.lightTextLabel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_lightTextLabel_item,
      { "lightTextLabel item", "h282.lightTextLabel_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_lightNumber,
      { "lightNumber", "h282.lightNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_10", HFILL }},
    { &hf_h282_lightLabel,
      { "lightLabel", "h282.lightLabel",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DeviceText", HFILL }},
    { &hf_h282_maxSpeed,
      { "maxSpeed", "h282.maxSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraPanSpeed", HFILL }},
    { &hf_h282_minSpeed,
      { "minSpeed", "h282.minSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraPanSpeed", HFILL }},
    { &hf_h282_speedStepSize,
      { "speedStepSize", "h282.speedStepSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraPanSpeed", HFILL }},
    { &hf_h282_maxSpeed_01,
      { "maxSpeed", "h282.maxSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraTiltSpeed", HFILL }},
    { &hf_h282_minSpeed_01,
      { "minSpeed", "h282.minSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraTiltSpeed", HFILL }},
    { &hf_h282_speedStepSize_01,
      { "speedStepSize", "h282.speedStepSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraTiltSpeed", HFILL }},
    { &hf_h282_maxLeft,
      { "maxLeft", "h282.maxLeft",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M18000_0", HFILL }},
    { &hf_h282_maxRight,
      { "maxRight", "h282.maxRight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_18000", HFILL }},
    { &hf_h282_minStepSize,
      { "minStepSize", "h282.minStepSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_18000", HFILL }},
    { &hf_h282_maxDown,
      { "maxDown", "h282.maxDown",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M18000_0", HFILL }},
    { &hf_h282_maxUp,
      { "maxUp", "h282.maxUp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_18000", HFILL }},
    { &hf_h282_multiplierFactors,
      { "multiplierFactors", "h282.multiplierFactors",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_multiplierFactors_item,
      { "multiplierFactors item", "h282.multiplierFactors_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_1000", HFILL }},
    { &hf_h282_divisorFactors,
      { "divisorFactors", "h282.divisorFactors",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_divisorFactors_item,
      { "divisorFactors item", "h282.divisorFactors_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_1000", HFILL }},
    { &hf_h282_numberOfDeviceInputs,
      { "numberOfDeviceInputs", "h282.numberOfDeviceInputs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_64", HFILL }},
    { &hf_h282_numberOfDeviceRows,
      { "numberOfDeviceRows", "h282.numberOfDeviceRows",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_64", HFILL }},
    { &hf_h282_availableDevices,
      { "availableDevices", "h282.availableDevices",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_availableDevices_item,
      { "availableDevices item", "h282.availableDevices_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceClass,
      { "deviceClass", "h282.deviceClass",
        FT_UINT32, BASE_DEC, VALS(h282_DeviceClass_vals), 0,
        NULL, HFILL }},
    { &hf_h282_deviceIdentifier,
      { "deviceIdentifier", "h282.deviceIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DeviceID", HFILL }},
    { &hf_h282_availableDevices_01,
      { "availableDevices", "h282.availableDevices",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_availableDevices_01", HFILL }},
    { &hf_h282_availableDevices_item_01,
      { "availableDevices item", "h282.availableDevices_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_availableDevices_item_01", HFILL }},
    { &hf_h282_deviceStateSupported,
      { "deviceStateSupported", "h282.deviceStateSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceDateSupported,
      { "deviceDateSupported", "h282.deviceDateSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceTimeSupported,
      { "deviceTimeSupported", "h282.deviceTimeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_devicePresetSupported,
      { "devicePresetSupported", "h282.devicePresetSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "DevicePresetCapability", HFILL }},
    { &hf_h282_irisModeSupported,
      { "irisModeSupported", "h282.irisModeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_focusModeSupported,
      { "focusModeSupported", "h282.focusModeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_pointingModeSupported,
      { "pointingModeSupported", "h282.pointingModeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_cameraLensSupported,
      { "cameraLensSupported", "h282.cameraLensSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "CameraLensCapability", HFILL }},
    { &hf_h282_cameraFilterSupported,
      { "cameraFilterSupported", "h282.cameraFilterSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "CameraFilterCapability", HFILL }},
    { &hf_h282_homePositionSupported,
      { "homePositionSupported", "h282.homePositionSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_externalCameraLightSupported,
      { "externalCameraLightSupported", "h282.externalCameraLightSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExternalCameraLightCapability", HFILL }},
    { &hf_h282_clearCameraLensSupported,
      { "clearCameraLensSupported", "h282.clearCameraLensSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_cameraPanSpeedSupported,
      { "cameraPanSpeedSupported", "h282.cameraPanSpeedSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "CameraPanSpeedCapability", HFILL }},
    { &hf_h282_cameraTiltSpeedSupported,
      { "cameraTiltSpeedSupported", "h282.cameraTiltSpeedSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "CameraTiltSpeedCapability", HFILL }},
    { &hf_h282_backLightModeSupported,
      { "backLightModeSupported", "h282.backLightModeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_backLightSettingSupported,
      { "backLightSettingSupported", "h282.backLightSettingSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxBacklight", HFILL }},
    { &hf_h282_whiteBalanceSettingSupported,
      { "whiteBalanceSettingSupported", "h282.whiteBalanceSettingSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxWhiteBalance", HFILL }},
    { &hf_h282_whiteBalanceModeSupported,
      { "whiteBalanceModeSupported", "h282.whiteBalanceModeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_calibrateWhiteBalanceSupported,
      { "calibrateWhiteBalanceSupported", "h282.calibrateWhiteBalanceSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_focusImageSupported,
      { "focusImageSupported", "h282.focusImageSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_captureImageSupported,
      { "captureImageSupported", "h282.captureImageSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_panContinuousSupported,
      { "panContinuousSupported", "h282.panContinuousSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_tiltContinuousSupported,
      { "tiltContinuousSupported", "h282.tiltContinuousSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_zoomContinuousSupported,
      { "zoomContinuousSupported", "h282.zoomContinuousSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_focusContinuousSupported,
      { "focusContinuousSupported", "h282.focusContinuousSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_irisContinuousSupported,
      { "irisContinuousSupported", "h282.irisContinuousSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_zoomPositionSupported,
      { "zoomPositionSupported", "h282.zoomPositionSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinZoomPositionSetSize", HFILL }},
    { &hf_h282_focusPositionSupported,
      { "focusPositionSupported", "h282.focusPositionSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinFocusPositionStepSize", HFILL }},
    { &hf_h282_irisPositionSupported,
      { "irisPositionSupported", "h282.irisPositionSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinIrisPositionStepSize", HFILL }},
    { &hf_h282_panPositionSupported,
      { "panPositionSupported", "h282.panPositionSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "PanPositionCapability", HFILL }},
    { &hf_h282_tiltPositionSupported,
      { "tiltPositionSupported", "h282.tiltPositionSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "TiltPositionCapability", HFILL }},
    { &hf_h282_zoomMagnificationSupported,
      { "zoomMagnificationSupported", "h282.zoomMagnificationSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinZoomMagnificationStepSize", HFILL }},
    { &hf_h282_panViewSupported,
      { "panViewSupported", "h282.panViewSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_tiltViewSupported,
      { "tiltViewSupported", "h282.tiltViewSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_selectSlideSupported,
      { "selectSlideSupported", "h282.selectSlideSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxNumberOfSlides", HFILL }},
    { &hf_h282_selectNextSlideSupported,
      { "selectNextSlideSupported", "h282.selectNextSlideSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_slideShowModeSupported,
      { "slideShowModeSupported", "h282.slideShowModeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_playSlideShowSupported,
      { "playSlideShowSupported", "h282.playSlideShowSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setSlideDisplayTimeSupported,
      { "setSlideDisplayTimeSupported", "h282.setSlideDisplayTimeSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxSlideDisplayTime", HFILL }},
    { &hf_h282_continuousRewindSupported,
      { "continuousRewindSupported", "h282.continuousRewindSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_continuousFastForwardSupported,
      { "continuousFastForwardSupported", "h282.continuousFastForwardSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_searchBackwardsSupported,
      { "searchBackwardsSupported", "h282.searchBackwardsSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_searchForwardsSupported,
      { "searchForwardsSupported", "h282.searchForwardsSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_pauseSupported,
      { "pauseSupported", "h282.pauseSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_selectProgramSupported,
      { "selectProgramSupported", "h282.selectProgramSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxNumberOfPrograms", HFILL }},
    { &hf_h282_nextProgramSupported,
      { "nextProgramSupported", "h282.nextProgramSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_gotoNormalPlayTimePointSupported,
      { "gotoNormalPlayTimePointSupported", "h282.gotoNormalPlayTimePointSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_readStreamPlayerStateSupported,
      { "readStreamPlayerStateSupported", "h282.readStreamPlayerStateSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_readProgramDurationSupported,
      { "readProgramDurationSupported", "h282.readProgramDurationSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_continuousPlayBackModeSupported,
      { "continuousPlayBackModeSupported", "h282.continuousPlayBackModeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_playbackSpeedSupported,
      { "playbackSpeedSupported", "h282.playbackSpeedSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "PlayBackSpeedCapability", HFILL }},
    { &hf_h282_playSupported,
      { "playSupported", "h282.playSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setAudioOutputStateSupported,
      { "setAudioOutputStateSupported", "h282.setAudioOutputStateSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_playToNormalPlayTimePointSupported,
      { "playToNormalPlayTimePointSupported", "h282.playToNormalPlayTimePointSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_recordSupported,
      { "recordSupported", "h282.recordSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_recordForDurationSupported,
      { "recordForDurationSupported", "h282.recordForDurationSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_configurableVideoInputsSupported,
      { "configurableVideoInputsSupported", "h282.configurableVideoInputsSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "VideoInputsCapability", HFILL }},
    { &hf_h282_videoInputsSupported,
      { "videoInputsSupported", "h282.videoInputsSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "VideoInputsCapability", HFILL }},
    { &hf_h282_configurableAudioInputsSupported,
      { "configurableAudioInputsSupported", "h282.configurableAudioInputsSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "AudioInputsCapability", HFILL }},
    { &hf_h282_audioInputsSupported,
      { "audioInputsSupported", "h282.audioInputsSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "AudioInputsCapability", HFILL }},
    { &hf_h282_deviceLockStateChangedSupported,
      { "deviceLockStateChangedSupported", "h282.deviceLockStateChangedSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceAvailabilityChangedSupported,
      { "deviceAvailabilityChangedSupported", "h282.deviceAvailabilityChangedSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_cameraPannedToLimitSupported,
      { "cameraPannedToLimitSupported", "h282.cameraPannedToLimitSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_cameraTiltedToLimitSupported,
      { "cameraTiltedToLimitSupported", "h282.cameraTiltedToLimitSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_cameraZoomedToLimitSupported,
      { "cameraZoomedToLimitSupported", "h282.cameraZoomedToLimitSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_cameraFocusedToLimitSupported,
      { "cameraFocusedToLimitSupported", "h282.cameraFocusedToLimitSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_autoSlideShowFinishedSupported,
      { "autoSlideShowFinishedSupported", "h282.autoSlideShowFinishedSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_streamPlayerStateChangeSupported,
      { "streamPlayerStateChangeSupported", "h282.streamPlayerStateChangeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_streamPlayerProgramChangeSupported,
      { "streamPlayerProgramChangeSupported", "h282.streamPlayerProgramChangeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_nonStandardAttributeSupported,
      { "nonStandardAttributeSupported", "h282.nonStandardAttributeSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h282_active,
      { "active", "h282.active",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_inactive,
      { "inactive", "h282.inactive",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_day,
      { "day", "h282.day",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_month,
      { "month", "h282.month",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_year,
      { "year", "h282.year",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_hour,
      { "hour", "h282.hour",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_minute,
      { "minute", "h282.minute",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_mode,
      { "mode", "h282.mode",
        FT_UINT32, BASE_DEC, VALS(h282_T_mode_vals), 0,
        NULL, HFILL }},
    { &hf_h282_store,
      { "store", "h282.store",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_activate,
      { "activate", "h282.activate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_manual,
      { "manual", "h282.manual",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_auto,
      { "auto", "h282.auto",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_toggle,
      { "toggle", "h282.toggle",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_none,
      { "none", "h282.none",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_panDirection,
      { "panDirection", "h282.panDirection",
        FT_UINT32, BASE_DEC, VALS(h282_T_panDirection_vals), 0,
        NULL, HFILL }},
    { &hf_h282_left,
      { "left", "h282.left",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_right,
      { "right", "h282.right",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_stop,
      { "stop", "h282.stop",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_continue,
      { "continue", "h282.continue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_timeOut,
      { "timeOut", "h282.timeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_50_1000", HFILL }},
    { &hf_h282_tiltDirection,
      { "tiltDirection", "h282.tiltDirection",
        FT_UINT32, BASE_DEC, VALS(h282_T_tiltDirection_vals), 0,
        NULL, HFILL }},
    { &hf_h282_up,
      { "up", "h282.up",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_down,
      { "down", "h282.down",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_zoomDirection,
      { "zoomDirection", "h282.zoomDirection",
        FT_UINT32, BASE_DEC, VALS(h282_T_zoomDirection_vals), 0,
        NULL, HFILL }},
    { &hf_h282_telescopic,
      { "telescopic", "h282.telescopic",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_wide,
      { "wide", "h282.wide",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_focusDirection,
      { "focusDirection", "h282.focusDirection",
        FT_UINT32, BASE_DEC, VALS(h282_T_focusDirection_vals), 0,
        NULL, HFILL }},
    { &hf_h282_near,
      { "near", "h282.near",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_far,
      { "far", "h282.far",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_relative,
      { "relative", "h282.relative",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_absolute,
      { "absolute", "h282.absolute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_zoomPosition,
      { "zoomPosition", "h282.zoomPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_positioningMode,
      { "positioningMode", "h282.positioningMode",
        FT_UINT32, BASE_DEC, VALS(h282_PositioningMode_vals), 0,
        NULL, HFILL }},
    { &hf_h282_focusPosition,
      { "focusPosition", "h282.focusPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_irisPosition,
      { "irisPosition", "h282.irisPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_panPosition,
      { "panPosition", "h282.panPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_tiltPosition,
      { "tiltPosition", "h282.tiltPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_next,
      { "next", "h282.next",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_previous,
      { "previous", "h282.previous",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_start,
      { "start", "h282.start",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_pause,
      { "pause", "h282.pause",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_hours,
      { "hours", "h282.hours",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_24", HFILL }},
    { &hf_h282_minutes,
      { "minutes", "h282.minutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_59", HFILL }},
    { &hf_h282_seconds,
      { "seconds", "h282.seconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_59", HFILL }},
    { &hf_h282_microseconds,
      { "microseconds", "h282.microseconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_99999", HFILL }},
    { &hf_h282_scaleFactor,
      { "scaleFactor", "h282.scaleFactor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_1000", HFILL }},
    { &hf_h282_multiplyFactor,
      { "multiplyFactor", "h282.multiplyFactor",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_inputDevices,
      { "inputDevices", "h282.inputDevices",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_inputDevices_item,
      { "inputDevices item", "h282.inputDevices_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setDeviceState,
      { "setDeviceState", "h282.setDeviceState",
        FT_UINT32, BASE_DEC, VALS(h282_DeviceState_vals), 0,
        "DeviceState", HFILL }},
    { &hf_h282_setDeviceDate,
      { "setDeviceDate", "h282.setDeviceDate",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeviceDate", HFILL }},
    { &hf_h282_setDeviceTime,
      { "setDeviceTime", "h282.setDeviceTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeviceTime", HFILL }},
    { &hf_h282_setDevicePreset,
      { "setDevicePreset", "h282.setDevicePreset",
        FT_NONE, BASE_NONE, NULL, 0,
        "DevicePreset", HFILL }},
    { &hf_h282_setIrisMode,
      { "setIrisMode", "h282.setIrisMode",
        FT_UINT32, BASE_DEC, VALS(h282_Mode_vals), 0,
        "Mode", HFILL }},
    { &hf_h282_setFocusMode,
      { "setFocusMode", "h282.setFocusMode",
        FT_UINT32, BASE_DEC, VALS(h282_Mode_vals), 0,
        "Mode", HFILL }},
    { &hf_h282_setBackLightMode,
      { "setBackLightMode", "h282.setBackLightMode",
        FT_UINT32, BASE_DEC, VALS(h282_Mode_vals), 0,
        "Mode", HFILL }},
    { &hf_h282_setPointingMode,
      { "setPointingMode", "h282.setPointingMode",
        FT_UINT32, BASE_DEC, VALS(h282_PointingToggle_vals), 0,
        "PointingToggle", HFILL }},
    { &hf_h282_selectCameraLens,
      { "selectCameraLens", "h282.selectCameraLens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraLensNumber", HFILL }},
    { &hf_h282_selectCameraFilter,
      { "selectCameraFilter", "h282.selectCameraFilter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraFilterNumber", HFILL }},
    { &hf_h282_gotoHomePosition,
      { "gotoHomePosition", "h282.gotoHomePosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_selectExternalLight,
      { "selectExternalLight", "h282.selectExternalLight",
        FT_UINT32, BASE_DEC, VALS(h282_SelectExternalLight_vals), 0,
        NULL, HFILL }},
    { &hf_h282_clearCameraLens,
      { "clearCameraLens", "h282.clearCameraLens",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setCameraPanSpeed,
      { "setCameraPanSpeed", "h282.setCameraPanSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraPanSpeed", HFILL }},
    { &hf_h282_setCameraTiltSpeed,
      { "setCameraTiltSpeed", "h282.setCameraTiltSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraTiltSpeed", HFILL }},
    { &hf_h282_setBackLight,
      { "setBackLight", "h282.setBackLight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BackLight", HFILL }},
    { &hf_h282_setWhiteBalance,
      { "setWhiteBalance", "h282.setWhiteBalance",
        FT_UINT32, BASE_DEC, NULL, 0,
        "WhiteBalance", HFILL }},
    { &hf_h282_setWhiteBalanceMode,
      { "setWhiteBalanceMode", "h282.setWhiteBalanceMode",
        FT_UINT32, BASE_DEC, VALS(h282_Mode_vals), 0,
        "Mode", HFILL }},
    { &hf_h282_calibrateWhiteBalance,
      { "calibrateWhiteBalance", "h282.calibrateWhiteBalance",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_focusImage,
      { "focusImage", "h282.focusImage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_captureImage,
      { "captureImage", "h282.captureImage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_panContinuous,
      { "panContinuous", "h282.panContinuous",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_tiltContinuous,
      { "tiltContinuous", "h282.tiltContinuous",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_zoomContinuous,
      { "zoomContinuous", "h282.zoomContinuous",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_focusContinuous,
      { "focusContinuous", "h282.focusContinuous",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setZoomPosition,
      { "setZoomPosition", "h282.setZoomPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setFocusPosition,
      { "setFocusPosition", "h282.setFocusPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setIrisPosition,
      { "setIrisPosition", "h282.setIrisPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setPanPosition,
      { "setPanPosition", "h282.setPanPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setTiltPosition,
      { "setTiltPosition", "h282.setTiltPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_setZoomMagnification,
      { "setZoomMagnification", "h282.setZoomMagnification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ZoomMagnification", HFILL }},
    { &hf_h282_setPanView,
      { "setPanView", "h282.setPanView",
        FT_INT32, BASE_DEC, NULL, 0,
        "PanView", HFILL }},
    { &hf_h282_setTiltView,
      { "setTiltView", "h282.setTiltView",
        FT_INT32, BASE_DEC, NULL, 0,
        "TiltView", HFILL }},
    { &hf_h282_selectSlide,
      { "selectSlide", "h282.selectSlide",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SlideNumber", HFILL }},
    { &hf_h282_selectNextSlide,
      { "selectNextSlide", "h282.selectNextSlide",
        FT_UINT32, BASE_DEC, VALS(h282_SelectDirection_vals), 0,
        "SelectDirection", HFILL }},
    { &hf_h282_playAutoSlideShow,
      { "playAutoSlideShow", "h282.playAutoSlideShow",
        FT_UINT32, BASE_DEC, VALS(h282_AutoSlideShowControl_vals), 0,
        "AutoSlideShowControl", HFILL }},
    { &hf_h282_setAutoSlideDisplayTime,
      { "setAutoSlideDisplayTime", "h282.setAutoSlideDisplayTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AutoSlideDisplayTime", HFILL }},
    { &hf_h282_continuousRewindControl,
      { "continuousRewindControl", "h282.continuousRewindControl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_continuousFastForwardControl,
      { "continuousFastForwardControl", "h282.continuousFastForwardControl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_searchBackwardsControl,
      { "searchBackwardsControl", "h282.searchBackwardsControl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_searchForwardsControl,
      { "searchForwardsControl", "h282.searchForwardsControl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_pause_01,
      { "pause", "h282.pause",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_selectProgram,
      { "selectProgram", "h282.selectProgram",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProgramNumber", HFILL }},
    { &hf_h282_nextProgramSelect,
      { "nextProgramSelect", "h282.nextProgramSelect",
        FT_UINT32, BASE_DEC, VALS(h282_SelectDirection_vals), 0,
        "SelectDirection", HFILL }},
    { &hf_h282_gotoNormalPlayTimePoint,
      { "gotoNormalPlayTimePoint", "h282.gotoNormalPlayTimePoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProgramDuration", HFILL }},
    { &hf_h282_continuousPlayBackMode,
      { "continuousPlayBackMode", "h282.continuousPlayBackMode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_setPlaybackSpeed,
      { "setPlaybackSpeed", "h282.setPlaybackSpeed",
        FT_NONE, BASE_NONE, NULL, 0,
        "PlaybackSpeed", HFILL }},
    { &hf_h282_play,
      { "play", "h282.play",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_setAudioOutputMute,
      { "setAudioOutputMute", "h282.setAudioOutputMute",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_playToNormalPlayTimePoint,
      { "playToNormalPlayTimePoint", "h282.playToNormalPlayTimePoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProgramDuration", HFILL }},
    { &hf_h282_record,
      { "record", "h282.record",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_recordForDuration,
      { "recordForDuration", "h282.recordForDuration",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_configureVideoInputs,
      { "configureVideoInputs", "h282.configureVideoInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeviceInputs", HFILL }},
    { &hf_h282_configureAudioInputs,
      { "configureAudioInputs", "h282.configureAudioInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeviceInputs", HFILL }},
    { &hf_h282_nonStandardControl,
      { "nonStandardControl", "h282.nonStandardControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h282_getDeviceState,
      { "getDeviceState", "h282.getDeviceState",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getDeviceDate,
      { "getDeviceDate", "h282.getDeviceDate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getDeviceTime,
      { "getDeviceTime", "h282.getDeviceTime",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getdevicePreset,
      { "getdevicePreset", "h282.getdevicePreset",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getIrisMode,
      { "getIrisMode", "h282.getIrisMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getFocusMode,
      { "getFocusMode", "h282.getFocusMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getBacklightMode,
      { "getBacklightMode", "h282.getBacklightMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getPointingMode,
      { "getPointingMode", "h282.getPointingMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getCameraLens,
      { "getCameraLens", "h282.getCameraLens",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getCameraFilter,
      { "getCameraFilter", "h282.getCameraFilter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getExternalLight,
      { "getExternalLight", "h282.getExternalLight",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getCameraPanSpeed,
      { "getCameraPanSpeed", "h282.getCameraPanSpeed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getCameraTiltSpeed,
      { "getCameraTiltSpeed", "h282.getCameraTiltSpeed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getBackLightMode,
      { "getBackLightMode", "h282.getBackLightMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getBackLight,
      { "getBackLight", "h282.getBackLight",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getWhiteBalance,
      { "getWhiteBalance", "h282.getWhiteBalance",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getWhiteBalanceMode,
      { "getWhiteBalanceMode", "h282.getWhiteBalanceMode",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getZoomPosition,
      { "getZoomPosition", "h282.getZoomPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getFocusPosition,
      { "getFocusPosition", "h282.getFocusPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getIrisPosition,
      { "getIrisPosition", "h282.getIrisPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getPanPosition,
      { "getPanPosition", "h282.getPanPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getTiltPosition,
      { "getTiltPosition", "h282.getTiltPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getSelectedSlide,
      { "getSelectedSlide", "h282.getSelectedSlide",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getAutoSlideDisplayTime,
      { "getAutoSlideDisplayTime", "h282.getAutoSlideDisplayTime",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getSelectedProgram,
      { "getSelectedProgram", "h282.getSelectedProgram",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getStreamPlayerState,
      { "getStreamPlayerState", "h282.getStreamPlayerState",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getCurrentProgramDuration,
      { "getCurrentProgramDuration", "h282.getCurrentProgramDuration",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getPlaybackSpeed,
      { "getPlaybackSpeed", "h282.getPlaybackSpeed",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getAudioOutputState,
      { "getAudioOutputState", "h282.getAudioOutputState",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getConfigurableVideoInputs,
      { "getConfigurableVideoInputs", "h282.getConfigurableVideoInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getVideoInputs,
      { "getVideoInputs", "h282.getVideoInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getConfigurableAudioInputs,
      { "getConfigurableAudioInputs", "h282.getConfigurableAudioInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getAudioInputs,
      { "getAudioInputs", "h282.getAudioInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_getNonStandardStatus,
      { "getNonStandardStatus", "h282.getNonStandardStatus",
        FT_UINT32, BASE_DEC, VALS(h282_NonStandardIdentifier_vals), 0,
        "NonStandardIdentifier", HFILL }},
    { &hf_h282_deviceState,
      { "deviceState", "h282.deviceState",
        FT_UINT32, BASE_DEC, VALS(h282_DeviceState_vals), 0,
        NULL, HFILL }},
    { &hf_h282_unknown,
      { "unknown", "h282.unknown",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_currentDay,
      { "currentDay", "h282.currentDay",
        FT_UINT32, BASE_DEC, VALS(h282_T_currentDay_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentMonth,
      { "currentMonth", "h282.currentMonth",
        FT_UINT32, BASE_DEC, VALS(h282_T_currentMonth_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentYear,
      { "currentYear", "h282.currentYear",
        FT_UINT32, BASE_DEC, VALS(h282_T_currentYear_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentHour,
      { "currentHour", "h282.currentHour",
        FT_UINT32, BASE_DEC, VALS(h282_T_currentHour_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentMinute,
      { "currentMinute", "h282.currentMinute",
        FT_UINT32, BASE_DEC, VALS(h282_T_currentMinute_vals), 0,
        NULL, HFILL }},
    { &hf_h282_preset,
      { "preset", "h282.preset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PresetNumber", HFILL }},
    { &hf_h282_mode_01,
      { "mode", "h282.mode",
        FT_UINT32, BASE_DEC, VALS(h282_Mode_vals), 0,
        NULL, HFILL }},
    { &hf_h282_automatic,
      { "automatic", "h282.automatic",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_lensNumber_01,
      { "lensNumber", "h282.lensNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraLensNumber", HFILL }},
    { &hf_h282_lensNumber_02,
      { "lensNumber", "h282.lensNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraFilterNumber", HFILL }},
    { &hf_h282_speed,
      { "speed", "h282.speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraPanSpeed", HFILL }},
    { &hf_h282_speed_01,
      { "speed", "h282.speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CameraTiltSpeed", HFILL }},
    { &hf_h282_backLight,
      { "backLight", "h282.backLight",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_whiteBalance,
      { "whiteBalance", "h282.whiteBalance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_slide,
      { "slide", "h282.slide",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SlideNumber", HFILL }},
    { &hf_h282_time,
      { "time", "h282.time",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AutoSlideDisplayTime", HFILL }},
    { &hf_h282_program,
      { "program", "h282.program",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProgramNumber", HFILL }},
    { &hf_h282_state,
      { "state", "h282.state",
        FT_UINT32, BASE_DEC, VALS(h282_StreamPlayerState_vals), 0,
        "StreamPlayerState", HFILL }},
    { &hf_h282_speed_02,
      { "speed", "h282.speed",
        FT_NONE, BASE_NONE, NULL, 0,
        "PlaybackSpeed", HFILL }},
    { &hf_h282_mute,
      { "mute", "h282.mute",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_currentdeviceState,
      { "currentdeviceState", "h282.currentdeviceState",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentDeviceState_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentDeviceDate,
      { "currentDeviceDate", "h282.currentDeviceDate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_currentDeviceTime,
      { "currentDeviceTime", "h282.currentDeviceTime",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_currentDevicePreset,
      { "currentDevicePreset", "h282.currentDevicePreset",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentDevicePreset_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentIrisMode,
      { "currentIrisMode", "h282.currentIrisMode",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentMode_vals), 0,
        "CurrentMode", HFILL }},
    { &hf_h282_currentFocusMode,
      { "currentFocusMode", "h282.currentFocusMode",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentMode_vals), 0,
        "CurrentMode", HFILL }},
    { &hf_h282_currentBackLightMode,
      { "currentBackLightMode", "h282.currentBackLightMode",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentMode_vals), 0,
        "CurrentMode", HFILL }},
    { &hf_h282_currentPointingMode,
      { "currentPointingMode", "h282.currentPointingMode",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentPointingMode_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentCameraLens,
      { "currentCameraLens", "h282.currentCameraLens",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentCameraLensNumber_vals), 0,
        "CurrentCameraLensNumber", HFILL }},
    { &hf_h282_currentCameraFilter,
      { "currentCameraFilter", "h282.currentCameraFilter",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentCameraFilterNumber_vals), 0,
        "CurrentCameraFilterNumber", HFILL }},
    { &hf_h282_currentExternalLight,
      { "currentExternalLight", "h282.currentExternalLight",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentExternalLight_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentCameraPanSpeed,
      { "currentCameraPanSpeed", "h282.currentCameraPanSpeed",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentCameraPanSpeed_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentCameraTiltSpeed,
      { "currentCameraTiltSpeed", "h282.currentCameraTiltSpeed",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentCameraTiltSpeed_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentBackLight,
      { "currentBackLight", "h282.currentBackLight",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentBackLight_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentWhiteBalance,
      { "currentWhiteBalance", "h282.currentWhiteBalance",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentWhiteBalance_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentWhiteBalanceMode,
      { "currentWhiteBalanceMode", "h282.currentWhiteBalanceMode",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentMode_vals), 0,
        "CurrentMode", HFILL }},
    { &hf_h282_currentZoomPosition,
      { "currentZoomPosition", "h282.currentZoomPosition",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentZoomPosition_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentFocusPosition,
      { "currentFocusPosition", "h282.currentFocusPosition",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentFocusPosition_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentIrisPosition,
      { "currentIrisPosition", "h282.currentIrisPosition",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentIrisPosition_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentPanPosition,
      { "currentPanPosition", "h282.currentPanPosition",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentPanPosition_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentTiltPosition,
      { "currentTiltPosition", "h282.currentTiltPosition",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentTiltPosition_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentSlide,
      { "currentSlide", "h282.currentSlide",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentSlide_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentAutoSlideDisplayTime,
      { "currentAutoSlideDisplayTime", "h282.currentAutoSlideDisplayTime",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentAutoSlideDisplayTime_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentSelectedProgram,
      { "currentSelectedProgram", "h282.currentSelectedProgram",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentSelectedProgram_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentstreamPlayerState,
      { "currentstreamPlayerState", "h282.currentstreamPlayerState",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentStreamPlayerState_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentProgramDuration,
      { "currentProgramDuration", "h282.currentProgramDuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProgramDuration", HFILL }},
    { &hf_h282_currentPlaybackSpeed,
      { "currentPlaybackSpeed", "h282.currentPlaybackSpeed",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentPlaybackSpeed_vals), 0,
        NULL, HFILL }},
    { &hf_h282_currentAudioOutputMute,
      { "currentAudioOutputMute", "h282.currentAudioOutputMute",
        FT_UINT32, BASE_DEC, VALS(h282_CurrentAudioOutputMute_vals), 0,
        NULL, HFILL }},
    { &hf_h282_configurableVideoInputs,
      { "configurableVideoInputs", "h282.configurableVideoInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeviceInputs", HFILL }},
    { &hf_h282_videoInputs,
      { "videoInputs", "h282.videoInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeviceInputs", HFILL }},
    { &hf_h282_configurableAudioInputs,
      { "configurableAudioInputs", "h282.configurableAudioInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeviceInputs", HFILL }},
    { &hf_h282_audioInputs,
      { "audioInputs", "h282.audioInputs",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeviceInputs", HFILL }},
    { &hf_h282_nonStandardStatus,
      { "nonStandardStatus", "h282.nonStandardStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h282_requestDeviceLockChanged,
      { "requestDeviceLockChanged", "h282.requestDeviceLockChanged",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestDeviceAvailabilityChanged,
      { "requestDeviceAvailabilityChanged", "h282.requestDeviceAvailabilityChanged",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestCameraPannedToLimit,
      { "requestCameraPannedToLimit", "h282.requestCameraPannedToLimit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestCameraTiltedToLimit,
      { "requestCameraTiltedToLimit", "h282.requestCameraTiltedToLimit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestCameraZoomedToLimit,
      { "requestCameraZoomedToLimit", "h282.requestCameraZoomedToLimit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestCameraFocusedToLimit,
      { "requestCameraFocusedToLimit", "h282.requestCameraFocusedToLimit",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestAutoSlideShowFinished,
      { "requestAutoSlideShowFinished", "h282.requestAutoSlideShowFinished",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestStreamPlayerStateChange,
      { "requestStreamPlayerStateChange", "h282.requestStreamPlayerStateChange",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestStreamPlayerProgramChange,
      { "requestStreamPlayerProgramChange", "h282.requestStreamPlayerProgramChange",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestNonStandardEvent,
      { "requestNonStandardEvent", "h282.requestNonStandardEvent",
        FT_UINT32, BASE_DEC, VALS(h282_NonStandardIdentifier_vals), 0,
        "NonStandardIdentifier", HFILL }},
    { &hf_h282_deviceLockChanged,
      { "deviceLockChanged", "h282.deviceLockChanged",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_deviceAvailabilityChanged,
      { "deviceAvailabilityChanged", "h282.deviceAvailabilityChanged",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_cameraPannedToLimit,
      { "cameraPannedToLimit", "h282.cameraPannedToLimit",
        FT_UINT32, BASE_DEC, VALS(h282_CameraPannedToLimit_vals), 0,
        NULL, HFILL }},
    { &hf_h282_cameraTiltedToLimit,
      { "cameraTiltedToLimit", "h282.cameraTiltedToLimit",
        FT_UINT32, BASE_DEC, VALS(h282_CameraTiltedToLimit_vals), 0,
        NULL, HFILL }},
    { &hf_h282_cameraZoomedToLimit,
      { "cameraZoomedToLimit", "h282.cameraZoomedToLimit",
        FT_UINT32, BASE_DEC, VALS(h282_CameraZoomedToLimit_vals), 0,
        NULL, HFILL }},
    { &hf_h282_cameraFocusedToLimit,
      { "cameraFocusedToLimit", "h282.cameraFocusedToLimit",
        FT_UINT32, BASE_DEC, VALS(h282_CameraFocusedToLimit_vals), 0,
        NULL, HFILL }},
    { &hf_h282_autoSlideShowFinished,
      { "autoSlideShowFinished", "h282.autoSlideShowFinished",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_streamPlayerStateChange,
      { "streamPlayerStateChange", "h282.streamPlayerStateChange",
        FT_UINT32, BASE_DEC, VALS(h282_StreamPlayerState_vals), 0,
        "StreamPlayerState", HFILL }},
    { &hf_h282_streamPlayerProgramChange,
      { "streamPlayerProgramChange", "h282.streamPlayerProgramChange",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProgramNumber", HFILL }},
    { &hf_h282_nonStandardEvent,
      { "nonStandardEvent", "h282.nonStandardEvent",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h282_requestHandle,
      { "requestHandle", "h282.requestHandle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Handle", HFILL }},
    { &hf_h282_streamIdentifier,
      { "streamIdentifier", "h282.streamIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StreamID", HFILL }},
    { &hf_h282_result,
      { "result", "h282.result",
        FT_UINT32, BASE_DEC, VALS(h282_T_result_vals), 0,
        NULL, HFILL }},
    { &hf_h282_successful,
      { "successful", "h282.successful",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_requestDenied,
      { "requestDenied", "h282.requestDenied",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceUnavailable,
      { "deviceUnavailable", "h282.deviceUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_invalidStreamID,
      { "invalidStreamID", "h282.invalidStreamID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_currentDeviceIsLocked,
      { "currentDeviceIsLocked", "h282.currentDeviceIsLocked",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceIncompatible,
      { "deviceIncompatible", "h282.deviceIncompatible",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_sourceEventNotify,
      { "sourceEventNotify", "h282.sourceEventNotify",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_result_01,
      { "result", "h282.result",
        FT_UINT32, BASE_DEC, VALS(h282_T_result_01_vals), 0,
        "T_result_01", HFILL }},
    { &hf_h282_eventsNotSupported,
      { "eventsNotSupported", "h282.eventsNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceAttributeList,
      { "deviceAttributeList", "h282.deviceAttributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_DeviceAttribute", HFILL }},
    { &hf_h282_deviceAttributeList_item,
      { "DeviceAttribute", "h282.DeviceAttribute",
        FT_UINT32, BASE_DEC, VALS(h282_DeviceAttribute_vals), 0,
        NULL, HFILL }},
    { &hf_h282_result_02,
      { "result", "h282.result",
        FT_UINT32, BASE_DEC, VALS(h282_T_result_02_vals), 0,
        "T_result_02", HFILL }},
    { &hf_h282_unknownDevice,
      { "unknownDevice", "h282.unknownDevice",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_lockFlag,
      { "lockFlag", "h282.lockFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h282_result_03,
      { "result", "h282.result",
        FT_UINT32, BASE_DEC, VALS(h282_T_result_03_vals), 0,
        "T_result_03", HFILL }},
    { &hf_h282_lockingNotSupported,
      { "lockingNotSupported", "h282.lockingNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceAlreadyLocked,
      { "deviceAlreadyLocked", "h282.deviceAlreadyLocked",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_result_04,
      { "result", "h282.result",
        FT_UINT32, BASE_DEC, VALS(h282_T_result_04_vals), 0,
        "T_result_04", HFILL }},
    { &hf_h282_lockRequired,
      { "lockRequired", "h282.lockRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_lockNotRequired,
      { "lockNotRequired", "h282.lockNotRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_controlAttributeList,
      { "controlAttributeList", "h282.controlAttributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_8_OF_ControlAttribute", HFILL }},
    { &hf_h282_controlAttributeList_item,
      { "ControlAttribute", "h282.ControlAttribute",
        FT_UINT32, BASE_DEC, VALS(h282_ControlAttribute_vals), 0,
        NULL, HFILL }},
    { &hf_h282_statusAttributeIdentifierList,
      { "statusAttributeIdentifierList", "h282.statusAttributeIdentifierList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_16_OF_StatusAttributeIdentifier", HFILL }},
    { &hf_h282_statusAttributeIdentifierList_item,
      { "StatusAttributeIdentifier", "h282.StatusAttributeIdentifier",
        FT_UINT32, BASE_DEC, VALS(h282_StatusAttributeIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_h282_statusAttributeList,
      { "statusAttributeList", "h282.statusAttributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_16_OF_StatusAttribute", HFILL }},
    { &hf_h282_statusAttributeList_item,
      { "StatusAttribute", "h282.StatusAttribute",
        FT_UINT32, BASE_DEC, VALS(h282_StatusAttribute_vals), 0,
        NULL, HFILL }},
    { &hf_h282_result_05,
      { "result", "h282.result",
        FT_UINT32, BASE_DEC, VALS(h282_T_result_05_vals), 0,
        "T_result_05", HFILL }},
    { &hf_h282_deviceAttributeError,
      { "deviceAttributeError", "h282.deviceAttributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceEventIdentifierList,
      { "deviceEventIdentifierList", "h282.deviceEventIdentifierList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_DeviceEventIdentifier", HFILL }},
    { &hf_h282_deviceEventIdentifierList_item,
      { "DeviceEventIdentifier", "h282.DeviceEventIdentifier",
        FT_UINT32, BASE_DEC, VALS(h282_DeviceEventIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_h282_result_06,
      { "result", "h282.result",
        FT_UINT32, BASE_DEC, VALS(h282_T_result_06_vals), 0,
        "T_result_06", HFILL }},
    { &hf_h282_deviceEventList,
      { "deviceEventList", "h282.deviceEventList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_8_OF_DeviceEvent", HFILL }},
    { &hf_h282_deviceEventList_item,
      { "DeviceEvent", "h282.DeviceEvent",
        FT_UINT32, BASE_DEC, VALS(h282_DeviceEvent_vals), 0,
        NULL, HFILL }},
    { &hf_h282_nonStandardData,
      { "nonStandardData", "h282.nonStandardData",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardParameter", HFILL }},
    { &hf_h282_request,
      { "request", "h282.request",
        FT_UINT32, BASE_DEC, VALS(h282_RequestPDU_vals), 0,
        "RequestPDU", HFILL }},
    { &hf_h282_response,
      { "response", "h282.response",
        FT_UINT32, BASE_DEC, VALS(h282_ResponsePDU_vals), 0,
        "ResponsePDU", HFILL }},
    { &hf_h282_indication,
      { "indication", "h282.indication",
        FT_UINT32, BASE_DEC, VALS(h282_IndicationPDU_vals), 0,
        "IndicationPDU", HFILL }},
    { &hf_h282_sourceSelectRequest,
      { "sourceSelectRequest", "h282.sourceSelectRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_sourceEventsRequest,
      { "sourceEventsRequest", "h282.sourceEventsRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceAttributeRequest,
      { "deviceAttributeRequest", "h282.deviceAttributeRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceLockRequest,
      { "deviceLockRequest", "h282.deviceLockRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceLockEnquireRequest,
      { "deviceLockEnquireRequest", "h282.deviceLockEnquireRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceControlRequest,
      { "deviceControlRequest", "h282.deviceControlRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceStatusEnquireRequest,
      { "deviceStatusEnquireRequest", "h282.deviceStatusEnquireRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_configureDeviceEventsRequest,
      { "configureDeviceEventsRequest", "h282.configureDeviceEventsRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_nonStandardRequest,
      { "nonStandardRequest", "h282.nonStandardRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardPDU", HFILL }},
    { &hf_h282_sourceSelectResponse,
      { "sourceSelectResponse", "h282.sourceSelectResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_sourceEventsResponse,
      { "sourceEventsResponse", "h282.sourceEventsResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceAttributeResponse,
      { "deviceAttributeResponse", "h282.deviceAttributeResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceLockResponse,
      { "deviceLockResponse", "h282.deviceLockResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceLockEnquireResponse,
      { "deviceLockEnquireResponse", "h282.deviceLockEnquireResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceStatusEnquireResponse,
      { "deviceStatusEnquireResponse", "h282.deviceStatusEnquireResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_configureDeviceEventsResponse,
      { "configureDeviceEventsResponse", "h282.configureDeviceEventsResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_nonStandardResponse,
      { "nonStandardResponse", "h282.nonStandardResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardPDU", HFILL }},
    { &hf_h282_sourceChangeEventIndication,
      { "sourceChangeEventIndication", "h282.sourceChangeEventIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceLockTerminatedIndication,
      { "deviceLockTerminatedIndication", "h282.deviceLockTerminatedIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_deviceEventNotifyIndication,
      { "deviceEventNotifyIndication", "h282.deviceEventNotifyIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h282_nonStandardIndication,
      { "nonStandardIndication", "h282.nonStandardIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardPDU", HFILL }},

/*--- End of included file: packet-h282-hfarr.c ---*/
#line 75 "../../asn1/h282/packet-h282-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h282,

/*--- Included file: packet-h282-ettarr.c ---*/
#line 1 "../../asn1/h282/packet-h282-ettarr.c"
    &ett_h282_Key,
    &ett_h282_NonStandardParameter,
    &ett_h282_NonStandardIdentifier,
    &ett_h282_DeviceClass,
    &ett_h282_DeviceProfile,
    &ett_h282_StreamProfile,
    &ett_h282_CapabilityID,
    &ett_h282_NonCollapsingCapabilities,
    &ett_h282_NonCollapsingCapabilities_item,
    &ett_h282_T_applicationData,
    &ett_h282_SET_SIZE_0_127_OF_DeviceProfile,
    &ett_h282_SET_SIZE_0_127_OF_StreamProfile,
    &ett_h282_StreamPlayerState,
    &ett_h282_DevicePresetCapability,
    &ett_h282_T_presetCapability,
    &ett_h282_T_presetCapability_item,
    &ett_h282_CameraFilterCapability,
    &ett_h282_T_filterTextLabel,
    &ett_h282_T_filterTextLabel_item,
    &ett_h282_CameraLensCapability,
    &ett_h282_T_accessoryTextLabel,
    &ett_h282_T_accessoryTextLabel_item,
    &ett_h282_ExternalCameraLightCapability,
    &ett_h282_T_lightTextLabel,
    &ett_h282_T_lightTextLabel_item,
    &ett_h282_CameraPanSpeedCapability,
    &ett_h282_CameraTiltSpeedCapability,
    &ett_h282_PanPositionCapability,
    &ett_h282_TiltPositionCapability,
    &ett_h282_PlayBackSpeedCapability,
    &ett_h282_T_multiplierFactors,
    &ett_h282_T_divisorFactors,
    &ett_h282_VideoInputsCapability,
    &ett_h282_T_availableDevices,
    &ett_h282_T_availableDevices_item,
    &ett_h282_AudioInputsCapability,
    &ett_h282_T_availableDevices_01,
    &ett_h282_T_availableDevices_item_01,
    &ett_h282_DeviceAttribute,
    &ett_h282_DeviceState,
    &ett_h282_DeviceDate,
    &ett_h282_DeviceTime,
    &ett_h282_DevicePreset,
    &ett_h282_T_mode,
    &ett_h282_Mode,
    &ett_h282_PointingToggle,
    &ett_h282_SelectExternalLight,
    &ett_h282_PanContinuous,
    &ett_h282_T_panDirection,
    &ett_h282_TiltContinuous,
    &ett_h282_T_tiltDirection,
    &ett_h282_ZoomContinuous,
    &ett_h282_T_zoomDirection,
    &ett_h282_FocusContinuous,
    &ett_h282_T_focusDirection,
    &ett_h282_PositioningMode,
    &ett_h282_SetZoomPosition,
    &ett_h282_SetFocusPosition,
    &ett_h282_SetIrisPosition,
    &ett_h282_SetPanPosition,
    &ett_h282_SetTiltPosition,
    &ett_h282_SelectDirection,
    &ett_h282_AutoSlideShowControl,
    &ett_h282_ProgramDuration,
    &ett_h282_PlaybackSpeed,
    &ett_h282_RecordForDuration,
    &ett_h282_DeviceInputs,
    &ett_h282_T_inputDevices,
    &ett_h282_T_inputDevices_item,
    &ett_h282_ControlAttribute,
    &ett_h282_StatusAttributeIdentifier,
    &ett_h282_CurrentDeviceState,
    &ett_h282_CurrentDeviceDate,
    &ett_h282_T_currentDay,
    &ett_h282_T_currentMonth,
    &ett_h282_T_currentYear,
    &ett_h282_CurrentDeviceTime,
    &ett_h282_T_currentHour,
    &ett_h282_T_currentMinute,
    &ett_h282_CurrentDevicePreset,
    &ett_h282_CurrentMode,
    &ett_h282_CurrentPointingMode,
    &ett_h282_CurrentCameraLensNumber,
    &ett_h282_CurrentCameraFilterNumber,
    &ett_h282_CurrentExternalLight,
    &ett_h282_CurrentCameraPanSpeed,
    &ett_h282_CurrentCameraTiltSpeed,
    &ett_h282_CurrentBackLight,
    &ett_h282_CurrentWhiteBalance,
    &ett_h282_CurrentZoomPosition,
    &ett_h282_CurrentFocusPosition,
    &ett_h282_CurrentIrisPosition,
    &ett_h282_CurrentPanPosition,
    &ett_h282_CurrentTiltPosition,
    &ett_h282_CurrentSlide,
    &ett_h282_CurrentAutoSlideDisplayTime,
    &ett_h282_CurrentSelectedProgram,
    &ett_h282_CurrentStreamPlayerState,
    &ett_h282_CurrentPlaybackSpeed,
    &ett_h282_CurrentAudioOutputMute,
    &ett_h282_StatusAttribute,
    &ett_h282_DeviceEventIdentifier,
    &ett_h282_CameraPannedToLimit,
    &ett_h282_CameraTiltedToLimit,
    &ett_h282_CameraZoomedToLimit,
    &ett_h282_CameraFocusedToLimit,
    &ett_h282_DeviceEvent,
    &ett_h282_SourceSelectRequest,
    &ett_h282_SourceSelectResponse,
    &ett_h282_T_result,
    &ett_h282_SourceEventsRequest,
    &ett_h282_SourceEventsResponse,
    &ett_h282_T_result_01,
    &ett_h282_SourceChangeEventIndication,
    &ett_h282_DeviceAttributeRequest,
    &ett_h282_DeviceAttributeResponse,
    &ett_h282_SET_OF_DeviceAttribute,
    &ett_h282_T_result_02,
    &ett_h282_DeviceLockRequest,
    &ett_h282_DeviceLockResponse,
    &ett_h282_T_result_03,
    &ett_h282_DeviceLockEnquireRequest,
    &ett_h282_DeviceLockEnquireResponse,
    &ett_h282_T_result_04,
    &ett_h282_DeviceLockTerminatedIndication,
    &ett_h282_DeviceControlRequest,
    &ett_h282_SET_SIZE_1_8_OF_ControlAttribute,
    &ett_h282_DeviceStatusEnquireRequest,
    &ett_h282_SET_SIZE_1_16_OF_StatusAttributeIdentifier,
    &ett_h282_DeviceStatusEnquireResponse,
    &ett_h282_SET_SIZE_1_16_OF_StatusAttribute,
    &ett_h282_T_result_05,
    &ett_h282_ConfigureDeviceEventsRequest,
    &ett_h282_SET_OF_DeviceEventIdentifier,
    &ett_h282_ConfigureDeviceEventsResponse,
    &ett_h282_T_result_06,
    &ett_h282_DeviceEventNotifyIndication,
    &ett_h282_SET_SIZE_1_8_OF_DeviceEvent,
    &ett_h282_NonStandardPDU,
    &ett_h282_RDCPDU,
    &ett_h282_RequestPDU,
    &ett_h282_ResponsePDU,
    &ett_h282_IndicationPDU,

/*--- End of included file: packet-h282-ettarr.c ---*/
#line 81 "../../asn1/h282/packet-h282-template.c"
  };

  /* Register protocol */
  proto_h282 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h282, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector(PFNAME, dissect_h282, proto_h282);
  new_register_dissector(PFNAME".device_list", dissect_NonCollapsingCapabilities_PDU, proto_h282);

}

/*--- proto_reg_handoff_h282 -------------------------------------------*/
void proto_reg_handoff_h282(void)
{

}

