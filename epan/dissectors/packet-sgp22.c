/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-sgp22.c                                                             */
/* asn2wrs.py -b -C -q -L -p sgp22 -c ./sgp22.cnf -s ./packet-sgp22-template -D . -O ../.. PEDefinitions.asn RSPDefinitions.asn */

/* packet-sgp22.c
 * Routines for SGP.22 packet dissection.
 *
 * Copyright 2025, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>

#include "packet-ber.h"
#include "packet-media-type.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-sgp22.h"

#define PNAME  "SGP.22 GSMA Remote SIM Provisioning (RSP)"
#define PSNAME "SGP.22"
#define PFNAME "sgp22"

void proto_register_sgp22(void);
void proto_reg_handoff_sgp22(void);

static int proto_sgp22;
static int hf_sgp22_GetEuiccInfo1Request_PDU;     /* GetEuiccInfo1Request */
static int hf_sgp22_EUICCInfo1_PDU;               /* EUICCInfo1 */
static int hf_sgp22_GetEuiccInfo2Request_PDU;     /* GetEuiccInfo2Request */
static int hf_sgp22_EUICCInfo2_PDU;               /* EUICCInfo2 */
static int hf_sgp22_ProfileInfoListRequest_PDU;   /* ProfileInfoListRequest */
static int hf_sgp22_ProfileInfoListResponse_PDU;  /* ProfileInfoListResponse */
static int hf_sgp22_ProfileInfo_PDU;              /* ProfileInfo */
static int hf_sgp22_StoreMetadataRequest_PDU;     /* StoreMetadataRequest */
static int hf_sgp22_UpdateMetadataRequest_PDU;    /* UpdateMetadataRequest */
static int hf_sgp22_PrepareDownloadRequest_PDU;   /* PrepareDownloadRequest */
static int hf_sgp22_PrepareDownloadResponse_PDU;  /* PrepareDownloadResponse */
static int hf_sgp22_AuthenticateServerRequest_PDU;  /* AuthenticateServerRequest */
static int hf_sgp22_AuthenticateServerResponse_PDU;  /* AuthenticateServerResponse */
static int hf_sgp22_CancelSessionRequest_PDU;     /* CancelSessionRequest */
static int hf_sgp22_CancelSessionResponse_PDU;    /* CancelSessionResponse */
static int hf_sgp22_BoundProfilePackage_PDU;      /* BoundProfilePackage */
static int hf_sgp22_GetEuiccChallengeRequest_PDU;  /* GetEuiccChallengeRequest */
static int hf_sgp22_GetEuiccChallengeResponse_PDU;  /* GetEuiccChallengeResponse */
static int hf_sgp22_ProfileInstallationResult_PDU;  /* ProfileInstallationResult */
static int hf_sgp22_ListNotificationRequest_PDU;  /* ListNotificationRequest */
static int hf_sgp22_ListNotificationResponse_PDU;  /* ListNotificationResponse */
static int hf_sgp22_NotificationMetadata_PDU;     /* NotificationMetadata */
static int hf_sgp22_SetNicknameRequest_PDU;       /* SetNicknameRequest */
static int hf_sgp22_SetNicknameResponse_PDU;      /* SetNicknameResponse */
static int hf_sgp22_ActivationCodeRetrievalInfo_PDU;  /* ActivationCodeRetrievalInfo */
static int hf_sgp22_InitialiseSecureChannelRequest_PDU;  /* InitialiseSecureChannelRequest */
static int hf_sgp22_ConfigureISDPRequest_PDU;     /* ConfigureISDPRequest */
static int hf_sgp22_ReplaceSessionKeysRequest_PDU;  /* ReplaceSessionKeysRequest */
static int hf_sgp22_RetrieveNotificationsListRequest_PDU;  /* RetrieveNotificationsListRequest */
static int hf_sgp22_RetrieveNotificationsListResponse_PDU;  /* RetrieveNotificationsListResponse */
static int hf_sgp22_NotificationSentRequest_PDU;  /* NotificationSentRequest */
static int hf_sgp22_NotificationSentResponse_PDU;  /* NotificationSentResponse */
static int hf_sgp22_EnableProfileRequest_PDU;     /* EnableProfileRequest */
static int hf_sgp22_EnableProfileResponse_PDU;    /* EnableProfileResponse */
static int hf_sgp22_DisableProfileRequest_PDU;    /* DisableProfileRequest */
static int hf_sgp22_DisableProfileResponse_PDU;   /* DisableProfileResponse */
static int hf_sgp22_DeleteProfileRequest_PDU;     /* DeleteProfileRequest */
static int hf_sgp22_DeleteProfileResponse_PDU;    /* DeleteProfileResponse */
static int hf_sgp22_EuiccMemoryResetRequest_PDU;  /* EuiccMemoryResetRequest */
static int hf_sgp22_EuiccMemoryResetResponse_PDU;  /* EuiccMemoryResetResponse */
static int hf_sgp22_GetEuiccDataRequest_PDU;      /* GetEuiccDataRequest */
static int hf_sgp22_GetEuiccDataResponse_PDU;     /* GetEuiccDataResponse */
static int hf_sgp22_GetRatRequest_PDU;            /* GetRatRequest */
static int hf_sgp22_GetRatResponse_PDU;           /* GetRatResponse */
static int hf_sgp22_LoadCRLRequest_PDU;           /* LoadCRLRequest */
static int hf_sgp22_LoadCRLResponse_PDU;          /* LoadCRLResponse */
static int hf_sgp22_ExpirationDate_PDU;           /* ExpirationDate */
static int hf_sgp22_TotalPartialCrlNumber_PDU;    /* TotalPartialCrlNumber */
static int hf_sgp22_PartialCrlNumber_PDU;         /* PartialCrlNumber */
static int hf_sgp22_RemoteProfileProvisioningRequest_PDU;  /* RemoteProfileProvisioningRequest */
static int hf_sgp22_RemoteProfileProvisioningResponse_PDU;  /* RemoteProfileProvisioningResponse */
static int hf_sgp22_InitiateAuthenticationRequest_PDU;  /* InitiateAuthenticationRequest */
static int hf_sgp22_InitiateAuthenticationResponse_PDU;  /* InitiateAuthenticationResponse */
static int hf_sgp22_AuthenticateClientRequest_PDU;  /* AuthenticateClientRequest */
static int hf_sgp22_AuthenticateClientResponseEs9_PDU;  /* AuthenticateClientResponseEs9 */
static int hf_sgp22_GetBoundProfilePackageRequest_PDU;  /* GetBoundProfilePackageRequest */
static int hf_sgp22_GetBoundProfilePackageResponse_PDU;  /* GetBoundProfilePackageResponse */
static int hf_sgp22_HandleNotification_PDU;       /* HandleNotification */
static int hf_sgp22_EuiccConfiguredAddressesRequest_PDU;  /* EuiccConfiguredAddressesRequest */
static int hf_sgp22_EuiccConfiguredAddressesResponse_PDU;  /* EuiccConfiguredAddressesResponse */
static int hf_sgp22_ISDRProprietaryApplicationTemplate_PDU;  /* ISDRProprietaryApplicationTemplate */
static int hf_sgp22_LpaeActivationRequest_PDU;    /* LpaeActivationRequest */
static int hf_sgp22_LpaeActivationResponse_PDU;   /* LpaeActivationResponse */
static int hf_sgp22_SetDefaultDpAddressRequest_PDU;  /* SetDefaultDpAddressRequest */
static int hf_sgp22_SetDefaultDpAddressResponse_PDU;  /* SetDefaultDpAddressResponse */
static int hf_sgp22_AuthenticateClientResponseEs11_PDU;  /* AuthenticateClientResponseEs11 */
static int hf_sgp22_svn;                          /* VersionType */
static int hf_sgp22_euiccCiPKIdListForVerification;  /* SEQUENCE_OF_SubjectKeyIdentifier */
static int hf_sgp22_euiccCiPKIdListForVerification_item;  /* SubjectKeyIdentifier */
static int hf_sgp22_euiccCiPKIdListForSigning;    /* SEQUENCE_OF_SubjectKeyIdentifier */
static int hf_sgp22_euiccCiPKIdListForSigning_item;  /* SubjectKeyIdentifier */
static int hf_sgp22_profileVersion;               /* VersionType */
static int hf_sgp22_euiccFirmwareVer;             /* VersionType */
static int hf_sgp22_extCardResource;              /* OCTET_STRING */
static int hf_sgp22_uiccCapability;               /* UICCCapability */
static int hf_sgp22_ts102241Version;              /* VersionType */
static int hf_sgp22_globalplatformVersion;        /* VersionType */
static int hf_sgp22_rspCapability;                /* RspCapability */
static int hf_sgp22_euiccCategory;                /* T_euiccCategory */
static int hf_sgp22_forbiddenProfilePolicyRules;  /* PprIds */
static int hf_sgp22_ppVersion;                    /* VersionType */
static int hf_sgp22_sasAcreditationNumber;        /* UTF8String_SIZE_0_64 */
static int hf_sgp22_certificationDataObject;      /* CertificationDataObject */
static int hf_sgp22_treProperties;                /* T_treProperties */
static int hf_sgp22_treProductReference;          /* UTF8String */
static int hf_sgp22_additionalEuiccProfilePackageVersions;  /* SEQUENCE_OF_VersionType */
static int hf_sgp22_additionalEuiccProfilePackageVersions_item;  /* VersionType */
static int hf_sgp22_platformLabel;                /* UTF8String */
static int hf_sgp22_discoveryBaseURL;             /* UTF8String */
static int hf_sgp22_tac;                          /* Octet4 */
static int hf_sgp22_deviceCapabilities;           /* DeviceCapabilities */
static int hf_sgp22_imei;                         /* Octet8 */
static int hf_sgp22_gsmSupportedRelease;          /* VersionType */
static int hf_sgp22_utranSupportedRelease;        /* VersionType */
static int hf_sgp22_cdma2000onexSupportedRelease;  /* VersionType */
static int hf_sgp22_cdma2000hrpdSupportedRelease;  /* VersionType */
static int hf_sgp22_cdma2000ehrpdSupportedRelease;  /* VersionType */
static int hf_sgp22_eutranEpcSupportedRelease;    /* VersionType */
static int hf_sgp22_contactlessSupportedRelease;  /* VersionType */
static int hf_sgp22_rspCrlSupportedVersion;       /* VersionType */
static int hf_sgp22_nrEpcSupportedRelease;        /* VersionType */
static int hf_sgp22_nr5gcSupportedRelease;        /* VersionType */
static int hf_sgp22_eutran5gcSupportedRelease;    /* VersionType */
static int hf_sgp22_lpaSvn;                       /* VersionType */
static int hf_sgp22_catSupportedClasses;          /* CatSupportedClasses */
static int hf_sgp22_euiccFormFactorType;          /* EuiccFormFactorType */
static int hf_sgp22_deviceAdditionalFeatureSupport;  /* DeviceAdditionalFeatureSupport */
static int hf_sgp22_naiSupport;                   /* VersionType */
static int hf_sgp22_groupOfDeviceManufacturerOid;  /* OBJECT_IDENTIFIER */
static int hf_sgp22_searchCriteria;               /* T_searchCriteria */
static int hf_sgp22_isdpAid;                      /* OctetTo16 */
static int hf_sgp22_iccid;                        /* Iccid */
static int hf_sgp22_profileClass;                 /* ProfileClass */
static int hf_sgp22_tagList;                      /* OCTET_STRING */
static int hf_sgp22_profileInfoListOk;            /* SEQUENCE_OF_ProfileInfo */
static int hf_sgp22_profileInfoListOk_item;       /* ProfileInfo */
static int hf_sgp22_profileInfoListError;         /* ProfileInfoListError */
static int hf_sgp22_profileState;                 /* ProfileState */
static int hf_sgp22_profileNickname;              /* UTF8String_SIZE_0_64 */
static int hf_sgp22_serviceProviderName;          /* UTF8String_SIZE_0_32 */
static int hf_sgp22_profileName;                  /* UTF8String_SIZE_0_64 */
static int hf_sgp22_iconType;                     /* IconType */
static int hf_sgp22_icon;                         /* OCTET_STRING_SIZE_0_1024 */
static int hf_sgp22_notificationConfigurationInfo;  /* SEQUENCE_OF_NotificationConfigurationInformation */
static int hf_sgp22_notificationConfigurationInfo_item;  /* NotificationConfigurationInformation */
static int hf_sgp22_profileOwner;                 /* OperatorId */
static int hf_sgp22_dpProprietaryData;            /* DpProprietaryData */
static int hf_sgp22_profilePolicyRules;           /* PprIds */
static int hf_sgp22_serviceSpecificDataStoredInEuicc;  /* VendorSpecificExtension */
static int hf_sgp22_mccMnc;                       /* OCTET_STRING_SIZE_3 */
static int hf_sgp22_gid1;                         /* OCTET_STRING */
static int hf_sgp22_gid2;                         /* OCTET_STRING */
static int hf_sgp22_serviceSpecificDataNotStoredInEuicc;  /* VendorSpecificExtension */
static int hf_sgp22_profileManagementOperation;   /* NotificationEvent */
static int hf_sgp22_notificationAddress;          /* UTF8String */
static int hf_sgp22_VendorSpecificExtension_item;  /* VendorSpecificExtension_item */
static int hf_sgp22_vendorOid;                    /* T_vendorOid */
static int hf_sgp22_vendorSpecificData;           /* T_vendorSpecificData */
static int hf_sgp22_smdpSigned2;                  /* SmdpSigned2 */
static int hf_sgp22_smdpSignature2;               /* OCTET_STRING */
static int hf_sgp22_hashCc;                       /* Octet32 */
static int hf_sgp22_smdpCertificate;              /* Certificate */
static int hf_sgp22_transactionId;                /* TransactionId */
static int hf_sgp22_ccRequiredFlag;               /* BOOLEAN */
static int hf_sgp22_bppEuiccOtpk;                 /* OCTET_STRING */
static int hf_sgp22_downloadResponseOk;           /* PrepareDownloadResponseOk */
static int hf_sgp22_downloadResponseError;        /* PrepareDownloadResponseError */
static int hf_sgp22_euiccSigned2;                 /* EUICCSigned2 */
static int hf_sgp22_euiccSignature2;              /* OCTET_STRING */
static int hf_sgp22_euiccOtpk;                    /* OCTET_STRING */
static int hf_sgp22_downloadErrorCode;            /* DownloadErrorCode */
static int hf_sgp22_serverSigned1;                /* ServerSigned1 */
static int hf_sgp22_serverSignature1;             /* OCTET_STRING */
static int hf_sgp22_euiccCiPKIdToBeUsed;          /* SubjectKeyIdentifier */
static int hf_sgp22_serverCertificate;            /* Certificate */
static int hf_sgp22_ctxParams1;                   /* CtxParams1 */
static int hf_sgp22_euiccChallenge;               /* Octet16 */
static int hf_sgp22_serverAddress;                /* UTF8String */
static int hf_sgp22_serverChallenge;              /* Octet16 */
static int hf_sgp22_ctxParamsForCommonAuthentication;  /* CtxParamsForCommonAuthentication */
static int hf_sgp22_matchingId;                   /* UTF8String */
static int hf_sgp22_deviceInfo;                   /* DeviceInfo */
static int hf_sgp22_authenticateResponseOk;       /* AuthenticateResponseOk */
static int hf_sgp22_authenticateResponseError;    /* AuthenticateResponseError */
static int hf_sgp22_euiccSigned1;                 /* EuiccSigned1 */
static int hf_sgp22_euiccSignature1;              /* OCTET_STRING */
static int hf_sgp22_euiccCertificate;             /* Certificate */
static int hf_sgp22_eumCertificate;               /* Certificate */
static int hf_sgp22_euiccInfo2;                   /* EUICCInfo2 */
static int hf_sgp22_authenticateErrorCode;        /* AuthenticateErrorCode */
static int hf_sgp22_reason;                       /* CancelSessionReason */
static int hf_sgp22_cancelSessionResponseOk;      /* CancelSessionResponseOk */
static int hf_sgp22_cancelSessionResponseError;   /* T_cancelSessionResponseError */
static int hf_sgp22_euiccCancelSessionSigned;     /* EuiccCancelSessionSigned */
static int hf_sgp22_euiccCancelSessionSignature;  /* OCTET_STRING */
static int hf_sgp22_smdpOid;                      /* OBJECT_IDENTIFIER */
static int hf_sgp22_initialiseSecureChannelRequest;  /* InitialiseSecureChannelRequest */
static int hf_sgp22_firstSequenceOf87;            /* T_firstSequenceOf87 */
static int hf_sgp22_firstSequenceOf87_item;       /* OCTET_STRING */
static int hf_sgp22_sequenceOf88;                 /* T_sequenceOf88 */
static int hf_sgp22_sequenceOf88_item;            /* OCTET_STRING */
static int hf_sgp22_secondSequenceOf87;           /* T_secondSequenceOf87 */
static int hf_sgp22_secondSequenceOf87_item;      /* OCTET_STRING */
static int hf_sgp22_sequenceOf86;                 /* T_sequenceOf86 */
static int hf_sgp22_sequenceOf86_item;            /* OCTET_STRING */
static int hf_sgp22_profileInstallationResultData;  /* ProfileInstallationResultData */
static int hf_sgp22_euiccSignPIR;                 /* EuiccSignPIR */
static int hf_sgp22_notificationMetadata;         /* NotificationMetadata */
static int hf_sgp22_finalResult;                  /* T_finalResult */
static int hf_sgp22_successResult;                /* SuccessResult */
static int hf_sgp22_errorResult;                  /* ErrorResult */
static int hf_sgp22_aid;                          /* OCTET_STRING_SIZE_5_16 */
static int hf_sgp22_simaResponse;                 /* OCTET_STRING */
static int hf_sgp22_bppCommandId;                 /* BppCommandId */
static int hf_sgp22_errorReason;                  /* ErrorReason */
static int hf_sgp22_notificationMetadataList;     /* SEQUENCE_OF_NotificationMetadata */
static int hf_sgp22_notificationMetadataList_item;  /* NotificationMetadata */
static int hf_sgp22_listNotificationsResultError;  /* T_listNotificationsResultError */
static int hf_sgp22_seqNumber;                    /* INTEGER */
static int hf_sgp22_setNicknameResult;            /* T_setNicknameResult */
static int hf_sgp22_activationCodeForProfileRedownload;  /* UTF8String_SIZE_0_255 */
static int hf_sgp22_activationCodeRetrievalAvailable;  /* BOOLEAN */
static int hf_sgp22_retryDelay;                   /* INTEGER */
static int hf_sgp22_remoteOpId;                   /* RemoteOpId */
static int hf_sgp22_controlRefTemplate;           /* ControlRefTemplate */
static int hf_sgp22_smdpOtpk;                     /* OCTET_STRING */
static int hf_sgp22_smdpSign;                     /* OCTET_STRING */
static int hf_sgp22_keyType;                      /* Octet1 */
static int hf_sgp22_keyLen;                       /* Octet1 */
static int hf_sgp22_hostId;                       /* OctetTo16 */
static int hf_sgp22_dpOid;                        /* OBJECT_IDENTIFIER */
static int hf_sgp22_initialMacChainingValue;      /* OCTET_STRING */
static int hf_sgp22_ppkEnc;                       /* OCTET_STRING */
static int hf_sgp22_ppkCmac;                      /* OCTET_STRING */
static int hf_sgp22_searchCriteria_01;            /* T_searchCriteria_01 */
static int hf_sgp22_notificationList;             /* SEQUENCE_OF_PendingNotification */
static int hf_sgp22_notificationList_item;        /* PendingNotification */
static int hf_sgp22_notificationsListResultError;  /* T_notificationsListResultError */
static int hf_sgp22_profileInstallationResult;    /* ProfileInstallationResult */
static int hf_sgp22_otherSignedNotification;      /* OtherSignedNotification */
static int hf_sgp22_tbsOtherNotification;         /* NotificationMetadata */
static int hf_sgp22_euiccNotificationSignature;   /* OCTET_STRING */
static int hf_sgp22_deleteNotificationStatus;     /* T_deleteNotificationStatus */
static int hf_sgp22_profileIdentifier;            /* T_profileIdentifier */
static int hf_sgp22_refreshFlag;                  /* BOOLEAN */
static int hf_sgp22_enableResult;                 /* T_enableResult */
static int hf_sgp22_profileIdentifier_01;         /* T_profileIdentifier_01 */
static int hf_sgp22_disableResult;                /* T_disableResult */
static int hf_sgp22_deleteResult;                 /* T_deleteResult */
static int hf_sgp22_resetOptions;                 /* T_resetOptions */
static int hf_sgp22_resetResult;                  /* T_resetResult */
static int hf_sgp22_tagList_01;                   /* Octet1 */
static int hf_sgp22_eidValue;                     /* Octet16 */
static int hf_sgp22_rat;                          /* RulesAuthorisationTable */
static int hf_sgp22_RulesAuthorisationTable_item;  /* ProfilePolicyAuthorisationRule */
static int hf_sgp22_pprIds;                       /* PprIds */
static int hf_sgp22_allowedOperators;             /* SEQUENCE_OF_OperatorId */
static int hf_sgp22_allowedOperators_item;        /* OperatorId */
static int hf_sgp22_pprFlags;                     /* T_pprFlags */
static int hf_sgp22_crl;                          /* CertificateList */
static int hf_sgp22_loadCRLResponseOk;            /* LoadCRLResponseOk */
static int hf_sgp22_loadCRLResponseError;         /* LoadCRLResponseError */
static int hf_sgp22_missingParts;                 /* T_missingParts */
static int hf_sgp22_missingParts_item;            /* INTEGER */
static int hf_sgp22_initiateAuthenticationRequest;  /* InitiateAuthenticationRequest */
static int hf_sgp22_authenticateClientRequest;    /* AuthenticateClientRequest */
static int hf_sgp22_getBoundProfilePackageRequest;  /* GetBoundProfilePackageRequest */
static int hf_sgp22_cancelSessionRequestEs9;      /* CancelSessionRequestEs9 */
static int hf_sgp22_handleNotification;           /* HandleNotification */
static int hf_sgp22_initiateAuthenticationResponse;  /* InitiateAuthenticationResponse */
static int hf_sgp22_authenticateClientResponseEs9;  /* AuthenticateClientResponseEs9 */
static int hf_sgp22_getBoundProfilePackageResponse;  /* GetBoundProfilePackageResponse */
static int hf_sgp22_cancelSessionResponseEs9;     /* CancelSessionResponseEs9 */
static int hf_sgp22_authenticateClientResponseEs11;  /* AuthenticateClientResponseEs11 */
static int hf_sgp22_smdpAddress;                  /* UTF8String */
static int hf_sgp22_euiccInfo1;                   /* EUICCInfo1 */
static int hf_sgp22_initiateAuthenticationOk;     /* InitiateAuthenticationOkEs9 */
static int hf_sgp22_initiateAuthenticationError;  /* T_initiateAuthenticationError */
static int hf_sgp22_authenticateServerResponse;   /* AuthenticateServerResponse */
static int hf_sgp22_useMatchingIdForAcr;          /* NULL */
static int hf_sgp22_authenticateClientOk;         /* AuthenticateClientOk */
static int hf_sgp22_authenticateClientError;      /* T_authenticateClientError */
static int hf_sgp22_profileMetaData;              /* StoreMetadataRequest */
static int hf_sgp22_prepareDownloadResponse;      /* PrepareDownloadResponse */
static int hf_sgp22_getBoundProfilePackageOk;     /* GetBoundProfilePackageOk */
static int hf_sgp22_getBoundProfilePackageError;  /* T_getBoundProfilePackageError */
static int hf_sgp22_boundProfilePackage;          /* BoundProfilePackage */
static int hf_sgp22_pendingNotification;          /* PendingNotification */
static int hf_sgp22_cancelSessionResponse;        /* CancelSessionResponse */
static int hf_sgp22_cancelSessionOk;              /* CancelSessionOk */
static int hf_sgp22_cancelSessionError;           /* T_cancelSessionError */
static int hf_sgp22_defaultDpAddress;             /* UTF8String */
static int hf_sgp22_rootDsAddress;                /* UTF8String */
static int hf_sgp22_lpaeSupport;                  /* T_lpaeSupport */
static int hf_sgp22_lpaeOption;                   /* T_lpaeOption */
static int hf_sgp22_lpaeActivationResult;         /* T_lpaeActivationResult */
static int hf_sgp22_setDefaultDpAddressResult;    /* T_setDefaultDpAddressResult */
static int hf_sgp22_authenticateClientOk_01;      /* AuthenticateClientOkEs11 */
static int hf_sgp22_authenticateClientError_01;   /* T_authenticateClientError_01 */
static int hf_sgp22_eventEntries;                 /* SEQUENCE_OF_EventEntries */
static int hf_sgp22_eventEntries_item;            /* EventEntries */
static int hf_sgp22_eventId;                      /* UTF8String */
static int hf_sgp22_rspServerAddress;             /* UTF8String */
/* named bits */
static int hf_sgp22_UICCCapability_contactlessSupport;
static int hf_sgp22_UICCCapability_usimSupport;
static int hf_sgp22_UICCCapability_isimSupport;
static int hf_sgp22_UICCCapability_csimSupport;
static int hf_sgp22_UICCCapability_akaMilenage;
static int hf_sgp22_UICCCapability_akaCave;
static int hf_sgp22_UICCCapability_akaTuak128;
static int hf_sgp22_UICCCapability_akaTuak256;
static int hf_sgp22_UICCCapability_usimTestAlgorithm;
static int hf_sgp22_UICCCapability_rfu2;
static int hf_sgp22_UICCCapability_gbaAuthenUsim;
static int hf_sgp22_UICCCapability_gbaAuthenISim;
static int hf_sgp22_UICCCapability_mbmsAuthenUsim;
static int hf_sgp22_UICCCapability_eapClient;
static int hf_sgp22_UICCCapability_javacard;
static int hf_sgp22_UICCCapability_multos;
static int hf_sgp22_UICCCapability_multipleUsimSupport;
static int hf_sgp22_UICCCapability_multipleIsimSupport;
static int hf_sgp22_UICCCapability_multipleCsimSupport;
static int hf_sgp22_UICCCapability_berTlvFileSupport;
static int hf_sgp22_UICCCapability_dfLinkSupport;
static int hf_sgp22_UICCCapability_catTp;
static int hf_sgp22_UICCCapability_getIdentity;
static int hf_sgp22_UICCCapability_profile_a_x25519;
static int hf_sgp22_UICCCapability_profile_b_p256;
static int hf_sgp22_UICCCapability_suciCalculatorApi;
static int hf_sgp22_UICCCapability_dns_resolution;
static int hf_sgp22_UICCCapability_scp11ac;
static int hf_sgp22_UICCCapability_scp11c_authorization_mechanism;
static int hf_sgp22_UICCCapability_s16mode;
static int hf_sgp22_UICCCapability_eaka;
static int hf_sgp22_UICCCapability_iotminimal;
static int hf_sgp22_T_treProperties_isDiscrete;
static int hf_sgp22_T_treProperties_isIntegrated;
static int hf_sgp22_T_treProperties_usesRemoteMemory;
static int hf_sgp22_RspCapability_additionalProfile;
static int hf_sgp22_RspCapability_crlSupport;
static int hf_sgp22_RspCapability_rpmSupport;
static int hf_sgp22_RspCapability_testProfileSupport;
static int hf_sgp22_RspCapability_deviceInfoExtensibilitySupport;
static int hf_sgp22_RspCapability_serviceSpecificDataSupport;
static int hf_sgp22_PprIds_pprUpdateControl;
static int hf_sgp22_PprIds_ppr1;
static int hf_sgp22_PprIds_ppr2;
static int hf_sgp22_NotificationEvent_notificationInstall;
static int hf_sgp22_NotificationEvent_notificationEnable;
static int hf_sgp22_NotificationEvent_notificationDisable;
static int hf_sgp22_NotificationEvent_notificationDelete;
static int hf_sgp22_T_resetOptions_deleteOperationalProfiles;
static int hf_sgp22_T_resetOptions_deleteFieldLoadedTestProfiles;
static int hf_sgp22_T_resetOptions_resetDefaultSmdpAddress;
static int hf_sgp22_T_pprFlags_consentRequired;
static int hf_sgp22_T_lpaeSupport_lpaeUsingCat;
static int hf_sgp22_T_lpaeSupport_lpaeUsingScws;
static int hf_sgp22_T_lpaeOption_activateCatBasedLpae;
static int hf_sgp22_T_lpaeOption_activateScwsBasedLpae;

static int ett_sgp22;
static int ett_sgp22_UICCCapability;
static int ett_sgp22_GetEuiccInfo1Request_U;
static int ett_sgp22_EUICCInfo1_U;
static int ett_sgp22_SEQUENCE_OF_SubjectKeyIdentifier;
static int ett_sgp22_GetEuiccInfo2Request_U;
static int ett_sgp22_EUICCInfo2_U;
static int ett_sgp22_T_treProperties;
static int ett_sgp22_SEQUENCE_OF_VersionType;
static int ett_sgp22_RspCapability;
static int ett_sgp22_CertificationDataObject;
static int ett_sgp22_DeviceInfo;
static int ett_sgp22_DeviceCapabilities;
static int ett_sgp22_DeviceAdditionalFeatureSupport;
static int ett_sgp22_ProfileInfoListRequest_U;
static int ett_sgp22_T_searchCriteria;
static int ett_sgp22_ProfileInfoListResponse_U;
static int ett_sgp22_SEQUENCE_OF_ProfileInfo;
static int ett_sgp22_ProfileInfo_U;
static int ett_sgp22_SEQUENCE_OF_NotificationConfigurationInformation;
static int ett_sgp22_PprIds;
static int ett_sgp22_OperatorId;
static int ett_sgp22_StoreMetadataRequest_U;
static int ett_sgp22_NotificationEvent;
static int ett_sgp22_NotificationConfigurationInformation;
static int ett_sgp22_VendorSpecificExtension;
static int ett_sgp22_VendorSpecificExtension_item;
static int ett_sgp22_UpdateMetadataRequest_U;
static int ett_sgp22_PrepareDownloadRequest_U;
static int ett_sgp22_SmdpSigned2;
static int ett_sgp22_PrepareDownloadResponse_U;
static int ett_sgp22_PrepareDownloadResponseOk;
static int ett_sgp22_EUICCSigned2;
static int ett_sgp22_PrepareDownloadResponseError;
static int ett_sgp22_AuthenticateServerRequest_U;
static int ett_sgp22_ServerSigned1;
static int ett_sgp22_CtxParams1;
static int ett_sgp22_CtxParamsForCommonAuthentication;
static int ett_sgp22_AuthenticateServerResponse_U;
static int ett_sgp22_AuthenticateResponseOk;
static int ett_sgp22_EuiccSigned1;
static int ett_sgp22_AuthenticateResponseError;
static int ett_sgp22_CancelSessionRequest_U;
static int ett_sgp22_CancelSessionResponse_U;
static int ett_sgp22_CancelSessionResponseOk;
static int ett_sgp22_EuiccCancelSessionSigned;
static int ett_sgp22_BoundProfilePackage_U;
static int ett_sgp22_T_firstSequenceOf87;
static int ett_sgp22_T_sequenceOf88;
static int ett_sgp22_T_secondSequenceOf87;
static int ett_sgp22_T_sequenceOf86;
static int ett_sgp22_GetEuiccChallengeRequest_U;
static int ett_sgp22_GetEuiccChallengeResponse_U;
static int ett_sgp22_ProfileInstallationResult_U;
static int ett_sgp22_ProfileInstallationResultData_U;
static int ett_sgp22_T_finalResult;
static int ett_sgp22_SuccessResult;
static int ett_sgp22_ErrorResult;
static int ett_sgp22_ListNotificationRequest_U;
static int ett_sgp22_ListNotificationResponse_U;
static int ett_sgp22_SEQUENCE_OF_NotificationMetadata;
static int ett_sgp22_NotificationMetadata_U;
static int ett_sgp22_SetNicknameRequest_U;
static int ett_sgp22_SetNicknameResponse_U;
static int ett_sgp22_ActivationCodeRetrievalInfo;
static int ett_sgp22_InitialiseSecureChannelRequest_U;
static int ett_sgp22_ControlRefTemplate;
static int ett_sgp22_ConfigureISDPRequest_U;
static int ett_sgp22_DpProprietaryData;
static int ett_sgp22_ReplaceSessionKeysRequest_U;
static int ett_sgp22_RetrieveNotificationsListRequest_U;
static int ett_sgp22_T_searchCriteria_01;
static int ett_sgp22_RetrieveNotificationsListResponse_U;
static int ett_sgp22_SEQUENCE_OF_PendingNotification;
static int ett_sgp22_PendingNotification;
static int ett_sgp22_OtherSignedNotification;
static int ett_sgp22_NotificationSentRequest_U;
static int ett_sgp22_NotificationSentResponse_U;
static int ett_sgp22_EnableProfileRequest_U;
static int ett_sgp22_T_profileIdentifier;
static int ett_sgp22_EnableProfileResponse_U;
static int ett_sgp22_DisableProfileRequest_U;
static int ett_sgp22_T_profileIdentifier_01;
static int ett_sgp22_DisableProfileResponse_U;
static int ett_sgp22_DeleteProfileRequest_U;
static int ett_sgp22_DeleteProfileResponse_U;
static int ett_sgp22_EuiccMemoryResetRequest_U;
static int ett_sgp22_T_resetOptions;
static int ett_sgp22_EuiccMemoryResetResponse_U;
static int ett_sgp22_GetEuiccDataRequest_U;
static int ett_sgp22_GetEuiccDataResponse_U;
static int ett_sgp22_GetRatRequest_U;
static int ett_sgp22_GetRatResponse_U;
static int ett_sgp22_RulesAuthorisationTable;
static int ett_sgp22_ProfilePolicyAuthorisationRule;
static int ett_sgp22_SEQUENCE_OF_OperatorId;
static int ett_sgp22_T_pprFlags;
static int ett_sgp22_LoadCRLRequest_U;
static int ett_sgp22_LoadCRLResponse_U;
static int ett_sgp22_LoadCRLResponseOk;
static int ett_sgp22_T_missingParts;
static int ett_sgp22_RemoteProfileProvisioningRequest_U;
static int ett_sgp22_RemoteProfileProvisioningResponse_U;
static int ett_sgp22_InitiateAuthenticationRequest_U;
static int ett_sgp22_InitiateAuthenticationResponse_U;
static int ett_sgp22_InitiateAuthenticationOkEs9;
static int ett_sgp22_AuthenticateClientRequest_U;
static int ett_sgp22_AuthenticateClientResponseEs9_U;
static int ett_sgp22_AuthenticateClientOk;
static int ett_sgp22_GetBoundProfilePackageRequest_U;
static int ett_sgp22_GetBoundProfilePackageResponse_U;
static int ett_sgp22_GetBoundProfilePackageOk;
static int ett_sgp22_HandleNotification_U;
static int ett_sgp22_CancelSessionRequestEs9_U;
static int ett_sgp22_CancelSessionResponseEs9_U;
static int ett_sgp22_CancelSessionOk;
static int ett_sgp22_EuiccConfiguredAddressesRequest_U;
static int ett_sgp22_EuiccConfiguredAddressesResponse_U;
static int ett_sgp22_ISDRProprietaryApplicationTemplate_U;
static int ett_sgp22_T_lpaeSupport;
static int ett_sgp22_LpaeActivationRequest_U;
static int ett_sgp22_T_lpaeOption;
static int ett_sgp22_LpaeActivationResponse_U;
static int ett_sgp22_SetDefaultDpAddressRequest_U;
static int ett_sgp22_SetDefaultDpAddressResponse_U;
static int ett_sgp22_AuthenticateClientResponseEs11_U;
static int ett_sgp22_AuthenticateClientOkEs11;
static int ett_sgp22_SEQUENCE_OF_EventEntries;
static int ett_sgp22_EventEntries;


static int * const UICCCapability_bits[] = {
  &hf_sgp22_UICCCapability_contactlessSupport,
  &hf_sgp22_UICCCapability_usimSupport,
  &hf_sgp22_UICCCapability_isimSupport,
  &hf_sgp22_UICCCapability_csimSupport,
  &hf_sgp22_UICCCapability_akaMilenage,
  &hf_sgp22_UICCCapability_akaCave,
  &hf_sgp22_UICCCapability_akaTuak128,
  &hf_sgp22_UICCCapability_akaTuak256,
  &hf_sgp22_UICCCapability_usimTestAlgorithm,
  &hf_sgp22_UICCCapability_rfu2,
  &hf_sgp22_UICCCapability_gbaAuthenUsim,
  &hf_sgp22_UICCCapability_gbaAuthenISim,
  &hf_sgp22_UICCCapability_mbmsAuthenUsim,
  &hf_sgp22_UICCCapability_eapClient,
  &hf_sgp22_UICCCapability_javacard,
  &hf_sgp22_UICCCapability_multos,
  &hf_sgp22_UICCCapability_multipleUsimSupport,
  &hf_sgp22_UICCCapability_multipleIsimSupport,
  &hf_sgp22_UICCCapability_multipleCsimSupport,
  &hf_sgp22_UICCCapability_berTlvFileSupport,
  &hf_sgp22_UICCCapability_dfLinkSupport,
  &hf_sgp22_UICCCapability_catTp,
  &hf_sgp22_UICCCapability_getIdentity,
  &hf_sgp22_UICCCapability_profile_a_x25519,
  &hf_sgp22_UICCCapability_profile_b_p256,
  &hf_sgp22_UICCCapability_suciCalculatorApi,
  &hf_sgp22_UICCCapability_dns_resolution,
  &hf_sgp22_UICCCapability_scp11ac,
  &hf_sgp22_UICCCapability_scp11c_authorization_mechanism,
  &hf_sgp22_UICCCapability_s16mode,
  &hf_sgp22_UICCCapability_eaka,
  &hf_sgp22_UICCCapability_iotminimal,
  NULL
};

int
dissect_sgp22_UICCCapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    UICCCapability_bits, 32, hf_index, ett_sgp22_UICCCapability,
                                    NULL);

  return offset;
}



static int
dissect_sgp22_Octet8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   8, 8, hf_index, NULL);

  return offset;
}



static int
dissect_sgp22_Octet4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   4, 4, hf_index, NULL);

  return offset;
}



int
dissect_sgp22_Octet16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   16, 16, hf_index, NULL);

  return offset;
}



int
dissect_sgp22_OctetTo16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 16, hf_index, NULL);

  return offset;
}



int
dissect_sgp22_Octet32(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   32, 32, hf_index, NULL);

  return offset;
}



int
dissect_sgp22_Octet1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 1, hf_index, NULL);

  return offset;
}



int
dissect_sgp22_VersionType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *next_tvb = NULL;

  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   3, 3, -1, &next_tvb);

  if (next_tvb) {
    wmem_strbuf_t *version_str = wmem_strbuf_create(NULL);
    for (unsigned i = 0; i < 3; i++) {
      uint8_t value = tvb_get_uint8(next_tvb, i);
      if (i < (3 - 1) || value > 0) {
        /* Do not show last value if this is 0, according to spec */
        wmem_strbuf_append_printf(version_str, "%c%u", (i == 0 ? 'v' : '.'), value);
      }
    }
    actx->created_item = proto_tree_add_string(tree, hf_index, next_tvb, 0, -1, wmem_strbuf_finalize(version_str));
  }


  return offset;
}



static int
dissect_sgp22_Iccid_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *next_tvb = NULL;

  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   10, 10, -1, &next_tvb);

  if (next_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, next_tvb, 0, -1, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);
  }


  return offset;
}



int
dissect_sgp22_Iccid(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 26, true, dissect_sgp22_Iccid_U);

  return offset;
}


static const value_string sgp22_RemoteOpId_U_vals[] = {
  {   1, "installBoundProfilePackage" },
  { 0, NULL }
};


static int
dissect_sgp22_RemoteOpId_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_sgp22_RemoteOpId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 2, true, dissect_sgp22_RemoteOpId_U);

  return offset;
}



int
dissect_sgp22_TransactionId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 16, hf_index, NULL);

  return offset;
}


static const ber_sequence_t GetEuiccInfo1Request_U_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetEuiccInfo1Request_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEuiccInfo1Request_U_sequence, hf_index, ett_sgp22_GetEuiccInfo1Request_U);

  return offset;
}



static int
dissect_sgp22_GetEuiccInfo1Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 32, true, dissect_sgp22_GetEuiccInfo1Request_U);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SubjectKeyIdentifier_sequence_of[1] = {
  { &hf_sgp22_euiccCiPKIdListForVerification_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_SubjectKeyIdentifier },
};

static int
dissect_sgp22_SEQUENCE_OF_SubjectKeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SubjectKeyIdentifier_sequence_of, hf_index, ett_sgp22_SEQUENCE_OF_SubjectKeyIdentifier);

  return offset;
}


static const ber_sequence_t EUICCInfo1_U_sequence[] = {
  { &hf_sgp22_svn           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_euiccCiPKIdListForVerification, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_SubjectKeyIdentifier },
  { &hf_sgp22_euiccCiPKIdListForSigning, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_SubjectKeyIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EUICCInfo1_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EUICCInfo1_U_sequence, hf_index, ett_sgp22_EUICCInfo1_U);

  return offset;
}



int
dissect_sgp22_EUICCInfo1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 32, true, dissect_sgp22_EUICCInfo1_U);

  return offset;
}


static const ber_sequence_t GetEuiccInfo2Request_U_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetEuiccInfo2Request_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEuiccInfo2Request_U_sequence, hf_index, ett_sgp22_GetEuiccInfo2Request_U);

  return offset;
}



static int
dissect_sgp22_GetEuiccInfo2Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 34, true, dissect_sgp22_GetEuiccInfo2Request_U);

  return offset;
}



static int
dissect_sgp22_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static int * const RspCapability_bits[] = {
  &hf_sgp22_RspCapability_additionalProfile,
  &hf_sgp22_RspCapability_crlSupport,
  &hf_sgp22_RspCapability_rpmSupport,
  &hf_sgp22_RspCapability_testProfileSupport,
  &hf_sgp22_RspCapability_deviceInfoExtensibilitySupport,
  &hf_sgp22_RspCapability_serviceSpecificDataSupport,
  NULL
};

int
dissect_sgp22_RspCapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    RspCapability_bits, 6, hf_index, ett_sgp22_RspCapability,
                                    NULL);

  return offset;
}


static const value_string sgp22_T_euiccCategory_vals[] = {
  {   0, "other" },
  {   1, "basicEuicc" },
  {   2, "mediumEuicc" },
  {   3, "contactlessEuicc" },
  { 0, NULL }
};


static int
dissect_sgp22_T_euiccCategory(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static int * const PprIds_bits[] = {
  &hf_sgp22_PprIds_pprUpdateControl,
  &hf_sgp22_PprIds_ppr1,
  &hf_sgp22_PprIds_ppr2,
  NULL
};

int
dissect_sgp22_PprIds(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    PprIds_bits, 3, hf_index, ett_sgp22_PprIds,
                                    NULL);

  return offset;
}



static int
dissect_sgp22_UTF8String_SIZE_0_64(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        0, 64, hf_index, NULL);

  return offset;
}



static int
dissect_sgp22_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t CertificationDataObject_sequence[] = {
  { &hf_sgp22_platformLabel , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_discoveryBaseURL, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_CertificationDataObject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificationDataObject_sequence, hf_index, ett_sgp22_CertificationDataObject);

  return offset;
}


static int * const T_treProperties_bits[] = {
  &hf_sgp22_T_treProperties_isDiscrete,
  &hf_sgp22_T_treProperties_isIntegrated,
  &hf_sgp22_T_treProperties_usesRemoteMemory,
  NULL
};

static int
dissect_sgp22_T_treProperties(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_treProperties_bits, 3, hf_index, ett_sgp22_T_treProperties,
                                    NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_VersionType_sequence_of[1] = {
  { &hf_sgp22_additionalEuiccProfilePackageVersions_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgp22_VersionType },
};

static int
dissect_sgp22_SEQUENCE_OF_VersionType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_VersionType_sequence_of, hf_index, ett_sgp22_SEQUENCE_OF_VersionType);

  return offset;
}


static const ber_sequence_t EUICCInfo2_U_sequence[] = {
  { &hf_sgp22_profileVersion, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_svn           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_euiccFirmwareVer, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_extCardResource, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_uiccCapability, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_sgp22_UICCCapability },
  { &hf_sgp22_ts102241Version, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_globalplatformVersion, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_rspCapability , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_sgp22_RspCapability },
  { &hf_sgp22_euiccCiPKIdListForVerification, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_SubjectKeyIdentifier },
  { &hf_sgp22_euiccCiPKIdListForSigning, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_SubjectKeyIdentifier },
  { &hf_sgp22_euiccCategory , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_T_euiccCategory },
  { &hf_sgp22_forbiddenProfilePolicyRules, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_PprIds },
  { &hf_sgp22_ppVersion     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_sasAcreditationNumber, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_sgp22_UTF8String_SIZE_0_64 },
  { &hf_sgp22_certificationDataObject, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_CertificationDataObject },
  { &hf_sgp22_treProperties , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_T_treProperties },
  { &hf_sgp22_treProductReference, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_additionalEuiccProfilePackageVersions, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_VersionType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EUICCInfo2_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EUICCInfo2_U_sequence, hf_index, ett_sgp22_EUICCInfo2_U);

  return offset;
}



static int
dissect_sgp22_EUICCInfo2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 34, true, dissect_sgp22_EUICCInfo2_U);

  return offset;
}



static int
dissect_sgp22_CatSupportedClasses(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_sgp22_EuiccFormFactorType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_sgp22_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t DeviceAdditionalFeatureSupport_sequence[] = {
  { &hf_sgp22_naiSupport    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_groupOfDeviceManufacturerOid, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OBJECT_IDENTIFIER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_DeviceAdditionalFeatureSupport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeviceAdditionalFeatureSupport_sequence, hf_index, ett_sgp22_DeviceAdditionalFeatureSupport);

  return offset;
}


static const ber_sequence_t DeviceCapabilities_sequence[] = {
  { &hf_sgp22_gsmSupportedRelease, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_utranSupportedRelease, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_cdma2000onexSupportedRelease, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_cdma2000hrpdSupportedRelease, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_cdma2000ehrpdSupportedRelease, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_eutranEpcSupportedRelease, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_contactlessSupportedRelease, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_rspCrlSupportedVersion, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_nrEpcSupportedRelease, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_nr5gcSupportedRelease, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_eutran5gcSupportedRelease, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_lpaSvn        , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_catSupportedClasses, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_CatSupportedClasses },
  { &hf_sgp22_euiccFormFactorType, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_EuiccFormFactorType },
  { &hf_sgp22_deviceAdditionalFeatureSupport, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_DeviceAdditionalFeatureSupport },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_DeviceCapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeviceCapabilities_sequence, hf_index, ett_sgp22_DeviceCapabilities);

  return offset;
}


static const ber_sequence_t DeviceInfo_sequence[] = {
  { &hf_sgp22_tac           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet4 },
  { &hf_sgp22_deviceCapabilities, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_DeviceCapabilities },
  { &hf_sgp22_imei          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_Octet8 },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_DeviceInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeviceInfo_sequence, hf_index, ett_sgp22_DeviceInfo);

  return offset;
}


const value_string sgp22_ProfileClass_vals[] = {
  {   0, "test" },
  {   1, "provisioning" },
  {   2, "operational" },
  { 0, NULL }
};


int
dissect_sgp22_ProfileClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_T_searchCriteria_vals[] = {
  {   0, "isdpAid" },
  {   1, "iccid" },
  {   2, "profileClass" },
  { 0, NULL }
};

static const ber_choice_t T_searchCriteria_choice[] = {
  {   0, &hf_sgp22_isdpAid       , BER_CLASS_APP, 15, BER_FLAGS_IMPLTAG, dissect_sgp22_OctetTo16 },
  {   1, &hf_sgp22_iccid         , BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  {   2, &hf_sgp22_profileClass  , BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileClass },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_T_searchCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_searchCriteria_choice, hf_index, ett_sgp22_T_searchCriteria,
                                 NULL);

  return offset;
}


static const ber_sequence_t ProfileInfoListRequest_U_sequence[] = {
  { &hf_sgp22_searchCriteria, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_T_searchCriteria },
  { &hf_sgp22_tagList       , BER_CLASS_APP, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ProfileInfoListRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileInfoListRequest_U_sequence, hf_index, ett_sgp22_ProfileInfoListRequest_U);

  return offset;
}



int
dissect_sgp22_ProfileInfoListRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 45, true, dissect_sgp22_ProfileInfoListRequest_U);

  return offset;
}


const value_string sgp22_ProfileState_vals[] = {
  {   0, "disabled" },
  {   1, "enabled" },
  { 0, NULL }
};


int
dissect_sgp22_ProfileState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_sgp22_UTF8String_SIZE_0_32(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        0, 32, hf_index, NULL);

  return offset;
}


const value_string sgp22_IconType_vals[] = {
  {   0, "jpg" },
  {   1, "png" },
  { 0, NULL }
};


int
dissect_sgp22_IconType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_sgp22_OCTET_STRING_SIZE_0_1024(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   0, 1024, hf_index, NULL);

  return offset;
}


static int * const NotificationEvent_bits[] = {
  &hf_sgp22_NotificationEvent_notificationInstall,
  &hf_sgp22_NotificationEvent_notificationEnable,
  &hf_sgp22_NotificationEvent_notificationDisable,
  &hf_sgp22_NotificationEvent_notificationDelete,
  NULL
};

int
dissect_sgp22_NotificationEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NotificationEvent_bits, 4, hf_index, ett_sgp22_NotificationEvent,
                                    NULL);

  return offset;
}


static const ber_sequence_t NotificationConfigurationInformation_sequence[] = {
  { &hf_sgp22_profileManagementOperation, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_NotificationEvent },
  { &hf_sgp22_notificationAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_NotificationConfigurationInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NotificationConfigurationInformation_sequence, hf_index, ett_sgp22_NotificationConfigurationInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_NotificationConfigurationInformation_sequence_of[1] = {
  { &hf_sgp22_notificationConfigurationInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_NotificationConfigurationInformation },
};

static int
dissect_sgp22_SEQUENCE_OF_NotificationConfigurationInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_NotificationConfigurationInformation_sequence_of, hf_index, ett_sgp22_SEQUENCE_OF_NotificationConfigurationInformation);

  return offset;
}



static int
dissect_sgp22_OCTET_STRING_SIZE_3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   3, 3, hf_index, NULL);

  return offset;
}


static const ber_sequence_t OperatorId_sequence[] = {
  { &hf_sgp22_mccMnc        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING_SIZE_3 },
  { &hf_sgp22_gid1          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_gid2          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_OperatorId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OperatorId_sequence, hf_index, ett_sgp22_OperatorId);

  return offset;
}


static const ber_sequence_t DpProprietaryData_sequence[] = {
  { &hf_sgp22_dpOid         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_OBJECT_IDENTIFIER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_DpProprietaryData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DpProprietaryData_sequence, hf_index, ett_sgp22_DpProprietaryData);

  return offset;
}



static int
dissect_sgp22_T_vendorOid(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_sgp22_vendorOid, &actx->external.direct_reference);

  return offset;
}



static int
dissect_sgp22_T_vendorSpecificData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t VendorSpecificExtension_item_sequence[] = {
  { &hf_sgp22_vendorOid     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_vendorOid },
  { &hf_sgp22_vendorSpecificData, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_vendorSpecificData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_VendorSpecificExtension_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   VendorSpecificExtension_item_sequence, hf_index, ett_sgp22_VendorSpecificExtension_item);

  return offset;
}


static const ber_sequence_t VendorSpecificExtension_sequence_of[1] = {
  { &hf_sgp22_VendorSpecificExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_VendorSpecificExtension_item },
};

int
dissect_sgp22_VendorSpecificExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      VendorSpecificExtension_sequence_of, hf_index, ett_sgp22_VendorSpecificExtension);

  return offset;
}


static const ber_sequence_t ProfileInfo_U_sequence[] = {
  { &hf_sgp22_iccid         , BER_CLASS_APP, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { &hf_sgp22_isdpAid       , BER_CLASS_APP, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OctetTo16 },
  { &hf_sgp22_profileState  , BER_CLASS_CON, 112, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileState },
  { &hf_sgp22_profileNickname, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_64 },
  { &hf_sgp22_serviceProviderName, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_32 },
  { &hf_sgp22_profileName   , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_64 },
  { &hf_sgp22_iconType      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_IconType },
  { &hf_sgp22_icon          , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING_SIZE_0_1024 },
  { &hf_sgp22_profileClass  , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileClass },
  { &hf_sgp22_notificationConfigurationInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_NotificationConfigurationInformation },
  { &hf_sgp22_profileOwner  , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OperatorId },
  { &hf_sgp22_dpProprietaryData, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_DpProprietaryData },
  { &hf_sgp22_profilePolicyRules, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_PprIds },
  { &hf_sgp22_serviceSpecificDataStoredInEuicc, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VendorSpecificExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ProfileInfo_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileInfo_U_sequence, hf_index, ett_sgp22_ProfileInfo_U);

  return offset;
}



static int
dissect_sgp22_ProfileInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 3, true, dissect_sgp22_ProfileInfo_U);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ProfileInfo_sequence_of[1] = {
  { &hf_sgp22_profileInfoListOk_item, BER_CLASS_PRI, 3, BER_FLAGS_NOOWNTAG, dissect_sgp22_ProfileInfo },
};

static int
dissect_sgp22_SEQUENCE_OF_ProfileInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ProfileInfo_sequence_of, hf_index, ett_sgp22_SEQUENCE_OF_ProfileInfo);

  return offset;
}


static const value_string sgp22_ProfileInfoListError_vals[] = {
  {   1, "incorrectInputValues" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_ProfileInfoListError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_ProfileInfoListResponse_U_vals[] = {
  {   0, "profileInfoListOk" },
  {   1, "profileInfoListError" },
  { 0, NULL }
};

static const ber_choice_t ProfileInfoListResponse_U_choice[] = {
  {   0, &hf_sgp22_profileInfoListOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_ProfileInfo },
  {   1, &hf_sgp22_profileInfoListError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileInfoListError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ProfileInfoListResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProfileInfoListResponse_U_choice, hf_index, ett_sgp22_ProfileInfoListResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_ProfileInfoListResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 45, true, dissect_sgp22_ProfileInfoListResponse_U);

  return offset;
}


static const ber_sequence_t StoreMetadataRequest_U_sequence[] = {
  { &hf_sgp22_iccid         , BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { &hf_sgp22_serviceProviderName, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_32 },
  { &hf_sgp22_profileName   , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_64 },
  { &hf_sgp22_iconType      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_IconType },
  { &hf_sgp22_icon          , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING_SIZE_0_1024 },
  { &hf_sgp22_profileClass  , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileClass },
  { &hf_sgp22_notificationConfigurationInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_NotificationConfigurationInformation },
  { &hf_sgp22_profileOwner  , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OperatorId },
  { &hf_sgp22_profilePolicyRules, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_PprIds },
  { &hf_sgp22_serviceSpecificDataStoredInEuicc, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VendorSpecificExtension },
  { &hf_sgp22_serviceSpecificDataNotStoredInEuicc, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VendorSpecificExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_StoreMetadataRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StoreMetadataRequest_U_sequence, hf_index, ett_sgp22_StoreMetadataRequest_U);

  return offset;
}



static int
dissect_sgp22_StoreMetadataRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 37, true, dissect_sgp22_StoreMetadataRequest_U);

  return offset;
}


static const ber_sequence_t UpdateMetadataRequest_U_sequence[] = {
  { &hf_sgp22_serviceProviderName, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_32 },
  { &hf_sgp22_profileName   , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_64 },
  { &hf_sgp22_iconType      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_IconType },
  { &hf_sgp22_icon          , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING_SIZE_0_1024 },
  { &hf_sgp22_profilePolicyRules, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_PprIds },
  { &hf_sgp22_serviceSpecificDataStoredInEuicc, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VendorSpecificExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_UpdateMetadataRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateMetadataRequest_U_sequence, hf_index, ett_sgp22_UpdateMetadataRequest_U);

  return offset;
}



static int
dissect_sgp22_UpdateMetadataRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 42, true, dissect_sgp22_UpdateMetadataRequest_U);

  return offset;
}



static int
dissect_sgp22_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SmdpSigned2_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_ccRequiredFlag, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_sgp22_BOOLEAN },
  { &hf_sgp22_bppEuiccOtpk  , BER_CLASS_APP, 73, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_SmdpSigned2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SmdpSigned2_sequence, hf_index, ett_sgp22_SmdpSigned2);

  return offset;
}


static const ber_sequence_t PrepareDownloadRequest_U_sequence[] = {
  { &hf_sgp22_smdpSigned2   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_SmdpSigned2 },
  { &hf_sgp22_smdpSignature2, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_hashCc        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_Octet32 },
  { &hf_sgp22_smdpCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_PrepareDownloadRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrepareDownloadRequest_U_sequence, hf_index, ett_sgp22_PrepareDownloadRequest_U);

  return offset;
}



static int
dissect_sgp22_PrepareDownloadRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 33, true, dissect_sgp22_PrepareDownloadRequest_U);

  return offset;
}


static const ber_sequence_t EUICCSigned2_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_euiccOtpk     , BER_CLASS_APP, 73, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_hashCc        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_Octet32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EUICCSigned2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EUICCSigned2_sequence, hf_index, ett_sgp22_EUICCSigned2);

  return offset;
}


static const ber_sequence_t PrepareDownloadResponseOk_sequence[] = {
  { &hf_sgp22_euiccSigned2  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_EUICCSigned2 },
  { &hf_sgp22_euiccSignature2, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_PrepareDownloadResponseOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrepareDownloadResponseOk_sequence, hf_index, ett_sgp22_PrepareDownloadResponseOk);

  return offset;
}


static const value_string sgp22_DownloadErrorCode_vals[] = {
  {   1, "invalidCertificate" },
  {   2, "invalidSignature" },
  {   3, "unsupportedCurve" },
  {   4, "noSessionContext" },
  {   5, "invalidTransactionId" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_DownloadErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PrepareDownloadResponseError_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_downloadErrorCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp22_DownloadErrorCode },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_PrepareDownloadResponseError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrepareDownloadResponseError_sequence, hf_index, ett_sgp22_PrepareDownloadResponseError);

  return offset;
}


static const value_string sgp22_PrepareDownloadResponse_U_vals[] = {
  {   0, "downloadResponseOk" },
  {   1, "downloadResponseError" },
  { 0, NULL }
};

static const ber_choice_t PrepareDownloadResponse_U_choice[] = {
  {   0, &hf_sgp22_downloadResponseOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_PrepareDownloadResponseOk },
  {   1, &hf_sgp22_downloadResponseError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_PrepareDownloadResponseError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_PrepareDownloadResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PrepareDownloadResponse_U_choice, hf_index, ett_sgp22_PrepareDownloadResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_PrepareDownloadResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 33, true, dissect_sgp22_PrepareDownloadResponse_U);

  return offset;
}


static const ber_sequence_t ServerSigned1_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_euiccChallenge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp22_serverAddress , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_serverChallenge, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_ServerSigned1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServerSigned1_sequence, hf_index, ett_sgp22_ServerSigned1);

  return offset;
}


static const ber_sequence_t CtxParamsForCommonAuthentication_sequence[] = {
  { &hf_sgp22_matchingId    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_deviceInfo    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_DeviceInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_CtxParamsForCommonAuthentication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CtxParamsForCommonAuthentication_sequence, hf_index, ett_sgp22_CtxParamsForCommonAuthentication);

  return offset;
}


const value_string sgp22_CtxParams1_vals[] = {
  {   0, "ctxParamsForCommonAuthentication" },
  { 0, NULL }
};

static const ber_choice_t CtxParams1_choice[] = {
  {   0, &hf_sgp22_ctxParamsForCommonAuthentication, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_CtxParamsForCommonAuthentication },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_CtxParams1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CtxParams1_choice, hf_index, ett_sgp22_CtxParams1,
                                 NULL);

  return offset;
}


static const ber_sequence_t AuthenticateServerRequest_U_sequence[] = {
  { &hf_sgp22_serverSigned1 , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_ServerSigned1 },
  { &hf_sgp22_serverSignature1, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_euiccCiPKIdToBeUsed, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_SubjectKeyIdentifier },
  { &hf_sgp22_serverCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp22_ctxParams1    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp22_CtxParams1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_AuthenticateServerRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateServerRequest_U_sequence, hf_index, ett_sgp22_AuthenticateServerRequest_U);

  return offset;
}



static int
dissect_sgp22_AuthenticateServerRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 56, true, dissect_sgp22_AuthenticateServerRequest_U);

  return offset;
}


static const ber_sequence_t EuiccSigned1_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_serverAddress , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_serverChallenge, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp22_euiccInfo2    , BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_sgp22_EUICCInfo2 },
  { &hf_sgp22_ctxParams1    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp22_CtxParams1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EuiccSigned1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccSigned1_sequence, hf_index, ett_sgp22_EuiccSigned1);

  return offset;
}


static const ber_sequence_t AuthenticateResponseOk_sequence[] = {
  { &hf_sgp22_euiccSigned1  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_EuiccSigned1 },
  { &hf_sgp22_euiccSignature1, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_euiccCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp22_eumCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_AuthenticateResponseOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateResponseOk_sequence, hf_index, ett_sgp22_AuthenticateResponseOk);

  return offset;
}


static const value_string sgp22_AuthenticateErrorCode_vals[] = {
  {   1, "invalidCertificate" },
  {   2, "invalidSignature" },
  {   3, "unsupportedCurve" },
  {   4, "noSessionContext" },
  {   5, "invalidOid" },
  {   6, "euiccChallengeMismatch" },
  {   7, "ciPKUnknown" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_AuthenticateErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AuthenticateResponseError_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_authenticateErrorCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp22_AuthenticateErrorCode },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_AuthenticateResponseError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateResponseError_sequence, hf_index, ett_sgp22_AuthenticateResponseError);

  return offset;
}


static const value_string sgp22_AuthenticateServerResponse_U_vals[] = {
  {   0, "authenticateResponseOk" },
  {   1, "authenticateResponseError" },
  { 0, NULL }
};

static const ber_choice_t AuthenticateServerResponse_U_choice[] = {
  {   0, &hf_sgp22_authenticateResponseOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateResponseOk },
  {   1, &hf_sgp22_authenticateResponseError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateResponseError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_AuthenticateServerResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticateServerResponse_U_choice, hf_index, ett_sgp22_AuthenticateServerResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_AuthenticateServerResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 56, true, dissect_sgp22_AuthenticateServerResponse_U);

  return offset;
}


const value_string sgp22_CancelSessionReason_vals[] = {
  {   0, "endUserRejection" },
  {   1, "postponed" },
  {   2, "timeout" },
  {   3, "pprNotAllowed" },
  {   4, "metadataMismatch" },
  {   5, "loadBppExecutionError" },
  { 127, "undefinedReason" },
  { 0, NULL }
};


int
dissect_sgp22_CancelSessionReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CancelSessionRequest_U_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_reason        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_CancelSessionRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelSessionRequest_U_sequence, hf_index, ett_sgp22_CancelSessionRequest_U);

  return offset;
}



static int
dissect_sgp22_CancelSessionRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 65, true, dissect_sgp22_CancelSessionRequest_U);

  return offset;
}


static const ber_sequence_t EuiccCancelSessionSigned_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_smdpOid       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_OBJECT_IDENTIFIER },
  { &hf_sgp22_reason        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EuiccCancelSessionSigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccCancelSessionSigned_sequence, hf_index, ett_sgp22_EuiccCancelSessionSigned);

  return offset;
}


static const ber_sequence_t CancelSessionResponseOk_sequence[] = {
  { &hf_sgp22_euiccCancelSessionSigned, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_EuiccCancelSessionSigned },
  { &hf_sgp22_euiccCancelSessionSignature, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_CancelSessionResponseOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelSessionResponseOk_sequence, hf_index, ett_sgp22_CancelSessionResponseOk);

  return offset;
}


static const value_string sgp22_T_cancelSessionResponseError_vals[] = {
  {   5, "invalidTransactionId" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_cancelSessionResponseError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_CancelSessionResponse_U_vals[] = {
  {   0, "cancelSessionResponseOk" },
  {   1, "cancelSessionResponseError" },
  { 0, NULL }
};

static const ber_choice_t CancelSessionResponse_U_choice[] = {
  {   0, &hf_sgp22_cancelSessionResponseOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionResponseOk },
  {   1, &hf_sgp22_cancelSessionResponseError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_cancelSessionResponseError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_CancelSessionResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CancelSessionResponse_U_choice, hf_index, ett_sgp22_CancelSessionResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_CancelSessionResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 65, true, dissect_sgp22_CancelSessionResponse_U);

  return offset;
}


static const ber_sequence_t ControlRefTemplate_sequence[] = {
  { &hf_sgp22_keyType       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet1 },
  { &hf_sgp22_keyLen        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet1 },
  { &hf_sgp22_hostId        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp22_OctetTo16 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ControlRefTemplate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ControlRefTemplate_sequence, hf_index, ett_sgp22_ControlRefTemplate);

  return offset;
}


static const ber_sequence_t InitialiseSecureChannelRequest_U_sequence[] = {
  { &hf_sgp22_remoteOpId    , BER_CLASS_CON, 2, BER_FLAGS_NOOWNTAG, dissect_sgp22_RemoteOpId },
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_controlRefTemplate, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_sgp22_ControlRefTemplate },
  { &hf_sgp22_smdpOtpk      , BER_CLASS_APP, 73, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_smdpSign      , BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_InitialiseSecureChannelRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitialiseSecureChannelRequest_U_sequence, hf_index, ett_sgp22_InitialiseSecureChannelRequest_U);

  return offset;
}



static int
dissect_sgp22_InitialiseSecureChannelRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 35, true, dissect_sgp22_InitialiseSecureChannelRequest_U);

  return offset;
}


static const ber_sequence_t T_firstSequenceOf87_sequence_of[1] = {
  { &hf_sgp22_firstSequenceOf87_item, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
};

static int
dissect_sgp22_T_firstSequenceOf87(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_firstSequenceOf87_sequence_of, hf_index, ett_sgp22_T_firstSequenceOf87);

  return offset;
}


static const ber_sequence_t T_sequenceOf88_sequence_of[1] = {
  { &hf_sgp22_sequenceOf88_item, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
};

static int
dissect_sgp22_T_sequenceOf88(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_sequenceOf88_sequence_of, hf_index, ett_sgp22_T_sequenceOf88);

  return offset;
}


static const ber_sequence_t T_secondSequenceOf87_sequence_of[1] = {
  { &hf_sgp22_secondSequenceOf87_item, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
};

static int
dissect_sgp22_T_secondSequenceOf87(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_secondSequenceOf87_sequence_of, hf_index, ett_sgp22_T_secondSequenceOf87);

  return offset;
}


static const ber_sequence_t T_sequenceOf86_sequence_of[1] = {
  { &hf_sgp22_sequenceOf86_item, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
};

static int
dissect_sgp22_T_sequenceOf86(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_sequenceOf86_sequence_of, hf_index, ett_sgp22_T_sequenceOf86);

  return offset;
}


static const ber_sequence_t BoundProfilePackage_U_sequence[] = {
  { &hf_sgp22_initialiseSecureChannelRequest, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_sgp22_InitialiseSecureChannelRequest },
  { &hf_sgp22_firstSequenceOf87, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_firstSequenceOf87 },
  { &hf_sgp22_sequenceOf88  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_sequenceOf88 },
  { &hf_sgp22_secondSequenceOf87, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_T_secondSequenceOf87 },
  { &hf_sgp22_sequenceOf86  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp22_T_sequenceOf86 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_BoundProfilePackage_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BoundProfilePackage_U_sequence, hf_index, ett_sgp22_BoundProfilePackage_U);

  return offset;
}



int
dissect_sgp22_BoundProfilePackage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 54, true, dissect_sgp22_BoundProfilePackage_U);

  return offset;
}


static const ber_sequence_t GetEuiccChallengeRequest_U_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetEuiccChallengeRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEuiccChallengeRequest_U_sequence, hf_index, ett_sgp22_GetEuiccChallengeRequest_U);

  return offset;
}



static int
dissect_sgp22_GetEuiccChallengeRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 46, true, dissect_sgp22_GetEuiccChallengeRequest_U);

  return offset;
}


static const ber_sequence_t GetEuiccChallengeResponse_U_sequence[] = {
  { &hf_sgp22_euiccChallenge, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetEuiccChallengeResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEuiccChallengeResponse_U_sequence, hf_index, ett_sgp22_GetEuiccChallengeResponse_U);

  return offset;
}



static int
dissect_sgp22_GetEuiccChallengeResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 46, true, dissect_sgp22_GetEuiccChallengeResponse_U);

  return offset;
}



static int
dissect_sgp22_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t NotificationMetadata_U_sequence[] = {
  { &hf_sgp22_seqNumber     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_INTEGER },
  { &hf_sgp22_profileManagementOperation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_NotificationEvent },
  { &hf_sgp22_notificationAddress, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_iccid         , BER_CLASS_APP, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_NotificationMetadata_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NotificationMetadata_U_sequence, hf_index, ett_sgp22_NotificationMetadata_U);

  return offset;
}



int
dissect_sgp22_NotificationMetadata(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 47, true, dissect_sgp22_NotificationMetadata_U);

  return offset;
}



static int
dissect_sgp22_OCTET_STRING_SIZE_5_16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   5, 16, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SuccessResult_sequence[] = {
  { &hf_sgp22_aid           , BER_CLASS_APP, 15, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING_SIZE_5_16 },
  { &hf_sgp22_simaResponse  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_SuccessResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SuccessResult_sequence, hf_index, ett_sgp22_SuccessResult);

  return offset;
}


static const value_string sgp22_BppCommandId_vals[] = {
  {   0, "initialiseSecureChannel" },
  {   1, "configureISDP" },
  {   2, "storeMetadata" },
  {   3, "storeMetadata2" },
  {   4, "replaceSessionKeys" },
  {   5, "loadProfileElements" },
  { 0, NULL }
};


static int
dissect_sgp22_BppCommandId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_ErrorReason_vals[] = {
  {   1, "incorrectInputValues" },
  {   2, "invalidSignature" },
  {   3, "invalidTransactionId" },
  {   4, "unsupportedCrtValues" },
  {   5, "unsupportedRemoteOperationType" },
  {   6, "unsupportedProfileClass" },
  {   7, "scp03tStructureError" },
  {   8, "scp03tSecurityError" },
  {   9, "installFailedDueToIccidAlreadyExistsOnEuicc" },
  {  10, "installFailedDueToInsufficientMemoryForProfile" },
  {  11, "installFailedDueToInterruption" },
  {  12, "installFailedDueToPEProcessingError" },
  {  13, "installFailedDueToDataMismatch" },
  {  14, "testProfileInstallFailedDueToInvalidNaaKey" },
  {  15, "pprNotAllowed" },
  { 127, "installFailedDueToUnknownError" },
  { 0, NULL }
};


static int
dissect_sgp22_ErrorReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ErrorResult_sequence[] = {
  { &hf_sgp22_bppCommandId  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_BppCommandId },
  { &hf_sgp22_errorReason   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_ErrorReason },
  { &hf_sgp22_simaResponse  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_ErrorResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ErrorResult_sequence, hf_index, ett_sgp22_ErrorResult);

  return offset;
}


static const value_string sgp22_T_finalResult_vals[] = {
  {   0, "successResult" },
  {   1, "errorResult" },
  { 0, NULL }
};

static const ber_choice_t T_finalResult_choice[] = {
  {   0, &hf_sgp22_successResult , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_SuccessResult },
  {   1, &hf_sgp22_errorResult   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_ErrorResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_T_finalResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_finalResult_choice, hf_index, ett_sgp22_T_finalResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ProfileInstallationResultData_U_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_notificationMetadata, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_sgp22_NotificationMetadata },
  { &hf_sgp22_smdpOid       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_sgp22_OBJECT_IDENTIFIER },
  { &hf_sgp22_finalResult   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_T_finalResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ProfileInstallationResultData_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileInstallationResultData_U_sequence, hf_index, ett_sgp22_ProfileInstallationResultData_U);

  return offset;
}



int
dissect_sgp22_ProfileInstallationResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 39, true, dissect_sgp22_ProfileInstallationResultData_U);

  return offset;
}



int
dissect_sgp22_EuiccSignPIR(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 55, true, dissect_sgp22_OCTET_STRING);

  return offset;
}


static const ber_sequence_t ProfileInstallationResult_U_sequence[] = {
  { &hf_sgp22_profileInstallationResultData, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileInstallationResultData },
  { &hf_sgp22_euiccSignPIR  , BER_CLASS_APP, 55, BER_FLAGS_NOOWNTAG, dissect_sgp22_EuiccSignPIR },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ProfileInstallationResult_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileInstallationResult_U_sequence, hf_index, ett_sgp22_ProfileInstallationResult_U);

  return offset;
}



static int
dissect_sgp22_ProfileInstallationResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 55, true, dissect_sgp22_ProfileInstallationResult_U);

  return offset;
}


static const ber_sequence_t ListNotificationRequest_U_sequence[] = {
  { &hf_sgp22_profileManagementOperation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_NotificationEvent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ListNotificationRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ListNotificationRequest_U_sequence, hf_index, ett_sgp22_ListNotificationRequest_U);

  return offset;
}



static int
dissect_sgp22_ListNotificationRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 40, true, dissect_sgp22_ListNotificationRequest_U);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_NotificationMetadata_sequence_of[1] = {
  { &hf_sgp22_notificationMetadataList_item, BER_CLASS_CON, 47, BER_FLAGS_NOOWNTAG, dissect_sgp22_NotificationMetadata },
};

static int
dissect_sgp22_SEQUENCE_OF_NotificationMetadata(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_NotificationMetadata_sequence_of, hf_index, ett_sgp22_SEQUENCE_OF_NotificationMetadata);

  return offset;
}


static const value_string sgp22_T_listNotificationsResultError_vals[] = {
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_listNotificationsResultError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_ListNotificationResponse_U_vals[] = {
  {   0, "notificationMetadataList" },
  {   1, "listNotificationsResultError" },
  { 0, NULL }
};

static const ber_choice_t ListNotificationResponse_U_choice[] = {
  {   0, &hf_sgp22_notificationMetadataList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_NotificationMetadata },
  {   1, &hf_sgp22_listNotificationsResultError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_listNotificationsResultError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ListNotificationResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ListNotificationResponse_U_choice, hf_index, ett_sgp22_ListNotificationResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_ListNotificationResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 40, true, dissect_sgp22_ListNotificationResponse_U);

  return offset;
}


static const ber_sequence_t SetNicknameRequest_U_sequence[] = {
  { &hf_sgp22_iccid         , BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { &hf_sgp22_profileNickname, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_64 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_SetNicknameRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetNicknameRequest_U_sequence, hf_index, ett_sgp22_SetNicknameRequest_U);

  return offset;
}



static int
dissect_sgp22_SetNicknameRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 41, true, dissect_sgp22_SetNicknameRequest_U);

  return offset;
}


static const value_string sgp22_T_setNicknameResult_vals[] = {
  {   0, "ok" },
  {   1, "iccidNotFound" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_setNicknameResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SetNicknameResponse_U_sequence[] = {
  { &hf_sgp22_setNicknameResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_setNicknameResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_SetNicknameResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetNicknameResponse_U_sequence, hf_index, ett_sgp22_SetNicknameResponse_U);

  return offset;
}



static int
dissect_sgp22_SetNicknameResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 41, true, dissect_sgp22_SetNicknameResponse_U);

  return offset;
}



static int
dissect_sgp22_UTF8String_SIZE_0_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        0, 255, hf_index, NULL);

  return offset;
}


static const value_string sgp22_ActivationCodeRetrievalInfo_vals[] = {
  {   1, "activationCodeForProfileRedownload" },
  {   2, "activationCodeRetrievalAvailable" },
  {   3, "retryDelay" },
  { 0, NULL }
};

static const ber_choice_t ActivationCodeRetrievalInfo_choice[] = {
  {   1, &hf_sgp22_activationCodeForProfileRedownload, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String_SIZE_0_255 },
  {   2, &hf_sgp22_activationCodeRetrievalAvailable, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_BOOLEAN },
  {   3, &hf_sgp22_retryDelay    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp22_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ActivationCodeRetrievalInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ActivationCodeRetrievalInfo_choice, hf_index, ett_sgp22_ActivationCodeRetrievalInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t ConfigureISDPRequest_U_sequence[] = {
  { &hf_sgp22_dpProprietaryData, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_DpProprietaryData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ConfigureISDPRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConfigureISDPRequest_U_sequence, hf_index, ett_sgp22_ConfigureISDPRequest_U);

  return offset;
}



static int
dissect_sgp22_ConfigureISDPRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 36, true, dissect_sgp22_ConfigureISDPRequest_U);

  return offset;
}


static const ber_sequence_t ReplaceSessionKeysRequest_U_sequence[] = {
  { &hf_sgp22_initialMacChainingValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_ppkEnc        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_ppkCmac       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ReplaceSessionKeysRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReplaceSessionKeysRequest_U_sequence, hf_index, ett_sgp22_ReplaceSessionKeysRequest_U);

  return offset;
}



static int
dissect_sgp22_ReplaceSessionKeysRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 38, true, dissect_sgp22_ReplaceSessionKeysRequest_U);

  return offset;
}


static const value_string sgp22_T_searchCriteria_01_vals[] = {
  {   0, "seqNumber" },
  {   1, "profileManagementOperation" },
  { 0, NULL }
};

static const ber_choice_t T_searchCriteria_01_choice[] = {
  {   0, &hf_sgp22_seqNumber     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_INTEGER },
  {   1, &hf_sgp22_profileManagementOperation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_NotificationEvent },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_T_searchCriteria_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_searchCriteria_01_choice, hf_index, ett_sgp22_T_searchCriteria_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t RetrieveNotificationsListRequest_U_sequence[] = {
  { &hf_sgp22_searchCriteria_01, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_T_searchCriteria_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_RetrieveNotificationsListRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RetrieveNotificationsListRequest_U_sequence, hf_index, ett_sgp22_RetrieveNotificationsListRequest_U);

  return offset;
}



static int
dissect_sgp22_RetrieveNotificationsListRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 43, true, dissect_sgp22_RetrieveNotificationsListRequest_U);

  return offset;
}


static const ber_sequence_t OtherSignedNotification_sequence[] = {
  { &hf_sgp22_tbsOtherNotification, BER_CLASS_CON, 47, BER_FLAGS_NOOWNTAG, dissect_sgp22_NotificationMetadata },
  { &hf_sgp22_euiccNotificationSignature, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_euiccCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp22_eumCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_sgp22_OtherSignedNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OtherSignedNotification_sequence, hf_index, ett_sgp22_OtherSignedNotification);

  return offset;
}


static const value_string sgp22_PendingNotification_vals[] = {
  {   0, "profileInstallationResult" },
  {   1, "otherSignedNotification" },
  { 0, NULL }
};

static const ber_choice_t PendingNotification_choice[] = {
  {   0, &hf_sgp22_profileInstallationResult, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileInstallationResult },
  {   1, &hf_sgp22_otherSignedNotification, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_OtherSignedNotification },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_PendingNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PendingNotification_choice, hf_index, ett_sgp22_PendingNotification,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PendingNotification_sequence_of[1] = {
  { &hf_sgp22_notificationList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp22_PendingNotification },
};

static int
dissect_sgp22_SEQUENCE_OF_PendingNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PendingNotification_sequence_of, hf_index, ett_sgp22_SEQUENCE_OF_PendingNotification);

  return offset;
}


static const value_string sgp22_T_notificationsListResultError_vals[] = {
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_notificationsListResultError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_RetrieveNotificationsListResponse_U_vals[] = {
  {   0, "notificationList" },
  {   1, "notificationsListResultError" },
  { 0, NULL }
};

static const ber_choice_t RetrieveNotificationsListResponse_U_choice[] = {
  {   0, &hf_sgp22_notificationList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_PendingNotification },
  {   1, &hf_sgp22_notificationsListResultError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_notificationsListResultError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_RetrieveNotificationsListResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RetrieveNotificationsListResponse_U_choice, hf_index, ett_sgp22_RetrieveNotificationsListResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_RetrieveNotificationsListResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 43, true, dissect_sgp22_RetrieveNotificationsListResponse_U);

  return offset;
}


static const ber_sequence_t NotificationSentRequest_U_sequence[] = {
  { &hf_sgp22_seqNumber     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_NotificationSentRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NotificationSentRequest_U_sequence, hf_index, ett_sgp22_NotificationSentRequest_U);

  return offset;
}



static int
dissect_sgp22_NotificationSentRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 48, true, dissect_sgp22_NotificationSentRequest_U);

  return offset;
}


static const value_string sgp22_T_deleteNotificationStatus_vals[] = {
  {   0, "ok" },
  {   1, "nothingToDelete" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_deleteNotificationStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t NotificationSentResponse_U_sequence[] = {
  { &hf_sgp22_deleteNotificationStatus, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_deleteNotificationStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_NotificationSentResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NotificationSentResponse_U_sequence, hf_index, ett_sgp22_NotificationSentResponse_U);

  return offset;
}



static int
dissect_sgp22_NotificationSentResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 48, true, dissect_sgp22_NotificationSentResponse_U);

  return offset;
}


static const value_string sgp22_T_profileIdentifier_vals[] = {
  {  15, "isdpAid" },
  {  26, "iccid" },
  { 0, NULL }
};

static const ber_choice_t T_profileIdentifier_choice[] = {
  {  15, &hf_sgp22_isdpAid       , BER_CLASS_APP, 15, BER_FLAGS_IMPLTAG, dissect_sgp22_OctetTo16 },
  {  26, &hf_sgp22_iccid         , BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_T_profileIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_profileIdentifier_choice, hf_index, ett_sgp22_T_profileIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t EnableProfileRequest_U_sequence[] = {
  { &hf_sgp22_profileIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_profileIdentifier },
  { &hf_sgp22_refreshFlag   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EnableProfileRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnableProfileRequest_U_sequence, hf_index, ett_sgp22_EnableProfileRequest_U);

  return offset;
}



static int
dissect_sgp22_EnableProfileRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 49, true, dissect_sgp22_EnableProfileRequest_U);

  return offset;
}


static const value_string sgp22_T_enableResult_vals[] = {
  {   0, "ok" },
  {   1, "iccidOrAidNotFound" },
  {   2, "profileNotInDisabledState" },
  {   3, "disallowedByPolicy" },
  {   4, "wrongProfileReenabling" },
  {   5, "catBusy" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_enableResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EnableProfileResponse_U_sequence[] = {
  { &hf_sgp22_enableResult  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_enableResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EnableProfileResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnableProfileResponse_U_sequence, hf_index, ett_sgp22_EnableProfileResponse_U);

  return offset;
}



static int
dissect_sgp22_EnableProfileResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 49, true, dissect_sgp22_EnableProfileResponse_U);

  return offset;
}


static const value_string sgp22_T_profileIdentifier_01_vals[] = {
  {  15, "isdpAid" },
  {  26, "iccid" },
  { 0, NULL }
};

static const ber_choice_t T_profileIdentifier_01_choice[] = {
  {  15, &hf_sgp22_isdpAid       , BER_CLASS_APP, 15, BER_FLAGS_IMPLTAG, dissect_sgp22_OctetTo16 },
  {  26, &hf_sgp22_iccid         , BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_T_profileIdentifier_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_profileIdentifier_01_choice, hf_index, ett_sgp22_T_profileIdentifier_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t DisableProfileRequest_U_sequence[] = {
  { &hf_sgp22_profileIdentifier_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_profileIdentifier_01 },
  { &hf_sgp22_refreshFlag   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_DisableProfileRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisableProfileRequest_U_sequence, hf_index, ett_sgp22_DisableProfileRequest_U);

  return offset;
}



static int
dissect_sgp22_DisableProfileRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 50, true, dissect_sgp22_DisableProfileRequest_U);

  return offset;
}


static const value_string sgp22_T_disableResult_vals[] = {
  {   0, "ok" },
  {   1, "iccidOrAidNotFound" },
  {   2, "profileNotInEnabledState" },
  {   3, "disallowedByPolicy" },
  {   5, "catBusy" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_disableResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DisableProfileResponse_U_sequence[] = {
  { &hf_sgp22_disableResult , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_disableResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_DisableProfileResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisableProfileResponse_U_sequence, hf_index, ett_sgp22_DisableProfileResponse_U);

  return offset;
}



static int
dissect_sgp22_DisableProfileResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 50, true, dissect_sgp22_DisableProfileResponse_U);

  return offset;
}


static const value_string sgp22_DeleteProfileRequest_U_vals[] = {
  {  15, "isdpAid" },
  {  26, "iccid" },
  { 0, NULL }
};

static const ber_choice_t DeleteProfileRequest_U_choice[] = {
  {  15, &hf_sgp22_isdpAid       , BER_CLASS_APP, 15, BER_FLAGS_IMPLTAG, dissect_sgp22_OctetTo16 },
  {  26, &hf_sgp22_iccid         , BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_DeleteProfileRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeleteProfileRequest_U_choice, hf_index, ett_sgp22_DeleteProfileRequest_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_DeleteProfileRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 51, true, dissect_sgp22_DeleteProfileRequest_U);

  return offset;
}


static const value_string sgp22_T_deleteResult_vals[] = {
  {   0, "ok" },
  {   1, "iccidOrAidNotFound" },
  {   2, "profileNotInDisabledState" },
  {   3, "disallowedByPolicy" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_deleteResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DeleteProfileResponse_U_sequence[] = {
  { &hf_sgp22_deleteResult  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_deleteResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_DeleteProfileResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteProfileResponse_U_sequence, hf_index, ett_sgp22_DeleteProfileResponse_U);

  return offset;
}



static int
dissect_sgp22_DeleteProfileResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 51, true, dissect_sgp22_DeleteProfileResponse_U);

  return offset;
}


static int * const T_resetOptions_bits[] = {
  &hf_sgp22_T_resetOptions_deleteOperationalProfiles,
  &hf_sgp22_T_resetOptions_deleteFieldLoadedTestProfiles,
  &hf_sgp22_T_resetOptions_resetDefaultSmdpAddress,
  NULL
};

static int
dissect_sgp22_T_resetOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_resetOptions_bits, 3, hf_index, ett_sgp22_T_resetOptions,
                                    NULL);

  return offset;
}


static const ber_sequence_t EuiccMemoryResetRequest_U_sequence[] = {
  { &hf_sgp22_resetOptions  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_T_resetOptions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EuiccMemoryResetRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccMemoryResetRequest_U_sequence, hf_index, ett_sgp22_EuiccMemoryResetRequest_U);

  return offset;
}



static int
dissect_sgp22_EuiccMemoryResetRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 52, true, dissect_sgp22_EuiccMemoryResetRequest_U);

  return offset;
}


static const value_string sgp22_T_resetResult_vals[] = {
  {   0, "ok" },
  {   1, "nothingToDelete" },
  {   5, "catBusy" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_resetResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EuiccMemoryResetResponse_U_sequence[] = {
  { &hf_sgp22_resetResult   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_resetResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EuiccMemoryResetResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccMemoryResetResponse_U_sequence, hf_index, ett_sgp22_EuiccMemoryResetResponse_U);

  return offset;
}



static int
dissect_sgp22_EuiccMemoryResetResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 52, true, dissect_sgp22_EuiccMemoryResetResponse_U);

  return offset;
}


static const ber_sequence_t GetEuiccDataRequest_U_sequence[] = {
  { &hf_sgp22_tagList_01    , BER_CLASS_APP, 28, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetEuiccDataRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEuiccDataRequest_U_sequence, hf_index, ett_sgp22_GetEuiccDataRequest_U);

  return offset;
}



static int
dissect_sgp22_GetEuiccDataRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 62, true, dissect_sgp22_GetEuiccDataRequest_U);

  return offset;
}


static const ber_sequence_t GetEuiccDataResponse_U_sequence[] = {
  { &hf_sgp22_eidValue      , BER_CLASS_APP, 26, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetEuiccDataResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEuiccDataResponse_U_sequence, hf_index, ett_sgp22_GetEuiccDataResponse_U);

  return offset;
}



static int
dissect_sgp22_GetEuiccDataResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 62, true, dissect_sgp22_GetEuiccDataResponse_U);

  return offset;
}


static const ber_sequence_t GetRatRequest_U_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetRatRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetRatRequest_U_sequence, hf_index, ett_sgp22_GetRatRequest_U);

  return offset;
}



static int
dissect_sgp22_GetRatRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 67, true, dissect_sgp22_GetRatRequest_U);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_OperatorId_sequence_of[1] = {
  { &hf_sgp22_allowedOperators_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_OperatorId },
};

static int
dissect_sgp22_SEQUENCE_OF_OperatorId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_OperatorId_sequence_of, hf_index, ett_sgp22_SEQUENCE_OF_OperatorId);

  return offset;
}


static int * const T_pprFlags_bits[] = {
  &hf_sgp22_T_pprFlags_consentRequired,
  NULL
};

static int
dissect_sgp22_T_pprFlags(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_pprFlags_bits, 1, hf_index, ett_sgp22_T_pprFlags,
                                    NULL);

  return offset;
}


static const ber_sequence_t ProfilePolicyAuthorisationRule_sequence[] = {
  { &hf_sgp22_pprIds        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_PprIds },
  { &hf_sgp22_allowedOperators, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_OperatorId },
  { &hf_sgp22_pprFlags      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_T_pprFlags },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ProfilePolicyAuthorisationRule(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfilePolicyAuthorisationRule_sequence, hf_index, ett_sgp22_ProfilePolicyAuthorisationRule);

  return offset;
}


static const ber_sequence_t RulesAuthorisationTable_sequence_of[1] = {
  { &hf_sgp22_RulesAuthorisationTable_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_ProfilePolicyAuthorisationRule },
};

int
dissect_sgp22_RulesAuthorisationTable(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RulesAuthorisationTable_sequence_of, hf_index, ett_sgp22_RulesAuthorisationTable);

  return offset;
}


static const ber_sequence_t GetRatResponse_U_sequence[] = {
  { &hf_sgp22_rat           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_RulesAuthorisationTable },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetRatResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetRatResponse_U_sequence, hf_index, ett_sgp22_GetRatResponse_U);

  return offset;
}



static int
dissect_sgp22_GetRatResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 67, true, dissect_sgp22_GetRatResponse_U);

  return offset;
}


static const ber_sequence_t LoadCRLRequest_U_sequence[] = {
  { &hf_sgp22_crl           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pkix1explicit_CertificateList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_LoadCRLRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LoadCRLRequest_U_sequence, hf_index, ett_sgp22_LoadCRLRequest_U);

  return offset;
}



static int
dissect_sgp22_LoadCRLRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 53, true, dissect_sgp22_LoadCRLRequest_U);

  return offset;
}


static const ber_sequence_t T_missingParts_sequence_of[1] = {
  { &hf_sgp22_missingParts_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp22_INTEGER },
};

static int
dissect_sgp22_T_missingParts(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_missingParts_sequence_of, hf_index, ett_sgp22_T_missingParts);

  return offset;
}


static const ber_sequence_t LoadCRLResponseOk_sequence[] = {
  { &hf_sgp22_missingParts  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_T_missingParts },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_LoadCRLResponseOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LoadCRLResponseOk_sequence, hf_index, ett_sgp22_LoadCRLResponseOk);

  return offset;
}


static const value_string sgp22_LoadCRLResponseError_vals[] = {
  {   1, "invalidSignature" },
  {   2, "invalidCRLFormat" },
  {   3, "notEnoughMemorySpace" },
  {   4, "verificationKeyNotFound" },
  {   5, "fresherCrlAlreadyLoaded" },
  {   6, "baseCrlMissing" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_LoadCRLResponseError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_LoadCRLResponse_U_vals[] = {
  {   0, "loadCRLResponseOk" },
  {   1, "loadCRLResponseError" },
  { 0, NULL }
};

static const ber_choice_t LoadCRLResponse_U_choice[] = {
  {   0, &hf_sgp22_loadCRLResponseOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_LoadCRLResponseOk },
  {   1, &hf_sgp22_loadCRLResponseError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_LoadCRLResponseError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_LoadCRLResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LoadCRLResponse_U_choice, hf_index, ett_sgp22_LoadCRLResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_LoadCRLResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 53, true, dissect_sgp22_LoadCRLResponse_U);

  return offset;
}



static int
dissect_sgp22_ExpirationDate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkix1explicit_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_sgp22_TotalPartialCrlNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_sgp22_PartialCrlNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t InitiateAuthenticationRequest_U_sequence[] = {
  { &hf_sgp22_euiccChallenge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp22_smdpAddress   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_euiccInfo1    , BER_CLASS_CON, 32, BER_FLAGS_NOOWNTAG, dissect_sgp22_EUICCInfo1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_InitiateAuthenticationRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateAuthenticationRequest_U_sequence, hf_index, ett_sgp22_InitiateAuthenticationRequest_U);

  return offset;
}



static int
dissect_sgp22_InitiateAuthenticationRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 57, true, dissect_sgp22_InitiateAuthenticationRequest_U);

  return offset;
}



static int
dissect_sgp22_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t AuthenticateClientRequest_U_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_authenticateServerResponse, BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateServerResponse },
  { &hf_sgp22_useMatchingIdForAcr, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_AuthenticateClientRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateClientRequest_U_sequence, hf_index, ett_sgp22_AuthenticateClientRequest_U);

  return offset;
}



static int
dissect_sgp22_AuthenticateClientRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 59, true, dissect_sgp22_AuthenticateClientRequest_U);

  return offset;
}


static const ber_sequence_t GetBoundProfilePackageRequest_U_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_prepareDownloadResponse, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_sgp22_PrepareDownloadResponse },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetBoundProfilePackageRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetBoundProfilePackageRequest_U_sequence, hf_index, ett_sgp22_GetBoundProfilePackageRequest_U);

  return offset;
}



static int
dissect_sgp22_GetBoundProfilePackageRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 58, true, dissect_sgp22_GetBoundProfilePackageRequest_U);

  return offset;
}


static const ber_sequence_t CancelSessionRequestEs9_U_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_cancelSessionResponse, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionResponse },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_CancelSessionRequestEs9_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelSessionRequestEs9_U_sequence, hf_index, ett_sgp22_CancelSessionRequestEs9_U);

  return offset;
}



static int
dissect_sgp22_CancelSessionRequestEs9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 65, true, dissect_sgp22_CancelSessionRequestEs9_U);

  return offset;
}


static const ber_sequence_t HandleNotification_U_sequence[] = {
  { &hf_sgp22_pendingNotification, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp22_PendingNotification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_HandleNotification_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HandleNotification_U_sequence, hf_index, ett_sgp22_HandleNotification_U);

  return offset;
}



static int
dissect_sgp22_HandleNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 61, true, dissect_sgp22_HandleNotification_U);

  return offset;
}


static const value_string sgp22_RemoteProfileProvisioningRequest_U_vals[] = {
  {  57, "initiateAuthenticationRequest" },
  {  59, "authenticateClientRequest" },
  {  58, "getBoundProfilePackageRequest" },
  {  65, "cancelSessionRequestEs9" },
  {  61, "handleNotification" },
  { 0, NULL }
};

static const ber_choice_t RemoteProfileProvisioningRequest_U_choice[] = {
  {  57, &hf_sgp22_initiateAuthenticationRequest, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_sgp22_InitiateAuthenticationRequest },
  {  59, &hf_sgp22_authenticateClientRequest, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateClientRequest },
  {  58, &hf_sgp22_getBoundProfilePackageRequest, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_sgp22_GetBoundProfilePackageRequest },
  {  65, &hf_sgp22_cancelSessionRequestEs9, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionRequestEs9 },
  {  61, &hf_sgp22_handleNotification, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_sgp22_HandleNotification },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_RemoteProfileProvisioningRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int choice;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RemoteProfileProvisioningRequest_U_choice, hf_index, ett_sgp22_RemoteProfileProvisioningRequest_U,
                                 &choice);

  if (choice != -1) {
    col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str_const(RemoteProfileProvisioningRequest_U_choice[choice].value, sgp22_RemoteProfileProvisioningRequest_U_vals, "Unknown"));
  }

  return offset;
}



static int
dissect_sgp22_RemoteProfileProvisioningRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 2, true, dissect_sgp22_RemoteProfileProvisioningRequest_U);

  return offset;
}


static const ber_sequence_t InitiateAuthenticationOkEs9_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_serverSigned1 , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_ServerSigned1 },
  { &hf_sgp22_serverSignature1, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_euiccCiPKIdToBeUsed, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_SubjectKeyIdentifier },
  { &hf_sgp22_serverCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_InitiateAuthenticationOkEs9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateAuthenticationOkEs9_sequence, hf_index, ett_sgp22_InitiateAuthenticationOkEs9);

  return offset;
}


static const value_string sgp22_T_initiateAuthenticationError_vals[] = {
  {   1, "invalidDpAddress" },
  {   2, "euiccVersionNotSupportedByDp" },
  {   3, "ciPKNotSupported" },
  { 0, NULL }
};


static int
dissect_sgp22_T_initiateAuthenticationError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_InitiateAuthenticationResponse_U_vals[] = {
  {   0, "initiateAuthenticationOk" },
  {   1, "initiateAuthenticationError" },
  { 0, NULL }
};

static const ber_choice_t InitiateAuthenticationResponse_U_choice[] = {
  {   0, &hf_sgp22_initiateAuthenticationOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_InitiateAuthenticationOkEs9 },
  {   1, &hf_sgp22_initiateAuthenticationError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_initiateAuthenticationError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_InitiateAuthenticationResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InitiateAuthenticationResponse_U_choice, hf_index, ett_sgp22_InitiateAuthenticationResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_InitiateAuthenticationResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 57, true, dissect_sgp22_InitiateAuthenticationResponse_U);

  return offset;
}


static const ber_sequence_t AuthenticateClientOk_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_profileMetaData, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_sgp22_StoreMetadataRequest },
  { &hf_sgp22_smdpSigned2   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_SmdpSigned2 },
  { &hf_sgp22_smdpSignature2, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp22_OCTET_STRING },
  { &hf_sgp22_smdpCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_AuthenticateClientOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateClientOk_sequence, hf_index, ett_sgp22_AuthenticateClientOk);

  return offset;
}


static const value_string sgp22_T_authenticateClientError_vals[] = {
  {   1, "eumCertificateInvalid" },
  {   2, "eumCertificateExpired" },
  {   3, "euiccCertificateInvalid" },
  {   4, "euiccCertificateExpired" },
  {   5, "euiccSignatureInvalid" },
  {   6, "matchingIdRefused" },
  {   7, "eidMismatch" },
  {   8, "noEligibleProfile" },
  {   9, "ciPKUnknown" },
  {  10, "invalidTransactionId" },
  {  11, "insufficientMemory" },
  {  18, "downloadOrderExpired" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_authenticateClientError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_AuthenticateClientResponseEs9_U_vals[] = {
  {   0, "authenticateClientOk" },
  {   1, "authenticateClientError" },
  { 0, NULL }
};

static const ber_choice_t AuthenticateClientResponseEs9_U_choice[] = {
  {   0, &hf_sgp22_authenticateClientOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateClientOk },
  {   1, &hf_sgp22_authenticateClientError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_authenticateClientError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_AuthenticateClientResponseEs9_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticateClientResponseEs9_U_choice, hf_index, ett_sgp22_AuthenticateClientResponseEs9_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_AuthenticateClientResponseEs9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 59, true, dissect_sgp22_AuthenticateClientResponseEs9_U);

  return offset;
}


static const ber_sequence_t GetBoundProfilePackageOk_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_boundProfilePackage, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_sgp22_BoundProfilePackage },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetBoundProfilePackageOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetBoundProfilePackageOk_sequence, hf_index, ett_sgp22_GetBoundProfilePackageOk);

  return offset;
}


static const value_string sgp22_T_getBoundProfilePackageError_vals[] = {
  {   1, "euiccSignatureInvalid" },
  {   2, "confirmationCodeMissing" },
  {   3, "confirmationCodeRefused" },
  {   4, "confirmationCodeRetriesExceeded" },
  {   5, "bppRebindingRefused" },
  {   6, "deprecated" },
  {  95, "invalidTransactionId" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_getBoundProfilePackageError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_GetBoundProfilePackageResponse_U_vals[] = {
  {   0, "getBoundProfilePackageOk" },
  {   1, "getBoundProfilePackageError" },
  { 0, NULL }
};

static const ber_choice_t GetBoundProfilePackageResponse_U_choice[] = {
  {   0, &hf_sgp22_getBoundProfilePackageOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_GetBoundProfilePackageOk },
  {   1, &hf_sgp22_getBoundProfilePackageError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_getBoundProfilePackageError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_GetBoundProfilePackageResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GetBoundProfilePackageResponse_U_choice, hf_index, ett_sgp22_GetBoundProfilePackageResponse_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_GetBoundProfilePackageResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 58, true, dissect_sgp22_GetBoundProfilePackageResponse_U);

  return offset;
}


static const ber_sequence_t CancelSessionOk_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_CancelSessionOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelSessionOk_sequence, hf_index, ett_sgp22_CancelSessionOk);

  return offset;
}


static const value_string sgp22_T_cancelSessionError_vals[] = {
  {   1, "invalidTransactionId" },
  {   2, "euiccSignatureInvalid" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_cancelSessionError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_CancelSessionResponseEs9_U_vals[] = {
  {   0, "cancelSessionOk" },
  {   1, "cancelSessionError" },
  { 0, NULL }
};

static const ber_choice_t CancelSessionResponseEs9_U_choice[] = {
  {   0, &hf_sgp22_cancelSessionOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionOk },
  {   1, &hf_sgp22_cancelSessionError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_cancelSessionError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_CancelSessionResponseEs9_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CancelSessionResponseEs9_U_choice, hf_index, ett_sgp22_CancelSessionResponseEs9_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_CancelSessionResponseEs9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 65, true, dissect_sgp22_CancelSessionResponseEs9_U);

  return offset;
}


static const ber_sequence_t EventEntries_sequence[] = {
  { &hf_sgp22_eventId       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_rspServerAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EventEntries(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventEntries_sequence, hf_index, ett_sgp22_EventEntries);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EventEntries_sequence_of[1] = {
  { &hf_sgp22_eventEntries_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_EventEntries },
};

static int
dissect_sgp22_SEQUENCE_OF_EventEntries(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EventEntries_sequence_of, hf_index, ett_sgp22_SEQUENCE_OF_EventEntries);

  return offset;
}


static const ber_sequence_t AuthenticateClientOkEs11_sequence[] = {
  { &hf_sgp22_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp22_eventEntries  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_SEQUENCE_OF_EventEntries },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_AuthenticateClientOkEs11(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateClientOkEs11_sequence, hf_index, ett_sgp22_AuthenticateClientOkEs11);

  return offset;
}


static const value_string sgp22_T_authenticateClientError_01_vals[] = {
  {   1, "eumCertificateInvalid" },
  {   2, "eumCertificateExpired" },
  {   3, "euiccCertificateInvalid" },
  {   4, "euiccCertificateExpired" },
  {   5, "euiccSignatureInvalid" },
  {   6, "eventIdUnknown" },
  {   7, "invalidTransactionId" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_authenticateClientError_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp22_AuthenticateClientResponseEs11_U_vals[] = {
  {   0, "authenticateClientOk" },
  {   1, "authenticateClientError" },
  { 0, NULL }
};

static const ber_choice_t AuthenticateClientResponseEs11_U_choice[] = {
  {   0, &hf_sgp22_authenticateClientOk_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateClientOkEs11 },
  {   1, &hf_sgp22_authenticateClientError_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_T_authenticateClientError_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_AuthenticateClientResponseEs11_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticateClientResponseEs11_U_choice, hf_index, ett_sgp22_AuthenticateClientResponseEs11_U,
                                 NULL);

  return offset;
}



static int
dissect_sgp22_AuthenticateClientResponseEs11(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 64, true, dissect_sgp22_AuthenticateClientResponseEs11_U);

  return offset;
}


static const value_string sgp22_RemoteProfileProvisioningResponse_U_vals[] = {
  {  57, "initiateAuthenticationResponse" },
  {  59, "authenticateClientResponseEs9" },
  {  58, "getBoundProfilePackageResponse" },
  {  65, "cancelSessionResponseEs9" },
  {  64, "authenticateClientResponseEs11" },
  { 0, NULL }
};

static const ber_choice_t RemoteProfileProvisioningResponse_U_choice[] = {
  {  57, &hf_sgp22_initiateAuthenticationResponse, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_sgp22_InitiateAuthenticationResponse },
  {  59, &hf_sgp22_authenticateClientResponseEs9, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateClientResponseEs9 },
  {  58, &hf_sgp22_getBoundProfilePackageResponse, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_sgp22_GetBoundProfilePackageResponse },
  {  65, &hf_sgp22_cancelSessionResponseEs9, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionResponseEs9 },
  {  64, &hf_sgp22_authenticateClientResponseEs11, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateClientResponseEs11 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_RemoteProfileProvisioningResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int choice;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RemoteProfileProvisioningResponse_U_choice, hf_index, ett_sgp22_RemoteProfileProvisioningResponse_U,
                                 &choice);

  if (choice != -1) {
    col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str_const(RemoteProfileProvisioningResponse_U_choice[choice].value, sgp22_RemoteProfileProvisioningResponse_U_vals, "Unknown"));
  }

  return offset;
}



static int
dissect_sgp22_RemoteProfileProvisioningResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 2, true, dissect_sgp22_RemoteProfileProvisioningResponse_U);

  return offset;
}


static const ber_sequence_t EuiccConfiguredAddressesRequest_U_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EuiccConfiguredAddressesRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccConfiguredAddressesRequest_U_sequence, hf_index, ett_sgp22_EuiccConfiguredAddressesRequest_U);

  return offset;
}



static int
dissect_sgp22_EuiccConfiguredAddressesRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 60, true, dissect_sgp22_EuiccConfiguredAddressesRequest_U);

  return offset;
}


static const ber_sequence_t EuiccConfiguredAddressesResponse_U_sequence[] = {
  { &hf_sgp22_defaultDpAddress, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { &hf_sgp22_rootDsAddress , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_EuiccConfiguredAddressesResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccConfiguredAddressesResponse_U_sequence, hf_index, ett_sgp22_EuiccConfiguredAddressesResponse_U);

  return offset;
}



static int
dissect_sgp22_EuiccConfiguredAddressesResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 60, true, dissect_sgp22_EuiccConfiguredAddressesResponse_U);

  return offset;
}


static int * const T_lpaeSupport_bits[] = {
  &hf_sgp22_T_lpaeSupport_lpaeUsingCat,
  &hf_sgp22_T_lpaeSupport_lpaeUsingScws,
  NULL
};

static int
dissect_sgp22_T_lpaeSupport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_lpaeSupport_bits, 2, hf_index, ett_sgp22_T_lpaeSupport,
                                    NULL);

  return offset;
}


static const ber_sequence_t ISDRProprietaryApplicationTemplate_U_sequence[] = {
  { &hf_sgp22_svn           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp22_lpaeSupport   , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_T_lpaeSupport },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_ISDRProprietaryApplicationTemplate_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ISDRProprietaryApplicationTemplate_U_sequence, hf_index, ett_sgp22_ISDRProprietaryApplicationTemplate_U);

  return offset;
}



static int
dissect_sgp22_ISDRProprietaryApplicationTemplate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 0, true, dissect_sgp22_ISDRProprietaryApplicationTemplate_U);

  return offset;
}


static int * const T_lpaeOption_bits[] = {
  &hf_sgp22_T_lpaeOption_activateCatBasedLpae,
  &hf_sgp22_T_lpaeOption_activateScwsBasedLpae,
  NULL
};

static int
dissect_sgp22_T_lpaeOption(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_lpaeOption_bits, 2, hf_index, ett_sgp22_T_lpaeOption,
                                    NULL);

  return offset;
}


static const ber_sequence_t LpaeActivationRequest_U_sequence[] = {
  { &hf_sgp22_lpaeOption    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_lpaeOption },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_LpaeActivationRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LpaeActivationRequest_U_sequence, hf_index, ett_sgp22_LpaeActivationRequest_U);

  return offset;
}



static int
dissect_sgp22_LpaeActivationRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 66, true, dissect_sgp22_LpaeActivationRequest_U);

  return offset;
}


static const value_string sgp22_T_lpaeActivationResult_vals[] = {
  {   0, "ok" },
  {   1, "notSupported" },
  { 0, NULL }
};


static int
dissect_sgp22_T_lpaeActivationResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t LpaeActivationResponse_U_sequence[] = {
  { &hf_sgp22_lpaeActivationResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_lpaeActivationResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_LpaeActivationResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LpaeActivationResponse_U_sequence, hf_index, ett_sgp22_LpaeActivationResponse_U);

  return offset;
}



static int
dissect_sgp22_LpaeActivationResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 66, true, dissect_sgp22_LpaeActivationResponse_U);

  return offset;
}


static const ber_sequence_t SetDefaultDpAddressRequest_U_sequence[] = {
  { &hf_sgp22_defaultDpAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_SetDefaultDpAddressRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetDefaultDpAddressRequest_U_sequence, hf_index, ett_sgp22_SetDefaultDpAddressRequest_U);

  return offset;
}



static int
dissect_sgp22_SetDefaultDpAddressRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 63, true, dissect_sgp22_SetDefaultDpAddressRequest_U);

  return offset;
}


static const value_string sgp22_T_setDefaultDpAddressResult_vals[] = {
  {   0, "ok" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static int
dissect_sgp22_T_setDefaultDpAddressResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SetDefaultDpAddressResponse_U_sequence[] = {
  { &hf_sgp22_setDefaultDpAddressResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_T_setDefaultDpAddressResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sgp22_SetDefaultDpAddressResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetDefaultDpAddressResponse_U_sequence, hf_index, ett_sgp22_SetDefaultDpAddressResponse_U);

  return offset;
}



static int
dissect_sgp22_SetDefaultDpAddressResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 63, true, dissect_sgp22_SetDefaultDpAddressResponse_U);

  return offset;
}

/*--- PDUs ---*/

static int dissect_GetEuiccInfo1Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetEuiccInfo1Request(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetEuiccInfo1Request_PDU);
  return offset;
}
static int dissect_EUICCInfo1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_EUICCInfo1(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_EUICCInfo1_PDU);
  return offset;
}
static int dissect_GetEuiccInfo2Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetEuiccInfo2Request(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetEuiccInfo2Request_PDU);
  return offset;
}
static int dissect_EUICCInfo2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_EUICCInfo2(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_EUICCInfo2_PDU);
  return offset;
}
static int dissect_ProfileInfoListRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ProfileInfoListRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ProfileInfoListRequest_PDU);
  return offset;
}
static int dissect_ProfileInfoListResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ProfileInfoListResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ProfileInfoListResponse_PDU);
  return offset;
}
static int dissect_ProfileInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ProfileInfo(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ProfileInfo_PDU);
  return offset;
}
static int dissect_StoreMetadataRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_StoreMetadataRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_StoreMetadataRequest_PDU);
  return offset;
}
static int dissect_UpdateMetadataRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_UpdateMetadataRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_UpdateMetadataRequest_PDU);
  return offset;
}
static int dissect_PrepareDownloadRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_PrepareDownloadRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_PrepareDownloadRequest_PDU);
  return offset;
}
static int dissect_PrepareDownloadResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_PrepareDownloadResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_PrepareDownloadResponse_PDU);
  return offset;
}
static int dissect_AuthenticateServerRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_AuthenticateServerRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_AuthenticateServerRequest_PDU);
  return offset;
}
static int dissect_AuthenticateServerResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_AuthenticateServerResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_AuthenticateServerResponse_PDU);
  return offset;
}
static int dissect_CancelSessionRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_CancelSessionRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_CancelSessionRequest_PDU);
  return offset;
}
static int dissect_CancelSessionResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_CancelSessionResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_CancelSessionResponse_PDU);
  return offset;
}
static int dissect_BoundProfilePackage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_BoundProfilePackage(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_BoundProfilePackage_PDU);
  return offset;
}
static int dissect_GetEuiccChallengeRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetEuiccChallengeRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetEuiccChallengeRequest_PDU);
  return offset;
}
static int dissect_GetEuiccChallengeResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetEuiccChallengeResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetEuiccChallengeResponse_PDU);
  return offset;
}
static int dissect_ProfileInstallationResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ProfileInstallationResult(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ProfileInstallationResult_PDU);
  return offset;
}
static int dissect_ListNotificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ListNotificationRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ListNotificationRequest_PDU);
  return offset;
}
static int dissect_ListNotificationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ListNotificationResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ListNotificationResponse_PDU);
  return offset;
}
static int dissect_NotificationMetadata_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_NotificationMetadata(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_NotificationMetadata_PDU);
  return offset;
}
static int dissect_SetNicknameRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_SetNicknameRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_SetNicknameRequest_PDU);
  return offset;
}
static int dissect_SetNicknameResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_SetNicknameResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_SetNicknameResponse_PDU);
  return offset;
}
static int dissect_ActivationCodeRetrievalInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ActivationCodeRetrievalInfo(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ActivationCodeRetrievalInfo_PDU);
  return offset;
}
static int dissect_InitialiseSecureChannelRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_InitialiseSecureChannelRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_InitialiseSecureChannelRequest_PDU);
  return offset;
}
static int dissect_ConfigureISDPRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ConfigureISDPRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ConfigureISDPRequest_PDU);
  return offset;
}
static int dissect_ReplaceSessionKeysRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ReplaceSessionKeysRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ReplaceSessionKeysRequest_PDU);
  return offset;
}
static int dissect_RetrieveNotificationsListRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_RetrieveNotificationsListRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_RetrieveNotificationsListRequest_PDU);
  return offset;
}
static int dissect_RetrieveNotificationsListResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_RetrieveNotificationsListResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_RetrieveNotificationsListResponse_PDU);
  return offset;
}
static int dissect_NotificationSentRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_NotificationSentRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_NotificationSentRequest_PDU);
  return offset;
}
static int dissect_NotificationSentResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_NotificationSentResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_NotificationSentResponse_PDU);
  return offset;
}
static int dissect_EnableProfileRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_EnableProfileRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_EnableProfileRequest_PDU);
  return offset;
}
static int dissect_EnableProfileResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_EnableProfileResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_EnableProfileResponse_PDU);
  return offset;
}
static int dissect_DisableProfileRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_DisableProfileRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_DisableProfileRequest_PDU);
  return offset;
}
static int dissect_DisableProfileResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_DisableProfileResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_DisableProfileResponse_PDU);
  return offset;
}
static int dissect_DeleteProfileRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_DeleteProfileRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_DeleteProfileRequest_PDU);
  return offset;
}
static int dissect_DeleteProfileResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_DeleteProfileResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_DeleteProfileResponse_PDU);
  return offset;
}
static int dissect_EuiccMemoryResetRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_EuiccMemoryResetRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_EuiccMemoryResetRequest_PDU);
  return offset;
}
static int dissect_EuiccMemoryResetResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_EuiccMemoryResetResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_EuiccMemoryResetResponse_PDU);
  return offset;
}
static int dissect_GetEuiccDataRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetEuiccDataRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetEuiccDataRequest_PDU);
  return offset;
}
static int dissect_GetEuiccDataResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetEuiccDataResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetEuiccDataResponse_PDU);
  return offset;
}
static int dissect_GetRatRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetRatRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetRatRequest_PDU);
  return offset;
}
static int dissect_GetRatResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetRatResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetRatResponse_PDU);
  return offset;
}
static int dissect_LoadCRLRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_LoadCRLRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_LoadCRLRequest_PDU);
  return offset;
}
static int dissect_LoadCRLResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_LoadCRLResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_LoadCRLResponse_PDU);
  return offset;
}
static int dissect_ExpirationDate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ExpirationDate(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ExpirationDate_PDU);
  return offset;
}
static int dissect_TotalPartialCrlNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_TotalPartialCrlNumber(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_TotalPartialCrlNumber_PDU);
  return offset;
}
static int dissect_PartialCrlNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_PartialCrlNumber(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_PartialCrlNumber_PDU);
  return offset;
}
static int dissect_RemoteProfileProvisioningRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_RemoteProfileProvisioningRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_RemoteProfileProvisioningRequest_PDU);
  return offset;
}
static int dissect_RemoteProfileProvisioningResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_RemoteProfileProvisioningResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_RemoteProfileProvisioningResponse_PDU);
  return offset;
}
static int dissect_InitiateAuthenticationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_InitiateAuthenticationRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_InitiateAuthenticationRequest_PDU);
  return offset;
}
static int dissect_InitiateAuthenticationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_InitiateAuthenticationResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_InitiateAuthenticationResponse_PDU);
  return offset;
}
static int dissect_AuthenticateClientRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_AuthenticateClientRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_AuthenticateClientRequest_PDU);
  return offset;
}
static int dissect_AuthenticateClientResponseEs9_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_AuthenticateClientResponseEs9(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_AuthenticateClientResponseEs9_PDU);
  return offset;
}
static int dissect_GetBoundProfilePackageRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetBoundProfilePackageRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetBoundProfilePackageRequest_PDU);
  return offset;
}
static int dissect_GetBoundProfilePackageResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_GetBoundProfilePackageResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_GetBoundProfilePackageResponse_PDU);
  return offset;
}
static int dissect_HandleNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_HandleNotification(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_HandleNotification_PDU);
  return offset;
}
static int dissect_EuiccConfiguredAddressesRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_EuiccConfiguredAddressesRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_EuiccConfiguredAddressesRequest_PDU);
  return offset;
}
static int dissect_EuiccConfiguredAddressesResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_EuiccConfiguredAddressesResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_EuiccConfiguredAddressesResponse_PDU);
  return offset;
}
static int dissect_ISDRProprietaryApplicationTemplate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_ISDRProprietaryApplicationTemplate(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_ISDRProprietaryApplicationTemplate_PDU);
  return offset;
}
static int dissect_LpaeActivationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_LpaeActivationRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_LpaeActivationRequest_PDU);
  return offset;
}
static int dissect_LpaeActivationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_LpaeActivationResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_LpaeActivationResponse_PDU);
  return offset;
}
static int dissect_SetDefaultDpAddressRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_SetDefaultDpAddressRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_SetDefaultDpAddressRequest_PDU);
  return offset;
}
static int dissect_SetDefaultDpAddressResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_SetDefaultDpAddressResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_SetDefaultDpAddressResponse_PDU);
  return offset;
}
static int dissect_AuthenticateClientResponseEs11_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp22_AuthenticateClientResponseEs11(false, tvb, offset, &asn1_ctx, tree, hf_sgp22_AuthenticateClientResponseEs11_PDU);
  return offset;
}


static dissector_handle_t sgp22_handle;

static int dissect_sgp22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  media_content_info_t *content_info = (media_content_info_t *)data;
  proto_item *sgp22_ti;
  proto_tree *sgp22_tree;
  int offset;

  if (!content_info ||
      ((content_info->type != MEDIA_CONTAINER_HTTP_REQUEST) &&
       (content_info->type != MEDIA_CONTAINER_HTTP_RESPONSE))) {
    return 0;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.22");
  col_clear(pinfo->cinfo, COL_INFO);

  sgp22_ti = proto_tree_add_item(tree, proto_sgp22, tvb, 0, -1, ENC_NA);
  sgp22_tree = proto_item_add_subtree(sgp22_ti, ett_sgp22);

  if (content_info->type == MEDIA_CONTAINER_HTTP_REQUEST) {
    offset = dissect_RemoteProfileProvisioningRequest_PDU(tvb, pinfo, sgp22_tree, NULL);
  } else {
    offset = dissect_RemoteProfileProvisioningResponse_PDU(tvb, pinfo, sgp22_tree, NULL);
  }

  return offset;
}

void proto_register_sgp22(void)
{
  static hf_register_info hf[] = {
    { &hf_sgp22_GetEuiccInfo1Request_PDU,
      { "GetEuiccInfo1Request", "sgp22.GetEuiccInfo1Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_EUICCInfo1_PDU,
      { "EUICCInfo1", "sgp22.EUICCInfo1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_GetEuiccInfo2Request_PDU,
      { "GetEuiccInfo2Request", "sgp22.GetEuiccInfo2Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_EUICCInfo2_PDU,
      { "EUICCInfo2", "sgp22.EUICCInfo2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ProfileInfoListRequest_PDU,
      { "ProfileInfoListRequest", "sgp22.ProfileInfoListRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ProfileInfoListResponse_PDU,
      { "ProfileInfoListResponse", "sgp22.ProfileInfoListResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_ProfileInfoListResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_ProfileInfo_PDU,
      { "ProfileInfo", "sgp22.ProfileInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_StoreMetadataRequest_PDU,
      { "StoreMetadataRequest", "sgp22.StoreMetadataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_UpdateMetadataRequest_PDU,
      { "UpdateMetadataRequest", "sgp22.UpdateMetadataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_PrepareDownloadRequest_PDU,
      { "PrepareDownloadRequest", "sgp22.PrepareDownloadRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_PrepareDownloadResponse_PDU,
      { "PrepareDownloadResponse", "sgp22.PrepareDownloadResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_PrepareDownloadResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_AuthenticateServerRequest_PDU,
      { "AuthenticateServerRequest", "sgp22.AuthenticateServerRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_AuthenticateServerResponse_PDU,
      { "AuthenticateServerResponse", "sgp22.AuthenticateServerResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_AuthenticateServerResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_CancelSessionRequest_PDU,
      { "CancelSessionRequest", "sgp22.CancelSessionRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_CancelSessionResponse_PDU,
      { "CancelSessionResponse", "sgp22.CancelSessionResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_CancelSessionResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_BoundProfilePackage_PDU,
      { "BoundProfilePackage", "sgp22.BoundProfilePackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_GetEuiccChallengeRequest_PDU,
      { "GetEuiccChallengeRequest", "sgp22.GetEuiccChallengeRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_GetEuiccChallengeResponse_PDU,
      { "GetEuiccChallengeResponse", "sgp22.GetEuiccChallengeResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ProfileInstallationResult_PDU,
      { "ProfileInstallationResult", "sgp22.ProfileInstallationResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ListNotificationRequest_PDU,
      { "ListNotificationRequest", "sgp22.ListNotificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ListNotificationResponse_PDU,
      { "ListNotificationResponse", "sgp22.ListNotificationResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_ListNotificationResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_NotificationMetadata_PDU,
      { "NotificationMetadata", "sgp22.NotificationMetadata_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_SetNicknameRequest_PDU,
      { "SetNicknameRequest", "sgp22.SetNicknameRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_SetNicknameResponse_PDU,
      { "SetNicknameResponse", "sgp22.SetNicknameResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ActivationCodeRetrievalInfo_PDU,
      { "ActivationCodeRetrievalInfo", "sgp22.ActivationCodeRetrievalInfo",
        FT_UINT32, BASE_DEC, VALS(sgp22_ActivationCodeRetrievalInfo_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_InitialiseSecureChannelRequest_PDU,
      { "InitialiseSecureChannelRequest", "sgp22.InitialiseSecureChannelRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ConfigureISDPRequest_PDU,
      { "ConfigureISDPRequest", "sgp22.ConfigureISDPRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ReplaceSessionKeysRequest_PDU,
      { "ReplaceSessionKeysRequest", "sgp22.ReplaceSessionKeysRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_RetrieveNotificationsListRequest_PDU,
      { "RetrieveNotificationsListRequest", "sgp22.RetrieveNotificationsListRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_RetrieveNotificationsListResponse_PDU,
      { "RetrieveNotificationsListResponse", "sgp22.RetrieveNotificationsListResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_RetrieveNotificationsListResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_NotificationSentRequest_PDU,
      { "NotificationSentRequest", "sgp22.NotificationSentRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_NotificationSentResponse_PDU,
      { "NotificationSentResponse", "sgp22.NotificationSentResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_EnableProfileRequest_PDU,
      { "EnableProfileRequest", "sgp22.EnableProfileRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_EnableProfileResponse_PDU,
      { "EnableProfileResponse", "sgp22.EnableProfileResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_DisableProfileRequest_PDU,
      { "DisableProfileRequest", "sgp22.DisableProfileRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_DisableProfileResponse_PDU,
      { "DisableProfileResponse", "sgp22.DisableProfileResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_DeleteProfileRequest_PDU,
      { "DeleteProfileRequest", "sgp22.DeleteProfileRequest",
        FT_UINT32, BASE_DEC, VALS(sgp22_DeleteProfileRequest_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_DeleteProfileResponse_PDU,
      { "DeleteProfileResponse", "sgp22.DeleteProfileResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_EuiccMemoryResetRequest_PDU,
      { "EuiccMemoryResetRequest", "sgp22.EuiccMemoryResetRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_EuiccMemoryResetResponse_PDU,
      { "EuiccMemoryResetResponse", "sgp22.EuiccMemoryResetResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_GetEuiccDataRequest_PDU,
      { "GetEuiccDataRequest", "sgp22.GetEuiccDataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_GetEuiccDataResponse_PDU,
      { "GetEuiccDataResponse", "sgp22.GetEuiccDataResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_GetRatRequest_PDU,
      { "GetRatRequest", "sgp22.GetRatRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_GetRatResponse_PDU,
      { "GetRatResponse", "sgp22.GetRatResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_LoadCRLRequest_PDU,
      { "LoadCRLRequest", "sgp22.LoadCRLRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_LoadCRLResponse_PDU,
      { "LoadCRLResponse", "sgp22.LoadCRLResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_LoadCRLResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_ExpirationDate_PDU,
      { "ExpirationDate", "sgp22.ExpirationDate",
        FT_UINT32, BASE_DEC, VALS(pkix1explicit_Time_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_TotalPartialCrlNumber_PDU,
      { "TotalPartialCrlNumber", "sgp22.TotalPartialCrlNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_PartialCrlNumber_PDU,
      { "PartialCrlNumber", "sgp22.PartialCrlNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_RemoteProfileProvisioningRequest_PDU,
      { "RemoteProfileProvisioningRequest", "sgp22.RemoteProfileProvisioningRequest",
        FT_UINT32, BASE_DEC, VALS(sgp22_RemoteProfileProvisioningRequest_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_RemoteProfileProvisioningResponse_PDU,
      { "RemoteProfileProvisioningResponse", "sgp22.RemoteProfileProvisioningResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_RemoteProfileProvisioningResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_InitiateAuthenticationRequest_PDU,
      { "InitiateAuthenticationRequest", "sgp22.InitiateAuthenticationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_InitiateAuthenticationResponse_PDU,
      { "InitiateAuthenticationResponse", "sgp22.InitiateAuthenticationResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_InitiateAuthenticationResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_AuthenticateClientRequest_PDU,
      { "AuthenticateClientRequest", "sgp22.AuthenticateClientRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_AuthenticateClientResponseEs9_PDU,
      { "AuthenticateClientResponseEs9", "sgp22.AuthenticateClientResponseEs9",
        FT_UINT32, BASE_DEC, VALS(sgp22_AuthenticateClientResponseEs9_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_GetBoundProfilePackageRequest_PDU,
      { "GetBoundProfilePackageRequest", "sgp22.GetBoundProfilePackageRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_GetBoundProfilePackageResponse_PDU,
      { "GetBoundProfilePackageResponse", "sgp22.GetBoundProfilePackageResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_GetBoundProfilePackageResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_HandleNotification_PDU,
      { "HandleNotification", "sgp22.HandleNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_EuiccConfiguredAddressesRequest_PDU,
      { "EuiccConfiguredAddressesRequest", "sgp22.EuiccConfiguredAddressesRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_EuiccConfiguredAddressesResponse_PDU,
      { "EuiccConfiguredAddressesResponse", "sgp22.EuiccConfiguredAddressesResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ISDRProprietaryApplicationTemplate_PDU,
      { "ISDRProprietaryApplicationTemplate", "sgp22.ISDRProprietaryApplicationTemplate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_LpaeActivationRequest_PDU,
      { "LpaeActivationRequest", "sgp22.LpaeActivationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_LpaeActivationResponse_PDU,
      { "LpaeActivationResponse", "sgp22.LpaeActivationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_SetDefaultDpAddressRequest_PDU,
      { "SetDefaultDpAddressRequest", "sgp22.SetDefaultDpAddressRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_SetDefaultDpAddressResponse_PDU,
      { "SetDefaultDpAddressResponse", "sgp22.SetDefaultDpAddressResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_AuthenticateClientResponseEs11_PDU,
      { "AuthenticateClientResponseEs11", "sgp22.AuthenticateClientResponseEs11",
        FT_UINT32, BASE_DEC, VALS(sgp22_AuthenticateClientResponseEs11_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_svn,
      { "svn", "sgp22.svn",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_euiccCiPKIdListForVerification,
      { "euiccCiPKIdListForVerification", "sgp22.euiccCiPKIdListForVerification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SubjectKeyIdentifier", HFILL }},
    { &hf_sgp22_euiccCiPKIdListForVerification_item,
      { "SubjectKeyIdentifier", "sgp22.SubjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccCiPKIdListForSigning,
      { "euiccCiPKIdListForSigning", "sgp22.euiccCiPKIdListForSigning",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SubjectKeyIdentifier", HFILL }},
    { &hf_sgp22_euiccCiPKIdListForSigning_item,
      { "SubjectKeyIdentifier", "sgp22.SubjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_profileVersion,
      { "profileVersion", "sgp22.profileVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_euiccFirmwareVer,
      { "euiccFirmwareVer", "sgp22.euiccFirmwareVer",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_extCardResource,
      { "extCardResource", "sgp22.extCardResource",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_uiccCapability,
      { "uiccCapability", "sgp22.uiccCapability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ts102241Version,
      { "ts102241Version", "sgp22.ts102241Version",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_globalplatformVersion,
      { "globalplatformVersion", "sgp22.globalplatformVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_rspCapability,
      { "rspCapability", "sgp22.rspCapability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccCategory,
      { "euiccCategory", "sgp22.euiccCategory",
        FT_INT32, BASE_DEC, VALS(sgp22_T_euiccCategory_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_forbiddenProfilePolicyRules,
      { "forbiddenProfilePolicyRules", "sgp22.forbiddenProfilePolicyRules",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PprIds", HFILL }},
    { &hf_sgp22_ppVersion,
      { "ppVersion", "sgp22.ppVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_sasAcreditationNumber,
      { "sasAcreditationNumber", "sgp22.sasAcreditationNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_64", HFILL }},
    { &hf_sgp22_certificationDataObject,
      { "certificationDataObject", "sgp22.certificationDataObject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_treProperties,
      { "treProperties", "sgp22.treProperties",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_treProductReference,
      { "treProductReference", "sgp22.treProductReference",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_additionalEuiccProfilePackageVersions,
      { "additionalEuiccProfilePackageVersions", "sgp22.additionalEuiccProfilePackageVersions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_VersionType", HFILL }},
    { &hf_sgp22_additionalEuiccProfilePackageVersions_item,
      { "VersionType", "sgp22.VersionType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_platformLabel,
      { "platformLabel", "sgp22.platformLabel",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_discoveryBaseURL,
      { "discoveryBaseURL", "sgp22.discoveryBaseURL",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_tac,
      { "tac", "sgp22.tac",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet4", HFILL }},
    { &hf_sgp22_deviceCapabilities,
      { "deviceCapabilities", "sgp22.deviceCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_imei,
      { "imei", "sgp22.imei",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet8", HFILL }},
    { &hf_sgp22_gsmSupportedRelease,
      { "gsmSupportedRelease", "sgp22.gsmSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_utranSupportedRelease,
      { "utranSupportedRelease", "sgp22.utranSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_cdma2000onexSupportedRelease,
      { "cdma2000onexSupportedRelease", "sgp22.cdma2000onexSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_cdma2000hrpdSupportedRelease,
      { "cdma2000hrpdSupportedRelease", "sgp22.cdma2000hrpdSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_cdma2000ehrpdSupportedRelease,
      { "cdma2000ehrpdSupportedRelease", "sgp22.cdma2000ehrpdSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_eutranEpcSupportedRelease,
      { "eutranEpcSupportedRelease", "sgp22.eutranEpcSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_contactlessSupportedRelease,
      { "contactlessSupportedRelease", "sgp22.contactlessSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_rspCrlSupportedVersion,
      { "rspCrlSupportedVersion", "sgp22.rspCrlSupportedVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_nrEpcSupportedRelease,
      { "nrEpcSupportedRelease", "sgp22.nrEpcSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_nr5gcSupportedRelease,
      { "nr5gcSupportedRelease", "sgp22.nr5gcSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_eutran5gcSupportedRelease,
      { "eutran5gcSupportedRelease", "sgp22.eutran5gcSupportedRelease",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_lpaSvn,
      { "lpaSvn", "sgp22.lpaSvn",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_catSupportedClasses,
      { "catSupportedClasses", "sgp22.catSupportedClasses",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccFormFactorType,
      { "euiccFormFactorType", "sgp22.euiccFormFactorType",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_deviceAdditionalFeatureSupport,
      { "deviceAdditionalFeatureSupport", "sgp22.deviceAdditionalFeatureSupport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_naiSupport,
      { "naiSupport", "sgp22.naiSupport",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp22_groupOfDeviceManufacturerOid,
      { "groupOfDeviceManufacturerOid", "sgp22.groupOfDeviceManufacturerOid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_sgp22_searchCriteria,
      { "searchCriteria", "sgp22.searchCriteria",
        FT_UINT32, BASE_DEC, VALS(sgp22_T_searchCriteria_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_isdpAid,
      { "isdpAid", "sgp22.isdpAid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OctetTo16", HFILL }},
    { &hf_sgp22_iccid,
      { "iccid", "sgp22.iccid",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_profileClass,
      { "profileClass", "sgp22.profileClass",
        FT_INT32, BASE_DEC, VALS(sgp22_ProfileClass_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_tagList,
      { "tagList", "sgp22.tagList",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_profileInfoListOk,
      { "profileInfoListOk", "sgp22.profileInfoListOk",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ProfileInfo", HFILL }},
    { &hf_sgp22_profileInfoListOk_item,
      { "ProfileInfo", "sgp22.ProfileInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_profileInfoListError,
      { "profileInfoListError", "sgp22.profileInfoListError",
        FT_INT32, BASE_DEC, VALS(sgp22_ProfileInfoListError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_profileState,
      { "profileState", "sgp22.profileState",
        FT_INT32, BASE_DEC, VALS(sgp22_ProfileState_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_profileNickname,
      { "profileNickname", "sgp22.profileNickname",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_64", HFILL }},
    { &hf_sgp22_serviceProviderName,
      { "serviceProviderName", "sgp22.serviceProviderName",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_32", HFILL }},
    { &hf_sgp22_profileName,
      { "profileName", "sgp22.profileName",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_64", HFILL }},
    { &hf_sgp22_iconType,
      { "iconType", "sgp22.iconType",
        FT_INT32, BASE_DEC, VALS(sgp22_IconType_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_icon,
      { "icon", "sgp22.icon",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_1024", HFILL }},
    { &hf_sgp22_notificationConfigurationInfo,
      { "notificationConfigurationInfo", "sgp22.notificationConfigurationInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NotificationConfigurationInformation", HFILL }},
    { &hf_sgp22_notificationConfigurationInfo_item,
      { "NotificationConfigurationInformation", "sgp22.NotificationConfigurationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_profileOwner,
      { "profileOwner", "sgp22.profileOwner_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperatorId", HFILL }},
    { &hf_sgp22_dpProprietaryData,
      { "dpProprietaryData", "sgp22.dpProprietaryData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_profilePolicyRules,
      { "profilePolicyRules", "sgp22.profilePolicyRules",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PprIds", HFILL }},
    { &hf_sgp22_serviceSpecificDataStoredInEuicc,
      { "serviceSpecificDataStoredInEuicc", "sgp22.serviceSpecificDataStoredInEuicc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VendorSpecificExtension", HFILL }},
    { &hf_sgp22_mccMnc,
      { "mccMnc", "sgp22.mccMnc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_sgp22_gid1,
      { "gid1", "sgp22.gid1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_gid2,
      { "gid2", "sgp22.gid2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_serviceSpecificDataNotStoredInEuicc,
      { "serviceSpecificDataNotStoredInEuicc", "sgp22.serviceSpecificDataNotStoredInEuicc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VendorSpecificExtension", HFILL }},
    { &hf_sgp22_profileManagementOperation,
      { "profileManagementOperation", "sgp22.profileManagementOperation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NotificationEvent", HFILL }},
    { &hf_sgp22_notificationAddress,
      { "notificationAddress", "sgp22.notificationAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_VendorSpecificExtension_item,
      { "VendorSpecificExtension item", "sgp22.VendorSpecificExtension_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_vendorOid,
      { "vendorOid", "sgp22.vendorOid",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_vendorSpecificData,
      { "vendorSpecificData", "sgp22.vendorSpecificData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_smdpSigned2,
      { "smdpSigned2", "sgp22.smdpSigned2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_smdpSignature2,
      { "smdpSignature2", "sgp22.smdpSignature2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_hashCc,
      { "hashCc", "sgp22.hashCc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet32", HFILL }},
    { &hf_sgp22_smdpCertificate,
      { "smdpCertificate", "sgp22.smdpCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp22_transactionId,
      { "transactionId", "sgp22.transactionId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_ccRequiredFlag,
      { "ccRequiredFlag", "sgp22.ccRequiredFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_sgp22_bppEuiccOtpk,
      { "bppEuiccOtpk", "sgp22.bppEuiccOtpk",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_downloadResponseOk,
      { "downloadResponseOk", "sgp22.downloadResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareDownloadResponseOk", HFILL }},
    { &hf_sgp22_downloadResponseError,
      { "downloadResponseError", "sgp22.downloadResponseError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareDownloadResponseError", HFILL }},
    { &hf_sgp22_euiccSigned2,
      { "euiccSigned2", "sgp22.euiccSigned2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccSignature2,
      { "euiccSignature2", "sgp22.euiccSignature2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_euiccOtpk,
      { "euiccOtpk", "sgp22.euiccOtpk",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_downloadErrorCode,
      { "downloadErrorCode", "sgp22.downloadErrorCode",
        FT_INT32, BASE_DEC, VALS(sgp22_DownloadErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_serverSigned1,
      { "serverSigned1", "sgp22.serverSigned1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_serverSignature1,
      { "serverSignature1", "sgp22.serverSignature1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_euiccCiPKIdToBeUsed,
      { "euiccCiPKIdToBeUsed", "sgp22.euiccCiPKIdToBeUsed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SubjectKeyIdentifier", HFILL }},
    { &hf_sgp22_serverCertificate,
      { "serverCertificate", "sgp22.serverCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp22_ctxParams1,
      { "ctxParams1", "sgp22.ctxParams1",
        FT_UINT32, BASE_DEC, VALS(sgp22_CtxParams1_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccChallenge,
      { "euiccChallenge", "sgp22.euiccChallenge",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet16", HFILL }},
    { &hf_sgp22_serverAddress,
      { "serverAddress", "sgp22.serverAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_serverChallenge,
      { "serverChallenge", "sgp22.serverChallenge",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet16", HFILL }},
    { &hf_sgp22_ctxParamsForCommonAuthentication,
      { "ctxParamsForCommonAuthentication", "sgp22.ctxParamsForCommonAuthentication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_matchingId,
      { "matchingId", "sgp22.matchingId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_deviceInfo,
      { "deviceInfo", "sgp22.deviceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateResponseOk,
      { "authenticateResponseOk", "sgp22.authenticateResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateResponseError,
      { "authenticateResponseError", "sgp22.authenticateResponseError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccSigned1,
      { "euiccSigned1", "sgp22.euiccSigned1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccSignature1,
      { "euiccSignature1", "sgp22.euiccSignature1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_euiccCertificate,
      { "euiccCertificate", "sgp22.euiccCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp22_eumCertificate,
      { "eumCertificate", "sgp22.eumCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp22_euiccInfo2,
      { "euiccInfo2", "sgp22.euiccInfo2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateErrorCode,
      { "authenticateErrorCode", "sgp22.authenticateErrorCode",
        FT_INT32, BASE_DEC, VALS(sgp22_AuthenticateErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_reason,
      { "reason", "sgp22.reason",
        FT_INT32, BASE_DEC, VALS(sgp22_CancelSessionReason_vals), 0,
        "CancelSessionReason", HFILL }},
    { &hf_sgp22_cancelSessionResponseOk,
      { "cancelSessionResponseOk", "sgp22.cancelSessionResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_cancelSessionResponseError,
      { "cancelSessionResponseError", "sgp22.cancelSessionResponseError",
        FT_INT32, BASE_DEC, VALS(sgp22_T_cancelSessionResponseError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccCancelSessionSigned,
      { "euiccCancelSessionSigned", "sgp22.euiccCancelSessionSigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccCancelSessionSignature,
      { "euiccCancelSessionSignature", "sgp22.euiccCancelSessionSignature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_smdpOid,
      { "smdpOid", "sgp22.smdpOid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_sgp22_initialiseSecureChannelRequest,
      { "initialiseSecureChannelRequest", "sgp22.initialiseSecureChannelRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_firstSequenceOf87,
      { "firstSequenceOf87", "sgp22.firstSequenceOf87",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_firstSequenceOf87_item,
      { "firstSequenceOf87 item", "sgp22.firstSequenceOf87_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_sequenceOf88,
      { "sequenceOf88", "sgp22.sequenceOf88",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_sequenceOf88_item,
      { "sequenceOf88 item", "sgp22.sequenceOf88_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_secondSequenceOf87,
      { "secondSequenceOf87", "sgp22.secondSequenceOf87",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_secondSequenceOf87_item,
      { "secondSequenceOf87 item", "sgp22.secondSequenceOf87_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_sequenceOf86,
      { "sequenceOf86", "sgp22.sequenceOf86",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_sequenceOf86_item,
      { "sequenceOf86 item", "sgp22.sequenceOf86_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_profileInstallationResultData,
      { "profileInstallationResultData", "sgp22.profileInstallationResultData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_euiccSignPIR,
      { "euiccSignPIR", "sgp22.euiccSignPIR",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_notificationMetadata,
      { "notificationMetadata", "sgp22.notificationMetadata_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_finalResult,
      { "finalResult", "sgp22.finalResult",
        FT_UINT32, BASE_DEC, VALS(sgp22_T_finalResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_successResult,
      { "successResult", "sgp22.successResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_errorResult,
      { "errorResult", "sgp22.errorResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_aid,
      { "aid", "sgp22.aid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_5_16", HFILL }},
    { &hf_sgp22_simaResponse,
      { "simaResponse", "sgp22.simaResponse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_bppCommandId,
      { "bppCommandId", "sgp22.bppCommandId",
        FT_INT32, BASE_DEC, VALS(sgp22_BppCommandId_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_errorReason,
      { "errorReason", "sgp22.errorReason",
        FT_INT32, BASE_DEC, VALS(sgp22_ErrorReason_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_notificationMetadataList,
      { "notificationMetadataList", "sgp22.notificationMetadataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NotificationMetadata", HFILL }},
    { &hf_sgp22_notificationMetadataList_item,
      { "NotificationMetadata", "sgp22.NotificationMetadata_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_listNotificationsResultError,
      { "listNotificationsResultError", "sgp22.listNotificationsResultError",
        FT_INT32, BASE_DEC, VALS(sgp22_T_listNotificationsResultError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_seqNumber,
      { "seqNumber", "sgp22.seqNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_sgp22_setNicknameResult,
      { "setNicknameResult", "sgp22.setNicknameResult",
        FT_INT32, BASE_DEC, VALS(sgp22_T_setNicknameResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_activationCodeForProfileRedownload,
      { "activationCodeForProfileRedownload", "sgp22.activationCodeForProfileRedownload",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_255", HFILL }},
    { &hf_sgp22_activationCodeRetrievalAvailable,
      { "activationCodeRetrievalAvailable", "sgp22.activationCodeRetrievalAvailable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_sgp22_retryDelay,
      { "retryDelay", "sgp22.retryDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_sgp22_remoteOpId,
      { "remoteOpId", "sgp22.remoteOpId",
        FT_INT32, BASE_DEC, VALS(sgp22_RemoteOpId_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_controlRefTemplate,
      { "controlRefTemplate", "sgp22.controlRefTemplate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_smdpOtpk,
      { "smdpOtpk", "sgp22.smdpOtpk",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_smdpSign,
      { "smdpSign", "sgp22.smdpSign",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_keyType,
      { "keyType", "sgp22.keyType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet1", HFILL }},
    { &hf_sgp22_keyLen,
      { "keyLen", "sgp22.keyLen",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet1", HFILL }},
    { &hf_sgp22_hostId,
      { "hostId", "sgp22.hostId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OctetTo16", HFILL }},
    { &hf_sgp22_dpOid,
      { "dpOid", "sgp22.dpOid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_sgp22_initialMacChainingValue,
      { "initialMacChainingValue", "sgp22.initialMacChainingValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_ppkEnc,
      { "ppkEnc", "sgp22.ppkEnc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_ppkCmac,
      { "ppkCmac", "sgp22.ppkCmac",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_searchCriteria_01,
      { "searchCriteria", "sgp22.searchCriteria",
        FT_UINT32, BASE_DEC, VALS(sgp22_T_searchCriteria_01_vals), 0,
        "T_searchCriteria_01", HFILL }},
    { &hf_sgp22_notificationList,
      { "notificationList", "sgp22.notificationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PendingNotification", HFILL }},
    { &hf_sgp22_notificationList_item,
      { "PendingNotification", "sgp22.PendingNotification",
        FT_UINT32, BASE_DEC, VALS(sgp22_PendingNotification_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_notificationsListResultError,
      { "notificationsListResultError", "sgp22.notificationsListResultError",
        FT_INT32, BASE_DEC, VALS(sgp22_T_notificationsListResultError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_profileInstallationResult,
      { "profileInstallationResult", "sgp22.profileInstallationResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_otherSignedNotification,
      { "otherSignedNotification", "sgp22.otherSignedNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_tbsOtherNotification,
      { "tbsOtherNotification", "sgp22.tbsOtherNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NotificationMetadata", HFILL }},
    { &hf_sgp22_euiccNotificationSignature,
      { "euiccNotificationSignature", "sgp22.euiccNotificationSignature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp22_deleteNotificationStatus,
      { "deleteNotificationStatus", "sgp22.deleteNotificationStatus",
        FT_INT32, BASE_DEC, VALS(sgp22_T_deleteNotificationStatus_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_profileIdentifier,
      { "profileIdentifier", "sgp22.profileIdentifier",
        FT_UINT32, BASE_DEC, VALS(sgp22_T_profileIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_refreshFlag,
      { "refreshFlag", "sgp22.refreshFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_sgp22_enableResult,
      { "enableResult", "sgp22.enableResult",
        FT_INT32, BASE_DEC, VALS(sgp22_T_enableResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_profileIdentifier_01,
      { "profileIdentifier", "sgp22.profileIdentifier",
        FT_UINT32, BASE_DEC, VALS(sgp22_T_profileIdentifier_01_vals), 0,
        "T_profileIdentifier_01", HFILL }},
    { &hf_sgp22_disableResult,
      { "disableResult", "sgp22.disableResult",
        FT_INT32, BASE_DEC, VALS(sgp22_T_disableResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_deleteResult,
      { "deleteResult", "sgp22.deleteResult",
        FT_INT32, BASE_DEC, VALS(sgp22_T_deleteResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_resetOptions,
      { "resetOptions", "sgp22.resetOptions",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_resetResult,
      { "resetResult", "sgp22.resetResult",
        FT_INT32, BASE_DEC, VALS(sgp22_T_resetResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_tagList_01,
      { "tagList", "sgp22.tagList",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet1", HFILL }},
    { &hf_sgp22_eidValue,
      { "eidValue", "sgp22.eidValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet16", HFILL }},
    { &hf_sgp22_rat,
      { "rat", "sgp22.rat",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RulesAuthorisationTable", HFILL }},
    { &hf_sgp22_RulesAuthorisationTable_item,
      { "ProfilePolicyAuthorisationRule", "sgp22.ProfilePolicyAuthorisationRule_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_pprIds,
      { "pprIds", "sgp22.pprIds",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_allowedOperators,
      { "allowedOperators", "sgp22.allowedOperators",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_OperatorId", HFILL }},
    { &hf_sgp22_allowedOperators_item,
      { "OperatorId", "sgp22.OperatorId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_pprFlags,
      { "pprFlags", "sgp22.pprFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_crl,
      { "crl", "sgp22.crl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateList", HFILL }},
    { &hf_sgp22_loadCRLResponseOk,
      { "loadCRLResponseOk", "sgp22.loadCRLResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_loadCRLResponseError,
      { "loadCRLResponseError", "sgp22.loadCRLResponseError",
        FT_INT32, BASE_DEC, VALS(sgp22_LoadCRLResponseError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_missingParts,
      { "missingParts", "sgp22.missingParts",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_missingParts_item,
      { "missingParts item", "sgp22.missingParts_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_sgp22_initiateAuthenticationRequest,
      { "initiateAuthenticationRequest", "sgp22.initiateAuthenticationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateClientRequest,
      { "authenticateClientRequest", "sgp22.authenticateClientRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_getBoundProfilePackageRequest,
      { "getBoundProfilePackageRequest", "sgp22.getBoundProfilePackageRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_cancelSessionRequestEs9,
      { "cancelSessionRequestEs9", "sgp22.cancelSessionRequestEs9_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_handleNotification,
      { "handleNotification", "sgp22.handleNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_initiateAuthenticationResponse,
      { "initiateAuthenticationResponse", "sgp22.initiateAuthenticationResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_InitiateAuthenticationResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateClientResponseEs9,
      { "authenticateClientResponseEs9", "sgp22.authenticateClientResponseEs9",
        FT_UINT32, BASE_DEC, VALS(sgp22_AuthenticateClientResponseEs9_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_getBoundProfilePackageResponse,
      { "getBoundProfilePackageResponse", "sgp22.getBoundProfilePackageResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_GetBoundProfilePackageResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_cancelSessionResponseEs9,
      { "cancelSessionResponseEs9", "sgp22.cancelSessionResponseEs9",
        FT_UINT32, BASE_DEC, VALS(sgp22_CancelSessionResponseEs9_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateClientResponseEs11,
      { "authenticateClientResponseEs11", "sgp22.authenticateClientResponseEs11",
        FT_UINT32, BASE_DEC, VALS(sgp22_AuthenticateClientResponseEs11_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_smdpAddress,
      { "smdpAddress", "sgp22.smdpAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_euiccInfo1,
      { "euiccInfo1", "sgp22.euiccInfo1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_initiateAuthenticationOk,
      { "initiateAuthenticationOk", "sgp22.initiateAuthenticationOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiateAuthenticationOkEs9", HFILL }},
    { &hf_sgp22_initiateAuthenticationError,
      { "initiateAuthenticationError", "sgp22.initiateAuthenticationError",
        FT_INT32, BASE_DEC, VALS(sgp22_T_initiateAuthenticationError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateServerResponse,
      { "authenticateServerResponse", "sgp22.authenticateServerResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_AuthenticateServerResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_useMatchingIdForAcr,
      { "useMatchingIdForAcr", "sgp22.useMatchingIdForAcr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateClientOk,
      { "authenticateClientOk", "sgp22.authenticateClientOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateClientError,
      { "authenticateClientError", "sgp22.authenticateClientError",
        FT_INT32, BASE_DEC, VALS(sgp22_T_authenticateClientError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_profileMetaData,
      { "profileMetaData", "sgp22.profileMetaData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StoreMetadataRequest", HFILL }},
    { &hf_sgp22_prepareDownloadResponse,
      { "prepareDownloadResponse", "sgp22.prepareDownloadResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_PrepareDownloadResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_getBoundProfilePackageOk,
      { "getBoundProfilePackageOk", "sgp22.getBoundProfilePackageOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_getBoundProfilePackageError,
      { "getBoundProfilePackageError", "sgp22.getBoundProfilePackageError",
        FT_INT32, BASE_DEC, VALS(sgp22_T_getBoundProfilePackageError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_boundProfilePackage,
      { "boundProfilePackage", "sgp22.boundProfilePackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_pendingNotification,
      { "pendingNotification", "sgp22.pendingNotification",
        FT_UINT32, BASE_DEC, VALS(sgp22_PendingNotification_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_cancelSessionResponse,
      { "cancelSessionResponse", "sgp22.cancelSessionResponse",
        FT_UINT32, BASE_DEC, VALS(sgp22_CancelSessionResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_cancelSessionOk,
      { "cancelSessionOk", "sgp22.cancelSessionOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_cancelSessionError,
      { "cancelSessionError", "sgp22.cancelSessionError",
        FT_INT32, BASE_DEC, VALS(sgp22_T_cancelSessionError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_defaultDpAddress,
      { "defaultDpAddress", "sgp22.defaultDpAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_rootDsAddress,
      { "rootDsAddress", "sgp22.rootDsAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_lpaeSupport,
      { "lpaeSupport", "sgp22.lpaeSupport",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_lpaeOption,
      { "lpaeOption", "sgp22.lpaeOption",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_lpaeActivationResult,
      { "lpaeActivationResult", "sgp22.lpaeActivationResult",
        FT_INT32, BASE_DEC, VALS(sgp22_T_lpaeActivationResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_setDefaultDpAddressResult,
      { "setDefaultDpAddressResult", "sgp22.setDefaultDpAddressResult",
        FT_INT32, BASE_DEC, VALS(sgp22_T_setDefaultDpAddressResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp22_authenticateClientOk_01,
      { "authenticateClientOk", "sgp22.authenticateClientOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticateClientOkEs11", HFILL }},
    { &hf_sgp22_authenticateClientError_01,
      { "authenticateClientError", "sgp22.authenticateClientError",
        FT_INT32, BASE_DEC, VALS(sgp22_T_authenticateClientError_01_vals), 0,
        "T_authenticateClientError_01", HFILL }},
    { &hf_sgp22_eventEntries,
      { "eventEntries", "sgp22.eventEntries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EventEntries", HFILL }},
    { &hf_sgp22_eventEntries_item,
      { "EventEntries", "sgp22.EventEntries_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp22_eventId,
      { "eventId", "sgp22.eventId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_rspServerAddress,
      { "rspServerAddress", "sgp22.rspServerAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp22_UICCCapability_contactlessSupport,
      { "contactlessSupport", "sgp22.UICCCapability.contactlessSupport",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_usimSupport,
      { "usimSupport", "sgp22.UICCCapability.usimSupport",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_isimSupport,
      { "isimSupport", "sgp22.UICCCapability.isimSupport",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_csimSupport,
      { "csimSupport", "sgp22.UICCCapability.csimSupport",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_akaMilenage,
      { "akaMilenage", "sgp22.UICCCapability.akaMilenage",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_akaCave,
      { "akaCave", "sgp22.UICCCapability.akaCave",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_akaTuak128,
      { "akaTuak128", "sgp22.UICCCapability.akaTuak128",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_akaTuak256,
      { "akaTuak256", "sgp22.UICCCapability.akaTuak256",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_usimTestAlgorithm,
      { "usimTestAlgorithm", "sgp22.UICCCapability.usimTestAlgorithm",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_rfu2,
      { "rfu2", "sgp22.UICCCapability.rfu2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_gbaAuthenUsim,
      { "gbaAuthenUsim", "sgp22.UICCCapability.gbaAuthenUsim",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_gbaAuthenISim,
      { "gbaAuthenISim", "sgp22.UICCCapability.gbaAuthenISim",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_mbmsAuthenUsim,
      { "mbmsAuthenUsim", "sgp22.UICCCapability.mbmsAuthenUsim",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_eapClient,
      { "eapClient", "sgp22.UICCCapability.eapClient",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_javacard,
      { "javacard", "sgp22.UICCCapability.javacard",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_multos,
      { "multos", "sgp22.UICCCapability.multos",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_multipleUsimSupport,
      { "multipleUsimSupport", "sgp22.UICCCapability.multipleUsimSupport",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_multipleIsimSupport,
      { "multipleIsimSupport", "sgp22.UICCCapability.multipleIsimSupport",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_multipleCsimSupport,
      { "multipleCsimSupport", "sgp22.UICCCapability.multipleCsimSupport",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_berTlvFileSupport,
      { "berTlvFileSupport", "sgp22.UICCCapability.berTlvFileSupport",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_dfLinkSupport,
      { "dfLinkSupport", "sgp22.UICCCapability.dfLinkSupport",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_catTp,
      { "catTp", "sgp22.UICCCapability.catTp",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_getIdentity,
      { "getIdentity", "sgp22.UICCCapability.getIdentity",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_profile_a_x25519,
      { "profile-a-x25519", "sgp22.UICCCapability.profile.a.x25519",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_profile_b_p256,
      { "profile-b-p256", "sgp22.UICCCapability.profile.b.p256",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_suciCalculatorApi,
      { "suciCalculatorApi", "sgp22.UICCCapability.suciCalculatorApi",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_dns_resolution,
      { "dns-resolution", "sgp22.UICCCapability.dns.resolution",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_scp11ac,
      { "scp11ac", "sgp22.UICCCapability.scp11ac",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_scp11c_authorization_mechanism,
      { "scp11c-authorization-mechanism", "sgp22.UICCCapability.scp11c.authorization.mechanism",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_s16mode,
      { "s16mode", "sgp22.UICCCapability.s16mode",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_eaka,
      { "eaka", "sgp22.UICCCapability.eaka",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_sgp22_UICCCapability_iotminimal,
      { "iotminimal", "sgp22.UICCCapability.iotminimal",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_sgp22_T_treProperties_isDiscrete,
      { "isDiscrete", "sgp22.T.treProperties.isDiscrete",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_T_treProperties_isIntegrated,
      { "isIntegrated", "sgp22.T.treProperties.isIntegrated",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_T_treProperties_usesRemoteMemory,
      { "usesRemoteMemory", "sgp22.T.treProperties.usesRemoteMemory",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_RspCapability_additionalProfile,
      { "additionalProfile", "sgp22.RspCapability.additionalProfile",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_RspCapability_crlSupport,
      { "crlSupport", "sgp22.RspCapability.crlSupport",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_RspCapability_rpmSupport,
      { "rpmSupport", "sgp22.RspCapability.rpmSupport",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_RspCapability_testProfileSupport,
      { "testProfileSupport", "sgp22.RspCapability.testProfileSupport",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp22_RspCapability_deviceInfoExtensibilitySupport,
      { "deviceInfoExtensibilitySupport", "sgp22.RspCapability.deviceInfoExtensibilitySupport",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp22_RspCapability_serviceSpecificDataSupport,
      { "serviceSpecificDataSupport", "sgp22.RspCapability.serviceSpecificDataSupport",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_sgp22_PprIds_pprUpdateControl,
      { "pprUpdateControl", "sgp22.PprIds.pprUpdateControl",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_PprIds_ppr1,
      { "ppr1", "sgp22.PprIds.ppr1",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_PprIds_ppr2,
      { "ppr2", "sgp22.PprIds.ppr2",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_NotificationEvent_notificationInstall,
      { "notificationInstall", "sgp22.NotificationEvent.notificationInstall",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_NotificationEvent_notificationEnable,
      { "notificationEnable", "sgp22.NotificationEvent.notificationEnable",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_NotificationEvent_notificationDisable,
      { "notificationDisable", "sgp22.NotificationEvent.notificationDisable",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_NotificationEvent_notificationDelete,
      { "notificationDelete", "sgp22.NotificationEvent.notificationDelete",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp22_T_resetOptions_deleteOperationalProfiles,
      { "deleteOperationalProfiles", "sgp22.T.resetOptions.deleteOperationalProfiles",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_T_resetOptions_deleteFieldLoadedTestProfiles,
      { "deleteFieldLoadedTestProfiles", "sgp22.T.resetOptions.deleteFieldLoadedTestProfiles",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_T_resetOptions_resetDefaultSmdpAddress,
      { "resetDefaultSmdpAddress", "sgp22.T.resetOptions.resetDefaultSmdpAddress",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp22_T_pprFlags_consentRequired,
      { "consentRequired", "sgp22.T.pprFlags.consentRequired",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_T_lpaeSupport_lpaeUsingCat,
      { "lpaeUsingCat", "sgp22.T.lpaeSupport.lpaeUsingCat",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_T_lpaeSupport_lpaeUsingScws,
      { "lpaeUsingScws", "sgp22.T.lpaeSupport.lpaeUsingScws",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp22_T_lpaeOption_activateCatBasedLpae,
      { "activateCatBasedLpae", "sgp22.T.lpaeOption.activateCatBasedLpae",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp22_T_lpaeOption_activateScwsBasedLpae,
      { "activateScwsBasedLpae", "sgp22.T.lpaeOption.activateScwsBasedLpae",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
  };

  static int *ett[] = {
    &ett_sgp22,
    &ett_sgp22_UICCCapability,
    &ett_sgp22_GetEuiccInfo1Request_U,
    &ett_sgp22_EUICCInfo1_U,
    &ett_sgp22_SEQUENCE_OF_SubjectKeyIdentifier,
    &ett_sgp22_GetEuiccInfo2Request_U,
    &ett_sgp22_EUICCInfo2_U,
    &ett_sgp22_T_treProperties,
    &ett_sgp22_SEQUENCE_OF_VersionType,
    &ett_sgp22_RspCapability,
    &ett_sgp22_CertificationDataObject,
    &ett_sgp22_DeviceInfo,
    &ett_sgp22_DeviceCapabilities,
    &ett_sgp22_DeviceAdditionalFeatureSupport,
    &ett_sgp22_ProfileInfoListRequest_U,
    &ett_sgp22_T_searchCriteria,
    &ett_sgp22_ProfileInfoListResponse_U,
    &ett_sgp22_SEQUENCE_OF_ProfileInfo,
    &ett_sgp22_ProfileInfo_U,
    &ett_sgp22_SEQUENCE_OF_NotificationConfigurationInformation,
    &ett_sgp22_PprIds,
    &ett_sgp22_OperatorId,
    &ett_sgp22_StoreMetadataRequest_U,
    &ett_sgp22_NotificationEvent,
    &ett_sgp22_NotificationConfigurationInformation,
    &ett_sgp22_VendorSpecificExtension,
    &ett_sgp22_VendorSpecificExtension_item,
    &ett_sgp22_UpdateMetadataRequest_U,
    &ett_sgp22_PrepareDownloadRequest_U,
    &ett_sgp22_SmdpSigned2,
    &ett_sgp22_PrepareDownloadResponse_U,
    &ett_sgp22_PrepareDownloadResponseOk,
    &ett_sgp22_EUICCSigned2,
    &ett_sgp22_PrepareDownloadResponseError,
    &ett_sgp22_AuthenticateServerRequest_U,
    &ett_sgp22_ServerSigned1,
    &ett_sgp22_CtxParams1,
    &ett_sgp22_CtxParamsForCommonAuthentication,
    &ett_sgp22_AuthenticateServerResponse_U,
    &ett_sgp22_AuthenticateResponseOk,
    &ett_sgp22_EuiccSigned1,
    &ett_sgp22_AuthenticateResponseError,
    &ett_sgp22_CancelSessionRequest_U,
    &ett_sgp22_CancelSessionResponse_U,
    &ett_sgp22_CancelSessionResponseOk,
    &ett_sgp22_EuiccCancelSessionSigned,
    &ett_sgp22_BoundProfilePackage_U,
    &ett_sgp22_T_firstSequenceOf87,
    &ett_sgp22_T_sequenceOf88,
    &ett_sgp22_T_secondSequenceOf87,
    &ett_sgp22_T_sequenceOf86,
    &ett_sgp22_GetEuiccChallengeRequest_U,
    &ett_sgp22_GetEuiccChallengeResponse_U,
    &ett_sgp22_ProfileInstallationResult_U,
    &ett_sgp22_ProfileInstallationResultData_U,
    &ett_sgp22_T_finalResult,
    &ett_sgp22_SuccessResult,
    &ett_sgp22_ErrorResult,
    &ett_sgp22_ListNotificationRequest_U,
    &ett_sgp22_ListNotificationResponse_U,
    &ett_sgp22_SEQUENCE_OF_NotificationMetadata,
    &ett_sgp22_NotificationMetadata_U,
    &ett_sgp22_SetNicknameRequest_U,
    &ett_sgp22_SetNicknameResponse_U,
    &ett_sgp22_ActivationCodeRetrievalInfo,
    &ett_sgp22_InitialiseSecureChannelRequest_U,
    &ett_sgp22_ControlRefTemplate,
    &ett_sgp22_ConfigureISDPRequest_U,
    &ett_sgp22_DpProprietaryData,
    &ett_sgp22_ReplaceSessionKeysRequest_U,
    &ett_sgp22_RetrieveNotificationsListRequest_U,
    &ett_sgp22_T_searchCriteria_01,
    &ett_sgp22_RetrieveNotificationsListResponse_U,
    &ett_sgp22_SEQUENCE_OF_PendingNotification,
    &ett_sgp22_PendingNotification,
    &ett_sgp22_OtherSignedNotification,
    &ett_sgp22_NotificationSentRequest_U,
    &ett_sgp22_NotificationSentResponse_U,
    &ett_sgp22_EnableProfileRequest_U,
    &ett_sgp22_T_profileIdentifier,
    &ett_sgp22_EnableProfileResponse_U,
    &ett_sgp22_DisableProfileRequest_U,
    &ett_sgp22_T_profileIdentifier_01,
    &ett_sgp22_DisableProfileResponse_U,
    &ett_sgp22_DeleteProfileRequest_U,
    &ett_sgp22_DeleteProfileResponse_U,
    &ett_sgp22_EuiccMemoryResetRequest_U,
    &ett_sgp22_T_resetOptions,
    &ett_sgp22_EuiccMemoryResetResponse_U,
    &ett_sgp22_GetEuiccDataRequest_U,
    &ett_sgp22_GetEuiccDataResponse_U,
    &ett_sgp22_GetRatRequest_U,
    &ett_sgp22_GetRatResponse_U,
    &ett_sgp22_RulesAuthorisationTable,
    &ett_sgp22_ProfilePolicyAuthorisationRule,
    &ett_sgp22_SEQUENCE_OF_OperatorId,
    &ett_sgp22_T_pprFlags,
    &ett_sgp22_LoadCRLRequest_U,
    &ett_sgp22_LoadCRLResponse_U,
    &ett_sgp22_LoadCRLResponseOk,
    &ett_sgp22_T_missingParts,
    &ett_sgp22_RemoteProfileProvisioningRequest_U,
    &ett_sgp22_RemoteProfileProvisioningResponse_U,
    &ett_sgp22_InitiateAuthenticationRequest_U,
    &ett_sgp22_InitiateAuthenticationResponse_U,
    &ett_sgp22_InitiateAuthenticationOkEs9,
    &ett_sgp22_AuthenticateClientRequest_U,
    &ett_sgp22_AuthenticateClientResponseEs9_U,
    &ett_sgp22_AuthenticateClientOk,
    &ett_sgp22_GetBoundProfilePackageRequest_U,
    &ett_sgp22_GetBoundProfilePackageResponse_U,
    &ett_sgp22_GetBoundProfilePackageOk,
    &ett_sgp22_HandleNotification_U,
    &ett_sgp22_CancelSessionRequestEs9_U,
    &ett_sgp22_CancelSessionResponseEs9_U,
    &ett_sgp22_CancelSessionOk,
    &ett_sgp22_EuiccConfiguredAddressesRequest_U,
    &ett_sgp22_EuiccConfiguredAddressesResponse_U,
    &ett_sgp22_ISDRProprietaryApplicationTemplate_U,
    &ett_sgp22_T_lpaeSupport,
    &ett_sgp22_LpaeActivationRequest_U,
    &ett_sgp22_T_lpaeOption,
    &ett_sgp22_LpaeActivationResponse_U,
    &ett_sgp22_SetDefaultDpAddressRequest_U,
    &ett_sgp22_SetDefaultDpAddressResponse_U,
    &ett_sgp22_AuthenticateClientResponseEs11_U,
    &ett_sgp22_AuthenticateClientOkEs11,
    &ett_sgp22_SEQUENCE_OF_EventEntries,
    &ett_sgp22_EventEntries,
  };

  proto_sgp22 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_sgp22, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sgp22_handle = register_dissector("sgp22", dissect_sgp22, proto_sgp22);

  register_dissector_table("sgp22.request", "SGP.22 Request", proto_sgp22, FT_UINT16, BASE_HEX);
  register_dissector_table("sgp22.response", "SGP.22 Response", proto_sgp22, FT_UINT16, BASE_HEX);
}

void proto_reg_handoff_sgp22(void)
{
  oid_add_from_string("id-rsp", id_rsp);
  oid_add_from_string("id-rsp-metadata", id_rsp_metadata);
  oid_add_from_string("id-rsp-metadata-serviceSpecificOIDs", id_rsp_metadata_serviceSpecificOIDs);
  oid_add_from_string("id-rsp-cert-objects", id_rsp_cert_objects);
  oid_add_from_string("id-rspExt", id_rspExt);
  oid_add_from_string("id-rspRole", id_rspRole);
  oid_add_from_string("id-rspRole-ci", id_rspRole_ci);
  oid_add_from_string("id-rspRole-euicc", id_rspRole_euicc);
  oid_add_from_string("id-rspRole-eum", id_rspRole_eum);
  oid_add_from_string("id-rspRole-dp-tls", id_rspRole_dp_tls);
  oid_add_from_string("id-rspRole-dp-auth", id_rspRole_dp_auth);
  oid_add_from_string("id-rspRole-dp-pb", id_rspRole_dp_pb);
  oid_add_from_string("id-rspRole-ds-tls", id_rspRole_ds_tls);
  oid_add_from_string("id-rspRole-ds-auth", id_rspRole_ds_auth);

  dissector_add_for_decode_as("media_type", sgp22_handle);

  register_ber_oid_dissector("2.23.146.1.2.0.1", dissect_ExpirationDate_PDU, proto_sgp22, "id-rsp-expDate");
  register_ber_oid_dissector("2.23.146.1.2.0.2", dissect_TotalPartialCrlNumber_PDU, proto_sgp22, "id-rsp-totalPartialCrlNumber");
  register_ber_oid_dissector("2.23.146.1.2.0.3", dissect_PartialCrlNumber_PDU, proto_sgp22, "id-rsp-partialCrlNumber");
  register_ber_oid_dissector("2.23.146.1.3.1.1", dissect_ActivationCodeRetrievalInfo_PDU, proto_sgp22, "id-rsp-metadata-activationCodeRetrievalInfo");
  dissector_add_uint("sgp22.request", 0xE0, create_dissector_handle(dissect_ISDRProprietaryApplicationTemplate_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xE3, create_dissector_handle(dissect_ProfileInfo_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF20, create_dissector_handle(dissect_GetEuiccInfo1Request_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF20, create_dissector_handle(dissect_EUICCInfo1_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF21, create_dissector_handle(dissect_PrepareDownloadRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF21, create_dissector_handle(dissect_PrepareDownloadResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF22, create_dissector_handle(dissect_GetEuiccInfo2Request_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF22, create_dissector_handle(dissect_EUICCInfo2_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF23, create_dissector_handle(dissect_InitialiseSecureChannelRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF24, create_dissector_handle(dissect_ConfigureISDPRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF25, create_dissector_handle(dissect_StoreMetadataRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF26, create_dissector_handle(dissect_ReplaceSessionKeysRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF28, create_dissector_handle(dissect_ListNotificationRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF28, create_dissector_handle(dissect_ListNotificationResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF29, create_dissector_handle(dissect_SetNicknameRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF29, create_dissector_handle(dissect_SetNicknameResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF2A, create_dissector_handle(dissect_UpdateMetadataRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF2B, create_dissector_handle(dissect_RetrieveNotificationsListRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF2B, create_dissector_handle(dissect_RetrieveNotificationsListResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF2D, create_dissector_handle(dissect_ProfileInfoListRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF2D, create_dissector_handle(dissect_ProfileInfoListResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF2E, create_dissector_handle(dissect_GetEuiccChallengeRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF2E, create_dissector_handle(dissect_GetEuiccChallengeResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF2F, create_dissector_handle(dissect_NotificationMetadata_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF30, create_dissector_handle(dissect_NotificationSentRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF30, create_dissector_handle(dissect_NotificationSentResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF31, create_dissector_handle(dissect_EnableProfileRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF31, create_dissector_handle(dissect_EnableProfileResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF32, create_dissector_handle(dissect_DisableProfileRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF32, create_dissector_handle(dissect_DisableProfileResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF33, create_dissector_handle(dissect_DeleteProfileRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF33, create_dissector_handle(dissect_DeleteProfileResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF34, create_dissector_handle(dissect_EuiccMemoryResetRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF34, create_dissector_handle(dissect_EuiccMemoryResetResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF35, create_dissector_handle(dissect_LoadCRLRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF35, create_dissector_handle(dissect_LoadCRLResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF36, create_dissector_handle(dissect_BoundProfilePackage_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF37, create_dissector_handle(dissect_ProfileInstallationResult_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF38, create_dissector_handle(dissect_AuthenticateServerRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF38, create_dissector_handle(dissect_AuthenticateServerResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF39, create_dissector_handle(dissect_InitiateAuthenticationRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF39, create_dissector_handle(dissect_InitiateAuthenticationResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF3A, create_dissector_handle(dissect_GetBoundProfilePackageRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF3A, create_dissector_handle(dissect_GetBoundProfilePackageResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF3B, create_dissector_handle(dissect_AuthenticateClientRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF3B, create_dissector_handle(dissect_AuthenticateClientResponseEs9_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF3C, create_dissector_handle(dissect_EuiccConfiguredAddressesRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF3C, create_dissector_handle(dissect_EuiccConfiguredAddressesResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF3D, create_dissector_handle(dissect_HandleNotification_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF3E, create_dissector_handle(dissect_GetEuiccDataRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF3E, create_dissector_handle(dissect_GetEuiccDataResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF3F, create_dissector_handle(dissect_SetDefaultDpAddressRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF3F, create_dissector_handle(dissect_SetDefaultDpAddressResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF40, create_dissector_handle(dissect_AuthenticateClientResponseEs11_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF41, create_dissector_handle(dissect_CancelSessionRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF41, create_dissector_handle(dissect_CancelSessionResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF42, create_dissector_handle(dissect_LpaeActivationRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF42, create_dissector_handle(dissect_LpaeActivationResponse_PDU, proto_sgp22));
  dissector_add_uint("sgp22.request", 0xBF43, create_dissector_handle(dissect_GetRatRequest_PDU, proto_sgp22));
  dissector_add_uint("sgp22.response", 0xBF43, create_dissector_handle(dissect_GetRatResponse_PDU, proto_sgp22));

}
