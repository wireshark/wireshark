/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-sgp32.c                                                             */
/* asn2wrs.py -b -q -L -p sgp32 -c ./sgp32.cnf -s ./packet-sgp32-template -D . -O ../.. SGP32Definitions.asn */

/* packet-sgp32.c
 * Routines for SGP.32 packet dissection.
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

#include "packet-ber.h"
#include "packet-media-type.h"
#include "packet-e212.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-sgp22.h"
#include "packet-sgp32.h"

#define PNAME  "SGP.32 GSMA Remote SIM Provisioning (RSP)"
#define PSNAME "SGP.32"
#define PFNAME "sgp32"

void proto_register_sgp32(void);
void proto_reg_handoff_sgp32(void);

static int proto_sgp32;
static int hf_sgp32_EuiccPackageRequest_PDU;      /* EuiccPackageRequest */
static int hf_sgp32_IpaEuiccDataRequest_PDU;      /* IpaEuiccDataRequest */
static int hf_sgp32_ProfileDownloadTriggerRequest_PDU;  /* ProfileDownloadTriggerRequest */
static int hf_sgp32_ProfileDownloadData_PDU;      /* ProfileDownloadData */
static int hf_sgp32_EimAcknowledgements_PDU;      /* EimAcknowledgements */
static int hf_sgp32_EuiccPackageResult_PDU;       /* EuiccPackageResult */
static int hf_sgp32_IpaEuiccDataResponse_PDU;     /* IpaEuiccDataResponse */
static int hf_sgp32_sgp32_ISDRProprietaryApplicationTemplateIoT_PDU;  /* ISDRProprietaryApplicationTemplateIoT */
static int hf_sgp32_IpaeActivationRequest_PDU;    /* IpaeActivationRequest */
static int hf_sgp32_IpaeActivationResponse_PDU;   /* IpaeActivationResponse */
static int hf_sgp32_AddInitialEimRequest_PDU;     /* AddInitialEimRequest */
static int hf_sgp32_AddInitialEimResponse_PDU;    /* AddInitialEimResponse */
static int hf_sgp32_EuiccMemoryResetRequest_PDU;  /* EuiccMemoryResetRequest */
static int hf_sgp32_EuiccMemoryResetResponse_PDU;  /* EuiccMemoryResetResponse */
static int hf_sgp32_GetCertsRequest_PDU;          /* GetCertsRequest */
static int hf_sgp32_GetCertsResponse_PDU;         /* GetCertsResponse */
static int hf_sgp32_RetrieveNotificationsListRequest_PDU;  /* RetrieveNotificationsListRequest */
static int hf_sgp32_RetrieveNotificationsListResponse_PDU;  /* RetrieveNotificationsListResponse */
static int hf_sgp32_ImmediateEnableRequest_PDU;   /* ImmediateEnableRequest */
static int hf_sgp32_ImmediateEnableResponse_PDU;  /* ImmediateEnableResponse */
static int hf_sgp32_ProfileRollbackRequest_PDU;   /* ProfileRollbackRequest */
static int hf_sgp32_ProfileRollbackResponse_PDU;  /* ProfileRollbackResponse */
static int hf_sgp32_ConfigureImmediateProfileEnablingRequest_PDU;  /* ConfigureImmediateProfileEnablingRequest */
static int hf_sgp32_ConfigureImmediateProfileEnablingResponse_PDU;  /* ConfigureImmediateProfileEnablingResponse */
static int hf_sgp32_GetEimConfigurationDataRequest_PDU;  /* GetEimConfigurationDataRequest */
static int hf_sgp32_GetEimConfigurationDataResponse_PDU;  /* GetEimConfigurationDataResponse */
static int hf_sgp32_ExecuteFallbackMechanismRequest_PDU;  /* ExecuteFallbackMechanismRequest */
static int hf_sgp32_ExecuteFallbackMechanismResponse_PDU;  /* ExecuteFallbackMechanismResponse */
static int hf_sgp32_ReturnFromFallbackRequest_PDU;  /* ReturnFromFallbackRequest */
static int hf_sgp32_ReturnFromFallbackResponse_PDU;  /* ReturnFromFallbackResponse */
static int hf_sgp32_EnableEmergencyProfileRequest_PDU;  /* EnableEmergencyProfileRequest */
static int hf_sgp32_EnableEmergencyProfileResponse_PDU;  /* EnableEmergencyProfileResponse */
static int hf_sgp32_DisableEmergencyProfileRequest_PDU;  /* DisableEmergencyProfileRequest */
static int hf_sgp32_DisableEmergencyProfileResponse_PDU;  /* DisableEmergencyProfileResponse */
static int hf_sgp32_GetConnectivityParametersRequest_PDU;  /* GetConnectivityParametersRequest */
static int hf_sgp32_GetConnectivityParametersResponse_PDU;  /* GetConnectivityParametersResponse */
static int hf_sgp32_SetDefaultDpAddressRequest_PDU;  /* SetDefaultDpAddressRequest */
static int hf_sgp32_SetDefaultDpAddressResponse_PDU;  /* SetDefaultDpAddressResponse */
static int hf_sgp32_EsipaMessageFromIpaToEim_PDU;  /* EsipaMessageFromIpaToEim */
static int hf_sgp32_EsipaMessageFromEimToIpa_PDU;  /* EsipaMessageFromEimToIpa */
static int hf_sgp32_InitiateAuthenticationRequestEsipa_PDU;  /* InitiateAuthenticationRequestEsipa */
static int hf_sgp32_InitiateAuthenticationResponseEsipa_PDU;  /* InitiateAuthenticationResponseEsipa */
static int hf_sgp32_AuthenticateClientRequestEsipa_PDU;  /* AuthenticateClientRequestEsipa */
static int hf_sgp32_AuthenticateClientResponseEsipa_PDU;  /* AuthenticateClientResponseEsipa */
static int hf_sgp32_GetBoundProfilePackageRequestEsipa_PDU;  /* GetBoundProfilePackageRequestEsipa */
static int hf_sgp32_GetBoundProfilePackageResponseEsipa_PDU;  /* GetBoundProfilePackageResponseEsipa */
static int hf_sgp32_HandleNotificationEsipa_PDU;  /* HandleNotificationEsipa */
static int hf_sgp32_CancelSessionRequestEsipa_PDU;  /* CancelSessionRequestEsipa */
static int hf_sgp32_CancelSessionResponseEsipa_PDU;  /* CancelSessionResponseEsipa */
static int hf_sgp32_GetEimPackageRequest_PDU;     /* GetEimPackageRequest */
static int hf_sgp32_GetEimPackageResponse_PDU;    /* GetEimPackageResponse */
static int hf_sgp32_ProvideEimPackageResult_PDU;  /* ProvideEimPackageResult */
static int hf_sgp32_ProvideEimPackageResultResponse_PDU;  /* ProvideEimPackageResultResponse */
static int hf_sgp32_TransferEimPackageRequest_PDU;  /* TransferEimPackageRequest */
static int hf_sgp32_TransferEimPackageResponse_PDU;  /* TransferEimPackageResponse */
static int hf_sgp32_euiccPackageSigned;           /* EuiccPackageSigned */
static int hf_sgp32_eimSignature;                 /* OCTET_STRING */
static int hf_sgp32_eimId;                        /* UTF8String_SIZE_1_128 */
static int hf_sgp32_eidValue;                     /* Octet16 */
static int hf_sgp32_counterValue;                 /* INTEGER */
static int hf_sgp32_eimTransactionId;             /* TransactionId */
static int hf_sgp32_euiccPackage;                 /* EuiccPackage */
static int hf_sgp32_psmoList;                     /* SEQUENCE_OF_Psmo */
static int hf_sgp32_psmoList_item;                /* Psmo */
static int hf_sgp32_ecoList;                      /* SEQUENCE_OF_Eco */
static int hf_sgp32_ecoList_item;                 /* Eco */
static int hf_sgp32_eimFqdn;                      /* UTF8String */
static int hf_sgp32_eimIdType;                    /* EimIdType */
static int hf_sgp32_associationToken;             /* INTEGER */
static int hf_sgp32_eimPublicKeyData;             /* T_eimPublicKeyData */
static int hf_sgp32_eimPublicKey;                 /* SubjectPublicKeyInfo */
static int hf_sgp32_eimCertificate;               /* Certificate */
static int hf_sgp32_trustedPublicKeyDataTls;      /* T_trustedPublicKeyDataTls */
static int hf_sgp32_trustedEimPkTls;              /* SubjectPublicKeyInfo */
static int hf_sgp32_trustedCertificateTls;        /* Certificate */
static int hf_sgp32_eimSupportedProtocol;         /* EimSupportedProtocol */
static int hf_sgp32_euiccCiPKId;                  /* SubjectKeyIdentifier */
static int hf_sgp32_indirectProfileDownload;      /* NULL */
static int hf_sgp32_addEim;                       /* EimConfigurationData */
static int hf_sgp32_deleteEim;                    /* T_deleteEim */
static int hf_sgp32_eimId_01;                     /* UTF8String */
static int hf_sgp32_updateEim;                    /* EimConfigurationData */
static int hf_sgp32_listEim;                      /* T_listEim */
static int hf_sgp32_enable;                       /* T_enable */
static int hf_sgp32_iccid;                        /* Iccid */
static int hf_sgp32_rollbackFlag;                 /* NULL */
static int hf_sgp32_disable;                      /* T_disable */
static int hf_sgp32_delete;                       /* T_delete */
static int hf_sgp32_listProfileInfo;              /* ProfileInfoListRequest */
static int hf_sgp32_getRAT;                       /* T_getRAT */
static int hf_sgp32_configureImmediateEnable;     /* T_configureImmediateEnable */
static int hf_sgp32_immediateEnableFlag;          /* NULL */
static int hf_sgp32_defaultSmdpOid;               /* OBJECT_IDENTIFIER */
static int hf_sgp32_defaultSmdpAddress;           /* UTF8String */
static int hf_sgp32_setFallbackAttribute;         /* T_setFallbackAttribute */
static int hf_sgp32_unsetFallbackAttribute;       /* T_unsetFallbackAttribute */
static int hf_sgp32_setDefaultDpAddress;          /* SetDefaultDpAddressRequest */
static int hf_sgp32_tagList;                      /* OCTET_STRING */
static int hf_sgp32_euiccCiPKIdentifierToBeUsed;  /* OCTET_STRING */
static int hf_sgp32_searchCriteriaNotification;   /* T_searchCriteriaNotification */
static int hf_sgp32_seqNumber;                    /* INTEGER */
static int hf_sgp32_profileManagementOperation;   /* NotificationEvent */
static int hf_sgp32_searchCriteriaEuiccPackageResult;  /* T_searchCriteriaEuiccPackageResult */
static int hf_sgp32_profileDownloadData;          /* ProfileDownloadData */
static int hf_sgp32_activationCode;               /* UTF8String_SIZE_0_255 */
static int hf_sgp32_contactDefaultSmdp;           /* NULL */
static int hf_sgp32_contactSmds;                  /* T_contactSmds */
static int hf_sgp32_smdsAddress;                  /* UTF8String */
static int hf_sgp32__untag_item;                  /* SequenceNumber */
static int hf_sgp32_euiccPackageResultSigned;     /* EuiccPackageResultSigned */
static int hf_sgp32_euiccPackageErrorSigned;      /* EuiccPackageErrorSigned */
static int hf_sgp32_euiccPackageErrorUnsigned;    /* EuiccPackageErrorUnsigned */
static int hf_sgp32_euiccPackageResultDataSigned;  /* EuiccPackageResultDataSigned */
static int hf_sgp32_euiccSignEPR;                 /* OCTET_STRING */
static int hf_sgp32_euiccResult;                  /* SEQUENCE_OF_EuiccResultData */
static int hf_sgp32_euiccResult_item;             /* EuiccResultData */
static int hf_sgp32_enableResult;                 /* EnableProfileResult */
static int hf_sgp32_disableResult;                /* DisableProfileResult */
static int hf_sgp32_deleteResult;                 /* DeleteProfileResult */
static int hf_sgp32_listProfileInfoResult;        /* ProfileInfoListResponse */
static int hf_sgp32_getRATResult;                 /* RulesAuthorisationTable */
static int hf_sgp32_configureImmediateEnableResult;  /* ConfigureImmediateEnableResult */
static int hf_sgp32_addEimResult;                 /* AddEimResult */
static int hf_sgp32_deleteEimResult;              /* DeleteEimResult */
static int hf_sgp32_updateEimResult;              /* UpdateEimResult */
static int hf_sgp32_listEimResult;                /* ListEimResult */
static int hf_sgp32_rollbackResult;               /* RollbackProfileResult */
static int hf_sgp32_setFallbackAttributeResult;   /* SetFallbackAttributeResult */
static int hf_sgp32_unsetFallbackAttributeResult;  /* UnsetFallbackAttributeResult */
static int hf_sgp32_processingTerminated;         /* T_processingTerminated */
static int hf_sgp32_setDefaultDpAddressResult;    /* SetDefaultDpAddressResponse */
static int hf_sgp32_euiccPackageErrorDataSigned;  /* EuiccPackageErrorDataSigned */
static int hf_sgp32_euiccSignEPE;                 /* OCTET_STRING */
static int hf_sgp32_euiccPackageErrorCode;        /* EuiccPackageErrorCode */
static int hf_sgp32_profileInfoListOk;            /* SEQUENCE_OF_ProfileInfo */
static int hf_sgp32_profileInfoListOk_item;       /* ProfileInfo */
static int hf_sgp32_profileInfoListError;         /* ProfileInfoListError */
static int hf_sgp32_addEimResultCode;             /* T_addEimResultCode */
static int hf_sgp32_eimIdList;                    /* SEQUENCE_OF_EimIdInfo */
static int hf_sgp32_eimIdList_item;               /* EimIdInfo */
static int hf_sgp32_listEimError;                 /* T_listEimError */
static int hf_sgp32_ipaEuiccDataErrorCode;        /* IpaEuiccDataErrorCode */
static int hf_sgp32_ipaEuiccData;                 /* IpaEuiccData */
static int hf_sgp32_ipaEuiccDataResponseError;    /* IpaEuiccDataResponseError */
static int hf_sgp32_PendingNotificationList_item;  /* PendingNotification */
static int hf_sgp32_EuiccPackageResultList_item;  /* EuiccPackageResult */
static int hf_sgp32_notificationsList;            /* PendingNotificationList */
static int hf_sgp32_euiccPackageResultList;       /* EuiccPackageResultList */
static int hf_sgp32_euiccInfo1;                   /* EUICCInfo1 */
static int hf_sgp32_euiccInfo2;                   /* EUICCInfo2 */
static int hf_sgp32_rootSmdsAddress;              /* UTF8String */
static int hf_sgp32_eumCertificate;               /* Certificate */
static int hf_sgp32_euiccCertificate;             /* Certificate */
static int hf_sgp32_ipaCapabilities;              /* IpaCapabilities */
static int hf_sgp32_deviceInfo;                   /* DeviceInfo */
static int hf_sgp32_profileDownloadTriggerResultData;  /* T_profileDownloadTriggerResultData */
static int hf_sgp32_profileInstallationResult;    /* ProfileInstallationResult */
static int hf_sgp32_profileDownloadError;         /* T_profileDownloadError */
static int hf_sgp32_profileDownloadErrorReason;   /* T_profileDownloadErrorReason */
static int hf_sgp32_errorResponse;                /* OCTET_STRING */
static int hf_sgp32_euiccConfiguration;           /* T_euiccConfiguration */
static int hf_sgp32_ipaeOption;                   /* T_ipaeOption */
static int hf_sgp32_ipaeActivationResult;         /* T_ipaeActivationResult */
static int hf_sgp32_ipaFeatures;                  /* T_ipaFeatures */
static int hf_sgp32_ipaSupportedProtocols;        /* T_ipaSupportedProtocols */
static int hf_sgp32_isdpAid;                      /* OctetTo16 */
static int hf_sgp32_profileState;                 /* ProfileState */
static int hf_sgp32_profileNickname;              /* UTF8String_SIZE_0_64 */
static int hf_sgp32_serviceProviderName;          /* UTF8String_SIZE_0_32 */
static int hf_sgp32_profileName;                  /* UTF8String_SIZE_0_64 */
static int hf_sgp32_iconType;                     /* IconType */
static int hf_sgp32_icon;                         /* OCTET_STRING_SIZE_0_1024 */
static int hf_sgp32_profileClass;                 /* ProfileClass */
static int hf_sgp32_notificationConfigurationInfo;  /* SEQUENCE_OF_NotificationConfigurationInformation */
static int hf_sgp32_notificationConfigurationInfo_item;  /* NotificationConfigurationInformation */
static int hf_sgp32_profileOwner;                 /* OperatorId */
static int hf_sgp32_dpProprietaryData;            /* DpProprietaryData */
static int hf_sgp32_profilePolicyRules;           /* PprIds */
static int hf_sgp32_serviceSpecificDataStoredInEuicc;  /* VendorSpecificExtension */
static int hf_sgp32_ecallIndication;              /* BOOLEAN */
static int hf_sgp32_fallbackAttribute;            /* BOOLEAN */
static int hf_sgp32_fallbackAllowed;              /* BOOLEAN */
static int hf_sgp32_serviceSpecificDataNotStoredInEuicc;  /* VendorSpecificExtension */
static int hf_sgp32_profileVersion;               /* VersionType */
static int hf_sgp32_svn;                          /* VersionType */
static int hf_sgp32_euiccFirmwareVer;             /* VersionType */
static int hf_sgp32_extCardResource;              /* OCTET_STRING */
static int hf_sgp32_uiccCapability;               /* UICCCapability */
static int hf_sgp32_ts102241Version;              /* VersionType */
static int hf_sgp32_globalplatformVersion;        /* VersionType */
static int hf_sgp32_rspCapability;                /* RspCapability */
static int hf_sgp32_euiccCiPKIdListForVerification;  /* SEQUENCE_OF_SubjectKeyIdentifier */
static int hf_sgp32_euiccCiPKIdListForVerification_item;  /* SubjectKeyIdentifier */
static int hf_sgp32_euiccCiPKIdListForSigning;    /* SEQUENCE_OF_SubjectKeyIdentifier */
static int hf_sgp32_euiccCiPKIdListForSigning_item;  /* SubjectKeyIdentifier */
static int hf_sgp32_euiccCategory;                /* T_euiccCategory */
static int hf_sgp32_forbiddenProfilePolicyRules;  /* PprIds */
static int hf_sgp32_ppVersion;                    /* VersionType */
static int hf_sgp32_sasAcreditationNumber;        /* UTF8String_SIZE_0_64 */
static int hf_sgp32_certificationDataObject;      /* CertificationDataObject */
static int hf_sgp32_treProperties;                /* T_treProperties */
static int hf_sgp32_treProductReference;          /* UTF8String */
static int hf_sgp32_additionalEuiccProfilePackageVersions;  /* SEQUENCE_OF_VersionType */
static int hf_sgp32_additionalEuiccProfilePackageVersions_item;  /* VersionType */
static int hf_sgp32_ipaMode;                      /* IpaMode */
static int hf_sgp32_euiccCiPKIdListForSigningV3;  /* SEQUENCE_OF_SubjectKeyIdentifier */
static int hf_sgp32_euiccCiPKIdListForSigningV3_item;  /* SubjectKeyIdentifier */
static int hf_sgp32_additionalEuiccInfo;          /* OCTET_STRING_SIZE_0_32 */
static int hf_sgp32_highestSvn;                   /* VersionType */
static int hf_sgp32_iotSpecificInfo;              /* IoTSpecificInfo */
static int hf_sgp32_iotVersion;                   /* SEQUENCE_OF_VersionType */
static int hf_sgp32_iotVersion_item;              /* VersionType */
static int hf_sgp32_ecallSupported;               /* NULL */
static int hf_sgp32_fallbackSupported;            /* NULL */
static int hf_sgp32_eimConfigurationDataList;     /* SEQUENCE_OF_EimConfigurationData */
static int hf_sgp32_eimConfigurationDataList_item;  /* EimConfigurationData */
static int hf_sgp32_addInitialEimOk;              /* T_addInitialEimOk */
static int hf_sgp32_addInitialEimOk_item;         /* T_addInitialEimOk_item */
static int hf_sgp32_addOk;                        /* NULL */
static int hf_sgp32_addInitialEimError;           /* T_addInitialEimError */
static int hf_sgp32_resetOptions;                 /* T_resetOptions */
static int hf_sgp32_resetResult;                  /* T_resetResult */
static int hf_sgp32_resetEimResult;               /* T_resetEimResult */
static int hf_sgp32_resetImmediateEnableConfigResult;  /* T_resetImmediateEnableConfigResult */
static int hf_sgp32_certs;                        /* T_certs */
static int hf_sgp32_getCertsError;                /* T_getCertsError */
static int hf_sgp32_searchCriteria;               /* T_searchCriteria */
static int hf_sgp32_euiccPackageResults;          /* NULL */
static int hf_sgp32_notificationList;             /* PendingNotificationList */
static int hf_sgp32_notificationsListResultError;  /* T_notificationsListResultError */
static int hf_sgp32_refreshFlag;                  /* BOOLEAN */
static int hf_sgp32_immediateEnableResult;        /* T_immediateEnableResult */
static int hf_sgp32_cmdResult;                    /* T_cmdResult */
static int hf_sgp32_eUICCPackageResult;           /* EuiccPackageResult */
static int hf_sgp32_configImmediateEnableResult;  /* T_configImmediateEnableResult */
static int hf_sgp32_searchCriteria_01;            /* T_searchCriteria_01 */
static int hf_sgp32_executeFallbackMechanismResult;  /* T_executeFallbackMechanismResult */
static int hf_sgp32_returnFromFallbackResult;     /* T_returnFromFallbackResult */
static int hf_sgp32_enableEmergencyProfileResult;  /* T_enableEmergencyProfileResult */
static int hf_sgp32_disableEmergencyProfileResult;  /* T_disableEmergencyProfileResult */
static int hf_sgp32_connectivityParameters;       /* ConnectivityParameters */
static int hf_sgp32_connectivityParametersError;  /* ConnectivityParametersError */
static int hf_sgp32_httpParams;                   /* OCTET_STRING */
static int hf_sgp32_defaultDpAddress;             /* UTF8String */
static int hf_sgp32_setDefaultDpAddressResult_01;  /* T_setDefaultDpAddressResult */
static int hf_sgp32_downloadResponseOk;           /* PrepareDownloadResponseOk */
static int hf_sgp32_downloadResponseError;        /* PrepareDownloadResponseError */
static int hf_sgp32_compactDownloadResponseOk;    /* CompactPrepareDownloadResponseOk */
static int hf_sgp32_compactEuiccSigned2;          /* CompactEuiccSigned2 */
static int hf_sgp32_euiccSignature2;              /* OCTET_STRING */
static int hf_sgp32_euiccOtpk;                    /* OCTET_STRING */
static int hf_sgp32_hashCc;                       /* Octet32 */
static int hf_sgp32_transactionId;                /* TransactionId */
static int hf_sgp32_serverAddress;                /* UTF8String */
static int hf_sgp32_serverChallenge;              /* Octet16 */
static int hf_sgp32_ctxParams1;                   /* CtxParams1 */
static int hf_sgp32_euiccSigned1;                 /* EuiccSigned1 */
static int hf_sgp32_euiccSignature1;              /* OCTET_STRING */
static int hf_sgp32_authenticateResponseOk;       /* AuthenticateResponseOk */
static int hf_sgp32_authenticateResponseError;    /* AuthenticateResponseError */
static int hf_sgp32_compactAuthenticateResponseOk;  /* CompactAuthenticateResponseOk */
static int hf_sgp32_signedData;                   /* T_signedData */
static int hf_sgp32_compactEuiccSigned1;          /* CompactEuiccSigned1 */
static int hf_sgp32_otherSignedNotification;      /* OtherSignedNotification */
static int hf_sgp32_compactProfileInstallationResult;  /* CompactProfileInstallationResult */
static int hf_sgp32_compactOtherSignedNotification;  /* CompactOtherSignedNotification */
static int hf_sgp32_profileInstallationResultData;  /* ProfileInstallationResultData */
static int hf_sgp32_euiccSignPIR;                 /* EuiccSignPIR */
static int hf_sgp32_compactProfileInstallationResultData;  /* CompactProfileInstallationResultData */
static int hf_sgp32_iccidPresent;                 /* BOOLEAN */
static int hf_sgp32_compactFinalResult;           /* T_compactFinalResult */
static int hf_sgp32_compactSuccessResult;         /* CompactSuccessResult */
static int hf_sgp32_errorResult;                  /* ErrorResult */
static int hf_sgp32_compactAid;                   /* OCTET_STRING_SIZE_2 */
static int hf_sgp32_simaResponse;                 /* OCTET_STRING */
static int hf_sgp32_tbsOtherNotification;         /* NotificationMetadata */
static int hf_sgp32_euiccNotificationSignature;   /* OCTET_STRING */
static int hf_sgp32_cancelSessionResponseOk;      /* CancelSessionResponseOk */
static int hf_sgp32_cancelSessionResponseError;   /* T_cancelSessionResponseError */
static int hf_sgp32_compactCancelSessionResponseOk;  /* CompactCancelSessionResponseOk */
static int hf_sgp32_compactEuiccCancelSessionSigned;  /* CompactEuiccCancelSessionSigned */
static int hf_sgp32_euiccCancelSessionSignature;  /* OCTET_STRING */
static int hf_sgp32_reason;                       /* CancelSessionReason */
static int hf_sgp32_initiateAuthenticationRequestEsipa;  /* InitiateAuthenticationRequestEsipa */
static int hf_sgp32_authenticateClientRequestEsipa;  /* AuthenticateClientRequestEsipa */
static int hf_sgp32_getBoundProfilePackageRequestEsipa;  /* GetBoundProfilePackageRequestEsipa */
static int hf_sgp32_cancelSessionRequestEsipa;    /* CancelSessionRequestEsipa */
static int hf_sgp32_handleNotificationEsipa;      /* HandleNotificationEsipa */
static int hf_sgp32_transferEimPackageResponse;   /* TransferEimPackageResponse */
static int hf_sgp32_getEimPackageRequest;         /* GetEimPackageRequest */
static int hf_sgp32_provideEimPackageResult;      /* ProvideEimPackageResult */
static int hf_sgp32_initiateAuthenticationResponseEsipa;  /* InitiateAuthenticationResponseEsipa */
static int hf_sgp32_authenticateClientResponseEsipa;  /* AuthenticateClientResponseEsipa */
static int hf_sgp32_getBoundProfilePackageResponseEsipa;  /* GetBoundProfilePackageResponseEsipa */
static int hf_sgp32_cancelSessionResponseEsipa;   /* CancelSessionResponseEsipa */
static int hf_sgp32_transferEimPackageRequest;    /* TransferEimPackageRequest */
static int hf_sgp32_getEimPackageResponse;        /* GetEimPackageResponse */
static int hf_sgp32_provideEimPackageResultResponse;  /* ProvideEimPackageResultResponse */
static int hf_sgp32_euiccChallenge;               /* Octet16 */
static int hf_sgp32_smdpAddress;                  /* UTF8String */
static int hf_sgp32_initiateAuthenticationOkEsipa;  /* InitiateAuthenticationOkEsipa */
static int hf_sgp32_initiateAuthenticationErrorEsipa;  /* T_initiateAuthenticationErrorEsipa */
static int hf_sgp32_serverSigned1;                /* ServerSigned1 */
static int hf_sgp32_serverSignature1;             /* OCTET_STRING */
static int hf_sgp32_serverCertificate;            /* Certificate */
static int hf_sgp32_matchingId;                   /* UTF8String */
static int hf_sgp32_authenticateServerResponse;   /* AuthenticateServerResponse */
static int hf_sgp32_authenticateClientOkDPEsipa;  /* AuthenticateClientOkDPEsipa */
static int hf_sgp32_authenticateClientOkDSEsipa;  /* AuthenticateClientOkDSEsipa */
static int hf_sgp32_authenticateClientErrorEsipa;  /* T_authenticateClientErrorEsipa */
static int hf_sgp32_profileMetaData;              /* StoreMetadataRequest */
static int hf_sgp32_smdpSigned2;                  /* SmdpSigned2 */
static int hf_sgp32_smdpSignature2;               /* OCTET_STRING */
static int hf_sgp32_smdpCertificate;              /* Certificate */
static int hf_sgp32_profileDownloadTrigger;       /* ProfileDownloadTriggerRequest */
static int hf_sgp32_prepareDownloadResponse;      /* PrepareDownloadResponse */
static int hf_sgp32_getBoundProfilePackageOkEsipa;  /* GetBoundProfilePackageOkEsipa */
static int hf_sgp32_getBoundProfilePackageErrorEsipa;  /* T_getBoundProfilePackageErrorEsipa */
static int hf_sgp32_boundProfilePackage;          /* BoundProfilePackage */
static int hf_sgp32_pendingNotification;          /* PendingNotification */
static int hf_sgp32_cancelSessionResponse;        /* CancelSessionResponse */
static int hf_sgp32_cancelSessionOk;              /* CancelSessionOk */
static int hf_sgp32_cancelSessionError;           /* T_cancelSessionError */
static int hf_sgp32_notifyStateChange;            /* NULL */
static int hf_sgp32_stateChangeCause;             /* StateChangeCause */
static int hf_sgp32_rPLMN;                        /* T_rPLMN */
static int hf_sgp32_euiccPackageRequest;          /* EuiccPackageRequest */
static int hf_sgp32_ipaEuiccDataRequest;          /* IpaEuiccDataRequest */
static int hf_sgp32_profileDownloadTriggerRequest;  /* ProfileDownloadTriggerRequest */
static int hf_sgp32_eimPackageError;              /* T_eimPackageError */
static int hf_sgp32_eimPackageResultErrorCode;    /* EimPackageResultErrorCode */
static int hf_sgp32_euiccPackageResult;           /* EuiccPackageResult */
static int hf_sgp32_ePRAndNotifications;          /* T_ePRAndNotifications */
static int hf_sgp32_ipaEuiccDataResponse;         /* IpaEuiccDataResponse */
static int hf_sgp32_profileDownloadTriggerResult;  /* ProfileDownloadTriggerResult */
static int hf_sgp32_eimPackageResultResponseError;  /* EimPackageResultResponseError */
static int hf_sgp32_eimPackageResult;             /* EimPackageResult */
static int hf_sgp32_eimAcknowledgements;          /* EimAcknowledgements */
static int hf_sgp32_emptyResponse;                /* T_emptyResponse */
static int hf_sgp32_provideEimPackageResultError;  /* T_provideEimPackageResultError */
static int hf_sgp32_ePRAndNotifications_01;       /* T_ePRAndNotifications_01 */
static int hf_sgp32_eimPackageReceived;           /* NULL */
static int hf_sgp32_eimPackageError_01;           /* T_eimPackageError_01 */
/* named bits */
static int hf_sgp32_EimSupportedProtocol_eimRetrieveHttps;
static int hf_sgp32_EimSupportedProtocol_eimRetrieveCoaps;
static int hf_sgp32_EimSupportedProtocol_eimInjectHttps;
static int hf_sgp32_EimSupportedProtocol_eimInjectCoaps;
static int hf_sgp32_EimSupportedProtocol_eimProprietary;
static int hf_sgp32_T_euiccConfiguration_ipaeSupported;
static int hf_sgp32_T_euiccConfiguration_enabledProfile;
static int hf_sgp32_T_ipaeOption_activateIpae;
static int hf_sgp32_T_ipaFeatures_directRspServerCommunication;
static int hf_sgp32_T_ipaFeatures_indirectRspServerCommunication;
static int hf_sgp32_T_ipaFeatures_eimDownloadDataHandling;
static int hf_sgp32_T_ipaFeatures_eimCtxParams1Generation;
static int hf_sgp32_T_ipaFeatures_eimProfileMetadataVerification;
static int hf_sgp32_T_ipaFeatures_minimizeEsipaBytes;
static int hf_sgp32_T_ipaSupportedProtocols_ipaRetrieveHttps;
static int hf_sgp32_T_ipaSupportedProtocols_ipaRetrieveCoaps;
static int hf_sgp32_T_ipaSupportedProtocols_ipaInjectHttps;
static int hf_sgp32_T_ipaSupportedProtocols_ipaInjectCoaps;
static int hf_sgp32_T_ipaSupportedProtocols_ipaProprietary;
static int hf_sgp32_T_treProperties_isDiscrete;
static int hf_sgp32_T_treProperties_isIntegrated;
static int hf_sgp32_T_treProperties_usesRemoteMemory;
static int hf_sgp32_T_resetOptions_deleteOperationalProfiles;
static int hf_sgp32_T_resetOptions_deleteFieldLoadedTestProfiles;
static int hf_sgp32_T_resetOptions_resetDefaultSmdpAddress;
static int hf_sgp32_T_resetOptions_deletePreLoadedTestProfiles;
static int hf_sgp32_T_resetOptions_deleteProvisioningProfiles;
static int hf_sgp32_T_resetOptions_resetEimConfigData;
static int hf_sgp32_T_resetOptions_resetImmediateEnableConfig;

static int ett_sgp32;
static int ett_sgp32_rPLMN;
static int ett_sgp32_EuiccPackageRequest_U;
static int ett_sgp32_EuiccPackageSigned;
static int ett_sgp32_EuiccPackage;
static int ett_sgp32_SEQUENCE_OF_Psmo;
static int ett_sgp32_SEQUENCE_OF_Eco;
static int ett_sgp32_EimConfigurationData;
static int ett_sgp32_T_eimPublicKeyData;
static int ett_sgp32_T_trustedPublicKeyDataTls;
static int ett_sgp32_EimSupportedProtocol;
static int ett_sgp32_Eco;
static int ett_sgp32_T_deleteEim;
static int ett_sgp32_T_listEim;
static int ett_sgp32_Psmo;
static int ett_sgp32_T_enable;
static int ett_sgp32_T_disable;
static int ett_sgp32_T_delete;
static int ett_sgp32_T_getRAT;
static int ett_sgp32_T_configureImmediateEnable;
static int ett_sgp32_T_setFallbackAttribute;
static int ett_sgp32_T_unsetFallbackAttribute;
static int ett_sgp32_IpaEuiccDataRequest_U;
static int ett_sgp32_T_searchCriteriaNotification;
static int ett_sgp32_T_searchCriteriaEuiccPackageResult;
static int ett_sgp32_ProfileDownloadTriggerRequest_U;
static int ett_sgp32_ProfileDownloadData;
static int ett_sgp32_T_contactSmds;
static int ett_sgp32_SEQUENCE_OF_SequenceNumber;
static int ett_sgp32_EuiccPackageResult_U;
static int ett_sgp32_EuiccPackageResultSigned;
static int ett_sgp32_EuiccPackageResultDataSigned;
static int ett_sgp32_SEQUENCE_OF_EuiccResultData;
static int ett_sgp32_EuiccResultData;
static int ett_sgp32_EuiccPackageErrorSigned;
static int ett_sgp32_EuiccPackageErrorDataSigned;
static int ett_sgp32_EuiccPackageErrorUnsigned;
static int ett_sgp32_ProfileInfoListResponse_U;
static int ett_sgp32_SEQUENCE_OF_ProfileInfo;
static int ett_sgp32_AddEimResult;
static int ett_sgp32_ListEimResult;
static int ett_sgp32_SEQUENCE_OF_EimIdInfo;
static int ett_sgp32_EimIdInfo;
static int ett_sgp32_IpaEuiccDataResponseError;
static int ett_sgp32_IpaEuiccDataResponse_U;
static int ett_sgp32_PendingNotificationList;
static int ett_sgp32_EuiccPackageResultList;
static int ett_sgp32_IpaEuiccData;
static int ett_sgp32_ProfileDownloadTriggerResult_U;
static int ett_sgp32_T_profileDownloadTriggerResultData;
static int ett_sgp32_T_profileDownloadError;
static int ett_sgp32_ISDRProprietaryApplicationTemplateIoT_U;
static int ett_sgp32_T_euiccConfiguration;
static int ett_sgp32_IpaeActivationRequest_U;
static int ett_sgp32_T_ipaeOption;
static int ett_sgp32_IpaeActivationResponse_U;
static int ett_sgp32_IpaCapabilities;
static int ett_sgp32_T_ipaFeatures;
static int ett_sgp32_T_ipaSupportedProtocols;
static int ett_sgp32_ProfileInfo_U;
static int ett_sgp32_SEQUENCE_OF_NotificationConfigurationInformation;
static int ett_sgp32_StoreMetadataRequest_U;
static int ett_sgp32_EUICCInfo2_U;
static int ett_sgp32_SEQUENCE_OF_SubjectKeyIdentifier;
static int ett_sgp32_T_treProperties;
static int ett_sgp32_SEQUENCE_OF_VersionType;
static int ett_sgp32_IoTSpecificInfo;
static int ett_sgp32_AddInitialEimRequest_U;
static int ett_sgp32_SEQUENCE_OF_EimConfigurationData;
static int ett_sgp32_AddInitialEimResponse_U;
static int ett_sgp32_T_addInitialEimOk;
static int ett_sgp32_T_addInitialEimOk_item;
static int ett_sgp32_EuiccMemoryResetRequest_U;
static int ett_sgp32_T_resetOptions;
static int ett_sgp32_EuiccMemoryResetResponse_U;
static int ett_sgp32_GetCertsRequest_U;
static int ett_sgp32_GetCertsResponse_U;
static int ett_sgp32_T_certs;
static int ett_sgp32_RetrieveNotificationsListRequest_U;
static int ett_sgp32_T_searchCriteria;
static int ett_sgp32_RetrieveNotificationsListResponse_U;
static int ett_sgp32_ImmediateEnableRequest_U;
static int ett_sgp32_ImmediateEnableResponse_U;
static int ett_sgp32_ProfileRollbackRequest_U;
static int ett_sgp32_ProfileRollbackResponse_U;
static int ett_sgp32_ConfigureImmediateProfileEnablingRequest_U;
static int ett_sgp32_ConfigureImmediateProfileEnablingResponse_U;
static int ett_sgp32_GetEimConfigurationDataRequest_U;
static int ett_sgp32_T_searchCriteria_01;
static int ett_sgp32_GetEimConfigurationDataResponse_U;
static int ett_sgp32_ExecuteFallbackMechanismRequest_U;
static int ett_sgp32_ExecuteFallbackMechanismResponse_U;
static int ett_sgp32_ReturnFromFallbackRequest_U;
static int ett_sgp32_ReturnFromFallbackResponse_U;
static int ett_sgp32_EnableEmergencyProfileRequest_U;
static int ett_sgp32_EnableEmergencyProfileResponse_U;
static int ett_sgp32_DisableEmergencyProfileRequest_U;
static int ett_sgp32_DisableEmergencyProfileResponse_U;
static int ett_sgp32_GetConnectivityParametersRequest_U;
static int ett_sgp32_GetConnectivityParametersResponse_U;
static int ett_sgp32_ConnectivityParameters;
static int ett_sgp32_SetDefaultDpAddressRequest_U;
static int ett_sgp32_SetDefaultDpAddressResponse_U;
static int ett_sgp32_PrepareDownloadResponse_U;
static int ett_sgp32_CompactPrepareDownloadResponseOk;
static int ett_sgp32_CompactEuiccSigned2;
static int ett_sgp32_EuiccSigned1;
static int ett_sgp32_AuthenticateResponseOk;
static int ett_sgp32_AuthenticateServerResponse_U;
static int ett_sgp32_CompactAuthenticateResponseOk;
static int ett_sgp32_T_signedData;
static int ett_sgp32_CompactEuiccSigned1;
static int ett_sgp32_PendingNotification;
static int ett_sgp32_ProfileInstallationResult_U;
static int ett_sgp32_CompactProfileInstallationResult;
static int ett_sgp32_CompactProfileInstallationResultData;
static int ett_sgp32_T_compactFinalResult;
static int ett_sgp32_CompactSuccessResult;
static int ett_sgp32_CompactOtherSignedNotification;
static int ett_sgp32_CancelSessionResponse_U;
static int ett_sgp32_CompactCancelSessionResponseOk;
static int ett_sgp32_CompactEuiccCancelSessionSigned;
static int ett_sgp32_EsipaMessageFromIpaToEim;
static int ett_sgp32_EsipaMessageFromEimToIpa;
static int ett_sgp32_InitiateAuthenticationRequestEsipa_U;
static int ett_sgp32_InitiateAuthenticationResponseEsipa_U;
static int ett_sgp32_InitiateAuthenticationOkEsipa;
static int ett_sgp32_AuthenticateClientRequestEsipa_U;
static int ett_sgp32_AuthenticateClientResponseEsipa_U;
static int ett_sgp32_AuthenticateClientOkDPEsipa;
static int ett_sgp32_AuthenticateClientOkDSEsipa;
static int ett_sgp32_GetBoundProfilePackageRequestEsipa_U;
static int ett_sgp32_GetBoundProfilePackageResponseEsipa_U;
static int ett_sgp32_GetBoundProfilePackageOkEsipa;
static int ett_sgp32_HandleNotificationEsipa_U;
static int ett_sgp32_CancelSessionRequestEsipa_U;
static int ett_sgp32_CancelSessionResponseEsipa_U;
static int ett_sgp32_CancelSessionOk;
static int ett_sgp32_GetEimPackageRequest_U;
static int ett_sgp32_GetEimPackageResponse_U;
static int ett_sgp32_EimPackageResultResponseError;
static int ett_sgp32_EimPackageResult;
static int ett_sgp32_T_ePRAndNotifications;
static int ett_sgp32_ProvideEimPackageResult_U;
static int ett_sgp32_ProvideEimPackageResultResponse_U;
static int ett_sgp32_T_emptyResponse;
static int ett_sgp32_TransferEimPackageRequest_U;
static int ett_sgp32_TransferEimPackageResponse_U;
static int ett_sgp32_T_ePRAndNotifications_01;



static unsigned
dissect_sgp32_UTF8String_SIZE_1_128(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        1, 128, hf_index, NULL);

  return offset;
}



static unsigned
dissect_sgp32_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static unsigned
dissect_sgp32_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_enable_sequence[] = {
  { &hf_sgp32_iccid         , BER_CLASS_APP, 26, BER_FLAGS_IMPLTAG, dissect_sgp22_Iccid },
  { &hf_sgp32_rollbackFlag  , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp32_NULL },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_enable(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_enable_sequence, hf_index, ett_sgp32_T_enable);

  return offset;
}


static const ber_sequence_t T_disable_sequence[] = {
  { &hf_sgp32_iccid         , BER_CLASS_APP, 26, BER_FLAGS_IMPLTAG, dissect_sgp22_Iccid },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_disable(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_disable_sequence, hf_index, ett_sgp32_T_disable);

  return offset;
}


static const ber_sequence_t T_delete_sequence[] = {
  { &hf_sgp32_iccid         , BER_CLASS_APP, 26, BER_FLAGS_IMPLTAG, dissect_sgp22_Iccid },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_delete(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_delete_sequence, hf_index, ett_sgp32_T_delete);

  return offset;
}


static const ber_sequence_t T_getRAT_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_getRAT(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_getRAT_sequence, hf_index, ett_sgp32_T_getRAT);

  return offset;
}



static unsigned
dissect_sgp32_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static unsigned
dissect_sgp32_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_configureImmediateEnable_sequence[] = {
  { &hf_sgp32_immediateEnableFlag, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_NULL },
  { &hf_sgp32_defaultSmdpOid, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_OBJECT_IDENTIFIER },
  { &hf_sgp32_defaultSmdpAddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_configureImmediateEnable(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_configureImmediateEnable_sequence, hf_index, ett_sgp32_T_configureImmediateEnable);

  return offset;
}


static const ber_sequence_t T_setFallbackAttribute_sequence[] = {
  { &hf_sgp32_iccid         , BER_CLASS_APP, 26, BER_FLAGS_IMPLTAG, dissect_sgp22_Iccid },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_setFallbackAttribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_setFallbackAttribute_sequence, hf_index, ett_sgp32_T_setFallbackAttribute);

  return offset;
}


static const ber_sequence_t T_unsetFallbackAttribute_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_unsetFallbackAttribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_unsetFallbackAttribute_sequence, hf_index, ett_sgp32_T_unsetFallbackAttribute);

  return offset;
}


static const ber_sequence_t SetDefaultDpAddressRequest_U_sequence[] = {
  { &hf_sgp32_defaultDpAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_SetDefaultDpAddressRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetDefaultDpAddressRequest_U_sequence, hf_index, ett_sgp32_SetDefaultDpAddressRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_SetDefaultDpAddressRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 101, true, dissect_sgp32_SetDefaultDpAddressRequest_U);

  return offset;
}


static const value_string sgp32_Psmo_vals[] = {
  {   3, "enable" },
  {   4, "disable" },
  {   5, "delete" },
  {  45, "listProfileInfo" },
  {   6, "getRAT" },
  {   7, "configureImmediateEnable" },
  {   8, "setFallbackAttribute" },
  {   9, "unsetFallbackAttribute" },
  { 101, "setDefaultDpAddress" },
  { 0, NULL }
};

static const ber_choice_t Psmo_choice[] = {
  {   3, &hf_sgp32_enable        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp32_T_enable },
  {   4, &hf_sgp32_disable       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp32_T_disable },
  {   5, &hf_sgp32_delete        , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_sgp32_T_delete },
  {  45, &hf_sgp32_listProfileInfo, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileInfoListRequest },
  {   6, &hf_sgp32_getRAT        , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_sgp32_T_getRAT },
  {   7, &hf_sgp32_configureImmediateEnable, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_sgp32_T_configureImmediateEnable },
  {   8, &hf_sgp32_setFallbackAttribute, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_sgp32_T_setFallbackAttribute },
  {   9, &hf_sgp32_unsetFallbackAttribute, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_sgp32_T_unsetFallbackAttribute },
  { 101, &hf_sgp32_setDefaultDpAddress, BER_CLASS_CON, 101, BER_FLAGS_IMPLTAG, dissect_sgp32_SetDefaultDpAddressRequest },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_Psmo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Psmo_choice, hf_index, ett_sgp32_Psmo,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Psmo_sequence_of[1] = {
  { &hf_sgp32_psmoList_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_Psmo },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_Psmo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Psmo_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_Psmo);

  return offset;
}


static const value_string sgp32_EimIdType_vals[] = {
  {   1, "eimIdTypeOid" },
  {   2, "eimIdTypeFqdn" },
  {   3, "eimIdTypeProprietary" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_EimIdType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_T_eimPublicKeyData_vals[] = {
  {   0, "eimPublicKey" },
  {   1, "eimCertificate" },
  { 0, NULL }
};

static const ber_choice_t T_eimPublicKeyData_choice[] = {
  {   0, &hf_sgp32_eimPublicKey  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pkix1explicit_SubjectPublicKeyInfo },
  {   1, &hf_sgp32_eimCertificate, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Certificate },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_eimPublicKeyData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_eimPublicKeyData_choice, hf_index, ett_sgp32_T_eimPublicKeyData,
                                 NULL);

  return offset;
}


static const value_string sgp32_T_trustedPublicKeyDataTls_vals[] = {
  {   0, "trustedEimPkTls" },
  {   1, "trustedCertificateTls" },
  { 0, NULL }
};

static const ber_choice_t T_trustedPublicKeyDataTls_choice[] = {
  {   0, &hf_sgp32_trustedEimPkTls, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pkix1explicit_SubjectPublicKeyInfo },
  {   1, &hf_sgp32_trustedCertificateTls, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Certificate },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_trustedPublicKeyDataTls(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_trustedPublicKeyDataTls_choice, hf_index, ett_sgp32_T_trustedPublicKeyDataTls,
                                 NULL);

  return offset;
}


static int * const EimSupportedProtocol_bits[] = {
  &hf_sgp32_EimSupportedProtocol_eimRetrieveHttps,
  &hf_sgp32_EimSupportedProtocol_eimRetrieveCoaps,
  &hf_sgp32_EimSupportedProtocol_eimInjectHttps,
  &hf_sgp32_EimSupportedProtocol_eimInjectCoaps,
  &hf_sgp32_EimSupportedProtocol_eimProprietary,
  NULL
};

static unsigned
dissect_sgp32_EimSupportedProtocol(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    EimSupportedProtocol_bits, 5, hf_index, ett_sgp32_EimSupportedProtocol,
                                    NULL);

  return offset;
}


static const ber_sequence_t EimConfigurationData_sequence[] = {
  { &hf_sgp32_eimId         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_1_128 },
  { &hf_sgp32_eimFqdn       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { &hf_sgp32_eimIdType     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_EimIdType },
  { &hf_sgp32_counterValue  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { &hf_sgp32_associationToken, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { &hf_sgp32_eimPublicKeyData, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_eimPublicKeyData },
  { &hf_sgp32_trustedPublicKeyDataTls, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_trustedPublicKeyDataTls },
  { &hf_sgp32_eimSupportedProtocol, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_EimSupportedProtocol },
  { &hf_sgp32_euiccCiPKId   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1implicit_SubjectKeyIdentifier },
  { &hf_sgp32_indirectProfileDownload, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_NULL },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EimConfigurationData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EimConfigurationData_sequence, hf_index, ett_sgp32_EimConfigurationData);

  return offset;
}


static const ber_sequence_t T_deleteEim_sequence[] = {
  { &hf_sgp32_eimId_01      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_deleteEim(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_deleteEim_sequence, hf_index, ett_sgp32_T_deleteEim);

  return offset;
}


static const ber_sequence_t T_listEim_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_listEim(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listEim_sequence, hf_index, ett_sgp32_T_listEim);

  return offset;
}


static const value_string sgp32_Eco_vals[] = {
  {   8, "addEim" },
  {   9, "deleteEim" },
  {  10, "updateEim" },
  {  11, "listEim" },
  { 0, NULL }
};

static const ber_choice_t Eco_choice[] = {
  {   8, &hf_sgp32_addEim        , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_sgp32_EimConfigurationData },
  {   9, &hf_sgp32_deleteEim     , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_sgp32_T_deleteEim },
  {  10, &hf_sgp32_updateEim     , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_sgp32_EimConfigurationData },
  {  11, &hf_sgp32_listEim       , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_sgp32_T_listEim },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_Eco(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Eco_choice, hf_index, ett_sgp32_Eco,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Eco_sequence_of[1] = {
  { &hf_sgp32_ecoList_item  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_Eco },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_Eco(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Eco_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_Eco);

  return offset;
}


static const value_string sgp32_EuiccPackage_vals[] = {
  {   0, "psmoList" },
  {   1, "ecoList" },
  { 0, NULL }
};

static const ber_choice_t EuiccPackage_choice[] = {
  {   0, &hf_sgp32_psmoList      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_Psmo },
  {   1, &hf_sgp32_ecoList       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_Eco },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackage(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EuiccPackage_choice, hf_index, ett_sgp32_EuiccPackage,
                                 NULL);

  return offset;
}


static const ber_sequence_t EuiccPackageSigned_sequence[] = {
  { &hf_sgp32_eimId         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_1_128 },
  { &hf_sgp32_eidValue      , BER_CLASS_APP, 26, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp32_counterValue  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_euiccPackage  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_EuiccPackage },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackageSigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccPackageSigned_sequence, hf_index, ett_sgp32_EuiccPackageSigned);

  return offset;
}



static unsigned
dissect_sgp32_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t EuiccPackageRequest_U_sequence[] = {
  { &hf_sgp32_euiccPackageSigned, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_EuiccPackageSigned },
  { &hf_sgp32_eimSignature  , BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackageRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccPackageRequest_U_sequence, hf_index, ett_sgp32_EuiccPackageRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_EuiccPackageRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 81, true, dissect_sgp32_EuiccPackageRequest_U);

  return offset;
}


static const value_string sgp32_T_searchCriteriaNotification_vals[] = {
  {   0, "seqNumber" },
  {   1, "profileManagementOperation" },
  { 0, NULL }
};

static const ber_choice_t T_searchCriteriaNotification_choice[] = {
  {   0, &hf_sgp32_seqNumber     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  {   1, &hf_sgp32_profileManagementOperation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_NotificationEvent },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_searchCriteriaNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_searchCriteriaNotification_choice, hf_index, ett_sgp32_T_searchCriteriaNotification,
                                 NULL);

  return offset;
}


static const value_string sgp32_T_searchCriteriaEuiccPackageResult_vals[] = {
  {   0, "seqNumber" },
  { 0, NULL }
};

static const ber_choice_t T_searchCriteriaEuiccPackageResult_choice[] = {
  {   0, &hf_sgp32_seqNumber     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_searchCriteriaEuiccPackageResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_searchCriteriaEuiccPackageResult_choice, hf_index, ett_sgp32_T_searchCriteriaEuiccPackageResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t IpaEuiccDataRequest_U_sequence[] = {
  { &hf_sgp32_tagList       , BER_CLASS_APP, 28, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_euiccCiPKIdentifierToBeUsed, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_searchCriteriaNotification, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_searchCriteriaNotification },
  { &hf_sgp32_searchCriteriaEuiccPackageResult, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_searchCriteriaEuiccPackageResult },
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_IpaEuiccDataRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IpaEuiccDataRequest_U_sequence, hf_index, ett_sgp32_IpaEuiccDataRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_IpaEuiccDataRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 82, true, dissect_sgp32_IpaEuiccDataRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_UTF8String_SIZE_0_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        0, 255, hf_index, NULL);

  return offset;
}


static const ber_sequence_t T_contactSmds_sequence[] = {
  { &hf_sgp32_smdsAddress   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_contactSmds(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_contactSmds_sequence, hf_index, ett_sgp32_T_contactSmds);

  return offset;
}


static const value_string sgp32_ProfileDownloadData_vals[] = {
  {   0, "activationCode" },
  {   1, "contactDefaultSmdp" },
  {   2, "contactSmds" },
  { 0, NULL }
};

static const ber_choice_t ProfileDownloadData_choice[] = {
  {   0, &hf_sgp32_activationCode, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_0_255 },
  {   1, &hf_sgp32_contactDefaultSmdp, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_NULL },
  {   2, &hf_sgp32_contactSmds   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_T_contactSmds },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProfileDownloadData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProfileDownloadData_choice, hf_index, ett_sgp32_ProfileDownloadData,
                                 NULL);

  return offset;
}


static const ber_sequence_t ProfileDownloadTriggerRequest_U_sequence[] = {
  { &hf_sgp32_profileDownloadData, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_ProfileDownloadData },
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProfileDownloadTriggerRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileDownloadTriggerRequest_U_sequence, hf_index, ett_sgp32_ProfileDownloadTriggerRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_ProfileDownloadTriggerRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 84, true, dissect_sgp32_ProfileDownloadTriggerRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_SequenceNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 0, true, dissect_sgp32_INTEGER);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SequenceNumber_sequence_of[1] = {
  { &hf_sgp32__untag_item   , BER_CLASS_CON, 0, BER_FLAGS_NOOWNTAG, dissect_sgp32_SequenceNumber },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_SequenceNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SequenceNumber_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_SequenceNumber);

  return offset;
}



static unsigned
dissect_sgp32_EimAcknowledgements(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 83, true, dissect_sgp32_SEQUENCE_OF_SequenceNumber);

  return offset;
}


static const value_string sgp32_EnableProfileResult_vals[] = {
  {   0, "ok" },
  {   1, "iccidOrAidNotFound" },
  {   2, "profileNotInDisabledState" },
  {   3, "disallowedByPolicy" },
  {   5, "catBusy" },
  {  20, "rollbackNotAvailable" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_EnableProfileResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_DisableProfileResult_vals[] = {
  {   0, "ok" },
  {   1, "iccidOrAidNotFound" },
  {   2, "profileNotInEnabledState" },
  {   3, "disallowedByPolicy" },
  {   5, "catBusy" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_DisableProfileResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_DeleteProfileResult_vals[] = {
  {   0, "ok" },
  {   1, "iccidOrAidNotFound" },
  {   2, "profileNotInDisabledState" },
  {   3, "disallowedByPolicy" },
  {  20, "rollbackNotAvailable" },
  {  21, "returnFallbackProfile" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_DeleteProfileResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static unsigned
dissect_sgp32_UTF8String_SIZE_0_64(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        0, 64, hf_index, NULL);

  return offset;
}



static unsigned
dissect_sgp32_UTF8String_SIZE_0_32(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        0, 32, hf_index, NULL);

  return offset;
}



static unsigned
dissect_sgp32_OCTET_STRING_SIZE_0_1024(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   0, 1024, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_NotificationConfigurationInformation_sequence_of[1] = {
  { &hf_sgp32_notificationConfigurationInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_NotificationConfigurationInformation },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_NotificationConfigurationInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_NotificationConfigurationInformation_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_NotificationConfigurationInformation);

  return offset;
}



static unsigned
dissect_sgp32_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ProfileInfo_U_sequence[] = {
  { &hf_sgp32_iccid         , BER_CLASS_APP, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { &hf_sgp32_isdpAid       , BER_CLASS_APP, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OctetTo16 },
  { &hf_sgp32_profileState  , BER_CLASS_CON, 112, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileState },
  { &hf_sgp32_profileNickname, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_0_64 },
  { &hf_sgp32_serviceProviderName, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_0_32 },
  { &hf_sgp32_profileName   , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_0_64 },
  { &hf_sgp32_iconType      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_IconType },
  { &hf_sgp32_icon          , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING_SIZE_0_1024 },
  { &hf_sgp32_profileClass  , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileClass },
  { &hf_sgp32_notificationConfigurationInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_NotificationConfigurationInformation },
  { &hf_sgp32_profileOwner  , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OperatorId },
  { &hf_sgp32_dpProprietaryData, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_DpProprietaryData },
  { &hf_sgp32_profilePolicyRules, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_PprIds },
  { &hf_sgp32_serviceSpecificDataStoredInEuicc, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VendorSpecificExtension },
  { &hf_sgp32_ecallIndication, BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { &hf_sgp32_fallbackAttribute, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { &hf_sgp32_fallbackAllowed, BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProfileInfo_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileInfo_U_sequence, hf_index, ett_sgp32_ProfileInfo_U);

  return offset;
}



static unsigned
dissect_sgp32_ProfileInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 3, true, dissect_sgp32_ProfileInfo_U);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ProfileInfo_sequence_of[1] = {
  { &hf_sgp32_profileInfoListOk_item, BER_CLASS_PRI, 3, BER_FLAGS_NOOWNTAG, dissect_sgp32_ProfileInfo },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_ProfileInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ProfileInfo_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_ProfileInfo);

  return offset;
}


static const value_string sgp32_ProfileInfoListError_vals[] = {
  {   1, "incorrectInputValues" },
  {  11, "profileChangeOngoing" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_ProfileInfoListError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_ProfileInfoListResponse_U_vals[] = {
  {   0, "profileInfoListOk" },
  {   1, "profileInfoListError" },
  { 0, NULL }
};

static const ber_choice_t ProfileInfoListResponse_U_choice[] = {
  {   0, &hf_sgp32_profileInfoListOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_ProfileInfo },
  {   1, &hf_sgp32_profileInfoListError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_ProfileInfoListError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProfileInfoListResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProfileInfoListResponse_U_choice, hf_index, ett_sgp32_ProfileInfoListResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_ProfileInfoListResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 45, true, dissect_sgp32_ProfileInfoListResponse_U);

  return offset;
}


static const value_string sgp32_ConfigureImmediateEnableResult_vals[] = {
  {   0, "ok" },
  {   1, "insufficientMemory" },
  {   7, "commandError" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_ConfigureImmediateEnableResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_T_addEimResultCode_vals[] = {
  {   0, "ok" },
  {   1, "insufficientMemory" },
  {   2, "associatedEimAlreadyExists" },
  {   3, "ciPKUnknown" },
  {   5, "invalidAssociationToken" },
  {   6, "counterValueOutOfRange" },
  {   7, "commandError" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_addEimResultCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_AddEimResult_vals[] = {
  {   0, "associationToken" },
  {   1, "addEimResultCode" },
  { 0, NULL }
};

static const ber_choice_t AddEimResult_choice[] = {
  {   0, &hf_sgp32_associationToken, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  {   1, &hf_sgp32_addEimResultCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_addEimResultCode },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AddEimResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AddEimResult_choice, hf_index, ett_sgp32_AddEimResult,
                                 NULL);

  return offset;
}


static const value_string sgp32_DeleteEimResult_vals[] = {
  {   0, "ok" },
  {   1, "eimNotFound" },
  {   2, "lastEimDeleted" },
  {   7, "commandError" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_DeleteEimResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_UpdateEimResult_vals[] = {
  {   0, "ok" },
  {   1, "eimNotFound" },
  {   3, "ciPKUnknown" },
  {   6, "counterValueOutOfRange" },
  {   7, "commandError" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_UpdateEimResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EimIdInfo_sequence[] = {
  { &hf_sgp32_eimId         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_1_128 },
  { &hf_sgp32_eimIdType     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_EimIdType },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EimIdInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EimIdInfo_sequence, hf_index, ett_sgp32_EimIdInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EimIdInfo_sequence_of[1] = {
  { &hf_sgp32_eimIdList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_EimIdInfo },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_EimIdInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EimIdInfo_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_EimIdInfo);

  return offset;
}


static const value_string sgp32_T_listEimError_vals[] = {
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_listEimError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_ListEimResult_vals[] = {
  {   0, "eimIdList" },
  {   1, "listEimError" },
  { 0, NULL }
};

static const ber_choice_t ListEimResult_choice[] = {
  {   0, &hf_sgp32_eimIdList     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_EimIdInfo },
  {   1, &hf_sgp32_listEimError  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_T_listEimError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ListEimResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ListEimResult_choice, hf_index, ett_sgp32_ListEimResult,
                                 NULL);

  return offset;
}


static const value_string sgp32_RollbackProfileResult_vals[] = {
  {   0, "ok" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_RollbackProfileResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_SetFallbackAttributeResult_vals[] = {
  {   0, "ok" },
  {   1, "iccidOrAidNotFound" },
  {   2, "fallbackNotAllowed" },
  {   3, "fallbackProfileEnabled" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_SetFallbackAttributeResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_UnsetFallbackAttributeResult_vals[] = {
  {   0, "ok" },
  {   2, "noFallbackAttribute" },
  {   3, "fallbackProfileEnabled" },
  {   7, "commandError" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_UnsetFallbackAttributeResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_T_processingTerminated_vals[] = {
  {   1, "resultSizeOverflow" },
  {   2, "unknownOrDamagedCommand" },
  {   3, "interruption" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_processingTerminated(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_T_setDefaultDpAddressResult_vals[] = {
  {   0, "ok" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_setDefaultDpAddressResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SetDefaultDpAddressResponse_U_sequence[] = {
  { &hf_sgp32_setDefaultDpAddressResult_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_setDefaultDpAddressResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_SetDefaultDpAddressResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetDefaultDpAddressResponse_U_sequence, hf_index, ett_sgp32_SetDefaultDpAddressResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_SetDefaultDpAddressResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 101, true, dissect_sgp32_SetDefaultDpAddressResponse_U);

  return offset;
}


static const value_string sgp32_EuiccResultData_vals[] = {
  {   0, "enableResult" },
  {   1, "disableResult" },
  {   2, "deleteResult" },
  {   3, "listProfileInfoResult" },
  {   4, "getRATResult" },
  {   5, "configureImmediateEnableResult" },
  {   6, "addEimResult" },
  {   7, "deleteEimResult" },
  {   8, "updateEimResult" },
  {   9, "listEimResult" },
  {  10, "rollbackResult" },
  {  11, "setFallbackAttributeResult" },
  {  12, "unsetFallbackAttributeResult" },
  {  13, "processingTerminated" },
  {  14, "setDefaultDpAddressResult" },
  { 0, NULL }
};

static const ber_choice_t EuiccResultData_choice[] = {
  {   0, &hf_sgp32_enableResult  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp32_EnableProfileResult },
  {   1, &hf_sgp32_disableResult , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp32_DisableProfileResult },
  {   2, &hf_sgp32_deleteResult  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_sgp32_DeleteProfileResult },
  {   3, &hf_sgp32_listProfileInfoResult, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_sgp32_ProfileInfoListResponse },
  {   4, &hf_sgp32_getRATResult  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_sgp22_RulesAuthorisationTable },
  {   5, &hf_sgp32_configureImmediateEnableResult, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_sgp32_ConfigureImmediateEnableResult },
  {   6, &hf_sgp32_addEimResult  , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_sgp32_AddEimResult },
  {   7, &hf_sgp32_deleteEimResult, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_sgp32_DeleteEimResult },
  {   8, &hf_sgp32_updateEimResult, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_sgp32_UpdateEimResult },
  {   9, &hf_sgp32_listEimResult , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_sgp32_ListEimResult },
  {  10, &hf_sgp32_rollbackResult, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_sgp32_RollbackProfileResult },
  {  11, &hf_sgp32_setFallbackAttributeResult, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_sgp32_SetFallbackAttributeResult },
  {  12, &hf_sgp32_unsetFallbackAttributeResult, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_sgp32_UnsetFallbackAttributeResult },
  {  13, &hf_sgp32_processingTerminated, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_processingTerminated },
  {  14, &hf_sgp32_setDefaultDpAddressResult, BER_CLASS_CON, 101, BER_FLAGS_IMPLTAG, dissect_sgp32_SetDefaultDpAddressResponse },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EuiccResultData_choice, hf_index, ett_sgp32_EuiccResultData,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EuiccResultData_sequence_of[1] = {
  { &hf_sgp32_euiccResult_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_EuiccResultData },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_EuiccResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EuiccResultData_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_EuiccResultData);

  return offset;
}


static const ber_sequence_t EuiccPackageResultDataSigned_sequence[] = {
  { &hf_sgp32_eimId         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_1_128 },
  { &hf_sgp32_counterValue  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_seqNumber     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { &hf_sgp32_euiccResult   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_SEQUENCE_OF_EuiccResultData },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackageResultDataSigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccPackageResultDataSigned_sequence, hf_index, ett_sgp32_EuiccPackageResultDataSigned);

  return offset;
}


static const ber_sequence_t EuiccPackageResultSigned_sequence[] = {
  { &hf_sgp32_euiccPackageResultDataSigned, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_EuiccPackageResultDataSigned },
  { &hf_sgp32_euiccSignEPR  , BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackageResultSigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccPackageResultSigned_sequence, hf_index, ett_sgp32_EuiccPackageResultSigned);

  return offset;
}


static const value_string sgp32_EuiccPackageErrorCode_vals[] = {
  {   3, "invalidEid" },
  {   4, "replayError" },
  {   6, "counterValueOutOfRange" },
  {  15, "sizeOverflow" },
  { 104, "ecallActive" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_EuiccPackageErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EuiccPackageErrorDataSigned_sequence[] = {
  { &hf_sgp32_eimId         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_1_128 },
  { &hf_sgp32_counterValue  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_euiccPackageErrorCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_EuiccPackageErrorCode },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackageErrorDataSigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccPackageErrorDataSigned_sequence, hf_index, ett_sgp32_EuiccPackageErrorDataSigned);

  return offset;
}


static const ber_sequence_t EuiccPackageErrorSigned_sequence[] = {
  { &hf_sgp32_euiccPackageErrorDataSigned, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_EuiccPackageErrorDataSigned },
  { &hf_sgp32_euiccSignEPE  , BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackageErrorSigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccPackageErrorSigned_sequence, hf_index, ett_sgp32_EuiccPackageErrorSigned);

  return offset;
}


static const ber_sequence_t EuiccPackageErrorUnsigned_sequence[] = {
  { &hf_sgp32_eimId         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_1_128 },
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_associationToken, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackageErrorUnsigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccPackageErrorUnsigned_sequence, hf_index, ett_sgp32_EuiccPackageErrorUnsigned);

  return offset;
}


static const value_string sgp32_EuiccPackageResult_U_vals[] = {
  {   0, "euiccPackageResultSigned" },
  {   1, "euiccPackageErrorSigned" },
  {   2, "euiccPackageErrorUnsigned" },
  { 0, NULL }
};

static const ber_choice_t EuiccPackageResult_U_choice[] = {
  {   0, &hf_sgp32_euiccPackageResultSigned, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageResultSigned },
  {   1, &hf_sgp32_euiccPackageErrorSigned, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageErrorSigned },
  {   2, &hf_sgp32_euiccPackageErrorUnsigned, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageErrorUnsigned },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccPackageResult_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EuiccPackageResult_U_choice, hf_index, ett_sgp32_EuiccPackageResult_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_EuiccPackageResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 81, true, dissect_sgp32_EuiccPackageResult_U);

  return offset;
}


static const value_string sgp32_IpaEuiccDataErrorCode_vals[] = {
  {   1, "incorrectTagList" },
  {   5, "euiccCiPKIdNotFound" },
  { 104, "ecallActive" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_IpaEuiccDataErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t IpaEuiccDataResponseError_sequence[] = {
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_ipaEuiccDataErrorCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_IpaEuiccDataErrorCode },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_IpaEuiccDataResponseError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IpaEuiccDataResponseError_sequence, hf_index, ett_sgp32_IpaEuiccDataResponseError);

  return offset;
}


static const ber_sequence_t ProfileInstallationResult_U_sequence[] = {
  { &hf_sgp32_profileInstallationResultData, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileInstallationResultData },
  { &hf_sgp32_euiccSignPIR  , BER_CLASS_APP, 55, BER_FLAGS_NOOWNTAG, dissect_sgp22_EuiccSignPIR },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProfileInstallationResult_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileInstallationResult_U_sequence, hf_index, ett_sgp32_ProfileInstallationResult_U);

  return offset;
}



static unsigned
dissect_sgp32_ProfileInstallationResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 55, true, dissect_sgp32_ProfileInstallationResult_U);

  return offset;
}



static unsigned
dissect_sgp32_OCTET_STRING_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   2, 2, hf_index, NULL);

  return offset;
}


static const ber_sequence_t CompactSuccessResult_sequence[] = {
  { &hf_sgp32_compactAid    , BER_CLASS_APP, 15, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING_SIZE_2 },
  { &hf_sgp32_simaResponse  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactSuccessResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactSuccessResult_sequence, hf_index, ett_sgp32_CompactSuccessResult);

  return offset;
}


static const value_string sgp32_T_compactFinalResult_vals[] = {
  {   0, "compactSuccessResult" },
  {   1, "errorResult" },
  { 0, NULL }
};

static const ber_choice_t T_compactFinalResult_choice[] = {
  {   0, &hf_sgp32_compactSuccessResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_CompactSuccessResult },
  {   1, &hf_sgp32_errorResult   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_ErrorResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_compactFinalResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_compactFinalResult_choice, hf_index, ett_sgp32_T_compactFinalResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t CompactProfileInstallationResultData_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_seqNumber     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_INTEGER },
  { &hf_sgp32_iccidPresent  , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp32_BOOLEAN },
  { &hf_sgp32_compactFinalResult, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_T_compactFinalResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactProfileInstallationResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactProfileInstallationResultData_sequence, hf_index, ett_sgp32_CompactProfileInstallationResultData);

  return offset;
}


static const ber_sequence_t CompactProfileInstallationResult_sequence[] = {
  { &hf_sgp32_compactProfileInstallationResultData, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_CompactProfileInstallationResultData },
  { &hf_sgp32_euiccSignPIR  , BER_CLASS_APP, 55, BER_FLAGS_NOOWNTAG, dissect_sgp22_EuiccSignPIR },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactProfileInstallationResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactProfileInstallationResult_sequence, hf_index, ett_sgp32_CompactProfileInstallationResult);

  return offset;
}


static const ber_sequence_t CompactOtherSignedNotification_sequence[] = {
  { &hf_sgp32_eidValue      , BER_CLASS_APP, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp32_tbsOtherNotification, BER_CLASS_CON, 47, BER_FLAGS_NOOWNTAG, dissect_sgp22_NotificationMetadata },
  { &hf_sgp32_euiccNotificationSignature, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactOtherSignedNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactOtherSignedNotification_sequence, hf_index, ett_sgp32_CompactOtherSignedNotification);

  return offset;
}


static const value_string sgp32_PendingNotification_vals[] = {
  {   0, "profileInstallationResult" },
  {   1, "otherSignedNotification" },
  {   2, "compactProfileInstallationResult" },
  {   3, "compactOtherSignedNotification" },
  { 0, NULL }
};

static const ber_choice_t PendingNotification_choice[] = {
  {   0, &hf_sgp32_profileInstallationResult, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_ProfileInstallationResult },
  {   1, &hf_sgp32_otherSignedNotification, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_OtherSignedNotification },
  {   2, &hf_sgp32_compactProfileInstallationResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_CompactProfileInstallationResult },
  {   3, &hf_sgp32_compactOtherSignedNotification, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_CompactOtherSignedNotification },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_PendingNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PendingNotification_choice, hf_index, ett_sgp32_PendingNotification,
                                 NULL);

  return offset;
}


static const ber_sequence_t PendingNotificationList_sequence_of[1] = {
  { &hf_sgp32_PendingNotificationList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_PendingNotification },
};

static unsigned
dissect_sgp32_PendingNotificationList(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PendingNotificationList_sequence_of, hf_index, ett_sgp32_PendingNotificationList);

  return offset;
}


static const ber_sequence_t EuiccPackageResultList_sequence_of[1] = {
  { &hf_sgp32_EuiccPackageResultList_item, BER_CLASS_CON, 81, BER_FLAGS_NOOWNTAG, dissect_sgp32_EuiccPackageResult },
};

static unsigned
dissect_sgp32_EuiccPackageResultList(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      EuiccPackageResultList_sequence_of, hf_index, ett_sgp32_EuiccPackageResultList);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SubjectKeyIdentifier_sequence_of[1] = {
  { &hf_sgp32_euiccCiPKIdListForVerification_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_SubjectKeyIdentifier },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_SubjectKeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SubjectKeyIdentifier_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_SubjectKeyIdentifier);

  return offset;
}


static const value_string sgp32_T_euiccCategory_vals[] = {
  {   0, "other" },
  {   1, "basicEuicc" },
  {   2, "mediumEuicc" },
  {   3, "contactlessEuicc" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_euiccCategory(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static int * const T_treProperties_bits[] = {
  &hf_sgp32_T_treProperties_isDiscrete,
  &hf_sgp32_T_treProperties_isIntegrated,
  &hf_sgp32_T_treProperties_usesRemoteMemory,
  NULL
};

static unsigned
dissect_sgp32_T_treProperties(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_treProperties_bits, 3, hf_index, ett_sgp32_T_treProperties,
                                    NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_VersionType_sequence_of[1] = {
  { &hf_sgp32_additionalEuiccProfilePackageVersions_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgp22_VersionType },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_VersionType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_VersionType_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_VersionType);

  return offset;
}


static const value_string sgp32_IpaMode_vals[] = {
  {   0, "ipad" },
  {   1, "ipae" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_IpaMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static unsigned
dissect_sgp32_OCTET_STRING_SIZE_0_32(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   0, 32, hf_index, NULL);

  return offset;
}


static const ber_sequence_t IoTSpecificInfo_sequence[] = {
  { &hf_sgp32_iotVersion    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_VersionType },
  { &hf_sgp32_ecallSupported, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_NULL },
  { &hf_sgp32_fallbackSupported, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_NULL },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_IoTSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IoTSpecificInfo_sequence, hf_index, ett_sgp32_IoTSpecificInfo);

  return offset;
}


static const ber_sequence_t EUICCInfo2_U_sequence[] = {
  { &hf_sgp32_profileVersion, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp32_svn           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp32_euiccFirmwareVer, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp32_extCardResource, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_uiccCapability, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_sgp22_UICCCapability },
  { &hf_sgp32_ts102241Version, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp32_globalplatformVersion, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp32_rspCapability , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_sgp22_RspCapability },
  { &hf_sgp32_euiccCiPKIdListForVerification, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_SubjectKeyIdentifier },
  { &hf_sgp32_euiccCiPKIdListForSigning, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_SubjectKeyIdentifier },
  { &hf_sgp32_euiccCategory , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_euiccCategory },
  { &hf_sgp32_forbiddenProfilePolicyRules, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_PprIds },
  { &hf_sgp32_ppVersion     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgp22_VersionType },
  { &hf_sgp32_sasAcreditationNumber, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_sgp32_UTF8String_SIZE_0_64 },
  { &hf_sgp32_certificationDataObject, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_CertificationDataObject },
  { &hf_sgp32_treProperties , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_treProperties },
  { &hf_sgp32_treProductReference, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { &hf_sgp32_additionalEuiccProfilePackageVersions, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_VersionType },
  { &hf_sgp32_ipaMode       , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_IpaMode },
  { &hf_sgp32_euiccCiPKIdListForSigningV3, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_SubjectKeyIdentifier },
  { &hf_sgp32_additionalEuiccInfo, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING_SIZE_0_32 },
  { &hf_sgp32_highestSvn    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VersionType },
  { &hf_sgp32_iotSpecificInfo, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_IoTSpecificInfo },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EUICCInfo2_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EUICCInfo2_U_sequence, hf_index, ett_sgp32_EUICCInfo2_U);

  return offset;
}



static unsigned
dissect_sgp32_EUICCInfo2(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 34, true, dissect_sgp32_EUICCInfo2_U);

  return offset;
}


static int * const T_ipaFeatures_bits[] = {
  &hf_sgp32_T_ipaFeatures_directRspServerCommunication,
  &hf_sgp32_T_ipaFeatures_indirectRspServerCommunication,
  &hf_sgp32_T_ipaFeatures_eimDownloadDataHandling,
  &hf_sgp32_T_ipaFeatures_eimCtxParams1Generation,
  &hf_sgp32_T_ipaFeatures_eimProfileMetadataVerification,
  &hf_sgp32_T_ipaFeatures_minimizeEsipaBytes,
  NULL
};

static unsigned
dissect_sgp32_T_ipaFeatures(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_ipaFeatures_bits, 6, hf_index, ett_sgp32_T_ipaFeatures,
                                    NULL);

  return offset;
}


static int * const T_ipaSupportedProtocols_bits[] = {
  &hf_sgp32_T_ipaSupportedProtocols_ipaRetrieveHttps,
  &hf_sgp32_T_ipaSupportedProtocols_ipaRetrieveCoaps,
  &hf_sgp32_T_ipaSupportedProtocols_ipaInjectHttps,
  &hf_sgp32_T_ipaSupportedProtocols_ipaInjectCoaps,
  &hf_sgp32_T_ipaSupportedProtocols_ipaProprietary,
  NULL
};

static unsigned
dissect_sgp32_T_ipaSupportedProtocols(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_ipaSupportedProtocols_bits, 5, hf_index, ett_sgp32_T_ipaSupportedProtocols,
                                    NULL);

  return offset;
}


static const ber_sequence_t IpaCapabilities_sequence[] = {
  { &hf_sgp32_ipaFeatures   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_ipaFeatures },
  { &hf_sgp32_ipaSupportedProtocols, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_ipaSupportedProtocols },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_IpaCapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IpaCapabilities_sequence, hf_index, ett_sgp32_IpaCapabilities);

  return offset;
}


static const ber_sequence_t IpaEuiccData_sequence[] = {
  { &hf_sgp32_notificationsList, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_PendingNotificationList },
  { &hf_sgp32_defaultSmdpAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { &hf_sgp32_euiccPackageResultList, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageResultList },
  { &hf_sgp32_euiccInfo1    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_EUICCInfo1 },
  { &hf_sgp32_euiccInfo2    , BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_EUICCInfo2 },
  { &hf_sgp32_rootSmdsAddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { &hf_sgp32_associationToken, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  { &hf_sgp32_eumCertificate, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp32_euiccCertificate, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_ipaCapabilities, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_IpaCapabilities },
  { &hf_sgp32_deviceInfo    , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_DeviceInfo },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_IpaEuiccData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IpaEuiccData_sequence, hf_index, ett_sgp32_IpaEuiccData);

  return offset;
}


static const value_string sgp32_IpaEuiccDataResponse_U_vals[] = {
  {   0, "ipaEuiccData" },
  {   1, "ipaEuiccDataResponseError" },
  { 0, NULL }
};

static const ber_choice_t IpaEuiccDataResponse_U_choice[] = {
  {   0, &hf_sgp32_ipaEuiccData  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_IpaEuiccData },
  {   1, &hf_sgp32_ipaEuiccDataResponseError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_IpaEuiccDataResponseError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_IpaEuiccDataResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IpaEuiccDataResponse_U_choice, hf_index, ett_sgp32_IpaEuiccDataResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_IpaEuiccDataResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 82, true, dissect_sgp32_IpaEuiccDataResponse_U);

  return offset;
}


static const value_string sgp32_T_profileDownloadErrorReason_vals[] = {
  { 104, "ecallActive" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_profileDownloadErrorReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_profileDownloadError_sequence[] = {
  { &hf_sgp32_profileDownloadErrorReason, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_profileDownloadErrorReason },
  { &hf_sgp32_errorResponse , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_profileDownloadError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_profileDownloadError_sequence, hf_index, ett_sgp32_T_profileDownloadError);

  return offset;
}


static const value_string sgp32_T_profileDownloadTriggerResultData_vals[] = {
  {   0, "profileInstallationResult" },
  {   1, "profileDownloadError" },
  { 0, NULL }
};

static const ber_choice_t T_profileDownloadTriggerResultData_choice[] = {
  {   0, &hf_sgp32_profileInstallationResult, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_ProfileInstallationResult },
  {   1, &hf_sgp32_profileDownloadError, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_profileDownloadError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_profileDownloadTriggerResultData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_profileDownloadTriggerResultData_choice, hf_index, ett_sgp32_T_profileDownloadTriggerResultData,
                                 NULL);

  return offset;
}


static const ber_sequence_t ProfileDownloadTriggerResult_U_sequence[] = {
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_profileDownloadTriggerResultData, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_T_profileDownloadTriggerResultData },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProfileDownloadTriggerResult_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileDownloadTriggerResult_U_sequence, hf_index, ett_sgp32_ProfileDownloadTriggerResult_U);

  return offset;
}



static unsigned
dissect_sgp32_ProfileDownloadTriggerResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 84, true, dissect_sgp32_ProfileDownloadTriggerResult_U);

  return offset;
}


static int * const T_euiccConfiguration_bits[] = {
  &hf_sgp32_T_euiccConfiguration_ipaeSupported,
  &hf_sgp32_T_euiccConfiguration_enabledProfile,
  NULL
};

static unsigned
dissect_sgp32_T_euiccConfiguration(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_euiccConfiguration_bits, 2, hf_index, ett_sgp32_T_euiccConfiguration,
                                    NULL);

  return offset;
}


static const ber_sequence_t ISDRProprietaryApplicationTemplateIoT_U_sequence[] = {
  { &hf_sgp32_euiccConfiguration, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_euiccConfiguration },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ISDRProprietaryApplicationTemplateIoT_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ISDRProprietaryApplicationTemplateIoT_U_sequence, hf_index, ett_sgp32_ISDRProprietaryApplicationTemplateIoT_U);

  return offset;
}



static unsigned
dissect_sgp32_ISDRProprietaryApplicationTemplateIoT(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 1, true, dissect_sgp32_ISDRProprietaryApplicationTemplateIoT_U);

  return offset;
}


static int * const T_ipaeOption_bits[] = {
  &hf_sgp32_T_ipaeOption_activateIpae,
  NULL
};

static unsigned
dissect_sgp32_T_ipaeOption(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_ipaeOption_bits, 1, hf_index, ett_sgp32_T_ipaeOption,
                                    NULL);

  return offset;
}


static const ber_sequence_t IpaeActivationRequest_U_sequence[] = {
  { &hf_sgp32_ipaeOption    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_ipaeOption },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_IpaeActivationRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IpaeActivationRequest_U_sequence, hf_index, ett_sgp32_IpaeActivationRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_IpaeActivationRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 66, true, dissect_sgp32_IpaeActivationRequest_U);

  return offset;
}


static const value_string sgp32_T_ipaeActivationResult_vals[] = {
  {   0, "ok" },
  {   1, "notSupported" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_ipaeActivationResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t IpaeActivationResponse_U_sequence[] = {
  { &hf_sgp32_ipaeActivationResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_ipaeActivationResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_IpaeActivationResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IpaeActivationResponse_U_sequence, hf_index, ett_sgp32_IpaeActivationResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_IpaeActivationResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 66, true, dissect_sgp32_IpaeActivationResponse_U);

  return offset;
}


static const ber_sequence_t StoreMetadataRequest_U_sequence[] = {
  { &hf_sgp32_iccid         , BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_sgp22_Iccid },
  { &hf_sgp32_serviceProviderName, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_0_32 },
  { &hf_sgp32_profileName   , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_0_64 },
  { &hf_sgp32_iconType      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_IconType },
  { &hf_sgp32_icon          , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING_SIZE_0_1024 },
  { &hf_sgp32_profileClass  , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_ProfileClass },
  { &hf_sgp32_notificationConfigurationInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_NotificationConfigurationInformation },
  { &hf_sgp32_profileOwner  , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_OperatorId },
  { &hf_sgp32_profilePolicyRules, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_PprIds },
  { &hf_sgp32_serviceSpecificDataStoredInEuicc, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VendorSpecificExtension },
  { &hf_sgp32_serviceSpecificDataNotStoredInEuicc, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_VendorSpecificExtension },
  { &hf_sgp32_ecallIndication, BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { &hf_sgp32_fallbackAllowed, BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_StoreMetadataRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StoreMetadataRequest_U_sequence, hf_index, ett_sgp32_StoreMetadataRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_StoreMetadataRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 37, true, dissect_sgp32_StoreMetadataRequest_U);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EimConfigurationData_sequence_of[1] = {
  { &hf_sgp32_eimConfigurationDataList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_EimConfigurationData },
};

static unsigned
dissect_sgp32_SEQUENCE_OF_EimConfigurationData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EimConfigurationData_sequence_of, hf_index, ett_sgp32_SEQUENCE_OF_EimConfigurationData);

  return offset;
}


static const ber_sequence_t AddInitialEimRequest_U_sequence[] = {
  { &hf_sgp32_eimConfigurationDataList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_EimConfigurationData },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AddInitialEimRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddInitialEimRequest_U_sequence, hf_index, ett_sgp32_AddInitialEimRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_AddInitialEimRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 87, true, dissect_sgp32_AddInitialEimRequest_U);

  return offset;
}


static const value_string sgp32_T_addInitialEimOk_item_vals[] = {
  {   0, "associationToken" },
  {   1, "addOk" },
  { 0, NULL }
};

static const ber_choice_t T_addInitialEimOk_item_choice[] = {
  {   0, &hf_sgp32_associationToken, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  {   1, &hf_sgp32_addOk         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_sgp32_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_addInitialEimOk_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_addInitialEimOk_item_choice, hf_index, ett_sgp32_T_addInitialEimOk_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_addInitialEimOk_sequence_of[1] = {
  { &hf_sgp32_addInitialEimOk_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_T_addInitialEimOk_item },
};

static unsigned
dissect_sgp32_T_addInitialEimOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_addInitialEimOk_sequence_of, hf_index, ett_sgp32_T_addInitialEimOk);

  return offset;
}


static const value_string sgp32_T_addInitialEimError_vals[] = {
  {   1, "insufficientMemory" },
  {   2, "associatedEimAlreadyExists" },
  {   3, "ciPKUnknown" },
  {   5, "invalidAssociationToken" },
  {   6, "counterValueOutOfRange" },
  {   7, "commandError" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_addInitialEimError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_AddInitialEimResponse_U_vals[] = {
  {   0, "addInitialEimOk" },
  {   1, "addInitialEimError" },
  { 0, NULL }
};

static const ber_choice_t AddInitialEimResponse_U_choice[] = {
  {   0, &hf_sgp32_addInitialEimOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_addInitialEimOk },
  {   1, &hf_sgp32_addInitialEimError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_T_addInitialEimError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AddInitialEimResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AddInitialEimResponse_U_choice, hf_index, ett_sgp32_AddInitialEimResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_AddInitialEimResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 87, true, dissect_sgp32_AddInitialEimResponse_U);

  return offset;
}


static int * const T_resetOptions_bits[] = {
  &hf_sgp32_T_resetOptions_deleteOperationalProfiles,
  &hf_sgp32_T_resetOptions_deleteFieldLoadedTestProfiles,
  &hf_sgp32_T_resetOptions_resetDefaultSmdpAddress,
  &hf_sgp32_T_resetOptions_deletePreLoadedTestProfiles,
  &hf_sgp32_T_resetOptions_deleteProvisioningProfiles,
  &hf_sgp32_T_resetOptions_resetEimConfigData,
  &hf_sgp32_T_resetOptions_resetImmediateEnableConfig,
  NULL
};

static unsigned
dissect_sgp32_T_resetOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_resetOptions_bits, 7, hf_index, ett_sgp32_T_resetOptions,
                                    NULL);

  return offset;
}


static const ber_sequence_t EuiccMemoryResetRequest_U_sequence[] = {
  { &hf_sgp32_resetOptions  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_T_resetOptions },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccMemoryResetRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccMemoryResetRequest_U_sequence, hf_index, ett_sgp32_EuiccMemoryResetRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_EuiccMemoryResetRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 100, true, dissect_sgp32_EuiccMemoryResetRequest_U);

  return offset;
}


static const value_string sgp32_T_resetResult_vals[] = {
  {   0, "ok" },
  {   1, "nothingToDelete" },
  {   5, "catBusy" },
  { 104, "ecallActive" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_resetResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_T_resetEimResult_vals[] = {
  {   0, "ok" },
  {   1, "nothingToDelete" },
  {   2, "eimResetNotSupported" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_resetEimResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_T_resetImmediateEnableConfigResult_vals[] = {
  {   0, "ok" },
  {   1, "resetIECNotSupported" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_resetImmediateEnableConfigResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EuiccMemoryResetResponse_U_sequence[] = {
  { &hf_sgp32_resetResult   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_resetResult },
  { &hf_sgp32_resetEimResult, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_resetEimResult },
  { &hf_sgp32_resetImmediateEnableConfigResult, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_resetImmediateEnableConfigResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccMemoryResetResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccMemoryResetResponse_U_sequence, hf_index, ett_sgp32_EuiccMemoryResetResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_EuiccMemoryResetResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 100, true, dissect_sgp32_EuiccMemoryResetResponse_U);

  return offset;
}


static const ber_sequence_t GetCertsRequest_U_sequence[] = {
  { &hf_sgp32_euiccCiPKId   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1implicit_SubjectKeyIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetCertsRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetCertsRequest_U_sequence, hf_index, ett_sgp32_GetCertsRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_GetCertsRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 86, true, dissect_sgp32_GetCertsRequest_U);

  return offset;
}


static const ber_sequence_t T_certs_sequence[] = {
  { &hf_sgp32_eumCertificate, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp32_euiccCertificate, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_certs(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_certs_sequence, hf_index, ett_sgp32_T_certs);

  return offset;
}


static const value_string sgp32_T_getCertsError_vals[] = {
  {   1, "invalidCiPKId" },
  { 127, "undfinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_getCertsError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_GetCertsResponse_U_vals[] = {
  {   0, "certs" },
  {   1, "getCertsError" },
  { 0, NULL }
};

static const ber_choice_t GetCertsResponse_U_choice[] = {
  {   0, &hf_sgp32_certs         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_certs },
  {   1, &hf_sgp32_getCertsError , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_T_getCertsError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetCertsResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GetCertsResponse_U_choice, hf_index, ett_sgp32_GetCertsResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_GetCertsResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 86, true, dissect_sgp32_GetCertsResponse_U);

  return offset;
}


static const value_string sgp32_T_searchCriteria_vals[] = {
  {   0, "seqNumber" },
  {   1, "profileManagementOperation" },
  {   2, "euiccPackageResults" },
  { 0, NULL }
};

static const ber_choice_t T_searchCriteria_choice[] = {
  {   0, &hf_sgp32_seqNumber     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_INTEGER },
  {   1, &hf_sgp32_profileManagementOperation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_NotificationEvent },
  {   2, &hf_sgp32_euiccPackageResults, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_searchCriteria(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_searchCriteria_choice, hf_index, ett_sgp32_T_searchCriteria,
                                 NULL);

  return offset;
}


static const ber_sequence_t RetrieveNotificationsListRequest_U_sequence[] = {
  { &hf_sgp32_searchCriteria, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_searchCriteria },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_RetrieveNotificationsListRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RetrieveNotificationsListRequest_U_sequence, hf_index, ett_sgp32_RetrieveNotificationsListRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_RetrieveNotificationsListRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 43, true, dissect_sgp32_RetrieveNotificationsListRequest_U);

  return offset;
}


static const value_string sgp32_T_notificationsListResultError_vals[] = {
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_notificationsListResultError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_RetrieveNotificationsListResponse_U_vals[] = {
  {   0, "notificationList" },
  {   1, "notificationsListResultError" },
  {   2, "euiccPackageResultList" },
  { 0, NULL }
};

static const ber_choice_t RetrieveNotificationsListResponse_U_choice[] = {
  {   0, &hf_sgp32_notificationList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_PendingNotificationList },
  {   1, &hf_sgp32_notificationsListResultError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_T_notificationsListResultError },
  {   2, &hf_sgp32_euiccPackageResultList, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageResultList },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_RetrieveNotificationsListResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RetrieveNotificationsListResponse_U_choice, hf_index, ett_sgp32_RetrieveNotificationsListResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_RetrieveNotificationsListResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 43, true, dissect_sgp32_RetrieveNotificationsListResponse_U);

  return offset;
}


static const ber_sequence_t ImmediateEnableRequest_U_sequence[] = {
  { &hf_sgp32_refreshFlag   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ImmediateEnableRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ImmediateEnableRequest_U_sequence, hf_index, ett_sgp32_ImmediateEnableRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_ImmediateEnableRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 90, true, dissect_sgp32_ImmediateEnableRequest_U);

  return offset;
}


static const value_string sgp32_T_immediateEnableResult_vals[] = {
  {   0, "ok" },
  {   1, "immediateEnableNotAvailable" },
  {   4, "noSessionContext" },
  {   5, "catBusy" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_immediateEnableResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ImmediateEnableResponse_U_sequence[] = {
  { &hf_sgp32_immediateEnableResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_immediateEnableResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ImmediateEnableResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ImmediateEnableResponse_U_sequence, hf_index, ett_sgp32_ImmediateEnableResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_ImmediateEnableResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 90, true, dissect_sgp32_ImmediateEnableResponse_U);

  return offset;
}


static const ber_sequence_t ProfileRollbackRequest_U_sequence[] = {
  { &hf_sgp32_refreshFlag   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProfileRollbackRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileRollbackRequest_U_sequence, hf_index, ett_sgp32_ProfileRollbackRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_ProfileRollbackRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 88, true, dissect_sgp32_ProfileRollbackRequest_U);

  return offset;
}


static const value_string sgp32_T_cmdResult_vals[] = {
  {   0, "ok" },
  {   1, "rollbackNotAllowed" },
  {   5, "catBusy" },
  {   7, "commandError" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_cmdResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ProfileRollbackResponse_U_sequence[] = {
  { &hf_sgp32_cmdResult     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_cmdResult },
  { &hf_sgp32_eUICCPackageResult, BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProfileRollbackResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProfileRollbackResponse_U_sequence, hf_index, ett_sgp32_ProfileRollbackResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_ProfileRollbackResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 88, true, dissect_sgp32_ProfileRollbackResponse_U);

  return offset;
}


static const ber_sequence_t ConfigureImmediateProfileEnablingRequest_U_sequence[] = {
  { &hf_sgp32_immediateEnableFlag, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_NULL },
  { &hf_sgp32_defaultSmdpOid, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_OBJECT_IDENTIFIER },
  { &hf_sgp32_defaultSmdpAddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ConfigureImmediateProfileEnablingRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConfigureImmediateProfileEnablingRequest_U_sequence, hf_index, ett_sgp32_ConfigureImmediateProfileEnablingRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_ConfigureImmediateProfileEnablingRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 89, true, dissect_sgp32_ConfigureImmediateProfileEnablingRequest_U);

  return offset;
}


static const value_string sgp32_T_configImmediateEnableResult_vals[] = {
  {   0, "ok" },
  {   1, "insufficientMemory" },
  {   2, "associatedEimAlreadyExists" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_configImmediateEnableResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ConfigureImmediateProfileEnablingResponse_U_sequence[] = {
  { &hf_sgp32_configImmediateEnableResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_configImmediateEnableResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ConfigureImmediateProfileEnablingResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConfigureImmediateProfileEnablingResponse_U_sequence, hf_index, ett_sgp32_ConfigureImmediateProfileEnablingResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_ConfigureImmediateProfileEnablingResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 89, true, dissect_sgp32_ConfigureImmediateProfileEnablingResponse_U);

  return offset;
}


static const value_string sgp32_T_searchCriteria_01_vals[] = {
  {   0, "eimId" },
  { 0, NULL }
};

static const ber_choice_t T_searchCriteria_01_choice[] = {
  {   0, &hf_sgp32_eimId         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String_SIZE_1_128 },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_searchCriteria_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_searchCriteria_01_choice, hf_index, ett_sgp32_T_searchCriteria_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t GetEimConfigurationDataRequest_U_sequence[] = {
  { &hf_sgp32_searchCriteria_01, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_searchCriteria_01 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetEimConfigurationDataRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEimConfigurationDataRequest_U_sequence, hf_index, ett_sgp32_GetEimConfigurationDataRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_GetEimConfigurationDataRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 85, true, dissect_sgp32_GetEimConfigurationDataRequest_U);

  return offset;
}


static const ber_sequence_t GetEimConfigurationDataResponse_U_sequence[] = {
  { &hf_sgp32_eimConfigurationDataList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_SEQUENCE_OF_EimConfigurationData },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetEimConfigurationDataResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEimConfigurationDataResponse_U_sequence, hf_index, ett_sgp32_GetEimConfigurationDataResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_GetEimConfigurationDataResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 85, true, dissect_sgp32_GetEimConfigurationDataResponse_U);

  return offset;
}


static const ber_sequence_t ExecuteFallbackMechanismRequest_U_sequence[] = {
  { &hf_sgp32_refreshFlag   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ExecuteFallbackMechanismRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExecuteFallbackMechanismRequest_U_sequence, hf_index, ett_sgp32_ExecuteFallbackMechanismRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_ExecuteFallbackMechanismRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 93, true, dissect_sgp32_ExecuteFallbackMechanismRequest_U);

  return offset;
}


static const value_string sgp32_T_executeFallbackMechanismResult_vals[] = {
  {   0, "ok" },
  {   2, "profileNotInDisabledState" },
  {   5, "catBusy" },
  {   6, "fallbackNotAvailable" },
  {   7, "commandError" },
  { 104, "ecallActive" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_executeFallbackMechanismResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ExecuteFallbackMechanismResponse_U_sequence[] = {
  { &hf_sgp32_executeFallbackMechanismResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_executeFallbackMechanismResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ExecuteFallbackMechanismResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExecuteFallbackMechanismResponse_U_sequence, hf_index, ett_sgp32_ExecuteFallbackMechanismResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_ExecuteFallbackMechanismResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 93, true, dissect_sgp32_ExecuteFallbackMechanismResponse_U);

  return offset;
}


static const ber_sequence_t ReturnFromFallbackRequest_U_sequence[] = {
  { &hf_sgp32_refreshFlag   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ReturnFromFallbackRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnFromFallbackRequest_U_sequence, hf_index, ett_sgp32_ReturnFromFallbackRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_ReturnFromFallbackRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 94, true, dissect_sgp32_ReturnFromFallbackRequest_U);

  return offset;
}


static const value_string sgp32_T_returnFromFallbackResult_vals[] = {
  {   0, "ok" },
  {   5, "catBusy" },
  {   6, "fallbackNotAvailable" },
  {   7, "commandError" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_returnFromFallbackResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ReturnFromFallbackResponse_U_sequence[] = {
  { &hf_sgp32_returnFromFallbackResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_returnFromFallbackResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ReturnFromFallbackResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnFromFallbackResponse_U_sequence, hf_index, ett_sgp32_ReturnFromFallbackResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_ReturnFromFallbackResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 94, true, dissect_sgp32_ReturnFromFallbackResponse_U);

  return offset;
}


static const ber_sequence_t EnableEmergencyProfileRequest_U_sequence[] = {
  { &hf_sgp32_refreshFlag   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EnableEmergencyProfileRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnableEmergencyProfileRequest_U_sequence, hf_index, ett_sgp32_EnableEmergencyProfileRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_EnableEmergencyProfileRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 91, true, dissect_sgp32_EnableEmergencyProfileRequest_U);

  return offset;
}


static const value_string sgp32_T_enableEmergencyProfileResult_vals[] = {
  {   0, "ok" },
  {   2, "profileNotInDisabledState" },
  {   5, "catBusy" },
  {   8, "ecallNotAvailable" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_enableEmergencyProfileResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EnableEmergencyProfileResponse_U_sequence[] = {
  { &hf_sgp32_enableEmergencyProfileResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_enableEmergencyProfileResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EnableEmergencyProfileResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnableEmergencyProfileResponse_U_sequence, hf_index, ett_sgp32_EnableEmergencyProfileResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_EnableEmergencyProfileResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 91, true, dissect_sgp32_EnableEmergencyProfileResponse_U);

  return offset;
}


static const ber_sequence_t DisableEmergencyProfileRequest_U_sequence[] = {
  { &hf_sgp32_refreshFlag   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_DisableEmergencyProfileRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisableEmergencyProfileRequest_U_sequence, hf_index, ett_sgp32_DisableEmergencyProfileRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_DisableEmergencyProfileRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 92, true, dissect_sgp32_DisableEmergencyProfileRequest_U);

  return offset;
}


static const value_string sgp32_T_disableEmergencyProfileResult_vals[] = {
  {   0, "ok" },
  {   2, "profileNotInEnabledState" },
  {   5, "catBusy" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_disableEmergencyProfileResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DisableEmergencyProfileResponse_U_sequence[] = {
  { &hf_sgp32_disableEmergencyProfileResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_T_disableEmergencyProfileResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_DisableEmergencyProfileResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisableEmergencyProfileResponse_U_sequence, hf_index, ett_sgp32_DisableEmergencyProfileResponse_U);

  return offset;
}



static unsigned
dissect_sgp32_DisableEmergencyProfileResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 92, true, dissect_sgp32_DisableEmergencyProfileResponse_U);

  return offset;
}


static const ber_sequence_t GetConnectivityParametersRequest_U_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetConnectivityParametersRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetConnectivityParametersRequest_U_sequence, hf_index, ett_sgp32_GetConnectivityParametersRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_GetConnectivityParametersRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 95, true, dissect_sgp32_GetConnectivityParametersRequest_U);

  return offset;
}


static const ber_sequence_t ConnectivityParameters_sequence[] = {
  { &hf_sgp32_httpParams    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ConnectivityParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectivityParameters_sequence, hf_index, ett_sgp32_ConnectivityParameters);

  return offset;
}


static const value_string sgp32_ConnectivityParametersError_vals[] = {
  {   1, "parametersNotAvailable" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_ConnectivityParametersError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_GetConnectivityParametersResponse_U_vals[] = {
  {   0, "connectivityParameters" },
  {   1, "connectivityParametersError" },
  { 0, NULL }
};

static const ber_choice_t GetConnectivityParametersResponse_U_choice[] = {
  {   0, &hf_sgp32_connectivityParameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_ConnectivityParameters },
  {   1, &hf_sgp32_connectivityParametersError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_ConnectivityParametersError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetConnectivityParametersResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GetConnectivityParametersResponse_U_choice, hf_index, ett_sgp32_GetConnectivityParametersResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_GetConnectivityParametersResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 95, true, dissect_sgp32_GetConnectivityParametersResponse_U);

  return offset;
}


static const ber_sequence_t CompactEuiccSigned2_sequence[] = {
  { &hf_sgp32_euiccOtpk     , BER_CLASS_APP, 73, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_hashCc        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_Octet32 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactEuiccSigned2(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactEuiccSigned2_sequence, hf_index, ett_sgp32_CompactEuiccSigned2);

  return offset;
}


static const ber_sequence_t CompactPrepareDownloadResponseOk_sequence[] = {
  { &hf_sgp32_compactEuiccSigned2, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_CompactEuiccSigned2 },
  { &hf_sgp32_euiccSignature2, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactPrepareDownloadResponseOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactPrepareDownloadResponseOk_sequence, hf_index, ett_sgp32_CompactPrepareDownloadResponseOk);

  return offset;
}


static const value_string sgp32_PrepareDownloadResponse_U_vals[] = {
  {   0, "downloadResponseOk" },
  {   1, "downloadResponseError" },
  {   2, "compactDownloadResponseOk" },
  { 0, NULL }
};

static const ber_choice_t PrepareDownloadResponse_U_choice[] = {
  {   0, &hf_sgp32_downloadResponseOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_PrepareDownloadResponseOk },
  {   1, &hf_sgp32_downloadResponseError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_PrepareDownloadResponseError },
  {   2, &hf_sgp32_compactDownloadResponseOk, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_CompactPrepareDownloadResponseOk },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_PrepareDownloadResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PrepareDownloadResponse_U_choice, hf_index, ett_sgp32_PrepareDownloadResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_PrepareDownloadResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 33, true, dissect_sgp32_PrepareDownloadResponse_U);

  return offset;
}


static const ber_sequence_t EuiccSigned1_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_serverAddress , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { &hf_sgp32_serverChallenge, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp32_euiccInfo2    , BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_sgp32_EUICCInfo2 },
  { &hf_sgp32_ctxParams1    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_sgp22_CtxParams1 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EuiccSigned1(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EuiccSigned1_sequence, hf_index, ett_sgp32_EuiccSigned1);

  return offset;
}


static const ber_sequence_t AuthenticateResponseOk_sequence[] = {
  { &hf_sgp32_euiccSigned1  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_EuiccSigned1 },
  { &hf_sgp32_euiccSignature1, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_euiccCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp32_eumCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AuthenticateResponseOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateResponseOk_sequence, hf_index, ett_sgp32_AuthenticateResponseOk);

  return offset;
}


static const ber_sequence_t CompactEuiccSigned1_sequence[] = {
  { &hf_sgp32_extCardResource, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_ctxParams1    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_CtxParams1 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactEuiccSigned1(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactEuiccSigned1_sequence, hf_index, ett_sgp32_CompactEuiccSigned1);

  return offset;
}


static const value_string sgp32_T_signedData_vals[] = {
  {   0, "euiccSigned1" },
  {   1, "compactEuiccSigned1" },
  { 0, NULL }
};

static const ber_choice_t T_signedData_choice[] = {
  {   0, &hf_sgp32_euiccSigned1  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_EuiccSigned1 },
  {   1, &hf_sgp32_compactEuiccSigned1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_CompactEuiccSigned1 },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_signedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_signedData_choice, hf_index, ett_sgp32_T_signedData,
                                 NULL);

  return offset;
}


static const ber_sequence_t CompactAuthenticateResponseOk_sequence[] = {
  { &hf_sgp32_signedData    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_T_signedData },
  { &hf_sgp32_euiccSignature1, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_euiccCertificate, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp32_eumCertificate, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactAuthenticateResponseOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactAuthenticateResponseOk_sequence, hf_index, ett_sgp32_CompactAuthenticateResponseOk);

  return offset;
}


static const value_string sgp32_AuthenticateServerResponse_U_vals[] = {
  {   0, "authenticateResponseOk" },
  {   1, "authenticateResponseError" },
  {   2, "compactAuthenticateResponseOk" },
  { 0, NULL }
};

static const ber_choice_t AuthenticateServerResponse_U_choice[] = {
  {   0, &hf_sgp32_authenticateResponseOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_AuthenticateResponseOk },
  {   1, &hf_sgp32_authenticateResponseError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_AuthenticateResponseError },
  {   2, &hf_sgp32_compactAuthenticateResponseOk, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_CompactAuthenticateResponseOk },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AuthenticateServerResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticateServerResponse_U_choice, hf_index, ett_sgp32_AuthenticateServerResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_AuthenticateServerResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 56, true, dissect_sgp32_AuthenticateServerResponse_U);

  return offset;
}


static const value_string sgp32_T_cancelSessionResponseError_vals[] = {
  {   5, "invalidTransactionId" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_cancelSessionResponseError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CompactEuiccCancelSessionSigned_sequence[] = {
  { &hf_sgp32_reason        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionReason },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactEuiccCancelSessionSigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactEuiccCancelSessionSigned_sequence, hf_index, ett_sgp32_CompactEuiccCancelSessionSigned);

  return offset;
}


static const ber_sequence_t CompactCancelSessionResponseOk_sequence[] = {
  { &hf_sgp32_compactEuiccCancelSessionSigned, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_CompactEuiccCancelSessionSigned },
  { &hf_sgp32_euiccCancelSessionSignature, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CompactCancelSessionResponseOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompactCancelSessionResponseOk_sequence, hf_index, ett_sgp32_CompactCancelSessionResponseOk);

  return offset;
}


static const value_string sgp32_CancelSessionResponse_U_vals[] = {
  {   0, "cancelSessionResponseOk" },
  {   1, "cancelSessionResponseError" },
  {   2, "compactCancelSessionResponseOk" },
  { 0, NULL }
};

static const ber_choice_t CancelSessionResponse_U_choice[] = {
  {   0, &hf_sgp32_cancelSessionResponseOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_CancelSessionResponseOk },
  {   1, &hf_sgp32_cancelSessionResponseError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_T_cancelSessionResponseError },
  {   2, &hf_sgp32_compactCancelSessionResponseOk, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_CompactCancelSessionResponseOk },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CancelSessionResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CancelSessionResponse_U_choice, hf_index, ett_sgp32_CancelSessionResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_CancelSessionResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 65, true, dissect_sgp32_CancelSessionResponse_U);

  return offset;
}


static const ber_sequence_t InitiateAuthenticationRequestEsipa_U_sequence[] = {
  { &hf_sgp32_euiccChallenge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp32_smdpAddress   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_UTF8String },
  { &hf_sgp32_euiccInfo1    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_EUICCInfo1 },
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_InitiateAuthenticationRequestEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateAuthenticationRequestEsipa_U_sequence, hf_index, ett_sgp32_InitiateAuthenticationRequestEsipa_U);

  return offset;
}



static unsigned
dissect_sgp32_InitiateAuthenticationRequestEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 57, true, dissect_sgp32_InitiateAuthenticationRequestEsipa_U);

  return offset;
}


static const ber_sequence_t AuthenticateClientRequestEsipa_U_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_authenticateServerResponse, BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_sgp32_AuthenticateServerResponse },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AuthenticateClientRequestEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateClientRequestEsipa_U_sequence, hf_index, ett_sgp32_AuthenticateClientRequestEsipa_U);

  return offset;
}



static unsigned
dissect_sgp32_AuthenticateClientRequestEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 59, true, dissect_sgp32_AuthenticateClientRequestEsipa_U);

  return offset;
}


static const ber_sequence_t GetBoundProfilePackageRequestEsipa_U_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_prepareDownloadResponse, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_sgp32_PrepareDownloadResponse },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetBoundProfilePackageRequestEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetBoundProfilePackageRequestEsipa_U_sequence, hf_index, ett_sgp32_GetBoundProfilePackageRequestEsipa_U);

  return offset;
}



static unsigned
dissect_sgp32_GetBoundProfilePackageRequestEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 58, true, dissect_sgp32_GetBoundProfilePackageRequestEsipa_U);

  return offset;
}


static const ber_sequence_t CancelSessionRequestEsipa_U_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_cancelSessionResponse, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_CancelSessionResponse },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CancelSessionRequestEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelSessionRequestEsipa_U_sequence, hf_index, ett_sgp32_CancelSessionRequestEsipa_U);

  return offset;
}



static unsigned
dissect_sgp32_CancelSessionRequestEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 65, true, dissect_sgp32_CancelSessionRequestEsipa_U);

  return offset;
}


static const ber_sequence_t T_ePRAndNotifications_sequence[] = {
  { &hf_sgp32_euiccPackageResult, BER_CLASS_CON, 81, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageResult },
  { &hf_sgp32_notificationList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_PendingNotificationList },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_ePRAndNotifications(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_ePRAndNotifications_sequence, hf_index, ett_sgp32_T_ePRAndNotifications);

  return offset;
}


static const value_string sgp32_EimPackageResultErrorCode_vals[] = {
  {   1, "invalidPackageFormat" },
  {   2, "unknownPackage" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_EimPackageResultErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EimPackageResultResponseError_sequence[] = {
  { &hf_sgp32_eimTransactionId, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_eimPackageResultErrorCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_EimPackageResultErrorCode },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EimPackageResultResponseError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EimPackageResultResponseError_sequence, hf_index, ett_sgp32_EimPackageResultResponseError);

  return offset;
}


static const value_string sgp32_EimPackageResult_vals[] = {
  {   0, "euiccPackageResult" },
  {   1, "ePRAndNotifications" },
  {   2, "ipaEuiccDataResponse" },
  {   3, "profileDownloadTriggerResult" },
  {   4, "eimPackageResultResponseError" },
  { 0, NULL }
};

static const ber_choice_t EimPackageResult_choice[] = {
  {   0, &hf_sgp32_euiccPackageResult, BER_CLASS_CON, 81, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageResult },
  {   1, &hf_sgp32_ePRAndNotifications, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_ePRAndNotifications },
  {   2, &hf_sgp32_ipaEuiccDataResponse, BER_CLASS_CON, 82, BER_FLAGS_IMPLTAG, dissect_sgp32_IpaEuiccDataResponse },
  {   3, &hf_sgp32_profileDownloadTriggerResult, BER_CLASS_CON, 84, BER_FLAGS_IMPLTAG, dissect_sgp32_ProfileDownloadTriggerResult },
  {   4, &hf_sgp32_eimPackageResultResponseError, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_EimPackageResultResponseError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EimPackageResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EimPackageResult_choice, hf_index, ett_sgp32_EimPackageResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ProvideEimPackageResult_U_sequence[] = {
  { &hf_sgp32_eidValue      , BER_CLASS_APP, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp32_eimPackageResult, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sgp32_EimPackageResult },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProvideEimPackageResult_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProvideEimPackageResult_U_sequence, hf_index, ett_sgp32_ProvideEimPackageResult_U);

  return offset;
}



static unsigned
dissect_sgp32_ProvideEimPackageResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 80, true, dissect_sgp32_ProvideEimPackageResult_U);

  return offset;
}


static const value_string sgp32_HandleNotificationEsipa_U_vals[] = {
  {   0, "pendingNotification" },
  {  80, "provideEimPackageResult" },
  { 0, NULL }
};

static const ber_choice_t HandleNotificationEsipa_U_choice[] = {
  {   0, &hf_sgp32_pendingNotification, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_PendingNotification },
  {  80, &hf_sgp32_provideEimPackageResult, BER_CLASS_CON, 80, BER_FLAGS_IMPLTAG, dissect_sgp32_ProvideEimPackageResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_HandleNotificationEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 HandleNotificationEsipa_U_choice, hf_index, ett_sgp32_HandleNotificationEsipa_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_HandleNotificationEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 61, true, dissect_sgp32_HandleNotificationEsipa_U);

  return offset;
}


static const ber_sequence_t T_ePRAndNotifications_01_sequence[] = {
  { &hf_sgp32_euiccPackageResult, BER_CLASS_CON, 81, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageResult },
  { &hf_sgp32_notificationList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_PendingNotificationList },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_ePRAndNotifications_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_ePRAndNotifications_01_sequence, hf_index, ett_sgp32_T_ePRAndNotifications_01);

  return offset;
}


static const value_string sgp32_T_eimPackageError_01_vals[] = {
  {   1, "invalidPackageFormat" },
  {   2, "unknownPackage" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_eimPackageError_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_TransferEimPackageResponse_U_vals[] = {
  {   0, "euiccPackageResult" },
  {   1, "ePRAndNotifications" },
  {   2, "ipaEuiccDataResponse" },
  {   3, "eimPackageReceived" },
  {   4, "eimPackageError" },
  { 0, NULL }
};

static const ber_choice_t TransferEimPackageResponse_U_choice[] = {
  {   0, &hf_sgp32_euiccPackageResult, BER_CLASS_CON, 81, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageResult },
  {   1, &hf_sgp32_ePRAndNotifications_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_ePRAndNotifications_01 },
  {   2, &hf_sgp32_ipaEuiccDataResponse, BER_CLASS_CON, 82, BER_FLAGS_IMPLTAG, dissect_sgp32_IpaEuiccDataResponse },
  {   3, &hf_sgp32_eimPackageReceived, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_sgp32_NULL },
  {   4, &hf_sgp32_eimPackageError_01, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_eimPackageError_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_TransferEimPackageResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TransferEimPackageResponse_U_choice, hf_index, ett_sgp32_TransferEimPackageResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_TransferEimPackageResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 78, true, dissect_sgp32_TransferEimPackageResponse_U);

  return offset;
}


static const value_string sgp32_StateChangeCause_vals[] = {
  {   0, "otherEim" },
  {   1, "fallback" },
  {   2, "emergencyProfile" },
  {   3, "local" },
  {   4, "reset" },
  {   5, "immediateEnableProfile" },
  {   6, "deviceChange" },
  { 127, "undefined" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_StateChangeCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static unsigned
dissect_sgp32_T_rPLMN(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;

  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   3, 3, hf_index, &parameter_tvb);

  if (parameter_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_sgp32_rPLMN);
    dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, false);
  }


  return offset;
}


static const ber_sequence_t GetEimPackageRequest_U_sequence[] = {
  { &hf_sgp32_eidValue      , BER_CLASS_APP, 26, BER_FLAGS_IMPLTAG, dissect_sgp22_Octet16 },
  { &hf_sgp32_notifyStateChange, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_NULL },
  { &hf_sgp32_stateChangeCause, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_StateChangeCause },
  { &hf_sgp32_rPLMN         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_T_rPLMN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetEimPackageRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEimPackageRequest_U_sequence, hf_index, ett_sgp32_GetEimPackageRequest_U);

  return offset;
}



static unsigned
dissect_sgp32_GetEimPackageRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 79, true, dissect_sgp32_GetEimPackageRequest_U);

  return offset;
}


static const value_string sgp32_EsipaMessageFromIpaToEim_vals[] = {
  {  57, "initiateAuthenticationRequestEsipa" },
  {  59, "authenticateClientRequestEsipa" },
  {  58, "getBoundProfilePackageRequestEsipa" },
  {  65, "cancelSessionRequestEsipa" },
  {  61, "handleNotificationEsipa" },
  {  78, "transferEimPackageResponse" },
  {  79, "getEimPackageRequest" },
  {  80, "provideEimPackageResult" },
  { 0, NULL }
};

static const ber_choice_t EsipaMessageFromIpaToEim_choice[] = {
  {  57, &hf_sgp32_initiateAuthenticationRequestEsipa, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_sgp32_InitiateAuthenticationRequestEsipa },
  {  59, &hf_sgp32_authenticateClientRequestEsipa, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_sgp32_AuthenticateClientRequestEsipa },
  {  58, &hf_sgp32_getBoundProfilePackageRequestEsipa, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_sgp32_GetBoundProfilePackageRequestEsipa },
  {  65, &hf_sgp32_cancelSessionRequestEsipa, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_sgp32_CancelSessionRequestEsipa },
  {  61, &hf_sgp32_handleNotificationEsipa, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_sgp32_HandleNotificationEsipa },
  {  78, &hf_sgp32_transferEimPackageResponse, BER_CLASS_CON, 78, BER_FLAGS_IMPLTAG, dissect_sgp32_TransferEimPackageResponse },
  {  79, &hf_sgp32_getEimPackageRequest, BER_CLASS_CON, 79, BER_FLAGS_IMPLTAG, dissect_sgp32_GetEimPackageRequest },
  {  80, &hf_sgp32_provideEimPackageResult, BER_CLASS_CON, 80, BER_FLAGS_IMPLTAG, dissect_sgp32_ProvideEimPackageResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EsipaMessageFromIpaToEim(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int choice;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EsipaMessageFromIpaToEim_choice, hf_index, ett_sgp32_EsipaMessageFromIpaToEim,
                                 &choice);

  if (choice != -1) {
    col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str_const(EsipaMessageFromIpaToEim_choice[choice].value, sgp32_EsipaMessageFromIpaToEim_vals, "Unknown"));
  }

  return offset;
}


static const ber_sequence_t InitiateAuthenticationOkEsipa_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_serverSigned1 , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_ServerSigned1 },
  { &hf_sgp32_serverSignature1, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_euiccCiPKIdentifierToBeUsed, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_serverCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp32_matchingId    , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp32_UTF8String },
  { &hf_sgp32_ctxParams1    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_CtxParams1 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_InitiateAuthenticationOkEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateAuthenticationOkEsipa_sequence, hf_index, ett_sgp32_InitiateAuthenticationOkEsipa);

  return offset;
}


static const value_string sgp32_T_initiateAuthenticationErrorEsipa_vals[] = {
  {   1, "invalidDpAddress" },
  {   2, "euiccVersionNotSupportedByDp" },
  {   3, "ciPKIdNotSupported" },
  {  50, "smdpAddressMismatch" },
  {  51, "smdpOidMismatch" },
  {  52, "invalidEimTransactionId" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_initiateAuthenticationErrorEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_InitiateAuthenticationResponseEsipa_U_vals[] = {
  {   0, "initiateAuthenticationOkEsipa" },
  {   1, "initiateAuthenticationErrorEsipa" },
  { 0, NULL }
};

static const ber_choice_t InitiateAuthenticationResponseEsipa_U_choice[] = {
  {   0, &hf_sgp32_initiateAuthenticationOkEsipa, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_InitiateAuthenticationOkEsipa },
  {   1, &hf_sgp32_initiateAuthenticationErrorEsipa, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_T_initiateAuthenticationErrorEsipa },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_InitiateAuthenticationResponseEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InitiateAuthenticationResponseEsipa_U_choice, hf_index, ett_sgp32_InitiateAuthenticationResponseEsipa_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_InitiateAuthenticationResponseEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 57, true, dissect_sgp32_InitiateAuthenticationResponseEsipa_U);

  return offset;
}


static const ber_sequence_t AuthenticateClientOkDPEsipa_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_profileMetaData, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_StoreMetadataRequest },
  { &hf_sgp32_smdpSigned2   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp22_SmdpSigned2 },
  { &hf_sgp32_smdpSignature2, BER_CLASS_APP, 55, BER_FLAGS_IMPLTAG, dissect_sgp32_OCTET_STRING },
  { &hf_sgp32_smdpCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { &hf_sgp32_hashCc        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sgp22_Octet32 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AuthenticateClientOkDPEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateClientOkDPEsipa_sequence, hf_index, ett_sgp32_AuthenticateClientOkDPEsipa);

  return offset;
}


static const ber_sequence_t AuthenticateClientOkDSEsipa_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_profileDownloadTrigger, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp32_ProfileDownloadTriggerRequest },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AuthenticateClientOkDSEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticateClientOkDSEsipa_sequence, hf_index, ett_sgp32_AuthenticateClientOkDSEsipa);

  return offset;
}


static const value_string sgp32_T_authenticateClientErrorEsipa_vals[] = {
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
  {  50, "pprNotAllowed" },
  {  56, "eventIdUnknown" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_authenticateClientErrorEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_AuthenticateClientResponseEsipa_U_vals[] = {
  {   0, "authenticateClientOkDPEsipa" },
  {   1, "authenticateClientOkDSEsipa" },
  {   2, "authenticateClientErrorEsipa" },
  { 0, NULL }
};

static const ber_choice_t AuthenticateClientResponseEsipa_U_choice[] = {
  {   0, &hf_sgp32_authenticateClientOkDPEsipa, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_AuthenticateClientOkDPEsipa },
  {   1, &hf_sgp32_authenticateClientOkDSEsipa, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_AuthenticateClientOkDSEsipa },
  {   2, &hf_sgp32_authenticateClientErrorEsipa, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sgp32_T_authenticateClientErrorEsipa },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_AuthenticateClientResponseEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuthenticateClientResponseEsipa_U_choice, hf_index, ett_sgp32_AuthenticateClientResponseEsipa_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_AuthenticateClientResponseEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 59, true, dissect_sgp32_AuthenticateClientResponseEsipa_U);

  return offset;
}


static const ber_sequence_t GetBoundProfilePackageOkEsipa_sequence[] = {
  { &hf_sgp32_transactionId , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgp22_TransactionId },
  { &hf_sgp32_boundProfilePackage, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_sgp22_BoundProfilePackage },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetBoundProfilePackageOkEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetBoundProfilePackageOkEsipa_sequence, hf_index, ett_sgp32_GetBoundProfilePackageOkEsipa);

  return offset;
}


static const value_string sgp32_T_getBoundProfilePackageErrorEsipa_vals[] = {
  {   1, "euiccSignatureInvalid" },
  {   2, "confirmationCodeMissing" },
  {   3, "confirmationCodeRefused" },
  {   4, "confirmationCodeRetriesExceeded" },
  {   5, "bppRebindingRefused" },
  {   6, "downloadOrderExpired" },
  {  50, "metadataMismatch" },
  {  95, "invalidTransactionId" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_getBoundProfilePackageErrorEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_GetBoundProfilePackageResponseEsipa_U_vals[] = {
  {   0, "getBoundProfilePackageOkEsipa" },
  {   1, "getBoundProfilePackageErrorEsipa" },
  { 0, NULL }
};

static const ber_choice_t GetBoundProfilePackageResponseEsipa_U_choice[] = {
  {   0, &hf_sgp32_getBoundProfilePackageOkEsipa, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_GetBoundProfilePackageOkEsipa },
  {   1, &hf_sgp32_getBoundProfilePackageErrorEsipa, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_T_getBoundProfilePackageErrorEsipa },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetBoundProfilePackageResponseEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GetBoundProfilePackageResponseEsipa_U_choice, hf_index, ett_sgp32_GetBoundProfilePackageResponseEsipa_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_GetBoundProfilePackageResponseEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 58, true, dissect_sgp32_GetBoundProfilePackageResponseEsipa_U);

  return offset;
}


static const ber_sequence_t CancelSessionOk_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CancelSessionOk(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelSessionOk_sequence, hf_index, ett_sgp32_CancelSessionOk);

  return offset;
}


static const value_string sgp32_T_cancelSessionError_vals[] = {
  {   1, "invalidTransactionId" },
  {   2, "euiccSignatureInvalid" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_cancelSessionError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_CancelSessionResponseEsipa_U_vals[] = {
  {   0, "cancelSessionOk" },
  {   1, "cancelSessionError" },
  { 0, NULL }
};

static const ber_choice_t CancelSessionResponseEsipa_U_choice[] = {
  {   0, &hf_sgp32_cancelSessionOk, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgp32_CancelSessionOk },
  {   1, &hf_sgp32_cancelSessionError, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgp32_T_cancelSessionError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_CancelSessionResponseEsipa_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CancelSessionResponseEsipa_U_choice, hf_index, ett_sgp32_CancelSessionResponseEsipa_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_CancelSessionResponseEsipa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 65, true, dissect_sgp32_CancelSessionResponseEsipa_U);

  return offset;
}


static const value_string sgp32_TransferEimPackageRequest_U_vals[] = {
  {  81, "euiccPackageRequest" },
  {  82, "ipaEuiccDataRequest" },
  {  83, "eimAcknowledgements" },
  {  84, "profileDownloadTriggerRequest" },
  { 0, NULL }
};

static const ber_choice_t TransferEimPackageRequest_U_choice[] = {
  {  81, &hf_sgp32_euiccPackageRequest, BER_CLASS_CON, 81, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageRequest },
  {  82, &hf_sgp32_ipaEuiccDataRequest, BER_CLASS_CON, 82, BER_FLAGS_IMPLTAG, dissect_sgp32_IpaEuiccDataRequest },
  {  83, &hf_sgp32_eimAcknowledgements, BER_CLASS_CON, 83, BER_FLAGS_IMPLTAG, dissect_sgp32_EimAcknowledgements },
  {  84, &hf_sgp32_profileDownloadTriggerRequest, BER_CLASS_CON, 84, BER_FLAGS_IMPLTAG, dissect_sgp32_ProfileDownloadTriggerRequest },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_TransferEimPackageRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TransferEimPackageRequest_U_choice, hf_index, ett_sgp32_TransferEimPackageRequest_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_TransferEimPackageRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 78, true, dissect_sgp32_TransferEimPackageRequest_U);

  return offset;
}


static const value_string sgp32_T_eimPackageError_vals[] = {
  {   1, "noEimPackageAvailable" },
  {   2, "eidNotFound" },
  {   3, "invalidEid" },
  {   4, "missingEid" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_eimPackageError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_GetEimPackageResponse_U_vals[] = {
  {   0, "euiccPackageRequest" },
  {   1, "ipaEuiccDataRequest" },
  {   2, "profileDownloadTriggerRequest" },
  {   3, "eimPackageError" },
  { 0, NULL }
};

static const ber_choice_t GetEimPackageResponse_U_choice[] = {
  {   0, &hf_sgp32_euiccPackageRequest, BER_CLASS_CON, 81, BER_FLAGS_IMPLTAG, dissect_sgp32_EuiccPackageRequest },
  {   1, &hf_sgp32_ipaEuiccDataRequest, BER_CLASS_CON, 82, BER_FLAGS_IMPLTAG, dissect_sgp32_IpaEuiccDataRequest },
  {   2, &hf_sgp32_profileDownloadTriggerRequest, BER_CLASS_CON, 84, BER_FLAGS_IMPLTAG, dissect_sgp32_ProfileDownloadTriggerRequest },
  {   3, &hf_sgp32_eimPackageError, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_eimPackageError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_GetEimPackageResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GetEimPackageResponse_U_choice, hf_index, ett_sgp32_GetEimPackageResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_GetEimPackageResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 79, true, dissect_sgp32_GetEimPackageResponse_U);

  return offset;
}


static const ber_sequence_t T_emptyResponse_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_T_emptyResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_emptyResponse_sequence, hf_index, ett_sgp32_T_emptyResponse);

  return offset;
}


static const value_string sgp32_T_provideEimPackageResultError_vals[] = {
  {   2, "eidNotFound" },
  {   3, "invalidEid" },
  {   4, "missingEid" },
  { 127, "undefinedError" },
  { 0, NULL }
};


static unsigned
dissect_sgp32_T_provideEimPackageResultError(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string sgp32_ProvideEimPackageResultResponse_U_vals[] = {
  {   0, "eimAcknowledgements" },
  {   1, "emptyResponse" },
  {   2, "provideEimPackageResultError" },
  { 0, NULL }
};

static const ber_choice_t ProvideEimPackageResultResponse_U_choice[] = {
  {   0, &hf_sgp32_eimAcknowledgements, BER_CLASS_CON, 83, BER_FLAGS_IMPLTAG, dissect_sgp32_EimAcknowledgements },
  {   1, &hf_sgp32_emptyResponse , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_emptyResponse },
  {   2, &hf_sgp32_provideEimPackageResultError, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_sgp32_T_provideEimPackageResultError },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_ProvideEimPackageResultResponse_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProvideEimPackageResultResponse_U_choice, hf_index, ett_sgp32_ProvideEimPackageResultResponse_U,
                                 NULL);

  return offset;
}



static unsigned
dissect_sgp32_ProvideEimPackageResultResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 80, true, dissect_sgp32_ProvideEimPackageResultResponse_U);

  return offset;
}


static const value_string sgp32_EsipaMessageFromEimToIpa_vals[] = {
  {  57, "initiateAuthenticationResponseEsipa" },
  {  59, "authenticateClientResponseEsipa" },
  {  58, "getBoundProfilePackageResponseEsipa" },
  {  65, "cancelSessionResponseEsipa" },
  {  78, "transferEimPackageRequest" },
  {  79, "getEimPackageResponse" },
  {  80, "provideEimPackageResultResponse" },
  { 0, NULL }
};

static const ber_choice_t EsipaMessageFromEimToIpa_choice[] = {
  {  57, &hf_sgp32_initiateAuthenticationResponseEsipa, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_sgp32_InitiateAuthenticationResponseEsipa },
  {  59, &hf_sgp32_authenticateClientResponseEsipa, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_sgp32_AuthenticateClientResponseEsipa },
  {  58, &hf_sgp32_getBoundProfilePackageResponseEsipa, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_sgp32_GetBoundProfilePackageResponseEsipa },
  {  65, &hf_sgp32_cancelSessionResponseEsipa, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_sgp32_CancelSessionResponseEsipa },
  {  78, &hf_sgp32_transferEimPackageRequest, BER_CLASS_CON, 78, BER_FLAGS_IMPLTAG, dissect_sgp32_TransferEimPackageRequest },
  {  79, &hf_sgp32_getEimPackageResponse, BER_CLASS_CON, 79, BER_FLAGS_IMPLTAG, dissect_sgp32_GetEimPackageResponse },
  {  80, &hf_sgp32_provideEimPackageResultResponse, BER_CLASS_CON, 80, BER_FLAGS_IMPLTAG, dissect_sgp32_ProvideEimPackageResultResponse },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_sgp32_EsipaMessageFromEimToIpa(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int choice;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EsipaMessageFromEimToIpa_choice, hf_index, ett_sgp32_EsipaMessageFromEimToIpa,
                                 &choice);

  if (choice != -1) {
    col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str_const(EsipaMessageFromEimToIpa_choice[choice].value, sgp32_EsipaMessageFromEimToIpa_vals, "Unknown"));
  }

  return offset;
}

/*--- PDUs ---*/

static int dissect_EuiccPackageRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EuiccPackageRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EuiccPackageRequest_PDU);
  return offset;
}
static int dissect_IpaEuiccDataRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_IpaEuiccDataRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_IpaEuiccDataRequest_PDU);
  return offset;
}
static int dissect_ProfileDownloadTriggerRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ProfileDownloadTriggerRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ProfileDownloadTriggerRequest_PDU);
  return offset;
}
static int dissect_ProfileDownloadData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ProfileDownloadData(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ProfileDownloadData_PDU);
  return offset;
}
static int dissect_EimAcknowledgements_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EimAcknowledgements(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EimAcknowledgements_PDU);
  return offset;
}
static int dissect_EuiccPackageResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EuiccPackageResult(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EuiccPackageResult_PDU);
  return offset;
}
static int dissect_IpaEuiccDataResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_IpaEuiccDataResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_IpaEuiccDataResponse_PDU);
  return offset;
}
int dissect_sgp32_ISDRProprietaryApplicationTemplateIoT_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ISDRProprietaryApplicationTemplateIoT(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_sgp32_ISDRProprietaryApplicationTemplateIoT_PDU);
  return offset;
}
static int dissect_IpaeActivationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_IpaeActivationRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_IpaeActivationRequest_PDU);
  return offset;
}
static int dissect_IpaeActivationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_IpaeActivationResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_IpaeActivationResponse_PDU);
  return offset;
}
static int dissect_AddInitialEimRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_AddInitialEimRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_AddInitialEimRequest_PDU);
  return offset;
}
static int dissect_AddInitialEimResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_AddInitialEimResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_AddInitialEimResponse_PDU);
  return offset;
}
static int dissect_EuiccMemoryResetRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EuiccMemoryResetRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EuiccMemoryResetRequest_PDU);
  return offset;
}
static int dissect_EuiccMemoryResetResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EuiccMemoryResetResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EuiccMemoryResetResponse_PDU);
  return offset;
}
static int dissect_GetCertsRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetCertsRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetCertsRequest_PDU);
  return offset;
}
static int dissect_GetCertsResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetCertsResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetCertsResponse_PDU);
  return offset;
}
static int dissect_RetrieveNotificationsListRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_RetrieveNotificationsListRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_RetrieveNotificationsListRequest_PDU);
  return offset;
}
static int dissect_RetrieveNotificationsListResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_RetrieveNotificationsListResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_RetrieveNotificationsListResponse_PDU);
  return offset;
}
static int dissect_ImmediateEnableRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ImmediateEnableRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ImmediateEnableRequest_PDU);
  return offset;
}
static int dissect_ImmediateEnableResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ImmediateEnableResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ImmediateEnableResponse_PDU);
  return offset;
}
static int dissect_ProfileRollbackRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ProfileRollbackRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ProfileRollbackRequest_PDU);
  return offset;
}
static int dissect_ProfileRollbackResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ProfileRollbackResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ProfileRollbackResponse_PDU);
  return offset;
}
static int dissect_ConfigureImmediateProfileEnablingRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ConfigureImmediateProfileEnablingRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ConfigureImmediateProfileEnablingRequest_PDU);
  return offset;
}
static int dissect_ConfigureImmediateProfileEnablingResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ConfigureImmediateProfileEnablingResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ConfigureImmediateProfileEnablingResponse_PDU);
  return offset;
}
static int dissect_GetEimConfigurationDataRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetEimConfigurationDataRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetEimConfigurationDataRequest_PDU);
  return offset;
}
static int dissect_GetEimConfigurationDataResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetEimConfigurationDataResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetEimConfigurationDataResponse_PDU);
  return offset;
}
static int dissect_ExecuteFallbackMechanismRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ExecuteFallbackMechanismRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ExecuteFallbackMechanismRequest_PDU);
  return offset;
}
static int dissect_ExecuteFallbackMechanismResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ExecuteFallbackMechanismResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ExecuteFallbackMechanismResponse_PDU);
  return offset;
}
static int dissect_ReturnFromFallbackRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ReturnFromFallbackRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ReturnFromFallbackRequest_PDU);
  return offset;
}
static int dissect_ReturnFromFallbackResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ReturnFromFallbackResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ReturnFromFallbackResponse_PDU);
  return offset;
}
static int dissect_EnableEmergencyProfileRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EnableEmergencyProfileRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EnableEmergencyProfileRequest_PDU);
  return offset;
}
static int dissect_EnableEmergencyProfileResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EnableEmergencyProfileResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EnableEmergencyProfileResponse_PDU);
  return offset;
}
static int dissect_DisableEmergencyProfileRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_DisableEmergencyProfileRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_DisableEmergencyProfileRequest_PDU);
  return offset;
}
static int dissect_DisableEmergencyProfileResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_DisableEmergencyProfileResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_DisableEmergencyProfileResponse_PDU);
  return offset;
}
static int dissect_GetConnectivityParametersRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetConnectivityParametersRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetConnectivityParametersRequest_PDU);
  return offset;
}
static int dissect_GetConnectivityParametersResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetConnectivityParametersResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetConnectivityParametersResponse_PDU);
  return offset;
}
static int dissect_SetDefaultDpAddressRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_SetDefaultDpAddressRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_SetDefaultDpAddressRequest_PDU);
  return offset;
}
static int dissect_SetDefaultDpAddressResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_SetDefaultDpAddressResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_SetDefaultDpAddressResponse_PDU);
  return offset;
}
static int dissect_EsipaMessageFromIpaToEim_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EsipaMessageFromIpaToEim(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EsipaMessageFromIpaToEim_PDU);
  return offset;
}
static int dissect_EsipaMessageFromEimToIpa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_EsipaMessageFromEimToIpa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_EsipaMessageFromEimToIpa_PDU);
  return offset;
}
static int dissect_InitiateAuthenticationRequestEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_InitiateAuthenticationRequestEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_InitiateAuthenticationRequestEsipa_PDU);
  return offset;
}
static int dissect_InitiateAuthenticationResponseEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_InitiateAuthenticationResponseEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_InitiateAuthenticationResponseEsipa_PDU);
  return offset;
}
static int dissect_AuthenticateClientRequestEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_AuthenticateClientRequestEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_AuthenticateClientRequestEsipa_PDU);
  return offset;
}
static int dissect_AuthenticateClientResponseEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_AuthenticateClientResponseEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_AuthenticateClientResponseEsipa_PDU);
  return offset;
}
static int dissect_GetBoundProfilePackageRequestEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetBoundProfilePackageRequestEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetBoundProfilePackageRequestEsipa_PDU);
  return offset;
}
static int dissect_GetBoundProfilePackageResponseEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetBoundProfilePackageResponseEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetBoundProfilePackageResponseEsipa_PDU);
  return offset;
}
static int dissect_HandleNotificationEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_HandleNotificationEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_HandleNotificationEsipa_PDU);
  return offset;
}
static int dissect_CancelSessionRequestEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_CancelSessionRequestEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_CancelSessionRequestEsipa_PDU);
  return offset;
}
static int dissect_CancelSessionResponseEsipa_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_CancelSessionResponseEsipa(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_CancelSessionResponseEsipa_PDU);
  return offset;
}
static int dissect_GetEimPackageRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetEimPackageRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetEimPackageRequest_PDU);
  return offset;
}
static int dissect_GetEimPackageResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_GetEimPackageResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_GetEimPackageResponse_PDU);
  return offset;
}
static int dissect_ProvideEimPackageResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ProvideEimPackageResult(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ProvideEimPackageResult_PDU);
  return offset;
}
static int dissect_ProvideEimPackageResultResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_ProvideEimPackageResultResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_ProvideEimPackageResultResponse_PDU);
  return offset;
}
static int dissect_TransferEimPackageRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_TransferEimPackageRequest(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_TransferEimPackageRequest_PDU);
  return offset;
}
static int dissect_TransferEimPackageResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_sgp32_TransferEimPackageResponse(false, tvb, offset, &asn1_ctx, tree, hf_sgp32_TransferEimPackageResponse_PDU);
  return offset;
}


static dissector_handle_t sgp32_handle;

/* Dissector tables */
static dissector_table_t sgp22_request_dissector_table;
static dissector_table_t sgp22_response_dissector_table;
static dissector_table_t sgp32_request_dissector_table;
static dissector_table_t sgp32_response_dissector_table;

static int get_sgp32_tag(tvbuff_t *tvb, uint32_t *tag)
{
  int offset = 0;

  *tag = tvb_get_uint8(tvb, offset++);
  if ((*tag & 0x1F) == 0x1F) {
    *tag = (*tag << 8) | tvb_get_uint8(tvb, offset++);
  }

  return offset;
}

static bool is_asn1_header(tvbuff_t *tvb, uint32_t *tag)
{
  uint32_t length = 0;
  int offset;

  offset = get_sgp32_tag(tvb, tag);
  offset = get_ber_length(tvb, offset, &length, NULL);

  return ((offset + length) == tvb_reported_length(tvb));
}

bool is_sgp32_request(tvbuff_t *tvb)
{
  uint32_t tag;

  if (!is_asn1_header(tvb, &tag)) {
    return false;
  }

  return dissector_get_uint_handle(sgp32_request_dissector_table, tag) ||
         dissector_get_uint_handle(sgp22_request_dissector_table, tag);
}

bool is_sgp32_response(tvbuff_t *tvb)
{
  uint32_t tag;

  if (!is_asn1_header(tvb, &tag)) {
    return false;
  }

  return dissector_get_uint_handle(sgp32_response_dissector_table, tag) ||
         dissector_get_uint_handle(sgp22_response_dissector_table, tag);
}

int dissect_sgp32_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;
  uint32_t tag = 0;
  int offset;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  get_sgp32_tag(tvb, &tag);
  offset = dissector_try_uint(sgp32_request_dissector_table, tag, tvb, pinfo, sgp32_tree);
  if (offset == 0) {
    offset = dissector_try_uint(sgp22_request_dissector_table, tag, tvb, pinfo, sgp32_tree);
  }

  return offset;
}

int dissect_sgp32_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;
  uint32_t tag = 0;
  int offset;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  get_sgp32_tag(tvb, &tag);
  offset = dissector_try_uint(sgp32_response_dissector_table, tag, tvb, pinfo, sgp32_tree);
  if (offset == 0) {
    offset = dissector_try_uint(sgp22_response_dissector_table, tag, tvb, pinfo, sgp32_tree);
  }

  return offset;
}

static int dissect_sgp32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  media_content_info_t *content_info = (media_content_info_t *)data;
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;
  int offset;

  if (!content_info ||
      ((content_info->type != MEDIA_CONTAINER_HTTP_REQUEST) &&
       (content_info->type != MEDIA_CONTAINER_HTTP_RESPONSE))) {
    return 0;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");
  col_clear(pinfo->cinfo, COL_INFO);

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  if (content_info->type == MEDIA_CONTAINER_HTTP_REQUEST) {
    offset = dissect_EsipaMessageFromIpaToEim_PDU(tvb, pinfo, sgp32_tree, NULL);
  } else {
    offset = dissect_EsipaMessageFromEimToIpa_PDU(tvb, pinfo, sgp32_tree, NULL);
  }

  return offset;
}

void proto_register_sgp32(void)
{
  static hf_register_info hf[] = {
    { &hf_sgp32_EuiccPackageRequest_PDU,
      { "EuiccPackageRequest", "sgp32.EuiccPackageRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_IpaEuiccDataRequest_PDU,
      { "IpaEuiccDataRequest", "sgp32.IpaEuiccDataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ProfileDownloadTriggerRequest_PDU,
      { "ProfileDownloadTriggerRequest", "sgp32.ProfileDownloadTriggerRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ProfileDownloadData_PDU,
      { "ProfileDownloadData", "sgp32.ProfileDownloadData",
        FT_UINT32, BASE_DEC, VALS(sgp32_ProfileDownloadData_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_EimAcknowledgements_PDU,
      { "EimAcknowledgements", "sgp32.EimAcknowledgements",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_EuiccPackageResult_PDU,
      { "EuiccPackageResult", "sgp32.EuiccPackageResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_EuiccPackageResult_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_IpaEuiccDataResponse_PDU,
      { "IpaEuiccDataResponse", "sgp32.IpaEuiccDataResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_IpaEuiccDataResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_sgp32_ISDRProprietaryApplicationTemplateIoT_PDU,
      { "ISDRProprietaryApplicationTemplateIoT", "sgp32.ISDRProprietaryApplicationTemplateIoT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_IpaeActivationRequest_PDU,
      { "IpaeActivationRequest", "sgp32.IpaeActivationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_IpaeActivationResponse_PDU,
      { "IpaeActivationResponse", "sgp32.IpaeActivationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_AddInitialEimRequest_PDU,
      { "AddInitialEimRequest", "sgp32.AddInitialEimRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_AddInitialEimResponse_PDU,
      { "AddInitialEimResponse", "sgp32.AddInitialEimResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_AddInitialEimResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_EuiccMemoryResetRequest_PDU,
      { "EuiccMemoryResetRequest", "sgp32.EuiccMemoryResetRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_EuiccMemoryResetResponse_PDU,
      { "EuiccMemoryResetResponse", "sgp32.EuiccMemoryResetResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_GetCertsRequest_PDU,
      { "GetCertsRequest", "sgp32.GetCertsRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_GetCertsResponse_PDU,
      { "GetCertsResponse", "sgp32.GetCertsResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_GetCertsResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_RetrieveNotificationsListRequest_PDU,
      { "RetrieveNotificationsListRequest", "sgp32.RetrieveNotificationsListRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_RetrieveNotificationsListResponse_PDU,
      { "RetrieveNotificationsListResponse", "sgp32.RetrieveNotificationsListResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_RetrieveNotificationsListResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_ImmediateEnableRequest_PDU,
      { "ImmediateEnableRequest", "sgp32.ImmediateEnableRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ImmediateEnableResponse_PDU,
      { "ImmediateEnableResponse", "sgp32.ImmediateEnableResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ProfileRollbackRequest_PDU,
      { "ProfileRollbackRequest", "sgp32.ProfileRollbackRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ProfileRollbackResponse_PDU,
      { "ProfileRollbackResponse", "sgp32.ProfileRollbackResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ConfigureImmediateProfileEnablingRequest_PDU,
      { "ConfigureImmediateProfileEnablingRequest", "sgp32.ConfigureImmediateProfileEnablingRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ConfigureImmediateProfileEnablingResponse_PDU,
      { "ConfigureImmediateProfileEnablingResponse", "sgp32.ConfigureImmediateProfileEnablingResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_GetEimConfigurationDataRequest_PDU,
      { "GetEimConfigurationDataRequest", "sgp32.GetEimConfigurationDataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_GetEimConfigurationDataResponse_PDU,
      { "GetEimConfigurationDataResponse", "sgp32.GetEimConfigurationDataResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ExecuteFallbackMechanismRequest_PDU,
      { "ExecuteFallbackMechanismRequest", "sgp32.ExecuteFallbackMechanismRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ExecuteFallbackMechanismResponse_PDU,
      { "ExecuteFallbackMechanismResponse", "sgp32.ExecuteFallbackMechanismResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ReturnFromFallbackRequest_PDU,
      { "ReturnFromFallbackRequest", "sgp32.ReturnFromFallbackRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ReturnFromFallbackResponse_PDU,
      { "ReturnFromFallbackResponse", "sgp32.ReturnFromFallbackResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_EnableEmergencyProfileRequest_PDU,
      { "EnableEmergencyProfileRequest", "sgp32.EnableEmergencyProfileRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_EnableEmergencyProfileResponse_PDU,
      { "EnableEmergencyProfileResponse", "sgp32.EnableEmergencyProfileResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_DisableEmergencyProfileRequest_PDU,
      { "DisableEmergencyProfileRequest", "sgp32.DisableEmergencyProfileRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_DisableEmergencyProfileResponse_PDU,
      { "DisableEmergencyProfileResponse", "sgp32.DisableEmergencyProfileResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_GetConnectivityParametersRequest_PDU,
      { "GetConnectivityParametersRequest", "sgp32.GetConnectivityParametersRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_GetConnectivityParametersResponse_PDU,
      { "GetConnectivityParametersResponse", "sgp32.GetConnectivityParametersResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_GetConnectivityParametersResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_SetDefaultDpAddressRequest_PDU,
      { "SetDefaultDpAddressRequest", "sgp32.SetDefaultDpAddressRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_SetDefaultDpAddressResponse_PDU,
      { "SetDefaultDpAddressResponse", "sgp32.SetDefaultDpAddressResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_EsipaMessageFromIpaToEim_PDU,
      { "EsipaMessageFromIpaToEim", "sgp32.EsipaMessageFromIpaToEim",
        FT_UINT32, BASE_DEC, VALS(sgp32_EsipaMessageFromIpaToEim_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_EsipaMessageFromEimToIpa_PDU,
      { "EsipaMessageFromEimToIpa", "sgp32.EsipaMessageFromEimToIpa",
        FT_UINT32, BASE_DEC, VALS(sgp32_EsipaMessageFromEimToIpa_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_InitiateAuthenticationRequestEsipa_PDU,
      { "InitiateAuthenticationRequestEsipa", "sgp32.InitiateAuthenticationRequestEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_InitiateAuthenticationResponseEsipa_PDU,
      { "InitiateAuthenticationResponseEsipa", "sgp32.InitiateAuthenticationResponseEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_InitiateAuthenticationResponseEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_AuthenticateClientRequestEsipa_PDU,
      { "AuthenticateClientRequestEsipa", "sgp32.AuthenticateClientRequestEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_AuthenticateClientResponseEsipa_PDU,
      { "AuthenticateClientResponseEsipa", "sgp32.AuthenticateClientResponseEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_AuthenticateClientResponseEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_GetBoundProfilePackageRequestEsipa_PDU,
      { "GetBoundProfilePackageRequestEsipa", "sgp32.GetBoundProfilePackageRequestEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_GetBoundProfilePackageResponseEsipa_PDU,
      { "GetBoundProfilePackageResponseEsipa", "sgp32.GetBoundProfilePackageResponseEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_GetBoundProfilePackageResponseEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_HandleNotificationEsipa_PDU,
      { "HandleNotificationEsipa", "sgp32.HandleNotificationEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_HandleNotificationEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_CancelSessionRequestEsipa_PDU,
      { "CancelSessionRequestEsipa", "sgp32.CancelSessionRequestEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_CancelSessionResponseEsipa_PDU,
      { "CancelSessionResponseEsipa", "sgp32.CancelSessionResponseEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_CancelSessionResponseEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_GetEimPackageRequest_PDU,
      { "GetEimPackageRequest", "sgp32.GetEimPackageRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_GetEimPackageResponse_PDU,
      { "GetEimPackageResponse", "sgp32.GetEimPackageResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_GetEimPackageResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_ProvideEimPackageResult_PDU,
      { "ProvideEimPackageResult", "sgp32.ProvideEimPackageResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ProvideEimPackageResultResponse_PDU,
      { "ProvideEimPackageResultResponse", "sgp32.ProvideEimPackageResultResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_ProvideEimPackageResultResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_TransferEimPackageRequest_PDU,
      { "TransferEimPackageRequest", "sgp32.TransferEimPackageRequest",
        FT_UINT32, BASE_DEC, VALS(sgp32_TransferEimPackageRequest_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_TransferEimPackageResponse_PDU,
      { "TransferEimPackageResponse", "sgp32.TransferEimPackageResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_TransferEimPackageResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccPackageSigned,
      { "euiccPackageSigned", "sgp32.euiccPackageSigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_eimSignature,
      { "eimSignature", "sgp32.eimSignature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_eimId,
      { "eimId", "sgp32.eimId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_128", HFILL }},
    { &hf_sgp32_eidValue,
      { "eidValue", "sgp32.eidValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet16", HFILL }},
    { &hf_sgp32_counterValue,
      { "counterValue", "sgp32.counterValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_sgp32_eimTransactionId,
      { "eimTransactionId", "sgp32.eimTransactionId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransactionId", HFILL }},
    { &hf_sgp32_euiccPackage,
      { "euiccPackage", "sgp32.euiccPackage",
        FT_UINT32, BASE_DEC, VALS(sgp32_EuiccPackage_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_psmoList,
      { "psmoList", "sgp32.psmoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Psmo", HFILL }},
    { &hf_sgp32_psmoList_item,
      { "Psmo", "sgp32.Psmo",
        FT_UINT32, BASE_DEC, VALS(sgp32_Psmo_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_ecoList,
      { "ecoList", "sgp32.ecoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Eco", HFILL }},
    { &hf_sgp32_ecoList_item,
      { "Eco", "sgp32.Eco",
        FT_UINT32, BASE_DEC, VALS(sgp32_Eco_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_eimFqdn,
      { "eimFqdn", "sgp32.eimFqdn",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_eimIdType,
      { "eimIdType", "sgp32.eimIdType",
        FT_INT32, BASE_DEC, VALS(sgp32_EimIdType_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_associationToken,
      { "associationToken", "sgp32.associationToken",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_sgp32_eimPublicKeyData,
      { "eimPublicKeyData", "sgp32.eimPublicKeyData",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_eimPublicKeyData_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_eimPublicKey,
      { "eimPublicKey", "sgp32.eimPublicKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubjectPublicKeyInfo", HFILL }},
    { &hf_sgp32_eimCertificate,
      { "eimCertificate", "sgp32.eimCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp32_trustedPublicKeyDataTls,
      { "trustedPublicKeyDataTls", "sgp32.trustedPublicKeyDataTls",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_trustedPublicKeyDataTls_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_trustedEimPkTls,
      { "trustedEimPkTls", "sgp32.trustedEimPkTls_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubjectPublicKeyInfo", HFILL }},
    { &hf_sgp32_trustedCertificateTls,
      { "trustedCertificateTls", "sgp32.trustedCertificateTls_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp32_eimSupportedProtocol,
      { "eimSupportedProtocol", "sgp32.eimSupportedProtocol",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccCiPKId,
      { "euiccCiPKId", "sgp32.euiccCiPKId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SubjectKeyIdentifier", HFILL }},
    { &hf_sgp32_indirectProfileDownload,
      { "indirectProfileDownload", "sgp32.indirectProfileDownload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_addEim,
      { "addEim", "sgp32.addEim_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EimConfigurationData", HFILL }},
    { &hf_sgp32_deleteEim,
      { "deleteEim", "sgp32.deleteEim_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_eimId_01,
      { "eimId", "sgp32.eimId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_updateEim,
      { "updateEim", "sgp32.updateEim_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EimConfigurationData", HFILL }},
    { &hf_sgp32_listEim,
      { "listEim", "sgp32.listEim_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_enable,
      { "enable", "sgp32.enable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_iccid,
      { "iccid", "sgp32.iccid",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_rollbackFlag,
      { "rollbackFlag", "sgp32.rollbackFlag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_disable,
      { "disable", "sgp32.disable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_delete,
      { "delete", "sgp32.delete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_listProfileInfo,
      { "listProfileInfo", "sgp32.listProfileInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProfileInfoListRequest", HFILL }},
    { &hf_sgp32_getRAT,
      { "getRAT", "sgp32.getRAT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_configureImmediateEnable,
      { "configureImmediateEnable", "sgp32.configureImmediateEnable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_immediateEnableFlag,
      { "immediateEnableFlag", "sgp32.immediateEnableFlag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_defaultSmdpOid,
      { "defaultSmdpOid", "sgp32.defaultSmdpOid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_sgp32_defaultSmdpAddress,
      { "defaultSmdpAddress", "sgp32.defaultSmdpAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_setFallbackAttribute,
      { "setFallbackAttribute", "sgp32.setFallbackAttribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_unsetFallbackAttribute,
      { "unsetFallbackAttribute", "sgp32.unsetFallbackAttribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_setDefaultDpAddress,
      { "setDefaultDpAddress", "sgp32.setDefaultDpAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SetDefaultDpAddressRequest", HFILL }},
    { &hf_sgp32_tagList,
      { "tagList", "sgp32.tagList",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_euiccCiPKIdentifierToBeUsed,
      { "euiccCiPKIdentifierToBeUsed", "sgp32.euiccCiPKIdentifierToBeUsed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_searchCriteriaNotification,
      { "searchCriteriaNotification", "sgp32.searchCriteriaNotification",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_searchCriteriaNotification_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_seqNumber,
      { "seqNumber", "sgp32.seqNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_sgp32_profileManagementOperation,
      { "profileManagementOperation", "sgp32.profileManagementOperation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NotificationEvent", HFILL }},
    { &hf_sgp32_searchCriteriaEuiccPackageResult,
      { "searchCriteriaEuiccPackageResult", "sgp32.searchCriteriaEuiccPackageResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_searchCriteriaEuiccPackageResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_profileDownloadData,
      { "profileDownloadData", "sgp32.profileDownloadData",
        FT_UINT32, BASE_DEC, VALS(sgp32_ProfileDownloadData_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_activationCode,
      { "activationCode", "sgp32.activationCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_255", HFILL }},
    { &hf_sgp32_contactDefaultSmdp,
      { "contactDefaultSmdp", "sgp32.contactDefaultSmdp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_contactSmds,
      { "contactSmds", "sgp32.contactSmds_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_smdsAddress,
      { "smdsAddress", "sgp32.smdsAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32__untag_item,
      { "SequenceNumber", "sgp32.SequenceNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccPackageResultSigned,
      { "euiccPackageResultSigned", "sgp32.euiccPackageResultSigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccPackageErrorSigned,
      { "euiccPackageErrorSigned", "sgp32.euiccPackageErrorSigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccPackageErrorUnsigned,
      { "euiccPackageErrorUnsigned", "sgp32.euiccPackageErrorUnsigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccPackageResultDataSigned,
      { "euiccPackageResultDataSigned", "sgp32.euiccPackageResultDataSigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccSignEPR,
      { "euiccSignEPR", "sgp32.euiccSignEPR",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_euiccResult,
      { "euiccResult", "sgp32.euiccResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EuiccResultData", HFILL }},
    { &hf_sgp32_euiccResult_item,
      { "EuiccResultData", "sgp32.EuiccResultData",
        FT_UINT32, BASE_DEC, VALS(sgp32_EuiccResultData_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_enableResult,
      { "enableResult", "sgp32.enableResult",
        FT_INT32, BASE_DEC, VALS(sgp32_EnableProfileResult_vals), 0,
        "EnableProfileResult", HFILL }},
    { &hf_sgp32_disableResult,
      { "disableResult", "sgp32.disableResult",
        FT_INT32, BASE_DEC, VALS(sgp32_DisableProfileResult_vals), 0,
        "DisableProfileResult", HFILL }},
    { &hf_sgp32_deleteResult,
      { "deleteResult", "sgp32.deleteResult",
        FT_INT32, BASE_DEC, VALS(sgp32_DeleteProfileResult_vals), 0,
        "DeleteProfileResult", HFILL }},
    { &hf_sgp32_listProfileInfoResult,
      { "listProfileInfoResult", "sgp32.listProfileInfoResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_ProfileInfoListResponse_U_vals), 0,
        "ProfileInfoListResponse", HFILL }},
    { &hf_sgp32_getRATResult,
      { "getRATResult", "sgp32.getRATResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RulesAuthorisationTable", HFILL }},
    { &hf_sgp32_configureImmediateEnableResult,
      { "configureImmediateEnableResult", "sgp32.configureImmediateEnableResult",
        FT_INT32, BASE_DEC, VALS(sgp32_ConfigureImmediateEnableResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_addEimResult,
      { "addEimResult", "sgp32.addEimResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_AddEimResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_deleteEimResult,
      { "deleteEimResult", "sgp32.deleteEimResult",
        FT_INT32, BASE_DEC, VALS(sgp32_DeleteEimResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_updateEimResult,
      { "updateEimResult", "sgp32.updateEimResult",
        FT_INT32, BASE_DEC, VALS(sgp32_UpdateEimResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_listEimResult,
      { "listEimResult", "sgp32.listEimResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_ListEimResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_rollbackResult,
      { "rollbackResult", "sgp32.rollbackResult",
        FT_INT32, BASE_DEC, VALS(sgp32_RollbackProfileResult_vals), 0,
        "RollbackProfileResult", HFILL }},
    { &hf_sgp32_setFallbackAttributeResult,
      { "setFallbackAttributeResult", "sgp32.setFallbackAttributeResult",
        FT_INT32, BASE_DEC, VALS(sgp32_SetFallbackAttributeResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_unsetFallbackAttributeResult,
      { "unsetFallbackAttributeResult", "sgp32.unsetFallbackAttributeResult",
        FT_INT32, BASE_DEC, VALS(sgp32_UnsetFallbackAttributeResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_processingTerminated,
      { "processingTerminated", "sgp32.processingTerminated",
        FT_INT32, BASE_DEC, VALS(sgp32_T_processingTerminated_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_setDefaultDpAddressResult,
      { "setDefaultDpAddressResult", "sgp32.setDefaultDpAddressResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SetDefaultDpAddressResponse", HFILL }},
    { &hf_sgp32_euiccPackageErrorDataSigned,
      { "euiccPackageErrorDataSigned", "sgp32.euiccPackageErrorDataSigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccSignEPE,
      { "euiccSignEPE", "sgp32.euiccSignEPE",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_euiccPackageErrorCode,
      { "euiccPackageErrorCode", "sgp32.euiccPackageErrorCode",
        FT_INT32, BASE_DEC, VALS(sgp32_EuiccPackageErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_profileInfoListOk,
      { "profileInfoListOk", "sgp32.profileInfoListOk",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ProfileInfo", HFILL }},
    { &hf_sgp32_profileInfoListOk_item,
      { "ProfileInfo", "sgp32.ProfileInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_profileInfoListError,
      { "profileInfoListError", "sgp32.profileInfoListError",
        FT_INT32, BASE_DEC, VALS(sgp32_ProfileInfoListError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_addEimResultCode,
      { "addEimResultCode", "sgp32.addEimResultCode",
        FT_INT32, BASE_DEC, VALS(sgp32_T_addEimResultCode_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_eimIdList,
      { "eimIdList", "sgp32.eimIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EimIdInfo", HFILL }},
    { &hf_sgp32_eimIdList_item,
      { "EimIdInfo", "sgp32.EimIdInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_listEimError,
      { "listEimError", "sgp32.listEimError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_listEimError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaEuiccDataErrorCode,
      { "ipaEuiccDataErrorCode", "sgp32.ipaEuiccDataErrorCode",
        FT_INT32, BASE_DEC, VALS(sgp32_IpaEuiccDataErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaEuiccData,
      { "ipaEuiccData", "sgp32.ipaEuiccData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaEuiccDataResponseError,
      { "ipaEuiccDataResponseError", "sgp32.ipaEuiccDataResponseError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_PendingNotificationList_item,
      { "PendingNotification", "sgp32.PendingNotification",
        FT_UINT32, BASE_DEC, VALS(sgp32_PendingNotification_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_EuiccPackageResultList_item,
      { "EuiccPackageResult", "sgp32.EuiccPackageResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_EuiccPackageResult_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_notificationsList,
      { "notificationsList", "sgp32.notificationsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PendingNotificationList", HFILL }},
    { &hf_sgp32_euiccPackageResultList,
      { "euiccPackageResultList", "sgp32.euiccPackageResultList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccInfo1,
      { "euiccInfo1", "sgp32.euiccInfo1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccInfo2,
      { "euiccInfo2", "sgp32.euiccInfo2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_rootSmdsAddress,
      { "rootSmdsAddress", "sgp32.rootSmdsAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_eumCertificate,
      { "eumCertificate", "sgp32.eumCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp32_euiccCertificate,
      { "euiccCertificate", "sgp32.euiccCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp32_ipaCapabilities,
      { "ipaCapabilities", "sgp32.ipaCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_deviceInfo,
      { "deviceInfo", "sgp32.deviceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_profileDownloadTriggerResultData,
      { "profileDownloadTriggerResultData", "sgp32.profileDownloadTriggerResultData",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_profileDownloadTriggerResultData_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_profileInstallationResult,
      { "profileInstallationResult", "sgp32.profileInstallationResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_profileDownloadError,
      { "profileDownloadError", "sgp32.profileDownloadError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_profileDownloadErrorReason,
      { "profileDownloadErrorReason", "sgp32.profileDownloadErrorReason",
        FT_INT32, BASE_DEC, VALS(sgp32_T_profileDownloadErrorReason_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_errorResponse,
      { "errorResponse", "sgp32.errorResponse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_euiccConfiguration,
      { "euiccConfiguration", "sgp32.euiccConfiguration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaeOption,
      { "ipaeOption", "sgp32.ipaeOption",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaeActivationResult,
      { "ipaeActivationResult", "sgp32.ipaeActivationResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_ipaeActivationResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaFeatures,
      { "ipaFeatures", "sgp32.ipaFeatures",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaSupportedProtocols,
      { "ipaSupportedProtocols", "sgp32.ipaSupportedProtocols",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_isdpAid,
      { "isdpAid", "sgp32.isdpAid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OctetTo16", HFILL }},
    { &hf_sgp32_profileState,
      { "profileState", "sgp32.profileState",
        FT_INT32, BASE_DEC, VALS(sgp22_ProfileState_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_profileNickname,
      { "profileNickname", "sgp32.profileNickname",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_64", HFILL }},
    { &hf_sgp32_serviceProviderName,
      { "serviceProviderName", "sgp32.serviceProviderName",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_32", HFILL }},
    { &hf_sgp32_profileName,
      { "profileName", "sgp32.profileName",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_64", HFILL }},
    { &hf_sgp32_iconType,
      { "iconType", "sgp32.iconType",
        FT_INT32, BASE_DEC, VALS(sgp22_IconType_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_icon,
      { "icon", "sgp32.icon",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_1024", HFILL }},
    { &hf_sgp32_profileClass,
      { "profileClass", "sgp32.profileClass",
        FT_INT32, BASE_DEC, VALS(sgp22_ProfileClass_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_notificationConfigurationInfo,
      { "notificationConfigurationInfo", "sgp32.notificationConfigurationInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_NotificationConfigurationInformation", HFILL }},
    { &hf_sgp32_notificationConfigurationInfo_item,
      { "NotificationConfigurationInformation", "sgp32.NotificationConfigurationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_profileOwner,
      { "profileOwner", "sgp32.profileOwner_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OperatorId", HFILL }},
    { &hf_sgp32_dpProprietaryData,
      { "dpProprietaryData", "sgp32.dpProprietaryData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_profilePolicyRules,
      { "profilePolicyRules", "sgp32.profilePolicyRules",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PprIds", HFILL }},
    { &hf_sgp32_serviceSpecificDataStoredInEuicc,
      { "serviceSpecificDataStoredInEuicc", "sgp32.serviceSpecificDataStoredInEuicc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VendorSpecificExtension", HFILL }},
    { &hf_sgp32_ecallIndication,
      { "ecallIndication", "sgp32.ecallIndication",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_sgp32_fallbackAttribute,
      { "fallbackAttribute", "sgp32.fallbackAttribute",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_sgp32_fallbackAllowed,
      { "fallbackAllowed", "sgp32.fallbackAllowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_sgp32_serviceSpecificDataNotStoredInEuicc,
      { "serviceSpecificDataNotStoredInEuicc", "sgp32.serviceSpecificDataNotStoredInEuicc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VendorSpecificExtension", HFILL }},
    { &hf_sgp32_profileVersion,
      { "profileVersion", "sgp32.profileVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp32_svn,
      { "svn", "sgp32.svn",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp32_euiccFirmwareVer,
      { "euiccFirmwareVer", "sgp32.euiccFirmwareVer",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp32_extCardResource,
      { "extCardResource", "sgp32.extCardResource",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_uiccCapability,
      { "uiccCapability", "sgp32.uiccCapability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ts102241Version,
      { "ts102241Version", "sgp32.ts102241Version",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp32_globalplatformVersion,
      { "globalplatformVersion", "sgp32.globalplatformVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp32_rspCapability,
      { "rspCapability", "sgp32.rspCapability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccCiPKIdListForVerification,
      { "euiccCiPKIdListForVerification", "sgp32.euiccCiPKIdListForVerification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SubjectKeyIdentifier", HFILL }},
    { &hf_sgp32_euiccCiPKIdListForVerification_item,
      { "SubjectKeyIdentifier", "sgp32.SubjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccCiPKIdListForSigning,
      { "euiccCiPKIdListForSigning", "sgp32.euiccCiPKIdListForSigning",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SubjectKeyIdentifier", HFILL }},
    { &hf_sgp32_euiccCiPKIdListForSigning_item,
      { "SubjectKeyIdentifier", "sgp32.SubjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccCategory,
      { "euiccCategory", "sgp32.euiccCategory",
        FT_INT32, BASE_DEC, VALS(sgp32_T_euiccCategory_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_forbiddenProfilePolicyRules,
      { "forbiddenProfilePolicyRules", "sgp32.forbiddenProfilePolicyRules",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PprIds", HFILL }},
    { &hf_sgp32_ppVersion,
      { "ppVersion", "sgp32.ppVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp32_sasAcreditationNumber,
      { "sasAcreditationNumber", "sgp32.sasAcreditationNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_0_64", HFILL }},
    { &hf_sgp32_certificationDataObject,
      { "certificationDataObject", "sgp32.certificationDataObject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_treProperties,
      { "treProperties", "sgp32.treProperties",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_treProductReference,
      { "treProductReference", "sgp32.treProductReference",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_additionalEuiccProfilePackageVersions,
      { "additionalEuiccProfilePackageVersions", "sgp32.additionalEuiccProfilePackageVersions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_VersionType", HFILL }},
    { &hf_sgp32_additionalEuiccProfilePackageVersions_item,
      { "VersionType", "sgp32.VersionType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaMode,
      { "ipaMode", "sgp32.ipaMode",
        FT_INT32, BASE_DEC, VALS(sgp32_IpaMode_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccCiPKIdListForSigningV3,
      { "euiccCiPKIdListForSigningV3", "sgp32.euiccCiPKIdListForSigningV3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SubjectKeyIdentifier", HFILL }},
    { &hf_sgp32_euiccCiPKIdListForSigningV3_item,
      { "SubjectKeyIdentifier", "sgp32.SubjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_additionalEuiccInfo,
      { "additionalEuiccInfo", "sgp32.additionalEuiccInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_32", HFILL }},
    { &hf_sgp32_highestSvn,
      { "highestSvn", "sgp32.highestSvn",
        FT_STRING, BASE_NONE, NULL, 0,
        "VersionType", HFILL }},
    { &hf_sgp32_iotSpecificInfo,
      { "iotSpecificInfo", "sgp32.iotSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_iotVersion,
      { "iotVersion", "sgp32.iotVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_VersionType", HFILL }},
    { &hf_sgp32_iotVersion_item,
      { "VersionType", "sgp32.VersionType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ecallSupported,
      { "ecallSupported", "sgp32.ecallSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_fallbackSupported,
      { "fallbackSupported", "sgp32.fallbackSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_eimConfigurationDataList,
      { "eimConfigurationDataList", "sgp32.eimConfigurationDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EimConfigurationData", HFILL }},
    { &hf_sgp32_eimConfigurationDataList_item,
      { "EimConfigurationData", "sgp32.EimConfigurationData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_addInitialEimOk,
      { "addInitialEimOk", "sgp32.addInitialEimOk",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_addInitialEimOk_item,
      { "addInitialEimOk item", "sgp32.addInitialEimOk_item",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_addInitialEimOk_item_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_addOk,
      { "addOk", "sgp32.addOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_addInitialEimError,
      { "addInitialEimError", "sgp32.addInitialEimError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_addInitialEimError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_resetOptions,
      { "resetOptions", "sgp32.resetOptions",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_resetResult,
      { "resetResult", "sgp32.resetResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_resetResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_resetEimResult,
      { "resetEimResult", "sgp32.resetEimResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_resetEimResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_resetImmediateEnableConfigResult,
      { "resetImmediateEnableConfigResult", "sgp32.resetImmediateEnableConfigResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_resetImmediateEnableConfigResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_certs,
      { "certs", "sgp32.certs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_getCertsError,
      { "getCertsError", "sgp32.getCertsError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_getCertsError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_searchCriteria,
      { "searchCriteria", "sgp32.searchCriteria",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_searchCriteria_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccPackageResults,
      { "euiccPackageResults", "sgp32.euiccPackageResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_notificationList,
      { "notificationList", "sgp32.notificationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PendingNotificationList", HFILL }},
    { &hf_sgp32_notificationsListResultError,
      { "notificationsListResultError", "sgp32.notificationsListResultError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_notificationsListResultError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_refreshFlag,
      { "refreshFlag", "sgp32.refreshFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_sgp32_immediateEnableResult,
      { "immediateEnableResult", "sgp32.immediateEnableResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_immediateEnableResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_cmdResult,
      { "cmdResult", "sgp32.cmdResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_cmdResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_eUICCPackageResult,
      { "eUICCPackageResult", "sgp32.eUICCPackageResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_EuiccPackageResult_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_configImmediateEnableResult,
      { "configImmediateEnableResult", "sgp32.configImmediateEnableResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_configImmediateEnableResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_searchCriteria_01,
      { "searchCriteria", "sgp32.searchCriteria",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_searchCriteria_01_vals), 0,
        "T_searchCriteria_01", HFILL }},
    { &hf_sgp32_executeFallbackMechanismResult,
      { "executeFallbackMechanismResult", "sgp32.executeFallbackMechanismResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_executeFallbackMechanismResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_returnFromFallbackResult,
      { "returnFromFallbackResult", "sgp32.returnFromFallbackResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_returnFromFallbackResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_enableEmergencyProfileResult,
      { "enableEmergencyProfileResult", "sgp32.enableEmergencyProfileResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_enableEmergencyProfileResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_disableEmergencyProfileResult,
      { "disableEmergencyProfileResult", "sgp32.disableEmergencyProfileResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_disableEmergencyProfileResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_connectivityParameters,
      { "connectivityParameters", "sgp32.connectivityParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_connectivityParametersError,
      { "connectivityParametersError", "sgp32.connectivityParametersError",
        FT_INT32, BASE_DEC, VALS(sgp32_ConnectivityParametersError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_httpParams,
      { "httpParams", "sgp32.httpParams",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_defaultDpAddress,
      { "defaultDpAddress", "sgp32.defaultDpAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_setDefaultDpAddressResult_01,
      { "setDefaultDpAddressResult", "sgp32.setDefaultDpAddressResult",
        FT_INT32, BASE_DEC, VALS(sgp32_T_setDefaultDpAddressResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_downloadResponseOk,
      { "downloadResponseOk", "sgp32.downloadResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareDownloadResponseOk", HFILL }},
    { &hf_sgp32_downloadResponseError,
      { "downloadResponseError", "sgp32.downloadResponseError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareDownloadResponseError", HFILL }},
    { &hf_sgp32_compactDownloadResponseOk,
      { "compactDownloadResponseOk", "sgp32.compactDownloadResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompactPrepareDownloadResponseOk", HFILL }},
    { &hf_sgp32_compactEuiccSigned2,
      { "compactEuiccSigned2", "sgp32.compactEuiccSigned2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccSignature2,
      { "euiccSignature2", "sgp32.euiccSignature2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_euiccOtpk,
      { "euiccOtpk", "sgp32.euiccOtpk",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_hashCc,
      { "hashCc", "sgp32.hashCc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet32", HFILL }},
    { &hf_sgp32_transactionId,
      { "transactionId", "sgp32.transactionId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_serverAddress,
      { "serverAddress", "sgp32.serverAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_serverChallenge,
      { "serverChallenge", "sgp32.serverChallenge",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet16", HFILL }},
    { &hf_sgp32_ctxParams1,
      { "ctxParams1", "sgp32.ctxParams1",
        FT_UINT32, BASE_DEC, VALS(sgp22_CtxParams1_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccSigned1,
      { "euiccSigned1", "sgp32.euiccSigned1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccSignature1,
      { "euiccSignature1", "sgp32.euiccSignature1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_authenticateResponseOk,
      { "authenticateResponseOk", "sgp32.authenticateResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_authenticateResponseError,
      { "authenticateResponseError", "sgp32.authenticateResponseError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_compactAuthenticateResponseOk,
      { "compactAuthenticateResponseOk", "sgp32.compactAuthenticateResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_signedData,
      { "signedData", "sgp32.signedData",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_signedData_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_compactEuiccSigned1,
      { "compactEuiccSigned1", "sgp32.compactEuiccSigned1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_otherSignedNotification,
      { "otherSignedNotification", "sgp32.otherSignedNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_compactProfileInstallationResult,
      { "compactProfileInstallationResult", "sgp32.compactProfileInstallationResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_compactOtherSignedNotification,
      { "compactOtherSignedNotification", "sgp32.compactOtherSignedNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_profileInstallationResultData,
      { "profileInstallationResultData", "sgp32.profileInstallationResultData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccSignPIR,
      { "euiccSignPIR", "sgp32.euiccSignPIR",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_compactProfileInstallationResultData,
      { "compactProfileInstallationResultData", "sgp32.compactProfileInstallationResultData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_iccidPresent,
      { "iccidPresent", "sgp32.iccidPresent",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_sgp32_compactFinalResult,
      { "compactFinalResult", "sgp32.compactFinalResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_T_compactFinalResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_compactSuccessResult,
      { "compactSuccessResult", "sgp32.compactSuccessResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_errorResult,
      { "errorResult", "sgp32.errorResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_compactAid,
      { "compactAid", "sgp32.compactAid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_sgp32_simaResponse,
      { "simaResponse", "sgp32.simaResponse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_tbsOtherNotification,
      { "tbsOtherNotification", "sgp32.tbsOtherNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NotificationMetadata", HFILL }},
    { &hf_sgp32_euiccNotificationSignature,
      { "euiccNotificationSignature", "sgp32.euiccNotificationSignature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_cancelSessionResponseOk,
      { "cancelSessionResponseOk", "sgp32.cancelSessionResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_cancelSessionResponseError,
      { "cancelSessionResponseError", "sgp32.cancelSessionResponseError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_cancelSessionResponseError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_compactCancelSessionResponseOk,
      { "compactCancelSessionResponseOk", "sgp32.compactCancelSessionResponseOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_compactEuiccCancelSessionSigned,
      { "compactEuiccCancelSessionSigned", "sgp32.compactEuiccCancelSessionSigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccCancelSessionSignature,
      { "euiccCancelSessionSignature", "sgp32.euiccCancelSessionSignature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_reason,
      { "reason", "sgp32.reason",
        FT_INT32, BASE_DEC, VALS(sgp22_CancelSessionReason_vals), 0,
        "CancelSessionReason", HFILL }},
    { &hf_sgp32_initiateAuthenticationRequestEsipa,
      { "initiateAuthenticationRequestEsipa", "sgp32.initiateAuthenticationRequestEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_authenticateClientRequestEsipa,
      { "authenticateClientRequestEsipa", "sgp32.authenticateClientRequestEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_getBoundProfilePackageRequestEsipa,
      { "getBoundProfilePackageRequestEsipa", "sgp32.getBoundProfilePackageRequestEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_cancelSessionRequestEsipa,
      { "cancelSessionRequestEsipa", "sgp32.cancelSessionRequestEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_handleNotificationEsipa,
      { "handleNotificationEsipa", "sgp32.handleNotificationEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_HandleNotificationEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_transferEimPackageResponse,
      { "transferEimPackageResponse", "sgp32.transferEimPackageResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_TransferEimPackageResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_getEimPackageRequest,
      { "getEimPackageRequest", "sgp32.getEimPackageRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_provideEimPackageResult,
      { "provideEimPackageResult", "sgp32.provideEimPackageResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_initiateAuthenticationResponseEsipa,
      { "initiateAuthenticationResponseEsipa", "sgp32.initiateAuthenticationResponseEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_InitiateAuthenticationResponseEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_authenticateClientResponseEsipa,
      { "authenticateClientResponseEsipa", "sgp32.authenticateClientResponseEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_AuthenticateClientResponseEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_getBoundProfilePackageResponseEsipa,
      { "getBoundProfilePackageResponseEsipa", "sgp32.getBoundProfilePackageResponseEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_GetBoundProfilePackageResponseEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_cancelSessionResponseEsipa,
      { "cancelSessionResponseEsipa", "sgp32.cancelSessionResponseEsipa",
        FT_UINT32, BASE_DEC, VALS(sgp32_CancelSessionResponseEsipa_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_transferEimPackageRequest,
      { "transferEimPackageRequest", "sgp32.transferEimPackageRequest",
        FT_UINT32, BASE_DEC, VALS(sgp32_TransferEimPackageRequest_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_getEimPackageResponse,
      { "getEimPackageResponse", "sgp32.getEimPackageResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_GetEimPackageResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_provideEimPackageResultResponse,
      { "provideEimPackageResultResponse", "sgp32.provideEimPackageResultResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_ProvideEimPackageResultResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccChallenge,
      { "euiccChallenge", "sgp32.euiccChallenge",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Octet16", HFILL }},
    { &hf_sgp32_smdpAddress,
      { "smdpAddress", "sgp32.smdpAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_initiateAuthenticationOkEsipa,
      { "initiateAuthenticationOkEsipa", "sgp32.initiateAuthenticationOkEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_initiateAuthenticationErrorEsipa,
      { "initiateAuthenticationErrorEsipa", "sgp32.initiateAuthenticationErrorEsipa",
        FT_INT32, BASE_DEC, VALS(sgp32_T_initiateAuthenticationErrorEsipa_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_serverSigned1,
      { "serverSigned1", "sgp32.serverSigned1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_serverSignature1,
      { "serverSignature1", "sgp32.serverSignature1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_serverCertificate,
      { "serverCertificate", "sgp32.serverCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp32_matchingId,
      { "matchingId", "sgp32.matchingId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_sgp32_authenticateServerResponse,
      { "authenticateServerResponse", "sgp32.authenticateServerResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_AuthenticateServerResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_authenticateClientOkDPEsipa,
      { "authenticateClientOkDPEsipa", "sgp32.authenticateClientOkDPEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_authenticateClientOkDSEsipa,
      { "authenticateClientOkDSEsipa", "sgp32.authenticateClientOkDSEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_authenticateClientErrorEsipa,
      { "authenticateClientErrorEsipa", "sgp32.authenticateClientErrorEsipa",
        FT_INT32, BASE_DEC, VALS(sgp32_T_authenticateClientErrorEsipa_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_profileMetaData,
      { "profileMetaData", "sgp32.profileMetaData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StoreMetadataRequest", HFILL }},
    { &hf_sgp32_smdpSigned2,
      { "smdpSigned2", "sgp32.smdpSigned2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_smdpSignature2,
      { "smdpSignature2", "sgp32.smdpSignature2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_sgp32_smdpCertificate,
      { "smdpCertificate", "sgp32.smdpCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_sgp32_profileDownloadTrigger,
      { "profileDownloadTrigger", "sgp32.profileDownloadTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProfileDownloadTriggerRequest", HFILL }},
    { &hf_sgp32_prepareDownloadResponse,
      { "prepareDownloadResponse", "sgp32.prepareDownloadResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_PrepareDownloadResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_getBoundProfilePackageOkEsipa,
      { "getBoundProfilePackageOkEsipa", "sgp32.getBoundProfilePackageOkEsipa_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_getBoundProfilePackageErrorEsipa,
      { "getBoundProfilePackageErrorEsipa", "sgp32.getBoundProfilePackageErrorEsipa",
        FT_INT32, BASE_DEC, VALS(sgp32_T_getBoundProfilePackageErrorEsipa_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_boundProfilePackage,
      { "boundProfilePackage", "sgp32.boundProfilePackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_pendingNotification,
      { "pendingNotification", "sgp32.pendingNotification",
        FT_UINT32, BASE_DEC, VALS(sgp32_PendingNotification_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_cancelSessionResponse,
      { "cancelSessionResponse", "sgp32.cancelSessionResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_CancelSessionResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_cancelSessionOk,
      { "cancelSessionOk", "sgp32.cancelSessionOk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_cancelSessionError,
      { "cancelSessionError", "sgp32.cancelSessionError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_cancelSessionError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_notifyStateChange,
      { "notifyStateChange", "sgp32.notifyStateChange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_stateChangeCause,
      { "stateChangeCause", "sgp32.stateChangeCause",
        FT_INT32, BASE_DEC, VALS(sgp32_StateChangeCause_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_rPLMN,
      { "rPLMN", "sgp32.rPLMN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccPackageRequest,
      { "euiccPackageRequest", "sgp32.euiccPackageRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaEuiccDataRequest,
      { "ipaEuiccDataRequest", "sgp32.ipaEuiccDataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_profileDownloadTriggerRequest,
      { "profileDownloadTriggerRequest", "sgp32.profileDownloadTriggerRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_eimPackageError,
      { "eimPackageError", "sgp32.eimPackageError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_eimPackageError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_eimPackageResultErrorCode,
      { "eimPackageResultErrorCode", "sgp32.eimPackageResultErrorCode",
        FT_INT32, BASE_DEC, VALS(sgp32_EimPackageResultErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_euiccPackageResult,
      { "euiccPackageResult", "sgp32.euiccPackageResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_EuiccPackageResult_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_ePRAndNotifications,
      { "ePRAndNotifications", "sgp32.ePRAndNotifications_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_ipaEuiccDataResponse,
      { "ipaEuiccDataResponse", "sgp32.ipaEuiccDataResponse",
        FT_UINT32, BASE_DEC, VALS(sgp32_IpaEuiccDataResponse_U_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_profileDownloadTriggerResult,
      { "profileDownloadTriggerResult", "sgp32.profileDownloadTriggerResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_eimPackageResultResponseError,
      { "eimPackageResultResponseError", "sgp32.eimPackageResultResponseError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_eimPackageResult,
      { "eimPackageResult", "sgp32.eimPackageResult",
        FT_UINT32, BASE_DEC, VALS(sgp32_EimPackageResult_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_eimAcknowledgements,
      { "eimAcknowledgements", "sgp32.eimAcknowledgements",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_emptyResponse,
      { "emptyResponse", "sgp32.emptyResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_provideEimPackageResultError,
      { "provideEimPackageResultError", "sgp32.provideEimPackageResultError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_provideEimPackageResultError_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_ePRAndNotifications_01,
      { "ePRAndNotifications", "sgp32.ePRAndNotifications_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ePRAndNotifications_01", HFILL }},
    { &hf_sgp32_eimPackageReceived,
      { "eimPackageReceived", "sgp32.eimPackageReceived_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sgp32_eimPackageError_01,
      { "eimPackageError", "sgp32.eimPackageError",
        FT_INT32, BASE_DEC, VALS(sgp32_T_eimPackageError_01_vals), 0,
        "T_eimPackageError_01", HFILL }},
    { &hf_sgp32_EimSupportedProtocol_eimRetrieveHttps,
      { "eimRetrieveHttps", "sgp32.EimSupportedProtocol.eimRetrieveHttps",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp32_EimSupportedProtocol_eimRetrieveCoaps,
      { "eimRetrieveCoaps", "sgp32.EimSupportedProtocol.eimRetrieveCoaps",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp32_EimSupportedProtocol_eimInjectHttps,
      { "eimInjectHttps", "sgp32.EimSupportedProtocol.eimInjectHttps",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp32_EimSupportedProtocol_eimInjectCoaps,
      { "eimInjectCoaps", "sgp32.EimSupportedProtocol.eimInjectCoaps",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp32_EimSupportedProtocol_eimProprietary,
      { "eimProprietary", "sgp32.EimSupportedProtocol.eimProprietary",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp32_T_euiccConfiguration_ipaeSupported,
      { "ipaeSupported", "sgp32.T.euiccConfiguration.ipaeSupported",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp32_T_euiccConfiguration_enabledProfile,
      { "enabledProfile", "sgp32.T.euiccConfiguration.enabledProfile",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaeOption_activateIpae,
      { "activateIpae", "sgp32.T.ipaeOption.activateIpae",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaFeatures_directRspServerCommunication,
      { "directRspServerCommunication", "sgp32.T.ipaFeatures.directRspServerCommunication",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaFeatures_indirectRspServerCommunication,
      { "indirectRspServerCommunication", "sgp32.T.ipaFeatures.indirectRspServerCommunication",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaFeatures_eimDownloadDataHandling,
      { "eimDownloadDataHandling", "sgp32.T.ipaFeatures.eimDownloadDataHandling",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaFeatures_eimCtxParams1Generation,
      { "eimCtxParams1Generation", "sgp32.T.ipaFeatures.eimCtxParams1Generation",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaFeatures_eimProfileMetadataVerification,
      { "eimProfileMetadataVerification", "sgp32.T.ipaFeatures.eimProfileMetadataVerification",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaFeatures_minimizeEsipaBytes,
      { "minimizeEsipaBytes", "sgp32.T.ipaFeatures.minimizeEsipaBytes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaSupportedProtocols_ipaRetrieveHttps,
      { "ipaRetrieveHttps", "sgp32.T.ipaSupportedProtocols.ipaRetrieveHttps",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaSupportedProtocols_ipaRetrieveCoaps,
      { "ipaRetrieveCoaps", "sgp32.T.ipaSupportedProtocols.ipaRetrieveCoaps",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaSupportedProtocols_ipaInjectHttps,
      { "ipaInjectHttps", "sgp32.T.ipaSupportedProtocols.ipaInjectHttps",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaSupportedProtocols_ipaInjectCoaps,
      { "ipaInjectCoaps", "sgp32.T.ipaSupportedProtocols.ipaInjectCoaps",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp32_T_ipaSupportedProtocols_ipaProprietary,
      { "ipaProprietary", "sgp32.T.ipaSupportedProtocols.ipaProprietary",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp32_T_treProperties_isDiscrete,
      { "isDiscrete", "sgp32.T.treProperties.isDiscrete",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp32_T_treProperties_isIntegrated,
      { "isIntegrated", "sgp32.T.treProperties.isIntegrated",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp32_T_treProperties_usesRemoteMemory,
      { "usesRemoteMemory", "sgp32.T.treProperties.usesRemoteMemory",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp32_T_resetOptions_deleteOperationalProfiles,
      { "deleteOperationalProfiles", "sgp32.T.resetOptions.deleteOperationalProfiles",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_sgp32_T_resetOptions_deleteFieldLoadedTestProfiles,
      { "deleteFieldLoadedTestProfiles", "sgp32.T.resetOptions.deleteFieldLoadedTestProfiles",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_sgp32_T_resetOptions_resetDefaultSmdpAddress,
      { "resetDefaultSmdpAddress", "sgp32.T.resetOptions.resetDefaultSmdpAddress",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_sgp32_T_resetOptions_deletePreLoadedTestProfiles,
      { "deletePreLoadedTestProfiles", "sgp32.T.resetOptions.deletePreLoadedTestProfiles",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_sgp32_T_resetOptions_deleteProvisioningProfiles,
      { "deleteProvisioningProfiles", "sgp32.T.resetOptions.deleteProvisioningProfiles",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_sgp32_T_resetOptions_resetEimConfigData,
      { "resetEimConfigData", "sgp32.T.resetOptions.resetEimConfigData",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_sgp32_T_resetOptions_resetImmediateEnableConfig,
      { "resetImmediateEnableConfig", "sgp32.T.resetOptions.resetImmediateEnableConfig",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
  };

  static int *ett[] = {
    &ett_sgp32,
    &ett_sgp32_rPLMN,
    &ett_sgp32_EuiccPackageRequest_U,
    &ett_sgp32_EuiccPackageSigned,
    &ett_sgp32_EuiccPackage,
    &ett_sgp32_SEQUENCE_OF_Psmo,
    &ett_sgp32_SEQUENCE_OF_Eco,
    &ett_sgp32_EimConfigurationData,
    &ett_sgp32_T_eimPublicKeyData,
    &ett_sgp32_T_trustedPublicKeyDataTls,
    &ett_sgp32_EimSupportedProtocol,
    &ett_sgp32_Eco,
    &ett_sgp32_T_deleteEim,
    &ett_sgp32_T_listEim,
    &ett_sgp32_Psmo,
    &ett_sgp32_T_enable,
    &ett_sgp32_T_disable,
    &ett_sgp32_T_delete,
    &ett_sgp32_T_getRAT,
    &ett_sgp32_T_configureImmediateEnable,
    &ett_sgp32_T_setFallbackAttribute,
    &ett_sgp32_T_unsetFallbackAttribute,
    &ett_sgp32_IpaEuiccDataRequest_U,
    &ett_sgp32_T_searchCriteriaNotification,
    &ett_sgp32_T_searchCriteriaEuiccPackageResult,
    &ett_sgp32_ProfileDownloadTriggerRequest_U,
    &ett_sgp32_ProfileDownloadData,
    &ett_sgp32_T_contactSmds,
    &ett_sgp32_SEQUENCE_OF_SequenceNumber,
    &ett_sgp32_EuiccPackageResult_U,
    &ett_sgp32_EuiccPackageResultSigned,
    &ett_sgp32_EuiccPackageResultDataSigned,
    &ett_sgp32_SEQUENCE_OF_EuiccResultData,
    &ett_sgp32_EuiccResultData,
    &ett_sgp32_EuiccPackageErrorSigned,
    &ett_sgp32_EuiccPackageErrorDataSigned,
    &ett_sgp32_EuiccPackageErrorUnsigned,
    &ett_sgp32_ProfileInfoListResponse_U,
    &ett_sgp32_SEQUENCE_OF_ProfileInfo,
    &ett_sgp32_AddEimResult,
    &ett_sgp32_ListEimResult,
    &ett_sgp32_SEQUENCE_OF_EimIdInfo,
    &ett_sgp32_EimIdInfo,
    &ett_sgp32_IpaEuiccDataResponseError,
    &ett_sgp32_IpaEuiccDataResponse_U,
    &ett_sgp32_PendingNotificationList,
    &ett_sgp32_EuiccPackageResultList,
    &ett_sgp32_IpaEuiccData,
    &ett_sgp32_ProfileDownloadTriggerResult_U,
    &ett_sgp32_T_profileDownloadTriggerResultData,
    &ett_sgp32_T_profileDownloadError,
    &ett_sgp32_ISDRProprietaryApplicationTemplateIoT_U,
    &ett_sgp32_T_euiccConfiguration,
    &ett_sgp32_IpaeActivationRequest_U,
    &ett_sgp32_T_ipaeOption,
    &ett_sgp32_IpaeActivationResponse_U,
    &ett_sgp32_IpaCapabilities,
    &ett_sgp32_T_ipaFeatures,
    &ett_sgp32_T_ipaSupportedProtocols,
    &ett_sgp32_ProfileInfo_U,
    &ett_sgp32_SEQUENCE_OF_NotificationConfigurationInformation,
    &ett_sgp32_StoreMetadataRequest_U,
    &ett_sgp32_EUICCInfo2_U,
    &ett_sgp32_SEQUENCE_OF_SubjectKeyIdentifier,
    &ett_sgp32_T_treProperties,
    &ett_sgp32_SEQUENCE_OF_VersionType,
    &ett_sgp32_IoTSpecificInfo,
    &ett_sgp32_AddInitialEimRequest_U,
    &ett_sgp32_SEQUENCE_OF_EimConfigurationData,
    &ett_sgp32_AddInitialEimResponse_U,
    &ett_sgp32_T_addInitialEimOk,
    &ett_sgp32_T_addInitialEimOk_item,
    &ett_sgp32_EuiccMemoryResetRequest_U,
    &ett_sgp32_T_resetOptions,
    &ett_sgp32_EuiccMemoryResetResponse_U,
    &ett_sgp32_GetCertsRequest_U,
    &ett_sgp32_GetCertsResponse_U,
    &ett_sgp32_T_certs,
    &ett_sgp32_RetrieveNotificationsListRequest_U,
    &ett_sgp32_T_searchCriteria,
    &ett_sgp32_RetrieveNotificationsListResponse_U,
    &ett_sgp32_ImmediateEnableRequest_U,
    &ett_sgp32_ImmediateEnableResponse_U,
    &ett_sgp32_ProfileRollbackRequest_U,
    &ett_sgp32_ProfileRollbackResponse_U,
    &ett_sgp32_ConfigureImmediateProfileEnablingRequest_U,
    &ett_sgp32_ConfigureImmediateProfileEnablingResponse_U,
    &ett_sgp32_GetEimConfigurationDataRequest_U,
    &ett_sgp32_T_searchCriteria_01,
    &ett_sgp32_GetEimConfigurationDataResponse_U,
    &ett_sgp32_ExecuteFallbackMechanismRequest_U,
    &ett_sgp32_ExecuteFallbackMechanismResponse_U,
    &ett_sgp32_ReturnFromFallbackRequest_U,
    &ett_sgp32_ReturnFromFallbackResponse_U,
    &ett_sgp32_EnableEmergencyProfileRequest_U,
    &ett_sgp32_EnableEmergencyProfileResponse_U,
    &ett_sgp32_DisableEmergencyProfileRequest_U,
    &ett_sgp32_DisableEmergencyProfileResponse_U,
    &ett_sgp32_GetConnectivityParametersRequest_U,
    &ett_sgp32_GetConnectivityParametersResponse_U,
    &ett_sgp32_ConnectivityParameters,
    &ett_sgp32_SetDefaultDpAddressRequest_U,
    &ett_sgp32_SetDefaultDpAddressResponse_U,
    &ett_sgp32_PrepareDownloadResponse_U,
    &ett_sgp32_CompactPrepareDownloadResponseOk,
    &ett_sgp32_CompactEuiccSigned2,
    &ett_sgp32_EuiccSigned1,
    &ett_sgp32_AuthenticateResponseOk,
    &ett_sgp32_AuthenticateServerResponse_U,
    &ett_sgp32_CompactAuthenticateResponseOk,
    &ett_sgp32_T_signedData,
    &ett_sgp32_CompactEuiccSigned1,
    &ett_sgp32_PendingNotification,
    &ett_sgp32_ProfileInstallationResult_U,
    &ett_sgp32_CompactProfileInstallationResult,
    &ett_sgp32_CompactProfileInstallationResultData,
    &ett_sgp32_T_compactFinalResult,
    &ett_sgp32_CompactSuccessResult,
    &ett_sgp32_CompactOtherSignedNotification,
    &ett_sgp32_CancelSessionResponse_U,
    &ett_sgp32_CompactCancelSessionResponseOk,
    &ett_sgp32_CompactEuiccCancelSessionSigned,
    &ett_sgp32_EsipaMessageFromIpaToEim,
    &ett_sgp32_EsipaMessageFromEimToIpa,
    &ett_sgp32_InitiateAuthenticationRequestEsipa_U,
    &ett_sgp32_InitiateAuthenticationResponseEsipa_U,
    &ett_sgp32_InitiateAuthenticationOkEsipa,
    &ett_sgp32_AuthenticateClientRequestEsipa_U,
    &ett_sgp32_AuthenticateClientResponseEsipa_U,
    &ett_sgp32_AuthenticateClientOkDPEsipa,
    &ett_sgp32_AuthenticateClientOkDSEsipa,
    &ett_sgp32_GetBoundProfilePackageRequestEsipa_U,
    &ett_sgp32_GetBoundProfilePackageResponseEsipa_U,
    &ett_sgp32_GetBoundProfilePackageOkEsipa,
    &ett_sgp32_HandleNotificationEsipa_U,
    &ett_sgp32_CancelSessionRequestEsipa_U,
    &ett_sgp32_CancelSessionResponseEsipa_U,
    &ett_sgp32_CancelSessionOk,
    &ett_sgp32_GetEimPackageRequest_U,
    &ett_sgp32_GetEimPackageResponse_U,
    &ett_sgp32_EimPackageResultResponseError,
    &ett_sgp32_EimPackageResult,
    &ett_sgp32_T_ePRAndNotifications,
    &ett_sgp32_ProvideEimPackageResult_U,
    &ett_sgp32_ProvideEimPackageResultResponse_U,
    &ett_sgp32_T_emptyResponse,
    &ett_sgp32_TransferEimPackageRequest_U,
    &ett_sgp32_TransferEimPackageResponse_U,
    &ett_sgp32_T_ePRAndNotifications_01,
  };

  proto_sgp32 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_sgp32, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sgp32_handle = register_dissector("sgp32", dissect_sgp32, proto_sgp32);
  register_dissector("sgp32.request", dissect_sgp32_request, proto_sgp32);
  register_dissector("sgp32.response", dissect_sgp32_response, proto_sgp32);

  sgp32_request_dissector_table = register_dissector_table("sgp32.request", "SGP.32 Request", proto_sgp32, FT_UINT16, BASE_HEX);
  sgp32_response_dissector_table = register_dissector_table("sgp32.response", "SGP.32 Response", proto_sgp32, FT_UINT16, BASE_HEX);

  register_ber_syntax_dissector("SGP.32 Request", proto_sgp32, dissect_sgp32_request);
  register_ber_syntax_dissector("SGP.32 Response", proto_sgp32, dissect_sgp32_response);
}

void proto_reg_handoff_sgp32(void)
{
  sgp22_request_dissector_table = find_dissector_table("sgp22.request");
  sgp22_response_dissector_table = find_dissector_table("sgp22.response");

  dissector_add_string("media_type", "application/x-gsma-rsp-asn1", sgp32_handle);
  dissector_add_string("coap_uri_path", "/gsma/rsp2/asn1", sgp32_handle);

  dissector_add_uint("sgp32.request", 0xBF2B, create_dissector_handle(dissect_RetrieveNotificationsListRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF2B, create_dissector_handle(dissect_RetrieveNotificationsListResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF39, create_dissector_handle(dissect_InitiateAuthenticationRequestEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF39, create_dissector_handle(dissect_InitiateAuthenticationResponseEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF3A, create_dissector_handle(dissect_GetBoundProfilePackageRequestEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF3A, create_dissector_handle(dissect_GetBoundProfilePackageResponseEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF3B, create_dissector_handle(dissect_AuthenticateClientRequestEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF3B, create_dissector_handle(dissect_AuthenticateClientResponseEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF3D, create_dissector_handle(dissect_HandleNotificationEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF41, create_dissector_handle(dissect_CancelSessionRequestEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF41, create_dissector_handle(dissect_CancelSessionResponseEsipa_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF42, create_dissector_handle(dissect_IpaeActivationRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF42, create_dissector_handle(dissect_IpaeActivationResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF4E, create_dissector_handle(dissect_TransferEimPackageRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF4E, create_dissector_handle(dissect_TransferEimPackageResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF4F, create_dissector_handle(dissect_GetEimPackageRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF4F, create_dissector_handle(dissect_GetEimPackageResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF50, create_dissector_handle(dissect_ProvideEimPackageResult_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF50, create_dissector_handle(dissect_ProvideEimPackageResultResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF51, create_dissector_handle(dissect_EuiccPackageRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF51, create_dissector_handle(dissect_EuiccPackageResult_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF52, create_dissector_handle(dissect_IpaEuiccDataRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF52, create_dissector_handle(dissect_IpaEuiccDataResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF53, create_dissector_handle(dissect_EimAcknowledgements_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF54, create_dissector_handle(dissect_ProfileDownloadTriggerRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF54, create_dissector_handle(dissect_ProfileDownloadData_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF55, create_dissector_handle(dissect_GetEimConfigurationDataRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF55, create_dissector_handle(dissect_GetEimConfigurationDataResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF56, create_dissector_handle(dissect_GetCertsRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF56, create_dissector_handle(dissect_GetCertsResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF57, create_dissector_handle(dissect_AddInitialEimRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF57, create_dissector_handle(dissect_AddInitialEimResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF58, create_dissector_handle(dissect_ProfileRollbackRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF58, create_dissector_handle(dissect_ProfileRollbackResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF59, create_dissector_handle(dissect_ConfigureImmediateProfileEnablingRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF59, create_dissector_handle(dissect_ConfigureImmediateProfileEnablingResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF5A, create_dissector_handle(dissect_ImmediateEnableRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF5A, create_dissector_handle(dissect_ImmediateEnableResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF5B, create_dissector_handle(dissect_EnableEmergencyProfileRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF5B, create_dissector_handle(dissect_EnableEmergencyProfileResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF5C, create_dissector_handle(dissect_DisableEmergencyProfileRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF5C, create_dissector_handle(dissect_DisableEmergencyProfileResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF5D, create_dissector_handle(dissect_ExecuteFallbackMechanismRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF5D, create_dissector_handle(dissect_ExecuteFallbackMechanismResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF5E, create_dissector_handle(dissect_ReturnFromFallbackRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF5E, create_dissector_handle(dissect_ReturnFromFallbackResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF5F, create_dissector_handle(dissect_GetConnectivityParametersRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF5F, create_dissector_handle(dissect_GetConnectivityParametersResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF64, create_dissector_handle(dissect_EuiccMemoryResetRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF64, create_dissector_handle(dissect_EuiccMemoryResetResponse_PDU, proto_sgp32));
  dissector_add_uint("sgp32.request", 0xBF65, create_dissector_handle(dissect_SetDefaultDpAddressRequest_PDU, proto_sgp32));
  dissector_add_uint("sgp32.response", 0xBF65, create_dissector_handle(dissect_SetDefaultDpAddressResponse_PDU, proto_sgp32));

}
