/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ieee1609dot2.c                                                      */
/* asn2wrs.py -q -L -p ieee1609dot2 -c ./ieee1609dot2.cnf -s ./packet-ieee1609dot2-template -D . -O ../.. IEEE1609dot2BaseTypes.asn Ieee1609Dot2CrlBaseTypes.asn Ieee1609Dot2Crl.asn Ieee1609Dot2.asn IEEE1609dot12.asn */

/* packet-IEEE1609dot2.c
 * Routines for IEEE 1609.2
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Also contains IEEE std 1609.12
 * section 4.1.3 PSID allocations
 */

#include "config.h"

#include <stdlib.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

#include "packet-oer.h"
#include "packet-ieee1609dot2.h"

#define PNAME  "IEEE1609dot2"
#define PSNAME "IEEE1609dot2"
#define PFNAME "ieee1609dot2"

void proto_register_ieee1609dot2(void);
void proto_reg_handoff_ieee1609dot2(void);

/* Initialize the protocol and registered fields */
int proto_ieee1609dot2;
dissector_handle_t proto_ieee1609dot2_handle;
static int hf_ieee1609dot2_SecuredCrl_PDU;        /* SecuredCrl */
static int hf_ieee1609dot2_Ieee1609Dot2Data_PDU;  /* Ieee1609Dot2Data */
static int hf_ieee1609dot2_SequenceOfUint8_item;  /* Uint8 */
static int hf_ieee1609dot2_SequenceOfUint16_item;  /* Uint16 */
static int hf_ieee1609dot2_SequenceOfHashedId3_item;  /* HashedId3 */
static int hf_ieee1609dot2_start;                 /* Time32 */
static int hf_ieee1609dot2_duration;              /* Duration */
static int hf_ieee1609dot2_microseconds;          /* Uint16 */
static int hf_ieee1609dot2_milliseconds;          /* Uint16 */
static int hf_ieee1609dot2_seconds;               /* Uint16 */
static int hf_ieee1609dot2_minutes;               /* Uint16 */
static int hf_ieee1609dot2_hours;                 /* Uint16 */
static int hf_ieee1609dot2_sixtyHours;            /* Uint16 */
static int hf_ieee1609dot2_years;                 /* Uint16 */
static int hf_ieee1609dot2_circularRegion;        /* CircularRegion */
static int hf_ieee1609dot2_rectangularRegion;     /* SequenceOfRectangularRegion */
static int hf_ieee1609dot2_polygonalRegion;       /* PolygonalRegion */
static int hf_ieee1609dot2_identifiedRegion;      /* SequenceOfIdentifiedRegion */
static int hf_ieee1609dot2_center;                /* TwoDLocation */
static int hf_ieee1609dot2_radius;                /* Uint16 */
static int hf_ieee1609dot2_northWest;             /* TwoDLocation */
static int hf_ieee1609dot2_southEast;             /* TwoDLocation */
static int hf_ieee1609dot2_SequenceOfRectangularRegion_item;  /* RectangularRegion */
static int hf_ieee1609dot2_PolygonalRegion_item;  /* TwoDLocation */
static int hf_ieee1609dot2_latitude;              /* Latitude */
static int hf_ieee1609dot2_longitude;             /* Longitude */
static int hf_ieee1609dot2_countryOnly;           /* UnCountryId */
static int hf_ieee1609dot2_countryAndRegions;     /* CountryAndRegions */
static int hf_ieee1609dot2_countryAndSubregions;  /* CountryAndSubregions */
static int hf_ieee1609dot2_SequenceOfIdentifiedRegion_item;  /* IdentifiedRegion */
static int hf_ieee1609dot2_regions;               /* SequenceOfUint8 */
static int hf_ieee1609dot2_regionAndSubregions;   /* SequenceOfRegionAndSubregions */
static int hf_ieee1609dot2_rasRegion;             /* Uint8 */
static int hf_ieee1609dot2_subregions;            /* SequenceOfUint16 */
static int hf_ieee1609dot2_SequenceOfRegionAndSubregions_item;  /* RegionAndSubregions */
static int hf_ieee1609dot2_elevation;             /* Elevation */
static int hf_ieee1609dot2_ecdsaNistP256Signature;  /* EcdsaP256Signature */
static int hf_ieee1609dot2_ecdsaBrainpoolP256r1Signature;  /* EcdsaP256Signature */
static int hf_ieee1609dot2_ecdsaBrainpoolP384r1Signature;  /* EcdsaP384Signature */
static int hf_ieee1609dot2_ecdsaNistP384Signature;  /* EcdsaP384Signature */
static int hf_ieee1609dot2_sm2Signature;          /* EcsigP256Signature */
static int hf_ieee1609dot2_rSig;                  /* EccP256CurvePoint */
static int hf_ieee1609dot2_sSig;                  /* OCTET_STRING_SIZE_32 */
static int hf_ieee1609dot2_ecdsap384RSig;         /* EccP384CurvePoint */
static int hf_ieee1609dot2_ecdsap384SSig;         /* OCTET_STRING_SIZE_48 */
static int hf_ieee1609dot2_rSig_01;               /* OCTET_STRING_SIZE_32 */
static int hf_ieee1609dot2_x_only;                /* OCTET_STRING_SIZE_32 */
static int hf_ieee1609dot2_fill;                  /* NULL */
static int hf_ieee1609dot2_compressed_y_0;        /* OCTET_STRING_SIZE_32 */
static int hf_ieee1609dot2_compressed_y_1;        /* OCTET_STRING_SIZE_32 */
static int hf_ieee1609dot2_uncompressedP256;      /* T_uncompressedP256 */
static int hf_ieee1609dot2_x;                     /* OCTET_STRING_SIZE_32 */
static int hf_ieee1609dot2_y;                     /* OCTET_STRING_SIZE_32 */
static int hf_ieee1609dot2_eccp384cpXOnly;        /* OCTET_STRING_SIZE_48 */
static int hf_ieee1609dot2_eccp384cpCompressed_y_0;  /* OCTET_STRING_SIZE_48 */
static int hf_ieee1609dot2_eccp384cpCompressed_y_1;  /* OCTET_STRING_SIZE_48 */
static int hf_ieee1609dot2_uncompressedP384;      /* T_uncompressedP384 */
static int hf_ieee1609dot2_eccp384cpX;            /* OCTET_STRING_SIZE_48 */
static int hf_ieee1609dot2_eccp384cpY;            /* OCTET_STRING_SIZE_48 */
static int hf_ieee1609dot2_v;                     /* EccP256CurvePoint */
static int hf_ieee1609dot2_c;                     /* OCTET_STRING_SIZE_16 */
static int hf_ieee1609dot2_t;                     /* OCTET_STRING_SIZE_16 */
static int hf_ieee1609dot2_t_01;                  /* OCTET_STRING_SIZE_32 */
static int hf_ieee1609dot2_public;                /* PublicEncryptionKey */
static int hf_ieee1609dot2_symmetric;             /* SymmetricEncryptionKey */
static int hf_ieee1609dot2_supportedSymmAlg;      /* SymmAlgorithm */
static int hf_ieee1609dot2_publicKey;             /* BasePublicEncryptionKey */
static int hf_ieee1609dot2_eciesNistP256;         /* EccP256CurvePoint */
static int hf_ieee1609dot2_eciesBrainpoolP256r1;  /* EccP256CurvePoint */
static int hf_ieee1609dot2_ecencSm2;              /* EccP256CurvePoint */
static int hf_ieee1609dot2_ecdsaNistP256;         /* EccP256CurvePoint */
static int hf_ieee1609dot2_ecdsaBrainpoolP256r1;  /* EccP256CurvePoint */
static int hf_ieee1609dot2_ecdsaBrainpoolP384r1;  /* EccP384CurvePoint */
static int hf_ieee1609dot2_ecdsaNistP384;         /* EccP384CurvePoint */
static int hf_ieee1609dot2_ecsigSm2;              /* EccP256CurvePoint */
static int hf_ieee1609dot2_aes128Ccm;             /* OCTET_STRING_SIZE_16 */
static int hf_ieee1609dot2_sm4Ccm;                /* OCTET_STRING_SIZE_16 */
static int hf_ieee1609dot2_psPsid;                /* T_psPsid */
static int hf_ieee1609dot2_ssp;                   /* ServiceSpecificPermissions */
static int hf_ieee1609dot2_SequenceOfPsidSsp_item;  /* PsidSsp */
static int hf_ieee1609dot2_opaque;                /* T_opaque */
static int hf_ieee1609dot2_bitmapSsp;             /* BitmapSsp */
static int hf_ieee1609dot2_psid;                  /* Psid */
static int hf_ieee1609dot2_sspRange;              /* SspRange */
static int hf_ieee1609dot2_SequenceOfPsidSspRange_item;  /* PsidSspRange */
static int hf_ieee1609dot2_srRange;               /* SequenceOfOctetString */
static int hf_ieee1609dot2_all;                   /* NULL */
static int hf_ieee1609dot2_bitmapSspRange;        /* BitmapSspRange */
static int hf_ieee1609dot2_sspValue;              /* OCTET_STRING_SIZE_1_32 */
static int hf_ieee1609dot2_sspBitmask;            /* OCTET_STRING_SIZE_1_32 */
static int hf_ieee1609dot2_SequenceOfOctetString_item;  /* OCTET_STRING_SIZE_0_MAX */
static int hf_ieee1609dot2_jValue;                /* OCTET_STRING_SIZE_4 */
static int hf_ieee1609dot2_value;                 /* OCTET_STRING_SIZE_9 */
static int hf_ieee1609dot2_SequenceOfLinkageSeed_item;  /* LinkageSeed */
static int hf_ieee1609dot2_version;               /* Uint8 */
static int hf_ieee1609dot2_crlSeries;             /* CrlSeries */
static int hf_ieee1609dot2_crlCraca;              /* HashedId8 */
static int hf_ieee1609dot2_issueDate;             /* Time32 */
static int hf_ieee1609dot2_nextCrl;               /* Time32 */
static int hf_ieee1609dot2_priorityInfo;          /* CrlPriorityInfo */
static int hf_ieee1609dot2_typeSpecific;          /* TypeSpecificCrlContents */
static int hf_ieee1609dot2_priority;              /* Uint8 */
static int hf_ieee1609dot2_fullHashCrl;           /* ToBeSignedHashIdCrl */
static int hf_ieee1609dot2_deltaHashCrl;          /* ToBeSignedHashIdCrl */
static int hf_ieee1609dot2_fullLinkedCrl;         /* ToBeSignedLinkageValueCrl */
static int hf_ieee1609dot2_deltaLinkedCrl;        /* ToBeSignedLinkageValueCrl */
static int hf_ieee1609dot2_fullLinkedCrlWithAlg;  /* ToBeSignedLinkageValueCrlWithAlgIdentifier */
static int hf_ieee1609dot2_deltaLinkedCrlWithAlg;  /* ToBeSignedLinkageValueCrlWithAlgIdentifier */
static int hf_ieee1609dot2_crlSerial;             /* Uint32 */
static int hf_ieee1609dot2_entries;               /* SequenceOfHashBasedRevocationInfo */
static int hf_ieee1609dot2_SequenceOfHashBasedRevocationInfo_item;  /* HashBasedRevocationInfo */
static int hf_ieee1609dot2_id;                    /* HashedId10 */
static int hf_ieee1609dot2_expiry;                /* Time32 */
static int hf_ieee1609dot2_iRev;                  /* IValue */
static int hf_ieee1609dot2_indexWithinI;          /* Uint8 */
static int hf_ieee1609dot2_individual;            /* SequenceOfJMaxGroup */
static int hf_ieee1609dot2_groups;                /* SequenceOfGroupCrlEntry */
static int hf_ieee1609dot2_groupsSingleSeed;      /* SequenceOfGroupSingleSeedCrlEntry */
static int hf_ieee1609dot2_SequenceOfJMaxGroup_item;  /* JMaxGroup */
static int hf_ieee1609dot2_jmax;                  /* Uint8 */
static int hf_ieee1609dot2_contents;              /* SequenceOfLAGroup */
static int hf_ieee1609dot2_SequenceOfLAGroup_item;  /* LAGroup */
static int hf_ieee1609dot2_la1Id;                 /* LaId */
static int hf_ieee1609dot2_la2Id;                 /* LaId */
static int hf_ieee1609dot2_contents_01;           /* SequenceOfIMaxGroup */
static int hf_ieee1609dot2_SequenceOfIMaxGroup_item;  /* IMaxGroup */
static int hf_ieee1609dot2_iMax;                  /* Uint16 */
static int hf_ieee1609dot2_contents_02;           /* SequenceOfIndividualRevocation */
static int hf_ieee1609dot2_singleSeed;            /* SequenceOfLinkageSeed */
static int hf_ieee1609dot2_SequenceOfIndividualRevocation_item;  /* IndividualRevocation */
static int hf_ieee1609dot2_linkageSeed1;          /* LinkageSeed */
static int hf_ieee1609dot2_linkageSeed2;          /* LinkageSeed */
static int hf_ieee1609dot2_SequenceOfGroupCrlEntry_item;  /* GroupCrlEntry */
static int hf_ieee1609dot2_seedEvolution;         /* SeedEvolutionFunctionIdentifier */
static int hf_ieee1609dot2_lvGeneration;          /* LvGenerationFunctionIdentifier */
static int hf_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry_item;  /* GroupSingleSeedCrlEntry */
static int hf_ieee1609dot2_laId;                  /* LaId */
static int hf_ieee1609dot2_linkageSeed;           /* LinkageSeed */
static int hf_ieee1609dot2_content;               /* SecuredCrlContent */
static int hf_ieee1609dot2_signedData;            /* CrlSignedData */
static int hf_ieee1609dot2_tbsData;               /* CrlToBeSignedData */
static int hf_ieee1609dot2_payload;               /* CrlSignedDataPayload */
static int hf_ieee1609dot2_headerInfo;            /* HeaderInfo */
static int hf_ieee1609dot2_data;                  /* Ieee1609Dot2CrlData */
static int hf_ieee1609dot2_content_01;            /* Ieee1609Dot2CrlContent */
static int hf_ieee1609dot2_unsecuredData;         /* CrlContents */
static int hf_ieee1609dot2_protocolVersion;       /* Uint8 */
static int hf_ieee1609dot2_content_02;            /* Ieee1609Dot2Content */
static int hf_ieee1609dot2_unsecuredData_01;      /* T_unsecuredData */
static int hf_ieee1609dot2_signedData_01;         /* SignedData */
static int hf_ieee1609dot2_encryptedData;         /* EncryptedData */
static int hf_ieee1609dot2_signedCertificateRequest;  /* Opaque */
static int hf_ieee1609dot2_signedX509CertificateRequest;  /* Opaque */
static int hf_ieee1609dot2_hashId;                /* HashAlgorithm */
static int hf_ieee1609dot2_tbsData_01;            /* ToBeSignedData */
static int hf_ieee1609dot2_signer;                /* SignerIdentifier */
static int hf_ieee1609dot2_signature;             /* Signature */
static int hf_ieee1609dot2_payload_01;            /* SignedDataPayload */
static int hf_ieee1609dot2_data_01;               /* Ieee1609Dot2Data */
static int hf_ieee1609dot2_extDataHash;           /* HashedData */
static int hf_ieee1609dot2_omitted;               /* NULL */
static int hf_ieee1609dot2_sha256HashedData;      /* HashedId32 */
static int hf_ieee1609dot2_sha384HashedData;      /* HashedId48 */
static int hf_ieee1609dot2_sm3HashedData;         /* HashedId32 */
static int hf_ieee1609dot2_hiPsid;                /* T_hiPsid */
static int hf_ieee1609dot2_generationTime;        /* Time64 */
static int hf_ieee1609dot2_expiryTime;            /* Time64 */
static int hf_ieee1609dot2_generationLocation;    /* ThreeDLocation */
static int hf_ieee1609dot2_p2pcdLearningRequest;  /* HashedId3 */
static int hf_ieee1609dot2_missingCrlIdentifier;  /* MissingCrlIdentifier */
static int hf_ieee1609dot2_encryptionKey;         /* EncryptionKey */
static int hf_ieee1609dot2_inlineP2pcdRequest;    /* SequenceOfHashedId3 */
static int hf_ieee1609dot2_requestedCertificate;  /* Certificate */
static int hf_ieee1609dot2_pduFunctionalType;     /* PduFunctionalType */
static int hf_ieee1609dot2_contributedExtensions;  /* ContributedExtensionBlocks */
static int hf_ieee1609dot2_cracaId;               /* HashedId3 */
static int hf_ieee1609dot2_ContributedExtensionBlocks_item;  /* ContributedExtensionBlock */
static int hf_ieee1609dot2_contributorId;         /* HeaderInfoContributorId */
static int hf_ieee1609dot2_extns;                 /* T_extns */
static int hf_ieee1609dot2_extns_item;            /* T_extns_item */
static int hf_ieee1609dot2_digest;                /* HashedId8 */
static int hf_ieee1609dot2_certificate;           /* SequenceOfCertificate */
static int hf_ieee1609dot2_siSelf;                /* NULL */
static int hf_ieee1609dot2_recipients;            /* SequenceOfRecipientInfo */
static int hf_ieee1609dot2_ciphertext;            /* SymmetricCiphertext */
static int hf_ieee1609dot2_pskRecipInfo;          /* PreSharedKeyRecipientInfo */
static int hf_ieee1609dot2_symmRecipInfo;         /* SymmRecipientInfo */
static int hf_ieee1609dot2_certRecipInfo;         /* PKRecipientInfo */
static int hf_ieee1609dot2_signedDataRecipInfo;   /* PKRecipientInfo */
static int hf_ieee1609dot2_rekRecipInfo;          /* PKRecipientInfo */
static int hf_ieee1609dot2_SequenceOfRecipientInfo_item;  /* RecipientInfo */
static int hf_ieee1609dot2_recipientId;           /* HashedId8 */
static int hf_ieee1609dot2_sriEncKey;             /* SymmetricCiphertext */
static int hf_ieee1609dot2_encKey;                /* EncryptedDataEncryptionKey */
static int hf_ieee1609dot2_edeEciesNistP256;      /* EciesP256EncryptedKey */
static int hf_ieee1609dot2_edekEciesBrainpoolP256r1;  /* EciesP256EncryptedKey */
static int hf_ieee1609dot2_ecencSm2256;           /* EcencP256EncryptedKey */
static int hf_ieee1609dot2_aes128ccm;             /* One28BitCcmCiphertext */
static int hf_ieee1609dot2_sm4Ccm_01;             /* One28BitCcmCiphertext */
static int hf_ieee1609dot2_nonce;                 /* OCTET_STRING_SIZE_12 */
static int hf_ieee1609dot2_ccmCiphertext;         /* Opaque */
static int hf_ieee1609dot2_SequenceOfCertificate_item;  /* Certificate */
static int hf_ieee1609dot2_type;                  /* CertificateType */
static int hf_ieee1609dot2_issuer;                /* IssuerIdentifier */
static int hf_ieee1609dot2_toBeSigned;            /* ToBeSignedCertificate */
static int hf_ieee1609dot2_sha256AndDigest;       /* HashedId8 */
static int hf_ieee1609dot2_iiSelf;                /* HashAlgorithm */
static int hf_ieee1609dot2_sha384AndDigest;       /* HashedId8 */
static int hf_ieee1609dot2_sm3AndDigest;          /* HashedId8 */
static int hf_ieee1609dot2_id_01;                 /* CertificateId */
static int hf_ieee1609dot2_validityPeriod;        /* ValidityPeriod */
static int hf_ieee1609dot2_region;                /* GeographicRegion */
static int hf_ieee1609dot2_assuranceLevel;        /* SubjectAssurance */
static int hf_ieee1609dot2_appPermissions;        /* SequenceOfPsidSsp */
static int hf_ieee1609dot2_certIssuePermissions;  /* SequenceOfPsidGroupPermissions */
static int hf_ieee1609dot2_certRequestPermissions;  /* SequenceOfPsidGroupPermissions */
static int hf_ieee1609dot2_canRequestRollover;    /* NULL */
static int hf_ieee1609dot2_tbscEncryptionKey;     /* PublicEncryptionKey */
static int hf_ieee1609dot2_verifyKeyIndicator;    /* VerificationKeyIndicator */
static int hf_ieee1609dot2_flags;                 /* T_flags */
static int hf_ieee1609dot2_appExtensions;         /* SequenceOfAppExtensions */
static int hf_ieee1609dot2_certIssueExtensions;   /* SequenceOfCertIssueExtensions */
static int hf_ieee1609dot2_certRequestExtension;  /* SequenceOfCertRequestExtensions */
static int hf_ieee1609dot2_linkageData;           /* LinkageData */
static int hf_ieee1609dot2_name;                  /* Hostname */
static int hf_ieee1609dot2_binaryId;              /* OCTET_STRING_SIZE_1_64 */
static int hf_ieee1609dot2_none;                  /* NULL */
static int hf_ieee1609dot2_iCert;                 /* IValue */
static int hf_ieee1609dot2_linkage_value;         /* LinkageValue */
static int hf_ieee1609dot2_group_linkage_value;   /* GroupLinkageValue */
static int hf_ieee1609dot2_subjectPermissions;    /* SubjectPermissions */
static int hf_ieee1609dot2_minChainLength;        /* INTEGER */
static int hf_ieee1609dot2_chainLengthRange;      /* INTEGER */
static int hf_ieee1609dot2_eeType;                /* EndEntityType */
static int hf_ieee1609dot2_SequenceOfPsidGroupPermissions_item;  /* PsidGroupPermissions */
static int hf_ieee1609dot2_explicit;              /* SequenceOfPsidSspRange */
static int hf_ieee1609dot2_verificationKey;       /* PublicVerificationKey */
static int hf_ieee1609dot2_reconstructionValue;   /* EccP256CurvePoint */
static int hf_ieee1609dot2_SequenceOfAppExtensions_item;  /* AppExtension */
static int hf_ieee1609dot2_id_02;                 /* ExtId */
static int hf_ieee1609dot2_content_03;            /* T_content */
static int hf_ieee1609dot2_SequenceOfCertIssueExtensions_item;  /* CertIssueExtension */
static int hf_ieee1609dot2_permissions;           /* T_permissions */
static int hf_ieee1609dot2_specific;              /* T_specific */
static int hf_ieee1609dot2_SequenceOfCertRequestExtensions_item;  /* CertRequestExtension */
static int hf_ieee1609dot2_permissions_01;        /* T_permissions_01 */
static int hf_ieee1609dot2_content_04;            /* T_content_01 */
/* named bits */
static int hf_ieee1609dot2_T_flags_usesCubk;
static int hf_ieee1609dot2_EndEntityType_app;
static int hf_ieee1609dot2_EndEntityType_enrol;

/* Initialize the subtree pointers */
static int ett_ieee1609dot2_ssp;
static int ett_ieee1609dot2_SequenceOfUint8;
static int ett_ieee1609dot2_SequenceOfUint16;
static int ett_ieee1609dot2_SequenceOfHashedId3;
static int ett_ieee1609dot2_ValidityPeriod;
static int ett_ieee1609dot2_Duration;
static int ett_ieee1609dot2_GeographicRegion;
static int ett_ieee1609dot2_CircularRegion;
static int ett_ieee1609dot2_RectangularRegion;
static int ett_ieee1609dot2_SequenceOfRectangularRegion;
static int ett_ieee1609dot2_PolygonalRegion;
static int ett_ieee1609dot2_TwoDLocation;
static int ett_ieee1609dot2_IdentifiedRegion;
static int ett_ieee1609dot2_SequenceOfIdentifiedRegion;
static int ett_ieee1609dot2_CountryAndRegions;
static int ett_ieee1609dot2_CountryAndSubregions;
static int ett_ieee1609dot2_RegionAndSubregions;
static int ett_ieee1609dot2_SequenceOfRegionAndSubregions;
static int ett_ieee1609dot2_ThreeDLocation;
static int ett_ieee1609dot2_Signature;
static int ett_ieee1609dot2_EcdsaP256Signature;
static int ett_ieee1609dot2_EcdsaP384Signature;
static int ett_ieee1609dot2_EcsigP256Signature;
static int ett_ieee1609dot2_EccP256CurvePoint;
static int ett_ieee1609dot2_T_uncompressedP256;
static int ett_ieee1609dot2_EccP384CurvePoint;
static int ett_ieee1609dot2_T_uncompressedP384;
static int ett_ieee1609dot2_EciesP256EncryptedKey;
static int ett_ieee1609dot2_EcencP256EncryptedKey;
static int ett_ieee1609dot2_EncryptionKey;
static int ett_ieee1609dot2_PublicEncryptionKey;
static int ett_ieee1609dot2_BasePublicEncryptionKey;
static int ett_ieee1609dot2_PublicVerificationKey;
static int ett_ieee1609dot2_SymmetricEncryptionKey;
static int ett_ieee1609dot2_PsidSsp;
static int ett_ieee1609dot2_SequenceOfPsidSsp;
static int ett_ieee1609dot2_ServiceSpecificPermissions;
static int ett_ieee1609dot2_PsidSspRange;
static int ett_ieee1609dot2_SequenceOfPsidSspRange;
static int ett_ieee1609dot2_SspRange;
static int ett_ieee1609dot2_BitmapSspRange;
static int ett_ieee1609dot2_SequenceOfOctetString;
static int ett_ieee1609dot2_GroupLinkageValue;
static int ett_ieee1609dot2_SequenceOfLinkageSeed;
static int ett_ieee1609dot2_CrlContents;
static int ett_ieee1609dot2_CrlPriorityInfo;
static int ett_ieee1609dot2_TypeSpecificCrlContents;
static int ett_ieee1609dot2_ToBeSignedHashIdCrl;
static int ett_ieee1609dot2_SequenceOfHashBasedRevocationInfo;
static int ett_ieee1609dot2_HashBasedRevocationInfo;
static int ett_ieee1609dot2_ToBeSignedLinkageValueCrl;
static int ett_ieee1609dot2_SequenceOfJMaxGroup;
static int ett_ieee1609dot2_JMaxGroup;
static int ett_ieee1609dot2_SequenceOfLAGroup;
static int ett_ieee1609dot2_LAGroup;
static int ett_ieee1609dot2_SequenceOfIMaxGroup;
static int ett_ieee1609dot2_IMaxGroup;
static int ett_ieee1609dot2_SequenceOfIndividualRevocation;
static int ett_ieee1609dot2_IndividualRevocation;
static int ett_ieee1609dot2_SequenceOfGroupCrlEntry;
static int ett_ieee1609dot2_GroupCrlEntry;
static int ett_ieee1609dot2_ToBeSignedLinkageValueCrlWithAlgIdentifier;
static int ett_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry;
static int ett_ieee1609dot2_GroupSingleSeedCrlEntry;
static int ett_ieee1609dot2_SecuredCrl;
static int ett_ieee1609dot2_SecuredCrlContent;
static int ett_ieee1609dot2_CrlSignedData;
static int ett_ieee1609dot2_CrlToBeSignedData;
static int ett_ieee1609dot2_CrlSignedDataPayload;
static int ett_ieee1609dot2_Ieee1609Dot2CrlData;
static int ett_ieee1609dot2_Ieee1609Dot2CrlContent;
static int ett_ieee1609dot2_Ieee1609Dot2Data;
static int ett_ieee1609dot2_Ieee1609Dot2Content;
static int ett_ieee1609dot2_SignedData;
static int ett_ieee1609dot2_ToBeSignedData;
static int ett_ieee1609dot2_SignedDataPayload;
static int ett_ieee1609dot2_HashedData;
static int ett_ieee1609dot2_HeaderInfo;
static int ett_ieee1609dot2_MissingCrlIdentifier;
static int ett_ieee1609dot2_ContributedExtensionBlocks;
static int ett_ieee1609dot2_ContributedExtensionBlock;
static int ett_ieee1609dot2_T_extns;
static int ett_ieee1609dot2_SignerIdentifier;
static int ett_ieee1609dot2_EncryptedData;
static int ett_ieee1609dot2_RecipientInfo;
static int ett_ieee1609dot2_SequenceOfRecipientInfo;
static int ett_ieee1609dot2_SymmRecipientInfo;
static int ett_ieee1609dot2_PKRecipientInfo;
static int ett_ieee1609dot2_EncryptedDataEncryptionKey;
static int ett_ieee1609dot2_SymmetricCiphertext;
static int ett_ieee1609dot2_One28BitCcmCiphertext;
static int ett_ieee1609dot2_SequenceOfCertificate;
static int ett_ieee1609dot2_CertificateBase;
static int ett_ieee1609dot2_IssuerIdentifier;
static int ett_ieee1609dot2_ToBeSignedCertificate;
static int ett_ieee1609dot2_T_flags;
static int ett_ieee1609dot2_CertificateId;
static int ett_ieee1609dot2_LinkageData;
static int ett_ieee1609dot2_EndEntityType;
static int ett_ieee1609dot2_PsidGroupPermissions;
static int ett_ieee1609dot2_SequenceOfPsidGroupPermissions;
static int ett_ieee1609dot2_SubjectPermissions;
static int ett_ieee1609dot2_VerificationKeyIndicator;
static int ett_ieee1609dot2_SequenceOfAppExtensions;
static int ett_ieee1609dot2_AppExtension;
static int ett_ieee1609dot2_SequenceOfCertIssueExtensions;
static int ett_ieee1609dot2_CertIssueExtension;
static int ett_ieee1609dot2_T_permissions;
static int ett_ieee1609dot2_SequenceOfCertRequestExtensions;
static int ett_ieee1609dot2_CertRequestExtension;
static int ett_ieee1609dot2_T_permissions_01;

static dissector_table_t unsecured_data_subdissector_table;
static dissector_table_t ssp_subdissector_table;

typedef struct ieee1609_private_data {
  tvbuff_t *unsecured_data;
  uint64_t psidssp; // psid for Service Specific Permissions
} ieee1609_private_data_t;

void
ieee1609dot2_set_next_default_psid(packet_info *pinfo, uint32_t psid)
{
  p_add_proto_data(wmem_file_scope(), pinfo, proto_ieee1609dot2, 0, GUINT_TO_POINTER(psid));
}

/*--- Cyclic dependencies ---*/

/* Ieee1609Dot2Data -> Ieee1609Dot2Content -> SignedData -> ToBeSignedData -> SignedDataPayload -> Ieee1609Dot2Data */
static int dissect_ieee1609dot2_Ieee1609Dot2Data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_ieee1609dot2_Uint8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_ieee1609dot2_Uint16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ieee1609dot2_Uint32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_ieee1609dot2_Uint64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(18446744073709551615), NULL, false);

  return offset;
}


static const oer_sequence_t SequenceOfUint8_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfUint8_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint8 },
};

static int
dissect_ieee1609dot2_SequenceOfUint8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfUint8, SequenceOfUint8_sequence_of);

  return offset;
}


static const oer_sequence_t SequenceOfUint16_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfUint16_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint16 },
};

static int
dissect_ieee1609dot2_SequenceOfUint16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfUint16, SequenceOfUint16_sequence_of);

  return offset;
}



static int
dissect_ieee1609dot2_Opaque(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_HashedId3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const oer_sequence_t SequenceOfHashedId3_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfHashedId3_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashedId3 },
};

static int
dissect_ieee1609dot2_SequenceOfHashedId3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfHashedId3, SequenceOfHashedId3_sequence_of);

  return offset;
}



static int
dissect_ieee1609dot2_HashedId8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_HashedId10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       10, 10, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_HashedId32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       32, 32, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_HashedId48(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       48, 48, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_Time32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_Uint32(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ieee1609dot2_Time64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_Uint64(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ieee1609dot2_Duration_vals[] = {
  {   0, "microseconds" },
  {   1, "milliseconds" },
  {   2, "seconds" },
  {   3, "minutes" },
  {   4, "hours" },
  {   5, "sixtyHours" },
  {   6, "years" },
  { 0, NULL }
};

static const oer_choice_t Duration_choice[] = {
  {   0, &hf_ieee1609dot2_microseconds, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_Uint16 },
  {   1, &hf_ieee1609dot2_milliseconds, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_Uint16 },
  {   2, &hf_ieee1609dot2_seconds, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_Uint16 },
  {   3, &hf_ieee1609dot2_minutes, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_Uint16 },
  {   4, &hf_ieee1609dot2_hours  , ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_Uint16 },
  {   5, &hf_ieee1609dot2_sixtyHours, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_Uint16 },
  {   6, &hf_ieee1609dot2_years  , ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_Uint16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_Duration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_Duration, Duration_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t ValidityPeriod_sequence[] = {
  { &hf_ieee1609dot2_start  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Time32 },
  { &hf_ieee1609dot2_duration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Duration },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_ValidityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_ValidityPeriod, ValidityPeriod_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_NinetyDegreeInt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -900000000, 900000001U, NULL, false);

  return offset;
}



static int
dissect_ieee1609dot2_Latitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_NinetyDegreeInt(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ieee1609dot2_OneEightyDegreeInt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1799999999, 1800000001U, NULL, false);

  return offset;
}



static int
dissect_ieee1609dot2_Longitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_OneEightyDegreeInt(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const oer_sequence_t TwoDLocation_sequence[] = {
  { &hf_ieee1609dot2_latitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Latitude },
  { &hf_ieee1609dot2_longitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Longitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_TwoDLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_TwoDLocation, TwoDLocation_sequence);

  return offset;
}


static const oer_sequence_t CircularRegion_sequence[] = {
  { &hf_ieee1609dot2_center , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_TwoDLocation },
  { &hf_ieee1609dot2_radius , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CircularRegion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CircularRegion, CircularRegion_sequence);

  return offset;
}


static const oer_sequence_t RectangularRegion_sequence[] = {
  { &hf_ieee1609dot2_northWest, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_TwoDLocation },
  { &hf_ieee1609dot2_southEast, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_TwoDLocation },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_RectangularRegion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_RectangularRegion, RectangularRegion_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfRectangularRegion_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfRectangularRegion_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_RectangularRegion },
};

static int
dissect_ieee1609dot2_SequenceOfRectangularRegion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfRectangularRegion, SequenceOfRectangularRegion_sequence_of);

  return offset;
}


static const oer_sequence_t PolygonalRegion_sequence_of[1] = {
  { &hf_ieee1609dot2_PolygonalRegion_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_TwoDLocation },
};

static int
dissect_ieee1609dot2_PolygonalRegion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ieee1609dot2_PolygonalRegion, PolygonalRegion_sequence_of,
                                                  3, NO_BOUND, false);

  return offset;
}



static int
dissect_ieee1609dot2_UnCountryId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_Uint16(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const oer_sequence_t CountryAndRegions_sequence[] = {
  { &hf_ieee1609dot2_countryOnly, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_UnCountryId },
  { &hf_ieee1609dot2_regions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfUint8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CountryAndRegions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CountryAndRegions, CountryAndRegions_sequence);

  return offset;
}


static const oer_sequence_t RegionAndSubregions_sequence[] = {
  { &hf_ieee1609dot2_rasRegion, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint8 },
  { &hf_ieee1609dot2_subregions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfUint16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_RegionAndSubregions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_RegionAndSubregions, RegionAndSubregions_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfRegionAndSubregions_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfRegionAndSubregions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_RegionAndSubregions },
};

static int
dissect_ieee1609dot2_SequenceOfRegionAndSubregions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfRegionAndSubregions, SequenceOfRegionAndSubregions_sequence_of);

  return offset;
}


static const oer_sequence_t CountryAndSubregions_sequence[] = {
  { &hf_ieee1609dot2_countryOnly, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_UnCountryId },
  { &hf_ieee1609dot2_regionAndSubregions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfRegionAndSubregions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CountryAndSubregions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CountryAndSubregions, CountryAndSubregions_sequence);

  return offset;
}


static const value_string ieee1609dot2_IdentifiedRegion_vals[] = {
  {   0, "countryOnly" },
  {   1, "countryAndRegions" },
  {   2, "countryAndSubregions" },
  { 0, NULL }
};

static const oer_choice_t IdentifiedRegion_choice[] = {
  {   0, &hf_ieee1609dot2_countryOnly, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_UnCountryId },
  {   1, &hf_ieee1609dot2_countryAndRegions, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_CountryAndRegions },
  {   2, &hf_ieee1609dot2_countryAndSubregions, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_CountryAndSubregions },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_IdentifiedRegion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_IdentifiedRegion, IdentifiedRegion_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t SequenceOfIdentifiedRegion_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfIdentifiedRegion_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_IdentifiedRegion },
};

static int
dissect_ieee1609dot2_SequenceOfIdentifiedRegion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfIdentifiedRegion, SequenceOfIdentifiedRegion_sequence_of);

  return offset;
}


static const value_string ieee1609dot2_GeographicRegion_vals[] = {
  {   0, "circularRegion" },
  {   1, "rectangularRegion" },
  {   2, "polygonalRegion" },
  {   3, "identifiedRegion" },
  { 0, NULL }
};

static const oer_choice_t GeographicRegion_choice[] = {
  {   0, &hf_ieee1609dot2_circularRegion, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_CircularRegion },
  {   1, &hf_ieee1609dot2_rectangularRegion, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_SequenceOfRectangularRegion },
  {   2, &hf_ieee1609dot2_polygonalRegion, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_PolygonalRegion },
  {   3, &hf_ieee1609dot2_identifiedRegion, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_SequenceOfIdentifiedRegion },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_GeographicRegion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_GeographicRegion, GeographicRegion_choice,
                                 NULL);

  return offset;
}



static int
dissect_ieee1609dot2_Elevation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_Uint16(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const oer_sequence_t ThreeDLocation_sequence[] = {
  { &hf_ieee1609dot2_latitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Latitude },
  { &hf_ieee1609dot2_longitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Longitude },
  { &hf_ieee1609dot2_elevation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Elevation },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_ThreeDLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_ThreeDLocation, ThreeDLocation_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       32, 32, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const oer_sequence_t T_uncompressedP256_sequence[] = {
  { &hf_ieee1609dot2_x      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  { &hf_ieee1609dot2_y      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_T_uncompressedP256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_T_uncompressedP256, T_uncompressedP256_sequence);

  return offset;
}


static const value_string ieee1609dot2_EccP256CurvePoint_vals[] = {
  {   0, "x-only" },
  {   1, "fill" },
  {   2, "compressed-y-0" },
  {   3, "compressed-y-1" },
  {   4, "uncompressedP256" },
  { 0, NULL }
};

static const oer_choice_t EccP256CurvePoint_choice[] = {
  {   0, &hf_ieee1609dot2_x_only , ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  {   1, &hf_ieee1609dot2_fill   , ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_NULL },
  {   2, &hf_ieee1609dot2_compressed_y_0, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  {   3, &hf_ieee1609dot2_compressed_y_1, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  {   4, &hf_ieee1609dot2_uncompressedP256, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_T_uncompressedP256 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_EccP256CurvePoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_EccP256CurvePoint, EccP256CurvePoint_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t EcdsaP256Signature_sequence[] = {
  { &hf_ieee1609dot2_rSig   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_EccP256CurvePoint },
  { &hf_ieee1609dot2_sSig   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_EcdsaP256Signature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_EcdsaP256Signature, EcdsaP256Signature_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_48(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       48, 48, false, NULL);

  return offset;
}


static const oer_sequence_t T_uncompressedP384_sequence[] = {
  { &hf_ieee1609dot2_eccp384cpX, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_48 },
  { &hf_ieee1609dot2_eccp384cpY, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_48 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_T_uncompressedP384(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_T_uncompressedP384, T_uncompressedP384_sequence);

  return offset;
}


static const value_string ieee1609dot2_EccP384CurvePoint_vals[] = {
  {   0, "x-only" },
  {   1, "fill" },
  {   2, "compressed-y-0" },
  {   3, "compressed-y-1" },
  {   4, "uncompressedP384" },
  { 0, NULL }
};

static const oer_choice_t EccP384CurvePoint_choice[] = {
  {   0, &hf_ieee1609dot2_eccp384cpXOnly, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_OCTET_STRING_SIZE_48 },
  {   1, &hf_ieee1609dot2_fill   , ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_NULL },
  {   2, &hf_ieee1609dot2_eccp384cpCompressed_y_0, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_OCTET_STRING_SIZE_48 },
  {   3, &hf_ieee1609dot2_eccp384cpCompressed_y_1, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_OCTET_STRING_SIZE_48 },
  {   4, &hf_ieee1609dot2_uncompressedP384, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_T_uncompressedP384 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_EccP384CurvePoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_EccP384CurvePoint, EccP384CurvePoint_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t EcdsaP384Signature_sequence[] = {
  { &hf_ieee1609dot2_ecdsap384RSig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_EccP384CurvePoint },
  { &hf_ieee1609dot2_ecdsap384SSig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_48 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_EcdsaP384Signature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_EcdsaP384Signature, EcdsaP384Signature_sequence);

  return offset;
}


static const oer_sequence_t EcsigP256Signature_sequence[] = {
  { &hf_ieee1609dot2_rSig_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  { &hf_ieee1609dot2_sSig   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_EcsigP256Signature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_EcsigP256Signature, EcsigP256Signature_sequence);

  return offset;
}


static const value_string ieee1609dot2_Signature_vals[] = {
  {   0, "ecdsaNistP256Signature" },
  {   1, "ecdsaBrainpoolP256r1Signature" },
  {   2, "ecdsaBrainpoolP384r1Signature" },
  {   3, "ecdsaNistP384Signature" },
  {   4, "sm2Signature" },
  { 0, NULL }
};

static const oer_choice_t Signature_choice[] = {
  {   0, &hf_ieee1609dot2_ecdsaNistP256Signature, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EcdsaP256Signature },
  {   1, &hf_ieee1609dot2_ecdsaBrainpoolP256r1Signature, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EcdsaP256Signature },
  {   2, &hf_ieee1609dot2_ecdsaBrainpoolP384r1Signature, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_EcdsaP384Signature },
  {   3, &hf_ieee1609dot2_ecdsaNistP384Signature, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_EcdsaP384Signature },
  {   4, &hf_ieee1609dot2_sm2Signature, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_EcsigP256Signature },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_Signature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_Signature, Signature_choice,
                                 NULL);

  return offset;
}


static const value_string ieee1609dot2_SymmAlgorithm_vals[] = {
  {   0, "aes128Ccm" },
  {   1, "sm4Ccm" },
  { 0, NULL }
};


static int
dissect_ieee1609dot2_SymmAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 1, NULL);

  return offset;
}


static const value_string ieee1609dot2_HashAlgorithm_vals[] = {
  {   0, "sha256" },
  {   1, "sha384" },
  {   2, "sm3" },
  { 0, NULL }
};


static int
dissect_ieee1609dot2_HashAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 2, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, false, NULL);

  return offset;
}


static const oer_sequence_t EciesP256EncryptedKey_sequence[] = {
  { &hf_ieee1609dot2_v      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_EccP256CurvePoint },
  { &hf_ieee1609dot2_c      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_16 },
  { &hf_ieee1609dot2_t      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_EciesP256EncryptedKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_EciesP256EncryptedKey, EciesP256EncryptedKey_sequence);

  return offset;
}


static const oer_sequence_t EcencP256EncryptedKey_sequence[] = {
  { &hf_ieee1609dot2_v      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_EccP256CurvePoint },
  { &hf_ieee1609dot2_c      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_16 },
  { &hf_ieee1609dot2_t_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_EcencP256EncryptedKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_EcencP256EncryptedKey, EcencP256EncryptedKey_sequence);

  return offset;
}


static const value_string ieee1609dot2_BasePublicEncryptionKey_vals[] = {
  {   0, "eciesNistP256" },
  {   1, "eciesBrainpoolP256r1" },
  {   2, "ecencSm2" },
  { 0, NULL }
};

static const oer_choice_t BasePublicEncryptionKey_choice[] = {
  {   0, &hf_ieee1609dot2_eciesNistP256, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EccP256CurvePoint },
  {   1, &hf_ieee1609dot2_eciesBrainpoolP256r1, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EccP256CurvePoint },
  {   2, &hf_ieee1609dot2_ecencSm2, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_EccP256CurvePoint },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_BasePublicEncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_BasePublicEncryptionKey, BasePublicEncryptionKey_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t PublicEncryptionKey_sequence[] = {
  { &hf_ieee1609dot2_supportedSymmAlg, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SymmAlgorithm },
  { &hf_ieee1609dot2_publicKey, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_BasePublicEncryptionKey },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_PublicEncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_PublicEncryptionKey, PublicEncryptionKey_sequence);

  return offset;
}


static const value_string ieee1609dot2_SymmetricEncryptionKey_vals[] = {
  {   0, "aes128Ccm" },
  {   1, "sm4Ccm" },
  { 0, NULL }
};

static const oer_choice_t SymmetricEncryptionKey_choice[] = {
  {   0, &hf_ieee1609dot2_aes128Ccm, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_OCTET_STRING_SIZE_16 },
  {   1, &hf_ieee1609dot2_sm4Ccm , ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_OCTET_STRING_SIZE_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_SymmetricEncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_SymmetricEncryptionKey, SymmetricEncryptionKey_choice,
                                 NULL);

  return offset;
}


static const value_string ieee1609dot2_EncryptionKey_vals[] = {
  {   0, "public" },
  {   1, "symmetric" },
  { 0, NULL }
};

static const oer_choice_t EncryptionKey_choice[] = {
  {   0, &hf_ieee1609dot2_public , ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_PublicEncryptionKey },
  {   1, &hf_ieee1609dot2_symmetric, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_SymmetricEncryptionKey },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_EncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_EncryptionKey, EncryptionKey_choice,
                                 NULL);

  return offset;
}


static const value_string ieee1609dot2_PublicVerificationKey_vals[] = {
  {   0, "ecdsaNistP256" },
  {   1, "ecdsaBrainpoolP256r1" },
  {   2, "ecdsaBrainpoolP384r1" },
  {   3, "ecdsaNistP384" },
  {   4, "ecsigSm2" },
  { 0, NULL }
};

static const oer_choice_t PublicVerificationKey_choice[] = {
  {   0, &hf_ieee1609dot2_ecdsaNistP256, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EccP256CurvePoint },
  {   1, &hf_ieee1609dot2_ecdsaBrainpoolP256r1, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EccP256CurvePoint },
  {   2, &hf_ieee1609dot2_ecdsaBrainpoolP384r1, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_EccP384CurvePoint },
  {   3, &hf_ieee1609dot2_ecdsaNistP384, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_EccP384CurvePoint },
  {   4, &hf_ieee1609dot2_ecsigSm2, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_EccP256CurvePoint },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_PublicVerificationKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_PublicVerificationKey, PublicVerificationKey_choice,
                                 NULL);

  return offset;
}


const val64_string ieee1609dot2_Psid_vals[] = {
  { psid_system, "psid-system" },
  { psid_electronic_fee_collection, "psid-electronic-fee-collection" },
  { psid_freight_fleet_management, "psid-freight-fleet-management" },
  { psid_public_transport, "psid-public-transport" },
  { psid_traffic_traveller_information, "psid-traffic-traveller-information" },
  { psid_traffic_control, "psid-traffic-control" },
  { psid_parking_management, "psid-parking-management" },
  { psid_geographic_road_database, "psid-geographic-road-database" },
  { psid_medium_range_preinformation, "psid-medium-range-preinformation" },
  { psid_man_machine_interface, "psid-man-machine-interface" },
  { psid_intersystem_interface, "psid-intersystem-interface" },
  { psid_automatic_vehicle_identification, "psid-automatic-vehicle-identification" },
  { psid_emergency_warning, "psid-emergency-warning" },
  { psid_private, "psid-private" },
  { psid_multi_purpose_payment, "psid-multi-purpose-payment" },
  { psid_dsrc_resource_manager, "psid-dsrc-resource-manager" },
  { psid_after_theft_systems, "psid-after-theft-systems" },
  { psid_cruise_assist_highway_system, "psid-cruise-assist-highway-system" },
  { psid_multi_purpose_information_system, "psid-multi-purpose-information-system" },
  { psid_multi_mobile_information_system, "psid-multi-mobile-information-system" },
  { psid_efc_compliance_check_communication_applications, "psid-efc-compliance-check-communication-applications" },
  { psid_efc_localisation_augmentation_communication_applications, "psid-efc-localisation-augmentation-communication-applications" },
  { psid_iso_cen_dsrc_applications_0x16, "psid-iso-cen-dsrc-applications-0x16" },
  { psid_iso_cen_dsrc_applications_0x17, "psid-iso-cen-dsrc-applications-0x17" },
  { psid_iso_cen_dsrc_applications_0x18, "psid-iso-cen-dsrc-applications-0x18" },
  { psid_iso_cen_dsrc_applications_0x19, "psid-iso-cen-dsrc-applications-0x19" },
  { psid_iso_cen_dsrc_applications_0x1a, "psid-iso-cen-dsrc-applications-0x1a" },
  { psid_iso_cen_dsrc_applications_0x1b, "psid-iso-cen-dsrc-applications-0x1b" },
  { psid_iso_cen_dsrc_applications_0x1c, "psid-iso-cen-dsrc-applications-0x1c" },
  { psid_private_use_0x1d, "psid-private-use-0x1d" },
  { psid_private_use_0x1e, "psid-private-use-0x1e" },
  { psid_iso_cen_dsrc_applications_0x1f, "psid-iso-cen-dsrc-applications-0x1f" },
  { psid_vehicle_to_vehicle_safety_and_awarenesss, "psid-vehicle-to-vehicle-safety-and-awarenesss" },
  { psid_limited_sensor_vehicle_to_vehicle_safety_and_awarenesss, "psid-limited-sensor-vehicle-to-vehicle-safety-and-awarenesss" },
  { psid_tracked_vehicle_safety_and_awarenesss, "psid-tracked-vehicle-safety-and-awarenesss" },
  { psid_wave_security_managements, "psid-wave-security-managements" },
  { psid_ca_basic_services, "psid-ca-basic-services" },
  { psid_den_basic_services, "psid-den-basic-services" },
  { psid_misbehavior_reporting_for_common_applications, "psid-misbehavior-reporting-for-common-applications" },
  { psid_vulnerable_road_users_safety_applications, "psid-vulnerable-road-users-safety-applications" },
  { psid_testings, "psid-testings" },
  { psid_differential_gps_corrections_uncompressed, "psid-differential-gps-corrections-uncompressed" },
  { psid_differential_gps_corrections_compressed, "psid-differential-gps-corrections-compressed" },
  { psid_intersection_safety_and_awareness, "psid-intersection-safety-and-awareness" },
  { psid_traveller_information_and_roadside_signage, "psid-traveller-information-and-roadside-signage" },
  { psid_mobile_probe_exchanges, "psid-mobile-probe-exchanges" },
  { psid_emergency_and_erratic_vehicles_present_in_roadway, "psid-emergency-and-erratic-vehicles-present-in-roadway" },
  { psid_remote_management_protocol_execution, "psid-remote-management-protocol-execution" },
  { psid_wave_service_advertisement, "psid-wave-service-advertisement" },
  { psid_peer_to_peer_distribution_of_security_management_information, "psid-peer-to-peer-distribution-of-security-management-information" },
  { psid_traffic_light_manoeuver_service, "psid-traffic-light-manoeuver-service" },
  { psid_road_and_lane_topology_service, "psid-road-and-lane-topology-service" },
  { psid_infrastructure_to_vehicle_information_service, "psid-infrastructure-to-vehicle-information-service" },
  { psid_traffic_light_control_requests_service, "psid-traffic-light-control-requests-service" },
  { psid_geonetworking_management_communications, "psid-geonetworking-management-communications" },
  { psid_certificate_revocation_list_application, "psid-certificate-revocation-list-application" },
  { psid_traffic_light_control_status_service, "psid-traffic-light-control-status-service" },
  { psid_collective_perception_service, "psid-collective-perception-service" },
  { psid_vehicle_initiated_distress_notivication, "psid-vehicle-initiated-distress-notivication" },
  { psid_fast_service_advertisement_protocol, "psid-fast-service-advertisement-protocol" },
  { psid_its_station_internal_management_communications_protocol, "psid-its-station-internal-management-communications-protocol" },
  { psid_veniam_delay_tolerant_networking, "psid-veniam-delay-tolerant-networking" },
  { psid_transcore_software_update, "psid-transcore-software-update" },
  { psid_sra_private_applications_0x204084, "psid-sra-private-applications-0x204084" },
  { psid_sra_private_applications_0x204085, "psid-sra-private-applications-0x204085" },
  { psid_sra_private_applications_0x204086, "psid-sra-private-applications-0x204086" },
  { psid_sra_private_applications_0x204087, "psid-sra-private-applications-0x204087" },
  { psid_ipv6_routing, "psid-ipv6-routing" },
  { 0, NULL }
};


static int
dissect_ieee1609dot2_Psid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer_64b_no_ub(tvb, offset, actx, tree, hf_index,
                                                            0U, NO_BOUND, NULL, false);

  return offset;
}



static int
dissect_ieee1609dot2_T_psPsid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer_64b_no_ub(tvb, offset, actx, tree, hf_index,
                                               0U, NO_BOUND, &((ieee1609_private_data_t*)actx->private_data)->psidssp, false);


  return offset;
}



static int
dissect_ieee1609dot2_T_opaque(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *ssp;
  ieee1609_private_data_t *my_private_data = (ieee1609_private_data_t*)actx->private_data;

  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       0, NO_BOUND, false, &ssp);
  if (ssp) {
    // Create subtree
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ieee1609dot2_ssp);
    /* Call next dissector here */
    dissector_try_uint(ssp_subdissector_table, (uint32_t) my_private_data->psidssp, ssp, actx->pinfo, subtree);
  }

  return offset;
}



static int
dissect_ieee1609dot2_BitmapSsp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       0, 31, false, NULL);

  return offset;
}


static const value_string ieee1609dot2_ServiceSpecificPermissions_vals[] = {
  {   0, "opaque" },
  {   1, "bitmapSsp" },
  { 0, NULL }
};

static const oer_choice_t ServiceSpecificPermissions_choice[] = {
  {   0, &hf_ieee1609dot2_opaque , ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_T_opaque },
  {   1, &hf_ieee1609dot2_bitmapSsp, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_BitmapSsp },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_ServiceSpecificPermissions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_ServiceSpecificPermissions, ServiceSpecificPermissions_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t PsidSsp_sequence[] = {
  { &hf_ieee1609dot2_psPsid , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_T_psPsid },
  { &hf_ieee1609dot2_ssp    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ieee1609dot2_ServiceSpecificPermissions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_PsidSsp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_PsidSsp, PsidSsp_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfPsidSsp_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfPsidSsp_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_PsidSsp },
};

static int
dissect_ieee1609dot2_SequenceOfPsidSsp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfPsidSsp, SequenceOfPsidSsp_sequence_of);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_0_MAX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       0, NO_BOUND, false, NULL);

  return offset;
}


static const oer_sequence_t SequenceOfOctetString_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfOctetString_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_0_MAX },
};

static int
dissect_ieee1609dot2_SequenceOfOctetString(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ieee1609dot2_SequenceOfOctetString, SequenceOfOctetString_sequence_of,
                                                  0, NO_BOUND, false);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 32, false, NULL);

  return offset;
}


static const oer_sequence_t BitmapSspRange_sequence[] = {
  { &hf_ieee1609dot2_sspValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_1_32 },
  { &hf_ieee1609dot2_sspBitmask, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_1_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_BitmapSspRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_BitmapSspRange, BitmapSspRange_sequence);

  return offset;
}


static const value_string ieee1609dot2_SspRange_vals[] = {
  {   0, "opaque" },
  {   1, "all" },
  {   2, "bitmapSspRange" },
  { 0, NULL }
};

static const oer_choice_t SspRange_choice[] = {
  {   0, &hf_ieee1609dot2_srRange, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_SequenceOfOctetString },
  {   1, &hf_ieee1609dot2_all    , ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_NULL },
  {   2, &hf_ieee1609dot2_bitmapSspRange, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_BitmapSspRange },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_SspRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_SspRange, SspRange_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t PsidSspRange_sequence[] = {
  { &hf_ieee1609dot2_psid   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Psid },
  { &hf_ieee1609dot2_sspRange, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ieee1609dot2_SspRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_PsidSspRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_PsidSspRange, PsidSspRange_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfPsidSspRange_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfPsidSspRange_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_PsidSspRange },
};

static int
dissect_ieee1609dot2_SequenceOfPsidSspRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfPsidSspRange, SequenceOfPsidSspRange_sequence_of);

  return offset;
}



static int
dissect_ieee1609dot2_SubjectAssurance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_CrlSeries(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_Uint16(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ieee1609dot2_IValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_Uint16(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ieee1609dot2_Hostname(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_UTF8String(tvb, offset, actx, tree, hf_index,
                                          0, 255, false);

  return offset;
}



static int
dissect_ieee1609dot2_LinkageValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       9, 9, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       9, 9, false, NULL);

  return offset;
}


static const oer_sequence_t GroupLinkageValue_sequence[] = {
  { &hf_ieee1609dot2_jValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_4 },
  { &hf_ieee1609dot2_value  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_9 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_GroupLinkageValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_GroupLinkageValue, GroupLinkageValue_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_LaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_LinkageSeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, false, NULL);

  return offset;
}


static const oer_sequence_t SequenceOfLinkageSeed_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfLinkageSeed_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LinkageSeed },
};

static int
dissect_ieee1609dot2_SequenceOfLinkageSeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfLinkageSeed, SequenceOfLinkageSeed_sequence_of);

  return offset;
}


static const value_string ieee1609dot2_ExtId_vals[] = {
  {   1, "certExtId-OperatingOrganization" },
  { 0, NULL }
};


static int
dissect_ieee1609dot2_ExtId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const oer_sequence_t CrlPriorityInfo_sequence[] = {
  { &hf_ieee1609dot2_priority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_Uint8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CrlPriorityInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CrlPriorityInfo, CrlPriorityInfo_sequence);

  return offset;
}


static const oer_sequence_t HashBasedRevocationInfo_sequence[] = {
  { &hf_ieee1609dot2_id     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashedId10 },
  { &hf_ieee1609dot2_expiry , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Time32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_HashBasedRevocationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_HashBasedRevocationInfo, HashBasedRevocationInfo_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfHashBasedRevocationInfo_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfHashBasedRevocationInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashBasedRevocationInfo },
};

static int
dissect_ieee1609dot2_SequenceOfHashBasedRevocationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfHashBasedRevocationInfo, SequenceOfHashBasedRevocationInfo_sequence_of);

  return offset;
}


static const oer_sequence_t ToBeSignedHashIdCrl_sequence[] = {
  { &hf_ieee1609dot2_crlSerial, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint32 },
  { &hf_ieee1609dot2_entries, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfHashBasedRevocationInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_ToBeSignedHashIdCrl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_ToBeSignedHashIdCrl, ToBeSignedHashIdCrl_sequence);

  return offset;
}


static const oer_sequence_t IndividualRevocation_sequence[] = {
  { &hf_ieee1609dot2_linkageSeed1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LinkageSeed },
  { &hf_ieee1609dot2_linkageSeed2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LinkageSeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_IndividualRevocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_IndividualRevocation, IndividualRevocation_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfIndividualRevocation_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfIndividualRevocation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_IndividualRevocation },
};

static int
dissect_ieee1609dot2_SequenceOfIndividualRevocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ieee1609dot2_SequenceOfIndividualRevocation, SequenceOfIndividualRevocation_sequence_of,
                                                  0, NO_BOUND, false);

  return offset;
}


static const oer_sequence_t IMaxGroup_sequence[] = {
  { &hf_ieee1609dot2_iMax   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint16 },
  { &hf_ieee1609dot2_contents_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfIndividualRevocation },
  { &hf_ieee1609dot2_singleSeed, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfLinkageSeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_IMaxGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_IMaxGroup, IMaxGroup_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfIMaxGroup_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfIMaxGroup_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_IMaxGroup },
};

static int
dissect_ieee1609dot2_SequenceOfIMaxGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfIMaxGroup, SequenceOfIMaxGroup_sequence_of);

  return offset;
}


static const oer_sequence_t LAGroup_sequence[] = {
  { &hf_ieee1609dot2_la1Id  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LaId },
  { &hf_ieee1609dot2_la2Id  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LaId },
  { &hf_ieee1609dot2_contents_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfIMaxGroup },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_LAGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_LAGroup, LAGroup_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfLAGroup_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfLAGroup_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LAGroup },
};

static int
dissect_ieee1609dot2_SequenceOfLAGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfLAGroup, SequenceOfLAGroup_sequence_of);

  return offset;
}


static const oer_sequence_t JMaxGroup_sequence[] = {
  { &hf_ieee1609dot2_jmax   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint8 },
  { &hf_ieee1609dot2_contents, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfLAGroup },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_JMaxGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_JMaxGroup, JMaxGroup_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfJMaxGroup_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfJMaxGroup_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_JMaxGroup },
};

static int
dissect_ieee1609dot2_SequenceOfJMaxGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfJMaxGroup, SequenceOfJMaxGroup_sequence_of);

  return offset;
}


static const oer_sequence_t GroupCrlEntry_sequence[] = {
  { &hf_ieee1609dot2_iMax   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint16 },
  { &hf_ieee1609dot2_la1Id  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LaId },
  { &hf_ieee1609dot2_linkageSeed1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LinkageSeed },
  { &hf_ieee1609dot2_la2Id  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LaId },
  { &hf_ieee1609dot2_linkageSeed2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LinkageSeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_GroupCrlEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_GroupCrlEntry, GroupCrlEntry_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfGroupCrlEntry_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfGroupCrlEntry_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_GroupCrlEntry },
};

static int
dissect_ieee1609dot2_SequenceOfGroupCrlEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfGroupCrlEntry, SequenceOfGroupCrlEntry_sequence_of);

  return offset;
}


static const oer_sequence_t GroupSingleSeedCrlEntry_sequence[] = {
  { &hf_ieee1609dot2_iMax   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint16 },
  { &hf_ieee1609dot2_laId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LaId },
  { &hf_ieee1609dot2_linkageSeed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LinkageSeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_GroupSingleSeedCrlEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_GroupSingleSeedCrlEntry, GroupSingleSeedCrlEntry_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfGroupSingleSeedCrlEntry_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_GroupSingleSeedCrlEntry },
};

static int
dissect_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry, SequenceOfGroupSingleSeedCrlEntry_sequence_of);

  return offset;
}


static const oer_sequence_t ToBeSignedLinkageValueCrl_sequence[] = {
  { &hf_ieee1609dot2_iRev   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_IValue },
  { &hf_ieee1609dot2_indexWithinI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint8 },
  { &hf_ieee1609dot2_individual, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfJMaxGroup },
  { &hf_ieee1609dot2_groups , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfGroupCrlEntry },
  { &hf_ieee1609dot2_groupsSingleSeed, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_ToBeSignedLinkageValueCrl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_ToBeSignedLinkageValueCrl, ToBeSignedLinkageValueCrl_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_SeedEvolutionFunctionIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ieee1609dot2_LvGenerationFunctionIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const oer_sequence_t ToBeSignedLinkageValueCrlWithAlgIdentifier_sequence[] = {
  { &hf_ieee1609dot2_iRev   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_IValue },
  { &hf_ieee1609dot2_indexWithinI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint8 },
  { &hf_ieee1609dot2_seedEvolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SeedEvolutionFunctionIdentifier },
  { &hf_ieee1609dot2_lvGeneration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LvGenerationFunctionIdentifier },
  { &hf_ieee1609dot2_individual, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfJMaxGroup },
  { &hf_ieee1609dot2_groups , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfGroupCrlEntry },
  { &hf_ieee1609dot2_groupsSingleSeed, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_ToBeSignedLinkageValueCrlWithAlgIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_ToBeSignedLinkageValueCrlWithAlgIdentifier, ToBeSignedLinkageValueCrlWithAlgIdentifier_sequence);

  return offset;
}


static const value_string ieee1609dot2_TypeSpecificCrlContents_vals[] = {
  {   0, "fullHashCrl" },
  {   1, "deltaHashCrl" },
  {   2, "fullLinkedCrl" },
  {   3, "deltaLinkedCrl" },
  {   4, "fullLinkedCrlWithAlg" },
  {   5, "deltaLinkedCrlWithAlg" },
  { 0, NULL }
};

static const oer_choice_t TypeSpecificCrlContents_choice[] = {
  {   0, &hf_ieee1609dot2_fullHashCrl, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_ToBeSignedHashIdCrl },
  {   1, &hf_ieee1609dot2_deltaHashCrl, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_ToBeSignedHashIdCrl },
  {   2, &hf_ieee1609dot2_fullLinkedCrl, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_ToBeSignedLinkageValueCrl },
  {   3, &hf_ieee1609dot2_deltaLinkedCrl, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_ToBeSignedLinkageValueCrl },
  {   4, &hf_ieee1609dot2_fullLinkedCrlWithAlg, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_ToBeSignedLinkageValueCrlWithAlgIdentifier },
  {   5, &hf_ieee1609dot2_deltaLinkedCrlWithAlg, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_ToBeSignedLinkageValueCrlWithAlgIdentifier },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_TypeSpecificCrlContents(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_TypeSpecificCrlContents, TypeSpecificCrlContents_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t CrlContents_sequence[] = {
  { &hf_ieee1609dot2_version, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint8 },
  { &hf_ieee1609dot2_crlSeries, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CrlSeries },
  { &hf_ieee1609dot2_crlCraca, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashedId8 },
  { &hf_ieee1609dot2_issueDate, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Time32 },
  { &hf_ieee1609dot2_nextCrl, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Time32 },
  { &hf_ieee1609dot2_priorityInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CrlPriorityInfo },
  { &hf_ieee1609dot2_typeSpecific, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_TypeSpecificCrlContents },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CrlContents(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CrlContents, CrlContents_sequence);

  return offset;
}


static const value_string ieee1609dot2_Ieee1609Dot2CrlContent_vals[] = {
  {   0, "unsecuredData" },
  { 0, NULL }
};

static const oer_choice_t Ieee1609Dot2CrlContent_choice[] = {
  {   0, &hf_ieee1609dot2_unsecuredData, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_CrlContents },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_Ieee1609Dot2CrlContent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_Ieee1609Dot2CrlContent, Ieee1609Dot2CrlContent_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t Ieee1609Dot2CrlData_sequence[] = {
  { &hf_ieee1609dot2_content_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Ieee1609Dot2CrlContent },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_Ieee1609Dot2CrlData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_Ieee1609Dot2CrlData, Ieee1609Dot2CrlData_sequence);

  return offset;
}


static const oer_sequence_t CrlSignedDataPayload_sequence[] = {
  { &hf_ieee1609dot2_data   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ieee1609dot2_Ieee1609Dot2CrlData },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CrlSignedDataPayload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CrlSignedDataPayload, CrlSignedDataPayload_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_T_hiPsid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint64_t psid;
  ieee1609_private_data_t *my_private_data = (ieee1609_private_data_t*)actx->private_data;

  offset = dissect_oer_constrained_integer_64b_no_ub(tvb, offset, actx, tree, hf_index,
                                                            0U, NO_BOUND, &psid, false);
  if ((my_private_data != NULL) && (my_private_data->unsecured_data != NULL)) {
    /* Call next dissector here */
    ieee1609dot2_set_next_default_psid(actx->pinfo, (uint32_t)psid);
    dissector_try_uint(unsecured_data_subdissector_table, (uint32_t) psid, my_private_data->unsecured_data, actx->pinfo, tree);
    my_private_data->unsecured_data = NULL;
  }


  return offset;
}


static const oer_sequence_t MissingCrlIdentifier_sequence[] = {
  { &hf_ieee1609dot2_cracaId, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashedId3 },
  { &hf_ieee1609dot2_crlSeries, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CrlSeries },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_MissingCrlIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_MissingCrlIdentifier, MissingCrlIdentifier_sequence);

  return offset;
}


static const value_string ieee1609dot2_CertificateType_vals[] = {
  {   0, "explicit" },
  {   1, "implicit" },
  { 0, NULL }
};


static int
dissect_ieee1609dot2_CertificateType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ieee1609dot2_IssuerIdentifier_vals[] = {
  {   0, "sha256AndDigest" },
  {   1, "self" },
  {   2, "sha384AndDigest" },
  {   3, "sm3AndDigest" },
  { 0, NULL }
};

static const oer_choice_t IssuerIdentifier_choice[] = {
  {   0, &hf_ieee1609dot2_sha256AndDigest, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_HashedId8 },
  {   1, &hf_ieee1609dot2_iiSelf , ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_HashAlgorithm },
  {   2, &hf_ieee1609dot2_sha384AndDigest, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_HashedId8 },
  {   3, &hf_ieee1609dot2_sm3AndDigest, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_HashedId8 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_IssuerIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_IssuerIdentifier, IssuerIdentifier_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t LinkageData_sequence[] = {
  { &hf_ieee1609dot2_iCert  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_IValue },
  { &hf_ieee1609dot2_linkage_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_LinkageValue },
  { &hf_ieee1609dot2_group_linkage_value, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ieee1609dot2_GroupLinkageValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_LinkageData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_LinkageData, LinkageData_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_1_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 64, false, NULL);

  return offset;
}


static const value_string ieee1609dot2_CertificateId_vals[] = {
  {   0, "linkageData" },
  {   1, "name" },
  {   2, "binaryId" },
  {   3, "none" },
  { 0, NULL }
};

static const oer_choice_t CertificateId_choice[] = {
  {   0, &hf_ieee1609dot2_linkageData, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_LinkageData },
  {   1, &hf_ieee1609dot2_name   , ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_Hostname },
  {   2, &hf_ieee1609dot2_binaryId, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_OCTET_STRING_SIZE_1_64 },
  {   3, &hf_ieee1609dot2_none   , ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_CertificateId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_CertificateId, CertificateId_choice,
                                 NULL);

  return offset;
}


static const value_string ieee1609dot2_SubjectPermissions_vals[] = {
  {   0, "explicit" },
  {   1, "all" },
  { 0, NULL }
};

static const oer_choice_t SubjectPermissions_choice[] = {
  {   0, &hf_ieee1609dot2_explicit, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_SequenceOfPsidSspRange },
  {   1, &hf_ieee1609dot2_all    , ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_SubjectPermissions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_SubjectPermissions, SubjectPermissions_choice,
                                 NULL);

  return offset;
}



static int
dissect_ieee1609dot2_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static int * const EndEntityType_bits[] = {
  &hf_ieee1609dot2_EndEntityType_app,
  &hf_ieee1609dot2_EndEntityType_enrol,
  NULL
};

static int
dissect_ieee1609dot2_EndEntityType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, EndEntityType_bits, 2, NULL, NULL);

  return offset;
}


static const oer_sequence_t PsidGroupPermissions_sequence[] = {
  { &hf_ieee1609dot2_subjectPermissions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SubjectPermissions },
  { &hf_ieee1609dot2_minChainLength, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ieee1609dot2_INTEGER },
  { &hf_ieee1609dot2_chainLengthRange, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ieee1609dot2_INTEGER },
  { &hf_ieee1609dot2_eeType , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ieee1609dot2_EndEntityType },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_PsidGroupPermissions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_PsidGroupPermissions, PsidGroupPermissions_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfPsidGroupPermissions_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfPsidGroupPermissions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_PsidGroupPermissions },
};

static int
dissect_ieee1609dot2_SequenceOfPsidGroupPermissions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfPsidGroupPermissions, SequenceOfPsidGroupPermissions_sequence_of);

  return offset;
}


static const value_string ieee1609dot2_VerificationKeyIndicator_vals[] = {
  {   0, "verificationKey" },
  {   1, "reconstructionValue" },
  { 0, NULL }
};

static const oer_choice_t VerificationKeyIndicator_choice[] = {
  {   0, &hf_ieee1609dot2_verificationKey, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_PublicVerificationKey },
  {   1, &hf_ieee1609dot2_reconstructionValue, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EccP256CurvePoint },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_VerificationKeyIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_VerificationKeyIndicator, VerificationKeyIndicator_choice,
                                 NULL);

  return offset;
}


static int * const T_flags_bits[] = {
  &hf_ieee1609dot2_T_flags_usesCubk,
  NULL
};

static int
dissect_ieee1609dot2_T_flags(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, T_flags_bits, 1, NULL, NULL);

  return offset;
}



static int
dissect_ieee1609dot2_T_content(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const oer_sequence_t AppExtension_sequence[] = {
  { &hf_ieee1609dot2_id_02  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_ExtId },
  { &hf_ieee1609dot2_content_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_T_content },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_AppExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_AppExtension, AppExtension_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfAppExtensions_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfAppExtensions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_AppExtension },
};

static int
dissect_ieee1609dot2_SequenceOfAppExtensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ieee1609dot2_SequenceOfAppExtensions, SequenceOfAppExtensions_sequence_of,
                                                  1, NO_BOUND, false);

  return offset;
}



static int
dissect_ieee1609dot2_T_specific(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string ieee1609dot2_T_permissions_vals[] = {
  {   0, "specific" },
  {   1, "all" },
  { 0, NULL }
};

static const oer_choice_t T_permissions_choice[] = {
  {   0, &hf_ieee1609dot2_specific, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_T_specific },
  {   1, &hf_ieee1609dot2_all    , ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_T_permissions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_T_permissions, T_permissions_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t CertIssueExtension_sequence[] = {
  { &hf_ieee1609dot2_id_02  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_ExtId },
  { &hf_ieee1609dot2_permissions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_T_permissions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CertIssueExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CertIssueExtension, CertIssueExtension_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfCertIssueExtensions_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfCertIssueExtensions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CertIssueExtension },
};

static int
dissect_ieee1609dot2_SequenceOfCertIssueExtensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ieee1609dot2_SequenceOfCertIssueExtensions, SequenceOfCertIssueExtensions_sequence_of,
                                                  1, NO_BOUND, false);

  return offset;
}



static int
dissect_ieee1609dot2_T_content_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string ieee1609dot2_T_permissions_01_vals[] = {
  {   0, "content" },
  {   1, "all" },
  { 0, NULL }
};

static const oer_choice_t T_permissions_01_choice[] = {
  {   0, &hf_ieee1609dot2_content_04, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_T_content_01 },
  {   1, &hf_ieee1609dot2_all    , ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_T_permissions_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_T_permissions_01, T_permissions_01_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t CertRequestExtension_sequence[] = {
  { &hf_ieee1609dot2_id_02  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_ExtId },
  { &hf_ieee1609dot2_permissions_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_T_permissions_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CertRequestExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CertRequestExtension, CertRequestExtension_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfCertRequestExtensions_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfCertRequestExtensions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CertRequestExtension },
};

static int
dissect_ieee1609dot2_SequenceOfCertRequestExtensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ieee1609dot2_SequenceOfCertRequestExtensions, SequenceOfCertRequestExtensions_sequence_of,
                                                  1, NO_BOUND, false);

  return offset;
}


static const oer_sequence_t ToBeSignedCertificate_sequence[] = {
  { &hf_ieee1609dot2_id_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CertificateId },
  { &hf_ieee1609dot2_cracaId, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashedId3 },
  { &hf_ieee1609dot2_crlSeries, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CrlSeries },
  { &hf_ieee1609dot2_validityPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_ValidityPeriod },
  { &hf_ieee1609dot2_region , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_GeographicRegion },
  { &hf_ieee1609dot2_assuranceLevel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SubjectAssurance },
  { &hf_ieee1609dot2_appPermissions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfPsidSsp },
  { &hf_ieee1609dot2_certIssuePermissions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfPsidGroupPermissions },
  { &hf_ieee1609dot2_certRequestPermissions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfPsidGroupPermissions },
  { &hf_ieee1609dot2_canRequestRollover, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_NULL },
  { &hf_ieee1609dot2_tbscEncryptionKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_PublicEncryptionKey },
  { &hf_ieee1609dot2_verifyKeyIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_VerificationKeyIndicator },
  { &hf_ieee1609dot2_flags  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ieee1609dot2_T_flags },
  { &hf_ieee1609dot2_appExtensions, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfAppExtensions },
  { &hf_ieee1609dot2_certIssueExtensions, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfCertIssueExtensions },
  { &hf_ieee1609dot2_certRequestExtension, ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfCertRequestExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_ToBeSignedCertificate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_ToBeSignedCertificate, ToBeSignedCertificate_sequence);

  return offset;
}


static const oer_sequence_t CertificateBase_sequence[] = {
  { &hf_ieee1609dot2_version, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint8 },
  { &hf_ieee1609dot2_type   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CertificateType },
  { &hf_ieee1609dot2_issuer , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_IssuerIdentifier },
  { &hf_ieee1609dot2_toBeSigned, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_ToBeSignedCertificate },
  { &hf_ieee1609dot2_signature, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ieee1609dot2_Signature },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CertificateBase(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CertificateBase, CertificateBase_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_Certificate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_CertificateBase(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ieee1609dot2_PduFunctionalType_vals[] = {
  {   1, "tlsHandshake" },
  {   2, "iso21177ExtendedAuth" },
  {   3, "iso21177SessionExtension" },
  { 0, NULL }
};


static int
dissect_ieee1609dot2_PduFunctionalType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string ieee1609dot2_HeaderInfoContributorId_vals[] = {
  {   1, "ieee1609HeaderInfoContributorId" },
  {   2, "etsiHeaderInfoContributorId" },
  { 0, NULL }
};


static int
dissect_ieee1609dot2_HeaderInfoContributorId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_ieee1609dot2_T_extns_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const oer_sequence_t T_extns_sequence_of[1] = {
  { &hf_ieee1609dot2_extns_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_T_extns_item },
};

static int
dissect_ieee1609dot2_T_extns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ieee1609dot2_T_extns, T_extns_sequence_of,
                                                  1, NO_BOUND, false);

  return offset;
}


static const oer_sequence_t ContributedExtensionBlock_sequence[] = {
  { &hf_ieee1609dot2_contributorId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HeaderInfoContributorId },
  { &hf_ieee1609dot2_extns  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_T_extns },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_ContributedExtensionBlock(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_ContributedExtensionBlock, ContributedExtensionBlock_sequence);

  return offset;
}


static const oer_sequence_t ContributedExtensionBlocks_sequence_of[1] = {
  { &hf_ieee1609dot2_ContributedExtensionBlocks_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_ContributedExtensionBlock },
};

static int
dissect_ieee1609dot2_ContributedExtensionBlocks(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ieee1609dot2_ContributedExtensionBlocks, ContributedExtensionBlocks_sequence_of,
                                                  1, NO_BOUND, false);

  return offset;
}


static const oer_sequence_t HeaderInfo_sequence[] = {
  { &hf_ieee1609dot2_hiPsid , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_T_hiPsid },
  { &hf_ieee1609dot2_generationTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_Time64 },
  { &hf_ieee1609dot2_expiryTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_Time64 },
  { &hf_ieee1609dot2_generationLocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_ThreeDLocation },
  { &hf_ieee1609dot2_p2pcdLearningRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_HashedId3 },
  { &hf_ieee1609dot2_missingCrlIdentifier, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_MissingCrlIdentifier },
  { &hf_ieee1609dot2_encryptionKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_EncryptionKey },
  { &hf_ieee1609dot2_inlineP2pcdRequest, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ieee1609dot2_SequenceOfHashedId3 },
  { &hf_ieee1609dot2_requestedCertificate, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ieee1609dot2_Certificate },
  { &hf_ieee1609dot2_pduFunctionalType, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ieee1609dot2_PduFunctionalType },
  { &hf_ieee1609dot2_contributedExtensions, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ieee1609dot2_ContributedExtensionBlocks },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_HeaderInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_HeaderInfo, HeaderInfo_sequence);

  return offset;
}


static const oer_sequence_t CrlToBeSignedData_sequence[] = {
  { &hf_ieee1609dot2_payload, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CrlSignedDataPayload },
  { &hf_ieee1609dot2_headerInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HeaderInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CrlToBeSignedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CrlToBeSignedData, CrlToBeSignedData_sequence);

  return offset;
}


static const oer_sequence_t CrlSignedData_sequence[] = {
  { &hf_ieee1609dot2_tbsData, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_CrlToBeSignedData },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_CrlSignedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_CrlSignedData, CrlSignedData_sequence);

  return offset;
}


static const value_string ieee1609dot2_SecuredCrlContent_vals[] = {
  {   0, "signedData" },
  { 0, NULL }
};

static const oer_choice_t SecuredCrlContent_choice[] = {
  {   0, &hf_ieee1609dot2_signedData, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_CrlSignedData },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_SecuredCrlContent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_SecuredCrlContent, SecuredCrlContent_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t SecuredCrl_sequence[] = {
  { &hf_ieee1609dot2_content, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SecuredCrlContent },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_SecuredCrl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_SecuredCrl, SecuredCrl_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_T_unsecuredData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ieee1609_private_data_t *my_private_data = (ieee1609_private_data_t*)actx->private_data;

  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &my_private_data->unsecured_data);

  if (my_private_data->unsecured_data) {
    // psid may also be provided in HeaderInfo
    uint32_t psid = GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), actx->pinfo, proto_ieee1609dot2, 0));
    if (psid) {
      /* Call next dissector here */
      dissector_try_uint(unsecured_data_subdissector_table, psid, my_private_data->unsecured_data, actx->pinfo, tree);
      my_private_data->unsecured_data = NULL;
    }
    // else: wait for the HeaderInfo for a second chance to dissect the content
  }


  return offset;
}


static const value_string ieee1609dot2_HashedData_vals[] = {
  {   0, "sha256HashedData" },
  {   1, "sha384HashedData" },
  {   2, "sm3HashedData" },
  { 0, NULL }
};

static const oer_choice_t HashedData_choice[] = {
  {   0, &hf_ieee1609dot2_sha256HashedData, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_HashedId32 },
  {   1, &hf_ieee1609dot2_sha384HashedData, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_HashedId48 },
  {   2, &hf_ieee1609dot2_sm3HashedData, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_HashedId32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_HashedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_HashedData, HashedData_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t SignedDataPayload_sequence[] = {
  { &hf_ieee1609dot2_data_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_Ieee1609Dot2Data },
  { &hf_ieee1609dot2_extDataHash, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ieee1609dot2_HashedData },
  { &hf_ieee1609dot2_omitted, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ieee1609dot2_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_SignedDataPayload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_SignedDataPayload, SignedDataPayload_sequence);

  return offset;
}


static const oer_sequence_t ToBeSignedData_sequence[] = {
  { &hf_ieee1609dot2_payload_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SignedDataPayload },
  { &hf_ieee1609dot2_headerInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HeaderInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_ToBeSignedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_ToBeSignedData, ToBeSignedData_sequence);

  return offset;
}


static const oer_sequence_t SequenceOfCertificate_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfCertificate_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Certificate },
};

static int
dissect_ieee1609dot2_SequenceOfCertificate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfCertificate, SequenceOfCertificate_sequence_of);

  return offset;
}


static const value_string ieee1609dot2_SignerIdentifier_vals[] = {
  {   0, "digest" },
  {   1, "certificate" },
  {   2, "self" },
  { 0, NULL }
};

static const oer_choice_t SignerIdentifier_choice[] = {
  {   0, &hf_ieee1609dot2_digest , ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_HashedId8 },
  {   1, &hf_ieee1609dot2_certificate, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_SequenceOfCertificate },
  {   2, &hf_ieee1609dot2_siSelf , ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_SignerIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_SignerIdentifier, SignerIdentifier_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t SignedData_sequence[] = {
  { &hf_ieee1609dot2_hashId , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashAlgorithm },
  { &hf_ieee1609dot2_tbsData_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_ToBeSignedData },
  { &hf_ieee1609dot2_signer , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SignerIdentifier },
  { &hf_ieee1609dot2_signature, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Signature },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_SignedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_SignedData, SignedData_sequence);

  return offset;
}



static int
dissect_ieee1609dot2_PreSharedKeyRecipientInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ieee1609dot2_HashedId8(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ieee1609dot2_OCTET_STRING_SIZE_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_octet_string(tvb, offset, actx, tree, hf_index,
                                       12, 12, false, NULL);

  return offset;
}


static const oer_sequence_t One28BitCcmCiphertext_sequence[] = {
  { &hf_ieee1609dot2_nonce  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_OCTET_STRING_SIZE_12 },
  { &hf_ieee1609dot2_ccmCiphertext, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Opaque },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_One28BitCcmCiphertext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_One28BitCcmCiphertext, One28BitCcmCiphertext_sequence);

  return offset;
}


static const value_string ieee1609dot2_SymmetricCiphertext_vals[] = {
  {   0, "aes128ccm" },
  {   1, "sm4Ccm" },
  { 0, NULL }
};

static const oer_choice_t SymmetricCiphertext_choice[] = {
  {   0, &hf_ieee1609dot2_aes128ccm, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_One28BitCcmCiphertext },
  {   1, &hf_ieee1609dot2_sm4Ccm_01, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_One28BitCcmCiphertext },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_SymmetricCiphertext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_SymmetricCiphertext, SymmetricCiphertext_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t SymmRecipientInfo_sequence[] = {
  { &hf_ieee1609dot2_recipientId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashedId8 },
  { &hf_ieee1609dot2_sriEncKey, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SymmetricCiphertext },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_SymmRecipientInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_SymmRecipientInfo, SymmRecipientInfo_sequence);

  return offset;
}


static const value_string ieee1609dot2_EncryptedDataEncryptionKey_vals[] = {
  {   0, "eciesNistP256" },
  {   1, "eciesBrainpoolP256r1" },
  {   2, "ecencSm2256" },
  { 0, NULL }
};

static const oer_choice_t EncryptedDataEncryptionKey_choice[] = {
  {   0, &hf_ieee1609dot2_edeEciesNistP256, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EciesP256EncryptedKey },
  {   1, &hf_ieee1609dot2_edekEciesBrainpoolP256r1, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EciesP256EncryptedKey },
  {   2, &hf_ieee1609dot2_ecencSm2256, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_EcencP256EncryptedKey },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_EncryptedDataEncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_EncryptedDataEncryptionKey, EncryptedDataEncryptionKey_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t PKRecipientInfo_sequence[] = {
  { &hf_ieee1609dot2_recipientId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_HashedId8 },
  { &hf_ieee1609dot2_encKey , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_EncryptedDataEncryptionKey },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_PKRecipientInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_PKRecipientInfo, PKRecipientInfo_sequence);

  return offset;
}


static const value_string ieee1609dot2_RecipientInfo_vals[] = {
  {   0, "pskRecipInfo" },
  {   1, "symmRecipInfo" },
  {   2, "certRecipInfo" },
  {   3, "signedDataRecipInfo" },
  {   4, "rekRecipInfo" },
  { 0, NULL }
};

static const oer_choice_t RecipientInfo_choice[] = {
  {   0, &hf_ieee1609dot2_pskRecipInfo, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_PreSharedKeyRecipientInfo },
  {   1, &hf_ieee1609dot2_symmRecipInfo, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_SymmRecipientInfo },
  {   2, &hf_ieee1609dot2_certRecipInfo, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_PKRecipientInfo },
  {   3, &hf_ieee1609dot2_signedDataRecipInfo, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_PKRecipientInfo },
  {   4, &hf_ieee1609dot2_rekRecipInfo, ASN1_NO_EXTENSIONS     , dissect_ieee1609dot2_PKRecipientInfo },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_RecipientInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_RecipientInfo, RecipientInfo_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t SequenceOfRecipientInfo_sequence_of[1] = {
  { &hf_ieee1609dot2_SequenceOfRecipientInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_RecipientInfo },
};

static int
dissect_ieee1609dot2_SequenceOfRecipientInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_ieee1609dot2_SequenceOfRecipientInfo, SequenceOfRecipientInfo_sequence_of);

  return offset;
}


static const oer_sequence_t EncryptedData_sequence[] = {
  { &hf_ieee1609dot2_recipients, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SequenceOfRecipientInfo },
  { &hf_ieee1609dot2_ciphertext, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_SymmetricCiphertext },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_EncryptedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_EncryptedData, EncryptedData_sequence);

  return offset;
}


static const value_string ieee1609dot2_Ieee1609Dot2Content_vals[] = {
  {   0, "unsecuredData" },
  {   1, "signedData" },
  {   2, "encryptedData" },
  {   3, "signedCertificateRequest" },
  {   4, "signedX509CertificateRequest" },
  { 0, NULL }
};

static const oer_choice_t Ieee1609Dot2Content_choice[] = {
  {   0, &hf_ieee1609dot2_unsecuredData_01, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_T_unsecuredData },
  {   1, &hf_ieee1609dot2_signedData_01, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_SignedData },
  {   2, &hf_ieee1609dot2_encryptedData, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_EncryptedData },
  {   3, &hf_ieee1609dot2_signedCertificateRequest, ASN1_EXTENSION_ROOT    , dissect_ieee1609dot2_Opaque },
  {   4, &hf_ieee1609dot2_signedX509CertificateRequest, ASN1_NOT_EXTENSION_ROOT, dissect_ieee1609dot2_Opaque },
  { 0, NULL, 0, NULL }
};

static int
dissect_ieee1609dot2_Ieee1609Dot2Content(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_oer_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ieee1609dot2_Ieee1609Dot2Content, Ieee1609Dot2Content_choice,
                                 NULL);

  return offset;
}


static const oer_sequence_t Ieee1609Dot2Data_sequence[] = {
  { &hf_ieee1609dot2_protocolVersion, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Uint8 },
  { &hf_ieee1609dot2_content_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ieee1609dot2_Ieee1609Dot2Content },
  { NULL, 0, 0, NULL }
};

static int
dissect_ieee1609dot2_Ieee1609Dot2Data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Ieee1609Dot2Data -> Ieee1609Dot2Content -> SignedData -> ToBeSignedData -> SignedDataPayload -> Ieee1609Dot2Data
  actx->pinfo->dissection_depth += 5;
  increment_dissection_depth(actx->pinfo);
  actx->private_data = (void*)wmem_new0(actx->pinfo->pool, ieee1609_private_data_t);
  offset = dissect_oer_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ieee1609dot2_Ieee1609Dot2Data, Ieee1609Dot2Data_sequence);

  actx->pinfo->dissection_depth -= 5;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}

/*--- PDUs ---*/

static int dissect_SecuredCrl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_OER, true, pinfo);
  offset = dissect_ieee1609dot2_SecuredCrl(tvb, offset, &asn1_ctx, tree, hf_ieee1609dot2_SecuredCrl_PDU);
  return offset;
}
static int dissect_Ieee1609Dot2Data_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_OER, true, pinfo);
  offset = dissect_ieee1609dot2_Ieee1609Dot2Data(tvb, offset, &asn1_ctx, tree, hf_ieee1609dot2_Ieee1609Dot2Data_PDU);
  return offset;
}



static void
ieee1609dot2_NinetyDegreeInt_fmt(char *s, uint32_t v)
{
  int32_t lat = (int32_t)v;
  if (lat == 900000001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable(%d)", lat);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
               abs(lat) / 10000000,
               abs(lat) % 10000000 * 6 / 1000000,
               abs(lat) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
               (lat >= 0) ? 'N' : 'S',
               lat);
  }
}

static void
ieee1609dot2_OneEightyDegreeInt_fmt(char *s, uint32_t v)
{
  int32_t lng = (int32_t)v;
  if (lng == 1800000001) {
    snprintf(s, ITEM_LABEL_LENGTH, "unavailable(%d)", lng);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u°%u'%.3f\"%c (%d)",
               abs(lng) / 10000000,
               abs(lng) % 10000000 * 6 / 1000000,
               abs(lng) % 10000000 * 6 % 1000000 * 6.0 / 100000.0,
               (lng >= 0) ? 'E' : 'W',
               lng);
  }
}


static void
ieee1609dot2_Time32_fmt(char *s, uint32_t v)
{
  time_t secs = v + 1072915200 - 5;
  struct tm *tm = gmtime(&secs);
  snprintf(s, ITEM_LABEL_LENGTH, "%u-%02u-%02u %02u:%02u:%02u (%u)",
    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, v
  );
}

static void
ieee1609dot2_Time64_fmt(char *s, uint64_t v)
{
  time_t secs = v / 1000000 + 1072915200 - 5;
  uint32_t usecs = v % 1000000;
  struct tm *tm = gmtime(&secs);
  snprintf(s, ITEM_LABEL_LENGTH, "%u-%02u-%02u %02u:%02u:%02u.%06u (%" PRIu64 ")",
    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, usecs, v
  );
}

/*--- proto_register_ieee1609dot2 ----------------------------------------------*/
void proto_register_ieee1609dot2(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ieee1609dot2_SecuredCrl_PDU,
      { "SecuredCrl", "ieee1609dot2.SecuredCrl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_Ieee1609Dot2Data_PDU,
      { "Ieee1609Dot2Data", "ieee1609dot2.Ieee1609Dot2Data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_SequenceOfUint8_item,
      { "Uint8", "ieee1609dot2.Uint8",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_SequenceOfUint16_item,
      { "Uint16", "ieee1609dot2.Uint16",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_SequenceOfHashedId3_item,
      { "HashedId3", "ieee1609dot2.HashedId3",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_start,
      { "start", "ieee1609dot2.start",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ieee1609dot2_Time32_fmt), 0,
        "Time32", HFILL }},
    { &hf_ieee1609dot2_duration,
      { "duration", "ieee1609dot2.duration",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_Duration_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_microseconds,
      { "microseconds", "ieee1609dot2.microseconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_milliseconds,
      { "milliseconds", "ieee1609dot2.milliseconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_seconds,
      { "seconds", "ieee1609dot2.seconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_minutes,
      { "minutes", "ieee1609dot2.minutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_hours,
      { "hours", "ieee1609dot2.hours",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_sixtyHours,
      { "sixtyHours", "ieee1609dot2.sixtyHours",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_years,
      { "years", "ieee1609dot2.years",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_circularRegion,
      { "circularRegion", "ieee1609dot2.circularRegion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_rectangularRegion,
      { "rectangularRegion", "ieee1609dot2.rectangularRegion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfRectangularRegion", HFILL }},
    { &hf_ieee1609dot2_polygonalRegion,
      { "polygonalRegion", "ieee1609dot2.polygonalRegion",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_identifiedRegion,
      { "identifiedRegion", "ieee1609dot2.identifiedRegion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfIdentifiedRegion", HFILL }},
    { &hf_ieee1609dot2_center,
      { "center", "ieee1609dot2.center_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TwoDLocation", HFILL }},
    { &hf_ieee1609dot2_radius,
      { "radius", "ieee1609dot2.radius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_northWest,
      { "northWest", "ieee1609dot2.northWest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TwoDLocation", HFILL }},
    { &hf_ieee1609dot2_southEast,
      { "southEast", "ieee1609dot2.southEast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TwoDLocation", HFILL }},
    { &hf_ieee1609dot2_SequenceOfRectangularRegion_item,
      { "RectangularRegion", "ieee1609dot2.RectangularRegion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_PolygonalRegion_item,
      { "TwoDLocation", "ieee1609dot2.TwoDLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_latitude,
      { "latitude", "ieee1609dot2.latitude",
        FT_INT32, BASE_CUSTOM, CF_FUNC(ieee1609dot2_NinetyDegreeInt_fmt), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_longitude,
      { "longitude", "ieee1609dot2.longitude",
        FT_INT32, BASE_CUSTOM, CF_FUNC(ieee1609dot2_OneEightyDegreeInt_fmt), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_countryOnly,
      { "countryOnly", "ieee1609dot2.countryOnly",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnCountryId", HFILL }},
    { &hf_ieee1609dot2_countryAndRegions,
      { "countryAndRegions", "ieee1609dot2.countryAndRegions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_countryAndSubregions,
      { "countryAndSubregions", "ieee1609dot2.countryAndSubregions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_SequenceOfIdentifiedRegion_item,
      { "IdentifiedRegion", "ieee1609dot2.IdentifiedRegion",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_IdentifiedRegion_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_regions,
      { "regions", "ieee1609dot2.regions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfUint8", HFILL }},
    { &hf_ieee1609dot2_regionAndSubregions,
      { "regionAndSubregions", "ieee1609dot2.regionAndSubregions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfRegionAndSubregions", HFILL }},
    { &hf_ieee1609dot2_rasRegion,
      { "region", "ieee1609dot2.region",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint8", HFILL }},
    { &hf_ieee1609dot2_subregions,
      { "subregions", "ieee1609dot2.subregions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfUint16", HFILL }},
    { &hf_ieee1609dot2_SequenceOfRegionAndSubregions_item,
      { "RegionAndSubregions", "ieee1609dot2.RegionAndSubregions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_elevation,
      { "elevation", "ieee1609dot2.elevation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_ecdsaNistP256Signature,
      { "ecdsaNistP256Signature", "ieee1609dot2.ecdsaNistP256Signature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EcdsaP256Signature", HFILL }},
    { &hf_ieee1609dot2_ecdsaBrainpoolP256r1Signature,
      { "ecdsaBrainpoolP256r1Signature", "ieee1609dot2.ecdsaBrainpoolP256r1Signature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EcdsaP256Signature", HFILL }},
    { &hf_ieee1609dot2_ecdsaBrainpoolP384r1Signature,
      { "ecdsaBrainpoolP384r1Signature", "ieee1609dot2.ecdsaBrainpoolP384r1Signature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EcdsaP384Signature", HFILL }},
    { &hf_ieee1609dot2_ecdsaNistP384Signature,
      { "ecdsaNistP384Signature", "ieee1609dot2.ecdsaNistP384Signature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EcdsaP384Signature", HFILL }},
    { &hf_ieee1609dot2_sm2Signature,
      { "sm2Signature", "ieee1609dot2.sm2Signature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EcsigP256Signature", HFILL }},
    { &hf_ieee1609dot2_rSig,
      { "rSig", "ieee1609dot2.rSig",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_sSig,
      { "sSig", "ieee1609dot2.sSig",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_32", HFILL }},
    { &hf_ieee1609dot2_ecdsap384RSig,
      { "rSig", "ieee1609dot2.rSig",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP384CurvePoint_vals), 0,
        "EccP384CurvePoint", HFILL }},
    { &hf_ieee1609dot2_ecdsap384SSig,
      { "sSig", "ieee1609dot2.sSig",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_48", HFILL }},
    { &hf_ieee1609dot2_rSig_01,
      { "rSig", "ieee1609dot2.rSig",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_32", HFILL }},
    { &hf_ieee1609dot2_x_only,
      { "x-only", "ieee1609dot2.x_only",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_32", HFILL }},
    { &hf_ieee1609dot2_fill,
      { "fill", "ieee1609dot2.fill_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_compressed_y_0,
      { "compressed-y-0", "ieee1609dot2.compressed_y_0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_32", HFILL }},
    { &hf_ieee1609dot2_compressed_y_1,
      { "compressed-y-1", "ieee1609dot2.compressed_y_1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_32", HFILL }},
    { &hf_ieee1609dot2_uncompressedP256,
      { "uncompressedP256", "ieee1609dot2.uncompressedP256_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_x,
      { "x", "ieee1609dot2.x",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_32", HFILL }},
    { &hf_ieee1609dot2_y,
      { "y", "ieee1609dot2.y",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_32", HFILL }},
    { &hf_ieee1609dot2_eccp384cpXOnly,
      { "x-only", "ieee1609dot2.x_only",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_48", HFILL }},
    { &hf_ieee1609dot2_eccp384cpCompressed_y_0,
      { "compressed-y-0", "ieee1609dot2.compressed_y_0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_48", HFILL }},
    { &hf_ieee1609dot2_eccp384cpCompressed_y_1,
      { "compressed-y-1", "ieee1609dot2.compressed_y_1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_48", HFILL }},
    { &hf_ieee1609dot2_uncompressedP384,
      { "uncompressedP384", "ieee1609dot2.uncompressedP384_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_eccp384cpX,
      { "x", "ieee1609dot2.x",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_48", HFILL }},
    { &hf_ieee1609dot2_eccp384cpY,
      { "y", "ieee1609dot2.y",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_48", HFILL }},
    { &hf_ieee1609dot2_v,
      { "v", "ieee1609dot2.v",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_c,
      { "c", "ieee1609dot2.c",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_ieee1609dot2_t,
      { "t", "ieee1609dot2.t",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_ieee1609dot2_t_01,
      { "t", "ieee1609dot2.t",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_32", HFILL }},
    { &hf_ieee1609dot2_public,
      { "public", "ieee1609dot2.public_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PublicEncryptionKey", HFILL }},
    { &hf_ieee1609dot2_symmetric,
      { "symmetric", "ieee1609dot2.symmetric",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_SymmetricEncryptionKey_vals), 0,
        "SymmetricEncryptionKey", HFILL }},
    { &hf_ieee1609dot2_supportedSymmAlg,
      { "supportedSymmAlg", "ieee1609dot2.supportedSymmAlg",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_SymmAlgorithm_vals), 0,
        "SymmAlgorithm", HFILL }},
    { &hf_ieee1609dot2_publicKey,
      { "publicKey", "ieee1609dot2.publicKey",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_BasePublicEncryptionKey_vals), 0,
        "BasePublicEncryptionKey", HFILL }},
    { &hf_ieee1609dot2_eciesNistP256,
      { "eciesNistP256", "ieee1609dot2.eciesNistP256",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_eciesBrainpoolP256r1,
      { "eciesBrainpoolP256r1", "ieee1609dot2.eciesBrainpoolP256r1",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_ecencSm2,
      { "ecencSm2", "ieee1609dot2.ecencSm2",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_ecdsaNistP256,
      { "ecdsaNistP256", "ieee1609dot2.ecdsaNistP256",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_ecdsaBrainpoolP256r1,
      { "ecdsaBrainpoolP256r1", "ieee1609dot2.ecdsaBrainpoolP256r1",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_ecdsaBrainpoolP384r1,
      { "ecdsaBrainpoolP384r1", "ieee1609dot2.ecdsaBrainpoolP384r1",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP384CurvePoint_vals), 0,
        "EccP384CurvePoint", HFILL }},
    { &hf_ieee1609dot2_ecdsaNistP384,
      { "ecdsaNistP384", "ieee1609dot2.ecdsaNistP384",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP384CurvePoint_vals), 0,
        "EccP384CurvePoint", HFILL }},
    { &hf_ieee1609dot2_ecsigSm2,
      { "ecsigSm2", "ieee1609dot2.ecsigSm2",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_aes128Ccm,
      { "aes128Ccm", "ieee1609dot2.aes128Ccm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_ieee1609dot2_sm4Ccm,
      { "sm4Ccm", "ieee1609dot2.sm4Ccm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_ieee1609dot2_psPsid,
      { "psid", "ieee1609dot2.psid",
        FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(ieee1609dot2_Psid_vals), 0,
        "T_psPsid", HFILL }},
    { &hf_ieee1609dot2_ssp,
      { "ssp", "ieee1609dot2.ssp",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_ServiceSpecificPermissions_vals), 0,
        "ServiceSpecificPermissions", HFILL }},
    { &hf_ieee1609dot2_SequenceOfPsidSsp_item,
      { "PsidSsp", "ieee1609dot2.PsidSsp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_opaque,
      { "opaque", "ieee1609dot2.opaque",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_bitmapSsp,
      { "bitmapSsp", "ieee1609dot2.bitmapSsp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_psid,
      { "psid", "ieee1609dot2.psid",
        FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(ieee1609dot2_Psid_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_sspRange,
      { "sspRange", "ieee1609dot2.sspRange",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_SspRange_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_SequenceOfPsidSspRange_item,
      { "PsidSspRange", "ieee1609dot2.PsidSspRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_srRange,
      { "opaque", "ieee1609dot2.srRange.opaque",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfOctetString", HFILL }},
    { &hf_ieee1609dot2_all,
      { "all", "ieee1609dot2.all_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_bitmapSspRange,
      { "bitmapSspRange", "ieee1609dot2.bitmapSspRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_sspValue,
      { "sspValue", "ieee1609dot2.sspValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_32", HFILL }},
    { &hf_ieee1609dot2_sspBitmask,
      { "sspBitmask", "ieee1609dot2.sspBitmask",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_32", HFILL }},
    { &hf_ieee1609dot2_SequenceOfOctetString_item,
      { "SequenceOfOctetString item", "ieee1609dot2.SequenceOfOctetString_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_MAX", HFILL }},
    { &hf_ieee1609dot2_jValue,
      { "jValue", "ieee1609dot2.jValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_ieee1609dot2_value,
      { "value", "ieee1609dot2.value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_9", HFILL }},
    { &hf_ieee1609dot2_SequenceOfLinkageSeed_item,
      { "LinkageSeed", "ieee1609dot2.LinkageSeed",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_version,
      { "version", "ieee1609dot2.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint8", HFILL }},
    { &hf_ieee1609dot2_crlSeries,
      { "crlSeries", "ieee1609dot2.crlSeries",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_crlCraca,
      { "crlCraca", "ieee1609dot2.crlCraca",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId8", HFILL }},
    { &hf_ieee1609dot2_issueDate,
      { "issueDate", "ieee1609dot2.issueDate",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ieee1609dot2_Time32_fmt), 0,
        "Time32", HFILL }},
    { &hf_ieee1609dot2_nextCrl,
      { "nextCrl", "ieee1609dot2.nextCrl",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ieee1609dot2_Time32_fmt), 0,
        "Time32", HFILL }},
    { &hf_ieee1609dot2_priorityInfo,
      { "priorityInfo", "ieee1609dot2.priorityInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CrlPriorityInfo", HFILL }},
    { &hf_ieee1609dot2_typeSpecific,
      { "typeSpecific", "ieee1609dot2.typeSpecific",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_TypeSpecificCrlContents_vals), 0,
        "TypeSpecificCrlContents", HFILL }},
    { &hf_ieee1609dot2_priority,
      { "priority", "ieee1609dot2.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint8", HFILL }},
    { &hf_ieee1609dot2_fullHashCrl,
      { "fullHashCrl", "ieee1609dot2.fullHashCrl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToBeSignedHashIdCrl", HFILL }},
    { &hf_ieee1609dot2_deltaHashCrl,
      { "deltaHashCrl", "ieee1609dot2.deltaHashCrl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToBeSignedHashIdCrl", HFILL }},
    { &hf_ieee1609dot2_fullLinkedCrl,
      { "fullLinkedCrl", "ieee1609dot2.fullLinkedCrl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToBeSignedLinkageValueCrl", HFILL }},
    { &hf_ieee1609dot2_deltaLinkedCrl,
      { "deltaLinkedCrl", "ieee1609dot2.deltaLinkedCrl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToBeSignedLinkageValueCrl", HFILL }},
    { &hf_ieee1609dot2_fullLinkedCrlWithAlg,
      { "fullLinkedCrlWithAlg", "ieee1609dot2.fullLinkedCrlWithAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToBeSignedLinkageValueCrlWithAlgIdentifier", HFILL }},
    { &hf_ieee1609dot2_deltaLinkedCrlWithAlg,
      { "deltaLinkedCrlWithAlg", "ieee1609dot2.deltaLinkedCrlWithAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToBeSignedLinkageValueCrlWithAlgIdentifier", HFILL }},
    { &hf_ieee1609dot2_crlSerial,
      { "crlSerial", "ieee1609dot2.crlSerial",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint32", HFILL }},
    { &hf_ieee1609dot2_entries,
      { "entries", "ieee1609dot2.entries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfHashBasedRevocationInfo", HFILL }},
    { &hf_ieee1609dot2_SequenceOfHashBasedRevocationInfo_item,
      { "HashBasedRevocationInfo", "ieee1609dot2.HashBasedRevocationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_id,
      { "id", "ieee1609dot2.id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId10", HFILL }},
    { &hf_ieee1609dot2_expiry,
      { "expiry", "ieee1609dot2.expiry",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ieee1609dot2_Time32_fmt), 0,
        "Time32", HFILL }},
    { &hf_ieee1609dot2_iRev,
      { "iRev", "ieee1609dot2.iRev",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IValue", HFILL }},
    { &hf_ieee1609dot2_indexWithinI,
      { "indexWithinI", "ieee1609dot2.indexWithinI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint8", HFILL }},
    { &hf_ieee1609dot2_individual,
      { "individual", "ieee1609dot2.individual",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfJMaxGroup", HFILL }},
    { &hf_ieee1609dot2_groups,
      { "groups", "ieee1609dot2.groups",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfGroupCrlEntry", HFILL }},
    { &hf_ieee1609dot2_groupsSingleSeed,
      { "groupsSingleSeed", "ieee1609dot2.groupsSingleSeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfGroupSingleSeedCrlEntry", HFILL }},
    { &hf_ieee1609dot2_SequenceOfJMaxGroup_item,
      { "JMaxGroup", "ieee1609dot2.JMaxGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_jmax,
      { "jmax", "ieee1609dot2.jmax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint8", HFILL }},
    { &hf_ieee1609dot2_contents,
      { "contents", "ieee1609dot2.contents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfLAGroup", HFILL }},
    { &hf_ieee1609dot2_SequenceOfLAGroup_item,
      { "LAGroup", "ieee1609dot2.LAGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_la1Id,
      { "la1Id", "ieee1609dot2.la1Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaId", HFILL }},
    { &hf_ieee1609dot2_la2Id,
      { "la2Id", "ieee1609dot2.la2Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaId", HFILL }},
    { &hf_ieee1609dot2_contents_01,
      { "contents", "ieee1609dot2.contents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfIMaxGroup", HFILL }},
    { &hf_ieee1609dot2_SequenceOfIMaxGroup_item,
      { "IMaxGroup", "ieee1609dot2.IMaxGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_iMax,
      { "iMax", "ieee1609dot2.iMax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint16", HFILL }},
    { &hf_ieee1609dot2_contents_02,
      { "contents", "ieee1609dot2.contents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfIndividualRevocation", HFILL }},
    { &hf_ieee1609dot2_singleSeed,
      { "singleSeed", "ieee1609dot2.singleSeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfLinkageSeed", HFILL }},
    { &hf_ieee1609dot2_SequenceOfIndividualRevocation_item,
      { "IndividualRevocation", "ieee1609dot2.IndividualRevocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_linkageSeed1,
      { "linkageSeed1", "ieee1609dot2.linkageSeed1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LinkageSeed", HFILL }},
    { &hf_ieee1609dot2_linkageSeed2,
      { "linkageSeed2", "ieee1609dot2.linkageSeed2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LinkageSeed", HFILL }},
    { &hf_ieee1609dot2_SequenceOfGroupCrlEntry_item,
      { "GroupCrlEntry", "ieee1609dot2.GroupCrlEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_seedEvolution,
      { "seedEvolution", "ieee1609dot2.seedEvolution_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeedEvolutionFunctionIdentifier", HFILL }},
    { &hf_ieee1609dot2_lvGeneration,
      { "lvGeneration", "ieee1609dot2.lvGeneration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LvGenerationFunctionIdentifier", HFILL }},
    { &hf_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry_item,
      { "GroupSingleSeedCrlEntry", "ieee1609dot2.GroupSingleSeedCrlEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_laId,
      { "laId", "ieee1609dot2.laId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_linkageSeed,
      { "linkageSeed", "ieee1609dot2.linkageSeed",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_content,
      { "content", "ieee1609dot2.content",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_SecuredCrlContent_vals), 0,
        "SecuredCrlContent", HFILL }},
    { &hf_ieee1609dot2_signedData,
      { "signedData", "ieee1609dot2.signedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CrlSignedData", HFILL }},
    { &hf_ieee1609dot2_tbsData,
      { "tbsData", "ieee1609dot2.tbsData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CrlToBeSignedData", HFILL }},
    { &hf_ieee1609dot2_payload,
      { "payload", "ieee1609dot2.payload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CrlSignedDataPayload", HFILL }},
    { &hf_ieee1609dot2_headerInfo,
      { "headerInfo", "ieee1609dot2.headerInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_data,
      { "data", "ieee1609dot2.data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ieee1609Dot2CrlData", HFILL }},
    { &hf_ieee1609dot2_content_01,
      { "content", "ieee1609dot2.content",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_Ieee1609Dot2CrlContent_vals), 0,
        "Ieee1609Dot2CrlContent", HFILL }},
    { &hf_ieee1609dot2_unsecuredData,
      { "unsecuredData", "ieee1609dot2.unsecuredData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CrlContents", HFILL }},
    { &hf_ieee1609dot2_protocolVersion,
      { "protocolVersion", "ieee1609dot2.protocolVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uint8", HFILL }},
    { &hf_ieee1609dot2_content_02,
      { "content", "ieee1609dot2.content",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_Ieee1609Dot2Content_vals), 0,
        "Ieee1609Dot2Content", HFILL }},
    { &hf_ieee1609dot2_unsecuredData_01,
      { "unsecuredData", "ieee1609dot2.unsecuredData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_signedData_01,
      { "signedData", "ieee1609dot2.signedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_encryptedData,
      { "encryptedData", "ieee1609dot2.encryptedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_signedCertificateRequest,
      { "signedCertificateRequest", "ieee1609dot2.signedCertificateRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Opaque", HFILL }},
    { &hf_ieee1609dot2_signedX509CertificateRequest,
      { "signedX509CertificateRequest", "ieee1609dot2.signedX509CertificateRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Opaque", HFILL }},
    { &hf_ieee1609dot2_hashId,
      { "hashId", "ieee1609dot2.hashId",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_HashAlgorithm_vals), 0,
        "HashAlgorithm", HFILL }},
    { &hf_ieee1609dot2_tbsData_01,
      { "tbsData", "ieee1609dot2.tbsData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToBeSignedData", HFILL }},
    { &hf_ieee1609dot2_signer,
      { "signer", "ieee1609dot2.signer",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_SignerIdentifier_vals), 0,
        "SignerIdentifier", HFILL }},
    { &hf_ieee1609dot2_signature,
      { "signature", "ieee1609dot2.signature",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_Signature_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_payload_01,
      { "payload", "ieee1609dot2.payload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignedDataPayload", HFILL }},
    { &hf_ieee1609dot2_data_01,
      { "data", "ieee1609dot2.data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ieee1609Dot2Data", HFILL }},
    { &hf_ieee1609dot2_extDataHash,
      { "extDataHash", "ieee1609dot2.extDataHash",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_HashedData_vals), 0,
        "HashedData", HFILL }},
    { &hf_ieee1609dot2_omitted,
      { "omitted", "ieee1609dot2.omitted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_sha256HashedData,
      { "sha256HashedData", "ieee1609dot2.sha256HashedData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId32", HFILL }},
    { &hf_ieee1609dot2_sha384HashedData,
      { "sha384HashedData", "ieee1609dot2.sha384HashedData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId48", HFILL }},
    { &hf_ieee1609dot2_sm3HashedData,
      { "sm3HashedData", "ieee1609dot2.sm3HashedData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId32", HFILL }},
    { &hf_ieee1609dot2_hiPsid,
      { "psid", "ieee1609dot2.psid",
        FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(ieee1609dot2_Psid_vals), 0,
        "T_hiPsid", HFILL }},
    { &hf_ieee1609dot2_generationTime,
      { "generationTime", "ieee1609dot2.generationTime",
        FT_UINT64, BASE_CUSTOM, CF_FUNC(ieee1609dot2_Time64_fmt), 0,
        "Time64", HFILL }},
    { &hf_ieee1609dot2_expiryTime,
      { "expiryTime", "ieee1609dot2.expiryTime",
        FT_UINT64, BASE_CUSTOM, CF_FUNC(ieee1609dot2_Time64_fmt), 0,
        "Time64", HFILL }},
    { &hf_ieee1609dot2_generationLocation,
      { "generationLocation", "ieee1609dot2.generationLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ThreeDLocation", HFILL }},
    { &hf_ieee1609dot2_p2pcdLearningRequest,
      { "p2pcdLearningRequest", "ieee1609dot2.p2pcdLearningRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId3", HFILL }},
    { &hf_ieee1609dot2_missingCrlIdentifier,
      { "missingCrlIdentifier", "ieee1609dot2.missingCrlIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_encryptionKey,
      { "encryptionKey", "ieee1609dot2.encryptionKey",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EncryptionKey_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_inlineP2pcdRequest,
      { "inlineP2pcdRequest", "ieee1609dot2.inlineP2pcdRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfHashedId3", HFILL }},
    { &hf_ieee1609dot2_requestedCertificate,
      { "requestedCertificate", "ieee1609dot2.requestedCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_ieee1609dot2_pduFunctionalType,
      { "pduFunctionalType", "ieee1609dot2.pduFunctionalType",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_PduFunctionalType_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_contributedExtensions,
      { "contributedExtensions", "ieee1609dot2.contributedExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContributedExtensionBlocks", HFILL }},
    { &hf_ieee1609dot2_cracaId,
      { "cracaId", "ieee1609dot2.cracaId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId3", HFILL }},
    { &hf_ieee1609dot2_ContributedExtensionBlocks_item,
      { "ContributedExtensionBlock", "ieee1609dot2.ContributedExtensionBlock_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_contributorId,
      { "contributorId", "ieee1609dot2.contributorId",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_HeaderInfoContributorId_vals), 0,
        "HeaderInfoContributorId", HFILL }},
    { &hf_ieee1609dot2_extns,
      { "extns", "ieee1609dot2.extns",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_extns_item,
      { "extns item", "ieee1609dot2.extns_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_digest,
      { "digest", "ieee1609dot2.digest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId8", HFILL }},
    { &hf_ieee1609dot2_certificate,
      { "certificate", "ieee1609dot2.certificate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfCertificate", HFILL }},
    { &hf_ieee1609dot2_siSelf,
      { "self", "ieee1609dot2.self_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_recipients,
      { "recipients", "ieee1609dot2.recipients",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfRecipientInfo", HFILL }},
    { &hf_ieee1609dot2_ciphertext,
      { "ciphertext", "ieee1609dot2.ciphertext",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_SymmetricCiphertext_vals), 0,
        "SymmetricCiphertext", HFILL }},
    { &hf_ieee1609dot2_pskRecipInfo,
      { "pskRecipInfo", "ieee1609dot2.pskRecipInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PreSharedKeyRecipientInfo", HFILL }},
    { &hf_ieee1609dot2_symmRecipInfo,
      { "symmRecipInfo", "ieee1609dot2.symmRecipInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SymmRecipientInfo", HFILL }},
    { &hf_ieee1609dot2_certRecipInfo,
      { "certRecipInfo", "ieee1609dot2.certRecipInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKRecipientInfo", HFILL }},
    { &hf_ieee1609dot2_signedDataRecipInfo,
      { "signedDataRecipInfo", "ieee1609dot2.signedDataRecipInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKRecipientInfo", HFILL }},
    { &hf_ieee1609dot2_rekRecipInfo,
      { "rekRecipInfo", "ieee1609dot2.rekRecipInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKRecipientInfo", HFILL }},
    { &hf_ieee1609dot2_SequenceOfRecipientInfo_item,
      { "RecipientInfo", "ieee1609dot2.RecipientInfo",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_RecipientInfo_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_recipientId,
      { "recipientId", "ieee1609dot2.recipientId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId8", HFILL }},
    { &hf_ieee1609dot2_sriEncKey,
      { "encKey", "ieee1609dot2.encKey",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_SymmetricCiphertext_vals), 0,
        "SymmetricCiphertext", HFILL }},
    { &hf_ieee1609dot2_encKey,
      { "encKey", "ieee1609dot2.encKey",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EncryptedDataEncryptionKey_vals), 0,
        "EncryptedDataEncryptionKey", HFILL }},
    { &hf_ieee1609dot2_edeEciesNistP256,
      { "eciesNistP256", "ieee1609dot2.eciesNistP256_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EciesP256EncryptedKey", HFILL }},
    { &hf_ieee1609dot2_edekEciesBrainpoolP256r1,
      { "eciesBrainpoolP256r1", "ieee1609dot2.eciesBrainpoolP256r1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EciesP256EncryptedKey", HFILL }},
    { &hf_ieee1609dot2_ecencSm2256,
      { "ecencSm2256", "ieee1609dot2.ecencSm2256_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EcencP256EncryptedKey", HFILL }},
    { &hf_ieee1609dot2_aes128ccm,
      { "aes128ccm", "ieee1609dot2.aes128ccm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "One28BitCcmCiphertext", HFILL }},
    { &hf_ieee1609dot2_sm4Ccm_01,
      { "sm4Ccm", "ieee1609dot2.sm4Ccm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "One28BitCcmCiphertext", HFILL }},
    { &hf_ieee1609dot2_nonce,
      { "nonce", "ieee1609dot2.nonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_12", HFILL }},
    { &hf_ieee1609dot2_ccmCiphertext,
      { "ccmCiphertext", "ieee1609dot2.ccmCiphertext",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Opaque", HFILL }},
    { &hf_ieee1609dot2_SequenceOfCertificate_item,
      { "Certificate", "ieee1609dot2.Certificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_type,
      { "type", "ieee1609dot2.type",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_CertificateType_vals), 0,
        "CertificateType", HFILL }},
    { &hf_ieee1609dot2_issuer,
      { "issuer", "ieee1609dot2.issuer",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_IssuerIdentifier_vals), 0,
        "IssuerIdentifier", HFILL }},
    { &hf_ieee1609dot2_toBeSigned,
      { "toBeSigned", "ieee1609dot2.toBeSigned_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ToBeSignedCertificate", HFILL }},
    { &hf_ieee1609dot2_sha256AndDigest,
      { "sha256AndDigest", "ieee1609dot2.sha256AndDigest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId8", HFILL }},
    { &hf_ieee1609dot2_iiSelf,
      { "self", "ieee1609dot2.self",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_HashAlgorithm_vals), 0,
        "HashAlgorithm", HFILL }},
    { &hf_ieee1609dot2_sha384AndDigest,
      { "sha384AndDigest", "ieee1609dot2.sha384AndDigest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId8", HFILL }},
    { &hf_ieee1609dot2_sm3AndDigest,
      { "sm3AndDigest", "ieee1609dot2.sm3AndDigest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HashedId8", HFILL }},
    { &hf_ieee1609dot2_id_01,
      { "id", "ieee1609dot2.id",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_CertificateId_vals), 0,
        "CertificateId", HFILL }},
    { &hf_ieee1609dot2_validityPeriod,
      { "validityPeriod", "ieee1609dot2.validityPeriod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_region,
      { "region", "ieee1609dot2.region",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_GeographicRegion_vals), 0,
        "GeographicRegion", HFILL }},
    { &hf_ieee1609dot2_assuranceLevel,
      { "assuranceLevel", "ieee1609dot2.assuranceLevel",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SubjectAssurance", HFILL }},
    { &hf_ieee1609dot2_appPermissions,
      { "appPermissions", "ieee1609dot2.appPermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfPsidSsp", HFILL }},
    { &hf_ieee1609dot2_certIssuePermissions,
      { "certIssuePermissions", "ieee1609dot2.certIssuePermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfPsidGroupPermissions", HFILL }},
    { &hf_ieee1609dot2_certRequestPermissions,
      { "certRequestPermissions", "ieee1609dot2.certRequestPermissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfPsidGroupPermissions", HFILL }},
    { &hf_ieee1609dot2_canRequestRollover,
      { "canRequestRollover", "ieee1609dot2.canRequestRollover_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_tbscEncryptionKey,
      { "encryptionKey", "ieee1609dot2.encryptionKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PublicEncryptionKey", HFILL }},
    { &hf_ieee1609dot2_verifyKeyIndicator,
      { "verifyKeyIndicator", "ieee1609dot2.verifyKeyIndicator",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_VerificationKeyIndicator_vals), 0,
        "VerificationKeyIndicator", HFILL }},
    { &hf_ieee1609dot2_flags,
      { "flags", "ieee1609dot2.flags",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_appExtensions,
      { "appExtensions", "ieee1609dot2.appExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfAppExtensions", HFILL }},
    { &hf_ieee1609dot2_certIssueExtensions,
      { "certIssueExtensions", "ieee1609dot2.certIssueExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfCertIssueExtensions", HFILL }},
    { &hf_ieee1609dot2_certRequestExtension,
      { "certRequestExtension", "ieee1609dot2.certRequestExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfCertRequestExtensions", HFILL }},
    { &hf_ieee1609dot2_linkageData,
      { "linkageData", "ieee1609dot2.linkageData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_name,
      { "name", "ieee1609dot2.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "Hostname", HFILL }},
    { &hf_ieee1609dot2_binaryId,
      { "binaryId", "ieee1609dot2.binaryId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_64", HFILL }},
    { &hf_ieee1609dot2_none,
      { "none", "ieee1609dot2.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_iCert,
      { "iCert", "ieee1609dot2.iCert",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IValue", HFILL }},
    { &hf_ieee1609dot2_linkage_value,
      { "linkage-value", "ieee1609dot2.linkage_value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LinkageValue", HFILL }},
    { &hf_ieee1609dot2_group_linkage_value,
      { "group-linkage-value", "ieee1609dot2.group_linkage_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GroupLinkageValue", HFILL }},
    { &hf_ieee1609dot2_subjectPermissions,
      { "subjectPermissions", "ieee1609dot2.subjectPermissions",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_SubjectPermissions_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_minChainLength,
      { "minChainLength", "ieee1609dot2.minChainLength",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ieee1609dot2_chainLengthRange,
      { "chainLengthRange", "ieee1609dot2.chainLengthRange",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ieee1609dot2_eeType,
      { "eeType", "ieee1609dot2.eeType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EndEntityType", HFILL }},
    { &hf_ieee1609dot2_SequenceOfPsidGroupPermissions_item,
      { "PsidGroupPermissions", "ieee1609dot2.PsidGroupPermissions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_explicit,
      { "explicit", "ieee1609dot2.explicit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SequenceOfPsidSspRange", HFILL }},
    { &hf_ieee1609dot2_verificationKey,
      { "verificationKey", "ieee1609dot2.verificationKey",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_PublicVerificationKey_vals), 0,
        "PublicVerificationKey", HFILL }},
    { &hf_ieee1609dot2_reconstructionValue,
      { "reconstructionValue", "ieee1609dot2.reconstructionValue",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_EccP256CurvePoint_vals), 0,
        "EccP256CurvePoint", HFILL }},
    { &hf_ieee1609dot2_SequenceOfAppExtensions_item,
      { "AppExtension", "ieee1609dot2.AppExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_id_02,
      { "id", "ieee1609dot2.id",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_ExtId_vals), 0,
        "ExtId", HFILL }},
    { &hf_ieee1609dot2_content_03,
      { "content", "ieee1609dot2.content_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_SequenceOfCertIssueExtensions_item,
      { "CertIssueExtension", "ieee1609dot2.CertIssueExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_permissions,
      { "permissions", "ieee1609dot2.permissions",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_T_permissions_vals), 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_specific,
      { "specific", "ieee1609dot2.specific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_SequenceOfCertRequestExtensions_item,
      { "CertRequestExtension", "ieee1609dot2.CertRequestExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ieee1609dot2_permissions_01,
      { "permissions", "ieee1609dot2.permissions",
        FT_UINT32, BASE_DEC, VALS(ieee1609dot2_T_permissions_01_vals), 0,
        "T_permissions_01", HFILL }},
    { &hf_ieee1609dot2_content_04,
      { "content", "ieee1609dot2.content_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_content_01", HFILL }},
    { &hf_ieee1609dot2_T_flags_usesCubk,
      { "usesCubk", "ieee1609dot2.T.flags.usesCubk",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ieee1609dot2_EndEntityType_app,
      { "app", "ieee1609dot2.EndEntityType.app",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ieee1609dot2_EndEntityType_enrol,
      { "enrol", "ieee1609dot2.EndEntityType.enrol",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ieee1609dot2_SequenceOfUint8,
    &ett_ieee1609dot2_SequenceOfUint16,
    &ett_ieee1609dot2_SequenceOfHashedId3,
    &ett_ieee1609dot2_ValidityPeriod,
    &ett_ieee1609dot2_Duration,
    &ett_ieee1609dot2_GeographicRegion,
    &ett_ieee1609dot2_CircularRegion,
    &ett_ieee1609dot2_RectangularRegion,
    &ett_ieee1609dot2_SequenceOfRectangularRegion,
    &ett_ieee1609dot2_PolygonalRegion,
    &ett_ieee1609dot2_TwoDLocation,
    &ett_ieee1609dot2_IdentifiedRegion,
    &ett_ieee1609dot2_SequenceOfIdentifiedRegion,
    &ett_ieee1609dot2_CountryAndRegions,
    &ett_ieee1609dot2_CountryAndSubregions,
    &ett_ieee1609dot2_RegionAndSubregions,
    &ett_ieee1609dot2_SequenceOfRegionAndSubregions,
    &ett_ieee1609dot2_ThreeDLocation,
    &ett_ieee1609dot2_Signature,
    &ett_ieee1609dot2_EcdsaP256Signature,
    &ett_ieee1609dot2_EcdsaP384Signature,
    &ett_ieee1609dot2_EcsigP256Signature,
    &ett_ieee1609dot2_EccP256CurvePoint,
    &ett_ieee1609dot2_T_uncompressedP256,
    &ett_ieee1609dot2_EccP384CurvePoint,
    &ett_ieee1609dot2_T_uncompressedP384,
    &ett_ieee1609dot2_EciesP256EncryptedKey,
    &ett_ieee1609dot2_EcencP256EncryptedKey,
    &ett_ieee1609dot2_EncryptionKey,
    &ett_ieee1609dot2_PublicEncryptionKey,
    &ett_ieee1609dot2_BasePublicEncryptionKey,
    &ett_ieee1609dot2_PublicVerificationKey,
    &ett_ieee1609dot2_SymmetricEncryptionKey,
    &ett_ieee1609dot2_PsidSsp,
    &ett_ieee1609dot2_SequenceOfPsidSsp,
    &ett_ieee1609dot2_ServiceSpecificPermissions,
    &ett_ieee1609dot2_PsidSspRange,
    &ett_ieee1609dot2_SequenceOfPsidSspRange,
    &ett_ieee1609dot2_SspRange,
    &ett_ieee1609dot2_BitmapSspRange,
    &ett_ieee1609dot2_SequenceOfOctetString,
    &ett_ieee1609dot2_GroupLinkageValue,
    &ett_ieee1609dot2_SequenceOfLinkageSeed,
    &ett_ieee1609dot2_CrlContents,
    &ett_ieee1609dot2_CrlPriorityInfo,
    &ett_ieee1609dot2_TypeSpecificCrlContents,
    &ett_ieee1609dot2_ToBeSignedHashIdCrl,
    &ett_ieee1609dot2_SequenceOfHashBasedRevocationInfo,
    &ett_ieee1609dot2_HashBasedRevocationInfo,
    &ett_ieee1609dot2_ToBeSignedLinkageValueCrl,
    &ett_ieee1609dot2_SequenceOfJMaxGroup,
    &ett_ieee1609dot2_JMaxGroup,
    &ett_ieee1609dot2_SequenceOfLAGroup,
    &ett_ieee1609dot2_LAGroup,
    &ett_ieee1609dot2_SequenceOfIMaxGroup,
    &ett_ieee1609dot2_IMaxGroup,
    &ett_ieee1609dot2_SequenceOfIndividualRevocation,
    &ett_ieee1609dot2_IndividualRevocation,
    &ett_ieee1609dot2_SequenceOfGroupCrlEntry,
    &ett_ieee1609dot2_GroupCrlEntry,
    &ett_ieee1609dot2_ToBeSignedLinkageValueCrlWithAlgIdentifier,
    &ett_ieee1609dot2_SequenceOfGroupSingleSeedCrlEntry,
    &ett_ieee1609dot2_GroupSingleSeedCrlEntry,
    &ett_ieee1609dot2_SecuredCrl,
    &ett_ieee1609dot2_SecuredCrlContent,
    &ett_ieee1609dot2_CrlSignedData,
    &ett_ieee1609dot2_CrlToBeSignedData,
    &ett_ieee1609dot2_CrlSignedDataPayload,
    &ett_ieee1609dot2_Ieee1609Dot2CrlData,
    &ett_ieee1609dot2_Ieee1609Dot2CrlContent,
    &ett_ieee1609dot2_Ieee1609Dot2Data,
    &ett_ieee1609dot2_Ieee1609Dot2Content,
    &ett_ieee1609dot2_SignedData,
    &ett_ieee1609dot2_ToBeSignedData,
    &ett_ieee1609dot2_SignedDataPayload,
    &ett_ieee1609dot2_HashedData,
    &ett_ieee1609dot2_HeaderInfo,
    &ett_ieee1609dot2_MissingCrlIdentifier,
    &ett_ieee1609dot2_ContributedExtensionBlocks,
    &ett_ieee1609dot2_ContributedExtensionBlock,
    &ett_ieee1609dot2_T_extns,
    &ett_ieee1609dot2_SignerIdentifier,
    &ett_ieee1609dot2_EncryptedData,
    &ett_ieee1609dot2_RecipientInfo,
    &ett_ieee1609dot2_SequenceOfRecipientInfo,
    &ett_ieee1609dot2_SymmRecipientInfo,
    &ett_ieee1609dot2_PKRecipientInfo,
    &ett_ieee1609dot2_EncryptedDataEncryptionKey,
    &ett_ieee1609dot2_SymmetricCiphertext,
    &ett_ieee1609dot2_One28BitCcmCiphertext,
    &ett_ieee1609dot2_SequenceOfCertificate,
    &ett_ieee1609dot2_CertificateBase,
    &ett_ieee1609dot2_IssuerIdentifier,
    &ett_ieee1609dot2_ToBeSignedCertificate,
    &ett_ieee1609dot2_T_flags,
    &ett_ieee1609dot2_CertificateId,
    &ett_ieee1609dot2_LinkageData,
    &ett_ieee1609dot2_EndEntityType,
    &ett_ieee1609dot2_PsidGroupPermissions,
    &ett_ieee1609dot2_SequenceOfPsidGroupPermissions,
    &ett_ieee1609dot2_SubjectPermissions,
    &ett_ieee1609dot2_VerificationKeyIndicator,
    &ett_ieee1609dot2_SequenceOfAppExtensions,
    &ett_ieee1609dot2_AppExtension,
    &ett_ieee1609dot2_SequenceOfCertIssueExtensions,
    &ett_ieee1609dot2_CertIssueExtension,
    &ett_ieee1609dot2_T_permissions,
    &ett_ieee1609dot2_SequenceOfCertRequestExtensions,
    &ett_ieee1609dot2_CertRequestExtension,
    &ett_ieee1609dot2_T_permissions_01,
        &ett_ieee1609dot2_ssp,
  };

  /* Register protocol */
  proto_ieee1609dot2 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ieee1609dot2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  proto_ieee1609dot2_handle = register_dissector("ieee1609dot2.data", dissect_Ieee1609Dot2Data_PDU, proto_ieee1609dot2);

  // See TS17419_ITS-AID_AssignedNumbers
  unsecured_data_subdissector_table = register_dissector_table("ieee1609dot2.psid",
        "ATS-AID/PSID based dissector for unsecured/signed data", proto_ieee1609dot2, FT_UINT32, BASE_HEX);
  ssp_subdissector_table = register_dissector_table("ieee1609dot2.ssp",
        "ATS-AID/PSID based dissector for Service Specific Permissions (SSP)", proto_ieee1609dot2, FT_UINT32, BASE_HEX);
}


void proto_reg_handoff_ieee1609dot2(void) {
    dissector_add_string("media_type", "application/x-its", proto_ieee1609dot2_handle);
    dissector_add_string("media_type", "application/x-its-request", proto_ieee1609dot2_handle);
    dissector_add_string("media_type", "application/x-its-response", proto_ieee1609dot2_handle);

    dissector_add_uint("ieee1609dot2.psid", psid_certificate_revocation_list_application, create_dissector_handle(dissect_SecuredCrl_PDU, proto_ieee1609dot2));
    //dissector_add_uint_range_with_preference("udp.port", "56000,56001", proto_ieee1609dot2_handle);

}
