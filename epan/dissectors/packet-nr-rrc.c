/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nr-rrc.c                                                            */
/* asn2wrs.py -L -p nr-rrc -c ./nr-rrc.cnf -s ./packet-nr-rrc-template -D . -O ../.. NR-InterNodeDefinitions.asn NR-RRC-Definitions.asn */

/* Input file: packet-nr-rrc-template.c */

#line 1 "./asn1/nr-rrc/packet-nr-rrc-template.c"
/* packet-nr-rrc-template.c
 * NR;
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 38.331 V15.0.0 Release 15) packet dissection
 * Copyright 2018, Pascal Quantin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/asn1.h>

#include <wsutil/str_util.h>

#include "packet-per.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"

#define PNAME  "NR Radio Resource Control (RRC) protocol"
#define PSNAME "NR RRC"
#define PFNAME "nr-rrc"

void proto_register_nr_rrc(void);
void proto_reg_handoff_nr_rrc(void);

/* Include constants */

/*--- Included file: packet-nr-rrc-val.h ---*/
#line 1 "./asn1/nr-rrc/packet-nr-rrc-val.h"
#define maxCellPrep                    1
#define maxCellSCG                     1
#define maxRS_IndexReport              1
#define maxBandComb                    1
#define maxBasebandProcComb            1
#define maxNrofSCells                  15
#define maxNrofCellMeas                1
#define maxNroSS_BlocksToAverage       2
#define maxNroCSI_RS_ResourcesToAverage 2
#define maxNrofSR_CongigPerCellGroup   8
#define maxLCG_ID                      7
#define macLC_ID                       64
#define maxNrofTAGs                    4
#define maxNrofTAGs_1                  3
#define maxNrofBandwidthParts          4
#define maxNrofBandwidthParts_1        3
#define maxSymbolIndex                 13
#define maxNrofPhysicalResourceBlocks  275
#define maxNrofPhysicalResourceBlocks_1 274
#define maxNrofPhysicalResourceBlocksTimes4 1100
#define maxNrofControlResourceSets     2
#define maxNrofControlResourceSets_1   1
#define maxCoReSetStartSymbol          0
#define maxCoReSetDuration             3
#define maxNrofSearchSpacesPerCoReSet  0
#define maxNrofRateMatchPatterns       1
#define maxNrofRateMatchPatterns_1     0
#define maxNrofCSI_Reports             1
#define maxNrofCSI_Reports_1           0
#define maxNrofCSI_ResourceConfigurations 1
#define maxNrofCSI_ResourceConfigurations_1 0
#define maxNrofCSI_ResourceSets        1
#define maxNrofCSI_ResourceSets_1      0
#define maxNrofNZP_CSI_RS_Resources    1
#define maxNrofNZP_CSI_RS_Resources_1  0
#define maxNrofZP_CSI_RS_Resources     1
#define maxNrofZP_CSI_RS_Resources_1   0
#define maxNrofCSI_IM_Resources        1
#define maxNrofCSI_IM_Resources_1      0
#define maxNrofSSB_Resources           64
#define maxNrofSSB_Resources_1         63
#define maxNrofCSI_RS_ResourcesPerSet  8
#define maxNrofCSI_MeasId              1
#define maxNrofCSI_MeasId_1            0
#define maxNrofCSI_RS_ResourcesRRM     1
#define maxNrofCSI_RS_ResourcesRRM_1   0
#define maxNrofObjectId                1
#define maxNrOfRA_PreamblesPerSSB      1
#define maxNrofReportConfigId          1
#define maxNrofMeasId                  1
#define maxNroQuantityConfig           2
#define maxNrofSRS_ResourceSets        1
#define maxNrofSRS_ResourceSets_1      0
#define maxNrofSRS_Resources           1
#define maxNrofSRS_Resources_1         0
#define maxRA_PreambleIndex            0
#define maxRAT_CapabilityContainers    3
#define maxServCell                    1
#define maxSimultaneousBands           1
#define maxBands                       256
#define maxCellReport                  8
#define maxDRB                         29
#define maxFreq                        1
#define maxLCid                        32
#define maxLCH                         8
#define maxQFI                         0
#define maxNrofAggregatedCellsPerCellGroup 1
#define maxNrofCSI_ReportConfig_1      0
#define maxNrofPCIsPerSMTC             1
#define maxNrofQFIs                    1
#define maxNrofSchedulingRequestResoruces 64
#define maxNrofSearchSpaces            1
#define maxNrofSlotFormatCombinations  1
#define maxNrofSlotFormatCombinations_1 1
#define maxNrofSR_ConfigPerCellGroup   1
#define maxNrofSRS_ResourcesPerSet     1
#define maxNroCSI_RS                   1
#define maxNroIndexesToReport          1
#define maxNroSSBs                     8
#define maxQuantityConfigId            1
#define maxRAcsirsResources            1
#define maxRAssbResources              1
#define maxReportConfigId              1
#define maxSCellGroups                 1

/*--- End of included file: packet-nr-rrc-val.h ---*/
#line 36 "./asn1/nr-rrc/packet-nr-rrc-template.c"

/* Initialize the protocol and registered fields */
static int proto_nr_rrc = -1;

/*--- Included file: packet-nr-rrc-hf.c ---*/
#line 1 "./asn1/nr-rrc/packet-nr-rrc-hf.c"
static int hf_nr_rrc_nr_rrc_SCG_ConfigInfo_PDU = -1;  /* SCG_ConfigInfo */
static int hf_nr_rrc_BCCH_BCH_Message_PDU = -1;   /* BCCH_BCH_Message */
static int hf_nr_rrc_DL_DCCH_Message_PDU = -1;    /* DL_DCCH_Message */
static int hf_nr_rrc_nr_rrc_UL_DCCH_Message_PDU = -1;  /* UL_DCCH_Message */
static int hf_nr_rrc_nr_rrc_MIB_PDU = -1;         /* MIB */
static int hf_nr_rrc_nr_rrc_RRCReconfiguration_PDU = -1;  /* RRCReconfiguration */
static int hf_nr_rrc_nr_rrc_RRCReconfigurationComplete_PDU = -1;  /* RRCReconfigurationComplete */
static int hf_nr_rrc_nr_rrc_CellGroupConfig_PDU = -1;  /* CellGroupConfig */
static int hf_nr_rrc_nr_rrc_MeasResults_PDU = -1;  /* MeasResults */
static int hf_nr_rrc_nr_rrc_RadioBearerConfig_PDU = -1;  /* RadioBearerConfig */
static int hf_nr_rrc_nr_rrc_UE_MRDC_Capability_PDU = -1;  /* UE_MRDC_Capability */
static int hf_nr_rrc_nr_rrc_UE_NR_Capability_PDU = -1;  /* UE_NR_Capability */
static int hf_nr_rrc_UECapabilityInformation_PDU = -1;  /* UECapabilityInformation */
static int hf_nr_rrc_RadioBearerConfiguration_PDU = -1;  /* RadioBearerConfiguration */
static int hf_nr_rrc_criticalExtensions = -1;     /* T_criticalExtensions */
static int hf_nr_rrc_c1 = -1;                     /* T_c1 */
static int hf_nr_rrc_scg_ConfigInfo_r15 = -1;     /* SCG_ConfigInfo_r15_IEs */
static int hf_nr_rrc_spare3 = -1;                 /* NULL */
static int hf_nr_rrc_spare2 = -1;                 /* NULL */
static int hf_nr_rrc_spare1 = -1;                 /* NULL */
static int hf_nr_rrc_criticalExtensionsFuture = -1;  /* T_criticalExtensionsFuture */
static int hf_nr_rrc_eutra_CapabilityInfo = -1;   /* T_eutra_CapabilityInfo */
static int hf_nr_rrc_candidateCellInfoList = -1;  /* CandidateCellInfoList */
static int hf_nr_rrc_measResultSSTD = -1;         /* MeasResultSSTD */
static int hf_nr_rrc_configRestrictInfo = -1;     /* ConfigRestrictInfoSCG */
static int hf_nr_rrc_drx_InfoMCG = -1;            /* DRX_Info */
static int hf_nr_rrc_sourceConfigSCG = -1;        /* T_sourceConfigSCG */
static int hf_nr_rrc_p_maxFR1 = -1;               /* P_Max */
static int hf_nr_rrc_mcg_RB_Config = -1;          /* T_mcg_RB_Config */
static int hf_nr_rrc_nonCriticalExtension = -1;   /* T_nonCriticalExtension */
static int hf_nr_rrc_restrictedBandCombinationNR = -1;  /* INTEGER */
static int hf_nr_rrc_restrictedBasebandCombinationNR_NR = -1;  /* T_restrictedBasebandCombinationNR_NR */
static int hf_nr_rrc_restrictedBasebandCombinationNR_NR_item = -1;  /* INTEGER */
static int hf_nr_rrc_maxMeasFreqsSCG_NR = -1;     /* INTEGER */
static int hf_nr_rrc_cycle = -1;                  /* INTEGER */
static int hf_nr_rrc_offset = -1;                 /* INTEGER */
static int hf_nr_rrc_CandidateCellInfoList_item = -1;  /* CandidateCellInfo */
static int hf_nr_rrc_cellIdentification = -1;     /* T_cellIdentification */
static int hf_nr_rrc_physCellId = -1;             /* PhysCellId */
static int hf_nr_rrc_dl_CarrierFreq = -1;         /* ARFCN_ValueNR */
static int hf_nr_rrc_measResultCell = -1;         /* T_measResultCell */
static int hf_nr_rrc_rsrpResultCell = -1;         /* RSRP_Range */
static int hf_nr_rrc_rsrqResultCell = -1;         /* RSRQ_Range */
static int hf_nr_rrc_candidateRS_IndexList = -1;  /* CandidateRS_IndexInfoList */
static int hf_nr_rrc_CandidateRS_IndexInfoList_item = -1;  /* CandidateRS_IndexInfo */
static int hf_nr_rrc_ssb_Index = -1;              /* SSB_Index */
static int hf_nr_rrc_measResultSSB = -1;          /* T_measResultSSB */
static int hf_nr_rrc_message = -1;                /* BCCH_BCH_MessageType */
static int hf_nr_rrc_mib = -1;                    /* MIB */
static int hf_nr_rrc_messageClassExtension = -1;  /* T_messageClassExtension */
static int hf_nr_rrc_message_01 = -1;             /* DL_DCCH_MessageType */
static int hf_nr_rrc_c1_01 = -1;                  /* T_c1_01 */
static int hf_nr_rrc_rrcReconfiguration = -1;     /* RRCReconfiguration */
static int hf_nr_rrc_spare15 = -1;                /* NULL */
static int hf_nr_rrc_spare14 = -1;                /* NULL */
static int hf_nr_rrc_spare13 = -1;                /* NULL */
static int hf_nr_rrc_spare12 = -1;                /* NULL */
static int hf_nr_rrc_spare11 = -1;                /* NULL */
static int hf_nr_rrc_spare10 = -1;                /* NULL */
static int hf_nr_rrc_spare9 = -1;                 /* NULL */
static int hf_nr_rrc_spare8 = -1;                 /* NULL */
static int hf_nr_rrc_spare7 = -1;                 /* NULL */
static int hf_nr_rrc_spare6 = -1;                 /* NULL */
static int hf_nr_rrc_spare5 = -1;                 /* NULL */
static int hf_nr_rrc_spare4 = -1;                 /* NULL */
static int hf_nr_rrc_messageClassExtension_01 = -1;  /* T_messageClassExtension_01 */
static int hf_nr_rrc_message_02 = -1;             /* UL_DCCH_MessageType */
static int hf_nr_rrc_c1_02 = -1;                  /* T_c1_02 */
static int hf_nr_rrc_measurementReport = -1;      /* MeasurementReport */
static int hf_nr_rrc_rrcReconfigurationComplete = -1;  /* RRCReconfigurationComplete */
static int hf_nr_rrc_messageClassExtension_02 = -1;  /* T_messageClassExtension_02 */
static int hf_nr_rrc_ssb_IndexExplicit = -1;      /* INTEGER_1_7 */
static int hf_nr_rrc_halfFrameIndex = -1;         /* T_halfFrameIndex */
static int hf_nr_rrc_systemFrameNumber = -1;      /* BIT_STRING_SIZE_10 */
static int hf_nr_rrc_subCarrierSpacingCommon = -1;  /* SubcarrierSpacing */
static int hf_nr_rrc_ssb_subcarrierOffset = -1;   /* INTEGER_0_11 */
static int hf_nr_rrc_dmrs_TypeA_Position = -1;    /* T_dmrs_TypeA_Position */
static int hf_nr_rrc_pdcchConfigSIB1 = -1;        /* INTEGER_0_255 */
static int hf_nr_rrc_cellBarred = -1;             /* T_cellBarred */
static int hf_nr_rrc_intraFreqReselection = -1;   /* T_intraFreqReselection */
static int hf_nr_rrc_spare = -1;                  /* BIT_STRING_SIZE_0 */
static int hf_nr_rrc_criticalExtensions_01 = -1;  /* T_criticalExtensions_01 */
static int hf_nr_rrc_measurementReport_01 = -1;   /* MeasurementReport_IEs */
static int hf_nr_rrc_criticalExtensionsFuture_01 = -1;  /* T_criticalExtensionsFuture_01 */
static int hf_nr_rrc_measResults = -1;            /* MeasResults */
static int hf_nr_rrc_rrc_TransactionIdentifier = -1;  /* RRC_TransactionIdentifier */
static int hf_nr_rrc_criticalExtensions_02 = -1;  /* T_criticalExtensions_02 */
static int hf_nr_rrc_rrcReconfiguration_01 = -1;  /* RRCReconfiguration_IEs */
static int hf_nr_rrc_criticalExtensionsFuture_02 = -1;  /* T_criticalExtensionsFuture_02 */
static int hf_nr_rrc_radioBearerConfig = -1;      /* RadioBearerConfig */
static int hf_nr_rrc_masterCellGroupConfig = -1;  /* CellGroupConfig */
static int hf_nr_rrc_secondaryCellGroupToAddModList = -1;  /* SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig */
static int hf_nr_rrc_secondaryCellGroupToAddModList_item = -1;  /* CellGroupConfig */
static int hf_nr_rrc_secondaryCellGroupToReleaseList = -1;  /* SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId */
static int hf_nr_rrc_secondaryCellGroupToReleaseList_item = -1;  /* CellGroupId */
static int hf_nr_rrc_measConfig = -1;             /* MeasConfig */
static int hf_nr_rrc_lateNonCriticalExtension = -1;  /* OCTET_STRING */
static int hf_nr_rrc_nonCriticalExtension_01 = -1;  /* T_nonCriticalExtension_01 */
static int hf_nr_rrc_criticalExtensions_03 = -1;  /* T_criticalExtensions_03 */
static int hf_nr_rrc_rrcReconfigurationComplete_01 = -1;  /* RRCReconfigurationComplete_IEs */
static int hf_nr_rrc_criticalExtensionsFuture_03 = -1;  /* T_criticalExtensionsFuture_03 */
static int hf_nr_rrc_bandwidthPartId = -1;        /* BandwidthPartId */
static int hf_nr_rrc_location = -1;               /* INTEGER_0_maxNrofPhysicalResourceBlocksTimes4 */
static int hf_nr_rrc_bandwidth = -1;              /* INTEGER_1_maxNrofPhysicalResourceBlocks */
static int hf_nr_rrc_subcarrierSpacing = -1;      /* T_subcarrierSpacing */
static int hf_nr_rrc_cyclicPrefix = -1;           /* T_cyclicPrefix */
static int hf_nr_rrc_directCurrentLocation = -1;  /* INTEGER_0_3299 */
static int hf_nr_rrc_cellGroupId = -1;            /* CellGroupId */
static int hf_nr_rrc_rlc_BearerToAddModList = -1;  /* SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config */
static int hf_nr_rrc_rlc_BearerToAddModList_item = -1;  /* LCH_Config */
static int hf_nr_rrc_rlc_BearerToReleaseList = -1;  /* SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity */
static int hf_nr_rrc_rlc_BearerToReleaseList_item = -1;  /* LogicalChannelIdentity */
static int hf_nr_rrc_mac_CellGroupConfig = -1;    /* MAC_CellGroupConfig */
static int hf_nr_rrc_rlf_TimersAndConstants = -1;  /* RLF_TimersAndConstants */
static int hf_nr_rrc_physical_CellGroupConfig = -1;  /* PhysicalCellGroupConfig */
static int hf_nr_rrc_spCellConfig = -1;           /* SpCellConfig */
static int hf_nr_rrc_sCellToAddModList = -1;      /* SCellToAddModList */
static int hf_nr_rrc_sCellToReleaseList = -1;     /* SCellToReleaseList */
static int hf_nr_rrc_logicalChannelIdentity = -1;  /* LogicalChannelIdentity */
static int hf_nr_rrc_servedRadioBearer = -1;      /* INTEGER_1_32 */
static int hf_nr_rrc_reestablishRLC = -1;         /* T_reestablishRLC */
static int hf_nr_rrc_rlc_Config = -1;             /* RLC_Config */
static int hf_nr_rrc_mac_LogicalChannelConfig = -1;  /* LogicalChannelConfig */
static int hf_nr_rrc_harq_ACK_Spatial_Bundling = -1;  /* T_harq_ACK_Spatial_Bundling */
static int hf_nr_rrc_reconfigurationWithSync = -1;  /* T_reconfigurationWithSync */
static int hf_nr_rrc_spCellConfigCommon = -1;     /* ServingCellConfigCommon */
static int hf_nr_rrc_newUE_Identity = -1;         /* C_RNTI */
static int hf_nr_rrc_t304 = -1;                   /* T_t304 */
static int hf_nr_rrc_rach_ConfigDedicated = -1;   /* RACH_ConfigDedicated */
static int hf_nr_rrc_spCellConfigDedicated = -1;  /* ServingCellConfigDedicated */
static int hf_nr_rrc_SCellToReleaseList_item = -1;  /* SCellIndex */
static int hf_nr_rrc_SCellToAddModList_item = -1;  /* SCellConfig */
static int hf_nr_rrc_sCellIndex = -1;             /* SCellIndex */
static int hf_nr_rrc_sCellConfigCommon = -1;      /* ServingCellConfigCommon */
static int hf_nr_rrc_sCellConfigDedicated = -1;   /* ServingCellConfigDedicated */
static int hf_nr_rrc_CellIndexList_item = -1;     /* CellIndex */
static int hf_nr_rrc_schedulingCellInfo = -1;     /* T_schedulingCellInfo */
static int hf_nr_rrc_own = -1;                    /* T_own */
static int hf_nr_rrc_cif_Presence = -1;           /* BOOLEAN */
static int hf_nr_rrc_other = -1;                  /* T_other */
static int hf_nr_rrc_schedulingCellId = -1;       /* ServCellIndex */
static int hf_nr_rrc_pdsch_Start = -1;            /* INTEGER_1_4 */
static int hf_nr_rrc_cif_InSchedulingCell = -1;   /* INTEGER_1_7 */
static int hf_nr_rrc_csi_ResourceConfigs = -1;    /* SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig */
static int hf_nr_rrc_csi_ResourceConfigs_item = -1;  /* CSI_ResourceConfig */
static int hf_nr_rrc_csi_ReportConfigs = -1;      /* SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig */
static int hf_nr_rrc_csi_ReportConfigs_item = -1;  /* CSI_ReportConfig */
static int hf_nr_rrc_csi_MeasIdToAddModList = -1;  /* SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod */
static int hf_nr_rrc_csi_MeasIdToAddModList_item = -1;  /* CSI_MeasIdToAddMod */
static int hf_nr_rrc_reportTrigger = -1;          /* T_reportTrigger */
static int hf_nr_rrc_reportTriggerSize = -1;      /* INTEGER_0_6 */
static int hf_nr_rrc_csi_ResourceConfigId = -1;   /* CSI_ResourceConfigId */
static int hf_nr_rrc_csi_ResourceSets = -1;       /* SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet */
static int hf_nr_rrc_csi_ResourceSets_item = -1;  /* CSI_ResourceSet */
static int hf_nr_rrc_ssb_Resources = -1;          /* SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource */
static int hf_nr_rrc_ssb_Resources_item = -1;     /* CSI_SSB_Resource */
static int hf_nr_rrc_resourceType = -1;           /* T_resourceType */
static int hf_nr_rrc_aperiodic = -1;              /* NULL */
static int hf_nr_rrc_semiPersistent = -1;         /* NULL */
static int hf_nr_rrc_periodic = -1;               /* NULL */
static int hf_nr_rrc_csi_ResourceSetId = -1;      /* CSI_ResourceSetId */
static int hf_nr_rrc_csi_rs_Resources = -1;       /* SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource */
static int hf_nr_rrc_csi_rs_Resources_item = -1;  /* NZP_CSI_RS_Resource */
static int hf_nr_rrc_repetition = -1;             /* BOOLEAN */
static int hf_nr_rrc_nzp_csi_rs_ResourceId = -1;  /* NZP_CSI_RS_ResourceId */
static int hf_nr_rrc_nrofPorts = -1;              /* T_nrofPorts */
static int hf_nr_rrc_resourceMapping = -1;        /* NULL */
static int hf_nr_rrc_cdm_Value = -1;              /* T_cdm_Value */
static int hf_nr_rrc_cdm_Pattern = -1;            /* T_cdm_Pattern */
static int hf_nr_rrc_csi_RS_Density = -1;         /* T_csi_RS_Density */
static int hf_nr_rrc_csi_RS_FreqBand = -1;        /* NULL */
static int hf_nr_rrc_powerControlOffset = -1;     /* NULL */
static int hf_nr_rrc_powerControlOffsetSS = -1;   /* NULL */
static int hf_nr_rrc_scramblingID = -1;           /* INTEGER_0 */
static int hf_nr_rrc_csi_RS_timeConfig = -1;      /* T_csi_RS_timeConfig */
static int hf_nr_rrc_sl5 = -1;                    /* INTEGER_0_4 */
static int hf_nr_rrc_sl10 = -1;                   /* INTEGER_0_9 */
static int hf_nr_rrc_sl20 = -1;                   /* INTEGER_0_19 */
static int hf_nr_rrc_sl40 = -1;                   /* INTEGER_0_39 */
static int hf_nr_rrc_sl80 = -1;                   /* INTEGER_0_79 */
static int hf_nr_rrc_sl160 = -1;                  /* INTEGER_0_159 */
static int hf_nr_rrc_sl320 = -1;                  /* INTEGER_0_319 */
static int hf_nr_rrc_sl640 = -1;                  /* INTEGER_0_639 */
static int hf_nr_rrc_reportConfigId = -1;         /* CSI_ReportConfigId */
static int hf_nr_rrc_reportConfigType = -1;       /* T_reportConfigType */
static int hf_nr_rrc_periodic_01 = -1;            /* T_periodic */
static int hf_nr_rrc_reportSlotConfig = -1;       /* T_reportSlotConfig */
static int hf_nr_rrc_pucch_CSI_ResourceIndex = -1;  /* NULL */
static int hf_nr_rrc_semiPersistent_01 = -1;      /* T_semiPersistent */
static int hf_nr_rrc_reportSlotConfig_01 = -1;    /* T_reportSlotConfig_01 */
static int hf_nr_rrc_aperiodic_01 = -1;           /* T_aperiodic */
static int hf_nr_rrc_aperiodicReportSlotOffset = -1;  /* NULL */
static int hf_nr_rrc_reportQuantity = -1;         /* T_reportQuantity */
static int hf_nr_rrc_cRI_RI_PMI_CQI = -1;         /* NULL */
static int hf_nr_rrc_cRI_RI_i1 = -1;              /* NULL */
static int hf_nr_rrc_cRI_RI_i1_CQI = -1;          /* T_cRI_RI_i1_CQI */
static int hf_nr_rrc_pdsch_BundleSizeForCSI = -1;  /* T_pdsch_BundleSizeForCSI */
static int hf_nr_rrc_cRI_RI_CQI = -1;             /* NULL */
static int hf_nr_rrc_cRI = -1;                    /* NULL */
static int hf_nr_rrc_cRI_RSRP = -1;               /* NULL */
static int hf_nr_rrc_spare0 = -1;                 /* NULL */
static int hf_nr_rrc_reportFreqConfiguration = -1;  /* T_reportFreqConfiguration */
static int hf_nr_rrc_cqi_FormatIndicator = -1;    /* T_cqi_FormatIndicator */
static int hf_nr_rrc_pmi_FormatIndicator = -1;    /* T_pmi_FormatIndicator */
static int hf_nr_rrc_csi_ReportingBand = -1;      /* T_csi_ReportingBand */
static int hf_nr_rrc_measRestrictionTimeForChannel = -1;  /* NULL */
static int hf_nr_rrc_measRestrictionTimeForInterference = -1;  /* NULL */
static int hf_nr_rrc_codebookConfig = -1;         /* CodebookConfig */
static int hf_nr_rrc_nrofCQIsPerReport = -1;      /* T_nrofCQIsPerReport */
static int hf_nr_rrc_groupBasedBeamReporting = -1;  /* T_groupBasedBeamReporting */
static int hf_nr_rrc_enabled = -1;                /* T_enabled */
static int hf_nr_rrc_nrofBeamsToReport = -1;      /* INTEGER_2_4 */
static int hf_nr_rrc_disabled = -1;               /* T_disabled */
static int hf_nr_rrc_nrofReportedRS = -1;         /* T_nrofReportedRS */
static int hf_nr_rrc_cqi_Table = -1;              /* T_cqi_Table */
static int hf_nr_rrc_subbandSize = -1;            /* T_subbandSize */
static int hf_nr_rrc_bler_Target = -1;            /* T_bler_Target */
static int hf_nr_rrc_codebookConfig_N1 = -1;      /* T_codebookConfig_N1 */
static int hf_nr_rrc_codebookConfig_N2 = -1;      /* T_codebookConfig_N2 */
static int hf_nr_rrc_codebookType = -1;           /* T_codebookType */
static int hf_nr_rrc_type1 = -1;                  /* T_type1 */
static int hf_nr_rrc_subType = -1;                /* T_subType */
static int hf_nr_rrc_codebookMode = -1;           /* T_codebookMode */
static int hf_nr_rrc_numberOfPanels = -1;         /* T_numberOfPanels */
static int hf_nr_rrc_codebookSubsetRestrictionType1 = -1;  /* T_codebookSubsetRestrictionType1 */
static int hf_nr_rrc_singlePanel = -1;            /* T_singlePanel */
static int hf_nr_rrc_singlePanel2TX = -1;         /* BIT_STRING_SIZE_6 */
static int hf_nr_rrc_multiPanel = -1;             /* T_multiPanel */
static int hf_nr_rrc_singlePanelCodebookSubsetRestriction_i2 = -1;  /* BIT_STRING_SIZE_16 */
static int hf_nr_rrc_ri_Restriction = -1;         /* T_ri_Restriction */
static int hf_nr_rrc_typeI_SinglePanelRI_Restriction = -1;  /* BIT_STRING_SIZE_8 */
static int hf_nr_rrc_typeI_MultiPanelRI_Restriction = -1;  /* BIT_STRING_SIZE_4 */
static int hf_nr_rrc_type2 = -1;                  /* T_type2 */
static int hf_nr_rrc_subType_01 = -1;             /* T_subType_01 */
static int hf_nr_rrc_phaseAlphabetSize = -1;      /* T_phaseAlphabetSize */
static int hf_nr_rrc_subbandAmplitude = -1;       /* BOOLEAN */
static int hf_nr_rrc_numberOfBeams = -1;          /* T_numberOfBeams */
static int hf_nr_rrc_portSelectionSamplingSize = -1;  /* T_portSelectionSamplingSize */
static int hf_nr_rrc_codebookSubsetRestrictionType2 = -1;  /* T_codebookSubsetRestrictionType2 */
static int hf_nr_rrc_ri_Restriction_01 = -1;      /* T_ri_Restriction_01 */
static int hf_nr_rrc_typeII_RI_Restriction = -1;  /* BIT_STRING_SIZE_2 */
static int hf_nr_rrc_typeII_PortSelectionRI_Restriction = -1;  /* BIT_STRING_SIZE_2 */
static int hf_nr_rrc_csi_measId = -1;             /* CSI_MeasId */
static int hf_nr_rrc_csi_RS_resourceConfigId = -1;  /* CSI_RS_ConfigurationId */
static int hf_nr_rrc_csi_reportConfigId = -1;     /* CSI_ReportConfigId */
static int hf_nr_rrc_measQuantity = -1;           /* T_measQuantity */
static int hf_nr_rrc_carrierFreqUL = -1;          /* ARFCN_ValueNR */
static int hf_nr_rrc_carrierBandwidthUL = -1;     /* CarrierBandwidthNR */
static int hf_nr_rrc_additionalSpectrumEmission = -1;  /* AdditionalSpectrumEmission */
static int hf_nr_rrc_p_Max = -1;                  /* P_Max */
static int hf_nr_rrc_frequencyShift7p5khz = -1;   /* T_frequencyShift7p5khz */
static int hf_nr_rrc_initialUplinkBandwidthPart = -1;  /* BandwidthPart */
static int hf_nr_rrc_ul_SpecificParameters = -1;  /* T_ul_SpecificParameters */
static int hf_nr_rrc_priority = -1;               /* INTEGER_1_16 */
static int hf_nr_rrc_prioritisedBitRate = -1;     /* T_prioritisedBitRate */
static int hf_nr_rrc_bucketSizeDuration = -1;     /* T_bucketSizeDuration */
static int hf_nr_rrc_allowedSubCarrierSpacing = -1;  /* SubcarrierSpacing */
static int hf_nr_rrc_allowedTiming = -1;          /* NULL */
static int hf_nr_rrc_logicalChannelGroup = -1;    /* INTEGER_0_maxLCid */
static int hf_nr_rrc_logicalChannelSR_Mask = -1;  /* BOOLEAN */
static int hf_nr_rrc_logicalChannelSR_DelayTimerApplied = -1;  /* BOOLEAN */
static int hf_nr_rrc_drx_Config = -1;             /* DRX_Config */
static int hf_nr_rrc_schedulingRequestConfig = -1;  /* SchedulingRequestConfig */
static int hf_nr_rrc_bsr_Config = -1;             /* BSR_Configuration */
static int hf_nr_rrc_tag_Config = -1;             /* TAG_Configuration */
static int hf_nr_rrc_phr_Config = -1;             /* PHR_Config */
static int hf_nr_rrc_sCellDeactivationTimer = -1;  /* T_sCellDeactivationTimer */
static int hf_nr_rrc_skipUplinkTxDynamic = -1;    /* BOOLEAN */
static int hf_nr_rrc_release = -1;                /* NULL */
static int hf_nr_rrc_setup = -1;                  /* T_setup */
static int hf_nr_rrc_drx_onDurationTimer = -1;    /* T_drx_onDurationTimer */
static int hf_nr_rrc_drx_InactivityTimer = -1;    /* T_drx_InactivityTimer */
static int hf_nr_rrc_drx_HARQ_RTT_TimerDL = -1;   /* INTEGER_0_56 */
static int hf_nr_rrc_drx_HARQ_RTT_TimerUL = -1;   /* INTEGER_0_56 */
static int hf_nr_rrc_drx_RetransmissionTimerDL = -1;  /* T_drx_RetransmissionTimerDL */
static int hf_nr_rrc_drx_RetransmissionTimerUL = -1;  /* T_drx_RetransmissionTimerUL */
static int hf_nr_rrc_drx_LongCycleStartOffset = -1;  /* T_drx_LongCycleStartOffset */
static int hf_nr_rrc_ms10 = -1;                   /* INTEGER_0_9 */
static int hf_nr_rrc_ms20 = -1;                   /* INTEGER_0_19 */
static int hf_nr_rrc_ms32 = -1;                   /* INTEGER_0_31 */
static int hf_nr_rrc_ms40 = -1;                   /* INTEGER_0_39 */
static int hf_nr_rrc_ms60 = -1;                   /* INTEGER_0_59 */
static int hf_nr_rrc_ms64 = -1;                   /* INTEGER_0_63 */
static int hf_nr_rrc_ms70 = -1;                   /* INTEGER_0_69 */
static int hf_nr_rrc_ms80 = -1;                   /* INTEGER_0_79 */
static int hf_nr_rrc_ms128 = -1;                  /* INTEGER_0_127 */
static int hf_nr_rrc_ms160 = -1;                  /* INTEGER_0_159 */
static int hf_nr_rrc_ms256 = -1;                  /* INTEGER_0_255 */
static int hf_nr_rrc_ms320 = -1;                  /* INTEGER_0_319 */
static int hf_nr_rrc_ms512 = -1;                  /* INTEGER_0_511 */
static int hf_nr_rrc_ms640 = -1;                  /* INTEGER_0_639 */
static int hf_nr_rrc_ms1024 = -1;                 /* INTEGER_0_1023 */
static int hf_nr_rrc_ms1280 = -1;                 /* INTEGER_0_1279 */
static int hf_nr_rrc_ms2048 = -1;                 /* INTEGER_0_2047 */
static int hf_nr_rrc_ms2560 = -1;                 /* INTEGER_0_2559 */
static int hf_nr_rrc_ms5120 = -1;                 /* INTEGER_0_5119 */
static int hf_nr_rrc_ms10240 = -1;                /* INTEGER_0_10239 */
static int hf_nr_rrc_shortDRX = -1;               /* T_shortDRX */
static int hf_nr_rrc_drx_ShortCycle = -1;         /* T_drx_ShortCycle */
static int hf_nr_rrc_drx_ShortCycleTimer = -1;    /* INTEGER_1_16 */
static int hf_nr_rrc_drx_SlotOffset = -1;         /* T_drx_SlotOffset */
static int hf_nr_rrc_setup_01 = -1;               /* T_setup_01 */
static int hf_nr_rrc_phr_PeriodicTimer = -1;      /* T_phr_PeriodicTimer */
static int hf_nr_rrc_phr_ProhibitTimer = -1;      /* T_phr_ProhibitTimer */
static int hf_nr_rrc_phr_Tx_PowerFactorChange = -1;  /* T_phr_Tx_PowerFactorChange */
static int hf_nr_rrc_multiplePHR = -1;            /* BOOLEAN */
static int hf_nr_rrc_phr_Type2PCell = -1;         /* BOOLEAN */
static int hf_nr_rrc_phr_Type2OtherCell = -1;     /* BOOLEAN */
static int hf_nr_rrc_phr_ModeOtherCG = -1;        /* T_phr_ModeOtherCG */
static int hf_nr_rrc_tag_ToReleaseList = -1;      /* TAG_ToReleaseList */
static int hf_nr_rrc_tag_ToAddModList = -1;       /* TAG_ToAddModList */
static int hf_nr_rrc_TAG_ToReleaseList_item = -1;  /* TAG_Id */
static int hf_nr_rrc_TAG_ToAddModList_item = -1;  /* TAG_ToAddMod */
static int hf_nr_rrc_tag_Id = -1;                 /* TAG_Id */
static int hf_nr_rrc_timeAlignmentTimer = -1;     /* TimeAlignmentTimer */
static int hf_nr_rrc_periodicBSR_Timer = -1;      /* T_periodicBSR_Timer */
static int hf_nr_rrc_retxBSR_Timer = -1;          /* T_retxBSR_Timer */
static int hf_nr_rrc_logicaChannelSR_DelayTimer = -1;  /* T_logicaChannelSR_DelayTimer */
static int hf_nr_rrc_measObjectToRemoveList = -1;  /* MeasObjectToRemoveList */
static int hf_nr_rrc_measObjectToAddModList = -1;  /* MeasObjectToAddModList */
static int hf_nr_rrc_reportConfigToRemoveList = -1;  /* ReportConfigToRemoveList */
static int hf_nr_rrc_reportConfigToAddModList = -1;  /* ReportConfigToAddModList */
static int hf_nr_rrc_measIdToRemoveList = -1;     /* MeasIdToRemoveList */
static int hf_nr_rrc_measIdToAddModList = -1;     /* MeasIdToAddModList */
static int hf_nr_rrc_s_MeasureConfig = -1;        /* T_s_MeasureConfig */
static int hf_nr_rrc_ssb_rsrp = -1;               /* RSRP_Range */
static int hf_nr_rrc_csi_rsrp = -1;               /* RSRP_Range */
static int hf_nr_rrc_quantityConfig = -1;         /* QuantityConfig */
static int hf_nr_rrc_measGapConfig = -1;          /* MeasGapConfig */
static int hf_nr_rrc_MeasObjectToRemoveList_item = -1;  /* MeasObjectId */
static int hf_nr_rrc_MeasIdToRemoveList_item = -1;  /* MeasId */
static int hf_nr_rrc_ReportConfigToRemoveList_item = -1;  /* ReportConfigId */
static int hf_nr_rrc_MeasIdToAddModList_item = -1;  /* MeasIdToAddMod */
static int hf_nr_rrc_measId = -1;                 /* MeasId */
static int hf_nr_rrc_measObjectId = -1;           /* MeasObjectId */
static int hf_nr_rrc_reportConfigId_01 = -1;      /* ReportConfigId */
static int hf_nr_rrc_carrierFreq = -1;            /* ARFCN_ValueNR */
static int hf_nr_rrc_referenceSignalConfig = -1;  /* ReferenceSignalConfig */
static int hf_nr_rrc_absThreshSS_BlocksConsolidation = -1;  /* ThresholdNR */
static int hf_nr_rrc_absThreshCSI_RS_Consolidation = -1;  /* ThresholdNR */
static int hf_nr_rrc_nroSS_BlocksToAverage = -1;  /* INTEGER_2_maxNroSS_BlocksToAverage */
static int hf_nr_rrc_nroCSI_RS_ResourcesToAverage = -1;  /* INTEGER_2_maxNroCSI_RS_ResourcesToAverage */
static int hf_nr_rrc_quantityConfigIndex = -1;    /* INTEGER_1_maxQuantityConfigId */
static int hf_nr_rrc_offsetFreq = -1;             /* Q_OffsetRangeList */
static int hf_nr_rrc_cellsToRemoveList = -1;      /* CellIndexList */
static int hf_nr_rrc_cellsToAddModList = -1;      /* CellsToAddModList */
static int hf_nr_rrc_blackCellsToRemoveList = -1;  /* CellIndexList */
static int hf_nr_rrc_blackCellsToAddModList = -1;  /* BlackCellsToAddModList */
static int hf_nr_rrc_whiteCellsToRemoveList = -1;  /* CellIndexList */
static int hf_nr_rrc_whiteCellsToAddModList = -1;  /* WhiteCellsToAddModList */
static int hf_nr_rrc_ssb_MeasurementTimingConfiguration = -1;  /* SSB_MeasurementTimingConfiguration */
static int hf_nr_rrc_ssbPresence = -1;            /* T_ssbPresence */
static int hf_nr_rrc_present = -1;                /* T_present */
static int hf_nr_rrc_frequencyOffset = -1;        /* NULL */
static int hf_nr_rrc_subcarrierSpacing_01 = -1;   /* SubcarrierSpacing */
static int hf_nr_rrc_notPresent = -1;             /* T_notPresent */
static int hf_nr_rrc_csi_rs_ResourceConfig_Mobility = -1;  /* CSI_RS_ResourceConfig_Mobility */
static int hf_nr_rrc_useServingCellTimingForSync = -1;  /* BOOLEAN */
static int hf_nr_rrc_smtc1 = -1;                  /* T_smtc1 */
static int hf_nr_rrc_periodicityAndOffset = -1;   /* T_periodicityAndOffset */
static int hf_nr_rrc_sf5 = -1;                    /* INTEGER_0_4 */
static int hf_nr_rrc_sf10 = -1;                   /* INTEGER_0_9 */
static int hf_nr_rrc_sf20 = -1;                   /* INTEGER_0_19 */
static int hf_nr_rrc_sf40 = -1;                   /* INTEGER_0_39 */
static int hf_nr_rrc_sf80 = -1;                   /* INTEGER_0_79 */
static int hf_nr_rrc_sf160 = -1;                  /* INTEGER_0_159 */
static int hf_nr_rrc_duration = -1;               /* T_duration */
static int hf_nr_rrc_ssb_ToMeasure = -1;          /* T_ssb_ToMeasure */
static int hf_nr_rrc_setup_02 = -1;               /* T_setup_02 */
static int hf_nr_rrc_shortBitmap = -1;            /* BIT_STRING_SIZE_4 */
static int hf_nr_rrc_mediumBitmap = -1;           /* BIT_STRING_SIZE_8 */
static int hf_nr_rrc_longBitmap = -1;             /* BIT_STRING_SIZE_64 */
static int hf_nr_rrc_smtc2 = -1;                  /* T_smtc2 */
static int hf_nr_rrc_pci_List = -1;               /* SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId */
static int hf_nr_rrc_pci_List_item = -1;          /* PhysicalCellId */
static int hf_nr_rrc_periodicty = -1;             /* NULL */
static int hf_nr_rrc_csi_rs_MeasurementBW = -1;   /* T_csi_rs_MeasurementBW */
static int hf_nr_rrc_csi_rs_measurementBW_size = -1;  /* T_csi_rs_measurementBW_size */
static int hf_nr_rrc_csi_rs_measurement_BW_start = -1;  /* T_csi_rs_measurement_BW_start */
static int hf_nr_rrc_associated_SSB = -1;         /* T_associated_SSB */
static int hf_nr_rrc_qcled_SSB = -1;              /* BOOLEAN */
static int hf_nr_rrc_isServingCellMO = -1;        /* BOOLEAN */
static int hf_nr_rrc_csi_rs_ResourceList_Mobility = -1;  /* SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility */
static int hf_nr_rrc_csi_rs_ResourceList_Mobility_item = -1;  /* CSI_RS_Resource_Mobility */
static int hf_nr_rrc_csi_rs_ResourceId_RRM = -1;  /* CSI_RS_ResourceId_RRM */
static int hf_nr_rrc_cellId = -1;                 /* PhysicalCellId */
static int hf_nr_rrc_slotConfig = -1;             /* T_slotConfig */
static int hf_nr_rrc_ms5 = -1;                    /* INTEGER_0_4 */
static int hf_nr_rrc_resourceElementMappingPattern = -1;  /* NULL */
static int hf_nr_rrc_sequenceGenerationConfig = -1;  /* NULL */
static int hf_nr_rrc_rsrpOffsetSSB = -1;          /* Q_OffsetRange */
static int hf_nr_rrc_rsrqOffsetSSB = -1;          /* Q_OffsetRange */
static int hf_nr_rrc_sinrOffsetSSB = -1;          /* Q_OffsetRange */
static int hf_nr_rrc_rsrpOffsetCSI_RS = -1;       /* Q_OffsetRange */
static int hf_nr_rrc_rsrqOffsetCSI_RS = -1;       /* Q_OffsetRange */
static int hf_nr_rrc_sinrOffsetCSI_RS = -1;       /* Q_OffsetRange */
static int hf_nr_rrc_threshold_RSRP = -1;         /* RSRP_Range */
static int hf_nr_rrc_threshold_RSRQ = -1;         /* RSRQ_Range */
static int hf_nr_rrc_threshold_SINR = -1;         /* SINR_Range */
static int hf_nr_rrc_CellsToAddModList_item = -1;  /* CellsToAddMod */
static int hf_nr_rrc_cellIndex = -1;              /* INTEGER_1_maxNrofCellMeas */
static int hf_nr_rrc_cellIndividualOffset = -1;   /* Q_OffsetRangeList */
static int hf_nr_rrc_BlackCellsToAddModList_item = -1;  /* BlackCellsToAddMod */
static int hf_nr_rrc_physCellIdRange = -1;        /* PhysCellIdRange */
static int hf_nr_rrc_WhiteCellsToAddModList_item = -1;  /* WhiteCellsToAddMod */
static int hf_nr_rrc_MeasObjectToAddModList_item = -1;  /* MeasObjectToAddMod */
static int hf_nr_rrc_measObject = -1;             /* T_measObject */
static int hf_nr_rrc_measObjectNR = -1;           /* MeasObjectNR */
static int hf_nr_rrc_measObjectEUTRA = -1;        /* MeasObjectEUTRA */
static int hf_nr_rrc_measResultServingFreqList = -1;  /* MeasResultServFreqList */
static int hf_nr_rrc_measResultNeighCells = -1;   /* T_measResultNeighCells */
static int hf_nr_rrc_measResultListNR = -1;       /* MeasResultListNR */
static int hf_nr_rrc_measResultListEUTRA = -1;    /* MeasResultListEUTRA */
static int hf_nr_rrc_MeasResultServFreqList_item = -1;  /* MeasResultServFreq */
static int hf_nr_rrc_servFreqId = -1;             /* ServCellIndex */
static int hf_nr_rrc_measResultServingCell = -1;  /* MeasResultNR */
static int hf_nr_rrc_measResultBestNeighCell = -1;  /* MeasResultNR */
static int hf_nr_rrc_MeasResultListNR_item = -1;  /* MeasResultNR */
static int hf_nr_rrc_cgi_Info = -1;               /* NULL */
static int hf_nr_rrc_measResult = -1;             /* T_measResult */
static int hf_nr_rrc_cellResults = -1;            /* T_cellResults */
static int hf_nr_rrc_resultsSSBCell = -1;         /* ResultsSSBCell */
static int hf_nr_rrc_resultsCSI_RSCell = -1;      /* ResultsCSI_RSCell */
static int hf_nr_rrc_rsIndexResults = -1;         /* T_rsIndexResults */
static int hf_nr_rrc_resultsSSBIndexes = -1;      /* ResultsPerSSBIndexList */
static int hf_nr_rrc_resultsCSI_RSIndexes = -1;   /* ResultsPerCSI_RSIndexList */
static int hf_nr_rrc_ssb_Cellrsrp = -1;           /* RSRP_Range */
static int hf_nr_rrc_ssb_Cellrsrq = -1;           /* RSRQ_Range */
static int hf_nr_rrc_ssb_Cellsinr = -1;           /* SINR_Range */
static int hf_nr_rrc_csi_rs_Cellrsrp = -1;        /* RSRP_Range */
static int hf_nr_rrc_csi_rs_Cellrsrq = -1;        /* RSRQ_Range */
static int hf_nr_rrc_csi_rs_Cellsinr = -1;        /* SINR_Range */
static int hf_nr_rrc_ResultsPerSSBIndexList_item = -1;  /* ResultsPerSSBIndex */
static int hf_nr_rrc_ss_rsrp = -1;                /* RSRP_Range */
static int hf_nr_rrc_ss_rsrq = -1;                /* RSRQ_Range */
static int hf_nr_rrc_ss_sinr = -1;                /* SINR_Range */
static int hf_nr_rrc_ResultsPerCSI_RSIndexList_item = -1;  /* ResultsPerCSI_RSIndex */
static int hf_nr_rrc_csi_rsIndex = -1;            /* CSI_RSIndex */
static int hf_nr_rrc_csi_rsrq = -1;               /* RSRQ_Range */
static int hf_nr_rrc_csi_sinr = -1;               /* SINR_Range */
static int hf_nr_rrc_controlResourceSetToAddModList = -1;  /* SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet */
static int hf_nr_rrc_controlResourceSetToAddModList_item = -1;  /* ControlResourceSet */
static int hf_nr_rrc_controlResourceSetToReleaseList = -1;  /* SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId */
static int hf_nr_rrc_controlResourceSetToReleaseList_item = -1;  /* ControlResourceId */
static int hf_nr_rrc_searchSpacesToAddModList = -1;  /* SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace */
static int hf_nr_rrc_searchSpacesToAddModList_item = -1;  /* SearchSpace */
static int hf_nr_rrc_searchSpacesToReleaseList = -1;  /* SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId */
static int hf_nr_rrc_searchSpacesToReleaseList_item = -1;  /* SearchSpaceId */
static int hf_nr_rrc_timing = -1;                 /* T_timing */
static int hf_nr_rrc_dl_assignment_to_DL_data = -1;  /* NULL */
static int hf_nr_rrc_ul_assignment_to_UL_data = -1;  /* NULL */
static int hf_nr_rrc_dl_data_to_UL_ACK = -1;      /* NULL */
static int hf_nr_rrc_controlResourceSetId = -1;   /* ControlResourceSetId */
static int hf_nr_rrc_frequencyDomainResources = -1;  /* NULL */
static int hf_nr_rrc_startSymbol = -1;            /* INTEGER_0_maxCoReSetStartSymbol */
static int hf_nr_rrc_duration_01 = -1;            /* INTEGER_1_maxCoReSetDuration */
static int hf_nr_rrc_reg_BundleSize = -1;         /* T_reg_BundleSize */
static int hf_nr_rrc_cce_reg_MappingType = -1;    /* T_cce_reg_MappingType */
static int hf_nr_rrc_precoderGranularity = -1;    /* NULL */
static int hf_nr_rrc_interleaverRows = -1;        /* T_interleaverRows */
static int hf_nr_rrc_shiftIndex = -1;             /* NULL */
static int hf_nr_rrc_tci_StateRefId = -1;         /* NULL */
static int hf_nr_rrc_pdcch_DMRS_ScramblingID = -1;  /* NULL */
static int hf_nr_rrc_searchSpaceId = -1;          /* SearchSpaceId */
static int hf_nr_rrc_monitoringSlotPeriodicityAndOffset = -1;  /* T_monitoringSlotPeriodicityAndOffset */
static int hf_nr_rrc_sl1 = -1;                    /* NULL */
static int hf_nr_rrc_sl2 = -1;                    /* INTEGER_0_1 */
static int hf_nr_rrc_monitoringSymbolsWithinSlot = -1;  /* BIT_STRING_SIZE_14 */
static int hf_nr_rrc_nrofCandidates = -1;         /* T_nrofCandidates */
static int hf_nr_rrc_aggregationLevel1 = -1;      /* T_aggregationLevel1 */
static int hf_nr_rrc_aggregationLevel2 = -1;      /* T_aggregationLevel2 */
static int hf_nr_rrc_aggregationLevel4 = -1;      /* T_aggregationLevel4 */
static int hf_nr_rrc_aggregationLevel8 = -1;      /* T_aggregationLevel8 */
static int hf_nr_rrc_searchSpaceType = -1;        /* T_searchSpaceType */
static int hf_nr_rrc_common = -1;                 /* T_common */
static int hf_nr_rrc_sfi_PDCCH = -1;              /* SFI_PDCCH */
static int hf_nr_rrc_preemp_DL = -1;              /* BOOLEAN */
static int hf_nr_rrc_int_RNTI = -1;               /* BIT_STRING_SIZE_16 */
static int hf_nr_rrc_int_TF = -1;                 /* T_int_TF */
static int hf_nr_rrc_monitoringPeriodicity = -1;  /* NULL */
static int hf_nr_rrc_ue_Specific = -1;            /* T_ue_Specific */
static int hf_nr_rrc_monitoringPeriodicity_01 = -1;  /* T_monitoringPeriodicity */
static int hf_nr_rrc_sfi_CellToSFI = -1;          /* SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI */
static int hf_nr_rrc_sfi_CellToSFI_item = -1;     /* CellToSFI */
static int hf_nr_rrc_nrofPDCCH_Candidates = -1;   /* T_nrofPDCCH_Candidates */
static int hf_nr_rrc_aggregationLevel = -1;       /* T_aggregationLevel */
static int hf_nr_rrc_sfi_RNTI = -1;               /* BIT_STRING_SIZE_16 */
static int hf_nr_rrc_dci_PayloadLength = -1;      /* NULL */
static int hf_nr_rrc_searchSpace = -1;            /* NULL */
static int hf_nr_rrc_sfi_PositionInDCI = -1;      /* INTEGER_1_1 */
static int hf_nr_rrc_slotFormatCombinations = -1;  /* SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination */
static int hf_nr_rrc_slotFormatCombinations_item = -1;  /* SlotFormatCombination */
static int hf_nr_rrc_slotFormatCombinationId = -1;  /* SlotFormatCombinationId */
static int hf_nr_rrc_drb = -1;                    /* T_drb */
static int hf_nr_rrc_discardTimer = -1;           /* T_discardTimer */
static int hf_nr_rrc_pdcp_SN_Size_UL = -1;        /* T_pdcp_SN_Size_UL */
static int hf_nr_rrc_pdcp_SN_Size_DL = -1;        /* T_pdcp_SN_Size_DL */
static int hf_nr_rrc_headerCompression = -1;      /* T_headerCompression */
static int hf_nr_rrc_notUsed = -1;                /* NULL */
static int hf_nr_rrc_rohc = -1;                   /* T_rohc */
static int hf_nr_rrc_maxCID = -1;                 /* INTEGER_1_16383 */
static int hf_nr_rrc_profiles = -1;               /* T_profiles */
static int hf_nr_rrc_profile0x0001 = -1;          /* BOOLEAN */
static int hf_nr_rrc_profile0x0002 = -1;          /* BOOLEAN */
static int hf_nr_rrc_profile0x0003 = -1;          /* BOOLEAN */
static int hf_nr_rrc_profile0x0004 = -1;          /* BOOLEAN */
static int hf_nr_rrc_profile0x0006 = -1;          /* BOOLEAN */
static int hf_nr_rrc_profile0x0101 = -1;          /* BOOLEAN */
static int hf_nr_rrc_profile0x0102 = -1;          /* BOOLEAN */
static int hf_nr_rrc_profile0x0103 = -1;          /* BOOLEAN */
static int hf_nr_rrc_profile0x0104 = -1;          /* BOOLEAN */
static int hf_nr_rrc_uplinkOnlyROHC = -1;         /* T_uplinkOnlyROHC */
static int hf_nr_rrc_profiles_01 = -1;            /* T_profiles_01 */
static int hf_nr_rrc_integrityProtection = -1;    /* BOOLEAN */
static int hf_nr_rrc_statusReportRequired = -1;   /* BOOLEAN */
static int hf_nr_rrc_moreThanOneRLC = -1;         /* T_moreThanOneRLC */
static int hf_nr_rrc_primaryPath = -1;            /* T_primaryPath */
static int hf_nr_rrc_cellGroup = -1;              /* CellGroupId */
static int hf_nr_rrc_logicalChannel = -1;         /* LogicalChannelIdentity */
static int hf_nr_rrc_ul_DataSplitThreshold = -1;  /* T_ul_DataSplitThreshold */
static int hf_nr_rrc_setup_03 = -1;               /* T_setup_03 */
static int hf_nr_rrc_ul_Duplication = -1;         /* BOOLEAN */
static int hf_nr_rrc_t_Reordering = -1;           /* T_t_Reordering */
static int hf_nr_rrc_outOfOrderDelivery = -1;     /* BOOLEAN */
static int hf_nr_rrc_codeBlockGroupTransmission = -1;  /* BOOLEAN */
static int hf_nr_rrc_maxCodeBlockGroupsPerTransportBlock = -1;  /* T_maxCodeBlockGroupsPerTransportBlock */
static int hf_nr_rrc_codeBlockGroupFlushIndicator = -1;  /* BOOLEAN */
static int hf_nr_rrc_dmrs_Type = -1;              /* T_dmrs_Type */
static int hf_nr_rrc_dmrs_AdditionalPosition = -1;  /* T_dmrs_AdditionalPosition */
static int hf_nr_rrc_dmrs_group1 = -1;            /* NULL */
static int hf_nr_rrc_dmrs_group2 = -1;            /* NULL */
static int hf_nr_rrc_phaseTracking_RS = -1;       /* T_phaseTracking_RS */
static int hf_nr_rrc_setup_04 = -1;               /* Downlink_PTRS_Config */
static int hf_nr_rrc_tci_States = -1;             /* NULL */
static int hf_nr_rrc_tci_rs_SetConfig = -1;       /* NULL */
static int hf_nr_rrc_tci_PresentInDCI = -1;       /* T_tci_PresentInDCI */
static int hf_nr_rrc_xOverhead = -1;              /* T_xOverhead */
static int hf_nr_rrc_pdsch_symbolAllocation = -1;  /* NULL */
static int hf_nr_rrc_rateMatchResourcesPDSCH = -1;  /* T_rateMatchResourcesPDSCH */
static int hf_nr_rrc_rateMatchPatterns = -1;      /* T_rateMatchPatterns */
static int hf_nr_rrc_setup_05 = -1;               /* SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern */
static int hf_nr_rrc_setup_item = -1;             /* RateMatchPattern */
static int hf_nr_rrc_lte_CRS_ToMatchAround = -1;  /* T_lte_CRS_ToMatchAround */
static int hf_nr_rrc_setup_06 = -1;               /* T_setup_04 */
static int hf_nr_rrc_nrofCRS_Ports = -1;          /* T_nrofCRS_Ports */
static int hf_nr_rrc_v_Shift = -1;                /* T_v_Shift */
static int hf_nr_rrc_rbg_Size = -1;               /* T_rbg_Size */
static int hf_nr_rrc_mcs_Table = -1;              /* T_mcs_Table */
static int hf_nr_rrc_maxNrofCodeWordsScheduledByDCI = -1;  /* T_maxNrofCodeWordsScheduledByDCI */
static int hf_nr_rrc_nrofHARQ_processesForPDSCH = -1;  /* NULL */
static int hf_nr_rrc_harq_ACK_Codebook = -1;      /* T_harq_ACK_Codebook */
static int hf_nr_rrc_pdsch_BundleSize = -1;       /* NULL */
static int hf_nr_rrc_prbBundlingEnabled = -1;     /* BOOLEAN */
static int hf_nr_rrc_frequencyDensity = -1;       /* NULL */
static int hf_nr_rrc_timeDensity = -1;            /* NULL */
static int hf_nr_rrc_nrofPorts_01 = -1;           /* T_nrofPorts_01 */
static int hf_nr_rrc_epre_Ratio = -1;             /* NULL */
static int hf_nr_rrc_resourceElementOffset = -1;  /* NULL */
static int hf_nr_rrc_resourceBlocks = -1;         /* BIT_STRING_SIZE_275 */
static int hf_nr_rrc_symbolsInResourceBlock = -1;  /* BIT_STRING_SIZE_14 */
static int hf_nr_rrc_periodicityAndOffset_01 = -1;  /* T_periodicityAndOffset_01 */
static int hf_nr_rrc_n5 = -1;                     /* INTEGER_0_4 */
static int hf_nr_rrc_n10 = -1;                    /* INTEGER_0_9 */
static int hf_nr_rrc_n20 = -1;                    /* INTEGER_0_19 */
static int hf_nr_rrc_n40 = -1;                    /* INTEGER_0_39 */
static int hf_nr_rrc_resourceSets = -1;           /* SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet */
static int hf_nr_rrc_resourceSets_item = -1;      /* PUCCH_ResourceSet */
static int hf_nr_rrc_format1 = -1;                /* T_format1 */
static int hf_nr_rrc_setup_07 = -1;               /* T_setup_05 */
static int hf_nr_rrc_interslotFrequencyHopping = -1;  /* T_interslotFrequencyHopping */
static int hf_nr_rrc_nrofSlots = -1;              /* T_nrofSlots */
static int hf_nr_rrc_format2 = -1;                /* T_format2 */
static int hf_nr_rrc_setup_08 = -1;               /* T_setup_06 */
static int hf_nr_rrc_maxCodeRate = -1;            /* INTEGER_0_7 */
static int hf_nr_rrc_nrofPRBs = -1;               /* INTEGER_1_16 */
static int hf_nr_rrc_simultaneousHARQ_ACK_CSI = -1;  /* T_simultaneousHARQ_ACK_CSI */
static int hf_nr_rrc_format3 = -1;                /* T_format3 */
static int hf_nr_rrc_setup_09 = -1;               /* T_setup_07 */
static int hf_nr_rrc_interslotFrequencyHopping_01 = -1;  /* T_interslotFrequencyHopping_01 */
static int hf_nr_rrc_additionalDMRS = -1;         /* T_additionalDMRS */
static int hf_nr_rrc_nrofSlots_01 = -1;           /* T_nrofSlots_01 */
static int hf_nr_rrc_pi2PBSK = -1;                /* T_pi2PBSK */
static int hf_nr_rrc_format4 = -1;                /* T_format4 */
static int hf_nr_rrc_setup_10 = -1;               /* T_setup_08 */
static int hf_nr_rrc_interslotFrequencyHopping_02 = -1;  /* T_interslotFrequencyHopping_02 */
static int hf_nr_rrc_additionalDMRS_01 = -1;      /* T_additionalDMRS_01 */
static int hf_nr_rrc_nrofSlots_02 = -1;           /* T_nrofSlots_02 */
static int hf_nr_rrc_pi2PBSK_01 = -1;             /* T_pi2PBSK_01 */
static int hf_nr_rrc_schedulingRequestResources = -1;  /* T_schedulingRequestResources */
static int hf_nr_rrc_setup_11 = -1;               /* SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config */
static int hf_nr_rrc_setup_item_01 = -1;          /* SchedulingRequestResource_Config */
static int hf_nr_rrc_tpc_PUCCH_RNTI = -1;         /* BIT_STRING_SIZE_16 */
static int hf_nr_rrc_codeBlockGroupTransmission_01 = -1;  /* T_codeBlockGroupTransmission */
static int hf_nr_rrc_maxCodeBlockGroupsPerTransportBlock_01 = -1;  /* T_maxCodeBlockGroupsPerTransportBlock_01 */
static int hf_nr_rrc_dmrs_Type_01 = -1;           /* T_dmrs_Type_01 */
static int hf_nr_rrc_dmrs_AdditionalPosition_01 = -1;  /* T_dmrs_AdditionalPosition_01 */
static int hf_nr_rrc_phaseTracking_RS_01 = -1;    /* T_phaseTracking_RS_01 */
static int hf_nr_rrc_setup_12 = -1;               /* Uplink_PTRS_Config */
static int hf_nr_rrc_tpcAccumulation = -1;        /* T_tpcAccumulation */
static int hf_nr_rrc_tcp_PUSCH_RNTI = -1;         /* BIT_STRING_SIZE_16 */
static int hf_nr_rrc_frequencyHopping = -1;       /* T_frequencyHopping */
static int hf_nr_rrc_rateMatching = -1;           /* T_rateMatching */
static int hf_nr_rrc_rateMatchResources = -1;     /* NULL */
static int hf_nr_rrc_symbolAllocationIndexs = -1;  /* NULL */
static int hf_nr_rrc_mcs_Table_01 = -1;           /* T_mcs_Table_01 */
static int hf_nr_rrc_mcs_TableTransformPrecoder = -1;  /* T_mcs_TableTransformPrecoder */
static int hf_nr_rrc_transformPrecoder = -1;      /* T_transformPrecoder */
static int hf_nr_rrc_rbg_Size_01 = -1;            /* T_rbg_Size_01 */
static int hf_nr_rrc_uci_on_PUSCH = -1;           /* T_uci_on_PUSCH */
static int hf_nr_rrc_setup_13 = -1;               /* T_setup_09 */
static int hf_nr_rrc_dynamic = -1;                /* SEQUENCE_SIZE_1_4_OF_BetaOffsets */
static int hf_nr_rrc_dynamic_item = -1;           /* BetaOffsets */
static int hf_nr_rrc_semiStatic = -1;             /* BetaOffsets */
static int hf_nr_rrc_xOverhead_01 = -1;           /* T_xOverhead_01 */
static int hf_nr_rrc_cp_OFDM = -1;                /* T_cp_OFDM */
static int hf_nr_rrc_setup_14 = -1;               /* T_setup_10 */
static int hf_nr_rrc_nrofPorts_02 = -1;           /* T_nrofPorts_02 */
static int hf_nr_rrc_dft_S_OFDM = -1;             /* T_dft_S_OFDM */
static int hf_nr_rrc_setup_15 = -1;               /* T_setup_11 */
static int hf_nr_rrc_sampleDensity = -1;          /* NULL */
static int hf_nr_rrc_timeDensity_01 = -1;         /* T_timeDensity */
static int hf_nr_rrc_sequence = -1;               /* NULL */
static int hf_nr_rrc_betaOffsetACK_Index1 = -1;   /* INTEGER_0_31 */
static int hf_nr_rrc_betaOffsetACK_Index2 = -1;   /* INTEGER_0_31 */
static int hf_nr_rrc_betaOffsetACK_Index3 = -1;   /* INTEGER_0_31 */
static int hf_nr_rrc_betaOffsetCSI_part1_Index1 = -1;  /* INTEGER_0_31 */
static int hf_nr_rrc_betaOffsetCSI_part1_Index2 = -1;  /* INTEGER_0_31 */
static int hf_nr_rrc_betaOffsetCSI_part2_Index1 = -1;  /* INTEGER_0_31 */
static int hf_nr_rrc_betaOffsetCSI_part2_Index2 = -1;  /* INTEGER_0_31 */
static int hf_nr_rrc_quantityConfigRSindex = -1;  /* QuantityConfigRS */
static int hf_nr_rrc_ssbFilterCoefficientRSRP = -1;  /* FilterCoefficient */
static int hf_nr_rrc_ssbFilterCoefficientRSRQ = -1;  /* FilterCoefficient */
static int hf_nr_rrc_ssbFilterCoefficientRS_SINR = -1;  /* FilterCoefficient */
static int hf_nr_rrc_csi_rsFilterCoefficientRSRP = -1;  /* FilterCoefficient */
static int hf_nr_rrc_csi_rsFilterCoefficientRSRQ = -1;  /* FilterCoefficient */
static int hf_nr_rrc_csi_rsFilterCoefficientRS_SINR = -1;  /* FilterCoefficient */
static int hf_nr_rrc_groupBconfigured = -1;       /* T_groupBconfigured */
static int hf_nr_rrc_ra_Msg3SizeGroupA = -1;      /* T_ra_Msg3SizeGroupA */
static int hf_nr_rrc_messagePowerOffsetGroupB = -1;  /* T_messagePowerOffsetGroupB */
static int hf_nr_rrc_cbra_SSB_ResourceList = -1;  /* CBRA_SSB_ResourceList */
static int hf_nr_rrc_ra_ContentionResolutionTimer = -1;  /* T_ra_ContentionResolutionTimer */
static int hf_nr_rrc_ssb_Threshold = -1;          /* NULL */
static int hf_nr_rrc_sul_RSRP_Threshold = -1;     /* NULL */
static int hf_nr_rrc_prach_ConfigurationIndex = -1;  /* INTEGER_0_255 */
static int hf_nr_rrc_prach_RootSequenceIndex = -1;  /* T_prach_RootSequenceIndex */
static int hf_nr_rrc_l839 = -1;                   /* INTEGER_0_837 */
static int hf_nr_rrc_l139 = -1;                   /* INTEGER_0_137 */
static int hf_nr_rrc_zeroCorrelationZoneConfig = -1;  /* INTEGER_0_15 */
static int hf_nr_rrc_restrictedSetConfig = -1;    /* T_restrictedSetConfig */
static int hf_nr_rrc_preambleReceivedTargetPower = -1;  /* T_preambleReceivedTargetPower */
static int hf_nr_rrc_powerRampingStep = -1;       /* T_powerRampingStep */
static int hf_nr_rrc_preambleTransMax = -1;       /* T_preambleTransMax */
static int hf_nr_rrc_ra_ResponseWindow = -1;      /* NULL */
static int hf_nr_rrc_msg2_SubcarrierSpacing = -1;  /* SubcarrierSpacing */
static int hf_nr_rrc_rach_ControlResourceSet = -1;  /* NULL */
static int hf_nr_rrc_msg3_SubcarrierSpacing = -1;  /* SubcarrierSpacing */
static int hf_nr_rrc_msg3_transformPrecoding = -1;  /* T_msg3_transformPrecoding */
static int hf_nr_rrc_CBRA_SSB_ResourceList_item = -1;  /* CBRA_SSB_Resource */
static int hf_nr_rrc_ssb = -1;                    /* SSB_ID */
static int hf_nr_rrc_startIndexRA_PreambleGroupA = -1;  /* PreambleStartIndex */
static int hf_nr_rrc_numberofRA_PreamblesGroupA = -1;  /* NumberOfRA_Preambles */
static int hf_nr_rrc_numberOfRA_Preambles = -1;   /* NumberOfRA_Preambles */
static int hf_nr_rrc_ra_Resources = -1;           /* RA_Resources */
static int hf_nr_rrc_cfra_Resources = -1;         /* CFRA_Resources */
static int hf_nr_rrc_rar_SubcarrierSpacing = -1;  /* SubcarrierSpacing */
static int hf_nr_rrc_cfra_ssb_ResourceList = -1;  /* SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource */
static int hf_nr_rrc_cfra_ssb_ResourceList_item = -1;  /* CFRA_SSB_Resource */
static int hf_nr_rrc_cfra_csirs_ResourceList = -1;  /* SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource */
static int hf_nr_rrc_cfra_csirs_ResourceList_item = -1;  /* CFRA_CSIRS_Resource */
static int hf_nr_rrc_ra_PreambleIndex = -1;       /* INTEGER_0_0 */
static int hf_nr_rrc_csirs = -1;                  /* CSIRS_ID */
static int hf_nr_rrc_srb_ToAddModList = -1;       /* SRB_ToAddModList */
static int hf_nr_rrc_srb_ToReleaseList = -1;      /* INTEGER_3 */
static int hf_nr_rrc_drb_ToAddModList = -1;       /* DRB_ToAddModList */
static int hf_nr_rrc_drb_ToReleaseList = -1;      /* DRB_ToReleaseList */
static int hf_nr_rrc_securityConfig = -1;         /* SecurityConfig */
static int hf_nr_rrc_SRB_ToAddModList_item = -1;  /* SRB_ToAddMod */
static int hf_nr_rrc_srb_Identity = -1;           /* SRB_Identity */
static int hf_nr_rrc_reestablishPDCP = -1;        /* T_reestablishPDCP */
static int hf_nr_rrc_pdcp_Config = -1;            /* PDCP_Config */
static int hf_nr_rrc_DRB_ToAddModList_item = -1;  /* DRB_ToAddMod */
static int hf_nr_rrc_cnAssociation = -1;          /* T_cnAssociation */
static int hf_nr_rrc_eps_BearerIdentity = -1;     /* INTEGER_0_15 */
static int hf_nr_rrc_sdap_Config = -1;            /* SDAP_Config */
static int hf_nr_rrc_drb_Identity = -1;           /* DRB_Identity */
static int hf_nr_rrc_reestablishPDCP_01 = -1;     /* T_reestablishPDCP_01 */
static int hf_nr_rrc_recoverPDCP = -1;            /* T_recoverPDCP */
static int hf_nr_rrc_DRB_ToReleaseList_item = -1;  /* DRB_Identity */
static int hf_nr_rrc_securityAlgorithmConfig = -1;  /* SecurityAlgorithmConfig */
static int hf_nr_rrc_keyToUse = -1;               /* T_keyToUse */
static int hf_nr_rrc_reportType = -1;             /* T_reportType */
static int hf_nr_rrc_periodical = -1;             /* PeriodicalReportConfig */
static int hf_nr_rrc_eventTriggered = -1;         /* EventTriggerConfig */
static int hf_nr_rrc_reportCGI = -1;              /* NULL */
static int hf_nr_rrc_eventId = -1;                /* T_eventId */
static int hf_nr_rrc_eventA1 = -1;                /* T_eventA1 */
static int hf_nr_rrc_a1_Threshold = -1;           /* MeasTriggerQuantity */
static int hf_nr_rrc_reportOnLeave = -1;          /* BOOLEAN */
static int hf_nr_rrc_hysteresis = -1;             /* Hysteresis */
static int hf_nr_rrc_timeToTrigger = -1;          /* TimeToTrigger */
static int hf_nr_rrc_eventA2 = -1;                /* T_eventA2 */
static int hf_nr_rrc_a2_Threshold = -1;           /* MeasTriggerQuantity */
static int hf_nr_rrc_eventA3 = -1;                /* T_eventA3 */
static int hf_nr_rrc_a3_Offset = -1;              /* MeasTriggerQuantityOffset */
static int hf_nr_rrc_useWhiteCellList = -1;       /* BOOLEAN */
static int hf_nr_rrc_eventA4 = -1;                /* T_eventA4 */
static int hf_nr_rrc_a4_Threshold = -1;           /* MeasTriggerQuantity */
static int hf_nr_rrc_eventA5 = -1;                /* T_eventA5 */
static int hf_nr_rrc_a5_Threshold1 = -1;          /* MeasTriggerQuantity */
static int hf_nr_rrc_a5_Threshold2 = -1;          /* MeasTriggerQuantity */
static int hf_nr_rrc_eventA6 = -1;                /* T_eventA6 */
static int hf_nr_rrc_a6_Offset = -1;              /* MeasTriggerQuantityOffset */
static int hf_nr_rrc_rsType = -1;                 /* T_rsType */
static int hf_nr_rrc_reportInterval = -1;         /* ReportInterval */
static int hf_nr_rrc_reportAmount = -1;           /* T_reportAmount */
static int hf_nr_rrc_reportQuantityCell = -1;     /* MeasReportQuantity */
static int hf_nr_rrc_maxReportCells = -1;         /* INTEGER_1_maxCellReport */
static int hf_nr_rrc_reportQuantityRsIndexes = -1;  /* MeasReportQuantity */
static int hf_nr_rrc_maxNroIndexesToReport = -1;  /* INTEGER_1_maxNroIndexesToReport */
static int hf_nr_rrc_onlyReportBeamIds = -1;      /* BOOLEAN */
static int hf_nr_rrc_reportAddNeighMeas = -1;     /* NULL */
static int hf_nr_rrc_rsType_01 = -1;              /* T_rsType_01 */
static int hf_nr_rrc_reportAmount_01 = -1;        /* T_reportAmount_01 */
static int hf_nr_rrc_maxNroRsIndexesToReport = -1;  /* INTEGER_1_maxNroIndexesToReport */
static int hf_nr_rrc_rsrp = -1;                   /* RSRPRange */
static int hf_nr_rrc_rsrq = -1;                   /* RSRQRange */
static int hf_nr_rrc_sinr = -1;                   /* SINRRange */
static int hf_nr_rrc_rsrp_01 = -1;                /* INTEGER_0 */
static int hf_nr_rrc_rsrq_01 = -1;                /* INTEGER_0 */
static int hf_nr_rrc_sinr_01 = -1;                /* INTEGER_0 */
static int hf_nr_rrc_rsrp_02 = -1;                /* BOOLEAN */
static int hf_nr_rrc_rsrq_02 = -1;                /* BOOLEAN */
static int hf_nr_rrc_sinr_02 = -1;                /* BOOLEAN */
static int hf_nr_rrc_ReportConfigToAddModList_item = -1;  /* ReportConfigToAddMod */
static int hf_nr_rrc_reportConfig = -1;           /* T_reportConfig */
static int hf_nr_rrc_reportConfigNR = -1;         /* ReportConfigNR */
static int hf_nr_rrc_reportConfigEUTRA = -1;      /* ReportConfigEUTRA */
static int hf_nr_rrc_am = -1;                     /* T_am */
static int hf_nr_rrc_ul_AM_RLC = -1;              /* UL_AM_RLC */
static int hf_nr_rrc_dl_AM_RLC = -1;              /* DL_AM_RLC */
static int hf_nr_rrc_um_Bi_Directional = -1;      /* T_um_Bi_Directional */
static int hf_nr_rrc_ul_UM_RLC = -1;              /* UL_UM_RLC */
static int hf_nr_rrc_dl_UM_RLC = -1;              /* DL_UM_RLC */
static int hf_nr_rrc_um_Uni_Directional_UL = -1;  /* T_um_Uni_Directional_UL */
static int hf_nr_rrc_um_Uni_Directional_DL = -1;  /* T_um_Uni_Directional_DL */
static int hf_nr_rrc_sn_FieldLength = -1;         /* SN_FieldLength_AM */
static int hf_nr_rrc_t_PollRetransmit = -1;       /* T_PollRetransmit */
static int hf_nr_rrc_pollPDU = -1;                /* PollPDU */
static int hf_nr_rrc_pollByte = -1;               /* PollByte */
static int hf_nr_rrc_maxRetxThreshold = -1;       /* T_maxRetxThreshold */
static int hf_nr_rrc_t_Reassembly = -1;           /* T_Reassembly */
static int hf_nr_rrc_t_StatusProhibit = -1;       /* T_StatusProhibit */
static int hf_nr_rrc_sn_FieldLength_01 = -1;      /* SN_FieldLength_UM */
static int hf_nr_rrc_schedulingRequestToAddModList = -1;  /* SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod */
static int hf_nr_rrc_schedulingRequestToAddModList_item = -1;  /* SchedulingRequestToAddMod */
static int hf_nr_rrc_schedulingRequestToReleaseList = -1;  /* SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId */
static int hf_nr_rrc_schedulingRequestToReleaseList_item = -1;  /* SchedulingRequestId */
static int hf_nr_rrc_schedulingRequestID = -1;    /* SchedulingRequestId */
static int hf_nr_rrc_sr_prohibitTimer = -1;       /* T_sr_prohibitTimer */
static int hf_nr_rrc_sr_TransMax = -1;            /* T_sr_TransMax */
static int hf_nr_rrc_pduSession = -1;             /* PDUsessionID */
static int hf_nr_rrc_sdap_Header_DL = -1;         /* T_sdap_Header_DL */
static int hf_nr_rrc_sdap_Header_UL = -1;         /* T_sdap_Header_UL */
static int hf_nr_rrc_defaultDRB = -1;             /* BOOLEAN */
static int hf_nr_rrc_reflectiveQoS = -1;          /* BOOLEAN */
static int hf_nr_rrc_mappedQoSflows = -1;         /* SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI */
static int hf_nr_rrc_mappedQoSflows_item = -1;    /* QFI */
static int hf_nr_rrc_cipheringAlgorithm = -1;     /* CipheringAlgorithm */
static int hf_nr_rrc_integrityProtAlgorithm = -1;  /* IntegrityProtAlgorithm */
static int hf_nr_rrc_frequencyInfoDL = -1;        /* T_frequencyInfoDL */
static int hf_nr_rrc_carrierFreqDL = -1;          /* ARFCN_ValueNR */
static int hf_nr_rrc_carrierBandwidthDL = -1;     /* CarrierBandwidthNR */
static int hf_nr_rrc_frequencyInfoUL = -1;        /* FrequencyInfoUL */
static int hf_nr_rrc_supplementaryUplink = -1;    /* T_supplementaryUplink */
static int hf_nr_rrc_subcarrierSpacingCommon = -1;  /* SubcarrierSpacing */
static int hf_nr_rrc_ssb_subcarrier_offset = -1;  /* INTEGER_1_11 */
static int hf_nr_rrc_ssb_PositionsInBurst = -1;   /* T_ssb_PositionsInBurst */
static int hf_nr_rrc_ssb_periodicityServingCell = -1;  /* T_ssb_periodicityServingCell */
static int hf_nr_rrc_dmrs_TypeA_Position_01 = -1;  /* T_dmrs_TypeA_Position_01 */
static int hf_nr_rrc_subcarrierSpacingSSB = -1;   /* SubcarrierSpacingSSB */
static int hf_nr_rrc_tdd_UL_DL_configurationCommon = -1;  /* T_tdd_UL_DL_configurationCommon */
static int hf_nr_rrc_dl_UL_TransmissionPeriodicity = -1;  /* T_dl_UL_TransmissionPeriodicity */
static int hf_nr_rrc_nrofDownlinkSlots = -1;      /* INTEGER_0_160 */
static int hf_nr_rrc_nrofDownlinkSymbols = -1;    /* INTEGER_0_maxSymbolIndex */
static int hf_nr_rrc_nrofUplinkSlots = -1;        /* INTEGER_0_160 */
static int hf_nr_rrc_nrofUplinkSymbols = -1;      /* INTEGER_0_maxSymbolIndex */
static int hf_nr_rrc_ss_PBCH_BlockPower = -1;     /* INTEGER_M60_50 */
static int hf_nr_rrc_rach_ConfigCommon = -1;      /* RACH_ConfigCommon */
static int hf_nr_rrc_tdd_UL_DL_configurationDedicated = -1;  /* T_tdd_UL_DL_configurationDedicated */
static int hf_nr_rrc_slotSpecificConfigurations = -1;  /* T_slotSpecificConfigurations */
static int hf_nr_rrc_slotSpecificConfigurations_item = -1;  /* T_slotSpecificConfigurations_item */
static int hf_nr_rrc_slotIndex = -1;              /* INTEGER_0_160 */
static int hf_nr_rrc_bandwidthParts = -1;         /* BandwidthParts */
static int hf_nr_rrc_dataScramblingIdentity = -1;  /* NULL */
static int hf_nr_rrc_pdcch_Config = -1;           /* PDCCH_Config */
static int hf_nr_rrc_pdsch_Config = -1;           /* PDSCH_Config */
static int hf_nr_rrc_csi_MeasConfig = -1;         /* CSI_MeasConfig */
static int hf_nr_rrc_pucch_Config = -1;           /* PUCCH_Config */
static int hf_nr_rrc_pusch_Config = -1;           /* PUSCH_Config */
static int hf_nr_rrc_srs_Config = -1;             /* SRS_Config */
static int hf_nr_rrc_sps_Config = -1;             /* SPS_Config */
static int hf_nr_rrc_crossCarrierSchedulingConfig = -1;  /* CrossCarrierSchedulingConfig */
static int hf_nr_rrc_ue_BeamLockFunction = -1;    /* T_ue_BeamLockFunction */
static int hf_nr_rrc_pathlossReferenceLinking = -1;  /* T_pathlossReferenceLinking */
static int hf_nr_rrc_uplink = -1;                 /* T_uplink */
static int hf_nr_rrc_periodicity = -1;            /* NULL */
static int hf_nr_rrc_powerControl = -1;           /* NULL */
static int hf_nr_rrc_transformPrecoder_01 = -1;   /* T_transformPrecoder_01 */
static int hf_nr_rrc_nrofHARQ_processes = -1;     /* INTEGER_1_1 */
static int hf_nr_rrc_repK_RV = -1;                /* T_repK_RV */
static int hf_nr_rrc_priodicity = -1;             /* T_priodicity */
static int hf_nr_rrc_rrcConfiguredUplinkGrant = -1;  /* T_rrcConfiguredUplinkGrant */
static int hf_nr_rrc_setup_16 = -1;               /* T_setup_12 */
static int hf_nr_rrc_timeDomainOffset = -1;       /* NULL */
static int hf_nr_rrc_timeDomainAllocation = -1;   /* NULL */
static int hf_nr_rrc_frequencyDomainAllocation = -1;  /* NULL */
static int hf_nr_rrc_dmrs = -1;                   /* NULL */
static int hf_nr_rrc_mcsAndTBS = -1;              /* NULL */
static int hf_nr_rrc_repK = -1;                   /* NULL */
static int hf_nr_rrc_srs_ResourceSetToReleaseList = -1;  /* SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId */
static int hf_nr_rrc_srs_ResourceSetToReleaseList_item = -1;  /* SRS_ResourceSetId */
static int hf_nr_rrc_srs_ResourceSetToAddModList = -1;  /* SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet */
static int hf_nr_rrc_srs_ResourceSetToAddModList_item = -1;  /* SRS_ResourceSet */
static int hf_nr_rrc_srs_ResourceToReleaseList = -1;  /* SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId */
static int hf_nr_rrc_srs_ResourceToReleaseList_item = -1;  /* SRS_ResourceId */
static int hf_nr_rrc_srs_ResourceToAddModList = -1;  /* SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource */
static int hf_nr_rrc_srs_ResourceToAddModList_item = -1;  /* SRS_Resource */
static int hf_nr_rrc_tpc_SRS_RNTI = -1;           /* BIT_STRING_SIZE_16 */
static int hf_nr_rrc_srs_ResourceSetId = -1;      /* SRS_ResourceSetId */
static int hf_nr_rrc_srs_ResourcesIds = -1;       /* SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId */
static int hf_nr_rrc_srs_ResourcesIds_item = -1;  /* SRS_ResourceId */
static int hf_nr_rrc_aperiodicSRS_ResourceTrigger = -1;  /* NULL */
static int hf_nr_rrc_srs_ResourceId = -1;         /* SRS_ResourceId */
static int hf_nr_rrc_nrofSRS_Ports = -1;          /* T_nrofSRS_Ports */
static int hf_nr_rrc_transmissionComb = -1;       /* T_transmissionComb */
static int hf_nr_rrc_freqDomainPosition = -1;     /* NULL */
static int hf_nr_rrc_freqHopping = -1;            /* INTEGER_0_63 */
static int hf_nr_rrc_groupOrSequenceHopping = -1;  /* INTEGER_0_2 */
static int hf_nr_rrc_resourceType_01 = -1;        /* T_resourceType_01 */
static int hf_nr_rrc_aperiodic_02 = -1;           /* T_aperiodic_01 */
static int hf_nr_rrc_semi_persistent = -1;        /* T_semi_persistent */
static int hf_nr_rrc_periodic_02 = -1;            /* T_periodic_01 */
static int hf_nr_rrc_periodicityAndOffset_02 = -1;  /* T_periodicityAndOffset_02 */
static int hf_nr_rrc_sequenceId = -1;             /* NULL */
static int hf_nr_rrc_antennaSwitching = -1;       /* NULL */
static int hf_nr_rrc_carrierSwitching = -1;       /* NULL */
static int hf_nr_rrc_cyclicShift = -1;            /* INTEGER_0_12 */
static int hf_nr_rrc_spatialRelationInfo = -1;    /* T_spatialRelationInfo */
static int hf_nr_rrc_BandCombinationList_item = -1;  /* BandCombination */
static int hf_nr_rrc_measParameters_MRDC = -1;    /* MeasParameters_MRDC */
static int hf_nr_rrc_rf_Parameters_MRDC = -1;     /* RF_Parameters_MRDC */
static int hf_nr_rrc_phyLayerParameters_MRDC = -1;  /* PhyLayerParameters_MRDC */
static int hf_nr_rrc_supportedBandCombination = -1;  /* BandCombinationList */
static int hf_nr_rrc_supportedBasebandProcessingCombination_MRDC = -1;  /* BasebandProcessingCombination_MRDC */
static int hf_nr_rrc_BasebandProcessingCombination_MRDC_item = -1;  /* LinkedBasebandProcessingCombination */
static int hf_nr_rrc_basebandProcessingCombinationIndex = -1;  /* BasebandProcessingCombinationIndex */
static int hf_nr_rrc_basebandProcessingCombinationLinkedIndex = -1;  /* SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex */
static int hf_nr_rrc_basebandProcessingCombinationLinkedIndex_item = -1;  /* BasebandProcessingCombinationIndex */
static int hf_nr_rrc_intraCarrierConcurrentMeas = -1;  /* T_intraCarrierConcurrentMeas */
static int hf_nr_rrc_independentGapConfig = -1;   /* T_independentGapConfig */
static int hf_nr_rrc_sstd_MeasType1 = -1;         /* T_sstd_MeasType1 */
static int hf_nr_rrc_pdcp_Parameters = -1;        /* PDCP_Parameters */
static int hf_nr_rrc_rlc_Parameters = -1;         /* RLC_Parameters */
static int hf_nr_rrc_mac_Parameters = -1;         /* MAC_Parameters */
static int hf_nr_rrc_phyLayerParameters = -1;     /* PhyLayerParameters */
static int hf_nr_rrc_rf_Parameters = -1;          /* RF_Parameters */
static int hf_nr_rrc_nonCriticalExtension_02 = -1;  /* T_nonCriticalExtension_02 */
static int hf_nr_rrc_supportedBasebandProcessingCombination = -1;  /* SupportedBasebandProcessingCombination */
static int hf_nr_rrc_supportedBandListNR = -1;    /* SupportedBandListNR */
static int hf_nr_rrc_intraBandAsyncFDD = -1;      /* T_intraBandAsyncFDD */
static int hf_nr_rrc_SupportedBandListNR_item = -1;  /* BandNR */
static int hf_nr_rrc_SupportedBasebandProcessingCombination_item = -1;  /* BasebandProcessingCombination */
static int hf_nr_rrc_basebandParametersPerBand = -1;  /* SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand */
static int hf_nr_rrc_basebandParametersPerBand_item = -1;  /* BasebandParametersPerBand */
static int hf_nr_rrc_ca_BandwidthClassDL = -1;    /* CA_BandwidthClass */
static int hf_nr_rrc_ca_BandwidthClassUL = -1;    /* CA_BandwidthClass */
static int hf_nr_rrc_basebandParametersPerCC = -1;  /* SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC */
static int hf_nr_rrc_basebandParametersPerCC_item = -1;  /* BasebandParametersPerCC */
static int hf_nr_rrc_supportedBWPerCC = -1;       /* BWPerCC */
static int hf_nr_rrc_supportedMIMO_CapabilityDL = -1;  /* MIMO_Capability */
static int hf_nr_rrc_supportedMIMO_CapabilityUL = -1;  /* MIMO_Capability */
static int hf_nr_rrc_modulationOrder = -1;        /* ModulationOrder */
static int hf_nr_rrc_subCarrierSpacing = -1;      /* SubCarrierSpacing */
static int hf_nr_rrc_bandNR = -1;                 /* FreqBandIndicatorNR */
static int hf_nr_rrc_dataRateDRB_IP = -1;         /* T_dataRateDRB_IP */
static int hf_nr_rrc_supportedROHC_Profiles = -1;  /* T_supportedROHC_Profiles */
static int hf_nr_rrc_profile0x0000 = -1;          /* BOOLEAN */
static int hf_nr_rrc_maxNumberROHC_ContextSessions = -1;  /* T_maxNumberROHC_ContextSessions */
static int hf_nr_rrc_uplinkOnlyROHC_Profiles = -1;  /* T_uplinkOnlyROHC_Profiles */
static int hf_nr_rrc_continueROHC_Context = -1;   /* T_continueROHC_Context */
static int hf_nr_rrc_outOfOrderDelivery_01 = -1;  /* T_outOfOrderDelivery */
static int hf_nr_rrc_shortSN = -1;                /* T_shortSN */
static int hf_nr_rrc_volteOverNR_PDCP = -1;       /* T_volteOverNR_PDCP */
static int hf_nr_rrc_amWithShortSN = -1;          /* T_amWithShortSN */
static int hf_nr_rrc_umWithShortSN = -1;          /* T_umWithShortSN */
static int hf_nr_rrc_umWIthLongSN = -1;           /* T_umWIthLongSN */
static int hf_nr_rrc_lcp_Restriction = -1;        /* T_lcp_Restriction */
static int hf_nr_rrc_skipUplinkTxDynamic_01 = -1;  /* T_skipUplinkTxDynamic */
static int hf_nr_rrc_logicalChannelSR_DelayTimer = -1;  /* T_logicalChannelSR_DelayTimer */
static int hf_nr_rrc_longDRX_Cycle = -1;          /* T_longDRX_Cycle */
static int hf_nr_rrc_shortDRX_Cycle = -1;         /* T_shortDRX_Cycle */
static int hf_nr_rrc_numberOfSR_Configurations = -1;  /* T_numberOfSR_Configurations */
static int hf_nr_rrc_numberOfConfiguredGrantConfigurations = -1;  /* T_numberOfConfiguredGrantConfigurations */
static int hf_nr_rrc_start = -1;                  /* PhysCellId */
static int hf_nr_rrc_range = -1;                  /* T_range */

/*--- End of included file: packet-nr-rrc-hf.c ---*/
#line 40 "./asn1/nr-rrc/packet-nr-rrc-template.c"

/* Initialize the subtree pointers */
static gint ett_nr_rrc = -1;

/*--- Included file: packet-nr-rrc-ett.c ---*/
#line 1 "./asn1/nr-rrc/packet-nr-rrc-ett.c"
static gint ett_nr_rrc_SCG_ConfigInfo = -1;
static gint ett_nr_rrc_T_criticalExtensions = -1;
static gint ett_nr_rrc_T_c1 = -1;
static gint ett_nr_rrc_T_criticalExtensionsFuture = -1;
static gint ett_nr_rrc_SCG_ConfigInfo_r15_IEs = -1;
static gint ett_nr_rrc_T_nonCriticalExtension = -1;
static gint ett_nr_rrc_ConfigRestrictInfoSCG = -1;
static gint ett_nr_rrc_T_restrictedBasebandCombinationNR_NR = -1;
static gint ett_nr_rrc_DRX_Info = -1;
static gint ett_nr_rrc_CandidateCellInfoList = -1;
static gint ett_nr_rrc_CandidateCellInfo = -1;
static gint ett_nr_rrc_T_cellIdentification = -1;
static gint ett_nr_rrc_T_measResultCell = -1;
static gint ett_nr_rrc_CandidateRS_IndexInfoList = -1;
static gint ett_nr_rrc_CandidateRS_IndexInfo = -1;
static gint ett_nr_rrc_T_measResultSSB = -1;
static gint ett_nr_rrc_MeasResultSSTD = -1;
static gint ett_nr_rrc_BCCH_BCH_Message = -1;
static gint ett_nr_rrc_BCCH_BCH_MessageType = -1;
static gint ett_nr_rrc_T_messageClassExtension = -1;
static gint ett_nr_rrc_DL_DCCH_Message = -1;
static gint ett_nr_rrc_DL_DCCH_MessageType = -1;
static gint ett_nr_rrc_T_c1_01 = -1;
static gint ett_nr_rrc_T_messageClassExtension_01 = -1;
static gint ett_nr_rrc_UL_DCCH_Message = -1;
static gint ett_nr_rrc_UL_DCCH_MessageType = -1;
static gint ett_nr_rrc_T_c1_02 = -1;
static gint ett_nr_rrc_T_messageClassExtension_02 = -1;
static gint ett_nr_rrc_MIB = -1;
static gint ett_nr_rrc_MeasurementReport = -1;
static gint ett_nr_rrc_T_criticalExtensions_01 = -1;
static gint ett_nr_rrc_T_criticalExtensionsFuture_01 = -1;
static gint ett_nr_rrc_MeasurementReport_IEs = -1;
static gint ett_nr_rrc_RRCReconfiguration = -1;
static gint ett_nr_rrc_T_criticalExtensions_02 = -1;
static gint ett_nr_rrc_T_criticalExtensionsFuture_02 = -1;
static gint ett_nr_rrc_RRCReconfiguration_IEs = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId = -1;
static gint ett_nr_rrc_T_nonCriticalExtension_01 = -1;
static gint ett_nr_rrc_RRCReconfigurationComplete = -1;
static gint ett_nr_rrc_T_criticalExtensions_03 = -1;
static gint ett_nr_rrc_T_criticalExtensionsFuture_03 = -1;
static gint ett_nr_rrc_RRCReconfigurationComplete_IEs = -1;
static gint ett_nr_rrc_BandwidthPart = -1;
static gint ett_nr_rrc_CellGroupConfig = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity = -1;
static gint ett_nr_rrc_LCH_Config = -1;
static gint ett_nr_rrc_PhysicalCellGroupConfig = -1;
static gint ett_nr_rrc_SpCellConfig = -1;
static gint ett_nr_rrc_T_reconfigurationWithSync = -1;
static gint ett_nr_rrc_SCellToReleaseList = -1;
static gint ett_nr_rrc_SCellToAddModList = -1;
static gint ett_nr_rrc_SCellConfig = -1;
static gint ett_nr_rrc_CellIndexList = -1;
static gint ett_nr_rrc_CrossCarrierSchedulingConfig = -1;
static gint ett_nr_rrc_T_schedulingCellInfo = -1;
static gint ett_nr_rrc_T_own = -1;
static gint ett_nr_rrc_T_other = -1;
static gint ett_nr_rrc_CSI_MeasConfig = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod = -1;
static gint ett_nr_rrc_T_reportTrigger = -1;
static gint ett_nr_rrc_CSI_ResourceConfig = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource = -1;
static gint ett_nr_rrc_T_resourceType = -1;
static gint ett_nr_rrc_CSI_ResourceSet = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource = -1;
static gint ett_nr_rrc_NZP_CSI_RS_Resource = -1;
static gint ett_nr_rrc_T_csi_RS_timeConfig = -1;
static gint ett_nr_rrc_CSI_SSB_Resource = -1;
static gint ett_nr_rrc_CSI_ReportConfig = -1;
static gint ett_nr_rrc_T_reportConfigType = -1;
static gint ett_nr_rrc_T_periodic = -1;
static gint ett_nr_rrc_T_reportSlotConfig = -1;
static gint ett_nr_rrc_T_semiPersistent = -1;
static gint ett_nr_rrc_T_reportSlotConfig_01 = -1;
static gint ett_nr_rrc_T_aperiodic = -1;
static gint ett_nr_rrc_T_reportQuantity = -1;
static gint ett_nr_rrc_T_cRI_RI_i1_CQI = -1;
static gint ett_nr_rrc_T_reportFreqConfiguration = -1;
static gint ett_nr_rrc_T_groupBasedBeamReporting = -1;
static gint ett_nr_rrc_T_enabled = -1;
static gint ett_nr_rrc_T_disabled = -1;
static gint ett_nr_rrc_CodebookConfig = -1;
static gint ett_nr_rrc_T_codebookType = -1;
static gint ett_nr_rrc_T_type1 = -1;
static gint ett_nr_rrc_T_codebookSubsetRestrictionType1 = -1;
static gint ett_nr_rrc_T_ri_Restriction = -1;
static gint ett_nr_rrc_T_type2 = -1;
static gint ett_nr_rrc_T_ri_Restriction_01 = -1;
static gint ett_nr_rrc_CSI_MeasIdToAddMod = -1;
static gint ett_nr_rrc_FrequencyInfoUL = -1;
static gint ett_nr_rrc_LogicalChannelConfig = -1;
static gint ett_nr_rrc_T_ul_SpecificParameters = -1;
static gint ett_nr_rrc_MAC_CellGroupConfig = -1;
static gint ett_nr_rrc_DRX_Config = -1;
static gint ett_nr_rrc_T_setup = -1;
static gint ett_nr_rrc_T_drx_LongCycleStartOffset = -1;
static gint ett_nr_rrc_T_shortDRX = -1;
static gint ett_nr_rrc_PHR_Config = -1;
static gint ett_nr_rrc_T_setup_01 = -1;
static gint ett_nr_rrc_TAG_Config = -1;
static gint ett_nr_rrc_TAG_ToReleaseList = -1;
static gint ett_nr_rrc_TAG_ToAddModList = -1;
static gint ett_nr_rrc_TAG_ToAddMod = -1;
static gint ett_nr_rrc_BSR_Config = -1;
static gint ett_nr_rrc_MeasConfig = -1;
static gint ett_nr_rrc_T_s_MeasureConfig = -1;
static gint ett_nr_rrc_MeasObjectToRemoveList = -1;
static gint ett_nr_rrc_MeasIdToRemoveList = -1;
static gint ett_nr_rrc_ReportConfigToRemoveList = -1;
static gint ett_nr_rrc_MeasIdToAddModList = -1;
static gint ett_nr_rrc_MeasIdToAddMod = -1;
static gint ett_nr_rrc_MeasObjectNR = -1;
static gint ett_nr_rrc_ReferenceSignalConfig = -1;
static gint ett_nr_rrc_T_ssbPresence = -1;
static gint ett_nr_rrc_T_present = -1;
static gint ett_nr_rrc_T_notPresent = -1;
static gint ett_nr_rrc_SSB_MeasurementTimingConfiguration = -1;
static gint ett_nr_rrc_T_smtc1 = -1;
static gint ett_nr_rrc_T_periodicityAndOffset = -1;
static gint ett_nr_rrc_T_ssb_ToMeasure = -1;
static gint ett_nr_rrc_T_setup_02 = -1;
static gint ett_nr_rrc_T_smtc2 = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId = -1;
static gint ett_nr_rrc_CSI_RS_ResourceConfig_Mobility = -1;
static gint ett_nr_rrc_T_csi_rs_MeasurementBW = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility = -1;
static gint ett_nr_rrc_CSI_RS_Resource_Mobility = -1;
static gint ett_nr_rrc_T_slotConfig = -1;
static gint ett_nr_rrc_Q_OffsetRangeList = -1;
static gint ett_nr_rrc_ThresholdNR = -1;
static gint ett_nr_rrc_CellsToAddModList = -1;
static gint ett_nr_rrc_CellsToAddMod = -1;
static gint ett_nr_rrc_BlackCellsToAddModList = -1;
static gint ett_nr_rrc_BlackCellsToAddMod = -1;
static gint ett_nr_rrc_WhiteCellsToAddModList = -1;
static gint ett_nr_rrc_WhiteCellsToAddMod = -1;
static gint ett_nr_rrc_MeasObjectToAddModList = -1;
static gint ett_nr_rrc_MeasObjectToAddMod = -1;
static gint ett_nr_rrc_T_measObject = -1;
static gint ett_nr_rrc_MeasResults = -1;
static gint ett_nr_rrc_T_measResultNeighCells = -1;
static gint ett_nr_rrc_MeasResultServFreqList = -1;
static gint ett_nr_rrc_MeasResultServFreq = -1;
static gint ett_nr_rrc_MeasResultListNR = -1;
static gint ett_nr_rrc_MeasResultNR = -1;
static gint ett_nr_rrc_T_measResult = -1;
static gint ett_nr_rrc_T_cellResults = -1;
static gint ett_nr_rrc_T_rsIndexResults = -1;
static gint ett_nr_rrc_ResultsSSBCell = -1;
static gint ett_nr_rrc_ResultsCSI_RSCell = -1;
static gint ett_nr_rrc_ResultsPerSSBIndexList = -1;
static gint ett_nr_rrc_ResultsPerSSBIndex = -1;
static gint ett_nr_rrc_ResultsPerCSI_RSIndexList = -1;
static gint ett_nr_rrc_ResultsPerCSI_RSIndex = -1;
static gint ett_nr_rrc_PDCCH_Config = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId = -1;
static gint ett_nr_rrc_T_timing = -1;
static gint ett_nr_rrc_ControlResourceSet = -1;
static gint ett_nr_rrc_SearchSpace = -1;
static gint ett_nr_rrc_T_monitoringSlotPeriodicityAndOffset = -1;
static gint ett_nr_rrc_T_nrofCandidates = -1;
static gint ett_nr_rrc_T_searchSpaceType = -1;
static gint ett_nr_rrc_T_common = -1;
static gint ett_nr_rrc_T_ue_Specific = -1;
static gint ett_nr_rrc_SFI_PDCCH = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI = -1;
static gint ett_nr_rrc_CellToSFI = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination = -1;
static gint ett_nr_rrc_SlotFormatCombination = -1;
static gint ett_nr_rrc_PDCP_Config = -1;
static gint ett_nr_rrc_T_drb = -1;
static gint ett_nr_rrc_T_headerCompression = -1;
static gint ett_nr_rrc_T_rohc = -1;
static gint ett_nr_rrc_T_profiles = -1;
static gint ett_nr_rrc_T_uplinkOnlyROHC = -1;
static gint ett_nr_rrc_T_profiles_01 = -1;
static gint ett_nr_rrc_T_moreThanOneRLC = -1;
static gint ett_nr_rrc_T_primaryPath = -1;
static gint ett_nr_rrc_T_ul_DataSplitThreshold = -1;
static gint ett_nr_rrc_PDSCH_Config = -1;
static gint ett_nr_rrc_T_phaseTracking_RS = -1;
static gint ett_nr_rrc_T_rateMatchResourcesPDSCH = -1;
static gint ett_nr_rrc_T_rateMatchPatterns = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern = -1;
static gint ett_nr_rrc_T_lte_CRS_ToMatchAround = -1;
static gint ett_nr_rrc_T_setup_04 = -1;
static gint ett_nr_rrc_Downlink_PTRS_Config = -1;
static gint ett_nr_rrc_RateMatchPattern = -1;
static gint ett_nr_rrc_T_periodicityAndOffset_01 = -1;
static gint ett_nr_rrc_PUCCH_Config = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet = -1;
static gint ett_nr_rrc_T_format1 = -1;
static gint ett_nr_rrc_T_setup_05 = -1;
static gint ett_nr_rrc_T_format2 = -1;
static gint ett_nr_rrc_T_setup_06 = -1;
static gint ett_nr_rrc_T_format3 = -1;
static gint ett_nr_rrc_T_setup_07 = -1;
static gint ett_nr_rrc_T_format4 = -1;
static gint ett_nr_rrc_T_setup_08 = -1;
static gint ett_nr_rrc_T_schedulingRequestResources = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config = -1;
static gint ett_nr_rrc_PUCCH_ResourceSet = -1;
static gint ett_nr_rrc_PUSCH_Config = -1;
static gint ett_nr_rrc_T_phaseTracking_RS_01 = -1;
static gint ett_nr_rrc_T_uci_on_PUSCH = -1;
static gint ett_nr_rrc_T_setup_09 = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_4_OF_BetaOffsets = -1;
static gint ett_nr_rrc_Uplink_PTRS_Config = -1;
static gint ett_nr_rrc_T_cp_OFDM = -1;
static gint ett_nr_rrc_T_setup_10 = -1;
static gint ett_nr_rrc_T_dft_S_OFDM = -1;
static gint ett_nr_rrc_T_setup_11 = -1;
static gint ett_nr_rrc_BetaOffsets = -1;
static gint ett_nr_rrc_QuantityConfig = -1;
static gint ett_nr_rrc_QuantityConfigRS = -1;
static gint ett_nr_rrc_RACH_ConfigCommon = -1;
static gint ett_nr_rrc_T_groupBconfigured = -1;
static gint ett_nr_rrc_T_prach_RootSequenceIndex = -1;
static gint ett_nr_rrc_CBRA_SSB_ResourceList = -1;
static gint ett_nr_rrc_CBRA_SSB_Resource = -1;
static gint ett_nr_rrc_RACH_ConfigDedicated = -1;
static gint ett_nr_rrc_CFRA_Resources = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource = -1;
static gint ett_nr_rrc_CFRA_SSB_Resource = -1;
static gint ett_nr_rrc_CFRA_CSIRS_Resource = -1;
static gint ett_nr_rrc_RadioBearerConfig = -1;
static gint ett_nr_rrc_SRB_ToAddModList = -1;
static gint ett_nr_rrc_SRB_ToAddMod = -1;
static gint ett_nr_rrc_DRB_ToAddModList = -1;
static gint ett_nr_rrc_DRB_ToAddMod = -1;
static gint ett_nr_rrc_T_cnAssociation = -1;
static gint ett_nr_rrc_DRB_ToReleaseList = -1;
static gint ett_nr_rrc_SecurityConfig = -1;
static gint ett_nr_rrc_ReportConfigNR = -1;
static gint ett_nr_rrc_T_reportType = -1;
static gint ett_nr_rrc_EventTriggerConfig = -1;
static gint ett_nr_rrc_T_eventId = -1;
static gint ett_nr_rrc_T_eventA1 = -1;
static gint ett_nr_rrc_T_eventA2 = -1;
static gint ett_nr_rrc_T_eventA3 = -1;
static gint ett_nr_rrc_T_eventA4 = -1;
static gint ett_nr_rrc_T_eventA5 = -1;
static gint ett_nr_rrc_T_eventA6 = -1;
static gint ett_nr_rrc_PeriodicalReportConfig = -1;
static gint ett_nr_rrc_MeasTriggerQuantity = -1;
static gint ett_nr_rrc_MeasTriggerQuantityOffset = -1;
static gint ett_nr_rrc_MeasReportQuantity = -1;
static gint ett_nr_rrc_ReportConfigToAddModList = -1;
static gint ett_nr_rrc_ReportConfigToAddMod = -1;
static gint ett_nr_rrc_T_reportConfig = -1;
static gint ett_nr_rrc_RLC_Config = -1;
static gint ett_nr_rrc_T_am = -1;
static gint ett_nr_rrc_T_um_Bi_Directional = -1;
static gint ett_nr_rrc_T_um_Uni_Directional_UL = -1;
static gint ett_nr_rrc_T_um_Uni_Directional_DL = -1;
static gint ett_nr_rrc_UL_AM_RLC = -1;
static gint ett_nr_rrc_DL_AM_RLC = -1;
static gint ett_nr_rrc_UL_UM_RLC = -1;
static gint ett_nr_rrc_DL_UM_RLC = -1;
static gint ett_nr_rrc_RLF_TimersAndConstants = -1;
static gint ett_nr_rrc_SchedulingRequestConfig = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId = -1;
static gint ett_nr_rrc_SchedulingRequestToAddMod = -1;
static gint ett_nr_rrc_SDAP_Config = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI = -1;
static gint ett_nr_rrc_SecurityAlgorithmConfig = -1;
static gint ett_nr_rrc_ServingCellConfigCommon = -1;
static gint ett_nr_rrc_T_frequencyInfoDL = -1;
static gint ett_nr_rrc_T_supplementaryUplink = -1;
static gint ett_nr_rrc_T_ssb_PositionsInBurst = -1;
static gint ett_nr_rrc_T_tdd_UL_DL_configurationCommon = -1;
static gint ett_nr_rrc_ServingCellConfigDedicated = -1;
static gint ett_nr_rrc_T_tdd_UL_DL_configurationDedicated = -1;
static gint ett_nr_rrc_T_slotSpecificConfigurations = -1;
static gint ett_nr_rrc_T_slotSpecificConfigurations_item = -1;
static gint ett_nr_rrc_SPS_Config = -1;
static gint ett_nr_rrc_T_uplink = -1;
static gint ett_nr_rrc_T_rrcConfiguredUplinkGrant = -1;
static gint ett_nr_rrc_T_setup_12 = -1;
static gint ett_nr_rrc_SRS_Config = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource = -1;
static gint ett_nr_rrc_SRS_ResourceSet = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId = -1;
static gint ett_nr_rrc_SRS_Resource = -1;
static gint ett_nr_rrc_T_resourceType_01 = -1;
static gint ett_nr_rrc_T_aperiodic_01 = -1;
static gint ett_nr_rrc_T_semi_persistent = -1;
static gint ett_nr_rrc_T_periodic_01 = -1;
static gint ett_nr_rrc_T_periodicityAndOffset_02 = -1;
static gint ett_nr_rrc_BandCombinationList = -1;
static gint ett_nr_rrc_BandCombination = -1;
static gint ett_nr_rrc_UE_MRDC_Capability = -1;
static gint ett_nr_rrc_RF_Parameters_MRDC = -1;
static gint ett_nr_rrc_PhyLayerParameters_MRDC = -1;
static gint ett_nr_rrc_BasebandProcessingCombination_MRDC = -1;
static gint ett_nr_rrc_LinkedBasebandProcessingCombination = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex = -1;
static gint ett_nr_rrc_MeasParameters_MRDC = -1;
static gint ett_nr_rrc_UE_NR_Capability = -1;
static gint ett_nr_rrc_T_nonCriticalExtension_02 = -1;
static gint ett_nr_rrc_PhyLayerParameters = -1;
static gint ett_nr_rrc_RF_Parameters = -1;
static gint ett_nr_rrc_SupportedBandListNR = -1;
static gint ett_nr_rrc_SupportedBasebandProcessingCombination = -1;
static gint ett_nr_rrc_BasebandProcessingCombination = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand = -1;
static gint ett_nr_rrc_BasebandParametersPerBand = -1;
static gint ett_nr_rrc_SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC = -1;
static gint ett_nr_rrc_BasebandParametersPerCC = -1;
static gint ett_nr_rrc_BandNR = -1;
static gint ett_nr_rrc_MIMO_Capability = -1;
static gint ett_nr_rrc_ModulationOrder = -1;
static gint ett_nr_rrc_SubCarrierSpacing = -1;
static gint ett_nr_rrc_PDCP_Parameters = -1;
static gint ett_nr_rrc_T_supportedROHC_Profiles = -1;
static gint ett_nr_rrc_RLC_Parameters = -1;
static gint ett_nr_rrc_MAC_Parameters = -1;
static gint ett_nr_rrc_MeasGapConfig = -1;
static gint ett_nr_rrc_MeasObjectEUTRA = -1;
static gint ett_nr_rrc_MeasResultListEUTRA = -1;
static gint ett_nr_rrc_PhysCellIdRange = -1;
static gint ett_nr_rrc_RA_Resources = -1;
static gint ett_nr_rrc_ReportConfigEUTRA = -1;
static gint ett_nr_rrc_SchedulingRequestResource_Config = -1;

/*--- End of included file: packet-nr-rrc-ett.c ---*/
#line 44 "./asn1/nr-rrc/packet-nr-rrc-template.c"
static gint ett_nr_rrc_UECapabilityInformation = -1;

#if 0
typedef struct {
  guint8 rat_type;
} nr_rrc_private_data_t;

/* Helper function to get or create a struct that will be actx->private_data */
static nr_rrc_private_data_t* nr_rrc_get_private_data(asn1_ctx_t *actx)
{
  if (actx->private_data == NULL) {
    actx->private_data = wmem_new0(wmem_packet_scope(), nr_rrc_private_data_t);
  }
  return (nr_rrc_private_data_t*)actx->private_data;
}

static guint8 private_data_get_rat_type(asn1_ctx_t *actx)
{
  nr_rrc_private_data_t *private_data = (nr_rrc_private_data_t*)nr_rrc_get_private_data(actx);
  return private_data->rat_type;
}

static void private_data_set_rat_type(asn1_ctx_t *actx, guint8 rat_type)
{
  nr_rrc_private_data_t *private_data = (nr_rrc_private_data_t*)nr_rrc_get_private_data(actx);
  private_data->rat_type = rat_type;
}
#endif


/*--- Included file: packet-nr-rrc-fn.c ---*/
#line 1 "./asn1/nr-rrc/packet-nr-rrc-fn.c"
/*--- PDUs declarations ---*/
static int dissect_UECapabilityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_RadioBearerConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);



static int
dissect_nr_rrc_T_eutra_CapabilityInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_UECapabilityInformation_PDU);

  return offset;
}



static int
dissect_nr_rrc_PhysCellId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_ARFCN_ValueNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t T_cellIdentification_sequence[] = {
  { &hf_nr_rrc_physCellId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhysCellId },
  { &hf_nr_rrc_dl_CarrierFreq, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ARFCN_ValueNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_cellIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_cellIdentification, T_cellIdentification_sequence);

  return offset;
}



static int
dissect_nr_rrc_RSRP_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_RSRQ_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_measResultCell_sequence[] = {
  { &hf_nr_rrc_rsrpResultCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RSRP_Range },
  { &hf_nr_rrc_rsrqResultCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RSRQ_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_measResultCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_measResultCell, T_measResultCell_sequence);

  return offset;
}



static int
dissect_nr_rrc_SSB_Index(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_measResultSSB_sequence[] = {
  { &hf_nr_rrc_rsrpResultCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RSRP_Range },
  { &hf_nr_rrc_rsrqResultCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RSRQ_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_measResultSSB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_measResultSSB, T_measResultSSB_sequence);

  return offset;
}


static const per_sequence_t CandidateRS_IndexInfo_sequence[] = {
  { &hf_nr_rrc_ssb_Index    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SSB_Index },
  { &hf_nr_rrc_measResultSSB, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_measResultSSB },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CandidateRS_IndexInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CandidateRS_IndexInfo, CandidateRS_IndexInfo_sequence);

  return offset;
}


static const per_sequence_t CandidateRS_IndexInfoList_sequence_of[1] = {
  { &hf_nr_rrc_CandidateRS_IndexInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CandidateRS_IndexInfo },
};

static int
dissect_nr_rrc_CandidateRS_IndexInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_CandidateRS_IndexInfoList, CandidateRS_IndexInfoList_sequence_of,
                                                  1, maxRS_IndexReport, FALSE);

  return offset;
}


static const per_sequence_t CandidateCellInfo_sequence[] = {
  { &hf_nr_rrc_cellIdentification, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_cellIdentification },
  { &hf_nr_rrc_measResultCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_measResultCell },
  { &hf_nr_rrc_candidateRS_IndexList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_CandidateRS_IndexInfoList },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CandidateCellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CandidateCellInfo, CandidateCellInfo_sequence);

  return offset;
}


static const per_sequence_t CandidateCellInfoList_sequence_of[1] = {
  { &hf_nr_rrc_CandidateCellInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CandidateCellInfo },
};

static int
dissect_nr_rrc_CandidateCellInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_CandidateCellInfoList, CandidateCellInfoList_sequence_of,
                                                  1, maxCellSCG, FALSE);

  return offset;
}


static const per_sequence_t MeasResultSSTD_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasResultSSTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasResultSSTD, MeasResultSSTD_sequence);

  return offset;
}



static int
dissect_nr_rrc_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t T_restrictedBasebandCombinationNR_NR_sequence_of[1] = {
  { &hf_nr_rrc_restrictedBasebandCombinationNR_NR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER },
};

static int
dissect_nr_rrc_T_restrictedBasebandCombinationNR_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_nr_rrc_T_restrictedBasebandCombinationNR_NR, T_restrictedBasebandCombinationNR_NR_sequence_of);

  return offset;
}


static const per_sequence_t ConfigRestrictInfoSCG_sequence[] = {
  { &hf_nr_rrc_restrictedBandCombinationNR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER },
  { &hf_nr_rrc_restrictedBasebandCombinationNR_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_restrictedBasebandCombinationNR_NR },
  { &hf_nr_rrc_maxMeasFreqsSCG_NR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ConfigRestrictInfoSCG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ConfigRestrictInfoSCG, ConfigRestrictInfoSCG_sequence);

  return offset;
}


static const per_sequence_t DRX_Info_sequence[] = {
  { &hf_nr_rrc_cycle        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER },
  { &hf_nr_rrc_offset       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_DRX_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_DRX_Info, DRX_Info_sequence);

  return offset;
}



static int
dissect_nr_rrc_T_sourceConfigSCG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_nr_rrc_RRCReconfiguration_PDU);

  return offset;
}



static int
dissect_nr_rrc_P_Max(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30, 33U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_T_mcg_RB_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_RadioBearerConfiguration_PDU);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_nonCriticalExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_nonCriticalExtension, T_nonCriticalExtension_sequence);

  return offset;
}


static const per_sequence_t SCG_ConfigInfo_r15_IEs_sequence[] = {
  { &hf_nr_rrc_eutra_CapabilityInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_eutra_CapabilityInfo },
  { &hf_nr_rrc_candidateCellInfoList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CandidateCellInfoList },
  { &hf_nr_rrc_measResultSSTD, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasResultSSTD },
  { &hf_nr_rrc_configRestrictInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ConfigRestrictInfoSCG },
  { &hf_nr_rrc_drx_InfoMCG  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_DRX_Info },
  { &hf_nr_rrc_sourceConfigSCG, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_sourceConfigSCG },
  { &hf_nr_rrc_p_maxFR1     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_P_Max },
  { &hf_nr_rrc_mcg_RB_Config, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_mcg_RB_Config },
  { &hf_nr_rrc_nonCriticalExtension, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_nonCriticalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SCG_ConfigInfo_r15_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SCG_ConfigInfo_r15_IEs, SCG_ConfigInfo_r15_IEs_sequence);

  return offset;
}



static int
dissect_nr_rrc_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string nr_rrc_T_c1_vals[] = {
  {   0, "scg-ConfigInfo-r15" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_choice[] = {
  {   0, &hf_nr_rrc_scg_ConfigInfo_r15, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_SCG_ConfigInfo_r15_IEs },
  {   1, &hf_nr_rrc_spare3       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   2, &hf_nr_rrc_spare2       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   3, &hf_nr_rrc_spare1       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_c1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_c1, T_c1_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_criticalExtensionsFuture(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_criticalExtensionsFuture, T_criticalExtensionsFuture_sequence);

  return offset;
}


static const value_string nr_rrc_T_criticalExtensions_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_choice[] = {
  {   0, &hf_nr_rrc_c1           , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_c1 },
  {   1, &hf_nr_rrc_criticalExtensionsFuture, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_criticalExtensionsFuture },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_criticalExtensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_criticalExtensions, T_criticalExtensions_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SCG_ConfigInfo_sequence[] = {
  { &hf_nr_rrc_criticalExtensions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_criticalExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SCG_ConfigInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SCG_ConfigInfo, SCG_ConfigInfo_sequence);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 7U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_halfFrameIndex_vals[] = {
  {   0, "firstHalf" },
  {   1, "secondHalf" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_halfFrameIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, NULL);

  return offset;
}


static const value_string nr_rrc_SubcarrierSpacing_vals[] = {
  {   0, "kHz15" },
  {   1, "kHz30" },
  {   2, "kHz60" },
  {   3, "kHz120" },
  { 0, NULL }
};


static int
dissect_nr_rrc_SubcarrierSpacing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 11U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_dmrs_TypeA_Position_vals[] = {
  {   0, "pos2" },
  {   1, "pos3" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_dmrs_TypeA_Position(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_cellBarred_vals[] = {
  {   0, "barred" },
  {   1, "notBarred" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_cellBarred(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_intraFreqReselection_vals[] = {
  {   0, "allowed" },
  {   1, "notAllowed" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_intraFreqReselection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     0, 0, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t MIB_sequence[] = {
  { &hf_nr_rrc_ssb_IndexExplicit, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_7 },
  { &hf_nr_rrc_halfFrameIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_halfFrameIndex },
  { &hf_nr_rrc_systemFrameNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BIT_STRING_SIZE_10 },
  { &hf_nr_rrc_subCarrierSpacingCommon, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SubcarrierSpacing },
  { &hf_nr_rrc_ssb_subcarrierOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_11 },
  { &hf_nr_rrc_dmrs_TypeA_Position, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_dmrs_TypeA_Position },
  { &hf_nr_rrc_pdcchConfigSIB1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_255 },
  { &hf_nr_rrc_cellBarred   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_cellBarred },
  { &hf_nr_rrc_intraFreqReselection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_intraFreqReselection },
  { &hf_nr_rrc_spare        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BIT_STRING_SIZE_0 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MIB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "MIB");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MIB, MIB_sequence);

  return offset;
}


static const per_sequence_t T_messageClassExtension_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_messageClassExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_messageClassExtension, T_messageClassExtension_sequence);

  return offset;
}


static const value_string nr_rrc_BCCH_BCH_MessageType_vals[] = {
  {   0, "mib" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t BCCH_BCH_MessageType_choice[] = {
  {   0, &hf_nr_rrc_mib          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_MIB },
  {   1, &hf_nr_rrc_messageClassExtension, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_messageClassExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_BCCH_BCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_BCCH_BCH_MessageType, BCCH_BCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BCCH_BCH_Message_sequence[] = {
  { &hf_nr_rrc_message      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BCCH_BCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BCCH_BCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_item *ti;

  col_set_str(actx->pinfo->cinfo, COL_PROTOCOL, "NR RRC");
  col_clear(actx->pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_nr_rrc);

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BCCH_BCH_Message, BCCH_BCH_Message_sequence);

  return offset;
}



static int
dissect_nr_rrc_RRC_TransactionIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_SRB_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_reestablishPDCP_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_reestablishPDCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_discardTimer_vals[] = {
  {   0, "ms10" },
  {   1, "ms20" },
  {   2, "ms30" },
  {   3, "ms40" },
  {   4, "ms50" },
  {   5, "ms60" },
  {   6, "ms75" },
  {   7, "ms100" },
  {   8, "ms150" },
  {   9, "ms200" },
  {  10, "ms250" },
  {  11, "ms300" },
  {  12, "ms500" },
  {  13, "ms750" },
  {  14, "ms1500" },
  {  15, "infinity" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_discardTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_pdcp_SN_Size_UL_vals[] = {
  {   0, "len12bits" },
  {   1, "len18bits" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_pdcp_SN_Size_UL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_pdcp_SN_Size_DL_vals[] = {
  {   0, "len12bits" },
  {   1, "len18bits" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_pdcp_SN_Size_DL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16383U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t T_profiles_sequence[] = {
  { &hf_nr_rrc_profile0x0001, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0002, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0003, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0004, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0006, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0101, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0102, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0103, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0104, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_profiles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_profiles, T_profiles_sequence);

  return offset;
}


static const per_sequence_t T_profiles_01_sequence[] = {
  { &hf_nr_rrc_profile0x0006, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_profiles_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_profiles_01, T_profiles_01_sequence);

  return offset;
}


static const per_sequence_t T_uplinkOnlyROHC_sequence[] = {
  { &hf_nr_rrc_maxCID       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_16383 },
  { &hf_nr_rrc_profiles_01  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_profiles_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_uplinkOnlyROHC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_uplinkOnlyROHC, T_uplinkOnlyROHC_sequence);

  return offset;
}


static const per_sequence_t T_rohc_sequence[] = {
  { &hf_nr_rrc_maxCID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_16383 },
  { &hf_nr_rrc_profiles     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_profiles },
  { &hf_nr_rrc_uplinkOnlyROHC, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_uplinkOnlyROHC },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_rohc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_rohc, T_rohc_sequence);

  return offset;
}


static const value_string nr_rrc_T_headerCompression_vals[] = {
  {   0, "notUsed" },
  {   1, "rohc" },
  { 0, NULL }
};

static const per_choice_t T_headerCompression_choice[] = {
  {   0, &hf_nr_rrc_notUsed      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_rohc         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_rohc },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_headerCompression(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_headerCompression, T_headerCompression_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_drb_sequence[] = {
  { &hf_nr_rrc_discardTimer , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_discardTimer },
  { &hf_nr_rrc_pdcp_SN_Size_UL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_pdcp_SN_Size_UL },
  { &hf_nr_rrc_pdcp_SN_Size_DL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_pdcp_SN_Size_DL },
  { &hf_nr_rrc_headerCompression, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_headerCompression },
  { &hf_nr_rrc_integrityProtection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_statusReportRequired, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_drb(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_drb, T_drb_sequence);

  return offset;
}



static int
dissect_nr_rrc_CellGroupId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxSCellGroups, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_LogicalChannelIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_primaryPath_sequence[] = {
  { &hf_nr_rrc_cellGroup    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CellGroupId },
  { &hf_nr_rrc_logicalChannel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_LogicalChannelIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_primaryPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_primaryPath, T_primaryPath_sequence);

  return offset;
}


static const value_string nr_rrc_T_setup_03_vals[] = {
  {   0, "b0" },
  {   1, "b100" },
  {   2, "b200" },
  {   3, "b400" },
  {   4, "b800" },
  {   5, "b1600" },
  {   6, "b3200" },
  {   7, "b6400" },
  {   8, "b12800" },
  {   9, "b25600" },
  {  10, "b51200" },
  {  11, "b102400" },
  {  12, "b204800" },
  {  13, "b409600" },
  {  14, "b819200" },
  {  15, "b1228800" },
  {  16, "b1638400" },
  {  17, "b2457600" },
  {  18, "b3276800" },
  {  19, "b4096000" },
  {  20, "b4915200" },
  {  21, "b5734400" },
  {  22, "b6553600" },
  {  23, "infinity" },
  {  24, "spare8" },
  {  25, "spare7" },
  {  26, "spare6" },
  {  27, "spare5" },
  {  28, "spare4" },
  {  29, "spare3" },
  {  30, "spare2" },
  {  31, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_setup_03_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_setup_03_vals);


static int
dissect_nr_rrc_T_setup_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_ul_DataSplitThreshold_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_ul_DataSplitThreshold_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_03     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_ul_DataSplitThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_ul_DataSplitThreshold, T_ul_DataSplitThreshold_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_moreThanOneRLC_sequence[] = {
  { &hf_nr_rrc_primaryPath  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_primaryPath },
  { &hf_nr_rrc_ul_DataSplitThreshold, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_ul_DataSplitThreshold },
  { &hf_nr_rrc_ul_Duplication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_moreThanOneRLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_moreThanOneRLC, T_moreThanOneRLC_sequence);

  return offset;
}


static const value_string nr_rrc_T_t_Reordering_vals[] = {
  {   0, "ms0" },
  {   1, "ms5" },
  {   2, "ms10" },
  {   3, "ms15" },
  {   4, "ms20" },
  {   5, "ms30" },
  {   6, "ms40" },
  {   7, "ms60" },
  {   8, "ms50" },
  {   9, "ms80" },
  {  10, "ms100" },
  {  11, "ms120" },
  {  12, "ms140" },
  {  13, "ms160" },
  {  14, "ms180" },
  {  15, "ms200" },
  {  16, "ms220" },
  {  17, "ms240" },
  {  18, "ms260" },
  {  19, "ms280" },
  {  20, "ms300" },
  {  21, "ms500" },
  {  22, "ms750" },
  {  23, "ms1000" },
  {  24, "ms1250" },
  {  25, "ms1500" },
  {  26, "ms1750" },
  {  27, "ms2000" },
  {  28, "ms2250" },
  {  29, "ms2500" },
  {  30, "ms2750" },
  {  31, "ms3000" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_t_Reordering_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_t_Reordering_vals);


static int
dissect_nr_rrc_T_t_Reordering(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PDCP_Config_sequence[] = {
  { &hf_nr_rrc_drb          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_drb },
  { &hf_nr_rrc_moreThanOneRLC, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_moreThanOneRLC },
  { &hf_nr_rrc_t_Reordering , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_t_Reordering },
  { &hf_nr_rrc_outOfOrderDelivery, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PDCP_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PDCP_Config, PDCP_Config_sequence);

  return offset;
}


static const per_sequence_t SRB_ToAddMod_sequence[] = {
  { &hf_nr_rrc_srb_Identity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRB_Identity },
  { &hf_nr_rrc_reestablishPDCP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_reestablishPDCP },
  { &hf_nr_rrc_pdcp_Config  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_PDCP_Config },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SRB_ToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SRB_ToAddMod, SRB_ToAddMod_sequence);

  return offset;
}


static const per_sequence_t SRB_ToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_SRB_ToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRB_ToAddMod },
};

static int
dissect_nr_rrc_SRB_ToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SRB_ToAddModList, SRB_ToAddModList_sequence_of,
                                                  1, 2, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            3U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_PDUsessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string nr_rrc_T_sdap_Header_DL_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_sdap_Header_DL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_sdap_Header_UL_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_sdap_Header_UL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_QFI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxQFI, NULL, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI_sequence_of[1] = {
  { &hf_nr_rrc_mappedQoSflows_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_QFI },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI, SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI_sequence_of,
                                                  0, maxNrofQFIs, FALSE);

  return offset;
}


static const per_sequence_t SDAP_Config_sequence[] = {
  { &hf_nr_rrc_pduSession   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PDUsessionID },
  { &hf_nr_rrc_sdap_Header_DL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_sdap_Header_DL },
  { &hf_nr_rrc_sdap_Header_UL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_sdap_Header_UL },
  { &hf_nr_rrc_defaultDRB   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_reflectiveQoS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_mappedQoSflows, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SDAP_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SDAP_Config, SDAP_Config_sequence);

  return offset;
}


static const value_string nr_rrc_T_cnAssociation_vals[] = {
  {   0, "eps-BearerIdentity" },
  {   1, "sdap-Config" },
  { 0, NULL }
};

static const per_choice_t T_cnAssociation_choice[] = {
  {   0, &hf_nr_rrc_eps_BearerIdentity, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_15 },
  {   1, &hf_nr_rrc_sdap_Config  , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_SDAP_Config },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_cnAssociation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_cnAssociation, T_cnAssociation_choice,
                                 NULL);

  return offset;
}



static int
dissect_nr_rrc_DRB_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            4U, 32U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_reestablishPDCP_01_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_reestablishPDCP_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_recoverPDCP_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_recoverPDCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t DRB_ToAddMod_sequence[] = {
  { &hf_nr_rrc_cnAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_cnAssociation },
  { &hf_nr_rrc_drb_Identity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_DRB_Identity },
  { &hf_nr_rrc_reestablishPDCP_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_reestablishPDCP_01 },
  { &hf_nr_rrc_recoverPDCP  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_recoverPDCP },
  { &hf_nr_rrc_pdcp_Config  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_PDCP_Config },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_DRB_ToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_DRB_ToAddMod, DRB_ToAddMod_sequence);

  return offset;
}


static const per_sequence_t DRB_ToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_DRB_ToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_DRB_ToAddMod },
};

static int
dissect_nr_rrc_DRB_ToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_DRB_ToAddModList, DRB_ToAddModList_sequence_of,
                                                  1, maxDRB, FALSE);

  return offset;
}


static const per_sequence_t DRB_ToReleaseList_sequence_of[1] = {
  { &hf_nr_rrc_DRB_ToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_DRB_Identity },
};

static int
dissect_nr_rrc_DRB_ToReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_DRB_ToReleaseList, DRB_ToReleaseList_sequence_of,
                                                  1, maxDRB, FALSE);

  return offset;
}


static const value_string nr_rrc_CipheringAlgorithm_vals[] = {
  {   0, "nea0" },
  {   1, "nea1" },
  {   2, "nea2" },
  {   3, "nea3" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_CipheringAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_IntegrityProtAlgorithm_vals[] = {
  {   0, "nia0" },
  {   1, "nia1" },
  {   2, "nia2" },
  {   3, "nia3" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_IntegrityProtAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SecurityAlgorithmConfig_sequence[] = {
  { &hf_nr_rrc_cipheringAlgorithm, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CipheringAlgorithm },
  { &hf_nr_rrc_integrityProtAlgorithm, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_IntegrityProtAlgorithm },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SecurityAlgorithmConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SecurityAlgorithmConfig, SecurityAlgorithmConfig_sequence);

  return offset;
}


static const value_string nr_rrc_T_keyToUse_vals[] = {
  {   0, "keNB" },
  {   1, "s-KgNB" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_keyToUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t SecurityConfig_sequence[] = {
  { &hf_nr_rrc_securityAlgorithmConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_SecurityAlgorithmConfig },
  { &hf_nr_rrc_keyToUse     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_keyToUse },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SecurityConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SecurityConfig, SecurityConfig_sequence);

  return offset;
}


static const per_sequence_t RadioBearerConfig_sequence[] = {
  { &hf_nr_rrc_srb_ToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SRB_ToAddModList },
  { &hf_nr_rrc_srb_ToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_3 },
  { &hf_nr_rrc_drb_ToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_DRB_ToAddModList },
  { &hf_nr_rrc_drb_ToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_DRB_ToReleaseList },
  { &hf_nr_rrc_securityConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SecurityConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RadioBearerConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RadioBearerConfig, RadioBearerConfig_sequence);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_reestablishRLC_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_reestablishRLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_SN_FieldLength_AM_vals[] = {
  {   0, "size12" },
  {   1, "size18" },
  { 0, NULL }
};


static int
dissect_nr_rrc_SN_FieldLength_AM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_PollRetransmit_vals[] = {
  {   0, "ms5" },
  {   1, "ms10" },
  {   2, "ms15" },
  {   3, "ms20" },
  {   4, "ms25" },
  {   5, "ms30" },
  {   6, "ms35" },
  {   7, "ms40" },
  {   8, "ms45" },
  {   9, "ms50" },
  {  10, "ms55" },
  {  11, "ms60" },
  {  12, "ms65" },
  {  13, "ms70" },
  {  14, "ms75" },
  {  15, "ms80" },
  {  16, "ms85" },
  {  17, "ms90" },
  {  18, "ms95" },
  {  19, "ms100" },
  {  20, "ms105" },
  {  21, "ms110" },
  {  22, "ms115" },
  {  23, "ms120" },
  {  24, "ms125" },
  {  25, "ms130" },
  {  26, "ms135" },
  {  27, "ms140" },
  {  28, "ms145" },
  {  29, "ms150" },
  {  30, "ms155" },
  {  31, "ms160" },
  {  32, "ms165" },
  {  33, "ms170" },
  {  34, "ms175" },
  {  35, "ms180" },
  {  36, "ms185" },
  {  37, "ms190" },
  {  38, "ms195" },
  {  39, "ms200" },
  {  40, "ms205" },
  {  41, "ms210" },
  {  42, "ms215" },
  {  43, "ms220" },
  {  44, "ms225" },
  {  45, "ms230" },
  {  46, "ms235" },
  {  47, "ms240" },
  {  48, "ms245" },
  {  49, "ms250" },
  {  50, "ms300" },
  {  51, "ms350" },
  {  52, "ms400" },
  {  53, "ms450" },
  {  54, "ms500" },
  {  55, "ms800" },
  {  56, "ms1000" },
  {  57, "ms2000" },
  {  58, "ms4000" },
  {  59, "spare5" },
  {  60, "spare4" },
  {  61, "spare3" },
  {  62, "spare2" },
  {  63, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_PollRetransmit_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_PollRetransmit_vals);


static int
dissect_nr_rrc_T_PollRetransmit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_PollPDU_vals[] = {
  {   0, "p4" },
  {   1, "p8" },
  {   2, "p16" },
  {   3, "p32" },
  {   4, "p64" },
  {   5, "p128" },
  {   6, "p256" },
  {   7, "p512" },
  {   8, "p1024" },
  {   9, "p2048" },
  {  10, "p4096" },
  {  11, "p6144" },
  {  12, "p8192" },
  {  13, "p12288" },
  {  14, "p16384" },
  {  15, "p20480" },
  {  16, "p24576" },
  {  17, "p28672" },
  {  18, "p32768" },
  {  19, "p40960" },
  {  20, "p49152" },
  {  21, "p57344" },
  {  22, "p65536" },
  {  23, "infinity" },
  {  24, "spare8" },
  {  25, "spare7" },
  {  26, "spare6" },
  {  27, "spare5" },
  {  28, "spare4" },
  {  29, "spare3" },
  {  30, "spare2" },
  {  31, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_PollPDU_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_PollPDU_vals);


static int
dissect_nr_rrc_PollPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_PollByte_vals[] = {
  {   0, "kB1" },
  {   1, "kB2" },
  {   2, "kB5" },
  {   3, "kB8" },
  {   4, "kB10" },
  {   5, "kB15" },
  {   6, "kB25" },
  {   7, "kB50" },
  {   8, "kB75" },
  {   9, "kB100" },
  {  10, "kB125" },
  {  11, "kB250" },
  {  12, "kB375" },
  {  13, "kB500" },
  {  14, "kB750" },
  {  15, "kB1000" },
  {  16, "kB1250" },
  {  17, "kB1500" },
  {  18, "kB2000" },
  {  19, "kB3000" },
  {  20, "kB4000" },
  {  21, "kB4500" },
  {  22, "kB5000" },
  {  23, "kB5500" },
  {  24, "kB6000" },
  {  25, "kB6500" },
  {  26, "kB7000" },
  {  27, "kB7500" },
  {  28, "mB8" },
  {  29, "mB9" },
  {  30, "mB10" },
  {  31, "mB11" },
  {  32, "mB12" },
  {  33, "mB13" },
  {  34, "mB14" },
  {  35, "mB15" },
  {  36, "mB16" },
  {  37, "mB17" },
  {  38, "mB18" },
  {  39, "mB20" },
  {  40, "mB25" },
  {  41, "mB30" },
  {  42, "mB40" },
  {  43, "infinity" },
  {  44, "spare20" },
  {  45, "spare19" },
  {  46, "spare18" },
  {  47, "spare17" },
  {  48, "spare16" },
  {  49, "spare15" },
  {  50, "spare14" },
  {  51, "spare13" },
  {  52, "spare12" },
  {  53, "spare11" },
  {  54, "spare10" },
  {  55, "spare9" },
  {  56, "spare8" },
  {  57, "spare7" },
  {  58, "spare6" },
  {  59, "spare5" },
  {  60, "spare4" },
  {  61, "spare3" },
  {  62, "spare2" },
  {  63, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_PollByte_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_PollByte_vals);


static int
dissect_nr_rrc_PollByte(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_maxRetxThreshold_vals[] = {
  {   0, "t1" },
  {   1, "t2" },
  {   2, "t3" },
  {   3, "t4" },
  {   4, "t6" },
  {   5, "t8" },
  {   6, "t16" },
  {   7, "t32" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_maxRetxThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t UL_AM_RLC_sequence[] = {
  { &hf_nr_rrc_sn_FieldLength, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SN_FieldLength_AM },
  { &hf_nr_rrc_t_PollRetransmit, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_PollRetransmit },
  { &hf_nr_rrc_pollPDU      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PollPDU },
  { &hf_nr_rrc_pollByte     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PollByte },
  { &hf_nr_rrc_maxRetxThreshold, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_maxRetxThreshold },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_UL_AM_RLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_UL_AM_RLC, UL_AM_RLC_sequence);

  return offset;
}


static const value_string nr_rrc_T_Reassembly_vals[] = {
  {   0, "ms0" },
  {   1, "ms5" },
  {   2, "ms10" },
  {   3, "ms15" },
  {   4, "ms20" },
  {   5, "ms25" },
  {   6, "ms30" },
  {   7, "ms35" },
  {   8, "ms40" },
  {   9, "ms45" },
  {  10, "ms50" },
  {  11, "ms55" },
  {  12, "ms60" },
  {  13, "ms65" },
  {  14, "ms70" },
  {  15, "ms75" },
  {  16, "ms80" },
  {  17, "ms85" },
  {  18, "ms90" },
  {  19, "ms95" },
  {  20, "ms100" },
  {  21, "ms110" },
  {  22, "ms120" },
  {  23, "ms130" },
  {  24, "ms140" },
  {  25, "ms150" },
  {  26, "ms160" },
  {  27, "ms170" },
  {  28, "ms180" },
  {  29, "ms190" },
  {  30, "ms200" },
  {  31, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_Reassembly_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_Reassembly_vals);


static int
dissect_nr_rrc_T_Reassembly(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_StatusProhibit_vals[] = {
  {   0, "ms0" },
  {   1, "ms5" },
  {   2, "ms10" },
  {   3, "ms15" },
  {   4, "ms20" },
  {   5, "ms25" },
  {   6, "ms30" },
  {   7, "ms35" },
  {   8, "ms40" },
  {   9, "ms45" },
  {  10, "ms50" },
  {  11, "ms55" },
  {  12, "ms60" },
  {  13, "ms65" },
  {  14, "ms70" },
  {  15, "ms75" },
  {  16, "ms80" },
  {  17, "ms85" },
  {  18, "ms90" },
  {  19, "ms95" },
  {  20, "ms100" },
  {  21, "ms105" },
  {  22, "ms110" },
  {  23, "ms115" },
  {  24, "ms120" },
  {  25, "ms125" },
  {  26, "ms130" },
  {  27, "ms135" },
  {  28, "ms140" },
  {  29, "ms145" },
  {  30, "ms150" },
  {  31, "ms155" },
  {  32, "ms160" },
  {  33, "ms165" },
  {  34, "ms170" },
  {  35, "ms175" },
  {  36, "ms180" },
  {  37, "ms185" },
  {  38, "ms190" },
  {  39, "ms195" },
  {  40, "ms200" },
  {  41, "ms205" },
  {  42, "ms210" },
  {  43, "ms215" },
  {  44, "ms220" },
  {  45, "ms225" },
  {  46, "ms230" },
  {  47, "ms235" },
  {  48, "ms240" },
  {  49, "ms245" },
  {  50, "ms250" },
  {  51, "ms300" },
  {  52, "ms350" },
  {  53, "ms400" },
  {  54, "ms450" },
  {  55, "ms500" },
  {  56, "ms800" },
  {  57, "ms1000" },
  {  58, "ms1200" },
  {  59, "ms1600" },
  {  60, "ms2000" },
  {  61, "ms2400" },
  {  62, "spare2" },
  {  63, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_StatusProhibit_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_StatusProhibit_vals);


static int
dissect_nr_rrc_T_StatusProhibit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t DL_AM_RLC_sequence[] = {
  { &hf_nr_rrc_sn_FieldLength, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SN_FieldLength_AM },
  { &hf_nr_rrc_t_Reassembly , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_Reassembly },
  { &hf_nr_rrc_t_StatusProhibit, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_StatusProhibit },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_DL_AM_RLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_DL_AM_RLC, DL_AM_RLC_sequence);

  return offset;
}


static const per_sequence_t T_am_sequence[] = {
  { &hf_nr_rrc_ul_AM_RLC    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_UL_AM_RLC },
  { &hf_nr_rrc_dl_AM_RLC    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_DL_AM_RLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_am(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_am, T_am_sequence);

  return offset;
}


static const value_string nr_rrc_SN_FieldLength_UM_vals[] = {
  {   0, "size6" },
  {   1, "size12" },
  { 0, NULL }
};


static int
dissect_nr_rrc_SN_FieldLength_UM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t UL_UM_RLC_sequence[] = {
  { &hf_nr_rrc_sn_FieldLength_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SN_FieldLength_UM },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_UL_UM_RLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_UL_UM_RLC, UL_UM_RLC_sequence);

  return offset;
}


static const per_sequence_t DL_UM_RLC_sequence[] = {
  { &hf_nr_rrc_sn_FieldLength_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SN_FieldLength_UM },
  { &hf_nr_rrc_t_Reassembly , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_Reassembly },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_DL_UM_RLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_DL_UM_RLC, DL_UM_RLC_sequence);

  return offset;
}


static const per_sequence_t T_um_Bi_Directional_sequence[] = {
  { &hf_nr_rrc_ul_UM_RLC    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_UL_UM_RLC },
  { &hf_nr_rrc_dl_UM_RLC    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_DL_UM_RLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_um_Bi_Directional(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_um_Bi_Directional, T_um_Bi_Directional_sequence);

  return offset;
}


static const per_sequence_t T_um_Uni_Directional_UL_sequence[] = {
  { &hf_nr_rrc_ul_UM_RLC    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_UL_UM_RLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_um_Uni_Directional_UL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_um_Uni_Directional_UL, T_um_Uni_Directional_UL_sequence);

  return offset;
}


static const per_sequence_t T_um_Uni_Directional_DL_sequence[] = {
  { &hf_nr_rrc_dl_UM_RLC    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_DL_UM_RLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_um_Uni_Directional_DL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_um_Uni_Directional_DL, T_um_Uni_Directional_DL_sequence);

  return offset;
}


static const value_string nr_rrc_RLC_Config_vals[] = {
  {   0, "am" },
  {   1, "um-Bi-Directional" },
  {   2, "um-Uni-Directional-UL" },
  {   3, "um-Uni-Directional-DL" },
  { 0, NULL }
};

static const per_choice_t RLC_Config_choice[] = {
  {   0, &hf_nr_rrc_am           , ASN1_EXTENSION_ROOT    , dissect_nr_rrc_T_am },
  {   1, &hf_nr_rrc_um_Bi_Directional, ASN1_EXTENSION_ROOT    , dissect_nr_rrc_T_um_Bi_Directional },
  {   2, &hf_nr_rrc_um_Uni_Directional_UL, ASN1_EXTENSION_ROOT    , dissect_nr_rrc_T_um_Uni_Directional_UL },
  {   3, &hf_nr_rrc_um_Uni_Directional_DL, ASN1_EXTENSION_ROOT    , dissect_nr_rrc_T_um_Uni_Directional_DL },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_RLC_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_RLC_Config, RLC_Config_choice,
                                 NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_prioritisedBitRate_vals[] = {
  {   0, "kBps0" },
  {   1, "kBps8" },
  {   2, "kBps16" },
  {   3, "kBps32" },
  {   4, "kBps64" },
  {   5, "kBps128" },
  {   6, "kBps256" },
  {   7, "kBps512" },
  {   8, "kBps1024" },
  {   9, "kBps2048" },
  {  10, "kBps4096" },
  {  11, "kBps8192" },
  {  12, "kBps16384" },
  {  13, "kBps32768" },
  {  14, "kBps65536" },
  {  15, "infinity" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_prioritisedBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_bucketSizeDuration_vals[] = {
  {   0, "ms50" },
  {   1, "ms100" },
  {   2, "ms150" },
  {   3, "ms300" },
  {   4, "ms500" },
  {   5, "ms1000" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_bucketSizeDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_maxLCid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxLCid, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_ul_SpecificParameters_sequence[] = {
  { &hf_nr_rrc_priority     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_16 },
  { &hf_nr_rrc_prioritisedBitRate, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_prioritisedBitRate },
  { &hf_nr_rrc_bucketSizeDuration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_bucketSizeDuration },
  { &hf_nr_rrc_allowedSubCarrierSpacing, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SubcarrierSpacing },
  { &hf_nr_rrc_allowedTiming, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_logicalChannelGroup, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_maxLCid },
  { &hf_nr_rrc_logicalChannelSR_Mask, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_logicalChannelSR_DelayTimerApplied, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_ul_SpecificParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_ul_SpecificParameters, T_ul_SpecificParameters_sequence);

  return offset;
}


static const per_sequence_t LogicalChannelConfig_sequence[] = {
  { &hf_nr_rrc_ul_SpecificParameters, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_ul_SpecificParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_LogicalChannelConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_LogicalChannelConfig, LogicalChannelConfig_sequence);

  return offset;
}


static const per_sequence_t LCH_Config_sequence[] = {
  { &hf_nr_rrc_logicalChannelIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_LogicalChannelIdentity },
  { &hf_nr_rrc_servedRadioBearer, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_32 },
  { &hf_nr_rrc_reestablishRLC, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_reestablishRLC },
  { &hf_nr_rrc_rlc_Config   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RLC_Config },
  { &hf_nr_rrc_mac_LogicalChannelConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_LogicalChannelConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_LCH_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_LCH_Config, LCH_Config_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config_sequence_of[1] = {
  { &hf_nr_rrc_rlc_BearerToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_LCH_Config },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config, SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config_sequence_of,
                                                  1, maxLCH, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity_sequence_of[1] = {
  { &hf_nr_rrc_rlc_BearerToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_LogicalChannelIdentity },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity, SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity_sequence_of,
                                                  1, maxLCH, FALSE);

  return offset;
}


static const value_string nr_rrc_T_drx_onDurationTimer_vals[] = {
  {   0, "ms1-32" },
  {   1, "ms2-32" },
  {   2, "ms3-32" },
  {   3, "ms4-32" },
  {   4, "ms5-32" },
  {   5, "ms6-32" },
  {   6, "ms7-32" },
  {   7, "ms8-32" },
  {   8, "ms9-32" },
  {   9, "ms10-32" },
  {  10, "ms11-32" },
  {  11, "ms12-32" },
  {  12, "ms13-32" },
  {  13, "ms14-32" },
  {  14, "ms15-32" },
  {  15, "ms16-32" },
  {  16, "ms17-32" },
  {  17, "ms18-32" },
  {  18, "ms19-32" },
  {  19, "ms-20-32" },
  {  20, "ms21-32" },
  {  21, "ms22-32" },
  {  22, "ms23-32" },
  {  23, "ms24-32" },
  {  24, "ms25-32" },
  {  25, "ms26-32" },
  {  26, "ms27-32" },
  {  27, "ms28-32" },
  {  28, "ms29-32" },
  {  29, "ms30-32" },
  {  30, "ms31-32" },
  {  31, "ms1" },
  {  32, "ms2" },
  {  33, "ms3" },
  {  34, "ms4" },
  {  35, "ms5" },
  {  36, "ms6" },
  {  37, "ms8" },
  {  38, "ms10" },
  {  39, "ms20" },
  {  40, "ms30" },
  {  41, "ms40" },
  {  42, "ms50" },
  {  43, "ms60" },
  {  44, "ms80" },
  {  45, "ms100" },
  {  46, "ms200" },
  {  47, "ms300" },
  {  48, "ms400" },
  {  49, "ms500" },
  {  50, "ms600" },
  {  51, "ms800" },
  {  52, "ms1000" },
  {  53, "ms1200" },
  {  54, "ms1600" },
  {  55, "spare9" },
  {  56, "spare8" },
  {  57, "spare7" },
  {  58, "spare6" },
  {  59, "spare5" },
  {  60, "spare4" },
  {  61, "spare3" },
  {  62, "spare2" },
  {  63, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_drx_onDurationTimer_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_drx_onDurationTimer_vals);


static int
dissect_nr_rrc_T_drx_onDurationTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_drx_InactivityTimer_vals[] = {
  {   0, "ms0" },
  {   1, "ms1" },
  {   2, "ms2" },
  {   3, "ms3" },
  {   4, "ms4" },
  {   5, "ms5" },
  {   6, "ms6" },
  {   7, "ms8" },
  {   8, "ms10" },
  {   9, "ms20" },
  {  10, "ms30" },
  {  11, "ms40" },
  {  12, "ms50" },
  {  13, "ms60" },
  {  14, "ms80" },
  {  15, "ms100" },
  {  16, "ms200" },
  {  17, "ms300" },
  {  18, "ms500" },
  {  19, "ms750" },
  {  20, "ms1280" },
  {  21, "ms1920" },
  {  22, "ms2560" },
  {  23, "spare9" },
  {  24, "spare8" },
  {  25, "spare7" },
  {  26, "spare6" },
  {  27, "spare5" },
  {  28, "spare4" },
  {  29, "spare3" },
  {  30, "spare2" },
  {  31, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_drx_InactivityTimer_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_drx_InactivityTimer_vals);


static int
dissect_nr_rrc_T_drx_InactivityTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_56(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 56U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_drx_RetransmissionTimerDL_vals[] = {
  {   0, "sl0" },
  {   1, "sl1" },
  {   2, "sl2" },
  {   3, "sl4" },
  {   4, "sl6" },
  {   5, "sl8" },
  {   6, "sl16" },
  {   7, "sl24" },
  {   8, "sl33" },
  {   9, "sl40" },
  {  10, "sl64" },
  {  11, "sl80" },
  {  12, "sl96" },
  {  13, "sl112" },
  {  14, "sl128" },
  {  15, "spare15" },
  {  16, "spare14" },
  {  17, "spare13" },
  {  18, "spare12" },
  {  19, "spare11" },
  {  20, "spare10" },
  {  21, "spare9" },
  {  22, "spare8" },
  {  23, "spare7" },
  {  24, "spare6" },
  {  25, "spare5" },
  {  26, "spare4" },
  {  27, "spare3" },
  {  28, "spare2" },
  {  29, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_drx_RetransmissionTimerDL_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_drx_RetransmissionTimerDL_vals);


static int
dissect_nr_rrc_T_drx_RetransmissionTimerDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     30, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_drx_RetransmissionTimerUL_vals[] = {
  {   0, "sl0" },
  {   1, "sl1" },
  {   2, "sl2" },
  {   3, "sl4" },
  {   4, "sl6" },
  {   5, "sl8" },
  {   6, "sl16" },
  {   7, "sl24" },
  {   8, "sl33" },
  {   9, "sl40" },
  {  10, "sl64" },
  {  11, "sl80" },
  {  12, "sl96" },
  {  13, "sl112" },
  {  14, "sl1128" },
  {  15, "u160sl160" },
  {  16, "u320sl320" },
  {  17, "spare15" },
  {  18, "spare14" },
  {  19, "spare13" },
  {  20, "spare12" },
  {  21, "spare11" },
  {  22, "spare10" },
  {  23, "spare9" },
  {  24, "spare8" },
  {  25, "spare7" },
  {  26, "spare6" },
  {  27, "spare5" },
  {  28, "spare4" },
  {  29, "spare3" },
  {  30, "spare2" },
  {  31, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_drx_RetransmissionTimerUL_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_drx_RetransmissionTimerUL_vals);


static int
dissect_nr_rrc_T_drx_RetransmissionTimerUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 19U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_39(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 39U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_59(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_69(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 69U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_79(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 79U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_159(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 159U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_319(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 319U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_639(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 639U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_1279(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1279U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_2559(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2559U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_5119(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 5119U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_10239(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10239U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_drx_LongCycleStartOffset_vals[] = {
  {   0, "ms10" },
  {   1, "ms20" },
  {   2, "ms32" },
  {   3, "ms40" },
  {   4, "ms60" },
  {   5, "ms64" },
  {   6, "ms70" },
  {   7, "ms80" },
  {   8, "ms128" },
  {   9, "ms160" },
  {  10, "ms256" },
  {  11, "ms320" },
  {  12, "ms512" },
  {  13, "ms640" },
  {  14, "ms1024" },
  {  15, "ms1280" },
  {  16, "ms2048" },
  {  17, "ms2560" },
  {  18, "ms5120" },
  {  19, "ms10240" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_drx_LongCycleStartOffset_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_drx_LongCycleStartOffset_vals);

static const per_choice_t T_drx_LongCycleStartOffset_choice[] = {
  {   0, &hf_nr_rrc_ms10         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   1, &hf_nr_rrc_ms20         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  {   2, &hf_nr_rrc_ms32         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_31 },
  {   3, &hf_nr_rrc_ms40         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_39 },
  {   4, &hf_nr_rrc_ms60         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_59 },
  {   5, &hf_nr_rrc_ms64         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_63 },
  {   6, &hf_nr_rrc_ms70         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_69 },
  {   7, &hf_nr_rrc_ms80         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_79 },
  {   8, &hf_nr_rrc_ms128        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_127 },
  {   9, &hf_nr_rrc_ms160        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_159 },
  {  10, &hf_nr_rrc_ms256        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_255 },
  {  11, &hf_nr_rrc_ms320        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_319 },
  {  12, &hf_nr_rrc_ms512        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_511 },
  {  13, &hf_nr_rrc_ms640        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_639 },
  {  14, &hf_nr_rrc_ms1024       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_1023 },
  {  15, &hf_nr_rrc_ms1280       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_1279 },
  {  16, &hf_nr_rrc_ms2048       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_2047 },
  {  17, &hf_nr_rrc_ms2560       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_2559 },
  {  18, &hf_nr_rrc_ms5120       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_5119 },
  {  19, &hf_nr_rrc_ms10240      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_10239 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_drx_LongCycleStartOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_drx_LongCycleStartOffset, T_drx_LongCycleStartOffset_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_drx_ShortCycle_vals[] = {
  {   0, "ms2" },
  {   1, "ms3" },
  {   2, "ms4" },
  {   3, "ms5" },
  {   4, "ms6" },
  {   5, "ms7" },
  {   6, "ms8" },
  {   7, "ms10" },
  {   8, "ms14" },
  {   9, "ms16" },
  {  10, "ms20" },
  {  11, "ms30" },
  {  12, "ms32" },
  {  13, "ms35" },
  {  14, "ms40" },
  {  15, "ms64" },
  {  16, "ms80" },
  {  17, "ms128" },
  {  18, "ms160" },
  {  19, "ms256" },
  {  20, "ms320" },
  {  21, "ms512" },
  {  22, "ms640" },
  {  23, "spare9" },
  {  24, "spare8" },
  {  25, "spare7" },
  {  26, "spare6" },
  {  27, "spare5" },
  {  28, "spare4" },
  {  29, "spare3" },
  {  30, "spare2" },
  {  31, "spare1" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_drx_ShortCycle_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_drx_ShortCycle_vals);


static int
dissect_nr_rrc_T_drx_ShortCycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_shortDRX_sequence[] = {
  { &hf_nr_rrc_drx_ShortCycle, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_drx_ShortCycle },
  { &hf_nr_rrc_drx_ShortCycleTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_shortDRX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_shortDRX, T_shortDRX_sequence);

  return offset;
}


static const value_string nr_rrc_T_drx_SlotOffset_vals[] = {
  {   0, "ms0" },
  {   1, "ms1-32" },
  {   2, "ms2-32" },
  {   3, "ms3-32" },
  {   4, "ms4-32" },
  {   5, "ms5-32" },
  {   6, "ms6-32" },
  {   7, "ms7-32" },
  {   8, "ms8-32" },
  {   9, "ms9-32" },
  {  10, "ms10-32" },
  {  11, "ms11-32" },
  {  12, "ms12-32" },
  {  13, "ms13-32" },
  {  14, "ms14-32" },
  {  15, "ms15-32" },
  {  16, "ms16-32" },
  {  17, "ms17-32" },
  {  18, "ms18-32" },
  {  19, "ms19-32" },
  {  20, "ms-20-32" },
  {  21, "ms21-32" },
  {  22, "ms22-32" },
  {  23, "ms23-32" },
  {  24, "ms24-32" },
  {  25, "ms25-32" },
  {  26, "ms26-32" },
  {  27, "ms27-32" },
  {  28, "ms28-32" },
  {  29, "ms29-32" },
  {  30, "ms30-32" },
  {  31, "ms31-32" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_drx_SlotOffset_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_drx_SlotOffset_vals);


static int
dissect_nr_rrc_T_drx_SlotOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_sequence[] = {
  { &hf_nr_rrc_drx_onDurationTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_drx_onDurationTimer },
  { &hf_nr_rrc_drx_InactivityTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_drx_InactivityTimer },
  { &hf_nr_rrc_drx_HARQ_RTT_TimerDL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_56 },
  { &hf_nr_rrc_drx_HARQ_RTT_TimerUL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_56 },
  { &hf_nr_rrc_drx_RetransmissionTimerDL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_drx_RetransmissionTimerDL },
  { &hf_nr_rrc_drx_RetransmissionTimerUL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_drx_RetransmissionTimerUL },
  { &hf_nr_rrc_drx_LongCycleStartOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_drx_LongCycleStartOffset },
  { &hf_nr_rrc_shortDRX     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_shortDRX },
  { &hf_nr_rrc_drx_SlotOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_drx_SlotOffset },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup, T_setup_sequence);

  return offset;
}


static const value_string nr_rrc_DRX_Config_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t DRX_Config_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_DRX_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_DRX_Config, DRX_Config_choice,
                                 NULL);

  return offset;
}



static int
dissect_nr_rrc_SchedulingRequestId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string nr_rrc_T_sr_prohibitTimer_vals[] = {
  {   0, "ms1" },
  {   1, "ms2" },
  {   2, "ms4" },
  {   3, "ms8" },
  {   4, "ms16" },
  {   5, "ms32" },
  {   6, "ms64" },
  {   7, "ms128" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_sr_prohibitTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_sr_TransMax_vals[] = {
  {   0, "n4" },
  {   1, "n8" },
  {   2, "n16" },
  {   3, "n32" },
  {   4, "n64" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_sr_TransMax(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t SchedulingRequestToAddMod_sequence[] = {
  { &hf_nr_rrc_schedulingRequestID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SchedulingRequestId },
  { &hf_nr_rrc_sr_prohibitTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_sr_prohibitTimer },
  { &hf_nr_rrc_sr_TransMax  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_sr_TransMax },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SchedulingRequestToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SchedulingRequestToAddMod, SchedulingRequestToAddMod_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod_sequence_of[1] = {
  { &hf_nr_rrc_schedulingRequestToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SchedulingRequestToAddMod },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod, SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod_sequence_of,
                                                  1, maxNrofSR_ConfigPerCellGroup, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId_sequence_of[1] = {
  { &hf_nr_rrc_schedulingRequestToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SchedulingRequestId },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId, SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId_sequence_of,
                                                  1, maxNrofSR_ConfigPerCellGroup, FALSE);

  return offset;
}


static const per_sequence_t SchedulingRequestConfig_sequence[] = {
  { &hf_nr_rrc_schedulingRequestToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod },
  { &hf_nr_rrc_schedulingRequestToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SchedulingRequestConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SchedulingRequestConfig, SchedulingRequestConfig_sequence);

  return offset;
}


static const value_string nr_rrc_T_periodicBSR_Timer_vals[] = {
  {   0, "sf1" },
  {   1, "sf5" },
  {   2, "sf10" },
  {   3, "sf16" },
  {   4, "sf20" },
  {   5, "sf32" },
  {   6, "sf40" },
  {   7, "sf64" },
  {   8, "sf80" },
  {   9, "sf128" },
  {  10, "sf160" },
  {  11, "sf320" },
  {  12, "sf640" },
  {  13, "sf1280" },
  {  14, "sf2560" },
  {  15, "infinity" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_periodicBSR_Timer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_retxBSR_Timer_vals[] = {
  {   0, "sf10" },
  {   1, "sf20" },
  {   2, "sf40" },
  {   3, "sf80" },
  {   4, "sf160" },
  {   5, "sf320" },
  {   6, "sf640" },
  {   7, "sf1280" },
  {   8, "sf2560" },
  {   9, "sf5120" },
  {  10, "sf10240" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_retxBSR_Timer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     11, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_logicaChannelSR_DelayTimer_vals[] = {
  {   0, "sf20" },
  {   1, "sf40" },
  {   2, "sf64" },
  {   3, "sf128" },
  {   4, "sf512" },
  {   5, "sf1024" },
  {   6, "sf2560" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_logicaChannelSR_DelayTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t BSR_Config_sequence[] = {
  { &hf_nr_rrc_periodicBSR_Timer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_periodicBSR_Timer },
  { &hf_nr_rrc_retxBSR_Timer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_retxBSR_Timer },
  { &hf_nr_rrc_logicaChannelSR_DelayTimer, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_logicaChannelSR_DelayTimer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BSR_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BSR_Config, BSR_Config_sequence);

  return offset;
}



static int
dissect_nr_rrc_BSR_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_BSR_Config(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_nr_rrc_TAG_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofTAGs_1, NULL, FALSE);

  return offset;
}


static const per_sequence_t TAG_ToReleaseList_sequence_of[1] = {
  { &hf_nr_rrc_TAG_ToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TAG_Id },
};

static int
dissect_nr_rrc_TAG_ToReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_TAG_ToReleaseList, TAG_ToReleaseList_sequence_of,
                                                  1, maxNrofTAGs, FALSE);

  return offset;
}


static const value_string nr_rrc_TimeAlignmentTimer_vals[] = {
  {   0, "ms500" },
  {   1, "ms750" },
  {   2, "ms1280" },
  {   3, "ms1920" },
  {   4, "ms2560" },
  {   5, "ms5120" },
  {   6, "ms10240" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_nr_rrc_TimeAlignmentTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t TAG_ToAddMod_sequence[] = {
  { &hf_nr_rrc_tag_Id       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TAG_Id },
  { &hf_nr_rrc_timeAlignmentTimer, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TimeAlignmentTimer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_TAG_ToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_TAG_ToAddMod, TAG_ToAddMod_sequence);

  return offset;
}


static const per_sequence_t TAG_ToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_TAG_ToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TAG_ToAddMod },
};

static int
dissect_nr_rrc_TAG_ToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_TAG_ToAddModList, TAG_ToAddModList_sequence_of,
                                                  1, maxNrofTAGs, FALSE);

  return offset;
}


static const per_sequence_t TAG_Config_sequence[] = {
  { &hf_nr_rrc_tag_ToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_TAG_ToReleaseList },
  { &hf_nr_rrc_tag_ToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_TAG_ToAddModList },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_TAG_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_TAG_Config, TAG_Config_sequence);

  return offset;
}



static int
dissect_nr_rrc_TAG_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_TAG_Config(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string nr_rrc_T_phr_PeriodicTimer_vals[] = {
  {   0, "sf10" },
  {   1, "sf20" },
  {   2, "sf50" },
  {   3, "sf100" },
  {   4, "sf200" },
  {   5, "sf500" },
  {   6, "sf1000" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_phr_PeriodicTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_phr_ProhibitTimer_vals[] = {
  {   0, "sf0" },
  {   1, "sf10" },
  {   2, "sf20" },
  {   3, "sf50" },
  {   4, "sf100" },
  {   5, "sf200" },
  {   6, "sf500" },
  {   7, "sf1000" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_phr_ProhibitTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_phr_Tx_PowerFactorChange_vals[] = {
  {   0, "dB1" },
  {   1, "dB3" },
  {   2, "dB6" },
  {   3, "infinity" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_phr_Tx_PowerFactorChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_phr_ModeOtherCG_vals[] = {
  {   0, "real" },
  {   1, "virtual" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_phr_ModeOtherCG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_01_sequence[] = {
  { &hf_nr_rrc_phr_PeriodicTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_phr_PeriodicTimer },
  { &hf_nr_rrc_phr_ProhibitTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_phr_ProhibitTimer },
  { &hf_nr_rrc_phr_Tx_PowerFactorChange, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_phr_Tx_PowerFactorChange },
  { &hf_nr_rrc_multiplePHR  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_phr_Type2PCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_phr_Type2OtherCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_phr_ModeOtherCG, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_phr_ModeOtherCG },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_01, T_setup_01_sequence);

  return offset;
}


static const value_string nr_rrc_PHR_Config_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t PHR_Config_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_01     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_PHR_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_PHR_Config, PHR_Config_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_sCellDeactivationTimer_vals[] = {
  {   0, "ms20" },
  {   1, "ms40" },
  {   2, "ms80" },
  {   3, "ms160" },
  {   4, "ms200" },
  {   5, "ms240" },
  {   6, "ms320" },
  {   7, "ms400" },
  {   8, "ms480" },
  {   9, "ms520" },
  {  10, "ms640" },
  {  11, "ms720" },
  {  12, "ms840" },
  {  13, "ms1280" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_sCellDeactivationTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t MAC_CellGroupConfig_sequence[] = {
  { &hf_nr_rrc_drx_Config   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_DRX_Config },
  { &hf_nr_rrc_schedulingRequestConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SchedulingRequestConfig },
  { &hf_nr_rrc_bsr_Config   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BSR_Configuration },
  { &hf_nr_rrc_tag_Config   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_TAG_Configuration },
  { &hf_nr_rrc_phr_Config   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_PHR_Config },
  { &hf_nr_rrc_sCellDeactivationTimer, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_sCellDeactivationTimer },
  { &hf_nr_rrc_skipUplinkTxDynamic, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MAC_CellGroupConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MAC_CellGroupConfig, MAC_CellGroupConfig_sequence);

  return offset;
}


static const per_sequence_t RLF_TimersAndConstants_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RLF_TimersAndConstants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RLF_TimersAndConstants, RLF_TimersAndConstants_sequence);

  return offset;
}


static const value_string nr_rrc_T_harq_ACK_Spatial_Bundling_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_harq_ACK_Spatial_Bundling(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PhysicalCellGroupConfig_sequence[] = {
  { &hf_nr_rrc_harq_ACK_Spatial_Bundling, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_harq_ACK_Spatial_Bundling },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PhysicalCellGroupConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PhysicalCellGroupConfig, PhysicalCellGroupConfig_sequence);

  return offset;
}


static const value_string nr_rrc_CarrierBandwidthNR_vals[] = {
  {   0, "ffs" },
  { 0, NULL }
};


static int
dissect_nr_rrc_CarrierBandwidthNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_frequencyInfoDL_sequence[] = {
  { &hf_nr_rrc_carrierFreqDL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ARFCN_ValueNR },
  { &hf_nr_rrc_carrierBandwidthDL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CarrierBandwidthNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_frequencyInfoDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_frequencyInfoDL, T_frequencyInfoDL_sequence);

  return offset;
}



static int
dissect_nr_rrc_AdditionalSpectrumEmission(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_frequencyShift7p5khz_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_frequencyShift7p5khz(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_BandwidthPartId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofBandwidthParts_1, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_maxNrofPhysicalResourceBlocksTimes4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofPhysicalResourceBlocksTimes4, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_maxNrofPhysicalResourceBlocks(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNrofPhysicalResourceBlocks, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_subcarrierSpacing_vals[] = {
  {   0, "n0" },
  {   1, "n1" },
  {   2, "n2" },
  {   3, "n3" },
  {   4, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_subcarrierSpacing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_cyclicPrefix_vals[] = {
  {   0, "extended" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_cyclicPrefix(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_3299(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3299U, NULL, FALSE);

  return offset;
}


static const per_sequence_t BandwidthPart_sequence[] = {
  { &hf_nr_rrc_bandwidthPartId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BandwidthPartId },
  { &hf_nr_rrc_location     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_maxNrofPhysicalResourceBlocksTimes4 },
  { &hf_nr_rrc_bandwidth    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_maxNrofPhysicalResourceBlocks },
  { &hf_nr_rrc_subcarrierSpacing, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_subcarrierSpacing },
  { &hf_nr_rrc_cyclicPrefix , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_cyclicPrefix },
  { &hf_nr_rrc_directCurrentLocation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_3299 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BandwidthPart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BandwidthPart, BandwidthPart_sequence);

  return offset;
}


static const per_sequence_t FrequencyInfoUL_sequence[] = {
  { &hf_nr_rrc_carrierFreqUL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ARFCN_ValueNR },
  { &hf_nr_rrc_carrierBandwidthUL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CarrierBandwidthNR },
  { &hf_nr_rrc_additionalSpectrumEmission, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_AdditionalSpectrumEmission },
  { &hf_nr_rrc_p_Max        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_P_Max },
  { &hf_nr_rrc_frequencyShift7p5khz, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_frequencyShift7p5khz },
  { &hf_nr_rrc_initialUplinkBandwidthPart, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BandwidthPart },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_FrequencyInfoUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_FrequencyInfoUL, FrequencyInfoUL_sequence);

  return offset;
}


static const per_sequence_t T_supplementaryUplink_sequence[] = {
  { &hf_nr_rrc_frequencyInfoUL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_FrequencyInfoUL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_supplementaryUplink(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_supplementaryUplink, T_supplementaryUplink_sequence);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 11U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, NULL);

  return offset;
}


static const value_string nr_rrc_T_ssb_PositionsInBurst_vals[] = {
  {   0, "shortBitmap" },
  {   1, "mediumBitmap" },
  {   2, "longBitmap" },
  { 0, NULL }
};

static const per_choice_t T_ssb_PositionsInBurst_choice[] = {
  {   0, &hf_nr_rrc_shortBitmap  , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_4 },
  {   1, &hf_nr_rrc_mediumBitmap , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_8 },
  {   2, &hf_nr_rrc_longBitmap   , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_64 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_ssb_PositionsInBurst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_ssb_PositionsInBurst, T_ssb_PositionsInBurst_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_ssb_periodicityServingCell_vals[] = {
  {   0, "ms5" },
  {   1, "ms10" },
  {   2, "ms20" },
  {   3, "ms40" },
  {   4, "ms80" },
  {   5, "ms160" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_ssb_periodicityServingCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_dmrs_TypeA_Position_01_vals[] = {
  {   0, "pos2" },
  {   1, "pos3" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_dmrs_TypeA_Position_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_SubcarrierSpacingSSB_vals[] = {
  {   0, "kHz15" },
  {   1, "kHz30" },
  {   2, "kHz120" },
  {   3, "kHz240" },
  { 0, NULL }
};


static int
dissect_nr_rrc_SubcarrierSpacingSSB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_dl_UL_TransmissionPeriodicity_vals[] = {
  {   0, "ms0dot5" },
  {   1, "ms1" },
  {   2, "ms2" },
  {   3, "ms5" },
  {   4, "ms10" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_dl_UL_TransmissionPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_160(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 160U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_maxSymbolIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxSymbolIndex, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_tdd_UL_DL_configurationCommon_sequence[] = {
  { &hf_nr_rrc_dl_UL_TransmissionPeriodicity, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_dl_UL_TransmissionPeriodicity },
  { &hf_nr_rrc_nrofDownlinkSlots, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_160 },
  { &hf_nr_rrc_nrofDownlinkSymbols, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_maxSymbolIndex },
  { &hf_nr_rrc_nrofUplinkSlots, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_160 },
  { &hf_nr_rrc_nrofUplinkSymbols, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_maxSymbolIndex },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_tdd_UL_DL_configurationCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_tdd_UL_DL_configurationCommon, T_tdd_UL_DL_configurationCommon_sequence);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_M60_50(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -60, 50U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_ra_Msg3SizeGroupA_vals[] = {
  {   0, "b56" },
  {   1, "b144" },
  {   2, "b208" },
  {   3, "b256" },
  {   4, "b282" },
  {   5, "b480" },
  {   6, "b640" },
  {   7, "b800" },
  {   8, "b1000" },
  {   9, "spare7" },
  {  10, "spare6" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_ra_Msg3SizeGroupA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_messagePowerOffsetGroupB_vals[] = {
  {   0, "minusinfinity" },
  {   1, "dB0" },
  {   2, "dB5" },
  {   3, "dB8" },
  {   4, "dB10" },
  {   5, "dB12" },
  {   6, "dB15" },
  {   7, "dB18" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_messagePowerOffsetGroupB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_groupBconfigured_sequence[] = {
  { &hf_nr_rrc_ra_Msg3SizeGroupA, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_ra_Msg3SizeGroupA },
  { &hf_nr_rrc_messagePowerOffsetGroupB, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_messagePowerOffsetGroupB },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_groupBconfigured(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_groupBconfigured, T_groupBconfigured_sequence);

  return offset;
}



static int
dissect_nr_rrc_SSB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 7U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_PreambleStartIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxRA_PreambleIndex, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_NumberofRA_Preambles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNrOfRA_PreamblesPerSSB, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_NumberOfRA_Preambles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_NumberofRA_Preambles(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RA_Resources_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RA_Resources(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RA_Resources, RA_Resources_sequence);

  return offset;
}


static const per_sequence_t CBRA_SSB_Resource_sequence[] = {
  { &hf_nr_rrc_ssb          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SSB_ID },
  { &hf_nr_rrc_startIndexRA_PreambleGroupA, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PreambleStartIndex },
  { &hf_nr_rrc_numberofRA_PreamblesGroupA, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NumberOfRA_Preambles },
  { &hf_nr_rrc_numberOfRA_Preambles, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NumberOfRA_Preambles },
  { &hf_nr_rrc_ra_Resources , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RA_Resources },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CBRA_SSB_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CBRA_SSB_Resource, CBRA_SSB_Resource_sequence);

  return offset;
}


static const per_sequence_t CBRA_SSB_ResourceList_sequence_of[1] = {
  { &hf_nr_rrc_CBRA_SSB_ResourceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CBRA_SSB_Resource },
};

static int
dissect_nr_rrc_CBRA_SSB_ResourceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_CBRA_SSB_ResourceList, CBRA_SSB_ResourceList_sequence_of,
                                                  1, maxRAssbResources, FALSE);

  return offset;
}


static const value_string nr_rrc_T_ra_ContentionResolutionTimer_vals[] = {
  {   0, "sf8" },
  {   1, "sf16" },
  {   2, "sf24" },
  {   3, "sf32" },
  {   4, "sf40" },
  {   5, "sf48" },
  {   6, "sf56" },
  {   7, "sf64" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_ra_ContentionResolutionTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_837(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 837U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_137(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 137U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_prach_RootSequenceIndex_vals[] = {
  {   0, "l839" },
  {   1, "l139" },
  { 0, NULL }
};

static const per_choice_t T_prach_RootSequenceIndex_choice[] = {
  {   0, &hf_nr_rrc_l839         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_837 },
  {   1, &hf_nr_rrc_l139         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_137 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_prach_RootSequenceIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_prach_RootSequenceIndex, T_prach_RootSequenceIndex_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_restrictedSetConfig_vals[] = {
  {   0, "unrestricted" },
  {   1, "restrictedToTypeA" },
  {   2, "restrictedToTypeB" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_restrictedSetConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_preambleReceivedTargetPower_vals[] = {
  {   0, "dBm-120" },
  {   1, "dBm-118" },
  {   2, "dBm-116" },
  {   3, "dBm-114" },
  {   4, "dBm-112" },
  {   5, "dBm-110" },
  {   6, "dBm-108" },
  {   7, "dBm-106" },
  {   8, "dBm-104" },
  {   9, "dBm-102" },
  {  10, "dBm-100" },
  {  11, "dBm-98" },
  {  12, "dBm-96" },
  {  13, "dBm-94" },
  {  14, "dBm-92" },
  {  15, "dBm-90" },
  {  16, "dBm-88" },
  {  17, "dBm-86" },
  {  18, "dBm-84" },
  {  19, "dBm-82" },
  {  20, "dBm-80" },
  {  21, "dBm-78" },
  {  22, "dBm-76" },
  {  23, "dBm-74" },
  {  24, "dBm-72" },
  {  25, "dBm-70" },
  {  26, "dBm-68" },
  {  27, "dBm-66" },
  {  28, "dBm-64" },
  {  29, "dBm-62" },
  {  30, "dBm-60" },
  {  31, "dBm-58" },
  {  32, "dBm-56" },
  {  33, "dBm-54" },
  {  34, "dBm-52" },
  {  35, "dBm-50" },
  {  36, "dBm-48" },
  {  37, "dBm-46" },
  {  38, "dBm-44" },
  {  39, "dBm-42" },
  {  40, "dBm-42" },
  {  41, "dBm-40" },
  {  42, "dBm-38" },
  {  43, "dBm-36" },
  {  44, "dBm-34" },
  {  45, "dBm-32" },
  {  46, "dBm-30" },
  {  47, "dBm-28" },
  {  48, "dBm-26" },
  {  49, "dBm-24" },
  {  50, "dBm-22" },
  {  51, "dBm-20" },
  {  52, "dBm-18" },
  {  53, "dBm-16" },
  {  54, "dBm-14" },
  {  55, "dBm-12" },
  {  56, "dBm-10" },
  {  57, "dBm-8" },
  {  58, "dBm-6" },
  {  59, "dBm-4" },
  {  60, "dBm-2" },
  {  61, "dBm-0" },
  {  62, "dBm2" },
  {  63, "dBm4" },
  {  64, "dBm6" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_preambleReceivedTargetPower_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_preambleReceivedTargetPower_vals);


static int
dissect_nr_rrc_T_preambleReceivedTargetPower(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     65, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_powerRampingStep_vals[] = {
  {   0, "dB0" },
  {   1, "dB2" },
  {   2, "dB4" },
  {   3, "dB6" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_powerRampingStep(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_preambleTransMax_vals[] = {
  {   0, "n3" },
  {   1, "n4" },
  {   2, "n5" },
  {   3, "n6" },
  {   4, "n7" },
  {   5, "n8" },
  {   6, "n10" },
  {   7, "n20" },
  {   8, "n50" },
  {   9, "n100" },
  {  10, "n200" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_preambleTransMax(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     11, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_msg3_transformPrecoding_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_msg3_transformPrecoding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RACH_ConfigCommon_sequence[] = {
  { &hf_nr_rrc_groupBconfigured, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_groupBconfigured },
  { &hf_nr_rrc_cbra_SSB_ResourceList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CBRA_SSB_ResourceList },
  { &hf_nr_rrc_ra_ContentionResolutionTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_ra_ContentionResolutionTimer },
  { &hf_nr_rrc_ssb_Threshold, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_sul_RSRP_Threshold, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_prach_ConfigurationIndex, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_255 },
  { &hf_nr_rrc_prach_RootSequenceIndex, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_prach_RootSequenceIndex },
  { &hf_nr_rrc_zeroCorrelationZoneConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_15 },
  { &hf_nr_rrc_restrictedSetConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_restrictedSetConfig },
  { &hf_nr_rrc_preambleReceivedTargetPower, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_preambleReceivedTargetPower },
  { &hf_nr_rrc_powerRampingStep, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_powerRampingStep },
  { &hf_nr_rrc_preambleTransMax, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_preambleTransMax },
  { &hf_nr_rrc_ra_ResponseWindow, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_msg2_SubcarrierSpacing, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SubcarrierSpacing },
  { &hf_nr_rrc_rach_ControlResourceSet, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_msg3_SubcarrierSpacing, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SubcarrierSpacing },
  { &hf_nr_rrc_msg3_transformPrecoding, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_msg3_transformPrecoding },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RACH_ConfigCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RACH_ConfigCommon, RACH_ConfigCommon_sequence);

  return offset;
}


static const per_sequence_t ServingCellConfigCommon_sequence[] = {
  { &hf_nr_rrc_physCellId   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_PhysCellId },
  { &hf_nr_rrc_frequencyInfoDL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_frequencyInfoDL },
  { &hf_nr_rrc_frequencyInfoUL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_FrequencyInfoUL },
  { &hf_nr_rrc_supplementaryUplink, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_supplementaryUplink },
  { &hf_nr_rrc_subcarrierSpacingCommon, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SubcarrierSpacing },
  { &hf_nr_rrc_ssb_subcarrier_offset, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_11 },
  { &hf_nr_rrc_ssb_PositionsInBurst, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_ssb_PositionsInBurst },
  { &hf_nr_rrc_ssb_periodicityServingCell, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_ssb_periodicityServingCell },
  { &hf_nr_rrc_dmrs_TypeA_Position_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_dmrs_TypeA_Position_01 },
  { &hf_nr_rrc_subcarrierSpacingSSB, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SubcarrierSpacingSSB },
  { &hf_nr_rrc_tdd_UL_DL_configurationCommon, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_tdd_UL_DL_configurationCommon },
  { &hf_nr_rrc_ss_PBCH_BlockPower, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_M60_50 },
  { &hf_nr_rrc_rach_ConfigCommon, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RACH_ConfigCommon },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ServingCellConfigCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ServingCellConfigCommon, ServingCellConfigCommon_sequence);

  return offset;
}



static int
dissect_nr_rrc_C_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}


static const value_string nr_rrc_T_t304_vals[] = {
  {   0, "ms50" },
  {   1, "ms100" },
  {   2, "ms150" },
  {   3, "ms200" },
  {   4, "ms500" },
  {   5, "ms1000" },
  {   6, "ms2000" },
  {   7, "ms10000-v1310" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_t304(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 0U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CFRA_SSB_Resource_sequence[] = {
  { &hf_nr_rrc_ssb          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SSB_ID },
  { &hf_nr_rrc_ra_PreambleIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_0 },
  { &hf_nr_rrc_ra_Resources , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RA_Resources },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CFRA_SSB_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CFRA_SSB_Resource, CFRA_SSB_Resource_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource_sequence_of[1] = {
  { &hf_nr_rrc_cfra_ssb_ResourceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CFRA_SSB_Resource },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource, SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource_sequence_of,
                                                  1, maxRAssbResources, FALSE);

  return offset;
}



static int
dissect_nr_rrc_CSIRS_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t CFRA_CSIRS_Resource_sequence[] = {
  { &hf_nr_rrc_csirs        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSIRS_ID },
  { &hf_nr_rrc_ra_PreambleIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_0 },
  { &hf_nr_rrc_ra_Resources , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RA_Resources },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CFRA_CSIRS_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CFRA_CSIRS_Resource, CFRA_CSIRS_Resource_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource_sequence_of[1] = {
  { &hf_nr_rrc_cfra_csirs_ResourceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CFRA_CSIRS_Resource },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource, SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource_sequence_of,
                                                  1, maxRAcsirsResources, FALSE);

  return offset;
}


static const value_string nr_rrc_CFRA_Resources_vals[] = {
  {   0, "cfra-ssb-ResourceList" },
  {   1, "cfra-csirs-ResourceList" },
  { 0, NULL }
};

static const per_choice_t CFRA_Resources_choice[] = {
  {   0, &hf_nr_rrc_cfra_ssb_ResourceList, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource },
  {   1, &hf_nr_rrc_cfra_csirs_ResourceList, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_CFRA_Resources(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_CFRA_Resources, CFRA_Resources_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RACH_ConfigDedicated_sequence[] = {
  { &hf_nr_rrc_cfra_Resources, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CFRA_Resources },
  { &hf_nr_rrc_rar_SubcarrierSpacing, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SubcarrierSpacing },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RACH_ConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RACH_ConfigDedicated, RACH_ConfigDedicated_sequence);

  return offset;
}


static const per_sequence_t T_reconfigurationWithSync_sequence[] = {
  { &hf_nr_rrc_spCellConfigCommon, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ServingCellConfigCommon },
  { &hf_nr_rrc_newUE_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_C_RNTI },
  { &hf_nr_rrc_t304         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_t304 },
  { &hf_nr_rrc_rach_ConfigDedicated, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RACH_ConfigDedicated },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_reconfigurationWithSync(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_reconfigurationWithSync, T_reconfigurationWithSync_sequence);

  return offset;
}


static const per_sequence_t T_slotSpecificConfigurations_item_sequence[] = {
  { &hf_nr_rrc_slotIndex    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_160 },
  { &hf_nr_rrc_nrofDownlinkSymbols, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_maxSymbolIndex },
  { &hf_nr_rrc_nrofUplinkSymbols, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_maxSymbolIndex },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_slotSpecificConfigurations_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_slotSpecificConfigurations_item, T_slotSpecificConfigurations_item_sequence);

  return offset;
}


static const per_sequence_t T_slotSpecificConfigurations_sequence_of[1] = {
  { &hf_nr_rrc_slotSpecificConfigurations_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_slotSpecificConfigurations_item },
};

static int
dissect_nr_rrc_T_slotSpecificConfigurations(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_T_slotSpecificConfigurations, T_slotSpecificConfigurations_sequence_of,
                                                  0, 160, FALSE);

  return offset;
}


static const per_sequence_t T_tdd_UL_DL_configurationDedicated_sequence[] = {
  { &hf_nr_rrc_slotSpecificConfigurations, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_slotSpecificConfigurations },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_tdd_UL_DL_configurationDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_tdd_UL_DL_configurationDedicated, T_tdd_UL_DL_configurationDedicated_sequence);

  return offset;
}



static int
dissect_nr_rrc_BandwidthParts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_BandwidthPart(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_nr_rrc_ControlResourceSetId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofControlResourceSets_1, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_maxCoReSetStartSymbol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxCoReSetStartSymbol, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_maxCoReSetDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxCoReSetDuration, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_reg_BundleSize_vals[] = {
  {   0, "n2" },
  {   1, "n3" },
  {   2, "n6" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_reg_BundleSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_cce_reg_MappingType_vals[] = {
  {   0, "interleaved" },
  {   1, "nonInterleaved" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_cce_reg_MappingType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_interleaverRows_vals[] = {
  {   0, "n2" },
  {   1, "n3" },
  {   2, "n6" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_interleaverRows(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ControlResourceSet_sequence[] = {
  { &hf_nr_rrc_controlResourceSetId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ControlResourceSetId },
  { &hf_nr_rrc_frequencyDomainResources, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_startSymbol  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_maxCoReSetStartSymbol },
  { &hf_nr_rrc_duration_01  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_maxCoReSetDuration },
  { &hf_nr_rrc_reg_BundleSize, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reg_BundleSize },
  { &hf_nr_rrc_cce_reg_MappingType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_cce_reg_MappingType },
  { &hf_nr_rrc_precoderGranularity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_interleaverRows, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_interleaverRows },
  { &hf_nr_rrc_shiftIndex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_tci_StateRefId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_pdcch_DMRS_ScramblingID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ControlResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ControlResourceSet, ControlResourceSet_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet_sequence_of[1] = {
  { &hf_nr_rrc_controlResourceSetToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ControlResourceSet },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet, SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet_sequence_of,
                                                  1, maxNrofControlResourceSets, FALSE);

  return offset;
}



static int
dissect_nr_rrc_ControlResourceId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_ControlResourceSetId(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId_sequence_of[1] = {
  { &hf_nr_rrc_controlResourceSetToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ControlResourceId },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId, SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId_sequence_of,
                                                  1, maxNrofControlResourceSets, FALSE);

  return offset;
}



static int
dissect_nr_rrc_SearchSpaceId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNrofSearchSpaces, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_monitoringSlotPeriodicityAndOffset_vals[] = {
  {   0, "sl1" },
  {   1, "sl2" },
  {   2, "sl5" },
  {   3, "sl10" },
  {   4, "sl20" },
  { 0, NULL }
};

static const per_choice_t T_monitoringSlotPeriodicityAndOffset_choice[] = {
  {   0, &hf_nr_rrc_sl1          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_sl2          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_1 },
  {   2, &hf_nr_rrc_sl5          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_4 },
  {   3, &hf_nr_rrc_sl10         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   4, &hf_nr_rrc_sl20         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_monitoringSlotPeriodicityAndOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_monitoringSlotPeriodicityAndOffset, T_monitoringSlotPeriodicityAndOffset_choice,
                                 NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     14, 14, FALSE, NULL, NULL);

  return offset;
}


static const value_string nr_rrc_T_aggregationLevel1_vals[] = {
  {   0, "n0" },
  {   1, "n1" },
  {   2, "n2" },
  {   3, "n3" },
  {   4, "n4" },
  {   5, "n5" },
  {   6, "n6" },
  {   7, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_aggregationLevel1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_aggregationLevel2_vals[] = {
  {   0, "n0" },
  {   1, "n1" },
  {   2, "n2" },
  {   3, "n3" },
  {   4, "n4" },
  {   5, "n5" },
  {   6, "n6" },
  {   7, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_aggregationLevel2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_aggregationLevel4_vals[] = {
  {   0, "n0" },
  {   1, "n1" },
  {   2, "n2" },
  {   3, "n3" },
  {   4, "n4" },
  {   5, "n5" },
  {   6, "n6" },
  {   7, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_aggregationLevel4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_aggregationLevel8_vals[] = {
  {   0, "n0" },
  {   1, "n1" },
  {   2, "n2" },
  {   3, "n3" },
  {   4, "n4" },
  {   5, "n5" },
  {   6, "n6" },
  {   7, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_aggregationLevel8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_nrofCandidates_sequence[] = {
  { &hf_nr_rrc_aggregationLevel1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_aggregationLevel1 },
  { &hf_nr_rrc_aggregationLevel2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_aggregationLevel2 },
  { &hf_nr_rrc_aggregationLevel4, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_aggregationLevel4 },
  { &hf_nr_rrc_aggregationLevel8, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_aggregationLevel8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_nrofCandidates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_nrofCandidates, T_nrofCandidates_sequence);

  return offset;
}


static const value_string nr_rrc_T_monitoringPeriodicity_vals[] = {
  {   0, "sl1" },
  {   1, "sl2" },
  {   2, "sl5" },
  {   3, "sl10" },
  {   4, "sl20" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_monitoringPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_SlotFormatCombinationId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofSlotFormatCombinations_1, NULL, FALSE);

  return offset;
}


static const per_sequence_t SlotFormatCombination_sequence[] = {
  { &hf_nr_rrc_slotFormatCombinationId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SlotFormatCombinationId },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SlotFormatCombination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SlotFormatCombination, SlotFormatCombination_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination_sequence_of[1] = {
  { &hf_nr_rrc_slotFormatCombinations_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SlotFormatCombination },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination, SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination_sequence_of,
                                                  1, maxNrofSlotFormatCombinations, FALSE);

  return offset;
}


static const per_sequence_t CellToSFI_sequence[] = {
  { &hf_nr_rrc_slotFormatCombinations, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CellToSFI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CellToSFI, CellToSFI_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI_sequence_of[1] = {
  { &hf_nr_rrc_sfi_CellToSFI_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CellToSFI },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI, SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI_sequence_of,
                                                  1, maxNrofAggregatedCellsPerCellGroup, FALSE);

  return offset;
}


static const value_string nr_rrc_T_nrofPDCCH_Candidates_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofPDCCH_Candidates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_aggregationLevel_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_aggregationLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SFI_PDCCH_sequence[] = {
  { &hf_nr_rrc_monitoringPeriodicity_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_monitoringPeriodicity },
  { &hf_nr_rrc_sfi_CellToSFI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI },
  { &hf_nr_rrc_nrofPDCCH_Candidates, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_nrofPDCCH_Candidates },
  { &hf_nr_rrc_aggregationLevel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_aggregationLevel },
  { &hf_nr_rrc_sfi_RNTI     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BIT_STRING_SIZE_16 },
  { &hf_nr_rrc_dci_PayloadLength, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_searchSpace  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_sfi_PositionInDCI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SFI_PDCCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SFI_PDCCH, SFI_PDCCH_sequence);

  return offset;
}


static const value_string nr_rrc_T_int_TF_vals[] = {
  {   0, "set0" },
  {   1, "set1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_int_TF(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_common_sequence[] = {
  { &hf_nr_rrc_sfi_PDCCH    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SFI_PDCCH },
  { &hf_nr_rrc_preemp_DL    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_int_RNTI     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BIT_STRING_SIZE_16 },
  { &hf_nr_rrc_int_TF       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_int_TF },
  { &hf_nr_rrc_monitoringPeriodicity, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_common(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_common, T_common_sequence);

  return offset;
}


static const per_sequence_t T_ue_Specific_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_ue_Specific(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_ue_Specific, T_ue_Specific_sequence);

  return offset;
}


static const value_string nr_rrc_T_searchSpaceType_vals[] = {
  {   0, "common" },
  {   1, "ue-Specific" },
  { 0, NULL }
};

static const per_choice_t T_searchSpaceType_choice[] = {
  {   0, &hf_nr_rrc_common       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_common },
  {   1, &hf_nr_rrc_ue_Specific  , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_ue_Specific },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_searchSpaceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_searchSpaceType, T_searchSpaceType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SearchSpace_sequence[] = {
  { &hf_nr_rrc_searchSpaceId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SearchSpaceId },
  { &hf_nr_rrc_controlResourceSetId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ControlResourceSetId },
  { &hf_nr_rrc_monitoringSlotPeriodicityAndOffset, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_monitoringSlotPeriodicityAndOffset },
  { &hf_nr_rrc_monitoringSymbolsWithinSlot, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BIT_STRING_SIZE_14 },
  { &hf_nr_rrc_nrofCandidates, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_nrofCandidates },
  { &hf_nr_rrc_searchSpaceType, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_searchSpaceType },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SearchSpace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SearchSpace, SearchSpace_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace_sequence_of[1] = {
  { &hf_nr_rrc_searchSpacesToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SearchSpace },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace, SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace_sequence_of,
                                                  1, maxNrofSearchSpaces, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId_sequence_of[1] = {
  { &hf_nr_rrc_searchSpacesToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SearchSpaceId },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId, SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId_sequence_of,
                                                  1, maxNrofSearchSpaces, FALSE);

  return offset;
}


static const per_sequence_t T_timing_sequence[] = {
  { &hf_nr_rrc_dl_assignment_to_DL_data, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_ul_assignment_to_UL_data, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_dl_data_to_UL_ACK, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_timing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_timing, T_timing_sequence);

  return offset;
}


static const per_sequence_t PDCCH_Config_sequence[] = {
  { &hf_nr_rrc_controlResourceSetToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet },
  { &hf_nr_rrc_controlResourceSetToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId },
  { &hf_nr_rrc_searchSpacesToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace },
  { &hf_nr_rrc_searchSpacesToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId },
  { &hf_nr_rrc_timing       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_timing },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PDCCH_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PDCCH_Config, PDCCH_Config_sequence);

  return offset;
}


static const value_string nr_rrc_T_maxCodeBlockGroupsPerTransportBlock_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n6" },
  {   3, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_maxCodeBlockGroupsPerTransportBlock(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_dmrs_Type_vals[] = {
  {   0, "type1" },
  {   1, "type2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_dmrs_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_dmrs_AdditionalPosition_vals[] = {
  {   0, "pos0" },
  {   1, "pos1" },
  {   2, "pos2" },
  {   3, "pos3" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_dmrs_AdditionalPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_nrofPorts_01_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofPorts_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Downlink_PTRS_Config_sequence[] = {
  { &hf_nr_rrc_frequencyDensity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_timeDensity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_nrofPorts_01 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_nrofPorts_01 },
  { &hf_nr_rrc_epre_Ratio   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_resourceElementOffset, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_Downlink_PTRS_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_Downlink_PTRS_Config, Downlink_PTRS_Config_sequence);

  return offset;
}


static const value_string nr_rrc_T_phaseTracking_RS_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_phaseTracking_RS_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_04     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_Downlink_PTRS_Config },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_phaseTracking_RS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_phaseTracking_RS, T_phaseTracking_RS_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_tci_PresentInDCI_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_tci_PresentInDCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_xOverhead_vals[] = {
  {   0, "n0" },
  {   1, "n6" },
  {   2, "n12" },
  {   3, "n18" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_xOverhead(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_275(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     275, 275, FALSE, NULL, NULL);

  return offset;
}


static const value_string nr_rrc_T_periodicityAndOffset_01_vals[] = {
  {   0, "n5" },
  {   1, "n10" },
  {   2, "n20" },
  {   3, "n40" },
  { 0, NULL }
};

static const per_choice_t T_periodicityAndOffset_01_choice[] = {
  {   0, &hf_nr_rrc_n5           , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_4 },
  {   1, &hf_nr_rrc_n10          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   2, &hf_nr_rrc_n20          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  {   3, &hf_nr_rrc_n40          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_39 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_periodicityAndOffset_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_periodicityAndOffset_01, T_periodicityAndOffset_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RateMatchPattern_sequence[] = {
  { &hf_nr_rrc_resourceBlocks, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BIT_STRING_SIZE_275 },
  { &hf_nr_rrc_symbolsInResourceBlock, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BIT_STRING_SIZE_14 },
  { &hf_nr_rrc_periodicityAndOffset_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_periodicityAndOffset_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RateMatchPattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RateMatchPattern, RateMatchPattern_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern_sequence_of[1] = {
  { &hf_nr_rrc_setup_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RateMatchPattern },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern, SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern_sequence_of,
                                                  1, maxNrofRateMatchPatterns, FALSE);

  return offset;
}


static const value_string nr_rrc_T_rateMatchPatterns_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_rateMatchPatterns_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_05     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_rateMatchPatterns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_rateMatchPatterns, T_rateMatchPatterns_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_nrofCRS_Ports_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofCRS_Ports(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_v_Shift_vals[] = {
  {   0, "n0" },
  {   1, "n1" },
  {   2, "n2" },
  {   3, "n3" },
  {   4, "n4" },
  {   5, "n5" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_v_Shift(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_04_sequence[] = {
  { &hf_nr_rrc_nrofCRS_Ports, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_nrofCRS_Ports },
  { &hf_nr_rrc_v_Shift      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_v_Shift },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_04, T_setup_04_sequence);

  return offset;
}


static const value_string nr_rrc_T_lte_CRS_ToMatchAround_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_lte_CRS_ToMatchAround_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_06     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_lte_CRS_ToMatchAround(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_lte_CRS_ToMatchAround, T_lte_CRS_ToMatchAround_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_rateMatchResourcesPDSCH_sequence[] = {
  { &hf_nr_rrc_rateMatchPatterns, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_rateMatchPatterns },
  { &hf_nr_rrc_lte_CRS_ToMatchAround, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_lte_CRS_ToMatchAround },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_rateMatchResourcesPDSCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_rateMatchResourcesPDSCH, T_rateMatchResourcesPDSCH_sequence);

  return offset;
}


static const value_string nr_rrc_T_rbg_Size_vals[] = {
  {   0, "config1" },
  {   1, "config2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_rbg_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_mcs_Table_vals[] = {
  {   0, "dl-64QAM" },
  {   1, "dl-256QAM" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_mcs_Table(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_maxNrofCodeWordsScheduledByDCI_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_maxNrofCodeWordsScheduledByDCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_harq_ACK_Codebook_vals[] = {
  {   0, "semiStatic" },
  {   1, "dynamic" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_harq_ACK_Codebook(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PDSCH_Config_sequence[] = {
  { &hf_nr_rrc_codeBlockGroupTransmission, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_maxCodeBlockGroupsPerTransportBlock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_maxCodeBlockGroupsPerTransportBlock },
  { &hf_nr_rrc_codeBlockGroupFlushIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_dmrs_Type    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_dmrs_Type },
  { &hf_nr_rrc_dmrs_AdditionalPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_dmrs_AdditionalPosition },
  { &hf_nr_rrc_dmrs_group1  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_dmrs_group2  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_phaseTracking_RS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_phaseTracking_RS },
  { &hf_nr_rrc_tci_States   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_tci_rs_SetConfig, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_tci_PresentInDCI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_tci_PresentInDCI },
  { &hf_nr_rrc_xOverhead    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_xOverhead },
  { &hf_nr_rrc_pdsch_symbolAllocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_rateMatchResourcesPDSCH, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_rateMatchResourcesPDSCH },
  { &hf_nr_rrc_rbg_Size     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_rbg_Size },
  { &hf_nr_rrc_mcs_Table    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_mcs_Table },
  { &hf_nr_rrc_maxNrofCodeWordsScheduledByDCI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_maxNrofCodeWordsScheduledByDCI },
  { &hf_nr_rrc_nrofHARQ_processesForPDSCH, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_harq_ACK_Codebook, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_harq_ACK_Codebook },
  { &hf_nr_rrc_pdsch_BundleSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_prbBundlingEnabled, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PDSCH_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PDSCH_Config, PDSCH_Config_sequence);

  return offset;
}



static int
dissect_nr_rrc_CSI_ResourceConfigId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofCSI_ResourceConfigurations_1, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_CSI_ResourceSetId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofCSI_ResourceSets_1, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_NZP_CSI_RS_ResourceId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofNZP_CSI_RS_Resources_1, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_nrofPorts_vals[] = {
  {   0, "p1" },
  {   1, "p2" },
  {   2, "p4" },
  {   3, "p8" },
  {   4, "p12" },
  {   5, "p16" },
  {   6, "p24" },
  {   7, "p32" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofPorts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_cdm_Value_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_cdm_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_cdm_Pattern_vals[] = {
  {   0, "freqOnly" },
  {   1, "timeAndFreq" },
  {   2, "timeOnly" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_cdm_Pattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_csi_RS_Density_vals[] = {
  {   0, "dot5" },
  {   1, "one" },
  {   2, "three" },
  {   3, "spare" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_csi_RS_Density(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 0U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_csi_RS_timeConfig_vals[] = {
  {   0, "sl5" },
  {   1, "sl10" },
  {   2, "sl20" },
  {   3, "sl40" },
  {   4, "sl80" },
  {   5, "sl160" },
  {   6, "sl320" },
  {   7, "sl640" },
  { 0, NULL }
};

static const per_choice_t T_csi_RS_timeConfig_choice[] = {
  {   0, &hf_nr_rrc_sl5          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_4 },
  {   1, &hf_nr_rrc_sl10         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   2, &hf_nr_rrc_sl20         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  {   3, &hf_nr_rrc_sl40         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_39 },
  {   4, &hf_nr_rrc_sl80         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_79 },
  {   5, &hf_nr_rrc_sl160        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_159 },
  {   6, &hf_nr_rrc_sl320        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_319 },
  {   7, &hf_nr_rrc_sl640        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_639 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_csi_RS_timeConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_csi_RS_timeConfig, T_csi_RS_timeConfig_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NZP_CSI_RS_Resource_sequence[] = {
  { &hf_nr_rrc_nzp_csi_rs_ResourceId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NZP_CSI_RS_ResourceId },
  { &hf_nr_rrc_nrofPorts    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_nrofPorts },
  { &hf_nr_rrc_resourceMapping, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_cdm_Value    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_cdm_Value },
  { &hf_nr_rrc_cdm_Pattern  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_cdm_Pattern },
  { &hf_nr_rrc_csi_RS_Density, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_csi_RS_Density },
  { &hf_nr_rrc_csi_RS_FreqBand, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_powerControlOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_powerControlOffsetSS, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_scramblingID , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0 },
  { &hf_nr_rrc_csi_RS_timeConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_csi_RS_timeConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_NZP_CSI_RS_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_NZP_CSI_RS_Resource, NZP_CSI_RS_Resource_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource_sequence_of[1] = {
  { &hf_nr_rrc_csi_rs_Resources_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NZP_CSI_RS_Resource },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource, SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource_sequence_of,
                                                  1, maxNrofCSI_RS_ResourcesPerSet, FALSE);

  return offset;
}


static const per_sequence_t CSI_ResourceSet_sequence[] = {
  { &hf_nr_rrc_csi_ResourceSetId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_ResourceSetId },
  { &hf_nr_rrc_csi_rs_Resources, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource },
  { &hf_nr_rrc_repetition   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CSI_ResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CSI_ResourceSet, CSI_ResourceSet_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet_sequence_of[1] = {
  { &hf_nr_rrc_csi_ResourceSets_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_ResourceSet },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet, SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet_sequence_of,
                                                  1, maxNrofCSI_ResourceSets, FALSE);

  return offset;
}


static const per_sequence_t CSI_SSB_Resource_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CSI_SSB_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CSI_SSB_Resource, CSI_SSB_Resource_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource_sequence_of[1] = {
  { &hf_nr_rrc_ssb_Resources_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_SSB_Resource },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource, SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource_sequence_of,
                                                  1, maxNrofSSB_Resources_1, FALSE);

  return offset;
}


static const value_string nr_rrc_T_resourceType_vals[] = {
  {   0, "aperiodic" },
  {   1, "semiPersistent" },
  {   2, "periodic" },
  { 0, NULL }
};

static const per_choice_t T_resourceType_choice[] = {
  {   0, &hf_nr_rrc_aperiodic    , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_semiPersistent, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   2, &hf_nr_rrc_periodic     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_resourceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_resourceType, T_resourceType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CSI_ResourceConfig_sequence[] = {
  { &hf_nr_rrc_csi_ResourceConfigId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_ResourceConfigId },
  { &hf_nr_rrc_csi_ResourceSets, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet },
  { &hf_nr_rrc_ssb_Resources, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource },
  { &hf_nr_rrc_resourceType , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_resourceType },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CSI_ResourceConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CSI_ResourceConfig, CSI_ResourceConfig_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig_sequence_of[1] = {
  { &hf_nr_rrc_csi_ResourceConfigs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_ResourceConfig },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig, SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig_sequence_of,
                                                  1, maxNrofCSI_ResourceConfigurations, FALSE);

  return offset;
}



static int
dissect_nr_rrc_CSI_ReportConfigId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofCSI_ReportConfig_1, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_reportSlotConfig_vals[] = {
  {   0, "sl5" },
  {   1, "sl10" },
  {   2, "sl20" },
  {   3, "sl40" },
  {   4, "sl80" },
  {   5, "sl160" },
  {   6, "sl320" },
  { 0, NULL }
};

static const per_choice_t T_reportSlotConfig_choice[] = {
  {   0, &hf_nr_rrc_sl5          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_4 },
  {   1, &hf_nr_rrc_sl10         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   2, &hf_nr_rrc_sl20         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  {   3, &hf_nr_rrc_sl40         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_39 },
  {   4, &hf_nr_rrc_sl80         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_79 },
  {   5, &hf_nr_rrc_sl160        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_159 },
  {   6, &hf_nr_rrc_sl320        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_319 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_reportSlotConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_reportSlotConfig, T_reportSlotConfig_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_periodic_sequence[] = {
  { &hf_nr_rrc_reportSlotConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportSlotConfig },
  { &hf_nr_rrc_pucch_CSI_ResourceIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_periodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_periodic, T_periodic_sequence);

  return offset;
}


static const value_string nr_rrc_T_reportSlotConfig_01_vals[] = {
  {   0, "sl5" },
  {   1, "sl10" },
  {   2, "sl20" },
  {   3, "sl40" },
  {   4, "sl80" },
  {   5, "sl160" },
  {   6, "sl320" },
  { 0, NULL }
};

static const per_choice_t T_reportSlotConfig_01_choice[] = {
  {   0, &hf_nr_rrc_sl5          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_4 },
  {   1, &hf_nr_rrc_sl10         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   2, &hf_nr_rrc_sl20         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  {   3, &hf_nr_rrc_sl40         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_39 },
  {   4, &hf_nr_rrc_sl80         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_79 },
  {   5, &hf_nr_rrc_sl160        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_159 },
  {   6, &hf_nr_rrc_sl320        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_319 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_reportSlotConfig_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_reportSlotConfig_01, T_reportSlotConfig_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_semiPersistent_sequence[] = {
  { &hf_nr_rrc_reportSlotConfig_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportSlotConfig_01 },
  { &hf_nr_rrc_pucch_CSI_ResourceIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_semiPersistent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_semiPersistent, T_semiPersistent_sequence);

  return offset;
}


static const per_sequence_t T_aperiodic_sequence[] = {
  { &hf_nr_rrc_aperiodicReportSlotOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_aperiodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_aperiodic, T_aperiodic_sequence);

  return offset;
}


static const value_string nr_rrc_T_reportConfigType_vals[] = {
  {   0, "periodic" },
  {   1, "semiPersistent" },
  {   2, "aperiodic" },
  { 0, NULL }
};

static const per_choice_t T_reportConfigType_choice[] = {
  {   0, &hf_nr_rrc_periodic_01  , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_periodic },
  {   1, &hf_nr_rrc_semiPersistent_01, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_semiPersistent },
  {   2, &hf_nr_rrc_aperiodic_01 , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_aperiodic },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_reportConfigType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_reportConfigType, T_reportConfigType_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_pdsch_BundleSizeForCSI_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_pdsch_BundleSizeForCSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_cRI_RI_i1_CQI_sequence[] = {
  { &hf_nr_rrc_pdsch_BundleSizeForCSI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_pdsch_BundleSizeForCSI },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_cRI_RI_i1_CQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_cRI_RI_i1_CQI, T_cRI_RI_i1_CQI_sequence);

  return offset;
}


static const value_string nr_rrc_T_reportQuantity_vals[] = {
  {   0, "cRI-RI-PMI-CQI" },
  {   1, "cRI-RI-i1" },
  {   2, "cRI-RI-i1-CQI" },
  {   3, "cRI-RI-CQI" },
  {   4, "cRI" },
  {   5, "cRI-RSRP" },
  {   6, "spare1" },
  {   7, "spare0" },
  { 0, NULL }
};

static const per_choice_t T_reportQuantity_choice[] = {
  {   0, &hf_nr_rrc_cRI_RI_PMI_CQI, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_cRI_RI_i1    , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   2, &hf_nr_rrc_cRI_RI_i1_CQI, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_cRI_RI_i1_CQI },
  {   3, &hf_nr_rrc_cRI_RI_CQI   , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   4, &hf_nr_rrc_cRI          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   5, &hf_nr_rrc_cRI_RSRP     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   6, &hf_nr_rrc_spare1       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   7, &hf_nr_rrc_spare0       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_reportQuantity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_reportQuantity, T_reportQuantity_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_cqi_FormatIndicator_vals[] = {
  {   0, "widebandCQI" },
  {   1, "subbandCQI" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_cqi_FormatIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_pmi_FormatIndicator_vals[] = {
  {   0, "widebandPMI" },
  {   1, "subbandPMI" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_pmi_FormatIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_T_csi_ReportingBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t T_reportFreqConfiguration_sequence[] = {
  { &hf_nr_rrc_cqi_FormatIndicator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_cqi_FormatIndicator },
  { &hf_nr_rrc_pmi_FormatIndicator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_pmi_FormatIndicator },
  { &hf_nr_rrc_csi_ReportingBand, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_csi_ReportingBand },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_reportFreqConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_reportFreqConfiguration, T_reportFreqConfiguration_sequence);

  return offset;
}


static const value_string nr_rrc_T_codebookConfig_N1_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n3" },
  {   3, "n4" },
  {   4, "n6" },
  {   5, "n8" },
  {   6, "n12" },
  {   7, "n16" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_codebookConfig_N1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_codebookConfig_N2_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n3" },
  {   3, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_codebookConfig_N2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_subType_vals[] = {
  {   0, "typeI-SinglePanel" },
  {   1, "typeI-MultiPanel" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_subType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_codebookMode_vals[] = {
  {   0, "config1" },
  {   1, "config2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_codebookMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_numberOfPanels_vals[] = {
  {   0, "panels2" },
  {   1, "panels4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_numberOfPanels(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_T_singlePanel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_nr_rrc_T_multiPanel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}


static const value_string nr_rrc_T_codebookSubsetRestrictionType1_vals[] = {
  {   0, "singlePanel" },
  {   1, "singlePanel2TX" },
  {   2, "multiPanel" },
  {   3, "singlePanelCodebookSubsetRestriction-i2" },
  { 0, NULL }
};

static const per_choice_t T_codebookSubsetRestrictionType1_choice[] = {
  {   0, &hf_nr_rrc_singlePanel  , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_singlePanel },
  {   1, &hf_nr_rrc_singlePanel2TX, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_6 },
  {   2, &hf_nr_rrc_multiPanel   , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_multiPanel },
  {   3, &hf_nr_rrc_singlePanelCodebookSubsetRestriction_i2, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_codebookSubsetRestrictionType1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_codebookSubsetRestrictionType1, T_codebookSubsetRestrictionType1_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_ri_Restriction_vals[] = {
  {   0, "typeI-SinglePanelRI-Restriction" },
  {   1, "typeI-MultiPanelRI-Restriction" },
  { 0, NULL }
};

static const per_choice_t T_ri_Restriction_choice[] = {
  {   0, &hf_nr_rrc_typeI_SinglePanelRI_Restriction, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_8 },
  {   1, &hf_nr_rrc_typeI_MultiPanelRI_Restriction, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_4 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_ri_Restriction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_ri_Restriction, T_ri_Restriction_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type1_sequence[] = {
  { &hf_nr_rrc_subType      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_subType },
  { &hf_nr_rrc_codebookMode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_codebookMode },
  { &hf_nr_rrc_numberOfPanels, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_numberOfPanels },
  { &hf_nr_rrc_codebookSubsetRestrictionType1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_codebookSubsetRestrictionType1 },
  { &hf_nr_rrc_ri_Restriction, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_ri_Restriction },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_type1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_type1, T_type1_sequence);

  return offset;
}


static const value_string nr_rrc_T_subType_01_vals[] = {
  {   0, "typeII" },
  {   1, "typeII-PortSelection" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_subType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_phaseAlphabetSize_vals[] = {
  {   0, "n4" },
  {   1, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_phaseAlphabetSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_numberOfBeams_vals[] = {
  {   0, "beams2" },
  {   1, "beams3" },
  {   2, "beams4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_numberOfBeams(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_portSelectionSamplingSize_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n3" },
  {   3, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_portSelectionSamplingSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_T_codebookSubsetRestrictionType2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_nr_rrc_BIT_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}


static const value_string nr_rrc_T_ri_Restriction_01_vals[] = {
  {   0, "typeII-RI-Restriction" },
  {   1, "typeII-PortSelectionRI-Restriction" },
  { 0, NULL }
};

static const per_choice_t T_ri_Restriction_01_choice[] = {
  {   0, &hf_nr_rrc_typeII_RI_Restriction, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_2 },
  {   1, &hf_nr_rrc_typeII_PortSelectionRI_Restriction, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_ri_Restriction_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_ri_Restriction_01, T_ri_Restriction_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_sequence[] = {
  { &hf_nr_rrc_subType_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_subType_01 },
  { &hf_nr_rrc_phaseAlphabetSize, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_phaseAlphabetSize },
  { &hf_nr_rrc_subbandAmplitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_numberOfBeams, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_numberOfBeams },
  { &hf_nr_rrc_portSelectionSamplingSize, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_portSelectionSamplingSize },
  { &hf_nr_rrc_codebookSubsetRestrictionType2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_codebookSubsetRestrictionType2 },
  { &hf_nr_rrc_ri_Restriction_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_ri_Restriction_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_type2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_type2, T_type2_sequence);

  return offset;
}


static const value_string nr_rrc_T_codebookType_vals[] = {
  {   0, "type1" },
  {   1, "type2" },
  { 0, NULL }
};

static const per_choice_t T_codebookType_choice[] = {
  {   0, &hf_nr_rrc_type1        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_type1 },
  {   1, &hf_nr_rrc_type2        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_type2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_codebookType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_codebookType, T_codebookType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CodebookConfig_sequence[] = {
  { &hf_nr_rrc_codebookConfig_N1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_codebookConfig_N1 },
  { &hf_nr_rrc_codebookConfig_N2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_codebookConfig_N2 },
  { &hf_nr_rrc_codebookType , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_codebookType },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CodebookConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CodebookConfig, CodebookConfig_sequence);

  return offset;
}


static const value_string nr_rrc_T_nrofCQIsPerReport_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofCQIsPerReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_2_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 4U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_enabled_sequence[] = {
  { &hf_nr_rrc_nrofBeamsToReport, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_2_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_enabled(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_enabled, T_enabled_sequence);

  return offset;
}


static const value_string nr_rrc_T_nrofReportedRS_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n3" },
  {   3, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofReportedRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_disabled_sequence[] = {
  { &hf_nr_rrc_nrofReportedRS, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_nrofReportedRS },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_disabled(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_disabled, T_disabled_sequence);

  return offset;
}


static const value_string nr_rrc_T_groupBasedBeamReporting_vals[] = {
  {   0, "enabled" },
  {   1, "disabled" },
  { 0, NULL }
};

static const per_choice_t T_groupBasedBeamReporting_choice[] = {
  {   0, &hf_nr_rrc_enabled      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_enabled },
  {   1, &hf_nr_rrc_disabled     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_disabled },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_groupBasedBeamReporting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_groupBasedBeamReporting, T_groupBasedBeamReporting_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_cqi_Table_vals[] = {
  {   0, "dl-64QAM" },
  {   1, "dl-256QAM" },
  {   2, "urllc1" },
  {   3, "urllc2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_cqi_Table(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_subbandSize_vals[] = {
  {   0, "value1" },
  {   1, "value2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_subbandSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_bler_Target_vals[] = {
  {   0, "v0dot1" },
  {   1, "spare3" },
  {   2, "space2" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_bler_Target(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t CSI_ReportConfig_sequence[] = {
  { &hf_nr_rrc_reportConfigId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_ReportConfigId },
  { &hf_nr_rrc_reportConfigType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportConfigType },
  { &hf_nr_rrc_reportQuantity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportQuantity },
  { &hf_nr_rrc_reportFreqConfiguration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportFreqConfiguration },
  { &hf_nr_rrc_measRestrictionTimeForChannel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_measRestrictionTimeForInterference, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_codebookConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CodebookConfig },
  { &hf_nr_rrc_nrofCQIsPerReport, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_nrofCQIsPerReport },
  { &hf_nr_rrc_groupBasedBeamReporting, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_groupBasedBeamReporting },
  { &hf_nr_rrc_cqi_Table    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_cqi_Table },
  { &hf_nr_rrc_subbandSize  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_subbandSize },
  { &hf_nr_rrc_bler_Target  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_bler_Target },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CSI_ReportConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CSI_ReportConfig, CSI_ReportConfig_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig_sequence_of[1] = {
  { &hf_nr_rrc_csi_ReportConfigs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_ReportConfig },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig, SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig_sequence_of,
                                                  1, maxNrofCSI_Reports, FALSE);

  return offset;
}



static int
dissect_nr_rrc_CSI_MeasId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofCSI_MeasId_1, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_CSI_RS_ConfigurationId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string nr_rrc_T_measQuantity_vals[] = {
  {   0, "channel" },
  {   1, "interference" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_measQuantity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t CSI_MeasIdToAddMod_sequence[] = {
  { &hf_nr_rrc_csi_measId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_MeasId },
  { &hf_nr_rrc_csi_RS_resourceConfigId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_RS_ConfigurationId },
  { &hf_nr_rrc_csi_reportConfigId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_ReportConfigId },
  { &hf_nr_rrc_measQuantity , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_measQuantity },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CSI_MeasIdToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CSI_MeasIdToAddMod, CSI_MeasIdToAddMod_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod_sequence_of[1] = {
  { &hf_nr_rrc_csi_MeasIdToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_MeasIdToAddMod },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod, SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod_sequence_of,
                                                  1, maxNrofCSI_MeasId, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 6U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_reportTrigger_sequence[] = {
  { &hf_nr_rrc_reportTriggerSize, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_6 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_reportTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_reportTrigger, T_reportTrigger_sequence);

  return offset;
}


static const per_sequence_t CSI_MeasConfig_sequence[] = {
  { &hf_nr_rrc_csi_ResourceConfigs, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig },
  { &hf_nr_rrc_csi_ReportConfigs, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig },
  { &hf_nr_rrc_csi_MeasIdToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod },
  { &hf_nr_rrc_reportTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportTrigger },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CSI_MeasConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CSI_MeasConfig, CSI_MeasConfig_sequence);

  return offset;
}


static const per_sequence_t PUCCH_ResourceSet_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PUCCH_ResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PUCCH_ResourceSet, PUCCH_ResourceSet_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet_sequence_of[1] = {
  { &hf_nr_rrc_resourceSets_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PUCCH_ResourceSet },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet, SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet_sequence_of,
                                                  1, 1, FALSE);

  return offset;
}


static const value_string nr_rrc_T_interslotFrequencyHopping_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_interslotFrequencyHopping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_nrofSlots_vals[] = {
  {   0, "n1" },
  {   1, "ny1" },
  {   2, "y2" },
  {   3, "y3" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofSlots(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_05_sequence[] = {
  { &hf_nr_rrc_interslotFrequencyHopping, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_interslotFrequencyHopping },
  { &hf_nr_rrc_nrofSlots    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_nrofSlots },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_05, T_setup_05_sequence);

  return offset;
}


static const value_string nr_rrc_T_format1_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_format1_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_07     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_05 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_format1, T_format1_choice,
                                 NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_simultaneousHARQ_ACK_CSI_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_simultaneousHARQ_ACK_CSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_06_sequence[] = {
  { &hf_nr_rrc_maxCodeRate  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_7 },
  { &hf_nr_rrc_nrofPRBs     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_16 },
  { &hf_nr_rrc_simultaneousHARQ_ACK_CSI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_simultaneousHARQ_ACK_CSI },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_06, T_setup_06_sequence);

  return offset;
}


static const value_string nr_rrc_T_format2_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_format2_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_08     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_06 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_format2, T_format2_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_interslotFrequencyHopping_01_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_interslotFrequencyHopping_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_additionalDMRS_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_additionalDMRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_nrofSlots_01_vals[] = {
  {   0, "n1" },
  {   1, "y1" },
  {   2, "y2" },
  {   3, "y3" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofSlots_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_pi2PBSK_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_pi2PBSK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_07_sequence[] = {
  { &hf_nr_rrc_interslotFrequencyHopping_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_interslotFrequencyHopping_01 },
  { &hf_nr_rrc_additionalDMRS, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_additionalDMRS },
  { &hf_nr_rrc_maxCodeRate  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_7 },
  { &hf_nr_rrc_nrofSlots_01 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_nrofSlots_01 },
  { &hf_nr_rrc_pi2PBSK      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_pi2PBSK },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_07, T_setup_07_sequence);

  return offset;
}


static const value_string nr_rrc_T_format3_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_format3_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_09     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_07 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_format3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_format3, T_format3_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_interslotFrequencyHopping_02_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_interslotFrequencyHopping_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_additionalDMRS_01_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_additionalDMRS_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_nrofSlots_02_vals[] = {
  {   0, "n1" },
  {   1, "y1" },
  {   2, "y2" },
  {   3, "y3" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofSlots_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_pi2PBSK_01_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_pi2PBSK_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_08_sequence[] = {
  { &hf_nr_rrc_interslotFrequencyHopping_02, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_interslotFrequencyHopping_02 },
  { &hf_nr_rrc_additionalDMRS_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_additionalDMRS_01 },
  { &hf_nr_rrc_maxCodeRate  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_7 },
  { &hf_nr_rrc_nrofSlots_02 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_nrofSlots_02 },
  { &hf_nr_rrc_pi2PBSK_01   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_pi2PBSK_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_08, T_setup_08_sequence);

  return offset;
}


static const value_string nr_rrc_T_format4_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_format4_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_10     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_08 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_format4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_format4, T_format4_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SchedulingRequestResource_Config_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SchedulingRequestResource_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SchedulingRequestResource_Config, SchedulingRequestResource_Config_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config_sequence_of[1] = {
  { &hf_nr_rrc_setup_item_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SchedulingRequestResource_Config },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config, SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config_sequence_of,
                                                  1, maxNrofSchedulingRequestResoruces, FALSE);

  return offset;
}


static const value_string nr_rrc_T_schedulingRequestResources_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_schedulingRequestResources_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_11     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_schedulingRequestResources(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_schedulingRequestResources, T_schedulingRequestResources_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PUCCH_Config_sequence[] = {
  { &hf_nr_rrc_resourceSets , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet },
  { &hf_nr_rrc_format1      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_format1 },
  { &hf_nr_rrc_format2      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_format2 },
  { &hf_nr_rrc_format3      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_format3 },
  { &hf_nr_rrc_format4      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_format4 },
  { &hf_nr_rrc_schedulingRequestResources, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_schedulingRequestResources },
  { &hf_nr_rrc_tpc_PUCCH_RNTI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BIT_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PUCCH_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PUCCH_Config, PUCCH_Config_sequence);

  return offset;
}


static const value_string nr_rrc_T_codeBlockGroupTransmission_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_codeBlockGroupTransmission(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_maxCodeBlockGroupsPerTransportBlock_01_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n6" },
  {   3, "n8" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_maxCodeBlockGroupsPerTransportBlock_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_dmrs_Type_01_vals[] = {
  {   0, "type1" },
  {   1, "type2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_dmrs_Type_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_dmrs_AdditionalPosition_01_vals[] = {
  {   0, "pos0" },
  {   1, "pos1" },
  {   2, "pos2" },
  {   3, "pos3" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_dmrs_AdditionalPosition_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_nrofPorts_02_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofPorts_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_10_sequence[] = {
  { &hf_nr_rrc_frequencyDensity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_timeDensity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_nrofPorts_02 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_nrofPorts_02 },
  { &hf_nr_rrc_resourceElementOffset, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_10, T_setup_10_sequence);

  return offset;
}


static const value_string nr_rrc_T_cp_OFDM_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_cp_OFDM_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_14     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_10 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_cp_OFDM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_cp_OFDM, T_cp_OFDM_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_timeDensity_vals[] = {
  {   0, "d1" },
  {   1, "d2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_timeDensity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_11_sequence[] = {
  { &hf_nr_rrc_sampleDensity, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_timeDensity_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_timeDensity },
  { &hf_nr_rrc_sequence     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_11, T_setup_11_sequence);

  return offset;
}


static const value_string nr_rrc_T_dft_S_OFDM_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_dft_S_OFDM_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_15     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_11 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_dft_S_OFDM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_dft_S_OFDM, T_dft_S_OFDM_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Uplink_PTRS_Config_sequence[] = {
  { &hf_nr_rrc_cp_OFDM      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_cp_OFDM },
  { &hf_nr_rrc_dft_S_OFDM   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_dft_S_OFDM },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_Uplink_PTRS_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_Uplink_PTRS_Config, Uplink_PTRS_Config_sequence);

  return offset;
}


static const value_string nr_rrc_T_phaseTracking_RS_01_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_phaseTracking_RS_01_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_12     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_Uplink_PTRS_Config },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_phaseTracking_RS_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_phaseTracking_RS_01, T_phaseTracking_RS_01_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_tpcAccumulation_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_tpcAccumulation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_frequencyHopping_vals[] = {
  {   0, "mode1" },
  {   1, "mode2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_frequencyHopping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_rateMatching_vals[] = {
  {   0, "fullBufferRM" },
  {   1, "limitedBufferRM" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_rateMatching(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_mcs_Table_01_vals[] = {
  {   0, "ul-64QAM" },
  {   1, "ul-256QAM" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_mcs_Table_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_mcs_TableTransformPrecoder_vals[] = {
  {   0, "ul-64QAM" },
  {   1, "ul-256QAM" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_mcs_TableTransformPrecoder(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_transformPrecoder_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_transformPrecoder(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_rbg_Size_01_vals[] = {
  {   0, "config1" },
  {   1, "config2" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_rbg_Size_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t BetaOffsets_sequence[] = {
  { &hf_nr_rrc_betaOffsetACK_Index1, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_31 },
  { &hf_nr_rrc_betaOffsetACK_Index2, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_31 },
  { &hf_nr_rrc_betaOffsetACK_Index3, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_31 },
  { &hf_nr_rrc_betaOffsetCSI_part1_Index1, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_31 },
  { &hf_nr_rrc_betaOffsetCSI_part1_Index2, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_31 },
  { &hf_nr_rrc_betaOffsetCSI_part2_Index1, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_31 },
  { &hf_nr_rrc_betaOffsetCSI_part2_Index2, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_31 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BetaOffsets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BetaOffsets, BetaOffsets_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4_OF_BetaOffsets_sequence_of[1] = {
  { &hf_nr_rrc_dynamic_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BetaOffsets },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_4_OF_BetaOffsets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_4_OF_BetaOffsets, SEQUENCE_SIZE_1_4_OF_BetaOffsets_sequence_of,
                                                  1, 4, FALSE);

  return offset;
}


static const value_string nr_rrc_T_setup_09_vals[] = {
  {   0, "dynamic" },
  {   1, "semiStatic" },
  { 0, NULL }
};

static const per_choice_t T_setup_09_choice[] = {
  {   0, &hf_nr_rrc_dynamic      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_SEQUENCE_SIZE_1_4_OF_BetaOffsets },
  {   1, &hf_nr_rrc_semiStatic   , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BetaOffsets },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_setup_09, T_setup_09_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_uci_on_PUSCH_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_uci_on_PUSCH_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_13     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_09 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_uci_on_PUSCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_uci_on_PUSCH, T_uci_on_PUSCH_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_xOverhead_01_vals[] = {
  {   0, "n0" },
  {   1, "n6" },
  {   2, "n12" },
  {   3, "n18" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_xOverhead_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PUSCH_Config_sequence[] = {
  { &hf_nr_rrc_codeBlockGroupTransmission_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_codeBlockGroupTransmission },
  { &hf_nr_rrc_maxCodeBlockGroupsPerTransportBlock_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_maxCodeBlockGroupsPerTransportBlock_01 },
  { &hf_nr_rrc_dmrs_Type_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_dmrs_Type_01 },
  { &hf_nr_rrc_dmrs_AdditionalPosition_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_dmrs_AdditionalPosition_01 },
  { &hf_nr_rrc_phaseTracking_RS_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_phaseTracking_RS_01 },
  { &hf_nr_rrc_tpcAccumulation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_tpcAccumulation },
  { &hf_nr_rrc_tcp_PUSCH_RNTI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_BIT_STRING_SIZE_16 },
  { &hf_nr_rrc_frequencyHopping, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_frequencyHopping },
  { &hf_nr_rrc_rateMatching , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_rateMatching },
  { &hf_nr_rrc_rateMatchResources, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_symbolAllocationIndexs, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_mcs_Table_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_mcs_Table_01 },
  { &hf_nr_rrc_mcs_TableTransformPrecoder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_mcs_TableTransformPrecoder },
  { &hf_nr_rrc_transformPrecoder, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_transformPrecoder },
  { &hf_nr_rrc_rbg_Size_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_rbg_Size_01 },
  { &hf_nr_rrc_uci_on_PUSCH , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_uci_on_PUSCH },
  { &hf_nr_rrc_xOverhead_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nr_rrc_T_xOverhead_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PUSCH_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PUSCH_Config, PUSCH_Config_sequence);

  return offset;
}



static int
dissect_nr_rrc_SRS_ResourceSetId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofSRS_ResourceSets_1, NULL, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId_sequence_of[1] = {
  { &hf_nr_rrc_srs_ResourceSetToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRS_ResourceSetId },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId, SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId_sequence_of,
                                                  0, maxNrofSRS_ResourceSets, FALSE);

  return offset;
}



static int
dissect_nr_rrc_SRS_ResourceId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofSRS_Resources_1, NULL, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId_sequence_of[1] = {
  { &hf_nr_rrc_srs_ResourcesIds_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRS_ResourceId },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId, SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId_sequence_of,
                                                  1, maxNrofSRS_ResourcesPerSet, FALSE);

  return offset;
}


static const per_sequence_t SRS_ResourceSet_sequence[] = {
  { &hf_nr_rrc_srs_ResourceSetId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRS_ResourceSetId },
  { &hf_nr_rrc_srs_ResourcesIds, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId },
  { &hf_nr_rrc_aperiodicSRS_ResourceTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SRS_ResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SRS_ResourceSet, SRS_ResourceSet_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet_sequence_of[1] = {
  { &hf_nr_rrc_srs_ResourceSetToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRS_ResourceSet },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet, SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet_sequence_of,
                                                  0, maxNrofSRS_ResourceSets, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId_sequence_of[1] = {
  { &hf_nr_rrc_srs_ResourceToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRS_ResourceId },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId, SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId_sequence_of,
                                                  1, maxNrofSRS_Resources, FALSE);

  return offset;
}


static const value_string nr_rrc_T_nrofSRS_Ports_vals[] = {
  {   0, "port1" },
  {   1, "ports2" },
  {   2, "ports4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_nrofSRS_Ports(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_transmissionComb_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_transmissionComb(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_aperiodic_01_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_aperiodic_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_aperiodic_01, T_aperiodic_01_sequence);

  return offset;
}


static const per_sequence_t T_semi_persistent_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_semi_persistent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_semi_persistent, T_semi_persistent_sequence);

  return offset;
}


static const per_sequence_t T_periodic_01_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_periodic_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_periodic_01, T_periodic_01_sequence);

  return offset;
}


static const value_string nr_rrc_T_resourceType_01_vals[] = {
  {   0, "aperiodic" },
  {   1, "semi-persistent" },
  {   2, "periodic" },
  { 0, NULL }
};

static const per_choice_t T_resourceType_01_choice[] = {
  {   0, &hf_nr_rrc_aperiodic_02 , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_aperiodic_01 },
  {   1, &hf_nr_rrc_semi_persistent, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_semi_persistent },
  {   2, &hf_nr_rrc_periodic_02  , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_periodic_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_resourceType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_resourceType_01, T_resourceType_01_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_periodicityAndOffset_02_vals[] = {
  {   0, "sl2" },
  {   1, "sl5" },
  {   2, "sl10" },
  {   3, "sl20" },
  {   4, "sl40" },
  {   5, "sl80" },
  {   6, "sl160" },
  {   7, "sl320" },
  { 0, NULL }
};

static const per_choice_t T_periodicityAndOffset_02_choice[] = {
  {   0, &hf_nr_rrc_sl2          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_1 },
  {   1, &hf_nr_rrc_sl5          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_4 },
  {   2, &hf_nr_rrc_sl10         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   3, &hf_nr_rrc_sl20         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  {   4, &hf_nr_rrc_sl40         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_39 },
  {   5, &hf_nr_rrc_sl80         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_79 },
  {   6, &hf_nr_rrc_sl160        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_159 },
  {   7, &hf_nr_rrc_sl320        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_319 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_periodicityAndOffset_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_periodicityAndOffset_02, T_periodicityAndOffset_02_choice,
                                 NULL);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_0_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 12U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_spatialRelationInfo_vals[] = {
  {   0, "ssb-pbch" },
  {   1, "csi-rs" },
  {   2, "srs" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_spatialRelationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t SRS_Resource_sequence[] = {
  { &hf_nr_rrc_srs_ResourceId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRS_ResourceId },
  { &hf_nr_rrc_nrofSRS_Ports, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_nrofSRS_Ports },
  { &hf_nr_rrc_transmissionComb, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_transmissionComb },
  { &hf_nr_rrc_resourceMapping, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_freqDomainPosition, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_freqHopping  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_0_63 },
  { &hf_nr_rrc_groupOrSequenceHopping, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_2 },
  { &hf_nr_rrc_resourceType_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_resourceType_01 },
  { &hf_nr_rrc_periodicityAndOffset_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_periodicityAndOffset_02 },
  { &hf_nr_rrc_sequenceId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_antennaSwitching, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_carrierSwitching, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_cyclicShift  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_0_12 },
  { &hf_nr_rrc_spatialRelationInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_spatialRelationInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SRS_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SRS_Resource, SRS_Resource_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource_sequence_of[1] = {
  { &hf_nr_rrc_srs_ResourceToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SRS_Resource },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource, SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource_sequence_of,
                                                  1, maxNrofSRS_Resources, FALSE);

  return offset;
}


static const per_sequence_t SRS_Config_sequence[] = {
  { &hf_nr_rrc_srs_ResourceSetToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId },
  { &hf_nr_rrc_srs_ResourceSetToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet },
  { &hf_nr_rrc_srs_ResourceToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId },
  { &hf_nr_rrc_srs_ResourceToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource },
  { &hf_nr_rrc_tpc_SRS_RNTI , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BIT_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SRS_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SRS_Config, SRS_Config_sequence);

  return offset;
}


static const value_string nr_rrc_T_transformPrecoder_01_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_transformPrecoder_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_repK_RV_vals[] = {
  {   0, "s1-0231" },
  {   1, "s2-0303" },
  {   2, "s3-0000" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_repK_RV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_priodicity_vals[] = {
  {   0, "sym2" },
  {   1, "sym7" },
  {   2, "ms0dot125" },
  {   3, "ms0dot25" },
  {   4, "ms0dot5" },
  {   5, "ms1" },
  {   6, "ms2" },
  {   7, "ms5" },
  {   8, "ms10" },
  {   9, "ms20" },
  {  10, "ms32" },
  {  11, "ms40" },
  {  12, "ms64" },
  {  13, "ms80" },
  {  14, "ms128" },
  {  15, "ms160" },
  {  16, "ms320" },
  {  17, "ms640" },
  { 0, NULL }
};

static value_string_ext nr_rrc_T_priodicity_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_T_priodicity_vals);


static int
dissect_nr_rrc_T_priodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     18, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_setup_12_sequence[] = {
  { &hf_nr_rrc_timeDomainOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_timeDomainAllocation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_frequencyDomainAllocation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_dmrs         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_mcsAndTBS    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_repK         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_setup_12, T_setup_12_sequence);

  return offset;
}


static const value_string nr_rrc_T_rrcConfiguredUplinkGrant_vals[] = {
  {   0, "setup" },
  {   1, "release" },
  { 0, NULL }
};

static const per_choice_t T_rrcConfiguredUplinkGrant_choice[] = {
  {   0, &hf_nr_rrc_setup_16     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_12 },
  {   1, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_rrcConfiguredUplinkGrant(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_rrcConfiguredUplinkGrant, T_rrcConfiguredUplinkGrant_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_uplink_sequence[] = {
  { &hf_nr_rrc_periodicity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_powerControl , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_transformPrecoder_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_transformPrecoder_01 },
  { &hf_nr_rrc_nrofHARQ_processes, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_1 },
  { &hf_nr_rrc_repK_RV      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_repK_RV },
  { &hf_nr_rrc_priodicity   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_priodicity },
  { &hf_nr_rrc_rrcConfiguredUplinkGrant, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_rrcConfiguredUplinkGrant },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_uplink(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_uplink, T_uplink_sequence);

  return offset;
}


static const per_sequence_t SPS_Config_sequence[] = {
  { &hf_nr_rrc_uplink       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_uplink },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SPS_Config(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SPS_Config, SPS_Config_sequence);

  return offset;
}


static const per_sequence_t T_own_sequence[] = {
  { &hf_nr_rrc_cif_Presence , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_own(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_own, T_own_sequence);

  return offset;
}



static int
dissect_nr_rrc_ServCellIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16U, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_other_sequence[] = {
  { &hf_nr_rrc_schedulingCellId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ServCellIndex },
  { &hf_nr_rrc_pdsch_Start  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_4 },
  { &hf_nr_rrc_cif_InSchedulingCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_other(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_other, T_other_sequence);

  return offset;
}


static const value_string nr_rrc_T_schedulingCellInfo_vals[] = {
  {   0, "own" },
  {   1, "other" },
  { 0, NULL }
};

static const per_choice_t T_schedulingCellInfo_choice[] = {
  {   0, &hf_nr_rrc_own          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_own },
  {   1, &hf_nr_rrc_other        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_other },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_schedulingCellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_schedulingCellInfo, T_schedulingCellInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CrossCarrierSchedulingConfig_sequence[] = {
  { &hf_nr_rrc_schedulingCellInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_schedulingCellInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CrossCarrierSchedulingConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CrossCarrierSchedulingConfig, CrossCarrierSchedulingConfig_sequence);

  return offset;
}


static const value_string nr_rrc_T_ue_BeamLockFunction_vals[] = {
  {   0, "enabled" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_ue_BeamLockFunction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_pathlossReferenceLinking_vals[] = {
  {   0, "pCell" },
  {   1, "sCell" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_pathlossReferenceLinking(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ServingCellConfigDedicated_sequence[] = {
  { &hf_nr_rrc_tdd_UL_DL_configurationDedicated, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_tdd_UL_DL_configurationDedicated },
  { &hf_nr_rrc_bandwidthParts, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BandwidthParts },
  { &hf_nr_rrc_dataScramblingIdentity, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_NULL },
  { &hf_nr_rrc_pdcch_Config , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_PDCCH_Config },
  { &hf_nr_rrc_pdsch_Config , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_PDSCH_Config },
  { &hf_nr_rrc_csi_MeasConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CSI_MeasConfig },
  { &hf_nr_rrc_pucch_Config , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_PUCCH_Config },
  { &hf_nr_rrc_pusch_Config , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_PUSCH_Config },
  { &hf_nr_rrc_srs_Config   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SRS_Config },
  { &hf_nr_rrc_sps_Config   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SPS_Config },
  { &hf_nr_rrc_crossCarrierSchedulingConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CrossCarrierSchedulingConfig },
  { &hf_nr_rrc_tag_Id       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TAG_Id },
  { &hf_nr_rrc_ue_BeamLockFunction, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_ue_BeamLockFunction },
  { &hf_nr_rrc_pathlossReferenceLinking, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_pathlossReferenceLinking },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ServingCellConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ServingCellConfigDedicated, ServingCellConfigDedicated_sequence);

  return offset;
}


static const per_sequence_t SpCellConfig_sequence[] = {
  { &hf_nr_rrc_reconfigurationWithSync, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_reconfigurationWithSync },
  { &hf_nr_rrc_spCellConfigDedicated, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ServingCellConfigDedicated },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SpCellConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SpCellConfig, SpCellConfig_sequence);

  return offset;
}



static int
dissect_nr_rrc_SCellIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 31U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SCellConfig_sequence[] = {
  { &hf_nr_rrc_sCellIndex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SCellIndex },
  { &hf_nr_rrc_sCellConfigCommon, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ServingCellConfigCommon },
  { &hf_nr_rrc_sCellConfigDedicated, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ServingCellConfigDedicated },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SCellConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SCellConfig, SCellConfig_sequence);

  return offset;
}


static const per_sequence_t SCellToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_SCellToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SCellConfig },
};

static int
dissect_nr_rrc_SCellToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SCellToAddModList, SCellToAddModList_sequence_of,
                                                  1, maxNrofSCells, FALSE);

  return offset;
}


static const per_sequence_t SCellToReleaseList_sequence_of[1] = {
  { &hf_nr_rrc_SCellToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SCellIndex },
};

static int
dissect_nr_rrc_SCellToReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SCellToReleaseList, SCellToReleaseList_sequence_of,
                                                  1, maxNrofSCells, FALSE);

  return offset;
}


static const per_sequence_t CellGroupConfig_sequence[] = {
  { &hf_nr_rrc_cellGroupId  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CellGroupId },
  { &hf_nr_rrc_rlc_BearerToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config },
  { &hf_nr_rrc_rlc_BearerToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity },
  { &hf_nr_rrc_mac_CellGroupConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MAC_CellGroupConfig },
  { &hf_nr_rrc_rlf_TimersAndConstants, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RLF_TimersAndConstants },
  { &hf_nr_rrc_physical_CellGroupConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_PhysicalCellGroupConfig },
  { &hf_nr_rrc_spCellConfig , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SpCellConfig },
  { &hf_nr_rrc_sCellToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SCellToAddModList },
  { &hf_nr_rrc_sCellToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SCellToReleaseList },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CellGroupConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CellGroupConfig, CellGroupConfig_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig_sequence_of[1] = {
  { &hf_nr_rrc_secondaryCellGroupToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CellGroupConfig },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig, SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig_sequence_of,
                                                  1, maxSCellGroups, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId_sequence_of[1] = {
  { &hf_nr_rrc_secondaryCellGroupToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CellGroupId },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId, SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId_sequence_of,
                                                  1, maxSCellGroups, FALSE);

  return offset;
}



static int
dissect_nr_rrc_MeasObjectId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNrofObjectId, NULL, FALSE);

  return offset;
}


static const per_sequence_t MeasObjectToRemoveList_sequence_of[1] = {
  { &hf_nr_rrc_MeasObjectToRemoveList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasObjectId },
};

static int
dissect_nr_rrc_MeasObjectToRemoveList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_MeasObjectToRemoveList, MeasObjectToRemoveList_sequence_of,
                                                  1, maxNrofObjectId, FALSE);

  return offset;
}


static const value_string nr_rrc_T_periodicityAndOffset_vals[] = {
  {   0, "sf5" },
  {   1, "sf10" },
  {   2, "sf20" },
  {   3, "sf40" },
  {   4, "sf80" },
  {   5, "sf160" },
  { 0, NULL }
};

static const per_choice_t T_periodicityAndOffset_choice[] = {
  {   0, &hf_nr_rrc_sf5          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_4 },
  {   1, &hf_nr_rrc_sf10         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   2, &hf_nr_rrc_sf20         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  {   3, &hf_nr_rrc_sf40         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_39 },
  {   4, &hf_nr_rrc_sf80         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_79 },
  {   5, &hf_nr_rrc_sf160        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_159 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_periodicityAndOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_periodicityAndOffset, T_periodicityAndOffset_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_duration_vals[] = {
  {   0, "sf1" },
  {   1, "sf5" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_duration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_setup_02_vals[] = {
  {   0, "shortBitmap" },
  {   1, "mediumBitmap" },
  {   2, "longBitmap" },
  { 0, NULL }
};

static const per_choice_t T_setup_02_choice[] = {
  {   0, &hf_nr_rrc_shortBitmap  , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_4 },
  {   1, &hf_nr_rrc_mediumBitmap , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_8 },
  {   2, &hf_nr_rrc_longBitmap   , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_BIT_STRING_SIZE_64 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_setup_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_setup_02, T_setup_02_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_ssb_ToMeasure_vals[] = {
  {   0, "release" },
  {   1, "setup" },
  { 0, NULL }
};

static const per_choice_t T_ssb_ToMeasure_choice[] = {
  {   0, &hf_nr_rrc_release      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   1, &hf_nr_rrc_setup_02     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_setup_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_ssb_ToMeasure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_ssb_ToMeasure, T_ssb_ToMeasure_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_smtc1_sequence[] = {
  { &hf_nr_rrc_periodicityAndOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_periodicityAndOffset },
  { &hf_nr_rrc_duration     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_duration },
  { &hf_nr_rrc_ssb_ToMeasure, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_ssb_ToMeasure },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_smtc1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_smtc1, T_smtc1_sequence);

  return offset;
}



static int
dissect_nr_rrc_PhysicalCellId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_PhysCellId(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId_sequence_of[1] = {
  { &hf_nr_rrc_pci_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhysicalCellId },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId, SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId_sequence_of,
                                                  1, maxNrofPCIsPerSMTC, FALSE);

  return offset;
}


static const per_sequence_t T_smtc2_sequence[] = {
  { &hf_nr_rrc_pci_List     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId },
  { &hf_nr_rrc_periodicty   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_smtc2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_smtc2, T_smtc2_sequence);

  return offset;
}


static const per_sequence_t SSB_MeasurementTimingConfiguration_sequence[] = {
  { &hf_nr_rrc_smtc1        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_smtc1 },
  { &hf_nr_rrc_smtc2        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_smtc2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SSB_MeasurementTimingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SSB_MeasurementTimingConfiguration, SSB_MeasurementTimingConfiguration_sequence);

  return offset;
}


static const per_sequence_t T_present_sequence[] = {
  { &hf_nr_rrc_frequencyOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_subcarrierSpacing_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SubcarrierSpacing },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_present(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_present, T_present_sequence);

  return offset;
}


static const per_sequence_t T_notPresent_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_notPresent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_notPresent, T_notPresent_sequence);

  return offset;
}


static const value_string nr_rrc_T_ssbPresence_vals[] = {
  {   0, "present" },
  {   1, "notPresent" },
  { 0, NULL }
};

static const per_choice_t T_ssbPresence_choice[] = {
  {   0, &hf_nr_rrc_present      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_present },
  {   1, &hf_nr_rrc_notPresent   , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_notPresent },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_ssbPresence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_ssbPresence, T_ssbPresence_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_csi_rs_measurementBW_size_vals[] = {
  {   0, "size24" },
  {   1, "size48" },
  {   2, "size96" },
  {   3, "size192" },
  {   4, "size268" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_csi_rs_measurementBW_size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_csi_rs_measurement_BW_start_vals[] = {
  {   0, "ffsTypeAndValue" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_csi_rs_measurement_BW_start(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_associated_SSB_vals[] = {
  {   0, "ffsTypeAndValue" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_associated_SSB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_csi_rs_MeasurementBW_sequence[] = {
  { &hf_nr_rrc_csi_rs_measurementBW_size, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_csi_rs_measurementBW_size },
  { &hf_nr_rrc_csi_rs_measurement_BW_start, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_csi_rs_measurement_BW_start },
  { &hf_nr_rrc_associated_SSB, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_associated_SSB },
  { &hf_nr_rrc_qcled_SSB    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_isServingCellMO, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_csi_rs_MeasurementBW(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_csi_rs_MeasurementBW, T_csi_rs_MeasurementBW_sequence);

  return offset;
}



static int
dissect_nr_rrc_CSI_RS_ResourceId_RRM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrofCSI_RS_ResourcesRRM_1, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_T_slotConfig_vals[] = {
  {   0, "ms5" },
  {   1, "ms10" },
  {   2, "ms20" },
  {   3, "ms40" },
  {   4, "ms80" },
  {   5, "ms160" },
  { 0, NULL }
};

static const per_choice_t T_slotConfig_choice[] = {
  {   0, &hf_nr_rrc_ms5          , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_4 },
  {   1, &hf_nr_rrc_ms10         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_9 },
  {   2, &hf_nr_rrc_ms20         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_19 },
  {   3, &hf_nr_rrc_ms40         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_39 },
  {   4, &hf_nr_rrc_ms80         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_79 },
  {   5, &hf_nr_rrc_ms160        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0_159 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_slotConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_slotConfig, T_slotConfig_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CSI_RS_Resource_Mobility_sequence[] = {
  { &hf_nr_rrc_csi_rs_ResourceId_RRM, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_RS_ResourceId_RRM },
  { &hf_nr_rrc_cellId       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhysicalCellId },
  { &hf_nr_rrc_slotConfig   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_slotConfig },
  { &hf_nr_rrc_resourceElementMappingPattern, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_sequenceGenerationConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CSI_RS_Resource_Mobility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CSI_RS_Resource_Mobility, CSI_RS_Resource_Mobility_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility_sequence_of[1] = {
  { &hf_nr_rrc_csi_rs_ResourceList_Mobility_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_RS_Resource_Mobility },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility, SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility_sequence_of,
                                                  1, maxNrofCSI_RS_ResourcesRRM, FALSE);

  return offset;
}


static const per_sequence_t CSI_RS_ResourceConfig_Mobility_sequence[] = {
  { &hf_nr_rrc_csi_rs_MeasurementBW, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_csi_rs_MeasurementBW },
  { &hf_nr_rrc_subcarrierSpacing_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SubcarrierSpacing },
  { &hf_nr_rrc_csi_rs_ResourceList_Mobility, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CSI_RS_ResourceConfig_Mobility(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CSI_RS_ResourceConfig_Mobility, CSI_RS_ResourceConfig_Mobility_sequence);

  return offset;
}


static const per_sequence_t ReferenceSignalConfig_sequence[] = {
  { &hf_nr_rrc_ssb_MeasurementTimingConfiguration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SSB_MeasurementTimingConfiguration },
  { &hf_nr_rrc_ssbPresence  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_ssbPresence },
  { &hf_nr_rrc_csi_rs_ResourceConfig_Mobility, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CSI_RS_ResourceConfig_Mobility },
  { &hf_nr_rrc_useServingCellTimingForSync, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ReferenceSignalConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ReferenceSignalConfig, ReferenceSignalConfig_sequence);

  return offset;
}



static int
dissect_nr_rrc_SINR_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ThresholdNR_sequence[] = {
  { &hf_nr_rrc_threshold_RSRP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRP_Range },
  { &hf_nr_rrc_threshold_RSRQ, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRQ_Range },
  { &hf_nr_rrc_threshold_SINR, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SINR_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ThresholdNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ThresholdNR, ThresholdNR_sequence);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_2_maxNroSS_BlocksToAverage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, maxNroSS_BlocksToAverage, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_2_maxNroCSI_RS_ResourcesToAverage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, maxNroCSI_RS_ResourcesToAverage, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_maxQuantityConfigId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxQuantityConfigId, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_Q_OffsetRange_vals[] = {
  {   0, "dB-24" },
  {   1, "dB-22" },
  {   2, "dB-20" },
  {   3, "dB-18" },
  {   4, "dB-16" },
  {   5, "dB-14" },
  {   6, "dB-12" },
  {   7, "dB-10" },
  {   8, "dB-8" },
  {   9, "dB-6" },
  {  10, "dB-5" },
  {  11, "dB-4" },
  {  12, "dB-3" },
  {  13, "dB-2" },
  {  14, "dB-1" },
  {  15, "dB0" },
  {  16, "dB1" },
  {  17, "dB2" },
  {  18, "dB3" },
  {  19, "dB4" },
  {  20, "dB5" },
  {  21, "dB6" },
  {  22, "dB8" },
  {  23, "dB10" },
  {  24, "dB12" },
  {  25, "dB14" },
  {  26, "dB16" },
  {  27, "dB18" },
  {  28, "dB20" },
  {  29, "dB22" },
  {  30, "dB24" },
  { 0, NULL }
};

static value_string_ext nr_rrc_Q_OffsetRange_vals_ext = VALUE_STRING_EXT_INIT(nr_rrc_Q_OffsetRange_vals);


static int
dissect_nr_rrc_Q_OffsetRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     31, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Q_OffsetRangeList_sequence[] = {
  { &hf_nr_rrc_rsrpOffsetSSB, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_Q_OffsetRange },
  { &hf_nr_rrc_rsrqOffsetSSB, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_Q_OffsetRange },
  { &hf_nr_rrc_sinrOffsetSSB, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_Q_OffsetRange },
  { &hf_nr_rrc_rsrpOffsetCSI_RS, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_Q_OffsetRange },
  { &hf_nr_rrc_rsrqOffsetCSI_RS, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_Q_OffsetRange },
  { &hf_nr_rrc_sinrOffsetCSI_RS, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_Q_OffsetRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_Q_OffsetRangeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_Q_OffsetRangeList, Q_OffsetRangeList_sequence);

  return offset;
}



static int
dissect_nr_rrc_CellIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNrofCellMeas, NULL, FALSE);

  return offset;
}


static const per_sequence_t CellIndexList_sequence_of[1] = {
  { &hf_nr_rrc_CellIndexList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CellIndex },
};

static int
dissect_nr_rrc_CellIndexList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_CellIndexList, CellIndexList_sequence_of,
                                                  1, maxNrofCellMeas, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_maxNrofCellMeas(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNrofCellMeas, NULL, FALSE);

  return offset;
}


static const per_sequence_t CellsToAddMod_sequence[] = {
  { &hf_nr_rrc_cellIndex    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_maxNrofCellMeas },
  { &hf_nr_rrc_physCellId   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhysCellId },
  { &hf_nr_rrc_cellIndividualOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_Q_OffsetRangeList },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_CellsToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_CellsToAddMod, CellsToAddMod_sequence);

  return offset;
}


static const per_sequence_t CellsToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_CellsToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CellsToAddMod },
};

static int
dissect_nr_rrc_CellsToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_CellsToAddModList, CellsToAddModList_sequence_of,
                                                  1, maxNrofCellMeas, FALSE);

  return offset;
}


static const value_string nr_rrc_T_range_vals[] = {
  {   0, "n4" },
  {   1, "n8" },
  {   2, "n12" },
  {   3, "n16" },
  {   4, "n24" },
  {   5, "n32" },
  {   6, "n48" },
  {   7, "n64" },
  {   8, "n84" },
  {   9, "n96" },
  {  10, "n128" },
  {  11, "n168" },
  {  12, "n252" },
  {  13, "n504" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PhysCellIdRange_sequence[] = {
  { &hf_nr_rrc_start        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhysCellId },
  { &hf_nr_rrc_range        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_range },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PhysCellIdRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PhysCellIdRange, PhysCellIdRange_sequence);

  return offset;
}


static const per_sequence_t BlackCellsToAddMod_sequence[] = {
  { &hf_nr_rrc_cellIndex    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_maxNrofCellMeas },
  { &hf_nr_rrc_physCellIdRange, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhysCellIdRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BlackCellsToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BlackCellsToAddMod, BlackCellsToAddMod_sequence);

  return offset;
}


static const per_sequence_t BlackCellsToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_BlackCellsToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BlackCellsToAddMod },
};

static int
dissect_nr_rrc_BlackCellsToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_BlackCellsToAddModList, BlackCellsToAddModList_sequence_of,
                                                  1, maxNrofCellMeas, FALSE);

  return offset;
}


static const per_sequence_t WhiteCellsToAddMod_sequence[] = {
  { &hf_nr_rrc_cellIndex    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_maxNrofCellMeas },
  { &hf_nr_rrc_physCellIdRange, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhysCellIdRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_WhiteCellsToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_WhiteCellsToAddMod, WhiteCellsToAddMod_sequence);

  return offset;
}


static const per_sequence_t WhiteCellsToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_WhiteCellsToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_WhiteCellsToAddMod },
};

static int
dissect_nr_rrc_WhiteCellsToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_WhiteCellsToAddModList, WhiteCellsToAddModList_sequence_of,
                                                  1, maxNrofCellMeas, FALSE);

  return offset;
}


static const per_sequence_t MeasObjectNR_sequence[] = {
  { &hf_nr_rrc_carrierFreq  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ARFCN_ValueNR },
  { &hf_nr_rrc_referenceSignalConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ReferenceSignalConfig },
  { &hf_nr_rrc_absThreshSS_BlocksConsolidation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ThresholdNR },
  { &hf_nr_rrc_absThreshCSI_RS_Consolidation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ThresholdNR },
  { &hf_nr_rrc_nroSS_BlocksToAverage, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_2_maxNroSS_BlocksToAverage },
  { &hf_nr_rrc_nroCSI_RS_ResourcesToAverage, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_2_maxNroCSI_RS_ResourcesToAverage },
  { &hf_nr_rrc_quantityConfigIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_maxQuantityConfigId },
  { &hf_nr_rrc_offsetFreq   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_Q_OffsetRangeList },
  { &hf_nr_rrc_cellsToRemoveList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CellIndexList },
  { &hf_nr_rrc_cellsToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CellsToAddModList },
  { &hf_nr_rrc_blackCellsToRemoveList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CellIndexList },
  { &hf_nr_rrc_blackCellsToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BlackCellsToAddModList },
  { &hf_nr_rrc_whiteCellsToRemoveList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CellIndexList },
  { &hf_nr_rrc_whiteCellsToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_WhiteCellsToAddModList },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasObjectNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasObjectNR, MeasObjectNR_sequence);

  return offset;
}


static const per_sequence_t MeasObjectEUTRA_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasObjectEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasObjectEUTRA, MeasObjectEUTRA_sequence);

  return offset;
}


static const value_string nr_rrc_T_measObject_vals[] = {
  {   0, "measObjectNR" },
  {   1, "measObjectEUTRA" },
  { 0, NULL }
};

static const per_choice_t T_measObject_choice[] = {
  {   0, &hf_nr_rrc_measObjectNR , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_MeasObjectNR },
  {   1, &hf_nr_rrc_measObjectEUTRA, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_MeasObjectEUTRA },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_measObject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_measObject, T_measObject_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasObjectToAddMod_sequence[] = {
  { &hf_nr_rrc_measObjectId , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasObjectId },
  { &hf_nr_rrc_measObject   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_measObject },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasObjectToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasObjectToAddMod, MeasObjectToAddMod_sequence);

  return offset;
}


static const per_sequence_t MeasObjectToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_MeasObjectToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasObjectToAddMod },
};

static int
dissect_nr_rrc_MeasObjectToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_MeasObjectToAddModList, MeasObjectToAddModList_sequence_of,
                                                  1, maxNrofObjectId, FALSE);

  return offset;
}



static int
dissect_nr_rrc_ReportConfigId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNrofReportConfigId, NULL, FALSE);

  return offset;
}


static const per_sequence_t ReportConfigToRemoveList_sequence_of[1] = {
  { &hf_nr_rrc_ReportConfigToRemoveList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ReportConfigId },
};

static int
dissect_nr_rrc_ReportConfigToRemoveList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_ReportConfigToRemoveList, ReportConfigToRemoveList_sequence_of,
                                                  1, maxNrofReportConfigId, FALSE);

  return offset;
}


static const value_string nr_rrc_T_rsType_01_vals[] = {
  {   0, "ssb" },
  {   1, "csi-rs" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_rsType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_ReportInterval_vals[] = {
  {   0, "ms120" },
  {   1, "ms240" },
  {   2, "ms480" },
  {   3, "ms640" },
  {   4, "ms1024" },
  {   5, "ms2048" },
  {   6, "ms5120" },
  {   7, "ms10240" },
  {   8, "min1" },
  {   9, "min6" },
  {  10, "min12" },
  {  11, "min30" },
  {  12, "min60" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_ReportInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_reportAmount_01_vals[] = {
  {   0, "ffs" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_reportAmount_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t MeasReportQuantity_sequence[] = {
  { &hf_nr_rrc_rsrp_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_rsrq_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_sinr_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasReportQuantity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasReportQuantity, MeasReportQuantity_sequence);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_maxCellReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxCellReport, NULL, FALSE);

  return offset;
}



static int
dissect_nr_rrc_INTEGER_1_maxNroIndexesToReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNroIndexesToReport, NULL, FALSE);

  return offset;
}


static const per_sequence_t PeriodicalReportConfig_sequence[] = {
  { &hf_nr_rrc_rsType_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_rsType_01 },
  { &hf_nr_rrc_reportInterval, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ReportInterval },
  { &hf_nr_rrc_reportAmount_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportAmount_01 },
  { &hf_nr_rrc_reportQuantityCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasReportQuantity },
  { &hf_nr_rrc_maxReportCells, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_maxCellReport },
  { &hf_nr_rrc_reportQuantityRsIndexes, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasReportQuantity },
  { &hf_nr_rrc_maxNroRsIndexesToReport, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_maxNroIndexesToReport },
  { &hf_nr_rrc_onlyReportBeamIds, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PeriodicalReportConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PeriodicalReportConfig, PeriodicalReportConfig_sequence);

  return offset;
}



static int
dissect_nr_rrc_RSRPRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_RSRP_Range(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_nr_rrc_RSRQRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_RSRQ_Range(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_nr_rrc_SINRRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_SINR_Range(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string nr_rrc_MeasTriggerQuantity_vals[] = {
  {   0, "rsrp" },
  {   1, "rsrq" },
  {   2, "sinr" },
  { 0, NULL }
};

static const per_choice_t MeasTriggerQuantity_choice[] = {
  {   0, &hf_nr_rrc_rsrp         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_RSRPRange },
  {   1, &hf_nr_rrc_rsrq         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_RSRQRange },
  {   2, &hf_nr_rrc_sinr         , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_SINRRange },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_MeasTriggerQuantity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_MeasTriggerQuantity, MeasTriggerQuantity_choice,
                                 NULL);

  return offset;
}



static int
dissect_nr_rrc_Hysteresis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 30U, NULL, FALSE);

  return offset;
}


static const value_string nr_rrc_TimeToTrigger_vals[] = {
  {   0, "ms0" },
  {   1, "ms40" },
  {   2, "ms64" },
  {   3, "ms80" },
  {   4, "ms100" },
  {   5, "ms128" },
  {   6, "ms160" },
  {   7, "ms256" },
  {   8, "ms320" },
  {   9, "ms480" },
  {  10, "ms512" },
  {  11, "ms640" },
  {  12, "ms1024" },
  {  13, "ms1280" },
  {  14, "ms2560" },
  {  15, "ms5120" },
  { 0, NULL }
};


static int
dissect_nr_rrc_TimeToTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_eventA1_sequence[] = {
  { &hf_nr_rrc_a1_Threshold , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasTriggerQuantity },
  { &hf_nr_rrc_reportOnLeave, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_hysteresis   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_Hysteresis },
  { &hf_nr_rrc_timeToTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TimeToTrigger },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_eventA1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_eventA1, T_eventA1_sequence);

  return offset;
}


static const per_sequence_t T_eventA2_sequence[] = {
  { &hf_nr_rrc_a2_Threshold , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasTriggerQuantity },
  { &hf_nr_rrc_reportOnLeave, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_hysteresis   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_Hysteresis },
  { &hf_nr_rrc_timeToTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TimeToTrigger },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_eventA2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_eventA2, T_eventA2_sequence);

  return offset;
}


static const value_string nr_rrc_MeasTriggerQuantityOffset_vals[] = {
  {   0, "rsrp" },
  {   1, "rsrq" },
  {   2, "sinr" },
  { 0, NULL }
};

static const per_choice_t MeasTriggerQuantityOffset_choice[] = {
  {   0, &hf_nr_rrc_rsrp_01      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0 },
  {   1, &hf_nr_rrc_rsrq_01      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0 },
  {   2, &hf_nr_rrc_sinr_01      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_INTEGER_0 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_MeasTriggerQuantityOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_MeasTriggerQuantityOffset, MeasTriggerQuantityOffset_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_eventA3_sequence[] = {
  { &hf_nr_rrc_a3_Offset    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasTriggerQuantityOffset },
  { &hf_nr_rrc_reportOnLeave, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_hysteresis   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_Hysteresis },
  { &hf_nr_rrc_timeToTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TimeToTrigger },
  { &hf_nr_rrc_useWhiteCellList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_eventA3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_eventA3, T_eventA3_sequence);

  return offset;
}


static const per_sequence_t T_eventA4_sequence[] = {
  { &hf_nr_rrc_a4_Threshold , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasTriggerQuantity },
  { &hf_nr_rrc_reportOnLeave, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_hysteresis   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_Hysteresis },
  { &hf_nr_rrc_timeToTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TimeToTrigger },
  { &hf_nr_rrc_useWhiteCellList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_eventA4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_eventA4, T_eventA4_sequence);

  return offset;
}


static const per_sequence_t T_eventA5_sequence[] = {
  { &hf_nr_rrc_a5_Threshold1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasTriggerQuantity },
  { &hf_nr_rrc_a5_Threshold2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasTriggerQuantity },
  { &hf_nr_rrc_reportOnLeave, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_hysteresis   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_Hysteresis },
  { &hf_nr_rrc_timeToTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TimeToTrigger },
  { &hf_nr_rrc_useWhiteCellList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_eventA5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_eventA5, T_eventA5_sequence);

  return offset;
}


static const per_sequence_t T_eventA6_sequence[] = {
  { &hf_nr_rrc_a6_Offset    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasTriggerQuantityOffset },
  { &hf_nr_rrc_reportOnLeave, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_hysteresis   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_Hysteresis },
  { &hf_nr_rrc_timeToTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_TimeToTrigger },
  { &hf_nr_rrc_useWhiteCellList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_eventA6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_eventA6, T_eventA6_sequence);

  return offset;
}


static const value_string nr_rrc_T_eventId_vals[] = {
  {   0, "eventA1" },
  {   1, "eventA2" },
  {   2, "eventA3" },
  {   3, "eventA4" },
  {   4, "eventA5" },
  {   5, "eventA6" },
  { 0, NULL }
};

static const per_choice_t T_eventId_choice[] = {
  {   0, &hf_nr_rrc_eventA1      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_eventA1 },
  {   1, &hf_nr_rrc_eventA2      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_eventA2 },
  {   2, &hf_nr_rrc_eventA3      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_eventA3 },
  {   3, &hf_nr_rrc_eventA4      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_eventA4 },
  {   4, &hf_nr_rrc_eventA5      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_eventA5 },
  {   5, &hf_nr_rrc_eventA6      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_eventA6 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_eventId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_eventId, T_eventId_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_T_rsType_vals[] = {
  {   0, "ss" },
  {   1, "csi-rs" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_rsType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_reportAmount_vals[] = {
  {   0, "ffs" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_reportAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t EventTriggerConfig_sequence[] = {
  { &hf_nr_rrc_eventId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_eventId },
  { &hf_nr_rrc_rsType       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_rsType },
  { &hf_nr_rrc_reportInterval, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ReportInterval },
  { &hf_nr_rrc_reportAmount , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportAmount },
  { &hf_nr_rrc_reportQuantityCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasReportQuantity },
  { &hf_nr_rrc_maxReportCells, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_INTEGER_1_maxCellReport },
  { &hf_nr_rrc_reportQuantityRsIndexes, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasReportQuantity },
  { &hf_nr_rrc_maxNroIndexesToReport, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_INTEGER_1_maxNroIndexesToReport },
  { &hf_nr_rrc_onlyReportBeamIds, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_reportAddNeighMeas, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_EventTriggerConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_EventTriggerConfig, EventTriggerConfig_sequence);

  return offset;
}


static const value_string nr_rrc_T_reportType_vals[] = {
  {   0, "periodical" },
  {   1, "eventTriggered" },
  {   2, "reportCGI" },
  { 0, NULL }
};

static const per_choice_t T_reportType_choice[] = {
  {   0, &hf_nr_rrc_periodical   , ASN1_EXTENSION_ROOT    , dissect_nr_rrc_PeriodicalReportConfig },
  {   1, &hf_nr_rrc_eventTriggered, ASN1_EXTENSION_ROOT    , dissect_nr_rrc_EventTriggerConfig },
  {   2, &hf_nr_rrc_reportCGI    , ASN1_EXTENSION_ROOT    , dissect_nr_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_reportType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_reportType, T_reportType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ReportConfigNR_sequence[] = {
  { &hf_nr_rrc_reportType   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportType },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ReportConfigNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ReportConfigNR, ReportConfigNR_sequence);

  return offset;
}


static const per_sequence_t ReportConfigEUTRA_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ReportConfigEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ReportConfigEUTRA, ReportConfigEUTRA_sequence);

  return offset;
}


static const value_string nr_rrc_T_reportConfig_vals[] = {
  {   0, "reportConfigNR" },
  {   1, "reportConfigEUTRA" },
  { 0, NULL }
};

static const per_choice_t T_reportConfig_choice[] = {
  {   0, &hf_nr_rrc_reportConfigNR, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_ReportConfigNR },
  {   1, &hf_nr_rrc_reportConfigEUTRA, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_ReportConfigEUTRA },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_reportConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_reportConfig, T_reportConfig_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ReportConfigToAddMod_sequence[] = {
  { &hf_nr_rrc_reportConfigId_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ReportConfigId },
  { &hf_nr_rrc_reportConfig , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_reportConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ReportConfigToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ReportConfigToAddMod, ReportConfigToAddMod_sequence);

  return offset;
}


static const per_sequence_t ReportConfigToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_ReportConfigToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ReportConfigToAddMod },
};

static int
dissect_nr_rrc_ReportConfigToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_ReportConfigToAddModList, ReportConfigToAddModList_sequence_of,
                                                  1, maxReportConfigId, FALSE);

  return offset;
}



static int
dissect_nr_rrc_MeasId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNrofMeasId, NULL, FALSE);

  return offset;
}


static const per_sequence_t MeasIdToRemoveList_sequence_of[1] = {
  { &hf_nr_rrc_MeasIdToRemoveList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasId },
};

static int
dissect_nr_rrc_MeasIdToRemoveList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_MeasIdToRemoveList, MeasIdToRemoveList_sequence_of,
                                                  1, maxNrofMeasId, FALSE);

  return offset;
}


static const per_sequence_t MeasIdToAddMod_sequence[] = {
  { &hf_nr_rrc_measId       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasId },
  { &hf_nr_rrc_measObjectId , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasObjectId },
  { &hf_nr_rrc_reportConfigId_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ReportConfigId },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasIdToAddMod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasIdToAddMod, MeasIdToAddMod_sequence);

  return offset;
}


static const per_sequence_t MeasIdToAddModList_sequence_of[1] = {
  { &hf_nr_rrc_MeasIdToAddModList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasIdToAddMod },
};

static int
dissect_nr_rrc_MeasIdToAddModList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_MeasIdToAddModList, MeasIdToAddModList_sequence_of,
                                                  1, maxNrofMeasId, FALSE);

  return offset;
}


static const value_string nr_rrc_T_s_MeasureConfig_vals[] = {
  {   0, "ssb-rsrp" },
  {   1, "csi-rsrp" },
  { 0, NULL }
};

static const per_choice_t T_s_MeasureConfig_choice[] = {
  {   0, &hf_nr_rrc_ssb_rsrp     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_RSRP_Range },
  {   1, &hf_nr_rrc_csi_rsrp     , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_RSRP_Range },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_s_MeasureConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_s_MeasureConfig, T_s_MeasureConfig_choice,
                                 NULL);

  return offset;
}


static const value_string nr_rrc_FilterCoefficient_vals[] = {
  {   0, "fc0" },
  {   1, "fc1" },
  {   2, "fc2" },
  {   3, "fc3" },
  {   4, "fc4" },
  {   5, "fc5" },
  {   6, "fc6" },
  {   7, "fc7" },
  {   8, "fc8" },
  {   9, "fc9" },
  {  10, "fc11" },
  {  11, "fc13" },
  {  12, "fc15" },
  {  13, "fc17" },
  {  14, "fc19" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_FilterCoefficient(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QuantityConfigRS_sequence[] = {
  { &hf_nr_rrc_ssbFilterCoefficientRSRP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_FilterCoefficient },
  { &hf_nr_rrc_ssbFilterCoefficientRSRQ, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_FilterCoefficient },
  { &hf_nr_rrc_ssbFilterCoefficientRS_SINR, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_FilterCoefficient },
  { &hf_nr_rrc_csi_rsFilterCoefficientRSRP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_FilterCoefficient },
  { &hf_nr_rrc_csi_rsFilterCoefficientRSRQ, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_FilterCoefficient },
  { &hf_nr_rrc_csi_rsFilterCoefficientRS_SINR, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_FilterCoefficient },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_QuantityConfigRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_QuantityConfigRS, QuantityConfigRS_sequence);

  return offset;
}


static const per_sequence_t QuantityConfig_sequence[] = {
  { &hf_nr_rrc_quantityConfigRSindex, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_QuantityConfigRS },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_QuantityConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_QuantityConfig, QuantityConfig_sequence);

  return offset;
}


static const per_sequence_t MeasGapConfig_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasGapConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasGapConfig, MeasGapConfig_sequence);

  return offset;
}


static const per_sequence_t MeasConfig_sequence[] = {
  { &hf_nr_rrc_measObjectToRemoveList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasObjectToRemoveList },
  { &hf_nr_rrc_measObjectToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasObjectToAddModList },
  { &hf_nr_rrc_reportConfigToRemoveList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ReportConfigToRemoveList },
  { &hf_nr_rrc_reportConfigToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ReportConfigToAddModList },
  { &hf_nr_rrc_measIdToRemoveList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasIdToRemoveList },
  { &hf_nr_rrc_measIdToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasIdToAddModList },
  { &hf_nr_rrc_s_MeasureConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_s_MeasureConfig },
  { &hf_nr_rrc_quantityConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_QuantityConfig },
  { &hf_nr_rrc_measGapConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasGapConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasConfig, MeasConfig_sequence);

  return offset;
}



static int
dissect_nr_rrc_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_01_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_nonCriticalExtension_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_nonCriticalExtension_01, T_nonCriticalExtension_01_sequence);

  return offset;
}


static const per_sequence_t RRCReconfiguration_IEs_sequence[] = {
  { &hf_nr_rrc_radioBearerConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RadioBearerConfig },
  { &hf_nr_rrc_masterCellGroupConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_CellGroupConfig },
  { &hf_nr_rrc_secondaryCellGroupToAddModList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig },
  { &hf_nr_rrc_secondaryCellGroupToReleaseList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId },
  { &hf_nr_rrc_measConfig   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MeasConfig },
  { &hf_nr_rrc_lateNonCriticalExtension, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_OCTET_STRING },
  { &hf_nr_rrc_nonCriticalExtension_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_nonCriticalExtension_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RRCReconfiguration_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RRCReconfiguration_IEs, RRCReconfiguration_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_02_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_criticalExtensionsFuture_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_criticalExtensionsFuture_02, T_criticalExtensionsFuture_02_sequence);

  return offset;
}


static const value_string nr_rrc_T_criticalExtensions_02_vals[] = {
  {   0, "rrcReconfiguration" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_02_choice[] = {
  {   0, &hf_nr_rrc_rrcReconfiguration_01, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_RRCReconfiguration_IEs },
  {   1, &hf_nr_rrc_criticalExtensionsFuture_02, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_criticalExtensionsFuture_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_criticalExtensions_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_criticalExtensions_02, T_criticalExtensions_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCReconfiguration_sequence[] = {
  { &hf_nr_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RRC_TransactionIdentifier },
  { &hf_nr_rrc_criticalExtensions_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_criticalExtensions_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RRCReconfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RRC Reconfiguration");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RRCReconfiguration, RRCReconfiguration_sequence);

  return offset;
}


static const value_string nr_rrc_T_c1_01_vals[] = {
  {   0, "rrcReconfiguration" },
  {   1, "spare15" },
  {   2, "spare14" },
  {   3, "spare13" },
  {   4, "spare12" },
  {   5, "spare11" },
  {   6, "spare10" },
  {   7, "spare9" },
  {   8, "spare8" },
  {   9, "spare7" },
  {  10, "spare6" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_01_choice[] = {
  {   0, &hf_nr_rrc_rrcReconfiguration, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_RRCReconfiguration },
  {   1, &hf_nr_rrc_spare15      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   2, &hf_nr_rrc_spare14      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   3, &hf_nr_rrc_spare13      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   4, &hf_nr_rrc_spare12      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   5, &hf_nr_rrc_spare11      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   6, &hf_nr_rrc_spare10      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   7, &hf_nr_rrc_spare9       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   8, &hf_nr_rrc_spare8       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   9, &hf_nr_rrc_spare7       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  10, &hf_nr_rrc_spare6       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  11, &hf_nr_rrc_spare5       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  12, &hf_nr_rrc_spare4       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  13, &hf_nr_rrc_spare3       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  14, &hf_nr_rrc_spare2       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  15, &hf_nr_rrc_spare1       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_c1_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_c1_01, T_c1_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_01_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_messageClassExtension_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_messageClassExtension_01, T_messageClassExtension_01_sequence);

  return offset;
}


static const value_string nr_rrc_DL_DCCH_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t DL_DCCH_MessageType_choice[] = {
  {   0, &hf_nr_rrc_c1_01        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_c1_01 },
  {   1, &hf_nr_rrc_messageClassExtension_01, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_messageClassExtension_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_DL_DCCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_DL_DCCH_MessageType, DL_DCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DL_DCCH_Message_sequence[] = {
  { &hf_nr_rrc_message_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_DL_DCCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_DL_DCCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_item *ti;

  col_set_str(actx->pinfo->cinfo, COL_PROTOCOL, "NR RRC");
  col_clear(actx->pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_nr_rrc);

  actx->pinfo->link_dir = P2P_DIR_DL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_DL_DCCH_Message, DL_DCCH_Message_sequence);

  return offset;
}


static const per_sequence_t ResultsSSBCell_sequence[] = {
  { &hf_nr_rrc_ssb_Cellrsrp , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRP_Range },
  { &hf_nr_rrc_ssb_Cellrsrq , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRQ_Range },
  { &hf_nr_rrc_ssb_Cellsinr , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SINR_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ResultsSSBCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ResultsSSBCell, ResultsSSBCell_sequence);

  return offset;
}


static const per_sequence_t ResultsCSI_RSCell_sequence[] = {
  { &hf_nr_rrc_csi_rs_Cellrsrp, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRP_Range },
  { &hf_nr_rrc_csi_rs_Cellrsrq, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRQ_Range },
  { &hf_nr_rrc_csi_rs_Cellsinr, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SINR_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ResultsCSI_RSCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ResultsCSI_RSCell, ResultsCSI_RSCell_sequence);

  return offset;
}


static const per_sequence_t T_cellResults_sequence[] = {
  { &hf_nr_rrc_resultsSSBCell, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ResultsSSBCell },
  { &hf_nr_rrc_resultsCSI_RSCell, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ResultsCSI_RSCell },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_cellResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_cellResults, T_cellResults_sequence);

  return offset;
}


static const per_sequence_t ResultsPerSSBIndex_sequence[] = {
  { &hf_nr_rrc_ssb_Index    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SSB_Index },
  { &hf_nr_rrc_ss_rsrp      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRP_Range },
  { &hf_nr_rrc_ss_rsrq      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRQ_Range },
  { &hf_nr_rrc_ss_sinr      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SINR_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ResultsPerSSBIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ResultsPerSSBIndex, ResultsPerSSBIndex_sequence);

  return offset;
}


static const per_sequence_t ResultsPerSSBIndexList_sequence_of[1] = {
  { &hf_nr_rrc_ResultsPerSSBIndexList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ResultsPerSSBIndex },
};

static int
dissect_nr_rrc_ResultsPerSSBIndexList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_ResultsPerSSBIndexList, ResultsPerSSBIndexList_sequence_of,
                                                  1, maxNroSSBs, FALSE);

  return offset;
}



static int
dissect_nr_rrc_CSI_RSIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t ResultsPerCSI_RSIndex_sequence[] = {
  { &hf_nr_rrc_csi_rsIndex  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CSI_RSIndex },
  { &hf_nr_rrc_csi_rsrp     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRP_Range },
  { &hf_nr_rrc_csi_rsrq     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_RSRQ_Range },
  { &hf_nr_rrc_csi_sinr     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_SINR_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ResultsPerCSI_RSIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ResultsPerCSI_RSIndex, ResultsPerCSI_RSIndex_sequence);

  return offset;
}


static const per_sequence_t ResultsPerCSI_RSIndexList_sequence_of[1] = {
  { &hf_nr_rrc_ResultsPerCSI_RSIndexList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ResultsPerCSI_RSIndex },
};

static int
dissect_nr_rrc_ResultsPerCSI_RSIndexList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_ResultsPerCSI_RSIndexList, ResultsPerCSI_RSIndexList_sequence_of,
                                                  1, maxNroCSI_RS, FALSE);

  return offset;
}


static const per_sequence_t T_rsIndexResults_sequence[] = {
  { &hf_nr_rrc_resultsSSBIndexes, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ResultsPerSSBIndexList },
  { &hf_nr_rrc_resultsCSI_RSIndexes, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ResultsPerCSI_RSIndexList },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_rsIndexResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_rsIndexResults, T_rsIndexResults_sequence);

  return offset;
}


static const per_sequence_t T_measResult_sequence[] = {
  { &hf_nr_rrc_cellResults  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_cellResults },
  { &hf_nr_rrc_rsIndexResults, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_rsIndexResults },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_measResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_measResult, T_measResult_sequence);

  return offset;
}


static const per_sequence_t MeasResultNR_sequence[] = {
  { &hf_nr_rrc_physCellId   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_PhysCellId },
  { &hf_nr_rrc_cgi_Info     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_NULL },
  { &hf_nr_rrc_measResult   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_measResult },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasResultNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasResultNR, MeasResultNR_sequence);

  return offset;
}


static const per_sequence_t MeasResultServFreq_sequence[] = {
  { &hf_nr_rrc_servFreqId   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_ServCellIndex },
  { &hf_nr_rrc_measResultServingCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasResultNR },
  { &hf_nr_rrc_measResultBestNeighCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasResultNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasResultServFreq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasResultServFreq, MeasResultServFreq_sequence);

  return offset;
}


static const per_sequence_t MeasResultServFreqList_sequence_of[1] = {
  { &hf_nr_rrc_MeasResultServFreqList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasResultServFreq },
};

static int
dissect_nr_rrc_MeasResultServFreqList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_MeasResultServFreqList, MeasResultServFreqList_sequence_of,
                                                  1, maxServCell, FALSE);

  return offset;
}


static const per_sequence_t MeasResultListNR_sequence_of[1] = {
  { &hf_nr_rrc_MeasResultListNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasResultNR },
};

static int
dissect_nr_rrc_MeasResultListNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_MeasResultListNR, MeasResultListNR_sequence_of,
                                                  1, maxCellReport, FALSE);

  return offset;
}


static const per_sequence_t MeasResultListEUTRA_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasResultListEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasResultListEUTRA, MeasResultListEUTRA_sequence);

  return offset;
}


static const value_string nr_rrc_T_measResultNeighCells_vals[] = {
  {   0, "measResultListNR" },
  {   1, "measResultListEUTRA" },
  { 0, NULL }
};

static const per_choice_t T_measResultNeighCells_choice[] = {
  {   0, &hf_nr_rrc_measResultListNR, ASN1_EXTENSION_ROOT    , dissect_nr_rrc_MeasResultListNR },
  {   1, &hf_nr_rrc_measResultListEUTRA, ASN1_EXTENSION_ROOT    , dissect_nr_rrc_MeasResultListEUTRA },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_measResultNeighCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_measResultNeighCells, T_measResultNeighCells_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasResults_sequence[] = {
  { &hf_nr_rrc_measId       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasId },
  { &hf_nr_rrc_measResultServingFreqList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasResultServFreqList },
  { &hf_nr_rrc_measResultNeighCells, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_measResultNeighCells },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasResults, MeasResults_sequence);

  return offset;
}


static const per_sequence_t MeasurementReport_IEs_sequence[] = {
  { &hf_nr_rrc_measResults  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasResults },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasurementReport_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasurementReport_IEs, MeasurementReport_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_01_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_criticalExtensionsFuture_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_criticalExtensionsFuture_01, T_criticalExtensionsFuture_01_sequence);

  return offset;
}


static const value_string nr_rrc_T_criticalExtensions_01_vals[] = {
  {   0, "measurementReport" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_01_choice[] = {
  {   0, &hf_nr_rrc_measurementReport_01, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_MeasurementReport_IEs },
  {   1, &hf_nr_rrc_criticalExtensionsFuture_01, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_criticalExtensionsFuture_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_criticalExtensions_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_criticalExtensions_01, T_criticalExtensions_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasurementReport_sequence[] = {
  { &hf_nr_rrc_criticalExtensions_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_criticalExtensions_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasurementReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "Measurement Report");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasurementReport, MeasurementReport_sequence);

  return offset;
}


static const per_sequence_t RRCReconfigurationComplete_IEs_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RRCReconfigurationComplete_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RRCReconfigurationComplete_IEs, RRCReconfigurationComplete_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_03_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_criticalExtensionsFuture_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_criticalExtensionsFuture_03, T_criticalExtensionsFuture_03_sequence);

  return offset;
}


static const value_string nr_rrc_T_criticalExtensions_03_vals[] = {
  {   0, "rrcReconfigurationComplete" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_03_choice[] = {
  {   0, &hf_nr_rrc_rrcReconfigurationComplete_01, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_RRCReconfigurationComplete_IEs },
  {   1, &hf_nr_rrc_criticalExtensionsFuture_03, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_criticalExtensionsFuture_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_criticalExtensions_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_criticalExtensions_03, T_criticalExtensions_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCReconfigurationComplete_sequence[] = {
  { &hf_nr_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RRC_TransactionIdentifier },
  { &hf_nr_rrc_criticalExtensions_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_criticalExtensions_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RRCReconfigurationComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_sep_str(actx->pinfo->cinfo, COL_INFO, NULL, "RRC Reconfiguration Complete");





  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RRCReconfigurationComplete, RRCReconfigurationComplete_sequence);

  return offset;
}


static const value_string nr_rrc_T_c1_02_vals[] = {
  {   0, "measurementReport" },
  {   1, "rrcReconfigurationComplete" },
  {   2, "spare14" },
  {   3, "spare13" },
  {   4, "spare12" },
  {   5, "spare11" },
  {   6, "spare10" },
  {   7, "spare9" },
  {   8, "spare8" },
  {   9, "spare7" },
  {  10, "spare6" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_02_choice[] = {
  {   0, &hf_nr_rrc_measurementReport, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_MeasurementReport },
  {   1, &hf_nr_rrc_rrcReconfigurationComplete, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_RRCReconfigurationComplete },
  {   2, &hf_nr_rrc_spare14      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   3, &hf_nr_rrc_spare13      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   4, &hf_nr_rrc_spare12      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   5, &hf_nr_rrc_spare11      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   6, &hf_nr_rrc_spare10      , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   7, &hf_nr_rrc_spare9       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   8, &hf_nr_rrc_spare8       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {   9, &hf_nr_rrc_spare7       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  10, &hf_nr_rrc_spare6       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  11, &hf_nr_rrc_spare5       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  12, &hf_nr_rrc_spare4       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  13, &hf_nr_rrc_spare3       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  14, &hf_nr_rrc_spare2       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  {  15, &hf_nr_rrc_spare1       , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_T_c1_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_T_c1_02, T_c1_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_02_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_messageClassExtension_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_messageClassExtension_02, T_messageClassExtension_02_sequence);

  return offset;
}


static const value_string nr_rrc_UL_DCCH_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t UL_DCCH_MessageType_choice[] = {
  {   0, &hf_nr_rrc_c1_02        , ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_c1_02 },
  {   1, &hf_nr_rrc_messageClassExtension_02, ASN1_NO_EXTENSIONS     , dissect_nr_rrc_T_messageClassExtension_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_nr_rrc_UL_DCCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nr_rrc_UL_DCCH_MessageType, UL_DCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UL_DCCH_Message_sequence[] = {
  { &hf_nr_rrc_message_02   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_UL_DCCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_UL_DCCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_item *ti;

  col_set_str(actx->pinfo->cinfo, COL_PROTOCOL, "NR RRC");
  col_clear(actx->pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_nr_rrc);

  actx->pinfo->link_dir = P2P_DIR_UL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_UL_DCCH_Message, UL_DCCH_Message_sequence);

  return offset;
}


static const per_sequence_t BandCombination_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BandCombination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BandCombination, BandCombination_sequence);

  return offset;
}


static const per_sequence_t BandCombinationList_sequence_of[1] = {
  { &hf_nr_rrc_BandCombinationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BandCombination },
};

static int
dissect_nr_rrc_BandCombinationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_BandCombinationList, BandCombinationList_sequence_of,
                                                  1, maxBandComb, FALSE);

  return offset;
}


static const value_string nr_rrc_T_intraCarrierConcurrentMeas_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_intraCarrierConcurrentMeas(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_independentGapConfig_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_independentGapConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_sstd_MeasType1_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_sstd_MeasType1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t MeasParameters_MRDC_sequence[] = {
  { &hf_nr_rrc_intraCarrierConcurrentMeas, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_intraCarrierConcurrentMeas },
  { &hf_nr_rrc_independentGapConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_independentGapConfig },
  { &hf_nr_rrc_sstd_MeasType1, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_sstd_MeasType1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MeasParameters_MRDC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MeasParameters_MRDC, MeasParameters_MRDC_sequence);

  return offset;
}


static const per_sequence_t RF_Parameters_MRDC_sequence[] = {
  { &hf_nr_rrc_supportedBandCombination, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BandCombinationList },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RF_Parameters_MRDC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RF_Parameters_MRDC, RF_Parameters_MRDC_sequence);

  return offset;
}



static int
dissect_nr_rrc_BasebandProcessingCombinationIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxBasebandProcComb, NULL, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex_sequence_of[1] = {
  { &hf_nr_rrc_basebandProcessingCombinationLinkedIndex_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BasebandProcessingCombinationIndex },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex, SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex_sequence_of,
                                                  1, maxBasebandProcComb, FALSE);

  return offset;
}


static const per_sequence_t LinkedBasebandProcessingCombination_sequence[] = {
  { &hf_nr_rrc_basebandProcessingCombinationIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BasebandProcessingCombinationIndex },
  { &hf_nr_rrc_basebandProcessingCombinationLinkedIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_LinkedBasebandProcessingCombination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_LinkedBasebandProcessingCombination, LinkedBasebandProcessingCombination_sequence);

  return offset;
}


static const per_sequence_t BasebandProcessingCombination_MRDC_sequence_of[1] = {
  { &hf_nr_rrc_BasebandProcessingCombination_MRDC_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_LinkedBasebandProcessingCombination },
};

static int
dissect_nr_rrc_BasebandProcessingCombination_MRDC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_BasebandProcessingCombination_MRDC, BasebandProcessingCombination_MRDC_sequence_of,
                                                  1, maxBasebandProcComb, FALSE);

  return offset;
}


static const per_sequence_t PhyLayerParameters_MRDC_sequence[] = {
  { &hf_nr_rrc_supportedBasebandProcessingCombination_MRDC, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BasebandProcessingCombination_MRDC },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PhyLayerParameters_MRDC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PhyLayerParameters_MRDC, PhyLayerParameters_MRDC_sequence);

  return offset;
}


static const per_sequence_t UE_MRDC_Capability_sequence[] = {
  { &hf_nr_rrc_measParameters_MRDC, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MeasParameters_MRDC },
  { &hf_nr_rrc_rf_Parameters_MRDC, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RF_Parameters_MRDC },
  { &hf_nr_rrc_phyLayerParameters_MRDC, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhyLayerParameters_MRDC },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_UE_MRDC_Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_UE_MRDC_Capability, UE_MRDC_Capability_sequence);

  return offset;
}


static const value_string nr_rrc_T_dataRateDRB_IP_vals[] = {
  {   0, "kbps64" },
  {   1, "spare6" },
  {   2, "spare5" },
  {   3, "spare4" },
  {   4, "spare3" },
  {   5, "spare2" },
  {   6, "spare1" },
  {   7, "spare0" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_dataRateDRB_IP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_supportedROHC_Profiles_sequence[] = {
  { &hf_nr_rrc_profile0x0000, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0001, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0002, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0003, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0004, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0006, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0101, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0102, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0103, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { &hf_nr_rrc_profile0x0104, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_supportedROHC_Profiles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_supportedROHC_Profiles, T_supportedROHC_Profiles_sequence);

  return offset;
}


static const value_string nr_rrc_T_maxNumberROHC_ContextSessions_vals[] = {
  {   0, "cs2" },
  {   1, "cs4" },
  {   2, "cs8" },
  {   3, "cs12" },
  {   4, "cs16" },
  {   5, "cs24" },
  {   6, "cs32" },
  {   7, "cs48" },
  {   8, "cs64" },
  {   9, "cs128" },
  {  10, "cs256" },
  {  11, "cs512" },
  {  12, "cs1024" },
  {  13, "cs16384" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_maxNumberROHC_ContextSessions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_uplinkOnlyROHC_Profiles_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_uplinkOnlyROHC_Profiles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_continueROHC_Context_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_continueROHC_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_outOfOrderDelivery_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_outOfOrderDelivery(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_shortSN_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_shortSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_volteOverNR_PDCP_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_volteOverNR_PDCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PDCP_Parameters_sequence[] = {
  { &hf_nr_rrc_dataRateDRB_IP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_dataRateDRB_IP },
  { &hf_nr_rrc_supportedROHC_Profiles, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_supportedROHC_Profiles },
  { &hf_nr_rrc_maxNumberROHC_ContextSessions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_T_maxNumberROHC_ContextSessions },
  { &hf_nr_rrc_uplinkOnlyROHC_Profiles, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_uplinkOnlyROHC_Profiles },
  { &hf_nr_rrc_continueROHC_Context, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_continueROHC_Context },
  { &hf_nr_rrc_outOfOrderDelivery_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_outOfOrderDelivery },
  { &hf_nr_rrc_shortSN      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_shortSN },
  { &hf_nr_rrc_volteOverNR_PDCP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_volteOverNR_PDCP },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PDCP_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PDCP_Parameters, PDCP_Parameters_sequence);

  return offset;
}


static const value_string nr_rrc_T_amWithShortSN_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_amWithShortSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_umWithShortSN_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_umWithShortSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_umWIthLongSN_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_umWIthLongSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RLC_Parameters_sequence[] = {
  { &hf_nr_rrc_amWithShortSN, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_amWithShortSN },
  { &hf_nr_rrc_umWithShortSN, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_umWithShortSN },
  { &hf_nr_rrc_umWIthLongSN , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_umWIthLongSN },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RLC_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RLC_Parameters, RLC_Parameters_sequence);

  return offset;
}


static const value_string nr_rrc_T_lcp_Restriction_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_lcp_Restriction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_skipUplinkTxDynamic_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_skipUplinkTxDynamic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_logicalChannelSR_DelayTimer_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_logicalChannelSR_DelayTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_longDRX_Cycle_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_longDRX_Cycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_shortDRX_Cycle_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_shortDRX_Cycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_numberOfSR_Configurations_vals[] = {
  {   0, "n2" },
  {   1, "n3" },
  {   2, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_numberOfSR_Configurations(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string nr_rrc_T_numberOfConfiguredGrantConfigurations_vals[] = {
  {   0, "n2" },
  {   1, "n3" },
  {   2, "n4" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_numberOfConfiguredGrantConfigurations(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MAC_Parameters_sequence[] = {
  { &hf_nr_rrc_lcp_Restriction, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_lcp_Restriction },
  { &hf_nr_rrc_skipUplinkTxDynamic_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_skipUplinkTxDynamic },
  { &hf_nr_rrc_logicalChannelSR_DelayTimer, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_logicalChannelSR_DelayTimer },
  { &hf_nr_rrc_longDRX_Cycle, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_longDRX_Cycle },
  { &hf_nr_rrc_shortDRX_Cycle, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_shortDRX_Cycle },
  { &hf_nr_rrc_numberOfSR_Configurations, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_numberOfSR_Configurations },
  { &hf_nr_rrc_numberOfConfiguredGrantConfigurations, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_numberOfConfiguredGrantConfigurations },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MAC_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MAC_Parameters, MAC_Parameters_sequence);

  return offset;
}


static const value_string nr_rrc_CA_BandwidthClass_vals[] = {
  {   0, "a" },
  {   1, "b" },
  {   2, "c" },
  {   3, "d" },
  {   4, "e" },
  {   5, "f" },
  { 0, NULL }
};


static int
dissect_nr_rrc_CA_BandwidthClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MIMO_Capability_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_MIMO_Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_MIMO_Capability, MIMO_Capability_sequence);

  return offset;
}


static const per_sequence_t ModulationOrder_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_ModulationOrder(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_ModulationOrder, ModulationOrder_sequence);

  return offset;
}


static const per_sequence_t SubCarrierSpacing_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_SubCarrierSpacing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_SubCarrierSpacing, SubCarrierSpacing_sequence);

  return offset;
}


static const per_sequence_t BasebandParametersPerCC_sequence[] = {
  { &hf_nr_rrc_supportedMIMO_CapabilityDL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MIMO_Capability },
  { &hf_nr_rrc_supportedMIMO_CapabilityUL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MIMO_Capability },
  { &hf_nr_rrc_modulationOrder, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_ModulationOrder },
  { &hf_nr_rrc_subCarrierSpacing, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SubCarrierSpacing },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BasebandParametersPerCC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BasebandParametersPerCC, BasebandParametersPerCC_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC_sequence_of[1] = {
  { &hf_nr_rrc_basebandParametersPerCC_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BasebandParametersPerCC },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC, SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC_sequence_of,
                                                  1, maxServCell, FALSE);

  return offset;
}



static int
dissect_nr_rrc_BWPerCC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_CA_BandwidthClass(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t BasebandParametersPerBand_sequence[] = {
  { &hf_nr_rrc_ca_BandwidthClassDL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CA_BandwidthClass },
  { &hf_nr_rrc_ca_BandwidthClassUL, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_CA_BandwidthClass },
  { &hf_nr_rrc_basebandParametersPerCC, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC },
  { &hf_nr_rrc_supportedBWPerCC, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BWPerCC },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BasebandParametersPerBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BasebandParametersPerBand, BasebandParametersPerBand_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand_sequence_of[1] = {
  { &hf_nr_rrc_basebandParametersPerBand_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BasebandParametersPerBand },
};

static int
dissect_nr_rrc_SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand, SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand_sequence_of,
                                                  1, maxSimultaneousBands, FALSE);

  return offset;
}


static const per_sequence_t BasebandProcessingCombination_sequence[] = {
  { &hf_nr_rrc_basebandParametersPerBand, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BasebandProcessingCombination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BasebandProcessingCombination, BasebandProcessingCombination_sequence);

  return offset;
}


static const per_sequence_t SupportedBasebandProcessingCombination_sequence_of[1] = {
  { &hf_nr_rrc_SupportedBasebandProcessingCombination_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BasebandProcessingCombination },
};

static int
dissect_nr_rrc_SupportedBasebandProcessingCombination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SupportedBasebandProcessingCombination, SupportedBasebandProcessingCombination_sequence_of,
                                                  1, maxBasebandProcComb, FALSE);

  return offset;
}


static const per_sequence_t PhyLayerParameters_sequence[] = {
  { &hf_nr_rrc_supportedBasebandProcessingCombination, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SupportedBasebandProcessingCombination },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_PhyLayerParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_PhyLayerParameters, PhyLayerParameters_sequence);

  return offset;
}



static int
dissect_nr_rrc_FreqBandIndicatorNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t BandNR_sequence[] = {
  { &hf_nr_rrc_bandNR       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_FreqBandIndicatorNR },
  { &hf_nr_rrc_supportedMIMO_CapabilityDL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MIMO_Capability },
  { &hf_nr_rrc_supportedMIMO_CapabilityUL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_MIMO_Capability },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_BandNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_BandNR, BandNR_sequence);

  return offset;
}


static const per_sequence_t SupportedBandListNR_sequence_of[1] = {
  { &hf_nr_rrc_SupportedBandListNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BandNR },
};

static int
dissect_nr_rrc_SupportedBandListNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nr_rrc_SupportedBandListNR, SupportedBandListNR_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const value_string nr_rrc_T_intraBandAsyncFDD_vals[] = {
  {   0, "supported" },
  { 0, NULL }
};


static int
dissect_nr_rrc_T_intraBandAsyncFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RF_Parameters_sequence[] = {
  { &hf_nr_rrc_supportedBandListNR, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_SupportedBandListNR },
  { &hf_nr_rrc_supportedBandCombination, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_BandCombinationList },
  { &hf_nr_rrc_intraBandAsyncFDD, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_intraBandAsyncFDD },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_RF_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_RF_Parameters, RF_Parameters_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_02_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_T_nonCriticalExtension_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_T_nonCriticalExtension_02, T_nonCriticalExtension_02_sequence);

  return offset;
}


static const per_sequence_t UE_NR_Capability_sequence[] = {
  { &hf_nr_rrc_pdcp_Parameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PDCP_Parameters },
  { &hf_nr_rrc_rlc_Parameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RLC_Parameters },
  { &hf_nr_rrc_mac_Parameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_MAC_Parameters },
  { &hf_nr_rrc_phyLayerParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_PhyLayerParameters },
  { &hf_nr_rrc_rf_Parameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nr_rrc_RF_Parameters },
  { &hf_nr_rrc_nonCriticalExtension_02, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nr_rrc_T_nonCriticalExtension_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nr_rrc_UE_NR_Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nr_rrc_UE_NR_Capability, UE_NR_Capability_sequence);

  return offset;
}



static int
dissect_nr_rrc_UECapabilityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &parameter_tvb);


  if (parameter_tvb) {
    subtree = proto_item_add_subtree(actx->created_item, ett_nr_rrc_UECapabilityInformation);
    dissect_lte_rrc_UECapabilityInformation_PDU(parameter_tvb, actx->pinfo, subtree, NULL);
  }

  return offset;
}



static int
dissect_nr_rrc_RadioBearerConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nr_rrc_RadioBearerConfig(tvb, offset, actx, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

int dissect_nr_rrc_SCG_ConfigInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_SCG_ConfigInfo(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_SCG_ConfigInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCCH_BCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_BCCH_BCH_Message(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_BCCH_BCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_DL_DCCH_Message(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_DL_DCCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_UL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_UL_DCCH_Message(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_UL_DCCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_MIB_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_MIB(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_MIB_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_RRCReconfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_RRCReconfiguration(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_RRCReconfiguration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_RRCReconfigurationComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_RRCReconfigurationComplete(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_RRCReconfigurationComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_CellGroupConfig_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_CellGroupConfig(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_CellGroupConfig_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_MeasResults_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_MeasResults(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_MeasResults_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_RadioBearerConfig_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_RadioBearerConfig(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_RadioBearerConfig_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_UE_MRDC_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_UE_MRDC_Capability(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_UE_MRDC_Capability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nr_rrc_UE_NR_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_UE_NR_Capability(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_nr_rrc_UE_NR_Capability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UECapabilityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_UECapabilityInformation(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_UECapabilityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RadioBearerConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_RadioBearerConfiguration(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_RadioBearerConfiguration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-nr-rrc-fn.c ---*/
#line 74 "./asn1/nr-rrc/packet-nr-rrc-template.c"

void proto_register_nr_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-nr-rrc-hfarr.c ---*/
#line 1 "./asn1/nr-rrc/packet-nr-rrc-hfarr.c"
    { &hf_nr_rrc_nr_rrc_SCG_ConfigInfo_PDU,
      { "SCG-ConfigInfo", "nr-rrc.SCG_ConfigInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_BCCH_BCH_Message_PDU,
      { "BCCH-BCH-Message", "nr-rrc.BCCH_BCH_Message_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_DL_DCCH_Message_PDU,
      { "DL-DCCH-Message", "nr-rrc.DL_DCCH_Message_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_UL_DCCH_Message_PDU,
      { "UL-DCCH-Message", "nr-rrc.UL_DCCH_Message_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_MIB_PDU,
      { "MIB", "nr-rrc.MIB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_RRCReconfiguration_PDU,
      { "RRCReconfiguration", "nr-rrc.RRCReconfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_RRCReconfigurationComplete_PDU,
      { "RRCReconfigurationComplete", "nr-rrc.RRCReconfigurationComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_CellGroupConfig_PDU,
      { "CellGroupConfig", "nr-rrc.CellGroupConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_MeasResults_PDU,
      { "MeasResults", "nr-rrc.MeasResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_RadioBearerConfig_PDU,
      { "RadioBearerConfig", "nr-rrc.RadioBearerConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_UE_MRDC_Capability_PDU,
      { "UE-MRDC-Capability", "nr-rrc.UE_MRDC_Capability_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nr_rrc_UE_NR_Capability_PDU,
      { "UE-NR-Capability", "nr-rrc.UE_NR_Capability_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_UECapabilityInformation_PDU,
      { "UECapabilityInformation", "nr-rrc.UECapabilityInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_RadioBearerConfiguration_PDU,
      { "RadioBearerConfiguration", "nr-rrc.RadioBearerConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_criticalExtensions,
      { "criticalExtensions", "nr-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_criticalExtensions_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_c1,
      { "c1", "nr-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_c1_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_scg_ConfigInfo_r15,
      { "scg-ConfigInfo-r15", "nr-rrc.scg_ConfigInfo_r15_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SCG_ConfigInfo_r15_IEs", HFILL }},
    { &hf_nr_rrc_spare3,
      { "spare3", "nr-rrc.spare3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare2,
      { "spare2", "nr-rrc.spare2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare1,
      { "spare1", "nr-rrc.spare1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_criticalExtensionsFuture,
      { "criticalExtensionsFuture", "nr-rrc.criticalExtensionsFuture_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_eutra_CapabilityInfo,
      { "eutra-CapabilityInfo", "nr-rrc.eutra_CapabilityInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_candidateCellInfoList,
      { "candidateCellInfoList", "nr-rrc.candidateCellInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measResultSSTD,
      { "measResultSSTD", "nr-rrc.measResultSSTD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_configRestrictInfo,
      { "configRestrictInfo", "nr-rrc.configRestrictInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConfigRestrictInfoSCG", HFILL }},
    { &hf_nr_rrc_drx_InfoMCG,
      { "drx-InfoMCG", "nr-rrc.drx_InfoMCG_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DRX_Info", HFILL }},
    { &hf_nr_rrc_sourceConfigSCG,
      { "sourceConfigSCG", "nr-rrc.sourceConfigSCG",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_p_maxFR1,
      { "p-maxFR1", "nr-rrc.p_maxFR1",
        FT_INT32, BASE_DEC, NULL, 0,
        "P_Max", HFILL }},
    { &hf_nr_rrc_mcg_RB_Config,
      { "mcg-RB-Config", "nr-rrc.mcg_RB_Config",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nonCriticalExtension,
      { "nonCriticalExtension", "nr-rrc.nonCriticalExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_restrictedBandCombinationNR,
      { "restrictedBandCombinationNR", "nr-rrc.restrictedBandCombinationNR",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_nr_rrc_restrictedBasebandCombinationNR_NR,
      { "restrictedBasebandCombinationNR-NR", "nr-rrc.restrictedBasebandCombinationNR_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_restrictedBasebandCombinationNR_NR_item,
      { "restrictedBasebandCombinationNR-NR item", "nr-rrc.restrictedBasebandCombinationNR_NR_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_nr_rrc_maxMeasFreqsSCG_NR,
      { "maxMeasFreqsSCG-NR", "nr-rrc.maxMeasFreqsSCG_NR",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_nr_rrc_cycle,
      { "cycle", "nr-rrc.cycle",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_nr_rrc_offset,
      { "offset", "nr-rrc.offset",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_nr_rrc_CandidateCellInfoList_item,
      { "CandidateCellInfo", "nr-rrc.CandidateCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cellIdentification,
      { "cellIdentification", "nr-rrc.cellIdentification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_physCellId,
      { "physCellId", "nr-rrc.physCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dl_CarrierFreq,
      { "dl-CarrierFreq", "nr-rrc.dl_CarrierFreq",
        FT_INT32, BASE_DEC, NULL, 0,
        "ARFCN_ValueNR", HFILL }},
    { &hf_nr_rrc_measResultCell,
      { "measResultCell", "nr-rrc.measResultCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rsrpResultCell,
      { "rsrpResultCell", "nr-rrc.rsrpResultCell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRP_Range", HFILL }},
    { &hf_nr_rrc_rsrqResultCell,
      { "rsrqResultCell", "nr-rrc.rsrqResultCell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRQ_Range", HFILL }},
    { &hf_nr_rrc_candidateRS_IndexList,
      { "candidateRS-IndexList", "nr-rrc.candidateRS_IndexList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CandidateRS_IndexInfoList", HFILL }},
    { &hf_nr_rrc_CandidateRS_IndexInfoList_item,
      { "CandidateRS-IndexInfo", "nr-rrc.CandidateRS_IndexInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssb_Index,
      { "ssb-Index", "nr-rrc.ssb_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measResultSSB,
      { "measResultSSB", "nr-rrc.measResultSSB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_message,
      { "message", "nr-rrc.message",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_BCCH_BCH_MessageType_vals), 0,
        "BCCH_BCH_MessageType", HFILL }},
    { &hf_nr_rrc_mib,
      { "mib", "nr-rrc.mib_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_messageClassExtension,
      { "messageClassExtension", "nr-rrc.messageClassExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_message_01,
      { "message", "nr-rrc.message",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_DL_DCCH_MessageType_vals), 0,
        "DL_DCCH_MessageType", HFILL }},
    { &hf_nr_rrc_c1_01,
      { "c1", "nr-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_c1_01_vals), 0,
        "T_c1_01", HFILL }},
    { &hf_nr_rrc_rrcReconfiguration,
      { "rrcReconfiguration", "nr-rrc.rrcReconfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare15,
      { "spare15", "nr-rrc.spare15_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare14,
      { "spare14", "nr-rrc.spare14_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare13,
      { "spare13", "nr-rrc.spare13_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare12,
      { "spare12", "nr-rrc.spare12_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare11,
      { "spare11", "nr-rrc.spare11_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare10,
      { "spare10", "nr-rrc.spare10_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare9,
      { "spare9", "nr-rrc.spare9_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare8,
      { "spare8", "nr-rrc.spare8_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare7,
      { "spare7", "nr-rrc.spare7_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare6,
      { "spare6", "nr-rrc.spare6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare5,
      { "spare5", "nr-rrc.spare5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare4,
      { "spare4", "nr-rrc.spare4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_messageClassExtension_01,
      { "messageClassExtension", "nr-rrc.messageClassExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_messageClassExtension_01", HFILL }},
    { &hf_nr_rrc_message_02,
      { "message", "nr-rrc.message",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_UL_DCCH_MessageType_vals), 0,
        "UL_DCCH_MessageType", HFILL }},
    { &hf_nr_rrc_c1_02,
      { "c1", "nr-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_c1_02_vals), 0,
        "T_c1_02", HFILL }},
    { &hf_nr_rrc_measurementReport,
      { "measurementReport", "nr-rrc.measurementReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rrcReconfigurationComplete,
      { "rrcReconfigurationComplete", "nr-rrc.rrcReconfigurationComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_messageClassExtension_02,
      { "messageClassExtension", "nr-rrc.messageClassExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_messageClassExtension_02", HFILL }},
    { &hf_nr_rrc_ssb_IndexExplicit,
      { "ssb-IndexExplicit", "nr-rrc.ssb_IndexExplicit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_7", HFILL }},
    { &hf_nr_rrc_halfFrameIndex,
      { "halfFrameIndex", "nr-rrc.halfFrameIndex",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_halfFrameIndex_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_systemFrameNumber,
      { "systemFrameNumber", "nr-rrc.systemFrameNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_nr_rrc_subCarrierSpacingCommon,
      { "subCarrierSpacingCommon", "nr-rrc.subCarrierSpacingCommon",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SubcarrierSpacing_vals), 0,
        "SubcarrierSpacing", HFILL }},
    { &hf_nr_rrc_ssb_subcarrierOffset,
      { "ssb-subcarrierOffset", "nr-rrc.ssb_subcarrierOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_11", HFILL }},
    { &hf_nr_rrc_dmrs_TypeA_Position,
      { "dmrs-TypeA-Position", "nr-rrc.dmrs_TypeA_Position",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dmrs_TypeA_Position_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdcchConfigSIB1,
      { "pdcchConfigSIB1", "nr-rrc.pdcchConfigSIB1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nr_rrc_cellBarred,
      { "cellBarred", "nr-rrc.cellBarred",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cellBarred_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_intraFreqReselection,
      { "intraFreqReselection", "nr-rrc.intraFreqReselection",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_intraFreqReselection_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare,
      { "spare", "nr-rrc.spare",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_0", HFILL }},
    { &hf_nr_rrc_criticalExtensions_01,
      { "criticalExtensions", "nr-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_criticalExtensions_01_vals), 0,
        "T_criticalExtensions_01", HFILL }},
    { &hf_nr_rrc_measurementReport_01,
      { "measurementReport", "nr-rrc.measurementReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MeasurementReport_IEs", HFILL }},
    { &hf_nr_rrc_criticalExtensionsFuture_01,
      { "criticalExtensionsFuture", "nr-rrc.criticalExtensionsFuture_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_criticalExtensionsFuture_01", HFILL }},
    { &hf_nr_rrc_measResults,
      { "measResults", "nr-rrc.measResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rrc_TransactionIdentifier,
      { "rrc-TransactionIdentifier", "nr-rrc.rrc_TransactionIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_criticalExtensions_02,
      { "criticalExtensions", "nr-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_criticalExtensions_02_vals), 0,
        "T_criticalExtensions_02", HFILL }},
    { &hf_nr_rrc_rrcReconfiguration_01,
      { "rrcReconfiguration", "nr-rrc.rrcReconfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRCReconfiguration_IEs", HFILL }},
    { &hf_nr_rrc_criticalExtensionsFuture_02,
      { "criticalExtensionsFuture", "nr-rrc.criticalExtensionsFuture_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_criticalExtensionsFuture_02", HFILL }},
    { &hf_nr_rrc_radioBearerConfig,
      { "radioBearerConfig", "nr-rrc.radioBearerConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_masterCellGroupConfig,
      { "masterCellGroupConfig", "nr-rrc.masterCellGroupConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellGroupConfig", HFILL }},
    { &hf_nr_rrc_secondaryCellGroupToAddModList,
      { "secondaryCellGroupToAddModList", "nr-rrc.secondaryCellGroupToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig", HFILL }},
    { &hf_nr_rrc_secondaryCellGroupToAddModList_item,
      { "CellGroupConfig", "nr-rrc.CellGroupConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_secondaryCellGroupToReleaseList,
      { "secondaryCellGroupToReleaseList", "nr-rrc.secondaryCellGroupToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId", HFILL }},
    { &hf_nr_rrc_secondaryCellGroupToReleaseList_item,
      { "CellGroupId", "nr-rrc.CellGroupId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measConfig,
      { "measConfig", "nr-rrc.measConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_lateNonCriticalExtension,
      { "lateNonCriticalExtension", "nr-rrc.lateNonCriticalExtension",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_nr_rrc_nonCriticalExtension_01,
      { "nonCriticalExtension", "nr-rrc.nonCriticalExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_nonCriticalExtension_01", HFILL }},
    { &hf_nr_rrc_criticalExtensions_03,
      { "criticalExtensions", "nr-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_criticalExtensions_03_vals), 0,
        "T_criticalExtensions_03", HFILL }},
    { &hf_nr_rrc_rrcReconfigurationComplete_01,
      { "rrcReconfigurationComplete", "nr-rrc.rrcReconfigurationComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRCReconfigurationComplete_IEs", HFILL }},
    { &hf_nr_rrc_criticalExtensionsFuture_03,
      { "criticalExtensionsFuture", "nr-rrc.criticalExtensionsFuture_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_criticalExtensionsFuture_03", HFILL }},
    { &hf_nr_rrc_bandwidthPartId,
      { "bandwidthPartId", "nr-rrc.bandwidthPartId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_location,
      { "location", "nr-rrc.location",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxNrofPhysicalResourceBlocksTimes4", HFILL }},
    { &hf_nr_rrc_bandwidth,
      { "bandwidth", "nr-rrc.bandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_maxNrofPhysicalResourceBlocks", HFILL }},
    { &hf_nr_rrc_subcarrierSpacing,
      { "subcarrierSpacing", "nr-rrc.subcarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_subcarrierSpacing_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cyclicPrefix,
      { "cyclicPrefix", "nr-rrc.cyclicPrefix",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cyclicPrefix_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_directCurrentLocation,
      { "directCurrentLocation", "nr-rrc.directCurrentLocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3299", HFILL }},
    { &hf_nr_rrc_cellGroupId,
      { "cellGroupId", "nr-rrc.cellGroupId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rlc_BearerToAddModList,
      { "rlc-BearerToAddModList", "nr-rrc.rlc_BearerToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config", HFILL }},
    { &hf_nr_rrc_rlc_BearerToAddModList_item,
      { "LCH-Config", "nr-rrc.LCH_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rlc_BearerToReleaseList,
      { "rlc-BearerToReleaseList", "nr-rrc.rlc_BearerToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity", HFILL }},
    { &hf_nr_rrc_rlc_BearerToReleaseList_item,
      { "LogicalChannelIdentity", "nr-rrc.LogicalChannelIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_mac_CellGroupConfig,
      { "mac-CellGroupConfig", "nr-rrc.mac_CellGroupConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rlf_TimersAndConstants,
      { "rlf-TimersAndConstants", "nr-rrc.rlf_TimersAndConstants_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_physical_CellGroupConfig,
      { "physical-CellGroupConfig", "nr-rrc.physical_CellGroupConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PhysicalCellGroupConfig", HFILL }},
    { &hf_nr_rrc_spCellConfig,
      { "spCellConfig", "nr-rrc.spCellConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sCellToAddModList,
      { "sCellToAddModList", "nr-rrc.sCellToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sCellToReleaseList,
      { "sCellToReleaseList", "nr-rrc.sCellToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_logicalChannelIdentity,
      { "logicalChannelIdentity", "nr-rrc.logicalChannelIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_servedRadioBearer,
      { "servedRadioBearer", "nr-rrc.servedRadioBearer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_nr_rrc_reestablishRLC,
      { "reestablishRLC", "nr-rrc.reestablishRLC",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reestablishRLC_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rlc_Config,
      { "rlc-Config", "nr-rrc.rlc_Config",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_RLC_Config_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_mac_LogicalChannelConfig,
      { "mac-LogicalChannelConfig", "nr-rrc.mac_LogicalChannelConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LogicalChannelConfig", HFILL }},
    { &hf_nr_rrc_harq_ACK_Spatial_Bundling,
      { "harq-ACK-Spatial-Bundling", "nr-rrc.harq_ACK_Spatial_Bundling",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_harq_ACK_Spatial_Bundling_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reconfigurationWithSync,
      { "reconfigurationWithSync", "nr-rrc.reconfigurationWithSync_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spCellConfigCommon,
      { "spCellConfigCommon", "nr-rrc.spCellConfigCommon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServingCellConfigCommon", HFILL }},
    { &hf_nr_rrc_newUE_Identity,
      { "newUE-Identity", "nr-rrc.newUE_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "C_RNTI", HFILL }},
    { &hf_nr_rrc_t304,
      { "t304", "nr-rrc.t304",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_t304_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rach_ConfigDedicated,
      { "rach-ConfigDedicated", "nr-rrc.rach_ConfigDedicated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spCellConfigDedicated,
      { "spCellConfigDedicated", "nr-rrc.spCellConfigDedicated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServingCellConfigDedicated", HFILL }},
    { &hf_nr_rrc_SCellToReleaseList_item,
      { "SCellIndex", "nr-rrc.SCellIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_SCellToAddModList_item,
      { "SCellConfig", "nr-rrc.SCellConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sCellIndex,
      { "sCellIndex", "nr-rrc.sCellIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sCellConfigCommon,
      { "sCellConfigCommon", "nr-rrc.sCellConfigCommon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServingCellConfigCommon", HFILL }},
    { &hf_nr_rrc_sCellConfigDedicated,
      { "sCellConfigDedicated", "nr-rrc.sCellConfigDedicated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServingCellConfigDedicated", HFILL }},
    { &hf_nr_rrc_CellIndexList_item,
      { "CellIndex", "nr-rrc.CellIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_schedulingCellInfo,
      { "schedulingCellInfo", "nr-rrc.schedulingCellInfo",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_schedulingCellInfo_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_own,
      { "own", "nr-rrc.own_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cif_Presence,
      { "cif-Presence", "nr-rrc.cif_Presence",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_other,
      { "other", "nr-rrc.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_schedulingCellId,
      { "schedulingCellId", "nr-rrc.schedulingCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServCellIndex", HFILL }},
    { &hf_nr_rrc_pdsch_Start,
      { "pdsch-Start", "nr-rrc.pdsch_Start",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4", HFILL }},
    { &hf_nr_rrc_cif_InSchedulingCell,
      { "cif-InSchedulingCell", "nr-rrc.cif_InSchedulingCell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_7", HFILL }},
    { &hf_nr_rrc_csi_ResourceConfigs,
      { "csi-ResourceConfigs", "nr-rrc.csi_ResourceConfigs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig", HFILL }},
    { &hf_nr_rrc_csi_ResourceConfigs_item,
      { "CSI-ResourceConfig", "nr-rrc.CSI_ResourceConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_ReportConfigs,
      { "csi-ReportConfigs", "nr-rrc.csi_ReportConfigs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig", HFILL }},
    { &hf_nr_rrc_csi_ReportConfigs_item,
      { "CSI-ReportConfig", "nr-rrc.CSI_ReportConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_MeasIdToAddModList,
      { "csi-MeasIdToAddModList", "nr-rrc.csi_MeasIdToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod", HFILL }},
    { &hf_nr_rrc_csi_MeasIdToAddModList_item,
      { "CSI-MeasIdToAddMod", "nr-rrc.CSI_MeasIdToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportTrigger,
      { "reportTrigger", "nr-rrc.reportTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportTriggerSize,
      { "reportTriggerSize", "nr-rrc.reportTriggerSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_6", HFILL }},
    { &hf_nr_rrc_csi_ResourceConfigId,
      { "csi-ResourceConfigId", "nr-rrc.csi_ResourceConfigId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_ResourceSets,
      { "csi-ResourceSets", "nr-rrc.csi_ResourceSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet", HFILL }},
    { &hf_nr_rrc_csi_ResourceSets_item,
      { "CSI-ResourceSet", "nr-rrc.CSI_ResourceSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssb_Resources,
      { "ssb-Resources", "nr-rrc.ssb_Resources",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource", HFILL }},
    { &hf_nr_rrc_ssb_Resources_item,
      { "CSI-SSB-Resource", "nr-rrc.CSI_SSB_Resource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_resourceType,
      { "resourceType", "nr-rrc.resourceType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_resourceType_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_aperiodic,
      { "aperiodic", "nr-rrc.aperiodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_semiPersistent,
      { "semiPersistent", "nr-rrc.semiPersistent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_periodic,
      { "periodic", "nr-rrc.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_ResourceSetId,
      { "csi-ResourceSetId", "nr-rrc.csi_ResourceSetId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_rs_Resources,
      { "csi-rs-Resources", "nr-rrc.csi_rs_Resources",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource", HFILL }},
    { &hf_nr_rrc_csi_rs_Resources_item,
      { "NZP-CSI-RS-Resource", "nr-rrc.NZP_CSI_RS_Resource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_repetition,
      { "repetition", "nr-rrc.repetition",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_nzp_csi_rs_ResourceId,
      { "nzp-csi-rs-ResourceId", "nr-rrc.nzp_csi_rs_ResourceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofPorts,
      { "nrofPorts", "nr-rrc.nrofPorts",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofPorts_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_resourceMapping,
      { "resourceMapping", "nr-rrc.resourceMapping_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cdm_Value,
      { "cdm-Value", "nr-rrc.cdm_Value",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cdm_Value_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cdm_Pattern,
      { "cdm-Pattern", "nr-rrc.cdm_Pattern",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cdm_Pattern_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_RS_Density,
      { "csi-RS-Density", "nr-rrc.csi_RS_Density",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_csi_RS_Density_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_RS_FreqBand,
      { "csi-RS-FreqBand", "nr-rrc.csi_RS_FreqBand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_powerControlOffset,
      { "powerControlOffset", "nr-rrc.powerControlOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_powerControlOffsetSS,
      { "powerControlOffsetSS", "nr-rrc.powerControlOffsetSS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_scramblingID,
      { "scramblingID", "nr-rrc.scramblingID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0", HFILL }},
    { &hf_nr_rrc_csi_RS_timeConfig,
      { "csi-RS-timeConfig", "nr-rrc.csi_RS_timeConfig",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_csi_RS_timeConfig_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sl5,
      { "sl5", "nr-rrc.sl5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4", HFILL }},
    { &hf_nr_rrc_sl10,
      { "sl10", "nr-rrc.sl10",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nr_rrc_sl20,
      { "sl20", "nr-rrc.sl20",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_19", HFILL }},
    { &hf_nr_rrc_sl40,
      { "sl40", "nr-rrc.sl40",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_39", HFILL }},
    { &hf_nr_rrc_sl80,
      { "sl80", "nr-rrc.sl80",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_79", HFILL }},
    { &hf_nr_rrc_sl160,
      { "sl160", "nr-rrc.sl160",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_159", HFILL }},
    { &hf_nr_rrc_sl320,
      { "sl320", "nr-rrc.sl320",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_319", HFILL }},
    { &hf_nr_rrc_sl640,
      { "sl640", "nr-rrc.sl640",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_639", HFILL }},
    { &hf_nr_rrc_reportConfigId,
      { "reportConfigId", "nr-rrc.reportConfigId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CSI_ReportConfigId", HFILL }},
    { &hf_nr_rrc_reportConfigType,
      { "reportConfigType", "nr-rrc.reportConfigType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reportConfigType_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_periodic_01,
      { "periodic", "nr-rrc.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportSlotConfig,
      { "reportSlotConfig", "nr-rrc.reportSlotConfig",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reportSlotConfig_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pucch_CSI_ResourceIndex,
      { "pucch-CSI-ResourceIndex", "nr-rrc.pucch_CSI_ResourceIndex_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_semiPersistent_01,
      { "semiPersistent", "nr-rrc.semiPersistent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportSlotConfig_01,
      { "reportSlotConfig", "nr-rrc.reportSlotConfig",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reportSlotConfig_01_vals), 0,
        "T_reportSlotConfig_01", HFILL }},
    { &hf_nr_rrc_aperiodic_01,
      { "aperiodic", "nr-rrc.aperiodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_aperiodicReportSlotOffset,
      { "aperiodicReportSlotOffset", "nr-rrc.aperiodicReportSlotOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportQuantity,
      { "reportQuantity", "nr-rrc.reportQuantity",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reportQuantity_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cRI_RI_PMI_CQI,
      { "cRI-RI-PMI-CQI", "nr-rrc.cRI_RI_PMI_CQI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cRI_RI_i1,
      { "cRI-RI-i1", "nr-rrc.cRI_RI_i1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cRI_RI_i1_CQI,
      { "cRI-RI-i1-CQI", "nr-rrc.cRI_RI_i1_CQI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdsch_BundleSizeForCSI,
      { "pdsch-BundleSizeForCSI", "nr-rrc.pdsch_BundleSizeForCSI",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_pdsch_BundleSizeForCSI_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cRI_RI_CQI,
      { "cRI-RI-CQI", "nr-rrc.cRI_RI_CQI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cRI,
      { "cRI", "nr-rrc.cRI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cRI_RSRP,
      { "cRI-RSRP", "nr-rrc.cRI_RSRP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_spare0,
      { "spare0", "nr-rrc.spare0_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportFreqConfiguration,
      { "reportFreqConfiguration", "nr-rrc.reportFreqConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cqi_FormatIndicator,
      { "cqi-FormatIndicator", "nr-rrc.cqi_FormatIndicator",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cqi_FormatIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pmi_FormatIndicator,
      { "pmi-FormatIndicator", "nr-rrc.pmi_FormatIndicator",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_pmi_FormatIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_ReportingBand,
      { "csi-ReportingBand", "nr-rrc.csi_ReportingBand",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measRestrictionTimeForChannel,
      { "measRestrictionTimeForChannel", "nr-rrc.measRestrictionTimeForChannel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measRestrictionTimeForInterference,
      { "measRestrictionTimeForInterference", "nr-rrc.measRestrictionTimeForInterference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_codebookConfig,
      { "codebookConfig", "nr-rrc.codebookConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofCQIsPerReport,
      { "nrofCQIsPerReport", "nr-rrc.nrofCQIsPerReport",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofCQIsPerReport_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_groupBasedBeamReporting,
      { "groupBasedBeamReporting", "nr-rrc.groupBasedBeamReporting",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_groupBasedBeamReporting_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_enabled,
      { "enabled", "nr-rrc.enabled_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofBeamsToReport,
      { "nrofBeamsToReport", "nr-rrc.nrofBeamsToReport",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_4", HFILL }},
    { &hf_nr_rrc_disabled,
      { "disabled", "nr-rrc.disabled_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofReportedRS,
      { "nrofReportedRS", "nr-rrc.nrofReportedRS",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofReportedRS_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cqi_Table,
      { "cqi-Table", "nr-rrc.cqi_Table",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cqi_Table_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_subbandSize,
      { "subbandSize", "nr-rrc.subbandSize",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_subbandSize_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_bler_Target,
      { "bler-Target", "nr-rrc.bler_Target",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_bler_Target_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_codebookConfig_N1,
      { "codebookConfig-N1", "nr-rrc.codebookConfig_N1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_codebookConfig_N1_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_codebookConfig_N2,
      { "codebookConfig-N2", "nr-rrc.codebookConfig_N2",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_codebookConfig_N2_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_codebookType,
      { "codebookType", "nr-rrc.codebookType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_codebookType_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_type1,
      { "type1", "nr-rrc.type1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_subType,
      { "subType", "nr-rrc.subType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_subType_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_codebookMode,
      { "codebookMode", "nr-rrc.codebookMode",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_codebookMode_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_numberOfPanels,
      { "numberOfPanels", "nr-rrc.numberOfPanels",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_numberOfPanels_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_codebookSubsetRestrictionType1,
      { "codebookSubsetRestrictionType1", "nr-rrc.codebookSubsetRestrictionType1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_codebookSubsetRestrictionType1_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_singlePanel,
      { "singlePanel", "nr-rrc.singlePanel",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_singlePanel2TX,
      { "singlePanel2TX", "nr-rrc.singlePanel2TX",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_nr_rrc_multiPanel,
      { "multiPanel", "nr-rrc.multiPanel",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_singlePanelCodebookSubsetRestriction_i2,
      { "singlePanelCodebookSubsetRestriction-i2", "nr-rrc.singlePanelCodebookSubsetRestriction_i2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_nr_rrc_ri_Restriction,
      { "ri-Restriction", "nr-rrc.ri_Restriction",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ri_Restriction_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_typeI_SinglePanelRI_Restriction,
      { "typeI-SinglePanelRI-Restriction", "nr-rrc.typeI_SinglePanelRI_Restriction",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_nr_rrc_typeI_MultiPanelRI_Restriction,
      { "typeI-MultiPanelRI-Restriction", "nr-rrc.typeI_MultiPanelRI_Restriction",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_nr_rrc_type2,
      { "type2", "nr-rrc.type2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_subType_01,
      { "subType", "nr-rrc.subType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_subType_01_vals), 0,
        "T_subType_01", HFILL }},
    { &hf_nr_rrc_phaseAlphabetSize,
      { "phaseAlphabetSize", "nr-rrc.phaseAlphabetSize",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_phaseAlphabetSize_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_subbandAmplitude,
      { "subbandAmplitude", "nr-rrc.subbandAmplitude",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_numberOfBeams,
      { "numberOfBeams", "nr-rrc.numberOfBeams",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_numberOfBeams_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_portSelectionSamplingSize,
      { "portSelectionSamplingSize", "nr-rrc.portSelectionSamplingSize",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_portSelectionSamplingSize_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_codebookSubsetRestrictionType2,
      { "codebookSubsetRestrictionType2", "nr-rrc.codebookSubsetRestrictionType2",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ri_Restriction_01,
      { "ri-Restriction", "nr-rrc.ri_Restriction",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ri_Restriction_01_vals), 0,
        "T_ri_Restriction_01", HFILL }},
    { &hf_nr_rrc_typeII_RI_Restriction,
      { "typeII-RI-Restriction", "nr-rrc.typeII_RI_Restriction",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_nr_rrc_typeII_PortSelectionRI_Restriction,
      { "typeII-PortSelectionRI-Restriction", "nr-rrc.typeII_PortSelectionRI_Restriction",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_nr_rrc_csi_measId,
      { "csi-measId", "nr-rrc.csi_measId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_RS_resourceConfigId,
      { "csi-RS-resourceConfigId", "nr-rrc.csi_RS_resourceConfigId",
        FT_INT32, BASE_DEC, NULL, 0,
        "CSI_RS_ConfigurationId", HFILL }},
    { &hf_nr_rrc_csi_reportConfigId,
      { "csi-reportConfigId", "nr-rrc.csi_reportConfigId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measQuantity,
      { "measQuantity", "nr-rrc.measQuantity",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_measQuantity_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_carrierFreqUL,
      { "carrierFreqUL", "nr-rrc.carrierFreqUL",
        FT_INT32, BASE_DEC, NULL, 0,
        "ARFCN_ValueNR", HFILL }},
    { &hf_nr_rrc_carrierBandwidthUL,
      { "carrierBandwidthUL", "nr-rrc.carrierBandwidthUL",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_CarrierBandwidthNR_vals), 0,
        "CarrierBandwidthNR", HFILL }},
    { &hf_nr_rrc_additionalSpectrumEmission,
      { "additionalSpectrumEmission", "nr-rrc.additionalSpectrumEmission",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_p_Max,
      { "p-Max", "nr-rrc.p_Max",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_frequencyShift7p5khz,
      { "frequencyShift7p5khz", "nr-rrc.frequencyShift7p5khz",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_frequencyShift7p5khz_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_initialUplinkBandwidthPart,
      { "initialUplinkBandwidthPart", "nr-rrc.initialUplinkBandwidthPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BandwidthPart", HFILL }},
    { &hf_nr_rrc_ul_SpecificParameters,
      { "ul-SpecificParameters", "nr-rrc.ul_SpecificParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_priority,
      { "priority", "nr-rrc.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_nr_rrc_prioritisedBitRate,
      { "prioritisedBitRate", "nr-rrc.prioritisedBitRate",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_prioritisedBitRate_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_bucketSizeDuration,
      { "bucketSizeDuration", "nr-rrc.bucketSizeDuration",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_bucketSizeDuration_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_allowedSubCarrierSpacing,
      { "allowedSubCarrierSpacing", "nr-rrc.allowedSubCarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SubcarrierSpacing_vals), 0,
        "SubcarrierSpacing", HFILL }},
    { &hf_nr_rrc_allowedTiming,
      { "allowedTiming", "nr-rrc.allowedTiming_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_logicalChannelGroup,
      { "logicalChannelGroup", "nr-rrc.logicalChannelGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxLCid", HFILL }},
    { &hf_nr_rrc_logicalChannelSR_Mask,
      { "logicalChannelSR-Mask", "nr-rrc.logicalChannelSR_Mask",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_logicalChannelSR_DelayTimerApplied,
      { "logicalChannelSR-DelayTimerApplied", "nr-rrc.logicalChannelSR_DelayTimerApplied",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_drx_Config,
      { "drx-Config", "nr-rrc.drx_Config",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_DRX_Config_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_schedulingRequestConfig,
      { "schedulingRequestConfig", "nr-rrc.schedulingRequestConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_bsr_Config,
      { "bsr-Config", "nr-rrc.bsr_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BSR_Configuration", HFILL }},
    { &hf_nr_rrc_tag_Config,
      { "tag-Config", "nr-rrc.tag_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TAG_Configuration", HFILL }},
    { &hf_nr_rrc_phr_Config,
      { "phr-Config", "nr-rrc.phr_Config",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_PHR_Config_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sCellDeactivationTimer,
      { "sCellDeactivationTimer", "nr-rrc.sCellDeactivationTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_sCellDeactivationTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_skipUplinkTxDynamic,
      { "skipUplinkTxDynamic", "nr-rrc.skipUplinkTxDynamic",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_release,
      { "release", "nr-rrc.release_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drx_onDurationTimer,
      { "drx-onDurationTimer", "nr-rrc.drx_onDurationTimer",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_drx_onDurationTimer_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drx_InactivityTimer,
      { "drx-InactivityTimer", "nr-rrc.drx_InactivityTimer",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_drx_InactivityTimer_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drx_HARQ_RTT_TimerDL,
      { "drx-HARQ-RTT-TimerDL", "nr-rrc.drx_HARQ_RTT_TimerDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_56", HFILL }},
    { &hf_nr_rrc_drx_HARQ_RTT_TimerUL,
      { "drx-HARQ-RTT-TimerUL", "nr-rrc.drx_HARQ_RTT_TimerUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_56", HFILL }},
    { &hf_nr_rrc_drx_RetransmissionTimerDL,
      { "drx-RetransmissionTimerDL", "nr-rrc.drx_RetransmissionTimerDL",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_drx_RetransmissionTimerDL_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drx_RetransmissionTimerUL,
      { "drx-RetransmissionTimerUL", "nr-rrc.drx_RetransmissionTimerUL",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_drx_RetransmissionTimerUL_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drx_LongCycleStartOffset,
      { "drx-LongCycleStartOffset", "nr-rrc.drx_LongCycleStartOffset",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_drx_LongCycleStartOffset_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ms10,
      { "ms10", "nr-rrc.ms10",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nr_rrc_ms20,
      { "ms20", "nr-rrc.ms20",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_19", HFILL }},
    { &hf_nr_rrc_ms32,
      { "ms32", "nr-rrc.ms32",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nr_rrc_ms40,
      { "ms40", "nr-rrc.ms40",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_39", HFILL }},
    { &hf_nr_rrc_ms60,
      { "ms60", "nr-rrc.ms60",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_59", HFILL }},
    { &hf_nr_rrc_ms64,
      { "ms64", "nr-rrc.ms64",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_nr_rrc_ms70,
      { "ms70", "nr-rrc.ms70",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_69", HFILL }},
    { &hf_nr_rrc_ms80,
      { "ms80", "nr-rrc.ms80",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_79", HFILL }},
    { &hf_nr_rrc_ms128,
      { "ms128", "nr-rrc.ms128",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_nr_rrc_ms160,
      { "ms160", "nr-rrc.ms160",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_159", HFILL }},
    { &hf_nr_rrc_ms256,
      { "ms256", "nr-rrc.ms256",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nr_rrc_ms320,
      { "ms320", "nr-rrc.ms320",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_319", HFILL }},
    { &hf_nr_rrc_ms512,
      { "ms512", "nr-rrc.ms512",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_511", HFILL }},
    { &hf_nr_rrc_ms640,
      { "ms640", "nr-rrc.ms640",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_639", HFILL }},
    { &hf_nr_rrc_ms1024,
      { "ms1024", "nr-rrc.ms1024",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_nr_rrc_ms1280,
      { "ms1280", "nr-rrc.ms1280",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1279", HFILL }},
    { &hf_nr_rrc_ms2048,
      { "ms2048", "nr-rrc.ms2048",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_nr_rrc_ms2560,
      { "ms2560", "nr-rrc.ms2560",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2559", HFILL }},
    { &hf_nr_rrc_ms5120,
      { "ms5120", "nr-rrc.ms5120",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_5119", HFILL }},
    { &hf_nr_rrc_ms10240,
      { "ms10240", "nr-rrc.ms10240",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_10239", HFILL }},
    { &hf_nr_rrc_shortDRX,
      { "shortDRX", "nr-rrc.shortDRX_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drx_ShortCycle,
      { "drx-ShortCycle", "nr-rrc.drx_ShortCycle",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_drx_ShortCycle_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drx_ShortCycleTimer,
      { "drx-ShortCycleTimer", "nr-rrc.drx_ShortCycleTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_nr_rrc_drx_SlotOffset,
      { "drx-SlotOffset", "nr-rrc.drx_SlotOffset",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_drx_SlotOffset_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_01,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_01", HFILL }},
    { &hf_nr_rrc_phr_PeriodicTimer,
      { "phr-PeriodicTimer", "nr-rrc.phr_PeriodicTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_phr_PeriodicTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_phr_ProhibitTimer,
      { "phr-ProhibitTimer", "nr-rrc.phr_ProhibitTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_phr_ProhibitTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_phr_Tx_PowerFactorChange,
      { "phr-Tx-PowerFactorChange", "nr-rrc.phr_Tx_PowerFactorChange",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_phr_Tx_PowerFactorChange_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_multiplePHR,
      { "multiplePHR", "nr-rrc.multiplePHR",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_phr_Type2PCell,
      { "phr-Type2PCell", "nr-rrc.phr_Type2PCell",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_phr_Type2OtherCell,
      { "phr-Type2OtherCell", "nr-rrc.phr_Type2OtherCell",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_phr_ModeOtherCG,
      { "phr-ModeOtherCG", "nr-rrc.phr_ModeOtherCG",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_phr_ModeOtherCG_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tag_ToReleaseList,
      { "tag-ToReleaseList", "nr-rrc.tag_ToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tag_ToAddModList,
      { "tag-ToAddModList", "nr-rrc.tag_ToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_TAG_ToReleaseList_item,
      { "TAG-Id", "nr-rrc.TAG_Id",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_TAG_ToAddModList_item,
      { "TAG-ToAddMod", "nr-rrc.TAG_ToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tag_Id,
      { "tag-Id", "nr-rrc.tag_Id",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_timeAlignmentTimer,
      { "timeAlignmentTimer", "nr-rrc.timeAlignmentTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_TimeAlignmentTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_periodicBSR_Timer,
      { "periodicBSR-Timer", "nr-rrc.periodicBSR_Timer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_periodicBSR_Timer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_retxBSR_Timer,
      { "retxBSR-Timer", "nr-rrc.retxBSR_Timer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_retxBSR_Timer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_logicaChannelSR_DelayTimer,
      { "logicaChannelSR-DelayTimer", "nr-rrc.logicaChannelSR_DelayTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_logicaChannelSR_DelayTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measObjectToRemoveList,
      { "measObjectToRemoveList", "nr-rrc.measObjectToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measObjectToAddModList,
      { "measObjectToAddModList", "nr-rrc.measObjectToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportConfigToRemoveList,
      { "reportConfigToRemoveList", "nr-rrc.reportConfigToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportConfigToAddModList,
      { "reportConfigToAddModList", "nr-rrc.reportConfigToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measIdToRemoveList,
      { "measIdToRemoveList", "nr-rrc.measIdToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measIdToAddModList,
      { "measIdToAddModList", "nr-rrc.measIdToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_s_MeasureConfig,
      { "s-MeasureConfig", "nr-rrc.s_MeasureConfig",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_s_MeasureConfig_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssb_rsrp,
      { "ssb-rsrp", "nr-rrc.ssb_rsrp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRP_Range", HFILL }},
    { &hf_nr_rrc_csi_rsrp,
      { "csi-rsrp", "nr-rrc.csi_rsrp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRP_Range", HFILL }},
    { &hf_nr_rrc_quantityConfig,
      { "quantityConfig", "nr-rrc.quantityConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measGapConfig,
      { "measGapConfig", "nr-rrc.measGapConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_MeasObjectToRemoveList_item,
      { "MeasObjectId", "nr-rrc.MeasObjectId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_MeasIdToRemoveList_item,
      { "MeasId", "nr-rrc.MeasId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ReportConfigToRemoveList_item,
      { "ReportConfigId", "nr-rrc.ReportConfigId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_MeasIdToAddModList_item,
      { "MeasIdToAddMod", "nr-rrc.MeasIdToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measId,
      { "measId", "nr-rrc.measId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measObjectId,
      { "measObjectId", "nr-rrc.measObjectId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportConfigId_01,
      { "reportConfigId", "nr-rrc.reportConfigId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_carrierFreq,
      { "carrierFreq", "nr-rrc.carrierFreq",
        FT_INT32, BASE_DEC, NULL, 0,
        "ARFCN_ValueNR", HFILL }},
    { &hf_nr_rrc_referenceSignalConfig,
      { "referenceSignalConfig", "nr-rrc.referenceSignalConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_absThreshSS_BlocksConsolidation,
      { "absThreshSS-BlocksConsolidation", "nr-rrc.absThreshSS_BlocksConsolidation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ThresholdNR", HFILL }},
    { &hf_nr_rrc_absThreshCSI_RS_Consolidation,
      { "absThreshCSI-RS-Consolidation", "nr-rrc.absThreshCSI_RS_Consolidation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ThresholdNR", HFILL }},
    { &hf_nr_rrc_nroSS_BlocksToAverage,
      { "nroSS-BlocksToAverage", "nr-rrc.nroSS_BlocksToAverage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_maxNroSS_BlocksToAverage", HFILL }},
    { &hf_nr_rrc_nroCSI_RS_ResourcesToAverage,
      { "nroCSI-RS-ResourcesToAverage", "nr-rrc.nroCSI_RS_ResourcesToAverage",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_maxNroCSI_RS_ResourcesToAverage", HFILL }},
    { &hf_nr_rrc_quantityConfigIndex,
      { "quantityConfigIndex", "nr-rrc.quantityConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_maxQuantityConfigId", HFILL }},
    { &hf_nr_rrc_offsetFreq,
      { "offsetFreq", "nr-rrc.offsetFreq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Q_OffsetRangeList", HFILL }},
    { &hf_nr_rrc_cellsToRemoveList,
      { "cellsToRemoveList", "nr-rrc.cellsToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellIndexList", HFILL }},
    { &hf_nr_rrc_cellsToAddModList,
      { "cellsToAddModList", "nr-rrc.cellsToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_blackCellsToRemoveList,
      { "blackCellsToRemoveList", "nr-rrc.blackCellsToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellIndexList", HFILL }},
    { &hf_nr_rrc_blackCellsToAddModList,
      { "blackCellsToAddModList", "nr-rrc.blackCellsToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_whiteCellsToRemoveList,
      { "whiteCellsToRemoveList", "nr-rrc.whiteCellsToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellIndexList", HFILL }},
    { &hf_nr_rrc_whiteCellsToAddModList,
      { "whiteCellsToAddModList", "nr-rrc.whiteCellsToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssb_MeasurementTimingConfiguration,
      { "ssb-MeasurementTimingConfiguration", "nr-rrc.ssb_MeasurementTimingConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssbPresence,
      { "ssbPresence", "nr-rrc.ssbPresence",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ssbPresence_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_present,
      { "present", "nr-rrc.present_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_frequencyOffset,
      { "frequencyOffset", "nr-rrc.frequencyOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_subcarrierSpacing_01,
      { "subcarrierSpacing", "nr-rrc.subcarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SubcarrierSpacing_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_notPresent,
      { "notPresent", "nr-rrc.notPresent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_rs_ResourceConfig_Mobility,
      { "csi-rs-ResourceConfig-Mobility", "nr-rrc.csi_rs_ResourceConfig_Mobility_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_useServingCellTimingForSync,
      { "useServingCellTimingForSync", "nr-rrc.useServingCellTimingForSync",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_smtc1,
      { "smtc1", "nr-rrc.smtc1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_periodicityAndOffset,
      { "periodicityAndOffset", "nr-rrc.periodicityAndOffset",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_periodicityAndOffset_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sf5,
      { "sf5", "nr-rrc.sf5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4", HFILL }},
    { &hf_nr_rrc_sf10,
      { "sf10", "nr-rrc.sf10",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nr_rrc_sf20,
      { "sf20", "nr-rrc.sf20",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_19", HFILL }},
    { &hf_nr_rrc_sf40,
      { "sf40", "nr-rrc.sf40",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_39", HFILL }},
    { &hf_nr_rrc_sf80,
      { "sf80", "nr-rrc.sf80",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_79", HFILL }},
    { &hf_nr_rrc_sf160,
      { "sf160", "nr-rrc.sf160",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_159", HFILL }},
    { &hf_nr_rrc_duration,
      { "duration", "nr-rrc.duration",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_duration_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssb_ToMeasure,
      { "ssb-ToMeasure", "nr-rrc.ssb_ToMeasure",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ssb_ToMeasure_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_02,
      { "setup", "nr-rrc.setup",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_setup_02_vals), 0,
        "T_setup_02", HFILL }},
    { &hf_nr_rrc_shortBitmap,
      { "shortBitmap", "nr-rrc.shortBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_nr_rrc_mediumBitmap,
      { "mediumBitmap", "nr-rrc.mediumBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_nr_rrc_longBitmap,
      { "longBitmap", "nr-rrc.longBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_nr_rrc_smtc2,
      { "smtc2", "nr-rrc.smtc2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pci_List,
      { "pci-List", "nr-rrc.pci_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId", HFILL }},
    { &hf_nr_rrc_pci_List_item,
      { "PhysicalCellId", "nr-rrc.PhysicalCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_periodicty,
      { "periodicty", "nr-rrc.periodicty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_rs_MeasurementBW,
      { "csi-rs-MeasurementBW", "nr-rrc.csi_rs_MeasurementBW_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_rs_measurementBW_size,
      { "csi-rs-measurementBW-size", "nr-rrc.csi_rs_measurementBW_size",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_csi_rs_measurementBW_size_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_rs_measurement_BW_start,
      { "csi-rs-measurement-BW-start", "nr-rrc.csi_rs_measurement_BW_start",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_csi_rs_measurement_BW_start_vals), 0,
        "T_csi_rs_measurement_BW_start", HFILL }},
    { &hf_nr_rrc_associated_SSB,
      { "associated-SSB", "nr-rrc.associated_SSB",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_associated_SSB_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_qcled_SSB,
      { "qcled-SSB", "nr-rrc.qcled_SSB",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_isServingCellMO,
      { "isServingCellMO", "nr-rrc.isServingCellMO",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_csi_rs_ResourceList_Mobility,
      { "csi-rs-ResourceList-Mobility", "nr-rrc.csi_rs_ResourceList_Mobility",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility", HFILL }},
    { &hf_nr_rrc_csi_rs_ResourceList_Mobility_item,
      { "CSI-RS-Resource-Mobility", "nr-rrc.CSI_RS_Resource_Mobility_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_rs_ResourceId_RRM,
      { "csi-rs-ResourceId-RRM", "nr-rrc.csi_rs_ResourceId_RRM",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cellId,
      { "cellId", "nr-rrc.cellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PhysicalCellId", HFILL }},
    { &hf_nr_rrc_slotConfig,
      { "slotConfig", "nr-rrc.slotConfig",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_slotConfig_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ms5,
      { "ms5", "nr-rrc.ms5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4", HFILL }},
    { &hf_nr_rrc_resourceElementMappingPattern,
      { "resourceElementMappingPattern", "nr-rrc.resourceElementMappingPattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sequenceGenerationConfig,
      { "sequenceGenerationConfig", "nr-rrc.sequenceGenerationConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rsrpOffsetSSB,
      { "rsrpOffsetSSB", "nr-rrc.rsrpOffsetSSB",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_Q_OffsetRange_vals_ext, 0,
        "Q_OffsetRange", HFILL }},
    { &hf_nr_rrc_rsrqOffsetSSB,
      { "rsrqOffsetSSB", "nr-rrc.rsrqOffsetSSB",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_Q_OffsetRange_vals_ext, 0,
        "Q_OffsetRange", HFILL }},
    { &hf_nr_rrc_sinrOffsetSSB,
      { "sinrOffsetSSB", "nr-rrc.sinrOffsetSSB",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_Q_OffsetRange_vals_ext, 0,
        "Q_OffsetRange", HFILL }},
    { &hf_nr_rrc_rsrpOffsetCSI_RS,
      { "rsrpOffsetCSI-RS", "nr-rrc.rsrpOffsetCSI_RS",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_Q_OffsetRange_vals_ext, 0,
        "Q_OffsetRange", HFILL }},
    { &hf_nr_rrc_rsrqOffsetCSI_RS,
      { "rsrqOffsetCSI-RS", "nr-rrc.rsrqOffsetCSI_RS",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_Q_OffsetRange_vals_ext, 0,
        "Q_OffsetRange", HFILL }},
    { &hf_nr_rrc_sinrOffsetCSI_RS,
      { "sinrOffsetCSI-RS", "nr-rrc.sinrOffsetCSI_RS",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_Q_OffsetRange_vals_ext, 0,
        "Q_OffsetRange", HFILL }},
    { &hf_nr_rrc_threshold_RSRP,
      { "threshold-RSRP", "nr-rrc.threshold_RSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRP_Range", HFILL }},
    { &hf_nr_rrc_threshold_RSRQ,
      { "threshold-RSRQ", "nr-rrc.threshold_RSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRQ_Range", HFILL }},
    { &hf_nr_rrc_threshold_SINR,
      { "threshold-SINR", "nr-rrc.threshold_SINR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SINR_Range", HFILL }},
    { &hf_nr_rrc_CellsToAddModList_item,
      { "CellsToAddMod", "nr-rrc.CellsToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cellIndex,
      { "cellIndex", "nr-rrc.cellIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_maxNrofCellMeas", HFILL }},
    { &hf_nr_rrc_cellIndividualOffset,
      { "cellIndividualOffset", "nr-rrc.cellIndividualOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Q_OffsetRangeList", HFILL }},
    { &hf_nr_rrc_BlackCellsToAddModList_item,
      { "BlackCellsToAddMod", "nr-rrc.BlackCellsToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_physCellIdRange,
      { "physCellIdRange", "nr-rrc.physCellIdRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_WhiteCellsToAddModList_item,
      { "WhiteCellsToAddMod", "nr-rrc.WhiteCellsToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_MeasObjectToAddModList_item,
      { "MeasObjectToAddMod", "nr-rrc.MeasObjectToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measObject,
      { "measObject", "nr-rrc.measObject",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_measObject_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measObjectNR,
      { "measObjectNR", "nr-rrc.measObjectNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measObjectEUTRA,
      { "measObjectEUTRA", "nr-rrc.measObjectEUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measResultServingFreqList,
      { "measResultServingFreqList", "nr-rrc.measResultServingFreqList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasResultServFreqList", HFILL }},
    { &hf_nr_rrc_measResultNeighCells,
      { "measResultNeighCells", "nr-rrc.measResultNeighCells",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_measResultNeighCells_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measResultListNR,
      { "measResultListNR", "nr-rrc.measResultListNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measResultListEUTRA,
      { "measResultListEUTRA", "nr-rrc.measResultListEUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_MeasResultServFreqList_item,
      { "MeasResultServFreq", "nr-rrc.MeasResultServFreq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_servFreqId,
      { "servFreqId", "nr-rrc.servFreqId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServCellIndex", HFILL }},
    { &hf_nr_rrc_measResultServingCell,
      { "measResultServingCell", "nr-rrc.measResultServingCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MeasResultNR", HFILL }},
    { &hf_nr_rrc_measResultBestNeighCell,
      { "measResultBestNeighCell", "nr-rrc.measResultBestNeighCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MeasResultNR", HFILL }},
    { &hf_nr_rrc_MeasResultListNR_item,
      { "MeasResultNR", "nr-rrc.MeasResultNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cgi_Info,
      { "cgi-Info", "nr-rrc.cgi_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measResult,
      { "measResult", "nr-rrc.measResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cellResults,
      { "cellResults", "nr-rrc.cellResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_resultsSSBCell,
      { "resultsSSBCell", "nr-rrc.resultsSSBCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_resultsCSI_RSCell,
      { "resultsCSI-RSCell", "nr-rrc.resultsCSI_RSCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rsIndexResults,
      { "rsIndexResults", "nr-rrc.rsIndexResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_resultsSSBIndexes,
      { "resultsSSBIndexes", "nr-rrc.resultsSSBIndexes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResultsPerSSBIndexList", HFILL }},
    { &hf_nr_rrc_resultsCSI_RSIndexes,
      { "resultsCSI-RSIndexes", "nr-rrc.resultsCSI_RSIndexes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResultsPerCSI_RSIndexList", HFILL }},
    { &hf_nr_rrc_ssb_Cellrsrp,
      { "ssb-Cellrsrp", "nr-rrc.ssb_Cellrsrp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRP_Range", HFILL }},
    { &hf_nr_rrc_ssb_Cellrsrq,
      { "ssb-Cellrsrq", "nr-rrc.ssb_Cellrsrq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRQ_Range", HFILL }},
    { &hf_nr_rrc_ssb_Cellsinr,
      { "ssb-Cellsinr", "nr-rrc.ssb_Cellsinr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SINR_Range", HFILL }},
    { &hf_nr_rrc_csi_rs_Cellrsrp,
      { "csi-rs-Cellrsrp", "nr-rrc.csi_rs_Cellrsrp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRP_Range", HFILL }},
    { &hf_nr_rrc_csi_rs_Cellrsrq,
      { "csi-rs-Cellrsrq", "nr-rrc.csi_rs_Cellrsrq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRQ_Range", HFILL }},
    { &hf_nr_rrc_csi_rs_Cellsinr,
      { "csi-rs-Cellsinr", "nr-rrc.csi_rs_Cellsinr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SINR_Range", HFILL }},
    { &hf_nr_rrc_ResultsPerSSBIndexList_item,
      { "ResultsPerSSBIndex", "nr-rrc.ResultsPerSSBIndex_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ss_rsrp,
      { "ss-rsrp", "nr-rrc.ss_rsrp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRP_Range", HFILL }},
    { &hf_nr_rrc_ss_rsrq,
      { "ss-rsrq", "nr-rrc.ss_rsrq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRQ_Range", HFILL }},
    { &hf_nr_rrc_ss_sinr,
      { "ss-sinr", "nr-rrc.ss_sinr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SINR_Range", HFILL }},
    { &hf_nr_rrc_ResultsPerCSI_RSIndexList_item,
      { "ResultsPerCSI-RSIndex", "nr-rrc.ResultsPerCSI_RSIndex_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_rsIndex,
      { "csi-rsIndex", "nr-rrc.csi_rsIndex",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_rsrq,
      { "csi-rsrq", "nr-rrc.csi_rsrq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRQ_Range", HFILL }},
    { &hf_nr_rrc_csi_sinr,
      { "csi-sinr", "nr-rrc.csi_sinr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SINR_Range", HFILL }},
    { &hf_nr_rrc_controlResourceSetToAddModList,
      { "controlResourceSetToAddModList", "nr-rrc.controlResourceSetToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet", HFILL }},
    { &hf_nr_rrc_controlResourceSetToAddModList_item,
      { "ControlResourceSet", "nr-rrc.ControlResourceSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_controlResourceSetToReleaseList,
      { "controlResourceSetToReleaseList", "nr-rrc.controlResourceSetToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId", HFILL }},
    { &hf_nr_rrc_controlResourceSetToReleaseList_item,
      { "ControlResourceId", "nr-rrc.ControlResourceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_searchSpacesToAddModList,
      { "searchSpacesToAddModList", "nr-rrc.searchSpacesToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace", HFILL }},
    { &hf_nr_rrc_searchSpacesToAddModList_item,
      { "SearchSpace", "nr-rrc.SearchSpace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_searchSpacesToReleaseList,
      { "searchSpacesToReleaseList", "nr-rrc.searchSpacesToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId", HFILL }},
    { &hf_nr_rrc_searchSpacesToReleaseList_item,
      { "SearchSpaceId", "nr-rrc.SearchSpaceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_timing,
      { "timing", "nr-rrc.timing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dl_assignment_to_DL_data,
      { "dl-assignment-to-DL-data", "nr-rrc.dl_assignment_to_DL_data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ul_assignment_to_UL_data,
      { "ul-assignment-to-UL-data", "nr-rrc.ul_assignment_to_UL_data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dl_data_to_UL_ACK,
      { "dl-data-to-UL-ACK", "nr-rrc.dl_data_to_UL_ACK_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_controlResourceSetId,
      { "controlResourceSetId", "nr-rrc.controlResourceSetId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_frequencyDomainResources,
      { "frequencyDomainResources", "nr-rrc.frequencyDomainResources_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_startSymbol,
      { "startSymbol", "nr-rrc.startSymbol",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxCoReSetStartSymbol", HFILL }},
    { &hf_nr_rrc_duration_01,
      { "duration", "nr-rrc.duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_maxCoReSetDuration", HFILL }},
    { &hf_nr_rrc_reg_BundleSize,
      { "reg-BundleSize", "nr-rrc.reg_BundleSize",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reg_BundleSize_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cce_reg_MappingType,
      { "cce-reg-MappingType", "nr-rrc.cce_reg_MappingType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cce_reg_MappingType_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_precoderGranularity,
      { "precoderGranularity", "nr-rrc.precoderGranularity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_interleaverRows,
      { "interleaverRows", "nr-rrc.interleaverRows",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_interleaverRows_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_shiftIndex,
      { "shiftIndex", "nr-rrc.shiftIndex_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tci_StateRefId,
      { "tci-StateRefId", "nr-rrc.tci_StateRefId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdcch_DMRS_ScramblingID,
      { "pdcch-DMRS-ScramblingID", "nr-rrc.pdcch_DMRS_ScramblingID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_searchSpaceId,
      { "searchSpaceId", "nr-rrc.searchSpaceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_monitoringSlotPeriodicityAndOffset,
      { "monitoringSlotPeriodicityAndOffset", "nr-rrc.monitoringSlotPeriodicityAndOffset",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_monitoringSlotPeriodicityAndOffset_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sl1,
      { "sl1", "nr-rrc.sl1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sl2,
      { "sl2", "nr-rrc.sl2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_nr_rrc_monitoringSymbolsWithinSlot,
      { "monitoringSymbolsWithinSlot", "nr-rrc.monitoringSymbolsWithinSlot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_nr_rrc_nrofCandidates,
      { "nrofCandidates", "nr-rrc.nrofCandidates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_aggregationLevel1,
      { "aggregationLevel1", "nr-rrc.aggregationLevel1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_aggregationLevel1_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_aggregationLevel2,
      { "aggregationLevel2", "nr-rrc.aggregationLevel2",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_aggregationLevel2_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_aggregationLevel4,
      { "aggregationLevel4", "nr-rrc.aggregationLevel4",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_aggregationLevel4_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_aggregationLevel8,
      { "aggregationLevel8", "nr-rrc.aggregationLevel8",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_aggregationLevel8_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_searchSpaceType,
      { "searchSpaceType", "nr-rrc.searchSpaceType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_searchSpaceType_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_common,
      { "common", "nr-rrc.common_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sfi_PDCCH,
      { "sfi-PDCCH", "nr-rrc.sfi_PDCCH_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_preemp_DL,
      { "preemp-DL", "nr-rrc.preemp_DL",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_int_RNTI,
      { "int-RNTI", "nr-rrc.int_RNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_nr_rrc_int_TF,
      { "int-TF", "nr-rrc.int_TF",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_int_TF_vals), 0,
        "T_int_TF", HFILL }},
    { &hf_nr_rrc_monitoringPeriodicity,
      { "monitoringPeriodicity", "nr-rrc.monitoringPeriodicity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ue_Specific,
      { "ue-Specific", "nr-rrc.ue_Specific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_monitoringPeriodicity_01,
      { "monitoringPeriodicity", "nr-rrc.monitoringPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_monitoringPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sfi_CellToSFI,
      { "sfi-CellToSFI", "nr-rrc.sfi_CellToSFI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI", HFILL }},
    { &hf_nr_rrc_sfi_CellToSFI_item,
      { "CellToSFI", "nr-rrc.CellToSFI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofPDCCH_Candidates,
      { "nrofPDCCH-Candidates", "nr-rrc.nrofPDCCH_Candidates",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofPDCCH_Candidates_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_aggregationLevel,
      { "aggregationLevel", "nr-rrc.aggregationLevel",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_aggregationLevel_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sfi_RNTI,
      { "sfi-RNTI", "nr-rrc.sfi_RNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_nr_rrc_dci_PayloadLength,
      { "dci-PayloadLength", "nr-rrc.dci_PayloadLength_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_searchSpace,
      { "searchSpace", "nr-rrc.searchSpace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sfi_PositionInDCI,
      { "sfi-PositionInDCI", "nr-rrc.sfi_PositionInDCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1", HFILL }},
    { &hf_nr_rrc_slotFormatCombinations,
      { "slotFormatCombinations", "nr-rrc.slotFormatCombinations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination", HFILL }},
    { &hf_nr_rrc_slotFormatCombinations_item,
      { "SlotFormatCombination", "nr-rrc.SlotFormatCombination_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_slotFormatCombinationId,
      { "slotFormatCombinationId", "nr-rrc.slotFormatCombinationId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drb,
      { "drb", "nr-rrc.drb_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_discardTimer,
      { "discardTimer", "nr-rrc.discardTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_discardTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdcp_SN_Size_UL,
      { "pdcp-SN-Size-UL", "nr-rrc.pdcp_SN_Size_UL",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_pdcp_SN_Size_UL_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdcp_SN_Size_DL,
      { "pdcp-SN-Size-DL", "nr-rrc.pdcp_SN_Size_DL",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_pdcp_SN_Size_DL_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_headerCompression,
      { "headerCompression", "nr-rrc.headerCompression",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_headerCompression_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_notUsed,
      { "notUsed", "nr-rrc.notUsed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rohc,
      { "rohc", "nr-rrc.rohc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_maxCID,
      { "maxCID", "nr-rrc.maxCID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16383", HFILL }},
    { &hf_nr_rrc_profiles,
      { "profiles", "nr-rrc.profiles_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_profile0x0001,
      { "profile0x0001", "nr-rrc.profile0x0001",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_profile0x0002,
      { "profile0x0002", "nr-rrc.profile0x0002",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_profile0x0003,
      { "profile0x0003", "nr-rrc.profile0x0003",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_profile0x0004,
      { "profile0x0004", "nr-rrc.profile0x0004",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_profile0x0006,
      { "profile0x0006", "nr-rrc.profile0x0006",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_profile0x0101,
      { "profile0x0101", "nr-rrc.profile0x0101",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_profile0x0102,
      { "profile0x0102", "nr-rrc.profile0x0102",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_profile0x0103,
      { "profile0x0103", "nr-rrc.profile0x0103",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_profile0x0104,
      { "profile0x0104", "nr-rrc.profile0x0104",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_uplinkOnlyROHC,
      { "uplinkOnlyROHC", "nr-rrc.uplinkOnlyROHC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_profiles_01,
      { "profiles", "nr-rrc.profiles_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_profiles_01", HFILL }},
    { &hf_nr_rrc_integrityProtection,
      { "integrityProtection", "nr-rrc.integrityProtection",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_statusReportRequired,
      { "statusReportRequired", "nr-rrc.statusReportRequired",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_moreThanOneRLC,
      { "moreThanOneRLC", "nr-rrc.moreThanOneRLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_primaryPath,
      { "primaryPath", "nr-rrc.primaryPath_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cellGroup,
      { "cellGroup", "nr-rrc.cellGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellGroupId", HFILL }},
    { &hf_nr_rrc_logicalChannel,
      { "logicalChannel", "nr-rrc.logicalChannel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LogicalChannelIdentity", HFILL }},
    { &hf_nr_rrc_ul_DataSplitThreshold,
      { "ul-DataSplitThreshold", "nr-rrc.ul_DataSplitThreshold",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ul_DataSplitThreshold_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_03,
      { "setup", "nr-rrc.setup",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_setup_03_vals_ext, 0,
        "T_setup_03", HFILL }},
    { &hf_nr_rrc_ul_Duplication,
      { "ul-Duplication", "nr-rrc.ul_Duplication",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_t_Reordering,
      { "t-Reordering", "nr-rrc.t_Reordering",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_t_Reordering_vals_ext, 0,
        "T_t_Reordering", HFILL }},
    { &hf_nr_rrc_outOfOrderDelivery,
      { "outOfOrderDelivery", "nr-rrc.outOfOrderDelivery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_codeBlockGroupTransmission,
      { "codeBlockGroupTransmission", "nr-rrc.codeBlockGroupTransmission",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_maxCodeBlockGroupsPerTransportBlock,
      { "maxCodeBlockGroupsPerTransportBlock", "nr-rrc.maxCodeBlockGroupsPerTransportBlock",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_maxCodeBlockGroupsPerTransportBlock_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_codeBlockGroupFlushIndicator,
      { "codeBlockGroupFlushIndicator", "nr-rrc.codeBlockGroupFlushIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_dmrs_Type,
      { "dmrs-Type", "nr-rrc.dmrs_Type",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dmrs_Type_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dmrs_AdditionalPosition,
      { "dmrs-AdditionalPosition", "nr-rrc.dmrs_AdditionalPosition",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dmrs_AdditionalPosition_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dmrs_group1,
      { "dmrs-group1", "nr-rrc.dmrs_group1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dmrs_group2,
      { "dmrs-group2", "nr-rrc.dmrs_group2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_phaseTracking_RS,
      { "phaseTracking-RS", "nr-rrc.phaseTracking_RS",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_phaseTracking_RS_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_04,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Downlink_PTRS_Config", HFILL }},
    { &hf_nr_rrc_tci_States,
      { "tci-States", "nr-rrc.tci_States_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tci_rs_SetConfig,
      { "tci-rs-SetConfig", "nr-rrc.tci_rs_SetConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tci_PresentInDCI,
      { "tci-PresentInDCI", "nr-rrc.tci_PresentInDCI",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_tci_PresentInDCI_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_xOverhead,
      { "xOverhead", "nr-rrc.xOverhead",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_xOverhead_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdsch_symbolAllocation,
      { "pdsch-symbolAllocation", "nr-rrc.pdsch_symbolAllocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rateMatchResourcesPDSCH,
      { "rateMatchResourcesPDSCH", "nr-rrc.rateMatchResourcesPDSCH_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rateMatchPatterns,
      { "rateMatchPatterns", "nr-rrc.rateMatchPatterns",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_rateMatchPatterns_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_05,
      { "setup", "nr-rrc.setup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern", HFILL }},
    { &hf_nr_rrc_setup_item,
      { "RateMatchPattern", "nr-rrc.RateMatchPattern_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_lte_CRS_ToMatchAround,
      { "lte-CRS-ToMatchAround", "nr-rrc.lte_CRS_ToMatchAround",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_lte_CRS_ToMatchAround_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_06,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_04", HFILL }},
    { &hf_nr_rrc_nrofCRS_Ports,
      { "nrofCRS-Ports", "nr-rrc.nrofCRS_Ports",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofCRS_Ports_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_v_Shift,
      { "v-Shift", "nr-rrc.v_Shift",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_v_Shift_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rbg_Size,
      { "rbg-Size", "nr-rrc.rbg_Size",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_rbg_Size_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_mcs_Table,
      { "mcs-Table", "nr-rrc.mcs_Table",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_mcs_Table_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_maxNrofCodeWordsScheduledByDCI,
      { "maxNrofCodeWordsScheduledByDCI", "nr-rrc.maxNrofCodeWordsScheduledByDCI",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_maxNrofCodeWordsScheduledByDCI_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofHARQ_processesForPDSCH,
      { "nrofHARQ-processesForPDSCH", "nr-rrc.nrofHARQ_processesForPDSCH_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_harq_ACK_Codebook,
      { "harq-ACK-Codebook", "nr-rrc.harq_ACK_Codebook",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_harq_ACK_Codebook_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdsch_BundleSize,
      { "pdsch-BundleSize", "nr-rrc.pdsch_BundleSize_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_prbBundlingEnabled,
      { "prbBundlingEnabled", "nr-rrc.prbBundlingEnabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_frequencyDensity,
      { "frequencyDensity", "nr-rrc.frequencyDensity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_timeDensity,
      { "timeDensity", "nr-rrc.timeDensity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofPorts_01,
      { "nrofPorts", "nr-rrc.nrofPorts",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofPorts_01_vals), 0,
        "T_nrofPorts_01", HFILL }},
    { &hf_nr_rrc_epre_Ratio,
      { "epre-Ratio", "nr-rrc.epre_Ratio_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_resourceElementOffset,
      { "resourceElementOffset", "nr-rrc.resourceElementOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_resourceBlocks,
      { "resourceBlocks", "nr-rrc.resourceBlocks",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_275", HFILL }},
    { &hf_nr_rrc_symbolsInResourceBlock,
      { "symbolsInResourceBlock", "nr-rrc.symbolsInResourceBlock",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_nr_rrc_periodicityAndOffset_01,
      { "periodicityAndOffset", "nr-rrc.periodicityAndOffset",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_periodicityAndOffset_01_vals), 0,
        "T_periodicityAndOffset_01", HFILL }},
    { &hf_nr_rrc_n5,
      { "n5", "nr-rrc.n5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4", HFILL }},
    { &hf_nr_rrc_n10,
      { "n10", "nr-rrc.n10",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nr_rrc_n20,
      { "n20", "nr-rrc.n20",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_19", HFILL }},
    { &hf_nr_rrc_n40,
      { "n40", "nr-rrc.n40",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_39", HFILL }},
    { &hf_nr_rrc_resourceSets,
      { "resourceSets", "nr-rrc.resourceSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet", HFILL }},
    { &hf_nr_rrc_resourceSets_item,
      { "PUCCH-ResourceSet", "nr-rrc.PUCCH_ResourceSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_format1,
      { "format1", "nr-rrc.format1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_format1_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_07,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_05", HFILL }},
    { &hf_nr_rrc_interslotFrequencyHopping,
      { "interslotFrequencyHopping", "nr-rrc.interslotFrequencyHopping",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_interslotFrequencyHopping_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofSlots,
      { "nrofSlots", "nr-rrc.nrofSlots",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofSlots_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_format2,
      { "format2", "nr-rrc.format2",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_format2_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_08,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_06", HFILL }},
    { &hf_nr_rrc_maxCodeRate,
      { "maxCodeRate", "nr-rrc.maxCodeRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_nr_rrc_nrofPRBs,
      { "nrofPRBs", "nr-rrc.nrofPRBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_nr_rrc_simultaneousHARQ_ACK_CSI,
      { "simultaneousHARQ-ACK-CSI", "nr-rrc.simultaneousHARQ_ACK_CSI",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_simultaneousHARQ_ACK_CSI_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_format3,
      { "format3", "nr-rrc.format3",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_format3_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_09,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_07", HFILL }},
    { &hf_nr_rrc_interslotFrequencyHopping_01,
      { "interslotFrequencyHopping", "nr-rrc.interslotFrequencyHopping",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_interslotFrequencyHopping_01_vals), 0,
        "T_interslotFrequencyHopping_01", HFILL }},
    { &hf_nr_rrc_additionalDMRS,
      { "additionalDMRS", "nr-rrc.additionalDMRS",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_additionalDMRS_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofSlots_01,
      { "nrofSlots", "nr-rrc.nrofSlots",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofSlots_01_vals), 0,
        "T_nrofSlots_01", HFILL }},
    { &hf_nr_rrc_pi2PBSK,
      { "pi2PBSK", "nr-rrc.pi2PBSK",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_pi2PBSK_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_format4,
      { "format4", "nr-rrc.format4",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_format4_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_10,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_08", HFILL }},
    { &hf_nr_rrc_interslotFrequencyHopping_02,
      { "interslotFrequencyHopping", "nr-rrc.interslotFrequencyHopping",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_interslotFrequencyHopping_02_vals), 0,
        "T_interslotFrequencyHopping_02", HFILL }},
    { &hf_nr_rrc_additionalDMRS_01,
      { "additionalDMRS", "nr-rrc.additionalDMRS",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_additionalDMRS_01_vals), 0,
        "T_additionalDMRS_01", HFILL }},
    { &hf_nr_rrc_nrofSlots_02,
      { "nrofSlots", "nr-rrc.nrofSlots",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofSlots_02_vals), 0,
        "T_nrofSlots_02", HFILL }},
    { &hf_nr_rrc_pi2PBSK_01,
      { "pi2PBSK", "nr-rrc.pi2PBSK",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_pi2PBSK_01_vals), 0,
        "T_pi2PBSK_01", HFILL }},
    { &hf_nr_rrc_schedulingRequestResources,
      { "schedulingRequestResources", "nr-rrc.schedulingRequestResources",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_schedulingRequestResources_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_11,
      { "setup", "nr-rrc.setup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config", HFILL }},
    { &hf_nr_rrc_setup_item_01,
      { "SchedulingRequestResource-Config", "nr-rrc.SchedulingRequestResource_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tpc_PUCCH_RNTI,
      { "tpc-PUCCH-RNTI", "nr-rrc.tpc_PUCCH_RNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_nr_rrc_codeBlockGroupTransmission_01,
      { "codeBlockGroupTransmission", "nr-rrc.codeBlockGroupTransmission",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_codeBlockGroupTransmission_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_maxCodeBlockGroupsPerTransportBlock_01,
      { "maxCodeBlockGroupsPerTransportBlock", "nr-rrc.maxCodeBlockGroupsPerTransportBlock",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_maxCodeBlockGroupsPerTransportBlock_01_vals), 0,
        "T_maxCodeBlockGroupsPerTransportBlock_01", HFILL }},
    { &hf_nr_rrc_dmrs_Type_01,
      { "dmrs-Type", "nr-rrc.dmrs_Type",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dmrs_Type_01_vals), 0,
        "T_dmrs_Type_01", HFILL }},
    { &hf_nr_rrc_dmrs_AdditionalPosition_01,
      { "dmrs-AdditionalPosition", "nr-rrc.dmrs_AdditionalPosition",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dmrs_AdditionalPosition_01_vals), 0,
        "T_dmrs_AdditionalPosition_01", HFILL }},
    { &hf_nr_rrc_phaseTracking_RS_01,
      { "phaseTracking-RS", "nr-rrc.phaseTracking_RS",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_phaseTracking_RS_01_vals), 0,
        "T_phaseTracking_RS_01", HFILL }},
    { &hf_nr_rrc_setup_12,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Uplink_PTRS_Config", HFILL }},
    { &hf_nr_rrc_tpcAccumulation,
      { "tpcAccumulation", "nr-rrc.tpcAccumulation",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_tpcAccumulation_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tcp_PUSCH_RNTI,
      { "tcp-PUSCH-RNTI", "nr-rrc.tcp_PUSCH_RNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_nr_rrc_frequencyHopping,
      { "frequencyHopping", "nr-rrc.frequencyHopping",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_frequencyHopping_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rateMatching,
      { "rateMatching", "nr-rrc.rateMatching",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_rateMatching_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rateMatchResources,
      { "rateMatchResources", "nr-rrc.rateMatchResources_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_symbolAllocationIndexs,
      { "symbolAllocationIndexs", "nr-rrc.symbolAllocationIndexs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_mcs_Table_01,
      { "mcs-Table", "nr-rrc.mcs_Table",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_mcs_Table_01_vals), 0,
        "T_mcs_Table_01", HFILL }},
    { &hf_nr_rrc_mcs_TableTransformPrecoder,
      { "mcs-TableTransformPrecoder", "nr-rrc.mcs_TableTransformPrecoder",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_mcs_TableTransformPrecoder_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_transformPrecoder,
      { "transformPrecoder", "nr-rrc.transformPrecoder",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_transformPrecoder_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rbg_Size_01,
      { "rbg-Size", "nr-rrc.rbg_Size",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_rbg_Size_01_vals), 0,
        "T_rbg_Size_01", HFILL }},
    { &hf_nr_rrc_uci_on_PUSCH,
      { "uci-on-PUSCH", "nr-rrc.uci_on_PUSCH",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_uci_on_PUSCH_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_13,
      { "setup", "nr-rrc.setup",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_setup_09_vals), 0,
        "T_setup_09", HFILL }},
    { &hf_nr_rrc_dynamic,
      { "dynamic", "nr-rrc.dynamic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4_OF_BetaOffsets", HFILL }},
    { &hf_nr_rrc_dynamic_item,
      { "BetaOffsets", "nr-rrc.BetaOffsets_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_semiStatic,
      { "semiStatic", "nr-rrc.semiStatic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BetaOffsets", HFILL }},
    { &hf_nr_rrc_xOverhead_01,
      { "xOverhead", "nr-rrc.xOverhead",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_xOverhead_01_vals), 0,
        "T_xOverhead_01", HFILL }},
    { &hf_nr_rrc_cp_OFDM,
      { "cp-OFDM", "nr-rrc.cp_OFDM",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cp_OFDM_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_14,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_10", HFILL }},
    { &hf_nr_rrc_nrofPorts_02,
      { "nrofPorts", "nr-rrc.nrofPorts",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofPorts_02_vals), 0,
        "T_nrofPorts_02", HFILL }},
    { &hf_nr_rrc_dft_S_OFDM,
      { "dft-S-OFDM", "nr-rrc.dft_S_OFDM",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dft_S_OFDM_vals), 0,
        "T_dft_S_OFDM", HFILL }},
    { &hf_nr_rrc_setup_15,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_11", HFILL }},
    { &hf_nr_rrc_sampleDensity,
      { "sampleDensity", "nr-rrc.sampleDensity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_timeDensity_01,
      { "timeDensity", "nr-rrc.timeDensity",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_timeDensity_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sequence,
      { "sequence", "nr-rrc.sequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_betaOffsetACK_Index1,
      { "betaOffsetACK-Index1", "nr-rrc.betaOffsetACK_Index1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nr_rrc_betaOffsetACK_Index2,
      { "betaOffsetACK-Index2", "nr-rrc.betaOffsetACK_Index2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nr_rrc_betaOffsetACK_Index3,
      { "betaOffsetACK-Index3", "nr-rrc.betaOffsetACK_Index3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nr_rrc_betaOffsetCSI_part1_Index1,
      { "betaOffsetCSI-part1-Index1", "nr-rrc.betaOffsetCSI_part1_Index1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nr_rrc_betaOffsetCSI_part1_Index2,
      { "betaOffsetCSI-part1-Index2", "nr-rrc.betaOffsetCSI_part1_Index2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nr_rrc_betaOffsetCSI_part2_Index1,
      { "betaOffsetCSI-part2-Index1", "nr-rrc.betaOffsetCSI_part2_Index1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nr_rrc_betaOffsetCSI_part2_Index2,
      { "betaOffsetCSI-part2-Index2", "nr-rrc.betaOffsetCSI_part2_Index2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nr_rrc_quantityConfigRSindex,
      { "quantityConfigRSindex", "nr-rrc.quantityConfigRSindex_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "QuantityConfigRS", HFILL }},
    { &hf_nr_rrc_ssbFilterCoefficientRSRP,
      { "ssbFilterCoefficientRSRP", "nr-rrc.ssbFilterCoefficientRSRP",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_FilterCoefficient_vals), 0,
        "FilterCoefficient", HFILL }},
    { &hf_nr_rrc_ssbFilterCoefficientRSRQ,
      { "ssbFilterCoefficientRSRQ", "nr-rrc.ssbFilterCoefficientRSRQ",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_FilterCoefficient_vals), 0,
        "FilterCoefficient", HFILL }},
    { &hf_nr_rrc_ssbFilterCoefficientRS_SINR,
      { "ssbFilterCoefficientRS-SINR", "nr-rrc.ssbFilterCoefficientRS_SINR",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_FilterCoefficient_vals), 0,
        "FilterCoefficient", HFILL }},
    { &hf_nr_rrc_csi_rsFilterCoefficientRSRP,
      { "csi-rsFilterCoefficientRSRP", "nr-rrc.csi_rsFilterCoefficientRSRP",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_FilterCoefficient_vals), 0,
        "FilterCoefficient", HFILL }},
    { &hf_nr_rrc_csi_rsFilterCoefficientRSRQ,
      { "csi-rsFilterCoefficientRSRQ", "nr-rrc.csi_rsFilterCoefficientRSRQ",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_FilterCoefficient_vals), 0,
        "FilterCoefficient", HFILL }},
    { &hf_nr_rrc_csi_rsFilterCoefficientRS_SINR,
      { "csi-rsFilterCoefficientRS-SINR", "nr-rrc.csi_rsFilterCoefficientRS_SINR",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_FilterCoefficient_vals), 0,
        "FilterCoefficient", HFILL }},
    { &hf_nr_rrc_groupBconfigured,
      { "groupBconfigured", "nr-rrc.groupBconfigured_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ra_Msg3SizeGroupA,
      { "ra-Msg3SizeGroupA", "nr-rrc.ra_Msg3SizeGroupA",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ra_Msg3SizeGroupA_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_messagePowerOffsetGroupB,
      { "messagePowerOffsetGroupB", "nr-rrc.messagePowerOffsetGroupB",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_messagePowerOffsetGroupB_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cbra_SSB_ResourceList,
      { "cbra-SSB-ResourceList", "nr-rrc.cbra_SSB_ResourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ra_ContentionResolutionTimer,
      { "ra-ContentionResolutionTimer", "nr-rrc.ra_ContentionResolutionTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ra_ContentionResolutionTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssb_Threshold,
      { "ssb-Threshold", "nr-rrc.ssb_Threshold_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sul_RSRP_Threshold,
      { "sul-RSRP-Threshold", "nr-rrc.sul_RSRP_Threshold_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_prach_ConfigurationIndex,
      { "prach-ConfigurationIndex", "nr-rrc.prach_ConfigurationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nr_rrc_prach_RootSequenceIndex,
      { "prach-RootSequenceIndex", "nr-rrc.prach_RootSequenceIndex",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_prach_RootSequenceIndex_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_l839,
      { "l839", "nr-rrc.l839",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_837", HFILL }},
    { &hf_nr_rrc_l139,
      { "l139", "nr-rrc.l139",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_137", HFILL }},
    { &hf_nr_rrc_zeroCorrelationZoneConfig,
      { "zeroCorrelationZoneConfig", "nr-rrc.zeroCorrelationZoneConfig",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_nr_rrc_restrictedSetConfig,
      { "restrictedSetConfig", "nr-rrc.restrictedSetConfig",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_restrictedSetConfig_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_preambleReceivedTargetPower,
      { "preambleReceivedTargetPower", "nr-rrc.preambleReceivedTargetPower",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_preambleReceivedTargetPower_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_powerRampingStep,
      { "powerRampingStep", "nr-rrc.powerRampingStep",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_powerRampingStep_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_preambleTransMax,
      { "preambleTransMax", "nr-rrc.preambleTransMax",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_preambleTransMax_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ra_ResponseWindow,
      { "ra-ResponseWindow", "nr-rrc.ra_ResponseWindow_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_msg2_SubcarrierSpacing,
      { "msg2-SubcarrierSpacing", "nr-rrc.msg2_SubcarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SubcarrierSpacing_vals), 0,
        "SubcarrierSpacing", HFILL }},
    { &hf_nr_rrc_rach_ControlResourceSet,
      { "rach-ControlResourceSet", "nr-rrc.rach_ControlResourceSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_msg3_SubcarrierSpacing,
      { "msg3-SubcarrierSpacing", "nr-rrc.msg3_SubcarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SubcarrierSpacing_vals), 0,
        "SubcarrierSpacing", HFILL }},
    { &hf_nr_rrc_msg3_transformPrecoding,
      { "msg3-transformPrecoding", "nr-rrc.msg3_transformPrecoding",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_msg3_transformPrecoding_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_CBRA_SSB_ResourceList_item,
      { "CBRA-SSB-Resource", "nr-rrc.CBRA_SSB_Resource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssb,
      { "ssb", "nr-rrc.ssb",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SSB_ID", HFILL }},
    { &hf_nr_rrc_startIndexRA_PreambleGroupA,
      { "startIndexRA-PreambleGroupA", "nr-rrc.startIndexRA_PreambleGroupA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PreambleStartIndex", HFILL }},
    { &hf_nr_rrc_numberofRA_PreamblesGroupA,
      { "numberofRA-PreamblesGroupA", "nr-rrc.numberofRA_PreamblesGroupA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NumberOfRA_Preambles", HFILL }},
    { &hf_nr_rrc_numberOfRA_Preambles,
      { "numberOfRA-Preambles", "nr-rrc.numberOfRA_Preambles",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ra_Resources,
      { "ra-Resources", "nr-rrc.ra_Resources_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cfra_Resources,
      { "cfra-Resources", "nr-rrc.cfra_Resources",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_CFRA_Resources_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rar_SubcarrierSpacing,
      { "rar-SubcarrierSpacing", "nr-rrc.rar_SubcarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SubcarrierSpacing_vals), 0,
        "SubcarrierSpacing", HFILL }},
    { &hf_nr_rrc_cfra_ssb_ResourceList,
      { "cfra-ssb-ResourceList", "nr-rrc.cfra_ssb_ResourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource", HFILL }},
    { &hf_nr_rrc_cfra_ssb_ResourceList_item,
      { "CFRA-SSB-Resource", "nr-rrc.CFRA_SSB_Resource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cfra_csirs_ResourceList,
      { "cfra-csirs-ResourceList", "nr-rrc.cfra_csirs_ResourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource", HFILL }},
    { &hf_nr_rrc_cfra_csirs_ResourceList_item,
      { "CFRA-CSIRS-Resource", "nr-rrc.CFRA_CSIRS_Resource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ra_PreambleIndex,
      { "ra-PreambleIndex", "nr-rrc.ra_PreambleIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_0", HFILL }},
    { &hf_nr_rrc_csirs,
      { "csirs", "nr-rrc.csirs",
        FT_INT32, BASE_DEC, NULL, 0,
        "CSIRS_ID", HFILL }},
    { &hf_nr_rrc_srb_ToAddModList,
      { "srb-ToAddModList", "nr-rrc.srb_ToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srb_ToReleaseList,
      { "srb-ToReleaseList", "nr-rrc.srb_ToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_3", HFILL }},
    { &hf_nr_rrc_drb_ToAddModList,
      { "drb-ToAddModList", "nr-rrc.drb_ToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drb_ToReleaseList,
      { "drb-ToReleaseList", "nr-rrc.drb_ToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_securityConfig,
      { "securityConfig", "nr-rrc.securityConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_SRB_ToAddModList_item,
      { "SRB-ToAddMod", "nr-rrc.SRB_ToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srb_Identity,
      { "srb-Identity", "nr-rrc.srb_Identity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reestablishPDCP,
      { "reestablishPDCP", "nr-rrc.reestablishPDCP",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reestablishPDCP_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdcp_Config,
      { "pdcp-Config", "nr-rrc.pdcp_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_DRB_ToAddModList_item,
      { "DRB-ToAddMod", "nr-rrc.DRB_ToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cnAssociation,
      { "cnAssociation", "nr-rrc.cnAssociation",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_cnAssociation_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_eps_BearerIdentity,
      { "eps-BearerIdentity", "nr-rrc.eps_BearerIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_nr_rrc_sdap_Config,
      { "sdap-Config", "nr-rrc.sdap_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_drb_Identity,
      { "drb-Identity", "nr-rrc.drb_Identity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reestablishPDCP_01,
      { "reestablishPDCP", "nr-rrc.reestablishPDCP",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reestablishPDCP_01_vals), 0,
        "T_reestablishPDCP_01", HFILL }},
    { &hf_nr_rrc_recoverPDCP,
      { "recoverPDCP", "nr-rrc.recoverPDCP",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_recoverPDCP_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_DRB_ToReleaseList_item,
      { "DRB-Identity", "nr-rrc.DRB_Identity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_securityAlgorithmConfig,
      { "securityAlgorithmConfig", "nr-rrc.securityAlgorithmConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_keyToUse,
      { "keyToUse", "nr-rrc.keyToUse",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_keyToUse_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportType,
      { "reportType", "nr-rrc.reportType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reportType_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_periodical,
      { "periodical", "nr-rrc.periodical_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PeriodicalReportConfig", HFILL }},
    { &hf_nr_rrc_eventTriggered,
      { "eventTriggered", "nr-rrc.eventTriggered_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTriggerConfig", HFILL }},
    { &hf_nr_rrc_reportCGI,
      { "reportCGI", "nr-rrc.reportCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_eventId,
      { "eventId", "nr-rrc.eventId",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_eventId_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_eventA1,
      { "eventA1", "nr-rrc.eventA1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_a1_Threshold,
      { "a1-Threshold", "nr-rrc.a1_Threshold",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_MeasTriggerQuantity_vals), 0,
        "MeasTriggerQuantity", HFILL }},
    { &hf_nr_rrc_reportOnLeave,
      { "reportOnLeave", "nr-rrc.reportOnLeave",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_hysteresis,
      { "hysteresis", "nr-rrc.hysteresis",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_timeToTrigger,
      { "timeToTrigger", "nr-rrc.timeToTrigger",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_TimeToTrigger_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_eventA2,
      { "eventA2", "nr-rrc.eventA2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_a2_Threshold,
      { "a2-Threshold", "nr-rrc.a2_Threshold",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_MeasTriggerQuantity_vals), 0,
        "MeasTriggerQuantity", HFILL }},
    { &hf_nr_rrc_eventA3,
      { "eventA3", "nr-rrc.eventA3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_a3_Offset,
      { "a3-Offset", "nr-rrc.a3_Offset",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_MeasTriggerQuantityOffset_vals), 0,
        "MeasTriggerQuantityOffset", HFILL }},
    { &hf_nr_rrc_useWhiteCellList,
      { "useWhiteCellList", "nr-rrc.useWhiteCellList",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_eventA4,
      { "eventA4", "nr-rrc.eventA4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_a4_Threshold,
      { "a4-Threshold", "nr-rrc.a4_Threshold",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_MeasTriggerQuantity_vals), 0,
        "MeasTriggerQuantity", HFILL }},
    { &hf_nr_rrc_eventA5,
      { "eventA5", "nr-rrc.eventA5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_a5_Threshold1,
      { "a5-Threshold1", "nr-rrc.a5_Threshold1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_MeasTriggerQuantity_vals), 0,
        "MeasTriggerQuantity", HFILL }},
    { &hf_nr_rrc_a5_Threshold2,
      { "a5-Threshold2", "nr-rrc.a5_Threshold2",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_MeasTriggerQuantity_vals), 0,
        "MeasTriggerQuantity", HFILL }},
    { &hf_nr_rrc_eventA6,
      { "eventA6", "nr-rrc.eventA6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_a6_Offset,
      { "a6-Offset", "nr-rrc.a6_Offset",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_MeasTriggerQuantityOffset_vals), 0,
        "MeasTriggerQuantityOffset", HFILL }},
    { &hf_nr_rrc_rsType,
      { "rsType", "nr-rrc.rsType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_rsType_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportInterval,
      { "reportInterval", "nr-rrc.reportInterval",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_ReportInterval_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportAmount,
      { "reportAmount", "nr-rrc.reportAmount",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reportAmount_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportQuantityCell,
      { "reportQuantityCell", "nr-rrc.reportQuantityCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MeasReportQuantity", HFILL }},
    { &hf_nr_rrc_maxReportCells,
      { "maxReportCells", "nr-rrc.maxReportCells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_maxCellReport", HFILL }},
    { &hf_nr_rrc_reportQuantityRsIndexes,
      { "reportQuantityRsIndexes", "nr-rrc.reportQuantityRsIndexes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MeasReportQuantity", HFILL }},
    { &hf_nr_rrc_maxNroIndexesToReport,
      { "maxNroIndexesToReport", "nr-rrc.maxNroIndexesToReport",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_maxNroIndexesToReport", HFILL }},
    { &hf_nr_rrc_onlyReportBeamIds,
      { "onlyReportBeamIds", "nr-rrc.onlyReportBeamIds",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_reportAddNeighMeas,
      { "reportAddNeighMeas", "nr-rrc.reportAddNeighMeas_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rsType_01,
      { "rsType", "nr-rrc.rsType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_rsType_01_vals), 0,
        "T_rsType_01", HFILL }},
    { &hf_nr_rrc_reportAmount_01,
      { "reportAmount", "nr-rrc.reportAmount",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reportAmount_01_vals), 0,
        "T_reportAmount_01", HFILL }},
    { &hf_nr_rrc_maxNroRsIndexesToReport,
      { "maxNroRsIndexesToReport", "nr-rrc.maxNroRsIndexesToReport",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_maxNroIndexesToReport", HFILL }},
    { &hf_nr_rrc_rsrp,
      { "rsrp", "nr-rrc.rsrp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRPRange", HFILL }},
    { &hf_nr_rrc_rsrq,
      { "rsrq", "nr-rrc.rsrq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRQRange", HFILL }},
    { &hf_nr_rrc_sinr,
      { "sinr", "nr-rrc.sinr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SINRRange", HFILL }},
    { &hf_nr_rrc_rsrp_01,
      { "rsrp", "nr-rrc.rsrp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0", HFILL }},
    { &hf_nr_rrc_rsrq_01,
      { "rsrq", "nr-rrc.rsrq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0", HFILL }},
    { &hf_nr_rrc_sinr_01,
      { "sinr", "nr-rrc.sinr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0", HFILL }},
    { &hf_nr_rrc_rsrp_02,
      { "rsrp", "nr-rrc.rsrp",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_rsrq_02,
      { "rsrq", "nr-rrc.rsrq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_sinr_02,
      { "sinr", "nr-rrc.sinr",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_ReportConfigToAddModList_item,
      { "ReportConfigToAddMod", "nr-rrc.ReportConfigToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportConfig,
      { "reportConfig", "nr-rrc.reportConfig",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_reportConfig_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportConfigNR,
      { "reportConfigNR", "nr-rrc.reportConfigNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_reportConfigEUTRA,
      { "reportConfigEUTRA", "nr-rrc.reportConfigEUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_am,
      { "am", "nr-rrc.am_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ul_AM_RLC,
      { "ul-AM-RLC", "nr-rrc.ul_AM_RLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dl_AM_RLC,
      { "dl-AM-RLC", "nr-rrc.dl_AM_RLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_um_Bi_Directional,
      { "um-Bi-Directional", "nr-rrc.um_Bi_Directional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ul_UM_RLC,
      { "ul-UM-RLC", "nr-rrc.ul_UM_RLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dl_UM_RLC,
      { "dl-UM-RLC", "nr-rrc.dl_UM_RLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_um_Uni_Directional_UL,
      { "um-Uni-Directional-UL", "nr-rrc.um_Uni_Directional_UL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_um_Uni_Directional_DL,
      { "um-Uni-Directional-DL", "nr-rrc.um_Uni_Directional_DL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sn_FieldLength,
      { "sn-FieldLength", "nr-rrc.sn_FieldLength",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SN_FieldLength_AM_vals), 0,
        "SN_FieldLength_AM", HFILL }},
    { &hf_nr_rrc_t_PollRetransmit,
      { "t-PollRetransmit", "nr-rrc.t_PollRetransmit",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_PollRetransmit_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pollPDU,
      { "pollPDU", "nr-rrc.pollPDU",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_PollPDU_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pollByte,
      { "pollByte", "nr-rrc.pollByte",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_PollByte_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_maxRetxThreshold,
      { "maxRetxThreshold", "nr-rrc.maxRetxThreshold",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_maxRetxThreshold_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_t_Reassembly,
      { "t-Reassembly", "nr-rrc.t_Reassembly",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_Reassembly_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_t_StatusProhibit,
      { "t-StatusProhibit", "nr-rrc.t_StatusProhibit",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_StatusProhibit_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sn_FieldLength_01,
      { "sn-FieldLength", "nr-rrc.sn_FieldLength",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SN_FieldLength_UM_vals), 0,
        "SN_FieldLength_UM", HFILL }},
    { &hf_nr_rrc_schedulingRequestToAddModList,
      { "schedulingRequestToAddModList", "nr-rrc.schedulingRequestToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod", HFILL }},
    { &hf_nr_rrc_schedulingRequestToAddModList_item,
      { "SchedulingRequestToAddMod", "nr-rrc.SchedulingRequestToAddMod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_schedulingRequestToReleaseList,
      { "schedulingRequestToReleaseList", "nr-rrc.schedulingRequestToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId", HFILL }},
    { &hf_nr_rrc_schedulingRequestToReleaseList_item,
      { "SchedulingRequestId", "nr-rrc.SchedulingRequestId",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_schedulingRequestID,
      { "schedulingRequestID", "nr-rrc.schedulingRequestID",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sr_prohibitTimer,
      { "sr-prohibitTimer", "nr-rrc.sr_prohibitTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_sr_prohibitTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sr_TransMax,
      { "sr-TransMax", "nr-rrc.sr_TransMax",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_sr_TransMax_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pduSession,
      { "pduSession", "nr-rrc.pduSession",
        FT_INT32, BASE_DEC, NULL, 0,
        "PDUsessionID", HFILL }},
    { &hf_nr_rrc_sdap_Header_DL,
      { "sdap-Header-DL", "nr-rrc.sdap_Header_DL",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_sdap_Header_DL_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sdap_Header_UL,
      { "sdap-Header-UL", "nr-rrc.sdap_Header_UL",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_sdap_Header_UL_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_defaultDRB,
      { "defaultDRB", "nr-rrc.defaultDRB",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_reflectiveQoS,
      { "reflectiveQoS", "nr-rrc.reflectiveQoS",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_mappedQoSflows,
      { "mappedQoSflows", "nr-rrc.mappedQoSflows",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI", HFILL }},
    { &hf_nr_rrc_mappedQoSflows_item,
      { "QFI", "nr-rrc.QFI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cipheringAlgorithm,
      { "cipheringAlgorithm", "nr-rrc.cipheringAlgorithm",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_CipheringAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_integrityProtAlgorithm,
      { "integrityProtAlgorithm", "nr-rrc.integrityProtAlgorithm",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_IntegrityProtAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_frequencyInfoDL,
      { "frequencyInfoDL", "nr-rrc.frequencyInfoDL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_carrierFreqDL,
      { "carrierFreqDL", "nr-rrc.carrierFreqDL",
        FT_INT32, BASE_DEC, NULL, 0,
        "ARFCN_ValueNR", HFILL }},
    { &hf_nr_rrc_carrierBandwidthDL,
      { "carrierBandwidthDL", "nr-rrc.carrierBandwidthDL",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_CarrierBandwidthNR_vals), 0,
        "CarrierBandwidthNR", HFILL }},
    { &hf_nr_rrc_frequencyInfoUL,
      { "frequencyInfoUL", "nr-rrc.frequencyInfoUL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_supplementaryUplink,
      { "supplementaryUplink", "nr-rrc.supplementaryUplink_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_subcarrierSpacingCommon,
      { "subcarrierSpacingCommon", "nr-rrc.subcarrierSpacingCommon",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SubcarrierSpacing_vals), 0,
        "SubcarrierSpacing", HFILL }},
    { &hf_nr_rrc_ssb_subcarrier_offset,
      { "ssb-subcarrier-offset", "nr-rrc.ssb_subcarrier_offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_11", HFILL }},
    { &hf_nr_rrc_ssb_PositionsInBurst,
      { "ssb-PositionsInBurst", "nr-rrc.ssb_PositionsInBurst",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ssb_PositionsInBurst_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ssb_periodicityServingCell,
      { "ssb-periodicityServingCell", "nr-rrc.ssb_periodicityServingCell",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ssb_periodicityServingCell_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dmrs_TypeA_Position_01,
      { "dmrs-TypeA-Position", "nr-rrc.dmrs_TypeA_Position",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dmrs_TypeA_Position_01_vals), 0,
        "T_dmrs_TypeA_Position_01", HFILL }},
    { &hf_nr_rrc_subcarrierSpacingSSB,
      { "subcarrierSpacingSSB", "nr-rrc.subcarrierSpacingSSB",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_SubcarrierSpacingSSB_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tdd_UL_DL_configurationCommon,
      { "tdd-UL-DL-configurationCommon", "nr-rrc.tdd_UL_DL_configurationCommon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dl_UL_TransmissionPeriodicity,
      { "dl-UL-TransmissionPeriodicity", "nr-rrc.dl_UL_TransmissionPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dl_UL_TransmissionPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofDownlinkSlots,
      { "nrofDownlinkSlots", "nr-rrc.nrofDownlinkSlots",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_160", HFILL }},
    { &hf_nr_rrc_nrofDownlinkSymbols,
      { "nrofDownlinkSymbols", "nr-rrc.nrofDownlinkSymbols",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxSymbolIndex", HFILL }},
    { &hf_nr_rrc_nrofUplinkSlots,
      { "nrofUplinkSlots", "nr-rrc.nrofUplinkSlots",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_160", HFILL }},
    { &hf_nr_rrc_nrofUplinkSymbols,
      { "nrofUplinkSymbols", "nr-rrc.nrofUplinkSymbols",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxSymbolIndex", HFILL }},
    { &hf_nr_rrc_ss_PBCH_BlockPower,
      { "ss-PBCH-BlockPower", "nr-rrc.ss_PBCH_BlockPower",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M60_50", HFILL }},
    { &hf_nr_rrc_rach_ConfigCommon,
      { "rach-ConfigCommon", "nr-rrc.rach_ConfigCommon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tdd_UL_DL_configurationDedicated,
      { "tdd-UL-DL-configurationDedicated", "nr-rrc.tdd_UL_DL_configurationDedicated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_slotSpecificConfigurations,
      { "slotSpecificConfigurations", "nr-rrc.slotSpecificConfigurations",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_slotSpecificConfigurations_item,
      { "slotSpecificConfigurations item", "nr-rrc.slotSpecificConfigurations_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_slotIndex,
      { "slotIndex", "nr-rrc.slotIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_160", HFILL }},
    { &hf_nr_rrc_bandwidthParts,
      { "bandwidthParts", "nr-rrc.bandwidthParts_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dataScramblingIdentity,
      { "dataScramblingIdentity", "nr-rrc.dataScramblingIdentity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdcch_Config,
      { "pdcch-Config", "nr-rrc.pdcch_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdsch_Config,
      { "pdsch-Config", "nr-rrc.pdsch_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_csi_MeasConfig,
      { "csi-MeasConfig", "nr-rrc.csi_MeasConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pucch_Config,
      { "pucch-Config", "nr-rrc.pucch_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pusch_Config,
      { "pusch-Config", "nr-rrc.pusch_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srs_Config,
      { "srs-Config", "nr-rrc.srs_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sps_Config,
      { "sps-Config", "nr-rrc.sps_Config_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_crossCarrierSchedulingConfig,
      { "crossCarrierSchedulingConfig", "nr-rrc.crossCarrierSchedulingConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ue_BeamLockFunction,
      { "ue-BeamLockFunction", "nr-rrc.ue_BeamLockFunction",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_ue_BeamLockFunction_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pathlossReferenceLinking,
      { "pathlossReferenceLinking", "nr-rrc.pathlossReferenceLinking",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_pathlossReferenceLinking_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_uplink,
      { "uplink", "nr-rrc.uplink_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_periodicity,
      { "periodicity", "nr-rrc.periodicity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_powerControl,
      { "powerControl", "nr-rrc.powerControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_transformPrecoder_01,
      { "transformPrecoder", "nr-rrc.transformPrecoder",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_transformPrecoder_01_vals), 0,
        "T_transformPrecoder_01", HFILL }},
    { &hf_nr_rrc_nrofHARQ_processes,
      { "nrofHARQ-processes", "nr-rrc.nrofHARQ_processes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1", HFILL }},
    { &hf_nr_rrc_repK_RV,
      { "repK-RV", "nr-rrc.repK_RV",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_repK_RV_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_priodicity,
      { "priodicity", "nr-rrc.priodicity",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &nr_rrc_T_priodicity_vals_ext, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rrcConfiguredUplinkGrant,
      { "rrcConfiguredUplinkGrant", "nr-rrc.rrcConfiguredUplinkGrant",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_rrcConfiguredUplinkGrant_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_setup_16,
      { "setup", "nr-rrc.setup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_setup_12", HFILL }},
    { &hf_nr_rrc_timeDomainOffset,
      { "timeDomainOffset", "nr-rrc.timeDomainOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_timeDomainAllocation,
      { "timeDomainAllocation", "nr-rrc.timeDomainAllocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_frequencyDomainAllocation,
      { "frequencyDomainAllocation", "nr-rrc.frequencyDomainAllocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_dmrs,
      { "dmrs", "nr-rrc.dmrs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_mcsAndTBS,
      { "mcsAndTBS", "nr-rrc.mcsAndTBS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_repK,
      { "repK", "nr-rrc.repK_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srs_ResourceSetToReleaseList,
      { "srs-ResourceSetToReleaseList", "nr-rrc.srs_ResourceSetToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId", HFILL }},
    { &hf_nr_rrc_srs_ResourceSetToReleaseList_item,
      { "SRS-ResourceSetId", "nr-rrc.SRS_ResourceSetId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srs_ResourceSetToAddModList,
      { "srs-ResourceSetToAddModList", "nr-rrc.srs_ResourceSetToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet", HFILL }},
    { &hf_nr_rrc_srs_ResourceSetToAddModList_item,
      { "SRS-ResourceSet", "nr-rrc.SRS_ResourceSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srs_ResourceToReleaseList,
      { "srs-ResourceToReleaseList", "nr-rrc.srs_ResourceToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId", HFILL }},
    { &hf_nr_rrc_srs_ResourceToReleaseList_item,
      { "SRS-ResourceId", "nr-rrc.SRS_ResourceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srs_ResourceToAddModList,
      { "srs-ResourceToAddModList", "nr-rrc.srs_ResourceToAddModList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource", HFILL }},
    { &hf_nr_rrc_srs_ResourceToAddModList_item,
      { "SRS-Resource", "nr-rrc.SRS_Resource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_tpc_SRS_RNTI,
      { "tpc-SRS-RNTI", "nr-rrc.tpc_SRS_RNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_nr_rrc_srs_ResourceSetId,
      { "srs-ResourceSetId", "nr-rrc.srs_ResourceSetId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srs_ResourcesIds,
      { "srs-ResourcesIds", "nr-rrc.srs_ResourcesIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId", HFILL }},
    { &hf_nr_rrc_srs_ResourcesIds_item,
      { "SRS-ResourceId", "nr-rrc.SRS_ResourceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_aperiodicSRS_ResourceTrigger,
      { "aperiodicSRS-ResourceTrigger", "nr-rrc.aperiodicSRS_ResourceTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_srs_ResourceId,
      { "srs-ResourceId", "nr-rrc.srs_ResourceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nrofSRS_Ports,
      { "nrofSRS-Ports", "nr-rrc.nrofSRS_Ports",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_nrofSRS_Ports_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_transmissionComb,
      { "transmissionComb", "nr-rrc.transmissionComb",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_transmissionComb_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_freqDomainPosition,
      { "freqDomainPosition", "nr-rrc.freqDomainPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_freqHopping,
      { "freqHopping", "nr-rrc.freqHopping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_nr_rrc_groupOrSequenceHopping,
      { "groupOrSequenceHopping", "nr-rrc.groupOrSequenceHopping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2", HFILL }},
    { &hf_nr_rrc_resourceType_01,
      { "resourceType", "nr-rrc.resourceType",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_resourceType_01_vals), 0,
        "T_resourceType_01", HFILL }},
    { &hf_nr_rrc_aperiodic_02,
      { "aperiodic", "nr-rrc.aperiodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_aperiodic_01", HFILL }},
    { &hf_nr_rrc_semi_persistent,
      { "semi-persistent", "nr-rrc.semi_persistent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_periodic_02,
      { "periodic", "nr-rrc.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_periodic_01", HFILL }},
    { &hf_nr_rrc_periodicityAndOffset_02,
      { "periodicityAndOffset", "nr-rrc.periodicityAndOffset",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_periodicityAndOffset_02_vals), 0,
        "T_periodicityAndOffset_02", HFILL }},
    { &hf_nr_rrc_sequenceId,
      { "sequenceId", "nr-rrc.sequenceId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_antennaSwitching,
      { "antennaSwitching", "nr-rrc.antennaSwitching_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_carrierSwitching,
      { "carrierSwitching", "nr-rrc.carrierSwitching_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_cyclicShift,
      { "cyclicShift", "nr-rrc.cyclicShift",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_12", HFILL }},
    { &hf_nr_rrc_spatialRelationInfo,
      { "spatialRelationInfo", "nr-rrc.spatialRelationInfo",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_spatialRelationInfo_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_BandCombinationList_item,
      { "BandCombination", "nr-rrc.BandCombination_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_measParameters_MRDC,
      { "measParameters-MRDC", "nr-rrc.measParameters_MRDC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rf_Parameters_MRDC,
      { "rf-Parameters-MRDC", "nr-rrc.rf_Parameters_MRDC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_phyLayerParameters_MRDC,
      { "phyLayerParameters-MRDC", "nr-rrc.phyLayerParameters_MRDC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_supportedBandCombination,
      { "supportedBandCombination", "nr-rrc.supportedBandCombination",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BandCombinationList", HFILL }},
    { &hf_nr_rrc_supportedBasebandProcessingCombination_MRDC,
      { "supportedBasebandProcessingCombination-MRDC", "nr-rrc.supportedBasebandProcessingCombination_MRDC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BasebandProcessingCombination_MRDC", HFILL }},
    { &hf_nr_rrc_BasebandProcessingCombination_MRDC_item,
      { "LinkedBasebandProcessingCombination", "nr-rrc.LinkedBasebandProcessingCombination_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_basebandProcessingCombinationIndex,
      { "basebandProcessingCombinationIndex", "nr-rrc.basebandProcessingCombinationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_basebandProcessingCombinationLinkedIndex,
      { "basebandProcessingCombinationLinkedIndex", "nr-rrc.basebandProcessingCombinationLinkedIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex", HFILL }},
    { &hf_nr_rrc_basebandProcessingCombinationLinkedIndex_item,
      { "BasebandProcessingCombinationIndex", "nr-rrc.BasebandProcessingCombinationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_intraCarrierConcurrentMeas,
      { "intraCarrierConcurrentMeas", "nr-rrc.intraCarrierConcurrentMeas",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_intraCarrierConcurrentMeas_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_independentGapConfig,
      { "independentGapConfig", "nr-rrc.independentGapConfig",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_independentGapConfig_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sstd_MeasType1,
      { "sstd-MeasType1", "nr-rrc.sstd_MeasType1",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_sstd_MeasType1_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_pdcp_Parameters,
      { "pdcp-Parameters", "nr-rrc.pdcp_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rlc_Parameters,
      { "rlc-Parameters", "nr-rrc.rlc_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_mac_Parameters,
      { "mac-Parameters", "nr-rrc.mac_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_phyLayerParameters,
      { "phyLayerParameters", "nr-rrc.phyLayerParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_rf_Parameters,
      { "rf-Parameters", "nr-rrc.rf_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_nonCriticalExtension_02,
      { "nonCriticalExtension", "nr-rrc.nonCriticalExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_nonCriticalExtension_02", HFILL }},
    { &hf_nr_rrc_supportedBasebandProcessingCombination,
      { "supportedBasebandProcessingCombination", "nr-rrc.supportedBasebandProcessingCombination",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_supportedBandListNR,
      { "supportedBandListNR", "nr-rrc.supportedBandListNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_intraBandAsyncFDD,
      { "intraBandAsyncFDD", "nr-rrc.intraBandAsyncFDD",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_intraBandAsyncFDD_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_SupportedBandListNR_item,
      { "BandNR", "nr-rrc.BandNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_SupportedBasebandProcessingCombination_item,
      { "BasebandProcessingCombination", "nr-rrc.BasebandProcessingCombination_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_basebandParametersPerBand,
      { "basebandParametersPerBand", "nr-rrc.basebandParametersPerBand",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand", HFILL }},
    { &hf_nr_rrc_basebandParametersPerBand_item,
      { "BasebandParametersPerBand", "nr-rrc.BasebandParametersPerBand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_ca_BandwidthClassDL,
      { "ca-BandwidthClassDL", "nr-rrc.ca_BandwidthClassDL",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_CA_BandwidthClass_vals), 0,
        "CA_BandwidthClass", HFILL }},
    { &hf_nr_rrc_ca_BandwidthClassUL,
      { "ca-BandwidthClassUL", "nr-rrc.ca_BandwidthClassUL",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_CA_BandwidthClass_vals), 0,
        "CA_BandwidthClass", HFILL }},
    { &hf_nr_rrc_basebandParametersPerCC,
      { "basebandParametersPerCC", "nr-rrc.basebandParametersPerCC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC", HFILL }},
    { &hf_nr_rrc_basebandParametersPerCC_item,
      { "BasebandParametersPerCC", "nr-rrc.BasebandParametersPerCC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_supportedBWPerCC,
      { "supportedBWPerCC", "nr-rrc.supportedBWPerCC",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_CA_BandwidthClass_vals), 0,
        "BWPerCC", HFILL }},
    { &hf_nr_rrc_supportedMIMO_CapabilityDL,
      { "supportedMIMO-CapabilityDL", "nr-rrc.supportedMIMO_CapabilityDL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MIMO_Capability", HFILL }},
    { &hf_nr_rrc_supportedMIMO_CapabilityUL,
      { "supportedMIMO-CapabilityUL", "nr-rrc.supportedMIMO_CapabilityUL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MIMO_Capability", HFILL }},
    { &hf_nr_rrc_modulationOrder,
      { "modulationOrder", "nr-rrc.modulationOrder_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_subCarrierSpacing,
      { "subCarrierSpacing", "nr-rrc.subCarrierSpacing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_bandNR,
      { "bandNR", "nr-rrc.bandNR",
        FT_INT32, BASE_DEC, NULL, 0,
        "FreqBandIndicatorNR", HFILL }},
    { &hf_nr_rrc_dataRateDRB_IP,
      { "dataRateDRB-IP", "nr-rrc.dataRateDRB_IP",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_dataRateDRB_IP_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_supportedROHC_Profiles,
      { "supportedROHC-Profiles", "nr-rrc.supportedROHC_Profiles_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_profile0x0000,
      { "profile0x0000", "nr-rrc.profile0x0000",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_nr_rrc_maxNumberROHC_ContextSessions,
      { "maxNumberROHC-ContextSessions", "nr-rrc.maxNumberROHC_ContextSessions",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_maxNumberROHC_ContextSessions_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_uplinkOnlyROHC_Profiles,
      { "uplinkOnlyROHC-Profiles", "nr-rrc.uplinkOnlyROHC_Profiles",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_uplinkOnlyROHC_Profiles_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_continueROHC_Context,
      { "continueROHC-Context", "nr-rrc.continueROHC_Context",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_continueROHC_Context_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_outOfOrderDelivery_01,
      { "outOfOrderDelivery", "nr-rrc.outOfOrderDelivery",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_outOfOrderDelivery_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_shortSN,
      { "shortSN", "nr-rrc.shortSN",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_shortSN_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_volteOverNR_PDCP,
      { "volteOverNR-PDCP", "nr-rrc.volteOverNR_PDCP",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_volteOverNR_PDCP_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_amWithShortSN,
      { "amWithShortSN", "nr-rrc.amWithShortSN",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_amWithShortSN_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_umWithShortSN,
      { "umWithShortSN", "nr-rrc.umWithShortSN",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_umWithShortSN_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_umWIthLongSN,
      { "umWIthLongSN", "nr-rrc.umWIthLongSN",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_umWIthLongSN_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_lcp_Restriction,
      { "lcp-Restriction", "nr-rrc.lcp_Restriction",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_lcp_Restriction_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_skipUplinkTxDynamic_01,
      { "skipUplinkTxDynamic", "nr-rrc.skipUplinkTxDynamic",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_skipUplinkTxDynamic_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_logicalChannelSR_DelayTimer,
      { "logicalChannelSR-DelayTimer", "nr-rrc.logicalChannelSR_DelayTimer",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_logicalChannelSR_DelayTimer_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_longDRX_Cycle,
      { "longDRX-Cycle", "nr-rrc.longDRX_Cycle",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_longDRX_Cycle_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_shortDRX_Cycle,
      { "shortDRX-Cycle", "nr-rrc.shortDRX_Cycle",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_shortDRX_Cycle_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_numberOfSR_Configurations,
      { "numberOfSR-Configurations", "nr-rrc.numberOfSR_Configurations",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_numberOfSR_Configurations_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_numberOfConfiguredGrantConfigurations,
      { "numberOfConfiguredGrantConfigurations", "nr-rrc.numberOfConfiguredGrantConfigurations",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_numberOfConfiguredGrantConfigurations_vals), 0,
        NULL, HFILL }},
    { &hf_nr_rrc_start,
      { "start", "nr-rrc.start",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PhysCellId", HFILL }},
    { &hf_nr_rrc_range,
      { "range", "nr-rrc.range",
        FT_UINT32, BASE_DEC, VALS(nr_rrc_T_range_vals), 0,
        NULL, HFILL }},

/*--- End of included file: packet-nr-rrc-hfarr.c ---*/
#line 81 "./asn1/nr-rrc/packet-nr-rrc-template.c"

  };

  static gint *ett[] = {
    &ett_nr_rrc,

/*--- Included file: packet-nr-rrc-ettarr.c ---*/
#line 1 "./asn1/nr-rrc/packet-nr-rrc-ettarr.c"
    &ett_nr_rrc_SCG_ConfigInfo,
    &ett_nr_rrc_T_criticalExtensions,
    &ett_nr_rrc_T_c1,
    &ett_nr_rrc_T_criticalExtensionsFuture,
    &ett_nr_rrc_SCG_ConfigInfo_r15_IEs,
    &ett_nr_rrc_T_nonCriticalExtension,
    &ett_nr_rrc_ConfigRestrictInfoSCG,
    &ett_nr_rrc_T_restrictedBasebandCombinationNR_NR,
    &ett_nr_rrc_DRX_Info,
    &ett_nr_rrc_CandidateCellInfoList,
    &ett_nr_rrc_CandidateCellInfo,
    &ett_nr_rrc_T_cellIdentification,
    &ett_nr_rrc_T_measResultCell,
    &ett_nr_rrc_CandidateRS_IndexInfoList,
    &ett_nr_rrc_CandidateRS_IndexInfo,
    &ett_nr_rrc_T_measResultSSB,
    &ett_nr_rrc_MeasResultSSTD,
    &ett_nr_rrc_BCCH_BCH_Message,
    &ett_nr_rrc_BCCH_BCH_MessageType,
    &ett_nr_rrc_T_messageClassExtension,
    &ett_nr_rrc_DL_DCCH_Message,
    &ett_nr_rrc_DL_DCCH_MessageType,
    &ett_nr_rrc_T_c1_01,
    &ett_nr_rrc_T_messageClassExtension_01,
    &ett_nr_rrc_UL_DCCH_Message,
    &ett_nr_rrc_UL_DCCH_MessageType,
    &ett_nr_rrc_T_c1_02,
    &ett_nr_rrc_T_messageClassExtension_02,
    &ett_nr_rrc_MIB,
    &ett_nr_rrc_MeasurementReport,
    &ett_nr_rrc_T_criticalExtensions_01,
    &ett_nr_rrc_T_criticalExtensionsFuture_01,
    &ett_nr_rrc_MeasurementReport_IEs,
    &ett_nr_rrc_RRCReconfiguration,
    &ett_nr_rrc_T_criticalExtensions_02,
    &ett_nr_rrc_T_criticalExtensionsFuture_02,
    &ett_nr_rrc_RRCReconfiguration_IEs,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupConfig,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxSCellGroups_OF_CellGroupId,
    &ett_nr_rrc_T_nonCriticalExtension_01,
    &ett_nr_rrc_RRCReconfigurationComplete,
    &ett_nr_rrc_T_criticalExtensions_03,
    &ett_nr_rrc_T_criticalExtensionsFuture_03,
    &ett_nr_rrc_RRCReconfigurationComplete_IEs,
    &ett_nr_rrc_BandwidthPart,
    &ett_nr_rrc_CellGroupConfig,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LCH_Config,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxLCH_OF_LogicalChannelIdentity,
    &ett_nr_rrc_LCH_Config,
    &ett_nr_rrc_PhysicalCellGroupConfig,
    &ett_nr_rrc_SpCellConfig,
    &ett_nr_rrc_T_reconfigurationWithSync,
    &ett_nr_rrc_SCellToReleaseList,
    &ett_nr_rrc_SCellToAddModList,
    &ett_nr_rrc_SCellConfig,
    &ett_nr_rrc_CellIndexList,
    &ett_nr_rrc_CrossCarrierSchedulingConfig,
    &ett_nr_rrc_T_schedulingCellInfo,
    &ett_nr_rrc_T_own,
    &ett_nr_rrc_T_other,
    &ett_nr_rrc_CSI_MeasConfig,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceConfigurations_OF_CSI_ResourceConfig,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_Reports_OF_CSI_ReportConfig,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_MeasId_OF_CSI_MeasIdToAddMod,
    &ett_nr_rrc_T_reportTrigger,
    &ett_nr_rrc_CSI_ResourceConfig,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_ResourceSets_OF_CSI_ResourceSet,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSSB_Resources_1_OF_CSI_SSB_Resource,
    &ett_nr_rrc_T_resourceType,
    &ett_nr_rrc_CSI_ResourceSet,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesPerSet_OF_NZP_CSI_RS_Resource,
    &ett_nr_rrc_NZP_CSI_RS_Resource,
    &ett_nr_rrc_T_csi_RS_timeConfig,
    &ett_nr_rrc_CSI_SSB_Resource,
    &ett_nr_rrc_CSI_ReportConfig,
    &ett_nr_rrc_T_reportConfigType,
    &ett_nr_rrc_T_periodic,
    &ett_nr_rrc_T_reportSlotConfig,
    &ett_nr_rrc_T_semiPersistent,
    &ett_nr_rrc_T_reportSlotConfig_01,
    &ett_nr_rrc_T_aperiodic,
    &ett_nr_rrc_T_reportQuantity,
    &ett_nr_rrc_T_cRI_RI_i1_CQI,
    &ett_nr_rrc_T_reportFreqConfiguration,
    &ett_nr_rrc_T_groupBasedBeamReporting,
    &ett_nr_rrc_T_enabled,
    &ett_nr_rrc_T_disabled,
    &ett_nr_rrc_CodebookConfig,
    &ett_nr_rrc_T_codebookType,
    &ett_nr_rrc_T_type1,
    &ett_nr_rrc_T_codebookSubsetRestrictionType1,
    &ett_nr_rrc_T_ri_Restriction,
    &ett_nr_rrc_T_type2,
    &ett_nr_rrc_T_ri_Restriction_01,
    &ett_nr_rrc_CSI_MeasIdToAddMod,
    &ett_nr_rrc_FrequencyInfoUL,
    &ett_nr_rrc_LogicalChannelConfig,
    &ett_nr_rrc_T_ul_SpecificParameters,
    &ett_nr_rrc_MAC_CellGroupConfig,
    &ett_nr_rrc_DRX_Config,
    &ett_nr_rrc_T_setup,
    &ett_nr_rrc_T_drx_LongCycleStartOffset,
    &ett_nr_rrc_T_shortDRX,
    &ett_nr_rrc_PHR_Config,
    &ett_nr_rrc_T_setup_01,
    &ett_nr_rrc_TAG_Config,
    &ett_nr_rrc_TAG_ToReleaseList,
    &ett_nr_rrc_TAG_ToAddModList,
    &ett_nr_rrc_TAG_ToAddMod,
    &ett_nr_rrc_BSR_Config,
    &ett_nr_rrc_MeasConfig,
    &ett_nr_rrc_T_s_MeasureConfig,
    &ett_nr_rrc_MeasObjectToRemoveList,
    &ett_nr_rrc_MeasIdToRemoveList,
    &ett_nr_rrc_ReportConfigToRemoveList,
    &ett_nr_rrc_MeasIdToAddModList,
    &ett_nr_rrc_MeasIdToAddMod,
    &ett_nr_rrc_MeasObjectNR,
    &ett_nr_rrc_ReferenceSignalConfig,
    &ett_nr_rrc_T_ssbPresence,
    &ett_nr_rrc_T_present,
    &ett_nr_rrc_T_notPresent,
    &ett_nr_rrc_SSB_MeasurementTimingConfiguration,
    &ett_nr_rrc_T_smtc1,
    &ett_nr_rrc_T_periodicityAndOffset,
    &ett_nr_rrc_T_ssb_ToMeasure,
    &ett_nr_rrc_T_setup_02,
    &ett_nr_rrc_T_smtc2,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofPCIsPerSMTC_OF_PhysicalCellId,
    &ett_nr_rrc_CSI_RS_ResourceConfig_Mobility,
    &ett_nr_rrc_T_csi_rs_MeasurementBW,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofCSI_RS_ResourcesRRM_OF_CSI_RS_Resource_Mobility,
    &ett_nr_rrc_CSI_RS_Resource_Mobility,
    &ett_nr_rrc_T_slotConfig,
    &ett_nr_rrc_Q_OffsetRangeList,
    &ett_nr_rrc_ThresholdNR,
    &ett_nr_rrc_CellsToAddModList,
    &ett_nr_rrc_CellsToAddMod,
    &ett_nr_rrc_BlackCellsToAddModList,
    &ett_nr_rrc_BlackCellsToAddMod,
    &ett_nr_rrc_WhiteCellsToAddModList,
    &ett_nr_rrc_WhiteCellsToAddMod,
    &ett_nr_rrc_MeasObjectToAddModList,
    &ett_nr_rrc_MeasObjectToAddMod,
    &ett_nr_rrc_T_measObject,
    &ett_nr_rrc_MeasResults,
    &ett_nr_rrc_T_measResultNeighCells,
    &ett_nr_rrc_MeasResultServFreqList,
    &ett_nr_rrc_MeasResultServFreq,
    &ett_nr_rrc_MeasResultListNR,
    &ett_nr_rrc_MeasResultNR,
    &ett_nr_rrc_T_measResult,
    &ett_nr_rrc_T_cellResults,
    &ett_nr_rrc_T_rsIndexResults,
    &ett_nr_rrc_ResultsSSBCell,
    &ett_nr_rrc_ResultsCSI_RSCell,
    &ett_nr_rrc_ResultsPerSSBIndexList,
    &ett_nr_rrc_ResultsPerSSBIndex,
    &ett_nr_rrc_ResultsPerCSI_RSIndexList,
    &ett_nr_rrc_ResultsPerCSI_RSIndex,
    &ett_nr_rrc_PDCCH_Config,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceSet,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofControlResourceSets_OF_ControlResourceId,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpace,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSearchSpaces_OF_SearchSpaceId,
    &ett_nr_rrc_T_timing,
    &ett_nr_rrc_ControlResourceSet,
    &ett_nr_rrc_SearchSpace,
    &ett_nr_rrc_T_monitoringSlotPeriodicityAndOffset,
    &ett_nr_rrc_T_nrofCandidates,
    &ett_nr_rrc_T_searchSpaceType,
    &ett_nr_rrc_T_common,
    &ett_nr_rrc_T_ue_Specific,
    &ett_nr_rrc_SFI_PDCCH,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofAggregatedCellsPerCellGroup_OF_CellToSFI,
    &ett_nr_rrc_CellToSFI,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSlotFormatCombinations_OF_SlotFormatCombination,
    &ett_nr_rrc_SlotFormatCombination,
    &ett_nr_rrc_PDCP_Config,
    &ett_nr_rrc_T_drb,
    &ett_nr_rrc_T_headerCompression,
    &ett_nr_rrc_T_rohc,
    &ett_nr_rrc_T_profiles,
    &ett_nr_rrc_T_uplinkOnlyROHC,
    &ett_nr_rrc_T_profiles_01,
    &ett_nr_rrc_T_moreThanOneRLC,
    &ett_nr_rrc_T_primaryPath,
    &ett_nr_rrc_T_ul_DataSplitThreshold,
    &ett_nr_rrc_PDSCH_Config,
    &ett_nr_rrc_T_phaseTracking_RS,
    &ett_nr_rrc_T_rateMatchResourcesPDSCH,
    &ett_nr_rrc_T_rateMatchPatterns,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofRateMatchPatterns_OF_RateMatchPattern,
    &ett_nr_rrc_T_lte_CRS_ToMatchAround,
    &ett_nr_rrc_T_setup_04,
    &ett_nr_rrc_Downlink_PTRS_Config,
    &ett_nr_rrc_RateMatchPattern,
    &ett_nr_rrc_T_periodicityAndOffset_01,
    &ett_nr_rrc_PUCCH_Config,
    &ett_nr_rrc_SEQUENCE_SIZE_1_1_OF_PUCCH_ResourceSet,
    &ett_nr_rrc_T_format1,
    &ett_nr_rrc_T_setup_05,
    &ett_nr_rrc_T_format2,
    &ett_nr_rrc_T_setup_06,
    &ett_nr_rrc_T_format3,
    &ett_nr_rrc_T_setup_07,
    &ett_nr_rrc_T_format4,
    &ett_nr_rrc_T_setup_08,
    &ett_nr_rrc_T_schedulingRequestResources,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSchedulingRequestResoruces_OF_SchedulingRequestResource_Config,
    &ett_nr_rrc_PUCCH_ResourceSet,
    &ett_nr_rrc_PUSCH_Config,
    &ett_nr_rrc_T_phaseTracking_RS_01,
    &ett_nr_rrc_T_uci_on_PUSCH,
    &ett_nr_rrc_T_setup_09,
    &ett_nr_rrc_SEQUENCE_SIZE_1_4_OF_BetaOffsets,
    &ett_nr_rrc_Uplink_PTRS_Config,
    &ett_nr_rrc_T_cp_OFDM,
    &ett_nr_rrc_T_setup_10,
    &ett_nr_rrc_T_dft_S_OFDM,
    &ett_nr_rrc_T_setup_11,
    &ett_nr_rrc_BetaOffsets,
    &ett_nr_rrc_QuantityConfig,
    &ett_nr_rrc_QuantityConfigRS,
    &ett_nr_rrc_RACH_ConfigCommon,
    &ett_nr_rrc_T_groupBconfigured,
    &ett_nr_rrc_T_prach_RootSequenceIndex,
    &ett_nr_rrc_CBRA_SSB_ResourceList,
    &ett_nr_rrc_CBRA_SSB_Resource,
    &ett_nr_rrc_RACH_ConfigDedicated,
    &ett_nr_rrc_CFRA_Resources,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxRAssbResources_OF_CFRA_SSB_Resource,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxRAcsirsResources_OF_CFRA_CSIRS_Resource,
    &ett_nr_rrc_CFRA_SSB_Resource,
    &ett_nr_rrc_CFRA_CSIRS_Resource,
    &ett_nr_rrc_RadioBearerConfig,
    &ett_nr_rrc_SRB_ToAddModList,
    &ett_nr_rrc_SRB_ToAddMod,
    &ett_nr_rrc_DRB_ToAddModList,
    &ett_nr_rrc_DRB_ToAddMod,
    &ett_nr_rrc_T_cnAssociation,
    &ett_nr_rrc_DRB_ToReleaseList,
    &ett_nr_rrc_SecurityConfig,
    &ett_nr_rrc_ReportConfigNR,
    &ett_nr_rrc_T_reportType,
    &ett_nr_rrc_EventTriggerConfig,
    &ett_nr_rrc_T_eventId,
    &ett_nr_rrc_T_eventA1,
    &ett_nr_rrc_T_eventA2,
    &ett_nr_rrc_T_eventA3,
    &ett_nr_rrc_T_eventA4,
    &ett_nr_rrc_T_eventA5,
    &ett_nr_rrc_T_eventA6,
    &ett_nr_rrc_PeriodicalReportConfig,
    &ett_nr_rrc_MeasTriggerQuantity,
    &ett_nr_rrc_MeasTriggerQuantityOffset,
    &ett_nr_rrc_MeasReportQuantity,
    &ett_nr_rrc_ReportConfigToAddModList,
    &ett_nr_rrc_ReportConfigToAddMod,
    &ett_nr_rrc_T_reportConfig,
    &ett_nr_rrc_RLC_Config,
    &ett_nr_rrc_T_am,
    &ett_nr_rrc_T_um_Bi_Directional,
    &ett_nr_rrc_T_um_Uni_Directional_UL,
    &ett_nr_rrc_T_um_Uni_Directional_DL,
    &ett_nr_rrc_UL_AM_RLC,
    &ett_nr_rrc_DL_AM_RLC,
    &ett_nr_rrc_UL_UM_RLC,
    &ett_nr_rrc_DL_UM_RLC,
    &ett_nr_rrc_RLF_TimersAndConstants,
    &ett_nr_rrc_SchedulingRequestConfig,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestToAddMod,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSR_ConfigPerCellGroup_OF_SchedulingRequestId,
    &ett_nr_rrc_SchedulingRequestToAddMod,
    &ett_nr_rrc_SDAP_Config,
    &ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofQFIs_OF_QFI,
    &ett_nr_rrc_SecurityAlgorithmConfig,
    &ett_nr_rrc_ServingCellConfigCommon,
    &ett_nr_rrc_T_frequencyInfoDL,
    &ett_nr_rrc_T_supplementaryUplink,
    &ett_nr_rrc_T_ssb_PositionsInBurst,
    &ett_nr_rrc_T_tdd_UL_DL_configurationCommon,
    &ett_nr_rrc_ServingCellConfigDedicated,
    &ett_nr_rrc_T_tdd_UL_DL_configurationDedicated,
    &ett_nr_rrc_T_slotSpecificConfigurations,
    &ett_nr_rrc_T_slotSpecificConfigurations_item,
    &ett_nr_rrc_SPS_Config,
    &ett_nr_rrc_T_uplink,
    &ett_nr_rrc_T_rrcConfiguredUplinkGrant,
    &ett_nr_rrc_T_setup_12,
    &ett_nr_rrc_SRS_Config,
    &ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSetId,
    &ett_nr_rrc_SEQUENCE_SIZE_0_maxNrofSRS_ResourceSets_OF_SRS_ResourceSet,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_ResourceId,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_Resources_OF_SRS_Resource,
    &ett_nr_rrc_SRS_ResourceSet,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxNrofSRS_ResourcesPerSet_OF_SRS_ResourceId,
    &ett_nr_rrc_SRS_Resource,
    &ett_nr_rrc_T_resourceType_01,
    &ett_nr_rrc_T_aperiodic_01,
    &ett_nr_rrc_T_semi_persistent,
    &ett_nr_rrc_T_periodic_01,
    &ett_nr_rrc_T_periodicityAndOffset_02,
    &ett_nr_rrc_BandCombinationList,
    &ett_nr_rrc_BandCombination,
    &ett_nr_rrc_UE_MRDC_Capability,
    &ett_nr_rrc_RF_Parameters_MRDC,
    &ett_nr_rrc_PhyLayerParameters_MRDC,
    &ett_nr_rrc_BasebandProcessingCombination_MRDC,
    &ett_nr_rrc_LinkedBasebandProcessingCombination,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxBasebandProcComb_OF_BasebandProcessingCombinationIndex,
    &ett_nr_rrc_MeasParameters_MRDC,
    &ett_nr_rrc_UE_NR_Capability,
    &ett_nr_rrc_T_nonCriticalExtension_02,
    &ett_nr_rrc_PhyLayerParameters,
    &ett_nr_rrc_RF_Parameters,
    &ett_nr_rrc_SupportedBandListNR,
    &ett_nr_rrc_SupportedBasebandProcessingCombination,
    &ett_nr_rrc_BasebandProcessingCombination,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxSimultaneousBands_OF_BasebandParametersPerBand,
    &ett_nr_rrc_BasebandParametersPerBand,
    &ett_nr_rrc_SEQUENCE_SIZE_1_maxServCell_OF_BasebandParametersPerCC,
    &ett_nr_rrc_BasebandParametersPerCC,
    &ett_nr_rrc_BandNR,
    &ett_nr_rrc_MIMO_Capability,
    &ett_nr_rrc_ModulationOrder,
    &ett_nr_rrc_SubCarrierSpacing,
    &ett_nr_rrc_PDCP_Parameters,
    &ett_nr_rrc_T_supportedROHC_Profiles,
    &ett_nr_rrc_RLC_Parameters,
    &ett_nr_rrc_MAC_Parameters,
    &ett_nr_rrc_MeasGapConfig,
    &ett_nr_rrc_MeasObjectEUTRA,
    &ett_nr_rrc_MeasResultListEUTRA,
    &ett_nr_rrc_PhysCellIdRange,
    &ett_nr_rrc_RA_Resources,
    &ett_nr_rrc_ReportConfigEUTRA,
    &ett_nr_rrc_SchedulingRequestResource_Config,

/*--- End of included file: packet-nr-rrc-ettarr.c ---*/
#line 87 "./asn1/nr-rrc/packet-nr-rrc-template.c"
    &ett_nr_rrc_UECapabilityInformation
  };

  /* Register protocol */
  proto_nr_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_nr_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the dissectors defined in nr-rrc.cnf */

/*--- Included file: packet-nr-rrc-dis-reg.c ---*/
#line 1 "./asn1/nr-rrc/packet-nr-rrc-dis-reg.c"
  register_dissector("nr-rrc.bcch.bch", dissect_BCCH_BCH_Message_PDU, proto_nr_rrc);
  register_dissector("nr-rrc.dl.dcch", dissect_DL_DCCH_Message_PDU, proto_nr_rrc);
  register_dissector("nr-rrc.ul.dcch", dissect_nr_rrc_UL_DCCH_Message_PDU, proto_nr_rrc);


/*--- End of included file: packet-nr-rrc-dis-reg.c ---*/
#line 99 "./asn1/nr-rrc/packet-nr-rrc-template.c"
}

void
proto_reg_handoff_nr_rrc(void)
{
}
