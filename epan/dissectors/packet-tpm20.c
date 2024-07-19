/* packet-tpm20.c
 * Dissector for TPM20 protocol
 * Copyright (c) 2018, Intel Corporation
 * Tadeusz Struk <tadeusz.struk@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/tvbuff.h>
#include <epan/expert.h>
#include <epan/wmem_scopes.h>

typedef struct {
	uint32_t com_pnum;
	uint32_t resp_type;
	uint32_t command;
	uint32_t num_auths;
} tpm_entry;

static wmem_tree_t *cmd_tree;
static unsigned last_command_pnum;
static bool response_size = true;

/* sub tree items */
static int proto_tpm20;
static int proto_tpm20_header;
static int proto_tpm20_resp_header;
static int proto_tpm20_hndl_area;
static int proto_tpm20_auth_area;
static int proto_tpm20_params_area;

/* pdu fields */
static int hf_tpm20_platform_cmd;
static int hf_tpm20_platform_resp_code;
static int hf_tpm20_platform_resp_size;
static int hf_tpm20_tag;
static int hf_tpm20_size;
static int hf_tpm20_cc;
static int hf_tpm20_resp_tag;
static int hf_tpm20_resp_size;
static int hf_tpm20_resp_code;
static int hf_tpm20_startup_type;
static int hf_tpmi_rh_hierarhy;
static int hf_tpmi_rh_provision;
static int hf_tpmi_rh_platform;
static int hf_tpmi_rh_endorsment;
static int hf_tpmi_rh_nv_index;
static int hf_tpmi_rh_nv_auth;
static int hf_tpmi_rh_hierarhy_auth;
static int hf_tpmi_rh_clear;
static int hf_tpmi_rh_lockout;
static int hf_tpmi_dh_object;
static int hf_tpmi_dh_entity;
static int hf_tpmi_dh_context;
static int hf_tpmi_dh_parent;
static int hf_tpmi_dh_pcr;
static int hf_tpmi_ht_handle;
static int hf_tpmi_sh_auth_session;
static int hf_tpmi_rh_act;
static int hf_auth_area_size;
static int hf_session_nonce_size;
static int hf_session_nonce;
static int hf_session_attribs_cont;
static int hf_session_attribs_auditex;
static int hf_session_attribs_auditreset;
static int hf_session_attribs_res;
static int hf_session_attribs_decrypt;
static int hf_session_attribs_encrypt;
static int hf_session_attribs_audit;
static int hf_session_auth_size;
static int hf_session_auth;
static int hf_resp_param_size;
static int hf_encrypted_secret_size;
static int hf_encrypted_secret;
static int hf_session_type;
static int hf_alg_hash;
static int hf_alg_sym;
static int hf_alg_sym_keybits;
static int hf_alg_sym_mode;
static int hf_tpm_priv_size;
static int hf_tpm_priv;
static int hf_tpm_pub_size;
static int hf_tpm_pub;
static int hf_tpm_name_size;
static int hf_tpm_name;
static int hf_tpm_sensitive_crate_size;
static int hf_tpm_sensitive_crate;
static int hf_tpm_template_size;
static int hf_tpm_template;
static int hf_tpm_data_size;
static int hf_tpm_data;
static int hf_tpm_creation_data_size;
static int hf_tpm_creation_data;
static int hf_tpm_digest_size;
static int hf_tpm_digest;
static int hf_params;

/* sub trees */
static int ett_tpm;
static int ett_tpm_header;
static int ett_tpm_response_header;
static int ett_tpm_handles;
static int ett_tpm_auth;
static int ett_tpm_params;
static int ett_tpm_attrib;

static expert_field ei_invalid_tag;
static expert_field ei_invalid_auth_size;
static expert_field ei_invalid_num_sessions;

void proto_register_tpm20(void);
void proto_reg_handoff_tpm20(void);

static dissector_handle_t tpm20_handle;

#define TCP_TPM_PORT_PLATFORM_PORT    2321
#define TCP_TPM_PORT_COMMAND_PORT     2322
#define TCP_TPM_PORTS    "2321-2322"
#define MAX_HNDL 3
#define MAX_SESSIONS 3
#define TPM_ALG_NULL 0x0010
#define TPM_MIN_AUTH_LEN 9
#define TPM_COMMAND_HEADER_LEN 10

struct num_handles {
	uint32_t command;
	uint8_t num_req_handles;
	int *req_pd[MAX_HNDL];
	uint8_t num_resp_handles;
	int *resp_pd[MAX_HNDL];
};

static struct num_handles tpm_handles_map[] = {
	{ 0x11f, 2, { &hf_tpmi_rh_provision, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0}}, /* CC_NV_UndefineSpaceSpecial */
	{ 0x120, 2, { &hf_tpmi_rh_provision, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0}}, /* CC_EvictControl */
	{ 0x121, 1, { &hf_tpmi_rh_hierarhy, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_HierarchyControl */
	{ 0x122, 2, { &hf_tpmi_rh_provision, &hf_tpmi_rh_nv_index, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_UndefineSpace */
	{ 0x124, 1, { &hf_tpmi_rh_platform, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ChangeEPS */
	{ 0x125, 1, { &hf_tpmi_rh_platform, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ChangePPS */
	{ 0x126, 1, { &hf_tpmi_rh_clear, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Clear */
	{ 0x127, 1, { &hf_tpmi_rh_clear, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ClearControl */
	{ 0x128, 1, { &hf_tpmi_rh_provision, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ClockSet */
	{ 0x129, 1, { &hf_tpmi_rh_hierarhy_auth, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_HierarchyChangeAuth */
	{ 0x12a, 1, { &hf_tpmi_rh_provision, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_DefineSpace */
	{ 0x12b, 1, { &hf_tpmi_rh_platform, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PCR_Allocate */
	{ 0x12c, 1, { &hf_tpmi_rh_platform, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PCR_SetAuthPolicy */
	{ 0x12d, 1, { &hf_tpmi_rh_platform, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PP_Commands */
	{ 0x12e, 1, { &hf_tpmi_rh_hierarhy_auth, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_SetPrimaryPolicy */
	{ 0x12f, 2, { &hf_tpmi_rh_platform, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_FieldUpgradeStart */
	{ 0x130, 1, { &hf_tpmi_rh_platform, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ClockRateAdjust */
	{ 0x131, 1, { &hf_tpmi_rh_hierarhy, 0, 0 }, 1, { &hf_tpmi_ht_handle, 0, 0 }}, /* CC_CreatePrimary */
	{ 0x132, 1, { &hf_tpmi_rh_provision, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_GlobalWriteLock */
	{ 0x133, 2, { &hf_tpmi_rh_endorsment, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_GetCommandAuditDigest */
	{ 0x134, 2, { &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_Increment */
	{ 0x135, 2, { &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_SetBits */
	{ 0x136, 2, { &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_Extend */
	{ 0x137, 2, { &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_Write */
	{ 0x138, 2, { &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_WriteLock */
	{ 0x139, 1, { &hf_tpmi_rh_lockout, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_DictionaryAttackLockReset */
	{ 0x13a, 1, { &hf_tpmi_rh_lockout, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_DictionaryAttackParameters */
	{ 0x13b, 1, { &hf_tpmi_rh_nv_index, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_ChangeAuth */
	{ 0x13c, 1, { &hf_tpmi_dh_pcr, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PCR_Event */
	{ 0x13d, 1, { &hf_tpmi_dh_pcr, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PCR_Reset */
	{ 0x13e, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_SequenceComplete */
	{ 0x13f, 1, { &hf_tpmi_rh_platform, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_SetAlgorithmSet */
	{ 0x140, 1, { &hf_tpmi_rh_provision, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_SetCommandCodeAuditStatus */
	{ 0x141, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_FieldUpgradeData */
	{ 0x142, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_IncrementalSelfTest */
	{ 0x143, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_SelfTest */
	{ 0x144, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Startup */
	{ 0x145, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Shutdown */
	{ 0x146, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_StirRandom */
	{ 0x147, 2, { &hf_tpmi_dh_object, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_ActivateCredential */
	{ 0x148, 2, { &hf_tpmi_dh_object, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_Certify */
	{ 0x149, 3, { &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index, &hf_tpmi_sh_auth_session}, 0, { 0, 0, 0 }}, /* CC_PolicyNV */
	{ 0x14a, 2, { &hf_tpmi_dh_object, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_CertifyCreation */
	{ 0x14b, 2, { &hf_tpmi_dh_object, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_Duplicate */
	{ 0x14c, 2, { &hf_tpmi_rh_endorsment, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_GetTime */
	{ 0x14d, 3, { &hf_tpmi_rh_endorsment, &hf_tpmi_dh_object, &hf_tpmi_sh_auth_session }, 0, { 0, 0, 0 }}, /* CC_GetSessionAuditDigest */
	{ 0x14e, 1, { &hf_tpmi_rh_nv_index, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_Read */
	{ 0x14f, 2, { &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_ReadLock */
	{ 0x150, 2, { &hf_tpmi_dh_object, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_ObjectChangeAuth */
	{ 0x151, 2, { &hf_tpmi_dh_entity, &hf_tpmi_sh_auth_session, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicySecret */
	{ 0x152, 2, { &hf_tpmi_dh_object, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_Rewrap */
	{ 0x153, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Create */
	{ 0x154, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ECDH_ZGen */
	{ 0x155, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_HMAC */
	{ 0x156, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Import */
	{ 0x157, 1, { &hf_tpmi_dh_object, 0, 0 }, 1, { &hf_tpmi_ht_handle, 0, 0 }}, /* CC_Load */
	{ 0x158, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Quote */
	{ 0x159, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_RSA_Decrypt */
	{ 0x15b, 1, { &hf_tpmi_dh_object, 0, 0 }, 1, { &hf_tpmi_dh_object, 0, 0 }}, /* CC_HMAC_Start */
	{ 0x15c, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_SequenceUpdate */
	{ 0x15d, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Sign */
	{ 0x15e, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Unseal */
	{ 0x160, 2, { &hf_tpmi_dh_object, &hf_tpmi_sh_auth_session, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicySigned */
	{ 0x161, 0, { 0, 0, 0 }, 1, { &hf_tpmi_dh_context, 0, 0 }}, /* CC_ContextLoad */
	{ 0x162, 1, { &hf_tpmi_dh_context, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ContextSave */
	{ 0x163, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ECDH_KeyGen */
	{ 0x164, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_EncryptDecrypt */
	{ 0x165, 1, { &hf_tpmi_dh_context, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_FlushContext */
	{ 0x167, 0, { 0, 0, 0 }, 1, { &hf_tpmi_dh_object, 0, 0 }}, /* CC_LoadExternal */
	{ 0x168, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_MakeCredential */
	{ 0x169, 1, { &hf_tpmi_rh_nv_index, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_NV_ReadPublic */
	{ 0x16a, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyAuthorize */
	{ 0x16b, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyAuthValue */
	{ 0x16c, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyCommandCode */
	{ 0x16d, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyCounterTimer" */
	{ 0x16e, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyCpHash */
	{ 0x16f, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyLocality */
	{ 0x170, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyNameHash */
	{ 0x171, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyOR */
	{ 0x172, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyTicket */
	{ 0x173, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ReadPublic */
	{ 0x174, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_RSA_Encrypt */
	{ 0x176, 2, { &hf_tpmi_dh_object, &hf_tpmi_dh_entity, 0 }, 1, { &hf_tpmi_sh_auth_session, 0, 0 }}, /* CC_StartAuthSession */
	{ 0x177, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_VerifySignature */
	{ 0x178, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ECC_Parameters */
	{ 0x179, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_FirmwareRead */
	{ 0x17a, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_GetCapability */
	{ 0x17b, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_GetRandom */
	{ 0x17c, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_GetTestResult */
	{ 0x17d, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Hash */
	{ 0x17e, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PCR_Read */
	{ 0x17f, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyPCR */
	{ 0x180, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyRestart */
	{ 0x181, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ReadClock */
	{ 0x182, 1, { &hf_tpmi_dh_pcr, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PCR_Extend */
	{ 0x183, 1, { &hf_tpmi_dh_pcr, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PCR_SetAuthValue */
	{ 0x184, 3, { &hf_tpmi_dh_object, &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index }, 0, { 0, 0, 0 }}, /* CC_NV_Certify */
	{ 0x185, 2, { &hf_tpmi_dh_pcr, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_EventSequenceComplete */
	{ 0x186, 0, { 0, 0, 0 }, 1, { &hf_tpmi_dh_object, 0, 0 }}, /* CC_HashSequenceStart */
	{ 0x187, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyPhysicalPresence */
	{ 0x188, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyDuplicationSelect */
	{ 0x189, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyGetDigest */
	{ 0x18a, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_TestParms */
	{ 0x18b, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Commit */
	{ 0x18c, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyPassword */
	{ 0x18d, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_ZGen_2Phase */
	{ 0x18e, 0, { 0, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_EC_Ephemeral */
	{ 0x18f, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyNvWritten */
	{ 0x190, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_PolicyTemplate */
	{ 0x191, 1, { &hf_tpmi_rh_hierarhy, 0, 0 }, 1, { &hf_tpmi_dh_parent, 0, 0 }}, /* CC_CreateLoaded */
	{ 0x192, 3, { &hf_tpmi_rh_nv_auth, &hf_tpmi_rh_nv_index, &hf_tpmi_sh_auth_session }, 0, { 0, 0, 0 }}, /* CC_PolicyAuthorizeNV */
	{ 0x193, 1, { &hf_tpmi_dh_object, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_EncryptDecrypt2 */
	{ 0x194, 1, { &hf_tpmi_ht_handle, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_AC_GetCapability */
	{ 0x195, 3, { &hf_tpmi_dh_object, &hf_tpmi_rh_nv_auth, &hf_tpmi_ht_handle }, 0, { 0, 0, 0 }}, /* CC_AC_Send */
	{ 0x196, 1, { &hf_tpmi_sh_auth_session, 0, 0 }, 0, { 0, 0, 0 }}, /* CC_Policy_AC_SendSelect */
	{ 0x197, 2, { &hf_tpmi_dh_object, &hf_tpmi_dh_object, 0 }, 0, { 0, 0, 0 }}, /* CC_CertifyX509 */
	{ 0x198, 1, { &hf_tpmi_rh_act, 0, 0 }, 0, { 0, 0, 0 }}, /* TPM_CC_ACT_SetTimeout */
};

static void get_num_hndl(struct num_handles *map)
{
	uint8_t i, y;

	for (i = 0; i < array_length(tpm_handles_map); i++) {
		if (map->command == tpm_handles_map[i].command) {
			map->num_req_handles = tpm_handles_map[i].num_req_handles;
			map->num_resp_handles = tpm_handles_map[i].num_resp_handles;
			for (y = 0; y < map->num_req_handles; y++)
				map->req_pd[y] = tpm_handles_map[i].req_pd[y];
			for (y = 0; y < map->num_resp_handles; y++)
				map->resp_pd[y] = tpm_handles_map[i].resp_pd[y];
		}
	}
}

static const value_string handles[] = {
	{ 0x40000000, "TPM2_RH_SRK" },
	{ 0x40000001, "TPM2_RH_OWNER" },
	{ 0x40000002, "TPM2_RH_REVOKE" },
	{ 0x40000003, "TPM2_RH_TRANSPORT" },
	{ 0x40000004, "TPM2_RH_OPERATOR" },
	{ 0x40000005, "TPM2_RH_ADMIN" },
	{ 0x40000006, "TPM2_RH_EK" },
	{ 0x40000007, "TPM2_RH_NULL" },
	{ 0x40000008, "TPM2_RH_UNASSIGNED" },
	{ 0x40000009, "TPM2_RS_PW" },
	{ 0x4000000A, "TPM2_RH_LOCKOUT" },
	{ 0x4000000B, "TPM2_RH_ENDORSEMENT" },
	{ 0x4000000C, "TPM2_RH_PLATFORM" },
	{ 0x4000000D, "TPM2_RH_PLATFORM_NV" },
	{ 0x40000010, "TPM2_RH_AUTH_00" },
	{ 0x4000010F, "TPM2_RH_AUTH_FF" },
	{ 0x40000110, "TPM_RH_ACT_0" },
	{ 0x40000111, "TPM_RH_ACT_1" },
	{ 0x40000112, "TPM_RH_ACT_2" },
	{ 0x40000113, "TPM_RH_ACT_3" },
	{ 0x40000114, "TPM_RH_ACT_4" },
	{ 0x40000115, "TPM_RH_ACT_5" },
	{ 0x40000116, "TPM_RH_ACT_6" },
	{ 0x40000117, "TPM_RH_ACT_7" },
	{ 0x40000118, "TPM_RH_ACT_8" },
	{ 0x40000119, "TPM_RH_ACT_9" },
	{ 0x4000011A, "TPM_RH_ACT_10" },
	{ 0x4000011B, "TPM_RH_ACT_11" },
	{ 0x4000011C, "TPM_RH_ACT_12" },
	{ 0x4000011D, "TPM_RH_ACT_13" },
	{ 0x4000011E, "TPM_RH_ACT_14" },
	{ 0x4000011F, "TPM_RH_ACT_15" },
	{ 0, NULL }
};

static const value_string startup_types[] = {
	{ 0x0000, "TPM_SU_CLEAR" },
	{ 0x0001, "TPM_SU_STATE" },
	{ 0, NULL }
};

static const value_string platform_commands[] = {
	{ 0x01, "TPM_POWER_ON" },
	{ 0x02, "TPM_POWER_OFF" },
	{ 0x08, "TPM_SEND_COMMAND" },
	{ 0x09, "TPM_CANCEL_ON" },
	{ 0x0a, "TPM_CANCEL_OFF" },
	{ 0x0b, "TPM_NV_ON" },
	{ 0x14, "TPM_SESSION_END" },
	{ 0, NULL }
};

static const value_string tags[] = {
	{ 0x8001, "Command with no authorization Sessions" },
	{ 0x8002, "Command with authorization Sessions" },
	{ 0, NULL }
};

static const value_string hierarhies[] = {
	{ 0x40000001, "TPM2_RH_OWNER" },
	{ 0x40000007, "TPM2_RH_NULL" },
	{ 0x4000000B, "TPM2_RH_ENDORSEMENT" },
	{ 0x4000000C, "TPM2_RH_PLATFORM" },
	{ 0, NULL }
};

static const value_string algs[] = {
	{ 0x0001, "TPM2_ALG_RSA" },
	{ 0x0004, "TPM2_ALG_SHA" },
	{ 0x0005, "TPM2_ALG_HMAC" },
	{ 0x0006, "TPM2_ALG_AES" },
	{ 0x0007, "TPM2_ALG_MGF1" },
	{ 0x0008, "TPM2_ALG_KEYEDHASH" },
	{ 0x000A, "TPM2_ALG_XOR" },
	{ 0x000B, "TPM2_ALG_SHA256" },
	{ 0x000C, "TPM2_ALG_SHA384" },
	{ 0x000D, "TPM2_ALG_SHA512" },
	{ 0x0010, "TPM2_ALG_NULL" },
	{ 0x0012, "TPM2_ALG_SM3_256" },
	{ 0x0013, "TPM2_ALG_SM4" },
	{ 0x0014, "TPM2_ALG_RSASSA" },
	{ 0x0015, "TPM2_ALG_RSAES" },
	{ 0x0016, "TPM2_ALG_RSAPSS" },
	{ 0x0017, "TPM2_ALG_OAEP" },
	{ 0x0018, "TPM2_ALG_ECDSA" },
	{ 0x0019, "TPM2_ALG_ECDH" },
	{ 0x001A, "TPM2_ALG_ECDAA" },
	{ 0x001B, "TPM2_ALG_SM2" },
	{ 0x001C, "TPM2_ALG_ECSCHNORR" },
	{ 0x001D, "TPM2_ALG_ECMQV" },
	{ 0x0020, "TPM2_ALG_KDF1_SP800_56A" },
	{ 0x0021, "TPM2_ALG_KDF2" },
	{ 0x0022, "TPM2_ALG_KDF1_SP800_108" },
	{ 0x0023, "TPM2_ALG_ECC" },
	{ 0x0025, "TPM2_ALG_SYMCIPHER" },
	{ 0x0026, "TPM2_ALG_CAMELLIA" },
	{ 0x0040, "TPM2_ALG_CTR" },
	{ 0x0027, "TPM2_ALG_SHA3_256" },
	{ 0x0028, "TPM2_ALG_SHA3_384" },
	{ 0x0029, "TPM2_ALG_SHA3_512" },
	{ 0x0041, "TPM2_ALG_OFB" },
	{ 0x0042, "TPM2_ALG_CBC" },
	{ 0x0043, "TPM2_ALG_CFB" },
	{ 0x0044, "TPM2_ALG_ECB" },
	{ 0, NULL }
};

static const value_string commands[] = {
	{ 0x11f, "TPM2_CC_NV_UndefineSpaceSpecial" },
	{ 0x120, "TPM2_CC_EvictControl" },
	{ 0x121, "TPM2_CC_HierarchyControl" },
	{ 0x122, "TPM2_CC_NV_UndefineSpace" },
	{ 0x124, "TPM2_CC_ChangeEPS" },
	{ 0x125, "TPM2_CC_ChangePPS" },
	{ 0x126, "TPM2_CC_Clear" },
	{ 0x127, "TPM2_CC_ClearControl" },
	{ 0x128, "TPM2_CC_ClockSet" },
	{ 0x129, "TPM2_CC_HierarchyChangeAuth" },
	{ 0x12a, "TPM2_CC_NV_DefineSpace" },
	{ 0x12b, "TPM2_CC_PCR_Allocate" },
	{ 0x12c, "TPM2_CC_PCR_SetAuthPolicy" },
	{ 0x12d, "TPM2_CC_PP_Commands" },
	{ 0x12e, "TPM2_CC_SetPrimaryPolicy" },
	{ 0x12f, "TPM2_CC_FieldUpgradeStart" },
	{ 0x130, "TPM2_CC_ClockRateAdjust" },
	{ 0x131, "TPM2_CC_CreatePrimary" },
	{ 0x132, "TPM2_CC_NV_GlobalWriteLock" },
	{ 0x133, "TPM2_CC_GetCommandAuditDigest" },
	{ 0x134, "TPM2_CC_NV_Increment" },
	{ 0x135, "TPM2_CC_NV_SetBits" },
	{ 0x136, "TPM2_CC_NV_Extend" },
	{ 0x137, "TPM2_CC_NV_Write" },
	{ 0x138, "TPM2_CC_NV_WriteLock" },
	{ 0x139, "TPM2_CC_DictionaryAttackLockReset" },
	{ 0x13a, "TPM2_CC_DictionaryAttackParameters" },
	{ 0x13b, "TPM2_CC_NV_ChangeAuth" },
	{ 0x13c, "TPM2_CC_PCR_Event" },
	{ 0x13d, "TPM2_CC_PCR_Reset" },
	{ 0x13e, "TPM2_CC_SequenceComplete" },
	{ 0x13f, "TPM2_CC_SetAlgorithmSet" },
	{ 0x140, "TPM2_CC_SetCommandCodeAuditStatus" },
	{ 0x141, "TPM2_CC_FieldUpgradeData" },
	{ 0x142, "TPM2_CC_IncrementalSelfTest" },
	{ 0x143, "TPM2_CC_SelfTest" },
	{ 0x144, "TPM2_CC_Startup" },
	{ 0x145, "TPM2_CC_Shutdown" },
	{ 0x146, "TPM2_CC_StirRandom" },
	{ 0x147, "TPM2_CC_ActivateCredential" },
	{ 0x148, "TPM2_CC_Certify" },
	{ 0x149, "TPM2_CC_PolicyNV" },
	{ 0x14a, "TPM2_CC_CertifyCreation" },
	{ 0x14b, "TPM2_CC_Duplicate" },
	{ 0x14c, "TPM2_CC_GetTime" },
	{ 0x14d, "TPM2_CC_GetSessionAuditDigest" },
	{ 0x14e, "TPM2_CC_NV_Read" },
	{ 0x14f, "TPM2_CC_NV_ReadLock" },
	{ 0x150, "TPM2_CC_ObjectChangeAuth" },
	{ 0x151, "TPM2_CC_PolicySecret" },
	{ 0x152, "TPM2_CC_Rewrap" },
	{ 0x153, "TPM2_CC_Create" },
	{ 0x154, "TPM2_CC_ECDH_ZGen" },
	{ 0x155, "TPM2_CC_HMAC" },
	{ 0x156, "TPM2_CC_Import" },
	{ 0x157, "TPM2_CC_Load" },
	{ 0x158, "TPM2_CC_Quote" },
	{ 0x159, "TPM2_CC_RSA_Decrypt" },
	{ 0x15b, "TPM2_CC_HMAC_Start" },
	{ 0x15c, "TPM2_CC_SequenceUpdate" },
	{ 0x15d, "TPM2_CC_Sign" },
	{ 0x15e, "TPM2_CC_Unseal" },
	{ 0x160, "TPM2_CC_PolicySigned" },
	{ 0x161, "TPM2_CC_ContextLoad" },
	{ 0x162, "TPM2_CC_ContextSave" },
	{ 0x163, "TPM2_CC_ECDH_KeyGen" },
	{ 0x164, "TPM2_CC_EncryptDecrypt" },
	{ 0x165, "TPM2_CC_FlushContext" },
	{ 0x167, "TPM2_CC_LoadExternal" },
	{ 0x168, "TPM2_CC_MakeCredential" },
	{ 0x169, "TPM2_CC_NV_ReadPublic" },
	{ 0x16a, "TPM2_CC_PolicyAuthorize" },
	{ 0x16b, "TPM2_CC_PolicyAuthValue" },
	{ 0x16c, "TPM2_CC_PolicyCommandCode" },
	{ 0x16d, "TPM2_CC_PolicyCounterTimer" },
	{ 0x16e, "TPM2_CC_PolicyCpHash" },
	{ 0x16f, "TPM2_CC_PolicyLocality" },
	{ 0x170, "TPM2_CC_PolicyNameHash" },
	{ 0x171, "TPM2_CC_PolicyOR" },
	{ 0x172, "TPM2_CC_PolicyTicket" },
	{ 0x173, "TPM2_CC_ReadPublic" },
	{ 0x174, "TPM2_CC_RSA_Encrypt" },
	{ 0x176, "TPM2_CC_StartAuthSession" },
	{ 0x177, "TPM2_CC_VerifySignature" },
	{ 0x178, "TPM2_CC_ECC_Parameters" },
	{ 0x179, "TPM2_CC_FirmwareRead" },
	{ 0x17a, "TPM2_CC_GetCapability" },
	{ 0x17b, "TPM2_CC_GetRandom" },
	{ 0x17c, "TPM2_CC_GetTestResult" },
	{ 0x17d, "TPM2_CC_Hash" },
	{ 0x17e, "TPM2_CC_PCR_Read" },
	{ 0x17f, "TPM2_CC_PolicyPCR" },
	{ 0x180, "TPM2_CC_PolicyRestart" },
	{ 0x181, "TPM2_CC_ReadClock" },
	{ 0x182, "TPM2_CC_PCR_Extend" },
	{ 0x183, "TPM2_CC_PCR_SetAuthValue" },
	{ 0x184, "TPM2_CC_NV_Certify" },
	{ 0x185, "TPM2_CC_EventSequenceComplete" },
	{ 0x186, "TPM2_CC_HashSequenceStart" },
	{ 0x187, "TPM2_CC_PolicyPhysicalPresence" },
	{ 0x188, "TPM2_CC_PolicyDuplicationSelect" },
	{ 0x189, "TPM2_CC_PolicyGetDigest" },
	{ 0x18a, "TPM2_CC_TestParms" },
	{ 0x18b, "TPM2_CC_Commit" },
	{ 0x18c, "TPM2_CC_PolicyPassword" },
	{ 0x18d, "TPM2_CC_ZGen_2Phase" },
	{ 0x18e, "TPM2_CC_EC_Ephemeral" },
	{ 0x18f, "TPM2_CC_PolicyNvWritten" },
	{ 0x190, "TPM2_CC_PolicyTemplate" },
	{ 0x191, "TPM2_CC_CreateLoaded" },
	{ 0x192, "TPM2_CC_PolicyAuthorizeNV" },
	{ 0x193, "TPM2_CC_EncryptDecrypt2" },
	{ 0x194, "TPM2_CC_AC_GetCapability" },
	{ 0x195, "TPM2_CC_AC_Send" },
	{ 0x196, "TPM2_CC_Policy_AC_SendSelect" },
	{ 0x197, "TPM2_CC_CertifyX509" },
	{ 0x198, "TPM2_CC_ACT_SetTimeout" },
	{ 0, NULL }
};

static const value_string session_type [] = {
	{ 0x00, "TPM2_SE_HMAC" },
	{ 0x01, "TPM2_SE_POLICY" },
	{ 0x03, "TPM2_SE_TRIAL" },
	{ 0, NULL }
};

static const value_string responses [] = {
	{ 0x00, "TPM2 Success" },
	{ 0x100, "TPM2_RC_INITIALIZE, TPM not initialized by TPM2_Startup or already initialized" },
	{ 0x101, "TPM2_RC_FAILURE, Commands not being accepted because of a TPM failure" },
	{ 0x103, "TPM2_RC_SEQUENCE, Improper use of a sequence handle" },
	{ 0x10B, "TPM2_RC_PRIVATE" },
	{ 0x119, "TPM2_RC_HMAC" },
	{ 0x120, "TPM2_RC_DISABLED, The command is disabled" },
	{ 0x121, "TPM2_RC_EXCLUSIVE, Command failed because audit sequence required exclusivity" },
	{ 0x124, "TPM2_RC_AUTH_TYPE, Authorization handle is not correct for command" },
	{ 0x125, "TPM2_RC_AUTH_MISSING, Command requires an authorization session for handle and it is not present" },
	{ 0x126, "TPM2_RC_POLICY, Policy failure in math operation or an invalid authPolicy value" },
	{ 0x127, "TPM2_RC_PCR, PCR check fail" },
	{ 0x128, "TPM2_RC_PCR_CHANGED, PCR have changed since checked" },
	{ 0x12D, "TPM2_RC_UPGRADE, TPM is in field upgrade mode" },
	{ 0x12E, "TPM2_RC_TOO_MANY_CONTEXTS, Context ID counter is at maximum" },
	{ 0x12F, "TPM2_RC_AUTH_UNAVAILABLE, AuthValue or authPolicy is not available for selected entity" },
	{ 0x130, "TPM2_RC_REBOOT, _TPM_Init and StartupCLEAR is required before the TPM can resume operation" },
	{ 0x131, "TPM2_RC_UNBALANCED, The digest size of must be larger than the symmetric key size" },
	{ 0x142, "TPM2_RC_COMMAND_SIZE, Command Size value is inconsistent with contents of the command buffer" },
	{ 0x143, "TPM2_RC_COMMAND_CODE, Command code not supported" },
	{ 0x144, "TPM2_RC_AUTHSIZE, The value of authorization size is out of range" },
	{ 0x145, "TPM2_RC_AUTH_CONTEXT, Use of an authorization session with a context that cannot have an authorization session" },
	{ 0x146, "TPM2_RC_NV_RANGE, NV offset + size is out of range" },
	{ 0x147, "TPM2_RC_NV_SIZE, Requested allocation size is larger than allowed" },
	{ 0x148, "TPM2_RC_NV_LOCKED, NV access locked" },
	{ 0x149, "TPM2_RC_NV_AUTHORIZATION, NV access authorization fails in command actions" },
	{ 0x14A, "TPM2_RC_NV_UNINITIALIZED, An NV Index is used before being initialized or the state could not be restored" },
	{ 0x14B, "TPM2_RC_NV_SPACE, Insufficient space for NV allocation" },
	{ 0x14C, "TPM2_RC_NV_DEFINED, NV Index or persistent object already defined" },
	{ 0x150, "TPM2_RC_BAD_CONTEXT, Context in TPM2_ContextLoad is not valid" },
	{ 0x151, "TPM2_RC_CPHASH, cpHash value already set or not correct for use" },
	{ 0x152, "TPM2_RC_PARENT, Handle for parent is not a valid parent" },
	{ 0x153, "TPM2_RC_NEEDS_TEST, Some function needs testing" },
	{ 0x154, "TPM2_RC_NO_RESULT, Internal function cannot process a request due to an unspecified problem" },
	{ 0x155, "TPM2_RC_SENSITIVE, The sensitive area did not unmarshal correctly after decryption" },
	{ 0x801, "TPM2_RC_ASYMMETRIC, Asymmetric algorithm not supported or not correct" },
	{ 0x802, "TPM2_RC_ATTRIBUTES, Inconsistent attributes" },
	{ 0x803, "TPM2_RC_HASH, Hash algorithm not supported or not appropriate" },
	{ 0x804, "TPM2_RC_VALUE, Value is out of range or is not correct for the context" },
	{ 0x805, "TPM2_RC_HIERARCHY, Hierarchy is not enabled or is not correct for the use" },
	{ 0x807, "TPM2_RC_KEY_SIZE, Key size is not supported" },
	{ 0x808, "TPM2_RC_MGF, Mask generation function not supported" },
	{ 0x809, "TPM2_RC_MODE, Mode of operation not supported" },
	{ 0x80A, "TPM2_RC_TYPE, The type of the value is not appropriate for the use" },
	{ 0x80B, "TPM2_RC_HANDLE, The handle is not correct for the use" },
	{ 0x80C, "TPM2_RC_KDF, Unsupported key derivation function or function not appropriate for use" },
	{ 0x80D, "TPM2_RC_RANGE, Value was out of allowed range" },
	{ 0x80E, "TPM2_RC_AUTH_FAIL, The authorization HMAC check failed" },
	{ 0x80F, "TPM2_RC_NONCE, invalid nonce size or nonce value mismatch" },
	{ 0x810, "TPM2_RC_PP, Authorization requires assertion of PP" },
	{ 0x812, "TPM2_RC_SCHEME, Unsupported or incompatible scheme" },
	{ 0x815, "TPM2_RC_SIZE, Structure is the wrong size" },
	{ 0x816, "TPM2_RC_SYMMETRIC, Unsupported symmetric algorithm or key size or not appropriate for instance" },
	{ 0x817, "TPM2_RC_TAG, Incorrect structure tag" },
	{ 0x818, "TPM2_RC_SELECTOR, Union selector is incorrect" },
	{ 0x81A, "TPM2_RC_INSUFFICIENT, Unable to unmarshal a value because there were not enough octets in the input buffer" },
	{ 0x81B, "TPM2_RC_SIGNATURE, The signature is not valid" },
	{ 0x81C, "TPM2_RC_KEY, Key fields are not compatible with the selected use" },
	{ 0x81D, "TPM2_RC_POLICY_FAIL, Policy check failed" },
	{ 0x81F, "TPM2_RC_INTEGRITY, Integrity check failed" },
	{ 0x820, "TPM2_RC_TICKET, Invalid ticket" },
	{ 0x821, "TPM2_RC_RESERVED_BITS, Reserved bits not set to zero as required" },
	{ 0x822, "TPM2_RC_BAD_AUTH, Authorization failure without DA implications" },
	{ 0x823, "TPM2_RC_EXPIRED, The policy has expired" },
	{ 0x824, "TPM2_RC_POLICY_CC, The commandCode in the policy is not the commandCode of the command or command not implemented" },
	{ 0x825, "TPM2_RC_BINDING, Public and sensitive portions of an object are not cryptographically bound" },
	{ 0x826, "TPM2_RC_CURVE, Curve not supported" },
	{ 0x827, "TPM2_RC_ECC_POINT, Point is not on the required curve" },
	{ 0x901, "TPM2_RC_CONTEXT_GAP, Gap for context ID is too large" },
	{ 0x902, "TPM2_RC_OBJECT_MEMORY, Out of memory for object contexts" },
	{ 0x903, "TPM2_RC_SESSION_MEMORY, Out of memory for session contexts" },
	{ 0x904, "TPM2_RC_MEMORY, Out of shared objectsession memory or need space for internal operations" },
	{ 0x905, "TPM2_RC_SESSION_HANDLES, Out of session handles. A session must be flushed before a new session may be created" },
	{ 0x906, "TPM2_RC_OBJECT_HANDLES, Out of object handles. A reboot is required" },
	{ 0x907, "TPM2_RC_LOCALITY, Bad locality" },
	{ 0x908, "TPM2_RC_YIELDED, TPM has suspended operation on the command" },
	{ 0x909, "TPM2_RC_CANCELED, The command was canceled" },
	{ 0x90A, "TPM2_RC_TESTING, TPM is performing selftests" },
	{ 0x910, "TPM2_RC_REFERENCE_H0, The 1st handle references a transient object or session that is not loaded" },
	{ 0x911, "TPM2_RC_REFERENCE_H1, The 2nd handle references a transient object or session that is not loaded" },
	{ 0x912, "TPM2_RC_REFERENCE_H2, The 3rd handle references a transient object or session that is not loaded" },
	{ 0x913, "TPM2_RC_REFERENCE_H3, The 4th handle references a transient object or session that is not loaded" },
	{ 0x914, "TPM2_RC_REFERENCE_H4, The 5th handle references a transient object or session that is not loaded" },
	{ 0x915, "TPM2_RC_REFERENCE_H5, The 6th handle references a transient object or session that is not loaded" },
	{ 0x916, "TPM2_RC_REFERENCE_H6, The 7th handle references a transient object or session that is not loaded" },
	{ 0x918, "TPM2_RC_REFERENCE_S0, The 1st authorization session handle references a session that is not loaded" },
	{ 0x919, "TPM2_RC_REFERENCE_S1, The 2nd authorization session handle references a session that is not loaded" },
	{ 0x91A, "TPM2_RC_REFERENCE_S2, The 3rd authorization session handle references a session that is not loaded" },
	{ 0x91B, "TPM2_RC_REFERENCE_S3, The 4th authorization session handle references a session that is not loaded" },
	{ 0x91C, "TPM2_RC_REFERENCE_S4, The 5th session handle references a session that is not loaded" },
	{ 0x91D, "TPM2_RC_REFERENCE_S5, The 6th session handle references a session that is not loaded" },
	{ 0x91E, "TPM2_RC_REFERENCE_S6, The 7th authorization session handle references a session that is not loaded" },
	{ 0x920, "TPM2_RC_NV_RATE, The TPM is ratelimiting accesses to prevent wearout of NV" },
	{ 0x921, "TPM2_RC_LOCKOUT, Authorizations for objects subject to DA protection are not allowed at this time. TPM is in DA lockout mode" },
	{ 0x922, "TPM2_RC_RETRY - the TPM was not able to start the command" },
	{ 0x923, "TPM2_RC_NV_UNAVAILABLE - the command may require writing of NV and NV is not current accessible" },
	{ 0, NULL }
};

#define TPMA_SESSION_CONTINUESESSION 0x01
#define TPMA_SESSION_AUDITEXCLUSIVE  0x02
#define TPMA_SESSION_AUDITRESET      0x04
#define TPMA_SESSION_RESERVED1_MASK  0x18
#define TPMA_SESSION_DECRYPT         0x20
#define TPMA_SESSION_ENCRYPT         0x40
#define TPMA_SESSION_AUDIT           0x80

static tpm_entry *get_command_entry(wmem_tree_t *tree, uint32_t pnum)
{
	tpm_entry *entry = (tpm_entry *)wmem_tree_lookup32(tree, pnum);
	DISSECTOR_ASSERT(entry != NULL);
	tpm_entry *command_entry = (tpm_entry *)wmem_tree_lookup32(tree, entry->com_pnum);
	DISSECTOR_ASSERT(command_entry != NULL);

	return command_entry;
}

static void
dissect_tpm20_platform_command(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	uint32_t command;

	proto_tree_add_item_ret_uint(tree, hf_tpm20_platform_cmd, tvb, 0,
				4, ENC_BIG_ENDIAN, &command);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", Platform Command %s",
		val_to_str(command, platform_commands, "Unknown (0x%02x)"));

	proto_item_append_text(tree, ", %s", val_to_str(command,
				platform_commands, "Unknown (0x%02x)"));
	response_size = false;
}

static void
dissect_auth_common(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *auth, proto_tree *tree _U_, int *offset)
{
	unsigned nonce_size, auth_size;
	static int * const attrib_fields[] = {
		&hf_session_attribs_cont,
		&hf_session_attribs_auditex,
		&hf_session_attribs_auditreset,
		&hf_session_attribs_res,
		&hf_session_attribs_decrypt,
		&hf_session_attribs_encrypt,
		&hf_session_attribs_audit,
		NULL
	};

	proto_tree_add_item_ret_uint(auth, hf_session_nonce_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &nonce_size);
	*offset += 2;
	proto_tree_add_item(auth, hf_session_nonce, tvb, *offset, nonce_size, ENC_NA);
	*offset += nonce_size;
	proto_tree_add_bitmask_text(auth, tvb, *offset, 1, "Session attributes", NULL,
			ett_tpm_attrib, attrib_fields, ENC_NA, BMT_NO_APPEND);
	*offset += 1;
	proto_tree_add_item_ret_uint(auth, hf_session_auth_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &auth_size);
	*offset += 2;
	proto_tree_add_item(auth, hf_session_auth, tvb, *offset, auth_size, ENC_NA);
	*offset += auth_size;
}

static void
dissect_auth_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *auth,
	proto_tree *tree, int *offset)
{
	tpm_entry *command_entry = get_command_entry(cmd_tree, pinfo->num);
	uint32_t i;

	for (i = 0; i < command_entry->num_auths; i++)
		dissect_auth_common(tvb, pinfo, auth, tree, offset);
}

static void
dissect_auth_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *auth,
		proto_tree *tree, int *offset)
{
	uint32_t auth_area_size;
	uint32_t num_auths = 0;
	tpm_entry *entry = (tpm_entry *)wmem_tree_lookup32(cmd_tree, pinfo->num);
	DISSECTOR_ASSERT(entry != NULL);

	proto_tree_add_item_ret_uint(auth, hf_auth_area_size, tvb, *offset,
				4, ENC_BIG_ENDIAN, &auth_area_size);
	*offset += 4;

	if (auth_area_size < TPM_MIN_AUTH_LEN)
		proto_tree_add_expert_format(auth, pinfo, &ei_invalid_auth_size, tvb, 0, 0,
					"Error: Auth size: %d", auth_area_size);
	while (auth_area_size) {
		uint32_t size;
		proto_tree_add_item(auth, hf_tpmi_sh_auth_session, tvb, *offset, 4, ENC_BIG_ENDIAN);
		*offset += 4;
		auth_area_size -= 4;
		size = *offset;
		dissect_auth_common(tvb, pinfo, auth, tree, offset);
		auth_area_size -= *offset - size;
		num_auths++;
	}

	if (num_auths > MAX_SESSIONS)
		proto_tree_add_expert_format(auth, pinfo, &ei_invalid_num_sessions, tvb, 0, 0,
					"Error: Invalid Number of sessions: %d", num_auths);
	entry->num_auths = num_auths;
}

static void
dissect_startup(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *header, proto_tree *tree _U_, int *offset)
{
	proto_tree_add_item(header, hf_tpm20_startup_type, tvb, *offset, 2, ENC_BIG_ENDIAN);
	*offset += 2;
}

static void
dissect_start_auth_session(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *header _U_, proto_tree *tree, int *offset)
{
	uint32_t nonce_size, encrypted, sym_alg;
	proto_tree_add_item_ret_uint(tree, hf_session_nonce_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &nonce_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_session_nonce, tvb, *offset, nonce_size, ENC_NA);
	*offset += nonce_size;

	proto_tree_add_item_ret_uint(tree, hf_encrypted_secret_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &encrypted);
	*offset += 2;
	proto_tree_add_item(tree, hf_encrypted_secret, tvb, *offset, encrypted, ENC_NA);
	*offset += encrypted;
	proto_tree_add_item(tree, hf_session_type, tvb, *offset, 1, ENC_NA);
	*offset += 1;

	proto_tree_add_item_ret_uint(tree, hf_alg_sym, tvb, *offset, 2, ENC_BIG_ENDIAN, &sym_alg);
	*offset += 2;
	if (sym_alg != TPM_ALG_NULL) {
		proto_tree_add_item(tree, hf_alg_sym_keybits, tvb, *offset, 2, ENC_BIG_ENDIAN);
		*offset += 2;
		proto_tree_add_item(tree, hf_alg_sym_mode, tvb, *offset, 2, ENC_BIG_ENDIAN);
		*offset += 2;
	}
	proto_tree_add_item(tree, hf_alg_hash, tvb, *offset, 2, ENC_NA);
	*offset += 2;
}

static void
dissect_create_primary(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *header _U_, proto_tree *tree, int *offset)
{
	uint32_t sensitive_size, pub_size, data_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_sensitive_crate_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &sensitive_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_sensitive_crate, tvb, *offset, sensitive_size, ENC_NA);
	*offset += sensitive_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_pub_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &pub_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_pub, tvb, *offset, pub_size, ENC_NA);
	*offset += pub_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_data_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &data_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_data, tvb, *offset, data_size, ENC_NA);
	*offset += data_size;
}

static void
dissect_create_loaded(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *header _U_, proto_tree *tree, int *offset)
{
	uint32_t sensitive_size, template_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_sensitive_crate_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &sensitive_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_sensitive_crate, tvb, *offset, sensitive_size, ENC_NA);
	*offset += sensitive_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_template_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &template_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_template, tvb, *offset, template_size, ENC_NA);
	*offset += template_size;
}

static void
dissect_command(uint32_t command, tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *header, proto_tree *tree, int *offset)
{
	last_command_pnum = pinfo->num;

	switch (command) {
	case 0x144: /* TPM Start Up */
		dissect_startup(tvb, pinfo, header, tree, offset);
		break;
	case 0x12e: /* Create Primary */
		dissect_create_primary(tvb, pinfo, header, tree, offset);
		break;
	case 0x176: /* Start Auth Session */
		dissect_start_auth_session(tvb, pinfo, header, tree, offset);
		break;
	case 0x191: /* Create Loaded */
		dissect_create_loaded(tvb, pinfo, header, tree, offset);
		break;
	}
}

static void
dissect_tpm20_tpm_command(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree)
{
	int offset = 0;
	uint32_t command = tvb_get_uint32(tvb, 6, ENC_BIG_ENDIAN);
	uint16_t tag = tvb_get_uint16(tvb, 0, ENC_BIG_ENDIAN);
	struct num_handles handl_map;
	unsigned int i;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", Command %s",
			val_to_str(command, commands, "Unknown (0x%02x)"));

	proto_item *item = proto_tree_add_item(tree, proto_tpm20_header,
						tvb, 0, -1, ENC_NA);
	proto_item_append_text(item, ", %s", val_to_str(command, commands,
				"Unknown (0x%02x)"));
	proto_tree *header = proto_item_add_subtree(item, ett_tpm_header);
	proto_tree_add_item(header, hf_tpm20_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(header, hf_tpm20_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(header, hf_tpm20_cc, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	tpm_entry *entry = (tpm_entry *)wmem_tree_lookup32(cmd_tree, pinfo->num);
	DISSECTOR_ASSERT(entry != NULL);
	entry->command = command;

	handl_map.command = command;
	handl_map.num_req_handles = 0;
	handl_map.num_resp_handles = 0;
	get_num_hndl(&handl_map);

	if (handl_map.num_req_handles) {
		proto_item *hndls = proto_tree_add_item(tree, proto_tpm20_hndl_area,
							tvb, 0, -1, ENC_NA);
		proto_tree *hndl_tree = proto_item_add_subtree(hndls, ett_tpm_handles);
		for (i = 0; i < handl_map.num_req_handles; i++) {
			proto_tree_add_item(hndl_tree, *handl_map.req_pd[i], tvb,
					offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}
	if (tag == 0x8002) {
		proto_item *auth = proto_tree_add_item(tree, proto_tpm20_auth_area,
							tvb, 0, -1, ENC_NA);
		proto_tree *auth_tree = proto_item_add_subtree(auth, ett_tpm_auth);
		dissect_auth_command(tvb, pinfo, auth_tree, tree, &offset);
	} else if (tag != 0x8001) {
		proto_tree_add_expert_format(tree, pinfo, &ei_invalid_tag, tvb, 0, 0,
				"Error: Invalid Tag: %x", tag);
	}

	dissect_command(command, tvb, pinfo, header, tree, &offset);
	response_size = true;
}

#define PNUM_UNINIT 0xFFFFFFFF
#define RESP_CODE 1
#define RESP_SIZE 2
static void
dissect_tpm20_platform_response(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree)
{
	uint32_t rc = tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN);

	tpm_entry *entry = (tpm_entry *)wmem_tree_lookup32(cmd_tree, pinfo->num);
	DISSECTOR_ASSERT(entry != NULL);

	if (entry->resp_type == PNUM_UNINIT) {
		if (response_size == true) {
			entry->resp_type = RESP_SIZE;
			response_size = false;
		} else {
			entry->resp_type = RESP_CODE;
			response_size = true;
		}
	}

	if (entry->resp_type == RESP_SIZE) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Response size %d", rc);
		proto_item_append_text(tree, ", Response size %d", rc);
		proto_tree_add_item(tree, hf_tpm20_platform_resp_size, tvb, 0, 4, ENC_BIG_ENDIAN);
	} else {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Response code %d", rc);
		proto_item_append_text(tree, ", Response code %s",
				       val_to_str(rc, responses, "Unknown (0x%02x)"));
		proto_tree_add_item(tree, hf_tpm20_platform_resp_code, tvb, 0, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_start_auth_session_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int *offset, uint32_t param_size _U_)
{
	uint32_t nonce_size;

	proto_tree_add_item_ret_uint(tree, hf_session_nonce_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &nonce_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_session_nonce, tvb, *offset, nonce_size, ENC_NA);
	*offset += nonce_size;
}

static void
dissect_create_primary_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int *offset, uint32_t param_size _U_)
{
	uint32_t pub_size, creation_data_size, digest_size, name_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_pub_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &pub_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_pub, tvb, *offset, pub_size, ENC_NA);
	*offset += pub_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_creation_data_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &creation_data_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_creation_data, tvb, *offset, creation_data_size, ENC_NA);
	*offset += creation_data_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_digest_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &digest_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_digest, tvb, *offset, digest_size, ENC_NA);
	*offset += digest_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_name_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &name_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_name, tvb, *offset, name_size, ENC_NA);
	*offset += name_size;
}

static void
dissect_create_loaded_resp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int *offset, uint32_t param_size _U_)
{
	uint32_t priv_size, pub_size, name_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_priv_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &priv_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_priv, tvb, *offset, priv_size, ENC_NA);
	*offset += priv_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_pub_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &pub_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_pub, tvb, *offset, pub_size, ENC_NA);
	*offset += pub_size;

	proto_tree_add_item_ret_uint(tree, hf_tpm_name_size, tvb, *offset, 2,
			ENC_BIG_ENDIAN, &name_size);
	*offset += 2;
	proto_tree_add_item(tree, hf_tpm_name, tvb, *offset, name_size, ENC_NA);
	*offset += name_size;
}

static void
dissect_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	int *offset, uint32_t param_size)
{
	tpm_entry *entry = get_command_entry(cmd_tree, pinfo->num);

	switch (entry->command) {
	case 0x12e: /* Create Primary */
		dissect_create_primary_resp(tvb, pinfo, tree, offset, param_size);
		break;
	case 0x176: /* Start Auth Session */
		dissect_start_auth_session_resp(tvb, pinfo, tree, offset, param_size);
		break;
	case 0x191: /* Create Loaded */
		dissect_create_loaded_resp(tvb, pinfo, tree, offset, param_size);
		break;
	case 0x144: /* TPM Start Up */
		break;
	default:
		/* For now dissect everything else and 'params'.
		 * This will allow to process the response auth section */
		proto_tree_add_item(tree, hf_params, tvb, *offset, param_size, ENC_NA);
		*offset += param_size;
	}
}

static void
dissect_tpm20_tpm_response(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree)
{
	int offset = 0;
	struct num_handles handl_map;
	uint16_t tag = tvb_get_uint16(tvb, 0, ENC_BIG_ENDIAN);
	uint32_t rc = tvb_get_uint32(tvb, 6, ENC_BIG_ENDIAN);
	uint32_t param_size;
	unsigned int i;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", Response Code %s",
			val_to_str(rc, responses, "Unknown (0x%02x)"));

	proto_item *item = proto_tree_add_item(tree, proto_tpm20_resp_header,
						tvb, 0, -1, ENC_NA);
	proto_item_append_text(item, ", %s", val_to_str(rc, responses, "Unknown (0x%02x)"));
	proto_tree *header = proto_item_add_subtree(item, ett_tpm_response_header);

	proto_tree_add_item(header, hf_tpm20_resp_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(header, hf_tpm20_resp_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(header, hf_tpm20_resp_code, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	/* if response code says error stop now */
	if (rc)
		return;

	/* find a corresponding request */
	tpm_entry *entry = (tpm_entry *)wmem_tree_lookup32(cmd_tree, pinfo->num);
	DISSECTOR_ASSERT(entry != NULL);
	if (entry->com_pnum == PNUM_UNINIT) {
		entry->com_pnum = last_command_pnum;
	}
	tpm_entry *command_entry = (tpm_entry *)wmem_tree_lookup32(cmd_tree, entry->com_pnum);
	DISSECTOR_ASSERT(command_entry != NULL);

	handl_map.command = command_entry->command;
	handl_map.num_req_handles = 0;
	handl_map.num_resp_handles = 0;
	get_num_hndl(&handl_map);

	/* Dissect response handles */
	if (handl_map.num_resp_handles) {
		proto_item *hndls = proto_tree_add_item(tree, proto_tpm20_hndl_area,
							tvb, 0, -1, ENC_NA);
		proto_tree *hndl_tree = proto_item_add_subtree(hndls, ett_tpm_handles);
		for (i = 0; i < handl_map.num_resp_handles; i++) {
			proto_tree_add_item(hndl_tree, *handl_map.resp_pd[i], tvb,
					offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}

	if (tag == 0x8002) {
		/* Dissect response params size and params */
		param_size = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_resp_param_size, tvb, offset, 4,
				ENC_BIG_ENDIAN);
		offset += 4;

		if (param_size) {
			proto_item *params = proto_tree_add_item(tree, proto_tpm20_params_area,
							 tvb, 0, -1, ENC_NA);
			proto_tree *param_tree = proto_item_add_subtree(params, ett_tpm_params);
			dissect_response(tvb, pinfo, param_tree, &offset, param_size);
		}

		/* Dissect response auth area */
		proto_item *auth = proto_tree_add_item(tree, proto_tpm20_auth_area,
							tvb, 0, -1, ENC_NA);
		proto_tree *auth_tree = proto_item_add_subtree(auth, ett_tpm_auth);
		dissect_auth_resp(tvb, pinfo, auth_tree, tree, &offset);
	} else if (tag == 0x8001) {

		/* Dissect rest of the response */
		dissect_response(tvb, pinfo, tree, &offset, 0);
	} else {
		proto_tree_add_expert_format(tree, pinfo, &ei_invalid_tag, tvb, 0, 0,
					"Error: Invalid Tag: %x", tag);
	}
}

static int
dissect_tpm20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void* data _U_)
{
	tpm_entry *entry;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TPM");
	col_clear(pinfo->cinfo, COL_INFO);
	col_append_ports(pinfo->cinfo, COL_INFO, PT_NONE, pinfo->srcport,
			 pinfo->destport);

	int length = tvb_reported_length(tvb);
	entry = (tpm_entry *)wmem_tree_lookup32(cmd_tree, pinfo->num);

	if (entry == NULL) {
		entry = wmem_new(wmem_file_scope(), tpm_entry);
		entry->com_pnum = PNUM_UNINIT;
		entry->resp_type = PNUM_UNINIT;
		entry->command = 0;
		entry->num_auths = 0;
		wmem_tree_insert32(cmd_tree, pinfo->num, entry);
	}

	proto_item *item = proto_tree_add_item(tree, proto_tpm20, tvb, 0, -1, ENC_NA);
	proto_tree *tpm_tree = proto_item_add_subtree(item, ett_tpm);

	if (pinfo->srcport > pinfo->destport) {
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, " [TPM Request]");
		if (length >= TPM_COMMAND_HEADER_LEN)
			dissect_tpm20_tpm_command(tvb, pinfo, tpm_tree);
		else
			dissect_tpm20_platform_command(tvb, pinfo, tpm_tree);

	} else {
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, " [TPM Response]");
		if (length >= TPM_COMMAND_HEADER_LEN)
			dissect_tpm20_tpm_response(tvb, pinfo, tpm_tree);
		else
			dissect_tpm20_platform_response(tvb, pinfo, tpm_tree);
	}
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "len(%d)", length);

	return tvb_captured_length(tvb);
}

static hf_register_info hf[] = {
	{ &proto_tpm20_header,
	{ "TPM2.0 Header", "tpm.req.header", FT_NONE, BASE_NONE, NULL,
	   0x0, "Tpm header", HFILL }},
	{ &hf_tpm20_tag,
	{ "Tag", "tpm.req.tag", FT_UINT16, BASE_HEX, VALS(tags),
	   0x0, NULL, HFILL }},
	{ &hf_tpm20_size,
	{ "Command size", "tpm.req.size", FT_UINT32, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm20_cc,
	{ "Command Code", "tpm.req.cc", FT_UINT32, BASE_HEX, VALS(commands),
	   0x0, NULL, HFILL }},
	{ &proto_tpm20_auth_area,
	{ "Authorization Area", "tpm.req.auth", FT_NONE, BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &proto_tpm20_hndl_area,
	{ "Handle Area", "tpm.req.hndl", FT_NONE, BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &proto_tpm20_params_area,
	{ "Parameters Area", "tpm.resp.params", FT_NONE, BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm20_platform_cmd,
	{ "Platform Command", "tpm.platform_req.cc", FT_UINT32, BASE_HEX, VALS(platform_commands),
	   0x0, NULL, HFILL }},
	{ &proto_tpm20_resp_header,
	{ "TPM2.0 Header", "tpm.resp.header", FT_NONE, BASE_NONE, NULL,
	   0x0, "Tpm header", HFILL }},
	{ &hf_tpm20_platform_resp_code,
	{ "Platform Response Code", "tpm.resp.code", FT_UINT32, BASE_HEX, VALS(responses),
	   0x0, NULL, HFILL }},
	{ &hf_tpm20_platform_resp_size,
	{ "Platform Response size", "tpm.resp.size", FT_UINT32, BASE_HEX, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm20_resp_tag,
	{ "Response Tag", "tpm.resp.tag", FT_UINT16, BASE_HEX, VALS(tags),
	   0x0, NULL, HFILL }},
	{ &hf_tpm20_resp_size,
	{ "Response size", "tpm.resp.size", FT_UINT32, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm20_resp_code,
	{ "Response rc", "tpm.resp.rc", FT_UINT32, BASE_HEX, VALS(responses),
	   0x0, NULL, HFILL }},
	{ &hf_tpm20_startup_type,
	{ "Startup type", "tpm.startup.type", FT_UINT16, BASE_HEX, VALS(startup_types),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_dh_object,
	{ "TPMI_DH_OBJECT", "tpm.handle.TPMI_DH_OBJECT", FT_UINT32, BASE_HEX, VALS(handles),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_dh_entity,
	{ "TPMI_DH_ENTITY", "tpm.handle.TPMI_DH_ENTITY", FT_UINT32, BASE_HEX, VALS(handles),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_dh_context,
	{ "TPMI_DH_CONTEXT", "tpm.handle.TPMI_DH_CONTEXT", FT_UINT32, BASE_HEX, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_dh_parent,
	{ "TPMI_DH_PARENT", "tpm.handle.TPMI_DH_PARENT", FT_UINT32, BASE_HEX, VALS(hierarhies),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_dh_pcr,
	{ "TPMI_DH_PCR", "tpm.handle.TPMI_DH_PCR", FT_UINT32, BASE_HEX, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_sh_auth_session,
	{ "TPMI_SH_AUTH_SESSION", "tpm.handle.TPMI_SH_AUTH_SESSION", FT_UINT32, BASE_HEX, VALS(handles),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_act,
	{ "TPMI_RH_ACT", "tpm.handle.TPMI_RH_ACT", FT_UINT32, BASE_HEX, VALS(handles),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_hierarhy,
	{ "TPMI_RH_HIERARCHY", "tpm.handle.TPMI_RH_HIERARCHY", FT_UINT32, BASE_HEX, VALS(hierarhies),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_provision,
	{ "TPMI_RH_PROVISION", "tpm.handle.TPMI_RH_PROVISION", FT_UINT32, BASE_HEX, VALS(handles),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_platform,
	{ "TPMI_RH_PLATFORM", "tpm.handle.TPMI_RH_PLATFORM", FT_UINT32, BASE_HEX, VALS(handles),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_clear,
	{ "TPMI_RH_CLEAR", "tpm.handle.TPMI_RH_CLEAR", FT_UINT32, BASE_HEX, VALS(handles),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_hierarhy_auth,
	{ "TPMI_RH_HIERARCHY_AUTH", "tpm.handle.TPMI_RH_HIERARCHY_AUTH", FT_UINT32, BASE_HEX, VALS(handles),
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_nv_auth,
	{ "TPMI_RH_NV_AUTH", "tpm.handle.TPMI_RH_NV_AUTH", FT_UINT32, BASE_HEX, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_nv_index,
	{ "TPMI_RH_NV_INDEX", "tpm.handle.TPMI_RH_NV_INDEX", FT_UINT32, BASE_HEX, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_lockout,
	{ "TPMI_RH_LOCKOUT", "tpm.handle.TPMI_RH_LOCKOUT", FT_UINT32, BASE_HEX, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_ht_handle,
	{ "TPM_HANDLE", "tpm.handle.TPM_HANDLE", FT_UINT32, BASE_HEX, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpmi_rh_endorsment,
	{ "TPMI_RH_ENDORSEMENT", "tpm.handle.TPMI_RH_ENDORSEMENT", FT_UINT32, BASE_HEX, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_auth_area_size,
	{ "AUTHAREA SIZE", "tpm.autharea_size", FT_UINT32, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_session_nonce_size,
	{ "AUTH NONCE SIZE", "tpm.auth_nonce_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_session_nonce,
	{ "AUTH NONCE", "tpm.auth_nonce", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_session_attribs_cont,
	{ "SESSION_CONTINUESESSION", "tpm.auth_attribs_cont", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
	   TPMA_SESSION_CONTINUESESSION, NULL, HFILL }},
	{ &hf_session_attribs_auditex,
	{ "SESSION_AUDITEXCLUSIVE", "tpm.auth_attribs_auditex", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
	   TPMA_SESSION_AUDITEXCLUSIVE, NULL, HFILL }},
	{ &hf_session_attribs_auditreset,
	{ "SESSION_AUDITRESET", "tpm.auth_attribs_auditreset", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
	   TPMA_SESSION_AUDITRESET, NULL, HFILL }},
	{ &hf_session_attribs_res,
	{ "SESSION_RESERVED", "tpm.auth_attribs_res", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
	   TPMA_SESSION_RESERVED1_MASK, NULL, HFILL }},
	{ &hf_session_attribs_decrypt,
	{ "SESSION_DECRYPT", "tpm.auth_attribs_decrypt", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
	   TPMA_SESSION_DECRYPT, NULL, HFILL }},
	{ &hf_session_attribs_encrypt,
	{ "SESSION_ENCRYPT", "tpm.auth_attribs_encrypt", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
	   TPMA_SESSION_ENCRYPT, NULL, HFILL }},
	{ &hf_session_attribs_audit,
	{ "SESSION_AUDIT", "tpm.auth_attribs_audit", FT_BOOLEAN, 8, TFS(&tfs_set_notset),
	   TPMA_SESSION_AUDIT, NULL, HFILL }},
	{ &hf_session_auth_size,
	{ "SESSION AUTH SIZE", "tpm.session_auth_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_session_auth,
	{ "SESSION AUTH", "tpm.session_auth", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_resp_param_size,
	{ "RESP PARAM SIZE", "tpm.resp_param_size", FT_UINT32, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_encrypted_secret_size,
	{ "ENCRYPTED SECRET SIZE", "tpm.enc_secret_size", FT_UINT32, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_encrypted_secret,
	{ "ENCRYPTED SECRET", "tpm.enc_secret", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_session_type,
	{ "SESSION TYPE", "tpm.session_type", FT_UINT8, BASE_HEX, VALS(session_type),
	   0x0, NULL, HFILL }},
	{ &hf_alg_sym,
	{ "SYM ALG", "tpm.sym_alg", FT_UINT16, BASE_HEX, VALS(algs),
	   0x0, NULL, HFILL }},
	{ &hf_alg_sym_mode,
	{ "SYM ALG MODE", "tpm.sym_alg_mode", FT_UINT16, BASE_HEX, VALS(algs),
	   0x0, NULL, HFILL }},
	{ &hf_alg_sym_keybits,
	{ "SYM ALG MODE", "tpm.sym_alg_keybits", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_alg_hash,
	{ "ALG HASH", "tpm.alg_hash", FT_UINT16, BASE_HEX, VALS(algs),
	   0x0, NULL, HFILL }},
	{ &hf_tpm_priv_size,
	{ "TPM PRIVATE SIZE", "tpm.private_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_priv,
	{ "TPM PRIVATE", "tpm.private", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_pub_size,
	{ "TPM PUBLIC SIZE", "tpm.public_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_pub,
	{ "TPM PUBLIC", "tpm.public", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_name_size,
	{ "TPM NAME SIZE", "tpm.name_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_name,
	{ "TPM NAME", "tpm.name", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_sensitive_crate_size,
	{ "TPM SENSITIVE CREATE SIZE", "tpm.sensitive_create_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_sensitive_crate,
	{ "TPM SENSITIVE CREATE", "tpm.sensitive_create", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_template_size,
	{ "TPM TEMPLATE SIZE", "tpm.template_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_template,
	{ "TPM TEMPLATE", "tpm.template", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_data_size,
	{ "TPM DATA SIZE", "tpm.data_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_data,
	{ "TPM DATA", "tpm.data", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_creation_data_size,
	{ "TPM CREATION DATA SIZE", "tpm.creation_data_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_creation_data,
	{ "TPM CREATION DATA", "tpm.creation_data", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_digest_size,
	{ "TPM DIGEST SIZE", "tpm.digest_size", FT_UINT16, BASE_DEC, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_tpm_digest,
	{ "TPM DIGEST", "tpm.digest", FT_BYTES, BASE_ALLOW_ZERO | BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
	{ &hf_params,
	{ "RESPONSE PARAMS", "tpm.PARAMS", FT_BYTES, BASE_NONE, NULL,
	   0x0, NULL, HFILL }},
};

static int *ett[] = {
	&ett_tpm,
	&ett_tpm_header,
	&ett_tpm_response_header,
	&ett_tpm_handles,
	&ett_tpm_auth,
	&ett_tpm_params,
	&ett_tpm_attrib
};

static ei_register_info ei[] = {
	{ &ei_invalid_tag, { "tpm.invalid_tag", PI_PROTOCOL, PI_ERROR, "Invalid Header Tag", EXPFILL }},
	{ &ei_invalid_auth_size, { "tpm.invalid_auth_size", PI_PROTOCOL, PI_ERROR, "Auth area size too small", EXPFILL }},
	{ &ei_invalid_num_sessions, { "tpm.invalid_num_sessions", PI_PROTOCOL, PI_ERROR, "Maximum number of sessions exceeded", EXPFILL }},
};

static void
tpm_init(void)
{
	cmd_tree = wmem_tree_new(wmem_file_scope());
}

void
proto_register_tpm20(void)
{
	proto_tpm20 = proto_register_protocol("TPM2.0 Protocol", "TPM2.0", "tpm");
	proto_register_field_array(proto_tpm20, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_module_t* expert_mod = expert_register_protocol(proto_tpm20);
	expert_register_field_array(expert_mod, ei, array_length(ei));
	register_init_routine(tpm_init);
	tpm20_handle = register_dissector("tpm", dissect_tpm20, proto_tpm20);
}

void
proto_reg_handoff_tpm20(void)
{
	dissector_add_uint_range_with_preference("tcp.port", TCP_TPM_PORTS, tpm20_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
