/* DO NOT EDIT
	This filter was automatically generated
	from frstrans.idl and frstrans.cnf.

	Pidl is a perl based IDL compiler for DCE/RPC idl files. 
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be 
	found at http://wiki.wireshark.org/Pidl
*/


#include "config.h"

#ifdef _MSC_VER
#pragma warning(disable:4005)
#pragma warning(disable:4013)
#pragma warning(disable:4018)
#pragma warning(disable:4101)
#endif

#include <glib.h>
#include <string.h>
#include <epan/packet.h>

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"
#include "packet-dcerpc-frstrans.h"

void proto_register_dcerpc_frstrans(void);
void proto_reg_handoff_dcerpc_frstrans(void);

/* Ett declarations */
static gint ett_dcerpc_frstrans = -1;
static gint ett_frstrans_frstrans_TransportFlags = -1;
static gint ett_frstrans_frstrans_VersionVector = -1;
static gint ett_frstrans_frstrans_Update = -1;
static gint ett_frstrans_frstrans_EpoqueVector = -1;
static gint ett_frstrans_frstrans_AsyncVersionVectorResponse = -1;
static gint ett_frstrans_frstrans_AsyncResponseContext = -1;
static gint ett_frstrans_frstrans_RdcParameterGeneric = -1;
static gint ett_frstrans_frstrans_RdcParameterFilterMax = -1;
static gint ett_frstrans_frstrans_RdcParameterFilterPoint = -1;
static gint ett_frstrans_frstrans_RdcParameterUnion = -1;
static gint ett_frstrans_frstrans_RdcParameters = -1;
static gint ett_frstrans_frstrans_RdcFileInfo = -1;


/* Header field declarations */
static gint hf_frstrans_frstrans_EpoqueVector_minute = -1;
static gint hf_frstrans_frstrans_RdcParameterFilterPoint_max_chunk_size = -1;
static gint hf_frstrans_frstrans_Update_sha1_hash = -1;
static gint hf_frstrans_frstrans_RequestVersionVector_change_type = -1;
static gint hf_frstrans_frstrans_AsyncVersionVectorResponse_version_vector = -1;
static gint hf_frstrans_frstrans_EpoqueVector_year = -1;
static gint hf_frstrans_frstrans_Update_fence = -1;
static gint hf_frstrans_frstrans_RequestVersionVector_sequence_number = -1;
static gint hf_frstrans_opnum = -1;
static gint hf_frstrans_frstrans_VersionVector_db_guid = -1;
static gint hf_frstrans_frstrans_RdcParameters_rdc_chunker_algorithm = -1;
static gint hf_frstrans_frstrans_Update_uid_version = -1;
static gint hf_frstrans_frstrans_RequestUpdates_version_vector_diff_count = -1;
static gint hf_frstrans_frstrans_EstablishConnection_connection_guid = -1;
static gint hf_frstrans_frstrans_RequestUpdates_credits_available = -1;
static gint hf_frstrans_frstrans_RdcParameterFilterMax_max_window_size = -1;
static gint hf_frstrans_frstrans_Update_name = -1;
static gint hf_frstrans_frstrans_VersionVector_low = -1;
static gint hf_frstrans_frstrans_AsyncVersionVectorResponse_version_vector_count = -1;
static gint hf_frstrans_frstrans_EstablishConnection_downstream_flags = -1;
static gint hf_frstrans_frstrans_RdcParameterGeneric_chunker_parameters = -1;
static gint hf_frstrans_frstrans_RdcFileInfo_compression_algorithm = -1;
static gint hf_frstrans_frstrans_Update_flags = -1;
static gint hf_frstrans_frstrans_EpoqueVector_machine_guid = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_connection_guid = -1;
static gint hf_frstrans_frstrans_RdcParameterUnion_filter_point = -1;
static gint hf_frstrans_frstrans_RdcParameterFilterMax_min_horizon_size = -1;
static gint hf_frstrans_frstrans_RdcParameterUnion_filter_generic = -1;
static gint hf_frstrans_frstrans_EpoqueVector_second = -1;
static gint hf_frstrans_frstrans_RdcFileInfo_rdc_filter_parameters = -1;
static gint hf_frstrans_frstrans_RequestVersionVector_content_set_guid = -1;
static gint hf_frstrans_frstrans_EpoqueVector_day = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_frs_update = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_is_end_of_file = -1;
static gint hf_frstrans_frstrans_EstablishConnection_upstream_flags = -1;
static gint hf_frstrans_frstrans_EstablishConnection_downstream_protocol_version = -1;
static gint hf_frstrans_frstrans_RequestUpdates_update_status = -1;
static gint hf_frstrans_frstrans_AsyncPoll_connection_guid = -1;
static gint hf_frstrans_frstrans_AsyncResponseContext_response = -1;
static gint hf_frstrans_frstrans_AsyncResponseContext_sequence_number = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_data_buffer = -1;
static gint hf_frstrans_frstrans_RequestVersionVector_request_type = -1;
static gint hf_frstrans_frstrans_Update_present = -1;
static gint hf_frstrans_frstrans_Update_gsvn_version = -1;
static gint hf_frstrans_frstrans_RdcParameterGeneric_chunker_type = -1;
static gint hf_frstrans_frstrans_TransportFlags_FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY = -1;
static gint hf_frstrans_frstrans_RdcFileInfo_file_size_estimate = -1;
static gint hf_frstrans_frstrans_CheckConnectivity_replica_set_guid = -1;
static gint hf_frstrans_frstrans_EstablishSession_connection_guid = -1;
static gint hf_frstrans_frstrans_EstablishSession_content_set_guid = -1;
static gint hf_frstrans_frstrans_Update_content_set_guid = -1;
static gint hf_frstrans_frstrans_RequestUpdates_update_count = -1;
static gint hf_frstrans_frstrans_Update_rdc_similarity = -1;
static gint hf_frstrans_frstrans_AsyncPoll_response = -1;
static gint hf_frstrans_frstrans_RequestUpdates_version_vector_diff = -1;
static gint hf_frstrans_frstrans_Update_clock = -1;
static gint hf_frstrans_frstrans_AsyncVersionVectorResponse_epoque_vector = -1;
static gint hf_frstrans_frstrans_VersionVector_high = -1;
static gint hf_frstrans_frstrans_EpoqueVector_day_of_week = -1;
static gint hf_frstrans_frstrans_Update_create_time = -1;
static gint hf_frstrans_frstrans_EpoqueVector_milli_seconds = -1;
static gint hf_frstrans_frstrans_RdcFileInfo_rdc_minimum_compatible_version = -1;
static gint hf_frstrans_frstrans_CheckConnectivity_connection_guid = -1;
static gint hf_frstrans_frstrans_Update_uid_db_guid = -1;
static gint hf_frstrans_frstrans_AsyncVersionVectorResponse_epoque_vector_count = -1;
static gint hf_frstrans_frstrans_Update_parent_version = -1;
static gint hf_frstrans_frstrans_RdcParameterFilterPoint_min_chunk_size = -1;
static gint hf_frstrans_frstrans_EstablishConnection_replica_set_guid = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_server_context = -1;
static gint hf_frstrans_frstrans_Update_gsvn_db_guid = -1;
static gint hf_frstrans_frstrans_RequestUpdates_update_request_type = -1;
static gint hf_frstrans_frstrans_Update_attributes = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_buffer_size = -1;
static gint hf_frstrans_frstrans_RequestVersionVector_vv_generation = -1;
static gint hf_frstrans_frstrans_RequestUpdates_gvsn_version = -1;
static gint hf_frstrans_frstrans_RdcParameterUnion_filter_max = -1;
static gint hf_frstrans_frstrans_AsyncVersionVectorResponse_vv_generation = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_staging_policy = -1;
static gint hf_frstrans_frstrans_RequestUpdates_gvsn_db_guid = -1;
static gint hf_frstrans_frstrans_RequestUpdates_hash_requested = -1;
static gint hf_frstrans_frstrans_RdcFileInfo_on_disk_file_size = -1;
static gint hf_frstrans_frstrans_RdcParameters_u = -1;
static gint hf_frstrans_frstrans_RdcFileInfo_rdc_version = -1;
static gint hf_frstrans_frstrans_EpoqueVector_hour = -1;
static gint hf_frstrans_frstrans_RequestUpdates_frs_update = -1;
static gint hf_frstrans_frstrans_AsyncResponseContext_status = -1;
static gint hf_frstrans_frstrans_RequestUpdates_content_set_guid = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_rdc_desired = -1;
static gint hf_frstrans_frstrans_Update_name_conflict = -1;
static gint hf_frstrans_frstrans_EstablishConnection_upstream_protocol_version = -1;
static gint hf_frstrans_frstrans_RequestUpdates_connection_guid = -1;
static gint hf_frstrans_werror = -1;
static gint hf_frstrans_frstrans_Update_parent_db_guid = -1;
static gint hf_frstrans_frstrans_EpoqueVector_month = -1;
static gint hf_frstrans_frstrans_RdcFileInfo_rdc_signature_levels = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_size_read = -1;
static gint hf_frstrans_frstrans_InitializeFileTransferAsync_rdc_file_info = -1;
static gint hf_frstrans_frstrans_RequestVersionVector_connection_guid = -1;

static gint proto_dcerpc_frstrans = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_frstrans = {
	0x897e2e5f, 0x93f3, 0x4376,
	{ 0x9c, 0x9c, 0xfd, 0x22, 0x77, 0x49, 0x5c, 0x27 }
};
static guint16 ver_dcerpc_frstrans = 1;

const value_string frstrans_frstrans_ProtocolVersion_vals[] = {
	{ FRSTRANS_PROTOCOL_VERSION_W2K3R2, "FRSTRANS_PROTOCOL_VERSION_W2K3R2" },
	{ FRSTRANS_PROTOCOL_VERSION_LONGHORN_SERVER, "FRSTRANS_PROTOCOL_VERSION_LONGHORN_SERVER" },
{ 0, NULL }
};
static const true_false_string frstrans_TransportFlags_FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY_tfs = {
   "FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY is SET",
   "FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY is NOT SET",
};
const value_string frstrans_frstrans_UpdateRequestType_vals[] = {
	{ FRSTRANS_UPDATE_REQUEST_ALL, "FRSTRANS_UPDATE_REQUEST_ALL" },
	{ FRSTRANS_UPDATE_REQUEST_TOMBSTONES, "FRSTRANS_UPDATE_REQUEST_TOMBSTONES" },
	{ FRSTRANS_UPDATE_REQUEST_LIVE, "FRSTRANS_UPDATE_REQUEST_LIVE" },
{ 0, NULL }
};
const value_string frstrans_frstrans_UpdateStatus_vals[] = {
	{ FRSTRANS_UPDATE_STATUS_DONE, "FRSTRANS_UPDATE_STATUS_DONE" },
	{ FRSTRANS_UPDATE_STATUS_MORE, "FRSTRANS_UPDATE_STATUS_MORE" },
{ 0, NULL }
};
static int frstrans_dissect_element_VersionVector_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_VersionVector_low(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_VersionVector_high(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_present(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_name_conflict(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_attributes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_fence(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_clock(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_create_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_content_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_sha1_hash(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_sha1_hash_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_rdc_similarity(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_rdc_similarity_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_uid_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_uid_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_gsvn_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_gsvn_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_parent_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_parent_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_Update_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
const value_string frstrans_frstrans_VersionRequestType_vals[] = {
	{ FRSTRANS_VERSION_REQUEST_NORNAL_SYNC, "FRSTRANS_VERSION_REQUEST_NORNAL_SYNC" },
	{ FRSTRANS_VERSION_REQUEST_SLOW_SYNC, "FRSTRANS_VERSION_REQUEST_SLOW_SYNC" },
	{ FRSTRANS_VERSION_REQUEST_SLAVE_SYNC, "FRSTRANS_VERSION_REQUEST_SLAVE_SYNC" },
{ 0, NULL }
};
const value_string frstrans_frstrans_VersionChangeType_vals[] = {
	{ FRSTRANS_VERSION_CHANGE_NOTIFY, "FRSTRANS_VERSION_CHANGE_NOTIFY" },
	{ FRSTRANS_VERSION_CHANGE_ALL, "FRSTRANS_VERSION_CHANGE_ALL" },
{ 0, NULL }
};
static int frstrans_dissect_element_EpoqueVector_machine_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EpoqueVector_year(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EpoqueVector_month(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EpoqueVector_day_of_week(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EpoqueVector_day(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EpoqueVector_hour(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EpoqueVector_minute(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EpoqueVector_second(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EpoqueVector_milli_seconds(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_vv_generation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_version_vector_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_version_vector(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_version_vector_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_version_vector__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncResponseContext_sequence_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncResponseContext_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncResponseContext_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
const value_string frstrans_frstrans_RequestedStagingPolicy_vals[] = {
	{ FRSTRANS_STAGING_POLICY_SERVER_DEFAULTY, "FRSTRANS_STAGING_POLICY_SERVER_DEFAULTY" },
	{ FRSTRANS_STAGING_POLICY_STATGING_REQUIRED, "FRSTRANS_STAGING_POLICY_STATGING_REQUIRED" },
	{ FRSTRANS_STAGING_POLICY_RESTATGING_REQUIRED, "FRSTRANS_STAGING_POLICY_RESTATGING_REQUIRED" },
{ 0, NULL }
};
const value_string frstrans_frstrans_RdcChunckerAlgorithm_vals[] = {
	{ FRSTRANS_RDC_FILTER_GENERIC, "FRSTRANS_RDC_FILTER_GENERIC" },
	{ FRSTRANS_RDC_FILTER_MAX, "FRSTRANS_RDC_FILTER_MAX" },
	{ FRSTRANS_RDC_FILTER_POINT, "FRSTRANS_RDC_FILTER_POINT" },
	{ FRSTRANS_RDC_MAX_ALGORITHM, "FRSTRANS_RDC_MAX_ALGORITHM" },
{ 0, NULL }
};
static int frstrans_dissect_element_RdcParameterGeneric_chunker_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterGeneric_chunker_parameters(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterGeneric_chunker_parameters_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterFilterMax_min_horizon_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterFilterMax_max_window_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterFilterPoint_min_chunk_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterFilterPoint_max_chunk_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterUnion_filter_generic(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterUnion_filter_max(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameterUnion_filter_point(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameters_rdc_chunker_algorithm(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcParameters_u(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
const value_string frstrans_frstrans_RdcVersion_vals[] = {
	{ FRSTRANS_RDC_VERSION, "FRSTRANS_RDC_VERSION" },
{ 0, NULL }
};
const value_string frstrans_frstrans_RdcVersionCompatible_vals[] = {
	{ FRSTRANS_RDC_VERSION_COMPATIBLE, "FRSTRANS_RDC_VERSION_COMPATIBLE" },
{ 0, NULL }
};
const value_string frstrans_frstrans_RdcCompressionAlgorithm_vals[] = {
	{ FRSTRANS_RDC_UNCOMPRESSED, "FRSTRANS_RDC_UNCOMPRESSED" },
	{ FRSTRANS_RDC_XPRESS, "FRSTRANS_RDC_XPRESS" },
{ 0, NULL }
};
static int frstrans_dissect_element_RdcFileInfo_on_disk_file_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcFileInfo_file_size_estimate(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcFileInfo_rdc_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcFileInfo_rdc_minimum_compatible_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcFileInfo_rdc_signature_levels(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcFileInfo_compression_algorithm(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcFileInfo_rdc_filter_parameters(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RdcFileInfo_rdc_filter_parameters_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_CheckConnectivity_replica_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_CheckConnectivity_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishConnection_replica_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishConnection_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishConnection_downstream_protocol_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishConnection_downstream_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishConnection_upstream_protocol_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishConnection_upstream_protocol_version_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishConnection_upstream_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishConnection_upstream_flags_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishSession_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_EstablishSession_content_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_content_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_credits_available(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_hash_requested(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_update_request_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_version_vector_diff_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_version_vector_diff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_version_vector_diff_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_version_vector_diff__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_frs_update(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_frs_update_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_frs_update__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_update_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_update_count_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_update_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_update_status_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_gvsn_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_gvsn_db_guid_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_gvsn_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestUpdates_gvsn_version_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestVersionVector_sequence_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestVersionVector_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestVersionVector_content_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestVersionVector_request_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestVersionVector_change_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_RequestVersionVector_vv_generation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncPoll_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncPoll_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_AsyncPoll_response_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_frs_update(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_frs_update_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_rdc_desired(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_staging_policy(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_staging_policy_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_server_context(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_server_context_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_data_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_data_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_data_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_buffer_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_size_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_size_read_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_is_end_of_file(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int frstrans_dissect_element_InitializeFileTransferAsync_is_end_of_file_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_);
static int
cnf_dissect_hyper(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, guint32 param _U_, int hfindex)
{
	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, di, drep, hfindex, NULL);
	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_PROTOCOL_VERSION_W2K3R2=0x00050000, */
/* IDL: 	FRSTRANS_PROTOCOL_VERSION_LONGHORN_SERVER=0x00050002, */
/* IDL: } */

int
frstrans_dissect_enum_ProtocolVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint32 parameter=0;
	if(param){
		parameter=(guint32)*param;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: bitmap { */
/* IDL: 	FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY =  0x00000001 , */
/* IDL: } */

int
frstrans_dissect_bitmap_TransportFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_frstrans_frstrans_TransportFlags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_frstrans_frstrans_TransportFlags_FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_UPDATE_REQUEST_ALL=0x0000, */
/* IDL: 	FRSTRANS_UPDATE_REQUEST_TOMBSTONES=0x0001, */
/* IDL: 	FRSTRANS_UPDATE_REQUEST_LIVE=0x0002, */
/* IDL: } */

int
frstrans_dissect_enum_UpdateRequestType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_UPDATE_STATUS_DONE=0x0002, */
/* IDL: 	FRSTRANS_UPDATE_STATUS_MORE=0x0003, */
/* IDL: } */

int
frstrans_dissect_enum_UpdateStatus(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	GUID db_guid; */
/* IDL: 	hyper low; */
/* IDL: 	hyper high; */
/* IDL: } */

static int
frstrans_dissect_element_VersionVector_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_VersionVector_db_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_VersionVector_low(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_VersionVector_low);

	return offset;
}

static int
frstrans_dissect_element_VersionVector_high(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_VersionVector_high);

	return offset;
}

int
frstrans_dissect_struct_VersionVector(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_8_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_VersionVector);
	}
	
	offset = frstrans_dissect_element_VersionVector_db_guid(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_VersionVector_low(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_VersionVector_high(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 present; */
/* IDL: 	uint32 name_conflict; */
/* IDL: 	uint32 attributes; */
/* IDL: 	NTTIME fence; */
/* IDL: 	NTTIME clock; */
/* IDL: 	NTTIME create_time; */
/* IDL: 	GUID content_set_guid; */
/* IDL: 	uint8 sha1_hash[20]; */
/* IDL: 	uint8 rdc_similarity[16]; */
/* IDL: 	GUID uid_db_guid; */
/* IDL: 	hyper uid_version; */
/* IDL: 	GUID gsvn_db_guid; */
/* IDL: 	hyper gsvn_version; */
/* IDL: 	GUID parent_db_guid; */
/* IDL: 	hyper parent_version; */
/* IDL: 	[charset(UTF16)] uint16 name[261]; */
/* IDL: 	uint32 flags; */
/* IDL: } */

static int
frstrans_dissect_element_Update_present(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_present, 0);

	return offset;
}

static int
frstrans_dissect_element_Update_name_conflict(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_name_conflict, 0);

	return offset;
}

static int
frstrans_dissect_element_Update_attributes(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_attributes, 0);

	return offset;
}

static int
frstrans_dissect_element_Update_fence(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_fence);

	return offset;
}

static int
frstrans_dissect_element_Update_clock(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_clock);

	return offset;
}

static int
frstrans_dissect_element_Update_create_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_create_time);

	return offset;
}

static int
frstrans_dissect_element_Update_content_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_content_set_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_Update_sha1_hash(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	int i;
	for (i = 0; i < 20; i++)
		offset = frstrans_dissect_element_Update_sha1_hash_(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int
frstrans_dissect_element_Update_sha1_hash_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_sha1_hash, 0);

	return offset;
}

static int
frstrans_dissect_element_Update_rdc_similarity(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	int i;
	for (i = 0; i < 16; i++)
		offset = frstrans_dissect_element_Update_rdc_similarity_(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int
frstrans_dissect_element_Update_rdc_similarity_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_rdc_similarity, 0);

	return offset;
}

static int
frstrans_dissect_element_Update_uid_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_uid_db_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_Update_uid_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_Update_uid_version);

	return offset;
}

static int
frstrans_dissect_element_Update_gsvn_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_gsvn_db_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_Update_gsvn_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_Update_gsvn_version);

	return offset;
}

static int
frstrans_dissect_element_Update_parent_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_parent_db_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_Update_parent_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_Update_parent_version);

	return offset;
}

static int
frstrans_dissect_element_Update_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_vstring(tvb, offset, pinfo, tree, di, drep, sizeof(guint16), hf_frstrans_frstrans_Update_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
frstrans_dissect_element_Update_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_Update_flags, 0);

	return offset;
}

int
frstrans_dissect_struct_Update(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_8_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_Update);
	}
	
	offset = frstrans_dissect_element_Update_present(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_name_conflict(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_attributes(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_fence(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_clock(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_create_time(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_content_set_guid(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_sha1_hash(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_rdc_similarity(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_uid_db_guid(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_uid_version(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_gsvn_db_guid(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_gsvn_version(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_parent_db_guid(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_parent_version(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_name(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_Update_flags(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_VERSION_REQUEST_NORNAL_SYNC=0x0000, */
/* IDL: 	FRSTRANS_VERSION_REQUEST_SLOW_SYNC=0x0001, */
/* IDL: 	FRSTRANS_VERSION_REQUEST_SLAVE_SYNC=0x0002, */
/* IDL: } */

int
frstrans_dissect_enum_VersionRequestType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_VERSION_CHANGE_NOTIFY=0x0000, */
/* IDL: 	FRSTRANS_VERSION_CHANGE_ALL=0x0002, */
/* IDL: } */

int
frstrans_dissect_enum_VersionChangeType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	GUID machine_guid; */
/* IDL: 	uint32 year; */
/* IDL: 	uint32 month; */
/* IDL: 	uint32 day_of_week; */
/* IDL: 	uint32 day; */
/* IDL: 	uint32 hour; */
/* IDL: 	uint32 minute; */
/* IDL: 	uint32 second; */
/* IDL: 	uint32 milli_seconds; */
/* IDL: } */

static int
frstrans_dissect_element_EpoqueVector_machine_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_machine_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_EpoqueVector_year(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_year, 0);

	return offset;
}

static int
frstrans_dissect_element_EpoqueVector_month(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_month, 0);

	return offset;
}

static int
frstrans_dissect_element_EpoqueVector_day_of_week(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_day_of_week, 0);

	return offset;
}

static int
frstrans_dissect_element_EpoqueVector_day(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_day, 0);

	return offset;
}

static int
frstrans_dissect_element_EpoqueVector_hour(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_hour, 0);

	return offset;
}

static int
frstrans_dissect_element_EpoqueVector_minute(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_minute, 0);

	return offset;
}

static int
frstrans_dissect_element_EpoqueVector_second(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_second, 0);

	return offset;
}

static int
frstrans_dissect_element_EpoqueVector_milli_seconds(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EpoqueVector_milli_seconds, 0);

	return offset;
}

int
frstrans_dissect_struct_EpoqueVector(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_EpoqueVector);
	}
	
	offset = frstrans_dissect_element_EpoqueVector_machine_guid(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_EpoqueVector_year(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_EpoqueVector_month(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_EpoqueVector_day_of_week(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_EpoqueVector_day(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_EpoqueVector_hour(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_EpoqueVector_minute(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_EpoqueVector_second(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_EpoqueVector_milli_seconds(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	hyper vv_generation; */
/* IDL: 	uint32 version_vector_count; */
/* IDL: 	[unique(1)] [size_is(version_vector_count)] frstrans_VersionVector *version_vector; */
/* IDL: 	uint32 epoque_vector_count; */
/* IDL: 	[unique(1)] [size_is(epoque_vector_count)] frstrans_EpoqueVector *epoque_vector; */
/* IDL: } */

static int
frstrans_dissect_element_AsyncVersionVectorResponse_vv_generation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_AsyncVersionVectorResponse_vv_generation);

	return offset;
}

static int
frstrans_dissect_element_AsyncVersionVectorResponse_version_vector_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_AsyncVersionVectorResponse_version_vector_count, 0);

	return offset;
}

static int
frstrans_dissect_element_AsyncVersionVectorResponse_version_vector(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_AsyncVersionVectorResponse_version_vector_, NDR_POINTER_UNIQUE, "Pointer to Version Vector (frstrans_VersionVector)",hf_frstrans_frstrans_AsyncVersionVectorResponse_version_vector);

	return offset;
}

static int
frstrans_dissect_element_AsyncVersionVectorResponse_version_vector_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_AsyncVersionVectorResponse_version_vector__);

	return offset;
}

static int
frstrans_dissect_element_AsyncVersionVectorResponse_version_vector__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_VersionVector(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_AsyncVersionVectorResponse_version_vector,0);

	return offset;
}

static int
frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_AsyncVersionVectorResponse_epoque_vector_count, 0);

	return offset;
}

static int
frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector_, NDR_POINTER_UNIQUE, "Pointer to Epoque Vector (frstrans_EpoqueVector)",hf_frstrans_frstrans_AsyncVersionVectorResponse_epoque_vector);

	return offset;
}

static int
frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector__);

	return offset;
}

static int
frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_EpoqueVector(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_AsyncVersionVectorResponse_epoque_vector,0);

	return offset;
}

int
frstrans_dissect_struct_AsyncVersionVectorResponse(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_8_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_AsyncVersionVectorResponse);
	}
	
	offset = frstrans_dissect_element_AsyncVersionVectorResponse_vv_generation(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_AsyncVersionVectorResponse_version_vector_count(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_AsyncVersionVectorResponse_version_vector(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector_count(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_AsyncVersionVectorResponse_epoque_vector(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 sequence_number; */
/* IDL: 	WERROR status; */
/* IDL: 	frstrans_AsyncVersionVectorResponse response; */
/* IDL: } */

static int
frstrans_dissect_element_AsyncResponseContext_sequence_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_AsyncResponseContext_sequence_number, 0);

	return offset;
}

static int
frstrans_dissect_element_AsyncResponseContext_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_AsyncResponseContext_status, 0);

	return offset;
}

static int
frstrans_dissect_element_AsyncResponseContext_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_AsyncVersionVectorResponse(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_AsyncResponseContext_response,0);

	return offset;
}

int
frstrans_dissect_struct_AsyncResponseContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_8_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_AsyncResponseContext);
	}
	
	offset = frstrans_dissect_element_AsyncResponseContext_sequence_number(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_AsyncResponseContext_status(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_AsyncResponseContext_response(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_STAGING_POLICY_SERVER_DEFAULTY=0x0000, */
/* IDL: 	FRSTRANS_STAGING_POLICY_STATGING_REQUIRED=0x0001, */
/* IDL: 	FRSTRANS_STAGING_POLICY_RESTATGING_REQUIRED=0x0002, */
/* IDL: } */

int
frstrans_dissect_enum_RequestedStagingPolicy(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_RDC_FILTER_GENERIC=0x0000, */
/* IDL: 	FRSTRANS_RDC_FILTER_MAX=0x0001, */
/* IDL: 	FRSTRANS_RDC_FILTER_POINT=0x0002, */
/* IDL: 	FRSTRANS_RDC_MAX_ALGORITHM=0x0003, */
/* IDL: } */

int
frstrans_dissect_enum_RdcChunckerAlgorithm(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	frstrans_RdcChunckerAlgorithm chunker_type; */
/* IDL: 	uint8 chunker_parameters[64]; */
/* IDL: } */

static int
frstrans_dissect_element_RdcParameterGeneric_chunker_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_RdcChunckerAlgorithm(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcParameterGeneric_chunker_type, 0);

	return offset;
}

static int
frstrans_dissect_element_RdcParameterGeneric_chunker_parameters(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	int i;
	for (i = 0; i < 64; i++)
		offset = frstrans_dissect_element_RdcParameterGeneric_chunker_parameters_(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int
frstrans_dissect_element_RdcParameterGeneric_chunker_parameters_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcParameterGeneric_chunker_parameters, 0);

	return offset;
}

int
frstrans_dissect_struct_RdcParameterGeneric(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_2_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_RdcParameterGeneric);
	}
	
	offset = frstrans_dissect_element_RdcParameterGeneric_chunker_type(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcParameterGeneric_chunker_parameters(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[range(128,1024*16)] uint16 min_horizon_size; */
/* IDL: 	[range(2,96)] uint16 max_window_size; */
/* IDL: } */

static int
frstrans_dissect_element_RdcParameterFilterMax_min_horizon_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcParameterFilterMax_min_horizon_size, 0);

	return offset;
}

static int
frstrans_dissect_element_RdcParameterFilterMax_max_window_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcParameterFilterMax_max_window_size, 0);

	return offset;
}

int
frstrans_dissect_struct_RdcParameterFilterMax(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_2_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_RdcParameterFilterMax);
	}
	
	offset = frstrans_dissect_element_RdcParameterFilterMax_min_horizon_size(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcParameterFilterMax_max_window_size(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint16 min_chunk_size; */
/* IDL: 	uint16 max_chunk_size; */
/* IDL: } */

static int
frstrans_dissect_element_RdcParameterFilterPoint_min_chunk_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcParameterFilterPoint_min_chunk_size, 0);

	return offset;
}

static int
frstrans_dissect_element_RdcParameterFilterPoint_max_chunk_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcParameterFilterPoint_max_chunk_size, 0);

	return offset;
}

int
frstrans_dissect_struct_RdcParameterFilterPoint(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_2_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_RdcParameterFilterPoint);
	}
	
	offset = frstrans_dissect_element_RdcParameterFilterPoint_min_chunk_size(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcParameterFilterPoint_max_chunk_size(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: [switch_type(frstrans_RdcChunckerAlgorithm)] union { */
/* IDL: [case(FRSTRANS_RDC_FILTER_GENERIC)] [case(FRSTRANS_RDC_FILTER_GENERIC)] frstrans_RdcParameterGeneric filter_generic; */
/* IDL: [case(FRSTRANS_RDC_FILTER_MAX)] [case(FRSTRANS_RDC_FILTER_MAX)] frstrans_RdcParameterFilterMax filter_max; */
/* IDL: [case(FRSTRANS_RDC_FILTER_POINT)] [case(FRSTRANS_RDC_FILTER_POINT)] frstrans_RdcParameterFilterPoint filter_point; */
/* IDL: } */

static int
frstrans_dissect_element_RdcParameterUnion_filter_generic(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_RdcParameterGeneric(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_RdcParameterUnion_filter_generic,0);

	return offset;
}

static int
frstrans_dissect_element_RdcParameterUnion_filter_max(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_RdcParameterFilterMax(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_RdcParameterUnion_filter_max,0);

	return offset;
}

static int
frstrans_dissect_element_RdcParameterUnion_filter_point(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_RdcParameterFilterPoint(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_RdcParameterUnion_filter_point,0);

	return offset;
}

static int
frstrans_dissect_RdcParameterUnion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint16 level;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "frstrans_RdcParameterUnion");
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_RdcParameterUnion);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &level);
	ALIGN_TO_2_BYTES;

	switch(level) {
		case FRSTRANS_RDC_FILTER_GENERIC:
			offset = frstrans_dissect_element_RdcParameterUnion_filter_generic(tvb, offset, pinfo, tree, di, drep);
		break;

		case FRSTRANS_RDC_FILTER_MAX:
			offset = frstrans_dissect_element_RdcParameterUnion_filter_max(tvb, offset, pinfo, tree, di, drep);
		break;

		case FRSTRANS_RDC_FILTER_POINT:
			offset = frstrans_dissect_element_RdcParameterUnion_filter_point(tvb, offset, pinfo, tree, di, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	frstrans_RdcChunckerAlgorithm rdc_chunker_algorithm; */
/* IDL: 	[switch_is(rdc_chunker_algorithm)] frstrans_RdcParameterUnion u; */
/* IDL: } */

static int
frstrans_dissect_element_RdcParameters_rdc_chunker_algorithm(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_RdcChunckerAlgorithm(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcParameters_rdc_chunker_algorithm, 0);

	return offset;
}

static int
frstrans_dissect_element_RdcParameters_u(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_RdcParameterUnion(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcParameters_u, 0);

	return offset;
}

int
frstrans_dissect_struct_RdcParameters(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_2_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_RdcParameters);
	}
	
	offset = frstrans_dissect_element_RdcParameters_rdc_chunker_algorithm(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcParameters_u(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_RDC_VERSION=0x0001, */
/* IDL: } */

int
frstrans_dissect_enum_RdcVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_RDC_VERSION_COMPATIBLE=0x0001, */
/* IDL: } */

int
frstrans_dissect_enum_RdcVersionCompatible(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	FRSTRANS_RDC_UNCOMPRESSED=0x0000, */
/* IDL: 	FRSTRANS_RDC_XPRESS=0x0001, */
/* IDL: } */

int
frstrans_dissect_enum_RdcCompressionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint16 parameter=0;
	if(param){
		parameter=(guint16)*param;
	}
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	hyper on_disk_file_size; */
/* IDL: 	hyper file_size_estimate; */
/* IDL: 	frstrans_RdcVersion rdc_version; */
/* IDL: 	frstrans_RdcVersionCompatible rdc_minimum_compatible_version; */
/* IDL: 	[range(0,8)] uint8 rdc_signature_levels; */
/* IDL: 	frstrans_RdcCompressionAlgorithm compression_algorithm; */
/* IDL: 	[size_is(rdc_signature_levels)] frstrans_RdcParameters rdc_filter_parameters[*]; */
/* IDL: } */

static int
frstrans_dissect_element_RdcFileInfo_on_disk_file_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_RdcFileInfo_on_disk_file_size);

	return offset;
}

static int
frstrans_dissect_element_RdcFileInfo_file_size_estimate(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_RdcFileInfo_file_size_estimate);

	return offset;
}

static int
frstrans_dissect_element_RdcFileInfo_rdc_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_RdcVersion(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcFileInfo_rdc_version, 0);

	return offset;
}

static int
frstrans_dissect_element_RdcFileInfo_rdc_minimum_compatible_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_RdcVersionCompatible(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcFileInfo_rdc_minimum_compatible_version, 0);

	return offset;
}

static int
frstrans_dissect_element_RdcFileInfo_rdc_signature_levels(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcFileInfo_rdc_signature_levels, 0);

	return offset;
}

static int
frstrans_dissect_element_RdcFileInfo_compression_algorithm(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_RdcCompressionAlgorithm(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RdcFileInfo_compression_algorithm, 0);

	return offset;
}

static int
frstrans_dissect_element_RdcFileInfo_rdc_filter_parameters(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RdcFileInfo_rdc_filter_parameters_);

	return offset;
}

static int
frstrans_dissect_element_RdcFileInfo_rdc_filter_parameters_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_RdcParameters(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_RdcFileInfo_rdc_filter_parameters,0);

	return offset;
}

int
frstrans_dissect_struct_RdcFileInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_8_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_frstrans_frstrans_RdcFileInfo);
	}
	
	offset = frstrans_dissect_element_RdcFileInfo_on_disk_file_size(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcFileInfo_file_size_estimate(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcFileInfo_rdc_version(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcFileInfo_rdc_minimum_compatible_version(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcFileInfo_rdc_signature_levels(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcFileInfo_compression_algorithm(tvb, offset, pinfo, tree, di, drep);

	offset = frstrans_dissect_element_RdcFileInfo_rdc_filter_parameters(tvb, offset, pinfo, tree, di, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
frstrans_dissect_element_CheckConnectivity_replica_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_CheckConnectivity_replica_set_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_CheckConnectivity_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_CheckConnectivity_connection_guid, NULL);

	return offset;
}

/* IDL: WERROR frstrans_CheckConnectivity( */
/* IDL: [in] GUID replica_set_guid, */
/* IDL: [in] GUID connection_guid */
/* IDL: ); */

static int
frstrans_dissect_CheckConnectivity_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="CheckConnectivity";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
frstrans_dissect_CheckConnectivity_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="CheckConnectivity";
	offset = frstrans_dissect_element_CheckConnectivity_replica_set_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_CheckConnectivity_connection_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
frstrans_dissect_element_EstablishConnection_replica_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EstablishConnection_replica_set_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_EstablishConnection_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EstablishConnection_connection_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_EstablishConnection_downstream_protocol_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_ProtocolVersion(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EstablishConnection_downstream_protocol_version, 0);

	return offset;
}

static int
frstrans_dissect_element_EstablishConnection_downstream_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_bitmap_TransportFlags(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EstablishConnection_downstream_flags, 0);

	return offset;
}

static int
frstrans_dissect_element_EstablishConnection_upstream_protocol_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_EstablishConnection_upstream_protocol_version_, NDR_POINTER_REF, "Pointer to Upstream Protocol Version (frstrans_ProtocolVersion)",hf_frstrans_frstrans_EstablishConnection_upstream_protocol_version);

	return offset;
}

static int
frstrans_dissect_element_EstablishConnection_upstream_protocol_version_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_ProtocolVersion(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EstablishConnection_upstream_protocol_version, 0);

	return offset;
}

static int
frstrans_dissect_element_EstablishConnection_upstream_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_EstablishConnection_upstream_flags_, NDR_POINTER_REF, "Pointer to Upstream Flags (frstrans_TransportFlags)",hf_frstrans_frstrans_EstablishConnection_upstream_flags);

	return offset;
}

static int
frstrans_dissect_element_EstablishConnection_upstream_flags_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_bitmap_TransportFlags(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EstablishConnection_upstream_flags, 0);

	return offset;
}

/* IDL: WERROR frstrans_EstablishConnection( */
/* IDL: [in] GUID replica_set_guid, */
/* IDL: [in] GUID connection_guid, */
/* IDL: [in] frstrans_ProtocolVersion downstream_protocol_version, */
/* IDL: [in] frstrans_TransportFlags downstream_flags, */
/* IDL: [out] [ref] frstrans_ProtocolVersion *upstream_protocol_version, */
/* IDL: [out] [ref] frstrans_TransportFlags *upstream_flags */
/* IDL: ); */

static int
frstrans_dissect_EstablishConnection_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="EstablishConnection";
	offset = frstrans_dissect_element_EstablishConnection_upstream_protocol_version(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_EstablishConnection_upstream_flags(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
frstrans_dissect_EstablishConnection_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="EstablishConnection";
	offset = frstrans_dissect_element_EstablishConnection_replica_set_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_EstablishConnection_connection_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_EstablishConnection_downstream_protocol_version(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_EstablishConnection_downstream_flags(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
frstrans_dissect_element_EstablishSession_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EstablishSession_connection_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_EstablishSession_content_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_EstablishSession_content_set_guid, NULL);

	return offset;
}

/* IDL: WERROR frstrans_EstablishSession( */
/* IDL: [in] GUID connection_guid, */
/* IDL: [in] GUID content_set_guid */
/* IDL: ); */

static int
frstrans_dissect_EstablishSession_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="EstablishSession";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
frstrans_dissect_EstablishSession_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="EstablishSession";
	offset = frstrans_dissect_element_EstablishSession_connection_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_EstablishSession_content_set_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_connection_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_content_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_content_set_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_credits_available(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_credits_available, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_hash_requested(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_hash_requested, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_update_request_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_UpdateRequestType(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_update_request_type, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_version_vector_diff_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_version_vector_diff_count, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_version_vector_diff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RequestUpdates_version_vector_diff_, NDR_POINTER_REF, "Pointer to Version Vector Diff (frstrans_VersionVector)",hf_frstrans_frstrans_RequestUpdates_version_vector_diff);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_version_vector_diff_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RequestUpdates_version_vector_diff__);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_version_vector_diff__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_VersionVector(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_RequestUpdates_version_vector_diff,0);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_frs_update(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RequestUpdates_frs_update_, NDR_POINTER_REF, "Pointer to Frs Update (frstrans_Update)",hf_frstrans_frstrans_RequestUpdates_frs_update);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_frs_update_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RequestUpdates_frs_update__);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_frs_update__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_Update(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_RequestUpdates_frs_update,0);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_update_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RequestUpdates_update_count_, NDR_POINTER_REF, "Pointer to Update Count (uint32)",hf_frstrans_frstrans_RequestUpdates_update_count);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_update_count_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_update_count, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_update_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RequestUpdates_update_status_, NDR_POINTER_REF, "Pointer to Update Status (frstrans_UpdateStatus)",hf_frstrans_frstrans_RequestUpdates_update_status);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_update_status_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_UpdateStatus(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_update_status, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_gvsn_db_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RequestUpdates_gvsn_db_guid_, NDR_POINTER_REF, "Pointer to Gvsn Db Guid (GUID)",hf_frstrans_frstrans_RequestUpdates_gvsn_db_guid);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_gvsn_db_guid_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestUpdates_gvsn_db_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_gvsn_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_RequestUpdates_gvsn_version_, NDR_POINTER_REF, "Pointer to Gvsn Version (hyper)",hf_frstrans_frstrans_RequestUpdates_gvsn_version);

	return offset;
}

static int
frstrans_dissect_element_RequestUpdates_gvsn_version_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_RequestUpdates_gvsn_version);

	return offset;
}

/* IDL: WERROR frstrans_RequestUpdates( */
/* IDL: [in] GUID connection_guid, */
/* IDL: [in] GUID content_set_guid, */
/* IDL: [in] [range(0,256)] uint32 credits_available, */
/* IDL: [in] [range(0,1)] uint32 hash_requested, */
/* IDL: [in] [range(0,2)] frstrans_UpdateRequestType update_request_type, */
/* IDL: [in] uint32 version_vector_diff_count, */
/* IDL: [ref] [in] [size_is(version_vector_diff_count)] frstrans_VersionVector *version_vector_diff, */
/* IDL: [out] [ref] [length_is(*update_count)] [size_is(credits_available)] frstrans_Update *frs_update, */
/* IDL: [out] [ref] uint32 *update_count, */
/* IDL: [out] [ref] frstrans_UpdateStatus *update_status, */
/* IDL: [out] [ref] GUID *gvsn_db_guid, */
/* IDL: [out] [ref] hyper *gvsn_version */
/* IDL: ); */

static int
frstrans_dissect_RequestUpdates_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="RequestUpdates";
	offset = frstrans_dissect_element_RequestUpdates_frs_update(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_RequestUpdates_update_count(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_RequestUpdates_update_status(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_RequestUpdates_gvsn_db_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_RequestUpdates_gvsn_version(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
frstrans_dissect_RequestUpdates_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="RequestUpdates";
	offset = frstrans_dissect_element_RequestUpdates_connection_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestUpdates_content_set_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestUpdates_credits_available(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestUpdates_hash_requested(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestUpdates_update_request_type(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestUpdates_version_vector_diff_count(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestUpdates_version_vector_diff(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
frstrans_dissect_element_RequestVersionVector_sequence_number(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestVersionVector_sequence_number, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestVersionVector_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestVersionVector_connection_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_RequestVersionVector_content_set_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestVersionVector_content_set_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_RequestVersionVector_request_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_VersionRequestType(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestVersionVector_request_type, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestVersionVector_change_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_VersionChangeType(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_RequestVersionVector_change_type, 0);

	return offset;
}

static int
frstrans_dissect_element_RequestVersionVector_vv_generation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset=cnf_dissect_hyper(tvb, offset, pinfo, tree, di, drep, 0, hf_frstrans_frstrans_RequestVersionVector_vv_generation);

	return offset;
}

/* IDL: WERROR frstrans_RequestVersionVector( */
/* IDL: [in] uint32 sequence_number, */
/* IDL: [in] GUID connection_guid, */
/* IDL: [in] GUID content_set_guid, */
/* IDL: [in] [range(0,2)] frstrans_VersionRequestType request_type, */
/* IDL: [in] [range(0,2)] frstrans_VersionChangeType change_type, */
/* IDL: [in] hyper vv_generation */
/* IDL: ); */

static int
frstrans_dissect_RequestVersionVector_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="RequestVersionVector";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
frstrans_dissect_RequestVersionVector_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="RequestVersionVector";
	offset = frstrans_dissect_element_RequestVersionVector_sequence_number(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestVersionVector_connection_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestVersionVector_content_set_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestVersionVector_request_type(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestVersionVector_change_type(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_RequestVersionVector_vv_generation(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

static int
frstrans_dissect_element_AsyncPoll_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_AsyncPoll_connection_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_AsyncPoll_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_AsyncPoll_response_, NDR_POINTER_REF, "Pointer to Response (frstrans_AsyncResponseContext)",hf_frstrans_frstrans_AsyncPoll_response);

	return offset;
}

static int
frstrans_dissect_element_AsyncPoll_response_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_AsyncResponseContext(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_AsyncPoll_response,0);

	return offset;
}

/* IDL: WERROR frstrans_AsyncPoll( */
/* IDL: [in] GUID connection_guid, */
/* IDL: [out] [ref] frstrans_AsyncResponseContext *response */
/* IDL: ); */

static int
frstrans_dissect_AsyncPoll_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="AsyncPoll";
	offset = frstrans_dissect_element_AsyncPoll_response(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
frstrans_dissect_AsyncPoll_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="AsyncPoll";
	offset = frstrans_dissect_element_AsyncPoll_connection_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

/* IDL: void FRSTRANS_REQUEST_RECORDS( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_REQUEST_RECORDS_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_REQUEST_RECORDS";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_REQUEST_RECORDS_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_REQUEST_RECORDS";
	return offset;
}

/* IDL: void FRSTRANS_UPDATE_CANCEL( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_UPDATE_CANCEL_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_UPDATE_CANCEL";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_UPDATE_CANCEL_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_UPDATE_CANCEL";
	return offset;
}

/* IDL: void FRSTRANS_RAW_GET_FILE_DATA( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_RAW_GET_FILE_DATA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RAW_GET_FILE_DATA";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_RAW_GET_FILE_DATA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RAW_GET_FILE_DATA";
	return offset;
}

/* IDL: void FRSTRANS_RDC_GET_SIGNATURES( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_RDC_GET_SIGNATURES_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_GET_SIGNATURES";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_RDC_GET_SIGNATURES_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_GET_SIGNATURES";
	return offset;
}

/* IDL: void FRSTRANS_RDC_PUSH_SOURCE_NEEDS( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_RDC_PUSH_SOURCE_NEEDS_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_PUSH_SOURCE_NEEDS";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_RDC_PUSH_SOURCE_NEEDS_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_PUSH_SOURCE_NEEDS";
	return offset;
}

/* IDL: void FRSTRANS_RDC_GET_FILE_DATA( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_RDC_GET_FILE_DATA_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_GET_FILE_DATA";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_RDC_GET_FILE_DATA_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_GET_FILE_DATA";
	return offset;
}

/* IDL: void FRSTRANS_RDC_CLOSE( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_RDC_CLOSE_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_CLOSE";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_RDC_CLOSE_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_CLOSE";
	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_connection_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_InitializeFileTransferAsync_connection_guid, NULL);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_frs_update(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_frs_update_, NDR_POINTER_REF, "Pointer to Frs Update (frstrans_Update)",hf_frstrans_frstrans_InitializeFileTransferAsync_frs_update);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_frs_update_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_Update(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_InitializeFileTransferAsync_frs_update,0);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_rdc_desired(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_InitializeFileTransferAsync_rdc_desired, 0);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_staging_policy(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_staging_policy_, NDR_POINTER_REF, "Pointer to Staging Policy (frstrans_RequestedStagingPolicy)",hf_frstrans_frstrans_InitializeFileTransferAsync_staging_policy);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_staging_policy_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_enum_RequestedStagingPolicy(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_InitializeFileTransferAsync_staging_policy, 0);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_server_context(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_server_context_, NDR_POINTER_REF, "Pointer to Server Context (policy_handle)",hf_frstrans_frstrans_InitializeFileTransferAsync_server_context);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_server_context_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_InitializeFileTransferAsync_server_context, 0);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info_, NDR_POINTER_REF, "Pointer to Rdc File Info (frstrans_RdcFileInfo)",hf_frstrans_frstrans_InitializeFileTransferAsync_rdc_file_info);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info__, NDR_POINTER_UNIQUE, "Pointer to Rdc File Info (frstrans_RdcFileInfo)",hf_frstrans_frstrans_InitializeFileTransferAsync_rdc_file_info);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = frstrans_dissect_struct_RdcFileInfo(tvb,offset,pinfo,tree,di,drep,hf_frstrans_frstrans_InitializeFileTransferAsync_rdc_file_info,0);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_data_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_data_buffer_, NDR_POINTER_REF, "Pointer to Data Buffer (uint8)",hf_frstrans_frstrans_InitializeFileTransferAsync_data_buffer);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_data_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_data_buffer__);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_data_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_InitializeFileTransferAsync_data_buffer, 0);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_buffer_size(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_InitializeFileTransferAsync_buffer_size, 0);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_size_read(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_size_read_, NDR_POINTER_REF, "Pointer to Size Read (uint32)",hf_frstrans_frstrans_InitializeFileTransferAsync_size_read);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_size_read_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_InitializeFileTransferAsync_size_read, 0);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_is_end_of_file(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, frstrans_dissect_element_InitializeFileTransferAsync_is_end_of_file_, NDR_POINTER_REF, "Pointer to Is End Of File (uint32)",hf_frstrans_frstrans_InitializeFileTransferAsync_is_end_of_file);

	return offset;
}

static int
frstrans_dissect_element_InitializeFileTransferAsync_is_end_of_file_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_frstrans_InitializeFileTransferAsync_is_end_of_file, 0);

	return offset;
}

/* IDL: WERROR frstrans_InitializeFileTransferAsync( */
/* IDL: [in] GUID connection_guid, */
/* IDL: [out] [in] [ref] frstrans_Update *frs_update, */
/* IDL: [in] [range(0,1)] uint32 rdc_desired, */
/* IDL: [out] [in] [ref] frstrans_RequestedStagingPolicy *staging_policy, */
/* IDL: [out] [ref] policy_handle *server_context, */
/* IDL: [out] [ref] frstrans_RdcFileInfo **rdc_file_info, */
/* IDL: [out] [ref] [length_is(*size_read)] [size_is(buffer_size)] uint8 *data_buffer, */
/* IDL: [in] [range(0,262144)] uint32 buffer_size, */
/* IDL: [out] [ref] uint32 *size_read, */
/* IDL: [out] [ref] uint32 *is_end_of_file */
/* IDL: ); */

static int
frstrans_dissect_InitializeFileTransferAsync_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	guint32 status;

	di->dcerpc_procedure_name="InitializeFileTransferAsync";
	offset = frstrans_dissect_element_InitializeFileTransferAsync_frs_update(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_InitializeFileTransferAsync_staging_policy(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_InitializeFileTransferAsync_server_context(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_InitializeFileTransferAsync_rdc_file_info(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_InitializeFileTransferAsync_data_buffer(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_InitializeFileTransferAsync_size_read(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = frstrans_dissect_element_InitializeFileTransferAsync_is_end_of_file(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_frstrans_werror, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
frstrans_dissect_InitializeFileTransferAsync_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="InitializeFileTransferAsync";
	offset = frstrans_dissect_element_InitializeFileTransferAsync_connection_guid(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_InitializeFileTransferAsync_frs_update(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_InitializeFileTransferAsync_rdc_desired(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_InitializeFileTransferAsync_staging_policy(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	offset = frstrans_dissect_element_InitializeFileTransferAsync_buffer_size(tvb, offset, pinfo, tree, di, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, di, drep);
	return offset;
}

/* IDL: void FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE";
	return offset;
}

/* IDL: void FRSTRANS_RAW_GET_FILE_DATA_ASYNC( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_RAW_GET_FILE_DATA_ASYNC_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RAW_GET_FILE_DATA_ASYNC";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_RAW_GET_FILE_DATA_ASYNC_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RAW_GET_FILE_DATA_ASYNC";
	return offset;
}

/* IDL: void FRSTRANS_RDC_GET_FILE_DATA_ASYNC( */
/* IDL:  */
/* IDL: ); */

static int
frstrans_dissect_FRSTRANS_RDC_GET_FILE_DATA_ASYNC_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_GET_FILE_DATA_ASYNC";
	return offset;
}

static int
frstrans_dissect_FRSTRANS_RDC_GET_FILE_DATA_ASYNC_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, guint8 *drep _U_)
{
	di->dcerpc_procedure_name="FRSTRANS_RDC_GET_FILE_DATA_ASYNC";
	return offset;
}


static dcerpc_sub_dissector frstrans_dissectors[] = {
	{ 0, "CheckConnectivity",
	   frstrans_dissect_CheckConnectivity_request, frstrans_dissect_CheckConnectivity_response},
	{ 1, "EstablishConnection",
	   frstrans_dissect_EstablishConnection_request, frstrans_dissect_EstablishConnection_response},
	{ 2, "EstablishSession",
	   frstrans_dissect_EstablishSession_request, frstrans_dissect_EstablishSession_response},
	{ 3, "RequestUpdates",
	   frstrans_dissect_RequestUpdates_request, frstrans_dissect_RequestUpdates_response},
	{ 4, "RequestVersionVector",
	   frstrans_dissect_RequestVersionVector_request, frstrans_dissect_RequestVersionVector_response},
	{ 5, "AsyncPoll",
	   frstrans_dissect_AsyncPoll_request, frstrans_dissect_AsyncPoll_response},
	{ 6, "FRSTRANS_REQUEST_RECORDS",
	   frstrans_dissect_FRSTRANS_REQUEST_RECORDS_request, frstrans_dissect_FRSTRANS_REQUEST_RECORDS_response},
	{ 7, "FRSTRANS_UPDATE_CANCEL",
	   frstrans_dissect_FRSTRANS_UPDATE_CANCEL_request, frstrans_dissect_FRSTRANS_UPDATE_CANCEL_response},
	{ 8, "FRSTRANS_RAW_GET_FILE_DATA",
	   frstrans_dissect_FRSTRANS_RAW_GET_FILE_DATA_request, frstrans_dissect_FRSTRANS_RAW_GET_FILE_DATA_response},
	{ 9, "FRSTRANS_RDC_GET_SIGNATURES",
	   frstrans_dissect_FRSTRANS_RDC_GET_SIGNATURES_request, frstrans_dissect_FRSTRANS_RDC_GET_SIGNATURES_response},
	{ 10, "FRSTRANS_RDC_PUSH_SOURCE_NEEDS",
	   frstrans_dissect_FRSTRANS_RDC_PUSH_SOURCE_NEEDS_request, frstrans_dissect_FRSTRANS_RDC_PUSH_SOURCE_NEEDS_response},
	{ 11, "FRSTRANS_RDC_GET_FILE_DATA",
	   frstrans_dissect_FRSTRANS_RDC_GET_FILE_DATA_request, frstrans_dissect_FRSTRANS_RDC_GET_FILE_DATA_response},
	{ 12, "FRSTRANS_RDC_CLOSE",
	   frstrans_dissect_FRSTRANS_RDC_CLOSE_request, frstrans_dissect_FRSTRANS_RDC_CLOSE_response},
	{ 13, "InitializeFileTransferAsync",
	   frstrans_dissect_InitializeFileTransferAsync_request, frstrans_dissect_InitializeFileTransferAsync_response},
	{ 14, "FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE",
	   frstrans_dissect_FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE_request, frstrans_dissect_FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE_response},
	{ 15, "FRSTRANS_RAW_GET_FILE_DATA_ASYNC",
	   frstrans_dissect_FRSTRANS_RAW_GET_FILE_DATA_ASYNC_request, frstrans_dissect_FRSTRANS_RAW_GET_FILE_DATA_ASYNC_response},
	{ 16, "FRSTRANS_RDC_GET_FILE_DATA_ASYNC",
	   frstrans_dissect_FRSTRANS_RDC_GET_FILE_DATA_ASYNC_request, frstrans_dissect_FRSTRANS_RDC_GET_FILE_DATA_ASYNC_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_frstrans(void)
{
	static hf_register_info hf[] = {
	{ &hf_frstrans_frstrans_EpoqueVector_minute, 
	  { "Minute", "frstrans.frstrans_EpoqueVector.minute", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterFilterPoint_max_chunk_size, 
	  { "Max Chunk Size", "frstrans.frstrans_RdcParameterFilterPoint.max_chunk_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_sha1_hash, 
	  { "Sha1 Hash", "frstrans.frstrans_Update.sha1_hash", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestVersionVector_change_type, 
	  { "Change Type", "frstrans.frstrans_RequestVersionVector.change_type", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_VersionChangeType_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncVersionVectorResponse_version_vector, 
	  { "Version Vector", "frstrans.frstrans_AsyncVersionVectorResponse.version_vector", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EpoqueVector_year, 
	  { "Year", "frstrans.frstrans_EpoqueVector.year", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_fence, 
	  { "Fence", "frstrans.frstrans_Update.fence", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestVersionVector_sequence_number, 
	  { "Sequence Number", "frstrans.frstrans_RequestVersionVector.sequence_number", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_opnum, 
	  { "Operation", "frstrans.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_VersionVector_db_guid, 
	  { "Db Guid", "frstrans.frstrans_VersionVector.db_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameters_rdc_chunker_algorithm, 
	  { "Rdc Chunker Algorithm", "frstrans.frstrans_RdcParameters.rdc_chunker_algorithm", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_RdcChunckerAlgorithm_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_uid_version, 
	  { "Uid Version", "frstrans.frstrans_Update.uid_version", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_version_vector_diff_count, 
	  { "Version Vector Diff Count", "frstrans.frstrans_RequestUpdates.version_vector_diff_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EstablishConnection_connection_guid, 
	  { "Connection Guid", "frstrans.frstrans_EstablishConnection.connection_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_credits_available, 
	  { "Credits Available", "frstrans.frstrans_RequestUpdates.credits_available", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterFilterMax_max_window_size, 
	  { "Max Window Size", "frstrans.frstrans_RdcParameterFilterMax.max_window_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_name, 
	  { "Name", "frstrans.frstrans_Update.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_VersionVector_low, 
	  { "Low", "frstrans.frstrans_VersionVector.low", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncVersionVectorResponse_version_vector_count, 
	  { "Version Vector Count", "frstrans.frstrans_AsyncVersionVectorResponse.version_vector_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EstablishConnection_downstream_flags, 
	  { "Downstream Flags", "frstrans.frstrans_EstablishConnection.downstream_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterGeneric_chunker_parameters, 
	  { "Chunker Parameters", "frstrans.frstrans_RdcParameterGeneric.chunker_parameters", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcFileInfo_compression_algorithm, 
	  { "Compression Algorithm", "frstrans.frstrans_RdcFileInfo.compression_algorithm", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_RdcCompressionAlgorithm_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_flags, 
	  { "Flags", "frstrans.frstrans_Update.flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EpoqueVector_machine_guid, 
	  { "Machine Guid", "frstrans.frstrans_EpoqueVector.machine_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_connection_guid, 
	  { "Connection Guid", "frstrans.frstrans_InitializeFileTransferAsync.connection_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterUnion_filter_point, 
	  { "Filter Point", "frstrans.frstrans_RdcParameterUnion.filter_point", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterFilterMax_min_horizon_size, 
	  { "Min Horizon Size", "frstrans.frstrans_RdcParameterFilterMax.min_horizon_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterUnion_filter_generic, 
	  { "Filter Generic", "frstrans.frstrans_RdcParameterUnion.filter_generic", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EpoqueVector_second, 
	  { "Second", "frstrans.frstrans_EpoqueVector.second", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcFileInfo_rdc_filter_parameters, 
	  { "Rdc Filter Parameters", "frstrans.frstrans_RdcFileInfo.rdc_filter_parameters", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestVersionVector_content_set_guid, 
	  { "Content Set Guid", "frstrans.frstrans_RequestVersionVector.content_set_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EpoqueVector_day, 
	  { "Day", "frstrans.frstrans_EpoqueVector.day", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_frs_update, 
	  { "Frs Update", "frstrans.frstrans_InitializeFileTransferAsync.frs_update", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_is_end_of_file, 
	  { "Is End Of File", "frstrans.frstrans_InitializeFileTransferAsync.is_end_of_file", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EstablishConnection_upstream_flags, 
	  { "Upstream Flags", "frstrans.frstrans_EstablishConnection.upstream_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EstablishConnection_downstream_protocol_version, 
	  { "Downstream Protocol Version", "frstrans.frstrans_EstablishConnection.downstream_protocol_version", FT_UINT32, BASE_DEC, VALS(frstrans_frstrans_ProtocolVersion_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_update_status, 
	  { "Update Status", "frstrans.frstrans_RequestUpdates.update_status", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_UpdateStatus_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncPoll_connection_guid, 
	  { "Connection Guid", "frstrans.frstrans_AsyncPoll.connection_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncResponseContext_response, 
	  { "Response", "frstrans.frstrans_AsyncResponseContext.response", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncResponseContext_sequence_number, 
	  { "Sequence Number", "frstrans.frstrans_AsyncResponseContext.sequence_number", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_data_buffer, 
	  { "Data Buffer", "frstrans.frstrans_InitializeFileTransferAsync.data_buffer", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestVersionVector_request_type, 
	  { "Request Type", "frstrans.frstrans_RequestVersionVector.request_type", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_VersionRequestType_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_present, 
	  { "Present", "frstrans.frstrans_Update.present", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_gsvn_version, 
	  { "Gsvn Version", "frstrans.frstrans_Update.gsvn_version", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterGeneric_chunker_type, 
	  { "Chunker Type", "frstrans.frstrans_RdcParameterGeneric.chunker_type", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_RdcChunckerAlgorithm_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_TransportFlags_FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY, 
	  { "Frstrans Transport Supports Rdc Similarity", "frstrans.frstrans_TransportFlags.FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY", FT_BOOLEAN, 32, TFS(&frstrans_TransportFlags_FRSTRANS_TRANSPORT_SUPPORTS_RDC_SIMILARITY_tfs), ( 0x00000001 ), NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcFileInfo_file_size_estimate, 
	  { "File Size Estimate", "frstrans.frstrans_RdcFileInfo.file_size_estimate", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_CheckConnectivity_replica_set_guid, 
	  { "Replica Set Guid", "frstrans.frstrans_CheckConnectivity.replica_set_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EstablishSession_connection_guid, 
	  { "Connection Guid", "frstrans.frstrans_EstablishSession.connection_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EstablishSession_content_set_guid, 
	  { "Content Set Guid", "frstrans.frstrans_EstablishSession.content_set_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_content_set_guid, 
	  { "Content Set Guid", "frstrans.frstrans_Update.content_set_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_update_count, 
	  { "Update Count", "frstrans.frstrans_RequestUpdates.update_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_rdc_similarity, 
	  { "Rdc Similarity", "frstrans.frstrans_Update.rdc_similarity", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncPoll_response, 
	  { "Response", "frstrans.frstrans_AsyncPoll.response", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_version_vector_diff, 
	  { "Version Vector Diff", "frstrans.frstrans_RequestUpdates.version_vector_diff", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_clock, 
	  { "Clock", "frstrans.frstrans_Update.clock", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncVersionVectorResponse_epoque_vector, 
	  { "Epoque Vector", "frstrans.frstrans_AsyncVersionVectorResponse.epoque_vector", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_VersionVector_high, 
	  { "High", "frstrans.frstrans_VersionVector.high", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EpoqueVector_day_of_week, 
	  { "Day Of Week", "frstrans.frstrans_EpoqueVector.day_of_week", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_create_time, 
	  { "Create Time", "frstrans.frstrans_Update.create_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EpoqueVector_milli_seconds, 
	  { "Milli Seconds", "frstrans.frstrans_EpoqueVector.milli_seconds", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcFileInfo_rdc_minimum_compatible_version, 
	  { "Rdc Minimum Compatible Version", "frstrans.frstrans_RdcFileInfo.rdc_minimum_compatible_version", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_RdcVersionCompatible_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_CheckConnectivity_connection_guid, 
	  { "Connection Guid", "frstrans.frstrans_CheckConnectivity.connection_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_uid_db_guid, 
	  { "Uid Db Guid", "frstrans.frstrans_Update.uid_db_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncVersionVectorResponse_epoque_vector_count, 
	  { "Epoque Vector Count", "frstrans.frstrans_AsyncVersionVectorResponse.epoque_vector_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_parent_version, 
	  { "Parent Version", "frstrans.frstrans_Update.parent_version", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterFilterPoint_min_chunk_size, 
	  { "Min Chunk Size", "frstrans.frstrans_RdcParameterFilterPoint.min_chunk_size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EstablishConnection_replica_set_guid, 
	  { "Replica Set Guid", "frstrans.frstrans_EstablishConnection.replica_set_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_server_context, 
	  { "Server Context", "frstrans.frstrans_InitializeFileTransferAsync.server_context", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_gsvn_db_guid, 
	  { "Gsvn Db Guid", "frstrans.frstrans_Update.gsvn_db_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_update_request_type, 
	  { "Update Request Type", "frstrans.frstrans_RequestUpdates.update_request_type", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_UpdateRequestType_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_attributes, 
	  { "Attributes", "frstrans.frstrans_Update.attributes", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_buffer_size, 
	  { "Buffer Size", "frstrans.frstrans_InitializeFileTransferAsync.buffer_size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestVersionVector_vv_generation, 
	  { "Vv Generation", "frstrans.frstrans_RequestVersionVector.vv_generation", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_gvsn_version, 
	  { "Gvsn Version", "frstrans.frstrans_RequestUpdates.gvsn_version", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameterUnion_filter_max, 
	  { "Filter Max", "frstrans.frstrans_RdcParameterUnion.filter_max", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncVersionVectorResponse_vv_generation, 
	  { "Vv Generation", "frstrans.frstrans_AsyncVersionVectorResponse.vv_generation", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_staging_policy, 
	  { "Staging Policy", "frstrans.frstrans_InitializeFileTransferAsync.staging_policy", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_RequestedStagingPolicy_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_gvsn_db_guid, 
	  { "Gvsn Db Guid", "frstrans.frstrans_RequestUpdates.gvsn_db_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_hash_requested, 
	  { "Hash Requested", "frstrans.frstrans_RequestUpdates.hash_requested", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcFileInfo_on_disk_file_size, 
	  { "On Disk File Size", "frstrans.frstrans_RdcFileInfo.on_disk_file_size", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcParameters_u, 
	  { "U", "frstrans.frstrans_RdcParameters.u", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcFileInfo_rdc_version, 
	  { "Rdc Version", "frstrans.frstrans_RdcFileInfo.rdc_version", FT_UINT16, BASE_DEC, VALS(frstrans_frstrans_RdcVersion_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EpoqueVector_hour, 
	  { "Hour", "frstrans.frstrans_EpoqueVector.hour", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_frs_update, 
	  { "Frs Update", "frstrans.frstrans_RequestUpdates.frs_update", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_AsyncResponseContext_status, 
	  { "Status", "frstrans.frstrans_AsyncResponseContext.status", FT_UINT32, BASE_DEC, VALS(WERR_errors), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_content_set_guid, 
	  { "Content Set Guid", "frstrans.frstrans_RequestUpdates.content_set_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_rdc_desired, 
	  { "Rdc Desired", "frstrans.frstrans_InitializeFileTransferAsync.rdc_desired", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_name_conflict, 
	  { "Name Conflict", "frstrans.frstrans_Update.name_conflict", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EstablishConnection_upstream_protocol_version, 
	  { "Upstream Protocol Version", "frstrans.frstrans_EstablishConnection.upstream_protocol_version", FT_UINT32, BASE_DEC, VALS(frstrans_frstrans_ProtocolVersion_vals), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestUpdates_connection_guid, 
	  { "Connection Guid", "frstrans.frstrans_RequestUpdates.connection_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_werror, 
	  { "Windows Error", "frstrans.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_Update_parent_db_guid, 
	  { "Parent Db Guid", "frstrans.frstrans_Update.parent_db_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_EpoqueVector_month, 
	  { "Month", "frstrans.frstrans_EpoqueVector.month", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RdcFileInfo_rdc_signature_levels, 
	  { "Rdc Signature Levels", "frstrans.frstrans_RdcFileInfo.rdc_signature_levels", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_size_read, 
	  { "Size Read", "frstrans.frstrans_InitializeFileTransferAsync.size_read", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_InitializeFileTransferAsync_rdc_file_info, 
	  { "Rdc File Info", "frstrans.frstrans_InitializeFileTransferAsync.rdc_file_info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_frstrans_frstrans_RequestVersionVector_connection_guid, 
	  { "Connection Guid", "frstrans.frstrans_RequestVersionVector.connection_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_frstrans,
		&ett_frstrans_frstrans_TransportFlags,
		&ett_frstrans_frstrans_VersionVector,
		&ett_frstrans_frstrans_Update,
		&ett_frstrans_frstrans_EpoqueVector,
		&ett_frstrans_frstrans_AsyncVersionVectorResponse,
		&ett_frstrans_frstrans_AsyncResponseContext,
		&ett_frstrans_frstrans_RdcParameterGeneric,
		&ett_frstrans_frstrans_RdcParameterFilterMax,
		&ett_frstrans_frstrans_RdcParameterFilterPoint,
		&ett_frstrans_frstrans_RdcParameterUnion,
		&ett_frstrans_frstrans_RdcParameters,
		&ett_frstrans_frstrans_RdcFileInfo,
	};

	proto_dcerpc_frstrans = proto_register_protocol("File Replication Service DFS-R", "FRSTRANS", "frstrans");
	proto_register_field_array(proto_dcerpc_frstrans, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_frstrans(void)
{
	dcerpc_init_uuid(proto_dcerpc_frstrans, ett_dcerpc_frstrans,
		&uuid_dcerpc_frstrans, ver_dcerpc_frstrans,
		frstrans_dissectors, hf_frstrans_opnum);
}
