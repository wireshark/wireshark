/* packet-ceph.c
 * Routines for Ceph dissection
 * Copyright 2014, Kevin Cox <kevincox@kevincox.ca>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR ADD PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/to_str.h>
#include <epan/proto_data.h>

void proto_reg_handoff_ceph(void);
void proto_register_ceph(void);

/* Extending the Ceph Dissector.
 *
 * Hello, this is a quick overview of the insertion points in the Ceph dissector
 * it is assumed that you know how dissectors work in general (if not please
 * read 'doc/README.dissector' and related documents).
 *
 * If you have any questions feel free to contact Kevin <kevincox@kevincox.ca>.
 *
 * ## Adding a MSGR Tag
 *
 * To add a MSGR tag you must update the switch statements inside both
 * `c_dissect_msgr()` to actually dissect the data and `c_pdu_end()` to
 * calculate the length of the data.
 *
 * ## Adding a New Message.
 *
 * To add a new message type you simply create a new function
 * `c_dissect_msg_{name}()` with the same signature as the others.  Please
 * insert your function in order of the tag value like the others.
 *
 * Then you simply add it into the switch in `c_dissect_msg()` (also in the
 * correct order).  Your message will then be dissected when encountered.
 *
 * ## Supporting new encodings.
 *
 * ### Message Encodings.
 *
 * The encoding version of messages is available in `data->head.ver` and the
 * code should be modified to conditionally decode the new version of the
 * message.
 *
 * ### Data Type Encodings.
 *
 * Data types encoded using Ceph's `ENCODE_START()` macro can be decoded by
 * using `c_dissect_encoded()` to extract the version and length.  You can
 * then conditionally decode using the version.
 *
 * Please rely on the length returned by `c_dissect_encoded()` to ensure future
 * compatibility.
 */

static dissector_handle_t ceph_handle;

/* Initialize the protocol and registered fields */
static int proto_ceph				 = -1;
static int hf_filter_data			 = -1;
static int hf_node_id				 = -1;
static int hf_node_type				 = -1;
static int hf_node_nonce			 = -1;
static int hf_entityinst_name			 = -1;
static int hf_entityinst_addr			 = -1;
static int hf_EntityName			 = -1;
static int hf_EntityName_type			 = -1;
static int hf_EntityName_id			 = -1;
static int hf_src_slug				 = -1;
static int hf_src_type				 = -1;
static int hf_dst_type				 = -1;
static int hf_dst_slug				 = -1;
static int hf_banner				 = -1;
static int hf_client_info			 = -1;
static int hf_server_info			 = -1;
static int hf_sockaddr				 = -1;
static int hf_inet_family			 = -1;
static int hf_port				 = -1;
static int hf_addr_ipv4				 = -1;
static int hf_addr_ipv6				 = -1;
static int hf_data_data				 = -1;
static int hf_data_size				 = -1;
static int hf_string_data			 = -1;
static int hf_string_size			 = -1;
static int hf_keepalive_time			 = -1;
static int hf_encoded_ver			 = -1;
static int hf_encoded_compat			 = -1;
static int hf_encoded_size			 = -1;
static int hf_version				 = -1;
static int hf_epoch				 = -1;
static int hf_pool				 = -1;
static int hf_key				 = -1;
static int hf_namespace				 = -1;
static int hf_hash				 = -1;
static int hf_pgid_ver				 = -1;
static int hf_pgid_pool				 = -1;
static int hf_pgid_seed				 = -1;
static int hf_pgid_preferred			 = -1;
static int hf_pg_create_epoch			 = -1;
static int hf_pg_create_parent			 = -1;
static int hf_pg_create_splitbits		 = -1;
static int hf_path_ver				 = -1;
static int hf_path_inode			 = -1;
static int hf_path_rel				 = -1;
static int hf_mds_release_inode			 = -1;
static int hf_mds_release_capid			 = -1;
static int hf_mds_release_new			 = -1;
static int hf_mds_release_wanted		 = -1;
static int hf_mds_release_seq			 = -1;
static int hf_mds_release_seq_issue		 = -1;
static int hf_mds_release_mseq			 = -1;
static int hf_mds_release_dname_seq		 = -1;
static int hf_mds_release_dname			 = -1;
static int hf_hitset_params			 = -1;
static int hf_hitset_params_type		 = -1;
static int hf_hitset_params_exphash_count	 = -1;
static int hf_hitset_params_exphash_hit		 = -1;
static int hf_snapinfo				 = -1;
static int hf_snapinfo_id			 = -1;
static int hf_snapinfo_time			 = -1;
static int hf_snapinfo_name			 = -1;
static int hf_pgpool				 = -1;
static int hf_pgpool_type			 = -1;
static int hf_pgpool_size			 = -1;
static int hf_pgpool_crush_ruleset		 = -1;
static int hf_pgpool_hash			 = -1;
static int hf_pgpool_pgnum			 = -1;
static int hf_pgpool_pgpnum			 = -1;
static int hf_pgpool_changed			 = -1;
static int hf_pgpool_snapseq			 = -1;
static int hf_pgpool_snapepoch			 = -1;
static int hf_pgpool_snap			 = -1;
static int hf_pgpool_snap_id			 = -1;
static int hf_pgpool_snapdel			 = -1;
static int hf_pgpool_snapdel_from		 = -1;
static int hf_pgpool_snapdel_to			 = -1;
static int hf_pgpool_uid			 = -1;
static int hf_pgpool_flags_low			 = -1;
static int hf_pgpool_flags_high			 = -1;
static int hf_pgpool_crash_reply_interval	 = -1;
static int hf_pgpool_min_size			 = -1;
static int hf_pgpool_quota_bytes		 = -1;
static int hf_pgpool_quota_objects		 = -1;
static int hf_pgpool_tier			 = -1;
static int hf_pgpool_tierof			 = -1;
static int hf_pgpool_cachemode			 = -1;
static int hf_pgpool_readtier			 = -1;
static int hf_pgpool_writetier			 = -1;
static int hf_pgpool_property			 = -1;
static int hf_pgpool_property_key		 = -1;
static int hf_pgpool_property_val		 = -1;
static int hf_pgpool_hitset_period		 = -1;
static int hf_pgpool_hitset_count		 = -1;
static int hf_pgpool_stripewidth		 = -1;
static int hf_pgpool_targetmaxsize		 = -1;
static int hf_pgpool_targetmaxobj		 = -1;
static int hf_pgpool_cache_targetdirtyratio	 = -1;
static int hf_pgpool_cache_targetfullratio	 = -1;
static int hf_pgpool_cache_flushage_min		 = -1;
static int hf_pgpool_cache_evictage_min		 = -1;
static int hf_pgpool_erasurecode_profile	 = -1;
static int hf_pgpool_lastforceresend		 = -1;
static int hf_pgpool_flag_hashpool		 = -1;
static int hf_pgpool_flag_full			 = -1;
static int hf_pgpool_flag_fake_ec_pool		 = -1;
static int hf_monmap				 = -1;
static int hf_monmap_fsid			 = -1;
static int hf_monmap_epoch			 = -1;
static int hf_monmap_address			 = -1;
static int hf_monmap_address_name		 = -1;
static int hf_monmap_address_addr		 = -1;
static int hf_monmap_changed			 = -1;
static int hf_monmap_created			 = -1;
static int hf_pg_stat_ver			 = -1;
static int hf_pg_stat_seq			 = -1;
static int hf_pg_stat_epoch			 = -1;
static int hf_pg_stat_state			 = -1;
static int hf_pg_stat_logstart			 = -1;
static int hf_pg_stat_logstartondisk		 = -1;
static int hf_pg_stat_created			 = -1;
static int hf_pg_stat_lastepochclean		 = -1;
static int hf_pg_stat_parent			 = -1;
static int hf_pg_stat_parent_splitbits		 = -1;
static int hf_pg_stat_lastscrub			 = -1;
static int hf_pg_stat_lastscrubstamp		 = -1;
static int hf_pg_stat_stats			 = -1;
static int hf_pg_stat_logsize			 = -1;
static int hf_pg_stat_logsizeondisk		 = -1;
static int hf_pg_stat_up			 = -1;
static int hf_pg_stat_acting			 = -1;
static int hf_pg_stat_lastfresh			 = -1;
static int hf_pg_stat_lastchange		 = -1;
static int hf_pg_stat_lastactive		 = -1;
static int hf_pg_stat_lastclean			 = -1;
static int hf_pg_stat_lastunstale		 = -1;
static int hf_pg_stat_mappingepoch		 = -1;
static int hf_pg_stat_lastdeepscrub		 = -1;
static int hf_pg_stat_lastdeepscrubstamp	 = -1;
static int hf_pg_stat_statsinvalid		 = -1;
static int hf_pg_stat_lastcleanscrubstamp	 = -1;
static int hf_pg_stat_lastbecameactive		 = -1;
static int hf_pg_stat_dirtystatsinvalid		 = -1;
static int hf_pg_stat_upprimary			 = -1;
static int hf_pg_stat_actingprimary		 = -1;
static int hf_pg_stat_omapstatsinvalid		 = -1;
static int hf_pg_stat_hitsetstatsinvalid	 = -1;
static int hf_crush				 = -1;
static int hf_osd_peerstat			 = -1;
static int hf_osd_peerstat_timestamp		 = -1;
static int hf_featureset_mask			 = -1;
static int hf_featureset_name			 = -1;
static int hf_featureset_name_val		 = -1;
static int hf_featureset_name_name		 = -1;
static int hf_compatset				 = -1;
static int hf_compatset_compat			 = -1;
static int hf_compatset_compatro		 = -1;
static int hf_compatset_incompat		 = -1;
static int hf_osd_superblock			 = -1;
static int hf_osd_superblock_clusterfsid	 = -1;
static int hf_osd_superblock_role		 = -1;
static int hf_osd_superblock_epoch		 = -1;
static int hf_osd_superblock_map_old		 = -1;
static int hf_osd_superblock_map_new		 = -1;
static int hf_osd_superblock_weight		 = -1;
static int hf_osd_superblock_mounted		 = -1;
static int hf_osd_superblock_osdfsid		 = -1;
static int hf_osd_superblock_clean		 = -1;
static int hf_osd_superblock_full		 = -1;
static int hf_osdinfo_ver			 = -1;
static int hf_osdinfo_lastclean_begin		 = -1;
static int hf_osdinfo_lastclean_end		 = -1;
static int hf_osdinfo_up_from			 = -1;
static int hf_osdinfo_up_through		 = -1;
static int hf_osdinfo_downat			 = -1;
static int hf_osdinfo_lostat			 = -1;
static int hf_osdxinfo_down			 = -1;
static int hf_osdxinfo_laggy_probability	 = -1;
static int hf_osdxinfo_laggy_interval		 = -1;
static int hf_osdxinfo_oldweight		 = -1;
static int hf_perfstat_commitlatency		 = -1;
static int hf_perfstat_applylatency		 = -1;
static int hf_osdstat				 = -1;
static int hf_osdstat_kb			 = -1;
static int hf_osdstat_kbused			 = -1;
static int hf_osdstat_kbavail			 = -1;
static int hf_osdstat_trimqueue			 = -1;
static int hf_osdstat_trimming			 = -1;
static int hf_osdstat_hbin			 = -1;
static int hf_osdstat_hbout			 = -1;
static int hf_osdstat_opqueue			 = -1;
static int hf_osdstat_fsperf			 = -1;
static int hf_osdmap				 = -1;
static int hf_osdmap_client			 = -1;
static int hf_osdmap_fsid			 = -1;
static int hf_osdmap_epoch			 = -1;
static int hf_osdmap_created			 = -1;
static int hf_osdmap_modified			 = -1;
static int hf_osdmap_pool			 = -1;
static int hf_osdmap_pool_id			 = -1;
static int hf_osdmap_poolname_item		 = -1;
static int hf_osdmap_poolname			 = -1;
static int hf_osdmap_poolmax			 = -1;
static int hf_osdmap_flags			 = -1;
static int hf_osdmap_osdmax			 = -1;
static int hf_osdmap_osd_state			 = -1;
static int hf_osdmap_osd_weight			 = -1;
static int hf_osdmap_osd_addr			 = -1;
static int hf_osdmap_pgtmp			 = -1;
static int hf_osdmap_pgtmp_pg			 = -1;
static int hf_osdmap_pgtmp_val			 = -1;
static int hf_osdmap_primarytmp			 = -1;
static int hf_osdmap_primarytmp_pg		 = -1;
static int hf_osdmap_primarytmp_val		 = -1;
static int hf_osdmap_osd_primaryaffinity	 = -1;
static int hf_osdmap_erasurecodeprofile		 = -1;
static int hf_osdmap_erasurecodeprofile_name	 = -1;
static int hf_osdmap_erasurecodeprofile_prop	 = -1;
static int hf_osdmap_erasurecodeprofile_k	 = -1;
static int hf_osdmap_erasurecodeprofile_v	 = -1;
static int hf_osdmap_osd			 = -1;
static int hf_osdmap_hbaddr_back		 = -1;
static int hf_osdmap_osd_info			 = -1;
static int hf_osdmap_blacklist			 = -1;
static int hf_osdmap_blacklist_addr		 = -1;
static int hf_osdmap_blacklist_time		 = -1;
static int hf_osdmap_cluster_addr		 = -1;
static int hf_osdmap_cluster_snapepoch		 = -1;
static int hf_osdmap_cluster_snap		 = -1;
static int hf_osdmap_osd_uuid			 = -1;
static int hf_osdmap_osd_xinfo			 = -1;
static int hf_osdmap_hbaddr_front		 = -1;
static int hf_osdmap_inc			 = -1;
static int hf_osdmap_inc_client			 = -1;
static int hf_osdmap_inc_fsid			 = -1;
static int hf_osdmap_inc_osd			 = -1;
static int hf_features_high			 = -1;
static int hf_features_low			 = -1;
static int hf_feature_uid			 = -1;
static int hf_feature_nosrcaddr			 = -1;
static int hf_feature_monclockcheck		 = -1;
static int hf_feature_flock			 = -1;
static int hf_feature_subscribe2		 = -1;
static int hf_feature_monnames			 = -1;
static int hf_feature_reconnect_seq		 = -1;
static int hf_feature_dirlayouthash		 = -1;
static int hf_feature_objectlocator		 = -1;
static int hf_feature_pgid64			 = -1;
static int hf_feature_incsubosdmap		 = -1;
static int hf_feature_pgpool3			 = -1;
static int hf_feature_osdreplymux		 = -1;
static int hf_feature_osdenc			 = -1;
static int hf_feature_omap			 = -1;
static int hf_feature_monenc			 = -1;
static int hf_feature_query_t			 = -1;
static int hf_feature_indep_pg_map		 = -1;
static int hf_feature_crush_tunables		 = -1;
static int hf_feature_chunky_scrub		 = -1;
static int hf_feature_mon_nullroute		 = -1;
static int hf_feature_mon_gv			 = -1;
static int hf_feature_backfill_reservation	 = -1;
static int hf_feature_msg_auth			 = -1;
static int hf_feature_recovery_reservation	 = -1;
static int hf_feature_crush_tunables2		 = -1;
static int hf_feature_createpoolid		 = -1;
static int hf_feature_reply_create_inode	 = -1;
static int hf_feature_osd_hbmsgs		 = -1;
static int hf_feature_mdsenc			 = -1;
static int hf_feature_osdhashpspool		 = -1;
static int hf_feature_mon_single_paxos		 = -1;
static int hf_feature_osd_snapmapper		 = -1;
static int hf_feature_mon_scrub			 = -1;
static int hf_feature_osd_packed_recovery	 = -1;
static int hf_feature_osd_cachepool		 = -1;
static int hf_feature_crush_v2			 = -1;
static int hf_feature_export_peer		 = -1;
static int hf_feature_osd_erasure_codes		 = -1;
static int hf_feature_osd_tmap2omap		 = -1;
static int hf_feature_osdmap_enc		 = -1;
static int hf_feature_mds_inline_data		 = -1;
static int hf_feature_crush_tunables3		 = -1;
static int hf_feature_osd_primary_affinity	 = -1;
static int hf_feature_msgr_keepalive2		 = -1;
static int hf_feature_reserved			 = -1;
static int hf_connect_host_type			 = -1;
static int hf_connect_seq_global		 = -1;
static int hf_connect_seq			 = -1;
static int hf_connect_proto_ver			 = -1;
static int hf_connect_auth_proto		 = -1;
static int hf_connect_auth_size			 = -1;
static int hf_connect_auth			 = -1;
static int hf_flags				 = -1;
static int hf_flag_lossy			 = -1;
static int hf_osd_flags				 = -1;
static int hf_osd_flag_ack			 = -1;
static int hf_osd_flag_onnvram			 = -1;
static int hf_osd_flag_ondisk			 = -1;
static int hf_osd_flag_retry			 = -1;
static int hf_osd_flag_read			 = -1;
static int hf_osd_flag_write			 = -1;
static int hf_osd_flag_ordersnap		 = -1;
static int hf_osd_flag_peerstat_old		 = -1;
static int hf_osd_flag_balance_reads		 = -1;
static int hf_osd_flag_parallelexec		 = -1;
static int hf_osd_flag_pgop			 = -1;
static int hf_osd_flag_exec			 = -1;
static int hf_osd_flag_exec_public		 = -1;
static int hf_osd_flag_localize_reads		 = -1;
static int hf_osd_flag_rwordered		 = -1;
static int hf_osd_flag_ignore_cache		 = -1;
static int hf_osd_flag_skiprwlocks		 = -1;
static int hf_osd_flag_ignore_overlay		 = -1;
static int hf_osd_flag_flush			 = -1;
static int hf_osd_flag_map_snap_clone		 = -1;
static int hf_osd_flag_enforce_snapc		 = -1;
static int hf_osd_op_type			 = -1;
static int hf_osd_op_data			 = -1;
static int hf_osd_op_extent_off			 = -1;
static int hf_osd_op_extent_size		 = -1;
static int hf_osd_op_extent_trunc_size		 = -1;
static int hf_osd_op_extent_trunc_seq		 = -1;
static int hf_osd_op_payload_size		 = -1;
static int hf_osd_redirect_oloc			 = -1;
static int hf_osd_redirect_obj			 = -1;
static int hf_osd_redirect_osdinstr		 = -1;
static int hf_osd_redirect_osdinstr_data	 = -1;
static int hf_osd_redirect_osdinstr_len		 = -1;
static int hf_statsum_bytes			 = -1;
static int hf_statsum_objects			 = -1;
static int hf_statsum_clones			 = -1;
static int hf_statsum_copies			 = -1;
static int hf_statsum_missing			 = -1;
static int hf_statsum_degraded			 = -1;
static int hf_statsum_unfound			 = -1;
static int hf_statsum_read_bytes		 = -1;
static int hf_statsum_read_kbytes		 = -1;
static int hf_statsum_written_bytes		 = -1;
static int hf_statsum_written_kbytes		 = -1;
static int hf_statsum_scrub_errors		 = -1;
static int hf_statsum_recovered			 = -1;
static int hf_statsum_bytes_recovered		 = -1;
static int hf_statsum_keys_recovered		 = -1;
static int hf_statsum_shallow_scrub_errors	 = -1;
static int hf_statsum_deep_scrub_errors		 = -1;
static int hf_statsum_dirty			 = -1;
static int hf_statsum_whiteouts			 = -1;
static int hf_statsum_omap			 = -1;
static int hf_statsum_hitset_archive		 = -1;
static int hf_connect				 = -1;
static int hf_connect_reply			 = -1;
static int hf_tag				 = -1;
static int hf_ack				 = -1;
static int hf_seq_existing			 = -1;
static int hf_seq_new				 = -1;
static int hf_head				 = -1;
static int hf_head_seq				 = -1;
static int hf_head_tid				 = -1;
static int hf_head_type				 = -1;
static int hf_head_priority			 = -1;
static int hf_head_version			 = -1;
static int hf_head_front_size			 = -1;
static int hf_head_middle_size			 = -1;
static int hf_head_data_size			 = -1;
static int hf_head_data_off			 = -1;
static int hf_head_srcname			 = -1;
static int hf_head_compat_version		 = -1;
static int hf_head_reserved			 = -1;
static int hf_head_crc				 = -1;
static int hf_foot				 = -1;
static int hf_foot_front_crc			 = -1;
static int hf_foot_middle_crc			 = -1;
static int hf_foot_data_crc			 = -1;
static int hf_foot_signature			 = -1;
static int hf_msg_front				 = -1;
static int hf_msg_middle			 = -1;
static int hf_msg_data				 = -1;
static int hf_statcollection			 = -1;
static int hf_paxos				 = -1;
static int hf_paxos_ver				 = -1;
static int hf_paxos_mon				 = -1;
static int hf_paxos_mon_tid			 = -1;
static int hf_msg_mon_map			 = -1;
static int hf_msg_statfs			 = -1;
static int hf_msg_statfs_fsid			 = -1;
static int hf_msg_statfsreply			 = -1;
static int hf_msg_statfsreply_fsid		 = -1;
static int hf_msg_statfsreply_ver		 = -1;
static int hf_msg_statfsreply_kb		 = -1;
static int hf_msg_statfsreply_kbused		 = -1;
static int hf_msg_statfsreply_kbavail		 = -1;
static int hf_msg_statfsreply_obj		 = -1;
static int hf_msg_mon_sub			 = -1;
static int hf_msg_mon_sub_item			 = -1;
static int hf_msg_mon_sub_item_len		 = -1;
static int hf_msg_mon_sub_what			 = -1;
static int hf_msg_mon_sub_start			 = -1;
static int hf_msg_mon_sub_flags			 = -1;
static int hf_msg_mon_sub_flags_onetime		 = -1;
static int hf_msg_mon_sub_ack			 = -1;
static int hf_msg_mon_sub_ack_interval		 = -1;
static int hf_msg_mon_sub_ack_fsid		 = -1;
static int hf_msg_auth				 = -1;
static int hf_msg_auth_proto			 = -1;
static int hf_msg_auth_supportedproto		 = -1;
static int hf_msg_auth_supportedproto_ver	 = -1;
static int hf_msg_auth_supportedproto_proto	 = -1;
static int hf_msg_auth_supportedproto_gid	 = -1;
static int hf_msg_auth_cephx			 = -1;
static int hf_msg_auth_cephx_req_type		 = -1;
static int hf_msg_auth_monmap_epoch		 = -1;
static int hf_msg_auth_reply			 = -1;
static int hf_msg_auth_reply_proto		 = -1;
static int hf_msg_auth_reply_result		 = -1;
static int hf_msg_auth_reply_global_id		 = -1;
static int hf_msg_auth_reply_msg		 = -1;
static int hf_msg_mon_getverison		 = -1;
static int hf_msg_mon_getverison_tid		 = -1;
static int hf_msg_mon_getverison_what		 = -1;
static int hf_msg_mon_getverisonreply		 = -1;
static int hf_msg_mon_getverisonreply_tid	 = -1;
static int hf_msg_mon_getverisonreply_ver	 = -1;
static int hf_msg_mon_getverisonreply_veroldest	 = -1;
static int hf_msg_mds_map			 = -1;
static int hf_msg_mds_map_fsid			 = -1;
static int hf_msg_mds_map_epoch			 = -1;
static int hf_msg_mds_map_datai			 = -1;
static int hf_msg_mds_map_data			 = -1;
static int hf_msg_mds_map_data_size		 = -1;
static int hf_msg_client_sess			 = -1;
static int hf_msg_client_sess_op		 = -1;
static int hf_msg_client_sess_seq		 = -1;
static int hf_msg_client_sess_time		 = -1;
static int hf_msg_client_sess_caps_max		 = -1;
static int hf_msg_client_sess_leases_max	 = -1;
static int hf_msg_client_req			 = -1;
static int hf_msg_client_req_oldest_tid		 = -1;
static int hf_msg_client_req_mdsmap_epoch	 = -1;
static int hf_msg_client_req_flags		 = -1;
static int hf_msg_client_req_retry		 = -1;
static int hf_msg_client_req_forward		 = -1;
static int hf_msg_client_req_releases		 = -1;
static int hf_msg_client_req_op			 = -1;
static int hf_msg_client_req_caller_uid		 = -1;
static int hf_msg_client_req_caller_gid		 = -1;
static int hf_msg_client_req_inode		 = -1;
static int hf_msg_client_req_path_src		 = -1;
static int hf_msg_client_req_path_dst		 = -1;
static int hf_msg_client_req_release		 = -1;
static int hf_msg_client_req_time		 = -1;
static int hf_msg_client_reqfwd			 = -1;
static int hf_msg_client_reqfwd_dst		 = -1;
static int hf_msg_client_reqfwd_fwd		 = -1;
static int hf_msg_client_reqfwd_resend		 = -1;
static int hf_msg_client_reply			 = -1;
static int hf_msg_client_reply_op		 = -1;
static int hf_msg_client_reply_result		 = -1;
static int hf_msg_client_reply_mdsmap_epoch	 = -1;
static int hf_msg_client_reply_safe		 = -1;
static int hf_msg_client_reply_isdentry		 = -1;
static int hf_msg_client_reply_istarget		 = -1;
static int hf_msg_client_reply_trace		 = -1;
static int hf_msg_client_reply_extra		 = -1;
static int hf_msg_client_reply_snaps		 = -1;
static int hf_msg_osd_map			 = -1;
static int hf_msg_osd_map_fsid			 = -1;
static int hf_msg_osd_map_inc			 = -1;
static int hf_msg_osd_map_inc_len		 = -1;
static int hf_msg_osd_map_map			 = -1;
static int hf_msg_osd_map_map_len		 = -1;
static int hf_msg_osd_map_epoch			 = -1;
static int hf_msg_osd_map_oldest		 = -1;
static int hf_msg_osd_map_newest		 = -1;
static int hf_msg_osd_op			 = -1;
static int hf_msg_osd_op_client_inc		 = -1;
static int hf_msg_osd_op_osdmap_epoch		 = -1;
static int hf_msg_osd_op_mtime			 = -1;
static int hf_msg_osd_op_reassert_version	 = -1;
static int hf_msg_osd_op_oloc			 = -1;
static int hf_msg_osd_op_pgid			 = -1;
static int hf_msg_osd_op_oid			 = -1;
static int hf_msg_osd_op_ops_len		 = -1;
static int hf_msg_osd_op_op			 = -1;
static int hf_msg_osd_op_snap_id		 = -1;
static int hf_msg_osd_op_snap_seq		 = -1;
static int hf_msg_osd_op_snaps_len		 = -1;
static int hf_msg_osd_op_snap			 = -1;
static int hf_msg_osd_op_retry_attempt		 = -1;
static int hf_msg_osd_op_payload		 = -1;
static int hf_msg_osd_opreply			 = -1;
static int hf_msg_osd_opreply_oid		 = -1;
static int hf_msg_osd_opreply_pgid		 = -1;
static int hf_msg_osd_opreply_result		 = -1;
static int hf_msg_osd_opreply_bad_replay_ver	 = -1;
static int hf_msg_osd_opreply_osdmap_epoch	 = -1;
static int hf_msg_osd_opreply_ops_len		 = -1;
static int hf_msg_osd_opreply_op		 = -1;
static int hf_msg_osd_opreply_retry_attempt	 = -1;
static int hf_msg_osd_opreply_rval		 = -1;
static int hf_msg_osd_opreply_replay_ver	 = -1;
static int hf_msg_osd_opreply_user_ver		 = -1;
static int hf_msg_osd_opreply_redirect		 = -1;
static int hf_msg_osd_opreply_payload		 = -1;
static int hf_msg_poolopreply			 = -1;
static int hf_msg_poolopreply_fsid		 = -1;
static int hf_msg_poolopreply_code		 = -1;
static int hf_msg_poolopreply_epoch		 = -1;
static int hf_msg_poolopreply_datai		 = -1;
static int hf_msg_poolopreply_data		 = -1;
static int hf_msg_poolopreply_data_size		 = -1;
static int hf_msg_poolop			 = -1;
static int hf_msg_poolop_fsid			 = -1;
static int hf_msg_poolop_pool			 = -1;
static int hf_msg_poolop_type			 = -1;
static int hf_msg_poolop_auid			 = -1;
static int hf_msg_poolop_snapid			 = -1;
static int hf_msg_poolop_name			 = -1;
static int hf_msg_poolop_crush_rule		 = -1;
static int hf_msg_poolop_crush_rule8		 = -1;
static int hf_msg_mon_cmd			 = -1;
static int hf_msg_mon_cmd_fsid			 = -1;
static int hf_msg_mon_cmd_arg			 = -1;
static int hf_msg_mon_cmd_arg_len		 = -1;
static int hf_msg_mon_cmd_str			 = -1;
static int hf_msg_mon_cmd_ack			 = -1;
static int hf_msg_mon_cmd_ack_code		 = -1;
static int hf_msg_mon_cmd_ack_res		 = -1;
static int hf_msg_mon_cmd_ack_arg		 = -1;
static int hf_msg_mon_cmd_ack_arg_len		 = -1;
static int hf_msg_mon_cmd_ack_arg_str		 = -1;
static int hf_msg_mon_cmd_ack_data		 = -1;
static int hf_msg_poolstats			 = -1;
static int hf_msg_poolstats_fsid		 = -1;
static int hf_msg_poolstats_pool		 = -1;
static int hf_msg_poolstatsreply		 = -1;
static int hf_msg_poolstatsreply_fsid		 = -1;
static int hf_msg_poolstatsreply_stat		 = -1;
static int hf_msg_poolstatsreply_pool		 = -1;
static int hf_msg_poolstatsreply_log_size	 = -1;
static int hf_msg_poolstatsreply_log_size_ondisk = -1;
static int hf_msg_mon_globalid_max		 = -1;
static int hf_msg_mon_election			 = -1;
static int hf_msg_mon_election_fsid		 = -1;
static int hf_msg_mon_election_op		 = -1;
static int hf_msg_mon_election_epoch		 = -1;
static int hf_msg_mon_election_quorum		 = -1;
static int hf_msg_mon_election_quorum_features	 = -1;
static int hf_msg_mon_election_defunct_one	 = -1;
static int hf_msg_mon_election_defunct_two	 = -1;
static int hf_msg_mon_election_sharing		 = -1;
static int hf_msg_mon_election_sharing_data	 = -1;
static int hf_msg_mon_election_sharing_size	 = -1;
static int hf_msg_mon_paxos			 = -1;
static int hf_msg_mon_paxos_epoch		 = -1;
static int hf_msg_mon_paxos_op			 = -1;
static int hf_msg_mon_paxos_first		 = -1;
static int hf_msg_mon_paxos_last		 = -1;
static int hf_msg_mon_paxos_pnfrom		 = -1;
static int hf_msg_mon_paxos_pn			 = -1;
static int hf_msg_mon_paxos_pnuncommitted	 = -1;
static int hf_msg_mon_paxos_lease		 = -1;
static int hf_msg_mon_paxos_sent		 = -1;
static int hf_msg_mon_paxos_latest_ver		 = -1;
static int hf_msg_mon_paxos_latest_val		 = -1;
static int hf_msg_mon_paxos_latest_val_data	 = -1;
static int hf_msg_mon_paxos_latest_val_size	 = -1;
static int hf_msg_mon_paxos_value		 = -1;
static int hf_msg_mon_paxos_ver			 = -1;
static int hf_msg_mon_paxos_val			 = -1;
static int hf_msg_mon_paxos_val_data		 = -1;
static int hf_msg_mon_paxos_val_size		 = -1;
static int hf_msg_mon_probe			 = -1;
static int hf_msg_mon_probe_fsid		 = -1;
static int hf_msg_mon_probe_type		 = -1;
static int hf_msg_mon_probe_name		 = -1;
static int hf_msg_mon_probe_quorum		 = -1;
static int hf_msg_mon_probe_paxos_first_ver	 = -1;
static int hf_msg_mon_probe_paxos_last_ver	 = -1;
static int hf_msg_mon_probe_ever_joined		 = -1;
static int hf_msg_mon_probe_req_features	 = -1;
static int hf_msg_osd_ping			 = -1;
static int hf_msg_osd_ping_fsid			 = -1;
static int hf_msg_osd_ping_mapepoch		 = -1;
static int hf_msg_osd_ping_peerepoch		 = -1;
static int hf_msg_osd_ping_op			 = -1;
static int hf_msg_osd_ping_time			 = -1;
static int hf_msg_osd_boot			 = -1;
static int hf_msg_osd_boot_addr_back		 = -1;
static int hf_msg_osd_boot_addr_cluster		 = -1;
static int hf_msg_osd_boot_epoch		 = -1;
static int hf_msg_osd_boot_addr_front		 = -1;
static int hf_msg_osd_boot_metadata		 = -1;
static int hf_msg_osd_boot_metadata_k		 = -1;
static int hf_msg_osd_boot_metadata_v		 = -1;
static int hf_msg_pgstats			 = -1;
static int hf_msg_pgstats_fsid			 = -1;
static int hf_msg_pgstats_pgstat		 = -1;
static int hf_msg_pgstats_pgstat_pg		 = -1;
static int hf_msg_pgstats_pgstat_stat		 = -1;
static int hf_msg_pgstats_epoch			 = -1;
static int hf_msg_pgstats_mapfor		 = -1;
static int hf_msg_osd_pg_create			 = -1;
static int hf_msg_osd_pg_create_epoch		 = -1;
static int hf_msg_osd_pg_create_mkpg		 = -1;
static int hf_msg_osd_pg_create_mkpg_pg		 = -1;
static int hf_msg_osd_pg_create_mkpg_create	 = -1;
static int hf_msg_client_caps			 = -1;
static int hf_msg_client_caps_op		 = -1;
static int hf_msg_client_caps_inode		 = -1;
static int hf_msg_client_caps_relam		 = -1;
static int hf_msg_client_caps_cap_id		 = -1;
static int hf_msg_client_caps_seq		 = -1;
static int hf_msg_client_caps_seq_issue		 = -1;
static int hf_msg_client_caps_new		 = -1;
static int hf_msg_client_caps_wanted		 = -1;
static int hf_msg_client_caps_dirty		 = -1;
static int hf_msg_client_caps_seq_migrate	 = -1;
static int hf_msg_client_caps_snap_follows	 = -1;
static int hf_msg_client_caps_uid		 = -1;
static int hf_msg_client_caps_gid		 = -1;
static int hf_msg_client_caps_mode		 = -1;
static int hf_msg_client_caps_nlink		 = -1;
static int hf_msg_client_caps_xattr_ver		 = -1;
static int hf_msg_client_caps_snap		 = -1;
static int hf_msg_client_caps_flock		 = -1;
static int hf_msg_client_caps_inline_ver	 = -1;
static int hf_msg_client_caps_inline_data	 = -1;
static int hf_msg_client_caps_xattr		 = -1;
static int hf_msg_client_caprel			 = -1;
static int hf_msg_client_caprel_cap		 = -1;
static int hf_msg_client_caprel_cap_inode	 = -1;
static int hf_msg_client_caprel_cap_id		 = -1;
static int hf_msg_client_caprel_cap_migrate	 = -1;
static int hf_msg_client_caprel_cap_seq		 = -1;
static int hf_msg_timecheck			 = -1;
static int hf_msg_timecheck_op			 = -1;
static int hf_msg_timecheck_epoch		 = -1;
static int hf_msg_timecheck_round		 = -1;
static int hf_msg_timecheck_time		 = -1;
static int hf_msg_timecheck_skew		 = -1;
static int hf_msg_timecheck_skew_node		 = -1;
static int hf_msg_timecheck_skew_skew		 = -1;
static int hf_msg_timecheck_latency		 = -1;
static int hf_msg_timecheck_latency_node	 = -1;
static int hf_msg_timecheck_latency_latency	 = -1;

/* Initialize the expert items. */
static expert_field ei_unused	      = EI_INIT;
static expert_field ei_overrun	      = EI_INIT;
static expert_field ei_tag_unknown    = EI_INIT;
static expert_field ei_msg_unknown    = EI_INIT;
static expert_field ei_union_unknown  = EI_INIT;
static expert_field ei_ver_tooold     = EI_INIT;
static expert_field ei_ver_toonew     = EI_INIT;
static expert_field ei_oloc_both      = EI_INIT;
/* static expert_field ei_banner_invalid = EI_INIT; */
static expert_field ei_sizeillogical  = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_ceph			   = -1;
static gint ett_data			   = -1;
static gint ett_str			   = -1;
static gint ett_blob			   = -1;
static gint ett_sockaddr		   = -1;
static gint ett_entityaddr		   = -1;
static gint ett_entityname		   = -1;
static gint ett_EntityName		   = -1;
static gint ett_entityinst		   = -1;
static gint ett_kv			   = -1;
static gint ett_eversion		   = -1;
static gint ett_objectlocator		   = -1;
static gint ett_pg			   = -1;
static gint ett_pg_create		   = -1;
static gint ett_filepath		   = -1;
static gint ett_mds_release		   = -1;
static gint ett_hitset_params		   = -1;
static gint ett_snapinfo		   = -1;
static gint ett_pgpool			   = -1;
static gint ett_pgpool_snap		   = -1;
static gint ett_pgpool_snapdel		   = -1;
static gint ett_pgpool_property		   = -1;
static gint ett_mon_map			   = -1;
static gint ett_mon_map_address		   = -1;
static gint ett_osd_peerstat		   = -1;
static gint ett_featureset		   = -1;
static gint ett_featureset_name		   = -1;
static gint ett_compatset		   = -1;
static gint ett_osd_superblock		   = -1;
static gint ett_osd_info		   = -1;
static gint ett_osd_xinfo		   = -1;
static gint ett_perfstat		   = -1;
static gint ett_osdstat			   = -1;
static gint ett_pg_stat			   = -1;
static gint ett_osd_map			   = -1;
static gint ett_osd_map_client		   = -1;
static gint ett_osd_map_pool		   = -1;
static gint ett_osd_map_poolname	   = -1;
static gint ett_osd_map_pgtmp		   = -1;
static gint ett_osd_map_primarytmp	   = -1;
static gint ett_osd_map_erasurecodeprofile = -1;
static gint ett_osd_map_osd		   = -1;
static gint ett_osd_map_blacklist	   = -1;
static gint ett_osd_map_inc		   = -1;
static gint ett_osd_map_inc_client	   = -1;
static gint ett_osd_map_inc_osd		   = -1;
static gint ett_osd_op			   = -1;
static gint ett_redirect		   = -1;
static gint ett_statcollection		   = -1;
static gint ett_paxos			   = -1;
static gint ett_msg_mon_map		   = -1;
static gint ett_msg_statfs		   = -1;
static gint ett_msg_statfsreply		   = -1;
static gint ett_msg_mon_sub		   = -1;
static gint ett_msg_mon_sub_item	   = -1;
static gint ett_msg_mon_sub_flags	   = -1;
static gint ett_msg_mon_sub_ack		   = -1;
static gint ett_msg_auth		   = -1;
static gint ett_msg_auth_supportedproto	   = -1;
static gint ett_msg_auth_cephx		   = -1;
static gint ett_msg_authreply		   = -1;
static gint ett_msg_mon_getversion	   = -1;
static gint ett_msg_mon_getversionreply	   = -1;
static gint ett_msg_mds_map		   = -1;
static gint ett_msg_client_sess		   = -1;
static gint ett_msg_client_req		   = -1;
static gint ett_msg_client_reqfwd	   = -1;
static gint ett_msg_client_reply	   = -1;
static gint ett_msg_osd_map		   = -1;
static gint ett_msg_osd_map_inc		   = -1;
static gint ett_msg_osd_map_full	   = -1;
static gint ett_msg_osd_op		   = -1;
static gint ett_msg_osd_opreply		   = -1;
static gint ett_msg_poolopreply		   = -1;
static gint ett_msg_poolop		   = -1;
static gint ett_msg_mon_cmd		   = -1;
static gint ett_msg_mon_cmd_arg		   = -1;
static gint ett_msg_mon_cmdack		   = -1;
static gint ett_msg_mon_cmdack_arg	   = -1;
static gint ett_msg_poolstats		   = -1;
static gint ett_msg_poolstatsreply	   = -1;
static gint ett_msg_poolstatsreply_stat	   = -1;
static gint ett_msg_mon_election	   = -1;
static gint ett_msg_mon_paxos		   = -1;
static gint ett_msg_mon_paxos_value	   = -1;
static gint ett_msg_mon_probe		   = -1;
static gint ett_msg_osd_ping		   = -1;
static gint ett_msg_osd_boot		   = -1;
static gint ett_msg_pgstats		   = -1;
static gint ett_msg_pgstats_pgstat	   = -1;
static gint ett_msg_osd_pg_create	   = -1;
static gint ett_msg_osd_pg_create_mkpg	   = -1;
static gint ett_msg_client_caps		   = -1;
static gint ett_msg_client_caprel	   = -1;
static gint ett_msg_client_caprel_cap	   = -1;
static gint ett_msg_timecheck		   = -1;
static gint ett_msg_timecheck_skew	   = -1;
static gint ett_msg_timecheck_latency	   = -1;
static gint ett_head			   = -1;
static gint ett_foot			   = -1;
static gint ett_connect			   = -1;
static gint ett_connect_reply		   = -1;
static gint ett_filter_data		   = -1;

static const guint8 *C_BANNER = (const guint8*)"ceph v";

#define C_BANNER_SIZE     9
#define C_BANNER_SIZE_MIN 6

/** Feature Flags */
/* Transmuted from ceph:/src/include/ceph_features.h */
#define C_FEATURE_UID		       (1U <<  0)
#define C_FEATURE_NOSRCADDR	       (1U <<  1)
#define C_FEATURE_MONCLOCKCHECK	       (1U <<  2)
#define C_FEATURE_FLOCK		       (1U <<  3)
#define C_FEATURE_SUBSCRIBE2	       (1U <<  4)
#define C_FEATURE_MONNAMES	       (1U <<  5)
#define C_FEATURE_RECONNECT_SEQ	       (1U <<  6)
#define C_FEATURE_DIRLAYOUTHASH	       (1U <<  7)
#define C_FEATURE_OBJECTLOCATOR	       (1U <<  8)
#define C_FEATURE_PGID64	       (1U <<  9)
#define C_FEATURE_INCSUBOSDMAP	       (1U << 10)
#define C_FEATURE_PGPOOL3	       (1U << 11)
#define C_FEATURE_OSDREPLYMUX	       (1U << 12)
#define C_FEATURE_OSDENC	       (1U << 13)
#define C_FEATURE_OMAP		       (1U << 14)
#define C_FEATURE_MONENC	       (1U << 15)
#define C_FEATURE_QUERY_T	       (1U << 16)
#define C_FEATURE_INDEP_PG_MAP	       (1U << 17)
#define C_FEATURE_CRUSH_TUNABLES       (1U << 18)
#define C_FEATURE_CHUNKY_SCRUB	       (1U << 19)
#define C_FEATURE_MON_NULLROUTE	       (1U << 20)
#define C_FEATURE_MON_GV	       (1U << 21)
#define C_FEATURE_BACKFILL_RESERVATION (1U << 22)
#define C_FEATURE_MSG_AUTH	       (1U << 23)
#define C_FEATURE_RECOVERY_RESERVATION (1U << 24)
#define C_FEATURE_CRUSH_TUNABLES2      (1U << 25)
#define C_FEATURE_CREATEPOOLID	       (1U << 26)
#define C_FEATURE_REPLY_CREATE_INODE   (1U << 27)
#define C_FEATURE_OSD_HBMSGS	       (1U << 28)
#define C_FEATURE_MDSENC	       (1U << 29)
#define C_FEATURE_OSDHASHPSPOOL	       (1U << 30)
#define C_FEATURE_MON_SINGLE_PAXOS     (1U << 31)
#define C_FEATURE_OSD_SNAPMAPPER       (1U <<  0)
#define C_FEATURE_MON_SCRUB	       (1U <<  1)
#define C_FEATURE_OSD_PACKED_RECOVERY  (1U <<  2)
#define C_FEATURE_OSD_CACHEPOOL	       (1U <<  3)
#define C_FEATURE_CRUSH_V2	       (1U <<  4)
#define C_FEATURE_EXPORT_PEER	       (1U <<  5)
#define C_FEATURE_OSD_ERASURE_CODES    (1U <<  6)
#define C_FEATURE_OSD_TMAP2OMAP	       (1U <<  6)
#define C_FEATURE_OSDMAP_ENC	       (1U <<  7)
#define C_FEATURE_MDS_INLINE_DATA      (1U <<  8)
#define C_FEATURE_CRUSH_TUNABLES3      (1U <<  9)
#define C_FEATURE_OSD_PRIMARY_AFFINITY (1U <<  9)
#define C_FEATURE_MSGR_KEEPALIVE2      (1U << 10)
#define C_FEATURE_RESERVED	       (1U << 31)

/** Connect Message Flags */
#define C_FLAG_LOSSY	               (1U << 0)

#define C_PGPOOL_FLAG_HASHPSPOOL       (1U << 0) /* hash pg seed and pool together (instead of adding) */
#define C_PGPOOL_FLAG_FULL	       (1U << 1) /* pool is full */
#define C_PGPOOL_FLAG_FAKE_EC_POOL     (1U << 2) /* require ReplicatedPG to act like an EC pg */

/** Macros to create value_stings.
 *
 * These are a quick wrapper around the functions in value_string.h.  They
 * create an enum `base` with the given values, a `value_string base_strings[]`
 * and a function `const char `base_string(base val)` which gets the string
 * for a value.
 *
 * Additionally, C_MAKE_STRINGS_EXT creates a
 * `value_strings_ext base_strings_ext` and uses this for the `base_string`
 * lookup.
 *
 * @param base The root name.
 * @param chars The number of characters to use when displaying the value.
 *		this is generally 2*bytes.
 */
#define C_MAKE_STRINGS(base, chars) \
	typedef gint base; \
	VALUE_STRING_ENUM(base##_strings); \
	VALUE_STRING_ARRAY(base##_strings); \
	static const char *base##_string(base val) { \
		return val_to_str(val, base##_strings, "Unknown (0x0"#chars"X)"); \
	}

#define C_MAKE_STRINGS_EXT(base, chars) \
	typedef gint base; \
	VALUE_STRING_ENUM(base##_strings); \
	VALUE_STRING_ARRAY(base##_strings); \
	\
	static value_string_ext \
	base##_strings_ext = VALUE_STRING_EXT_INIT(base##_strings); \
	\
	static const char *base##_string(base val) { \
		return val_to_str_ext(val, &base##_strings_ext, "Unknown (0x0"#chars"X)"); \
	}

#define c_inet_strings_VALUE_STRING_LIST(V) \
	V(C_IPv4, 0x0002, "IPv4") \
	V(C_IPv6, 0x000A, "IPv6")

typedef gint c_inet;
VALUE_STRING_ENUM(c_inet_strings);
VALUE_STRING_ARRAY(c_inet_strings);

/** Message Tags */
#define c_tag_strings_VALUE_STRING_LIST(V) \
	V(C_TAG_READY,		0x01, "server->client: ready for messages")		     \
	V(C_TAG_RESETSESSION,	0x02, "server->client: reset, try again")		     \
	V(C_TAG_WAIT,		0x03, "server->client: wait for racing incoming connection") \
	V(C_TAG_RETRY_SESSION,	0x04, "server->client + cseq: try again with higher cseq")   \
	V(C_TAG_RETRY_GLOBAL,	0x05, "server->client + gseq: try again with higher gseq")   \
	V(C_TAG_CLOSE,		0x06, "closing pipe")					     \
	V(C_TAG_MSG,		0x07, "message")					     \
	V(C_TAG_ACK,		0x08, "message ack")					     \
	V(C_TAG_KEEPALIVE,	0x09, "just a keepalive byte!")				     \
	V(C_TAG_BADPROTOVER,	0x0A, "bad protocol version")				     \
	V(C_TAG_BADAUTHORIZER,	0x0B, "bad authorizer")					     \
	V(C_TAG_FEATURES,	0x0C, "insufficient features")				     \
	V(C_TAG_SEQ,		0x0D, "64-bit int follows with seen seq number")	     \
	V(C_TAG_KEEPALIVE2,	0x0E, "keepalive2")					     \
	V(C_TAG_KEEPALIVE2_ACK, 0x0F, "keepalive2 reply")				     \

typedef gint c_tag;
VALUE_STRING_ENUM(c_tag_strings);
VALUE_STRING_ARRAY(c_tag_strings);
static value_string_ext c_tag_strings_ext = VALUE_STRING_EXT_INIT(c_tag_strings);

/* Extracted from the Ceph tree.
 *
 * These are MSG_* constants for server <-> server (internal) messages. and
 * CEPH_MSG_* for client <-> server messages.  There is no functional
 * difference, just a naming convention.
 */
#define c_msg_type_strings_VALUE_STRING_LIST(V) \
	V(C_MSG_UNKNOWN,		     0x0000, "Unknown (0x0000)")		  \
											  \
	V(C_CEPH_MSG_SHUTDOWN,		     0x0001, "C_CEPH_MSG_SHUTDOWN")		  \
	V(C_CEPH_MSG_PING,		     0x0002, "C_CEPH_MSG_PING")			  \
	V(C_CEPH_MSG_MON_MAP,		     0x0004, "C_CEPH_MSG_MON_MAP")		  \
	V(C_CEPH_MSG_MON_GET_MAP,	     0x0005, "C_CEPH_MSG_MON_GET_MAP")		  \
	V(C_CEPH_MSG_STATFS,		     0x000D, "C_CEPH_MSG_STATFS")		  \
	V(C_CEPH_MSG_STATFS_REPLY,	     0x000E, "C_CEPH_MSG_STATFS_REPLY")		  \
	V(C_CEPH_MSG_MON_SUBSCRIBE,	     0x000F, "C_CEPH_MSG_MON_SUBSCRIBE")	  \
	V(C_CEPH_MSG_MON_SUBSCRIBE_ACK,	     0x0010, "C_CEPH_MSG_MON_SUBSCRIBE_ACK")	  \
	V(C_CEPH_MSG_AUTH,		     0x0011, "C_CEPH_MSG_AUTH")			  \
	V(C_CEPH_MSG_AUTH_REPLY,	     0x0012, "C_CEPH_MSG_AUTH_REPLY")		  \
	V(C_CEPH_MSG_MON_GET_VERSION,	     0x0013, "C_CEPH_MSG_MON_GET_VERSION")	  \
	V(C_CEPH_MSG_MON_GET_VERSION_REPLY,  0x0014, "C_CEPH_MSG_MON_GET_VERSION_REPLY")  \
	V(C_CEPH_MSG_MDS_MAP,		     0x0015, "C_CEPH_MSG_MDS_MAP")		  \
	V(C_CEPH_MSG_CLIENT_SESSION,	     0x0016, "C_CEPH_MSG_CLIENT_SESSION")	  \
	V(C_CEPH_MSG_CLIENT_RECONNECT,	     0x0017, "C_CEPH_MSG_CLIENT_RECONNECT")	  \
	V(C_CEPH_MSG_CLIENT_REQUEST,	     0x0018, "C_CEPH_MSG_CLIENT_REQUEST")	  \
	V(C_CEPH_MSG_CLIENT_REQUEST_FORWARD, 0x0019, "C_CEPH_MSG_CLIENT_REQUEST_FORWARD") \
	V(C_CEPH_MSG_CLIENT_REPLY,	     0x001A, "C_CEPH_MSG_CLIENT_REPLY")		  \
	V(C_MSG_PAXOS,			     0x0028, "C_MSG_PAXOS")			  \
	V(C_CEPH_MSG_OSD_MAP,		     0x0029, "C_CEPH_MSG_OSD_MAP")		  \
	V(C_CEPH_MSG_OSD_OP,		     0x002A, "C_CEPH_MSG_OSD_OP")		  \
	V(C_CEPH_MSG_OSD_OPREPLY,	     0x002B, "C_CEPH_MSG_OSD_OPREPLY")		  \
	V(C_CEPH_MSG_WATCH_NOTIFY,	     0x002C, "C_CEPH_MSG_WATCH_NOTIFY")		  \
	V(C_MSG_FORWARD,		     0x002E, "C_MSG_FORWARD")			  \
	V(C_MSG_ROUTE,			     0x002F, "C_MSG_ROUTE")			  \
	V(C_MSG_POOLOPREPLY,		     0x0030, "C_MSG_POOLOPREPLY")		  \
	V(C_MSG_POOLOP,			     0x0031, "C_MSG_POOLOP")			  \
	V(C_MSG_MON_COMMAND,		     0x0032, "C_MSG_MON_COMMAND")		  \
	V(C_MSG_MON_COMMAND_ACK,	     0x0033, "C_MSG_MON_COMMAND_ACK")		  \
	V(C_MSG_LOG,			     0x0034, "C_MSG_LOG")			  \
	V(C_MSG_LOGACK,			     0x0035, "C_MSG_LOGACK")			  \
	V(C_MSG_MON_OBSERVE,		     0x0036, "C_MSG_MON_OBSERVE")		  \
	V(C_MSG_MON_OBSERVE_NOTIFY,	     0x0037, "C_MSG_MON_OBSERVE_NOTIFY")	  \
	V(C_MSG_CLASS,			     0x0038, "C_MSG_CLASS")			  \
	V(C_MSG_CLASS_ACK,		     0x0039, "C_MSG_CLASS_ACK")			  \
	V(C_MSG_GETPOOLSTATS,		     0x003A, "C_MSG_GETPOOLSTATS")		  \
	V(C_MSG_GETPOOLSTATSREPLY,	     0x003B, "C_MSG_GETPOOLSTATSREPLY")		  \
	V(C_MSG_MON_GLOBAL_ID,		     0x003C, "C_MSG_MON_GLOBAL_ID")		  \
	V(C_CEPH_MSG_PRIO_LOW,		     0x0040, "C_CEPH_MSG_PRIO_LOW")		  \
	V(C_MSG_MON_SCRUB,		     0x0040, "C_MSG_MON_SCRUB")			  \
	V(C_MSG_MON_ELECTION,		     0x0041, "C_MSG_MON_ELECTION")		  \
	V(C_MSG_MON_PAXOS,		     0x0042, "C_MSG_MON_PAXOS")			  \
	V(C_MSG_MON_PROBE,		     0x0043, "C_MSG_MON_PROBE")			  \
	V(C_MSG_MON_JOIN,		     0x0044, "C_MSG_MON_JOIN")			  \
	V(C_MSG_MON_SYNC,		     0x0045, "C_MSG_MON_SYNC")			  \
	V(C_MSG_OSD_PING,		     0x0046, "C_MSG_OSD_PING")			  \
	V(C_MSG_OSD_BOOT,		     0x0047, "C_MSG_OSD_BOOT")			  \
	V(C_MSG_OSD_FAILURE,		     0x0048, "C_MSG_OSD_FAILURE")		  \
	V(C_MSG_OSD_ALIVE,		     0x0049, "C_MSG_OSD_ALIVE")			  \
	V(C_MSG_OSD_MARK_ME_DOWN,	     0x004A, "C_MSG_OSD_MARK_ME_DOWN")		  \
	V(C_MSG_OSD_SUBOP,		     0x004C, "C_MSG_OSD_SUBOP")			  \
	V(C_MSG_OSD_SUBOPREPLY,		     0x004D, "C_MSG_OSD_SUBOPREPLY")		  \
	V(C_MSG_OSD_PGTEMP,		     0x004E, "C_MSG_OSD_PGTEMP")		  \
	V(C_MSG_OSD_PG_NOTIFY,		     0x0050, "C_MSG_OSD_PG_NOTIFY")		  \
	V(C_MSG_OSD_PG_QUERY,		     0x0051, "C_MSG_OSD_PG_QUERY")		  \
	V(C_MSG_OSD_PG_SUMMARY,		     0x0052, "C_MSG_OSD_PG_SUMMARY")		  \
	V(C_MSG_OSD_PG_LOG,		     0x0053, "C_MSG_OSD_PG_LOG")		  \
	V(C_MSG_OSD_PG_REMOVE,		     0x0054, "C_MSG_OSD_PG_REMOVE")		  \
	V(C_MSG_OSD_PG_INFO,		     0x0055, "C_MSG_OSD_PG_INFO")		  \
	V(C_MSG_OSD_PG_TRIM,		     0x0056, "C_MSG_OSD_PG_TRIM")		  \
	V(C_MSG_PGSTATS,		     0x0057, "C_MSG_PGSTATS")			  \
	V(C_MSG_PGSTATSACK,		     0x0058, "C_MSG_PGSTATSACK")		  \
	V(C_MSG_OSD_PG_CREATE,		     0x0059, "C_MSG_OSD_PG_CREATE")		  \
	V(C_MSG_REMOVE_SNAPS,		     0x005A, "C_MSG_REMOVE_SNAPS")		  \
	V(C_MSG_OSD_SCRUB,		     0x005B, "C_MSG_OSD_SCRUB")			  \
	V(C_MSG_OSD_PG_MISSING,		     0x005C, "C_MSG_OSD_PG_MISSING")		  \
	V(C_MSG_OSD_REP_SCRUB,		     0x005D, "C_MSG_OSD_REP_SCRUB")		  \
	V(C_MSG_OSD_PG_SCAN,		     0x005E, "C_MSG_OSD_PG_SCAN")		  \
	V(C_MSG_OSD_PG_BACKFILL,	     0x005F, "C_MSG_OSD_PG_BACKFILL")		  \
	V(C_MSG_COMMAND,		     0x0061, "C_MSG_COMMAND")			  \
	V(C_MSG_COMMAND_REPLY,		     0x0062, "C_MSG_COMMAND_REPLY")		  \
	V(C_MSG_OSD_BACKFILL_RESERVE,	     0x0063, "C_MSG_OSD_BACKFILL_RESERVE")	  \
	V(C_MSG_MDS_BEACON,		     0x0064, "C_MSG_MDS_BEACON")		  \
	V(C_MSG_MDS_SLAVE_REQUEST,	     0x0065, "C_MSG_MDS_SLAVE_REQUEST")		  \
	V(C_MSG_MDS_TABLE_REQUEST,	     0x0066, "C_MSG_MDS_TABLE_REQUEST")		  \
	V(C_MSG_OSD_PG_PUSH,		     0x0069, "C_MSG_OSD_PG_PUSH")		  \
	V(C_MSG_OSD_PG_PULL,		     0x006A, "C_MSG_OSD_PG_PULL")		  \
	V(C_MSG_OSD_PG_PUSH_REPLY,	     0x006B, "C_MSG_OSD_PG_PUSH_REPLY")		  \
	V(C_MSG_OSD_EC_WRITE,		     0x006C, "C_MSG_OSD_EC_WRITE")		  \
	V(C_MSG_OSD_EC_WRITE_REPLY,	     0x006D, "C_MSG_OSD_EC_WRITE_REPLY")	  \
	V(C_MSG_OSD_EC_READ,		     0x006E, "C_MSG_OSD_EC_READ")		  \
	V(C_MSG_OSD_EC_READ_REPLY,	     0x006F, "C_MSG_OSD_EC_READ_REPLY")		  \
	V(C_CEPH_MSG_PRIO_DEFAULT,	     0x007F, "C_CEPH_MSG_PRIO_DEFAULT")		  \
	V(C_MSG_OSD_RECOVERY_RESERVE,	     0x0096, "C_MSG_OSD_RECOVERY_RESERVE")	  \
	V(C_CEPH_MSG_PRIO_HIGH,		     0x00C4, "C_CEPH_MSG_PRIO_HIGH")		  \
	V(C_CEPH_MSG_PRIO_HIGHEST,	     0x00FF, "C_CEPH_MSG_PRIO_HIGHEST")		  \
	V(C_MSG_MDS_RESOLVE,		     0x0200, "C_MSG_MDS_RESOLVE")		  \
	V(C_MSG_MDS_RESOLVEACK,		     0x0201, "C_MSG_MDS_RESOLVEACK")		  \
	V(C_MSG_MDS_CACHEREJOIN,	     0x0202, "C_MSG_MDS_CACHEREJOIN")		  \
	V(C_MSG_MDS_DISCOVER,		     0x0203, "C_MSG_MDS_DISCOVER")		  \
	V(C_MSG_MDS_DISCOVERREPLY,	     0x0204, "C_MSG_MDS_DISCOVERREPLY")		  \
	V(C_MSG_MDS_INODEUPDATE,	     0x0205, "C_MSG_MDS_INODEUPDATE")		  \
	V(C_MSG_MDS_DIRUPDATE,		     0x0206, "C_MSG_MDS_DIRUPDATE")		  \
	V(C_MSG_MDS_CACHEEXPIRE,	     0x0207, "C_MSG_MDS_CACHEEXPIRE")		  \
	V(C_MSG_MDS_DENTRYUNLINK,	     0x0208, "C_MSG_MDS_DENTRYUNLINK")		  \
	V(C_MSG_MDS_FRAGMENTNOTIFY,	     0x0209, "C_MSG_MDS_FRAGMENTNOTIFY")	  \
	V(C_MSG_MDS_OFFLOAD_TARGETS,	     0x020A, "C_MSG_MDS_OFFLOAD_TARGETS")	  \
	V(C_MSG_MDS_DENTRYLINK,		     0x020C, "C_MSG_MDS_DENTRYLINK")		  \
	V(C_MSG_MDS_FINDINO,		     0x020D, "C_MSG_MDS_FINDINO")		  \
	V(C_MSG_MDS_FINDINOREPLY,	     0x020E, "C_MSG_MDS_FINDINOREPLY")		  \
	V(C_MSG_MDS_OPENINO,		     0x020F, "C_MSG_MDS_OPENINO")		  \
	V(C_MSG_MDS_OPENINOREPLY,	     0x0210, "C_MSG_MDS_OPENINOREPLY")		  \
	V(C_MSG_MDS_LOCK,		     0x0300, "C_MSG_MDS_LOCK")			  \
	V(C_MSG_MDS_INODEFILECAPS,	     0x0301, "C_MSG_MDS_INODEFILECAPS")		  \
	V(C_CEPH_MSG_CLIENT_CAPS,	     0x0310, "C_CEPH_MSG_CLIENT_CAPS")		  \
	V(C_CEPH_MSG_CLIENT_LEASE,	     0x0311, "C_CEPH_MSG_CLIENT_LEASE")		  \
	V(C_CEPH_MSG_CLIENT_SNAP,	     0x0312, "C_CEPH_MSG_CLIENT_SNAP")		  \
	V(C_CEPH_MSG_CLIENT_CAPRELEASE,	     0x0313, "C_CEPH_MSG_CLIENT_CAPRELEASE")	  \
	V(C_MSG_MDS_EXPORTDIRDISCOVER,	     0x0449, "C_MSG_MDS_EXPORTDIRDISCOVER")	  \
	V(C_MSG_MDS_EXPORTDIRDISCOVERACK,    0x0450, "C_MSG_MDS_EXPORTDIRDISCOVERACK")	  \
	V(C_MSG_MDS_EXPORTDIRCANCEL,	     0x0451, "C_MSG_MDS_EXPORTDIRCANCEL")	  \
	V(C_MSG_MDS_EXPORTDIRPREP,	     0x0452, "C_MSG_MDS_EXPORTDIRPREP")		  \
	V(C_MSG_MDS_EXPORTDIRPREPACK,	     0x0453, "C_MSG_MDS_EXPORTDIRPREPACK")	  \
	V(C_MSG_MDS_EXPORTDIRWARNING,	     0x0454, "C_MSG_MDS_EXPORTDIRWARNING")	  \
	V(C_MSG_MDS_EXPORTDIRWARNINGACK,     0x0455, "C_MSG_MDS_EXPORTDIRWARNINGACK")	  \
	V(C_MSG_MDS_EXPORTDIR,		     0x0456, "C_MSG_MDS_EXPORTDIR")		  \
	V(C_MSG_MDS_EXPORTDIRACK,	     0x0457, "C_MSG_MDS_EXPORTDIRACK")		  \
	V(C_MSG_MDS_EXPORTDIRNOTIFY,	     0x0458, "C_MSG_MDS_EXPORTDIRNOTIFY")	  \
	V(C_MSG_MDS_EXPORTDIRNOTIFYACK,	     0x0459, "C_MSG_MDS_EXPORTDIRNOTIFYACK")	  \
	V(C_MSG_MDS_EXPORTDIRFINISH,	     0x0460, "C_MSG_MDS_EXPORTDIRFINISH")	  \
	V(C_MSG_MDS_EXPORTCAPS,		     0x0470, "C_MSG_MDS_EXPORTCAPS")		  \
	V(C_MSG_MDS_EXPORTCAPSACK,	     0x0471, "C_MSG_MDS_EXPORTCAPSACK")		  \
	V(C_MSG_MDS_HEARTBEAT,		     0x0500, "C_MSG_MDS_HEARTBEAT")		  \
	V(C_MSG_TIMECHECK,		     0x0600, "C_MSG_TIMECHECK")			  \
	V(C_MSG_MON_HEALTH,		     0x0601, "C_MSG_MON_HEALTH")

C_MAKE_STRINGS_EXT(c_msg_type, 4)

#define c_osd_optype_strings_VALUE_STRING_LIST(V) \
	/*** Raw Codes ***/												\
	V(C_OSD_OP_TYPE_LOCK,  0x0100, "C_OSD_OP_TYPE_LOCK")								\
	V(C_OSD_OP_TYPE_DATA,  0x0200, "C_OSD_OP_TYPE_DATA")								\
	V(C_OSD_OP_TYPE_ATTR,  0x0300, "C_OSD_OP_TYPE_ATTR")								\
	V(C_OSD_OP_TYPE_EXEC,  0x0400, "C_OSD_OP_TYPE_EXEC")								\
	V(C_OSD_OP_TYPE_PG,    0x0500, "C_OSD_OP_TYPE_PG")								\
	V(C_OSD_OP_TYPE_MULTI, 0x0600, "C_OSD_OP_TYPE_MULTI") /* multiobject */						\
	V(C_OSD_OP_TYPE,       0x0f00, "C_OSD_OP_TYPE")									\
															\
	/*** Sorted by value, keep it that way. ***/									\
	V(C_OSD_OP_MODE_RD,	       0x1000,						 "C_OSD_OP_MODE_RD")		\
	V(C_OSD_OP_READ,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x01, "C_OSD_OP_READ")		\
	V(C_OSD_OP_STAT,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x02, "C_OSD_OP_STAT")		\
	V(C_OSD_OP_MAPEXT,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x03, "C_OSD_OP_MAPEXT")		\
	V(C_OSD_OP_MASKTRUNC,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x04, "C_OSD_OP_MASKTRUNC")		\
	V(C_OSD_OP_SPARSE_READ,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x05, "C_OSD_OP_SPARSE_READ")	\
	V(C_OSD_OP_NOTIFY,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x06, "C_OSD_OP_NOTIFY")		\
	V(C_OSD_OP_NOTIFY_ACK,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x07, "C_OSD_OP_NOTIFY_ACK")		\
	V(C_OSD_OP_ASSERT_VER,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x08, "C_OSD_OP_ASSERT_VER")		\
	V(C_OSD_OP_LIST_WATCHERS,      C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x09, "C_OSD_OP_LIST_WATCHERS")	\
	V(C_OSD_OP_LIST_SNAPS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x0A, "C_OSD_OP_LIST_SNAPS")		\
	V(C_OSD_OP_SYNC_READ,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x0B, "C_OSD_OP_SYNC_READ")		\
	V(C_OSD_OP_TMAPGET,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x0C, "C_OSD_OP_TMAPGET")		\
	V(C_OSD_OP_OMAPGETKEYS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x11, "C_OSD_OP_OMAPGETKEYS")	\
	V(C_OSD_OP_OMAPGETVALS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x12, "C_OSD_OP_OMAPGETVALS")	\
	V(C_OSD_OP_OMAPGETHEADER,      C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x13, "C_OSD_OP_OMAPGETHEADER")	\
	V(C_OSD_OP_OMAPGETVALSBYKEYS,  C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x14, "C_OSD_OP_OMAPGETVALSBYKEYS")	\
	V(C_OSD_OP_OMAP_CMP,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x19, "C_OSD_OP_OMAP_CMP")		\
	V(C_OSD_OP_COPY_GET_CLASSIC,   C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x1B, "C_OSD_OP_COPY_GET_CLASSIC")	\
	V(C_OSD_OP_ISDIRTY,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x1D, "C_OSD_OP_ISDIRTY")		\
	V(C_OSD_OP_COPY_GET,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_DATA	 | 0x1E, "C_OSD_OP_COPY_GET")		\
	V(C_OSD_OP_GETXATTR,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_ATTR	 | 0x01, "C_OSD_OP_GETXATTR")		\
	V(C_OSD_OP_GETXATTRS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_ATTR	 | 0x02, "C_OSD_OP_GETXATTRS")		\
	V(C_OSD_OP_CMPXATTR,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_ATTR	 | 0x03, "C_OSD_OP_CMPXATTR")		\
	V(C_OSD_OP_CALL,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_EXEC	 | 0x01, "C_OSD_OP_CALL")		\
	V(C_OSD_OP_PGLS,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_PG	 | 0x01, "C_OSD_OP_PGLS")		\
	V(C_OSD_OP_PGLS_FILTER,	       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_PG	 | 0x02, "C_OSD_OP_PGLS_FILTER")	\
	V(C_OSD_OP_PG_HITSET_LS,       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_PG	 | 0x03, "C_OSD_OP_PG_HITSET_LS")	\
	V(C_OSD_OP_PG_HITSET_GET,      C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_PG	 | 0x04, "C_OSD_OP_PG_HITSET_GET")	\
	V(C_OSD_OP_ASSERT_SRC_VERSION, C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_MULTI | 0x02, "C_OSD_OP_ASSERT_SRC_VERSION") \
	V(C_OSD_OP_SRC_CMPXATTR,       C_OSD_OP_MODE_RD	   | C_OSD_OP_TYPE_MULTI | 0x03, "C_OSD_OP_SRC_CMPXATTR")	\
	V(C_OSD_OP_MODE_WR,	       0x2000,						 "C_OSD_OP_MODE_WR")		\
	V(C_OSD_OP_WRLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x01, "C_OSD_OP_WRLOCK")		\
	V(C_OSD_OP_WRUNLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x02, "C_OSD_OP_WRUNLOCK")		\
	V(C_OSD_OP_RDLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x03, "C_OSD_OP_RDLOCK")		\
	V(C_OSD_OP_RDUNLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x04, "C_OSD_OP_RDUNLOCK")		\
	V(C_OSD_OP_UPLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x05, "C_OSD_OP_UPLOCK")		\
	V(C_OSD_OP_DNLOCK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_LOCK	 | 0x06, "C_OSD_OP_DNLOCK")		\
	V(C_OSD_OP_WRITE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x01, "C_OSD_OP_WRITE")		\
	V(C_OSD_OP_WRITEFULL,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x02, "C_OSD_OP_WRITEFULL")		\
	V(C_OSD_OP_TRUNCATE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x03, "C_OSD_OP_TRUNCATE")		\
	V(C_OSD_OP_ZERO,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x04, "C_OSD_OP_ZERO")		\
	V(C_OSD_OP_DELETE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x05, "C_OSD_OP_DELETE")		\
	V(C_OSD_OP_APPEND,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x06, "C_OSD_OP_APPEND")		\
	V(C_OSD_OP_STARTSYNC,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x07, "C_OSD_OP_STARTSYNC")		\
	V(C_OSD_OP_SETTRUNC,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x08, "C_OSD_OP_SETTRUNC")		\
	V(C_OSD_OP_TRIMTRUNC,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x09, "C_OSD_OP_TRIMTRUNC")		\
	V(C_OSD_OP_TMAPPUT,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x0B, "C_OSD_OP_TMAPPUT")		\
	V(C_OSD_OP_CREATE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x0D, "C_OSD_OP_CREATE")		\
	V(C_OSD_OP_ROLLBACK,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x0E, "C_OSD_OP_ROLLBACK")		\
	V(C_OSD_OP_WATCH,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x0F, "C_OSD_OP_WATCH")		\
	V(C_OSD_OP_OMAPSETVALS,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x15, "C_OSD_OP_OMAPSETVALS")	\
	V(C_OSD_OP_OMAPSETHEADER,      C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x16, "C_OSD_OP_OMAPSETHEADER")	\
	V(C_OSD_OP_OMAPCLEAR,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x17, "C_OSD_OP_OMAPCLEAR")		\
	V(C_OSD_OP_OMAPRMKEYS,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x18, "C_OSD_OP_OMAPRMKEYS")		\
	V(C_OSD_OP_COPY_FROM,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x1A, "C_OSD_OP_COPY_FROM")		\
	V(C_OSD_OP_UNDIRTY,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x1C, "C_OSD_OP_UNDIRTY")		\
	V(C_OSD_OP_SETALLOCHINT,       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_DATA	 | 0x23, "C_OSD_OP_SETALLOCHINT")	\
	V(C_OSD_OP_SETXATTR,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_ATTR	 | 0x01, "C_OSD_OP_SETXATTR")		\
	V(C_OSD_OP_SETXATTRS,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_ATTR	 | 0x02, "C_OSD_OP_SETXATTRS")		\
	V(C_OSD_OP_RESETXATTRS,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_ATTR	 | 0x03, "C_OSD_OP_RESETXATTRS")	\
	V(C_OSD_OP_RMXATTR,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_ATTR	 | 0x04, "C_OSD_OP_RMXATTR")		\
	V(C_OSD_OP_CLONERANGE,	       C_OSD_OP_MODE_WR	   | C_OSD_OP_TYPE_MULTI | 0x01, "C_OSD_OP_CLONERANGE")		\
	V(C_OSD_OP_MODE_RMW,	       0x3000,						 "C_OSD_OP_MODE_RMW")		\
	V(C_OSD_OP_TMAPUP,	       C_OSD_OP_MODE_RMW   | C_OSD_OP_TYPE_DATA	 | 0x0A, "C_OSD_OP_TMAPUP")		\
	V(C_OSD_OP_TMAP2OMAP,	       C_OSD_OP_MODE_RMW   | C_OSD_OP_TYPE_DATA	 | 0x22, "C_OSD_OP_TMAP2OMAP")		\
	V(C_OSD_OP_MODE_SUB,	       0x4000,						 "C_OSD_OP_MODE_SUB")		\
	V(C_OSD_OP_PULL,	       C_OSD_OP_MODE_SUB			 | 0x01, "C_OSD_OP_PULL")		\
	V(C_OSD_OP_PUSH,	       C_OSD_OP_MODE_SUB			 | 0x02, "C_OSD_OP_PUSH")		\
	V(C_OSD_OP_BALANCEREADS,       C_OSD_OP_MODE_SUB			 | 0x03, "C_OSD_OP_BALANCEREADS")	\
	V(C_OSD_OP_UNBALANCEREADS,     C_OSD_OP_MODE_SUB			 | 0x04, "C_OSD_OP_UNBALANCEREADS")	\
	V(C_OSD_OP_SCRUB,	       C_OSD_OP_MODE_SUB			 | 0x05, "C_OSD_OP_SCRUB")		\
	V(C_OSD_OP_SCRUB_RESERVE,      C_OSD_OP_MODE_SUB			 | 0x06, "C_OSD_OP_SCRUB_RESERVE")	\
	V(C_OSD_OP_SCRUB_UNRESERVE,    C_OSD_OP_MODE_SUB			 | 0x07, "C_OSD_OP_SCRUB_UNRESERVE")	\
	V(C_OSD_OP_SCRUB_STOP,	       C_OSD_OP_MODE_SUB			 | 0x08, "C_OSD_OP_SCRUB_STOP")		\
	V(C_OSD_OP_SCRUB_MAP,	       C_OSD_OP_MODE_SUB			 | 0x09, "C_OSD_OP_SCRUB_MAP")		\
	V(C_OSD_OP_MODE_CACHE,	       0x8000,						 "C_OSD_OP_MODE_CACHE")		\
	V(C_OSD_OP_CACHE_FLUSH,	       C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA	 | 0x1F, "C_OSD_OP_CACHE_FLUSH")	\
	V(C_OSD_OP_CACHE_EVICT,	       C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA	 | 0x20, "C_OSD_OP_CACHE_EVICT")	\
	V(C_OSD_OP_CACHE_TRY_FLUSH,    C_OSD_OP_MODE_CACHE | C_OSD_OP_TYPE_DATA	 | 0x21, "C_OSD_OP_CACHE_TRY_FLUSH")	\
	V(C_OSD_OP_MODE,	       0xf000,						 "C_OSD_OP_MODE")

C_MAKE_STRINGS_EXT(c_osd_optype, 4)

#define c_poolop_type_strings_VALUE_STRING_LIST(V) \
	V(POOL_OP_CREATE,		 0x01, "Create")		    \
	V(POOL_OP_DELETE,		 0x02, "Delete")		    \
	V(POOL_OP_AUID_CHANGE,		 0x03, "Change Owner")		    \
	V(POOL_OP_CREATE_SNAP,		 0x11, "Create Snapshot")	    \
	V(POOL_OP_DELETE_SNAP,		 0x12, "Delete Snapshot")	    \
	V(POOL_OP_CREATE_UNMANAGED_SNAP, 0x21, "Create Unmanaged Snapshot") \
	V(POOL_OP_DELETE_UNMANAGED_SNAP, 0x22, "Delete Unmanaged Snapshot")

C_MAKE_STRINGS(c_poolop_type, 2)

#define c_mon_election_type_strings_VALUE_STRING_LIST(V) \
	V(C_MON_ELECTION_PROPOSE, 0x00000001, "Propose")	      \
	V(C_MON_ELECTION_ACK,	  0x00000002, "Acknowledge")	      \
	V(C_MON_ELECTION_NAK,	  0x00000003, "Negative Acknowledge") \
	V(C_MON_ELECTION_VICTORY, 0x00000004, "Victory")

C_MAKE_STRINGS_EXT(c_mon_election_type, 8)

#define c_mon_paxos_op_strings_VALUE_STRING_LIST(V) \
	V(C_MON_PAXOS_COLLECT,	0x00000001, "Propose Round")	    \
	V(C_MON_PAXOS_LAST,	0x00000002, "Accept Round")	    \
	V(C_MON_PAXOS_BEGIN,	0x00000003, "Propose Value")	    \
	V(C_MON_PAXOS_ACCEPT,	0x00000004, "Accept Value")	    \
	V(C_MON_PAXOS_COMMIT,	0x00000005, "Commit")		    \
	V(C_MON_PAXOS_LEASE,	0x00000006, "Extend Peon Lease")    \
	V(C_MON_PAXOS_LEASEACK, 0x00000007, "Lease Acknowledgment")

C_MAKE_STRINGS_EXT(c_mon_paxos_op, 8)

#define c_mon_probe_type_strings_VALUE_STRING_LIST(V) \
	V(C_MON_PROBE_PROBE,		0x00000001, "Probe")		\
	V(C_MON_PROBE_REPLY,		0x00000002, "Reply")		\
	V(C_MON_PROBE_SLURP,		0x00000003, "Slurp")		\
	V(C_MON_PROBE_SLURP_LATEST,	0x00000004, "Slurp Latest")	\
	V(C_MON_PROBE_DATA,		0x00000005, "Data")		\
	V(C_MON_PROBE_MISSING_FEATURES, 0x00000006, "Missing Features")

C_MAKE_STRINGS_EXT(c_mon_probe_type, 8)

#define c_osd_ping_op_strings_VALUE_STRING_LIST(V) \
	V(C_TIMECHECK_HEARTBEAT,       0x00, "Heartbeat")	 \
	V(C_TIMECHECK_START_HEARTBEAT, 0x01, "Start Heartbeats") \
	V(C_TIMECHECK_YOU_DIED,	       0x02, "You Died")	 \
	V(C_TIMECHECK_STOP_HEARTBEAT,  0x03, "Stop Heartbeats")	 \
	V(C_TIMECHECK_PING,	       0x04, "Ping")		 \
	V(C_TIMECHECK_PING_REPLY,      0x05, "Pong")

C_MAKE_STRINGS_EXT(c_osd_ping_op, 2)

#define c_session_op_type_strings_VALUE_STRING_LIST(V) \
	V(C_SESSION_REQUEST_OPEN,      0x00000000, "Request Open")	 \
	V(C_SESSION_OPEN,	       0x00000001, "Open")		 \
	V(C_SESSION_REQUEST_CLOSE,     0x00000002, "Request Close")	 \
	V(C_SESSION_CLOSE,	       0x00000003, "Close")		 \
	V(C_SESSION_REQUEST_RENEWCAPS, 0x00000004, "Request Renew Caps") \
	V(C_SESSION_RENEWCAPS,	       0x00000005, "Renew Caps")	 \
	V(C_SESSION_STALE,	       0x00000006, "Stale")		 \
	V(C_SESSION_RECALL_STATE,      0x00000007, "Recall Stale")	 \
	V(C_SESSION_FLUSHMSG,	       0x00000008, "Flush Message")	 \
	V(C_SESSION_FLUSHMSG_ACK,      0x00000009, "Flush Message Ack")

C_MAKE_STRINGS_EXT(c_session_op_type, 8)

#define c_mds_op_type_strings_VALUE_STRING_LIST(V) \
	V(C_MDS_OP_LOOKUP,	 0x00000100, "MDS_OP_LOOKUP")	    \
	V(C_MDS_OP_GETATTR,	 0x00000101, "MDS_OP_GETATTR")	    \
	V(C_MDS_OP_LOOKUPHASH,	 0x00000102, "MDS_OP_LOOKUPHASH")   \
	V(C_MDS_OP_LOOKUPPARENT, 0x00000103, "MDS_OP_LOOKUPPARENT") \
	V(C_MDS_OP_LOOKUPINO,	 0x00000104, "MDS_OP_LOOKUPINO")    \
	V(C_MDS_OP_LOOKUPNAME,	 0x00000105, "MDS_OP_LOOKUPNAME")   \
	V(C_MDS_OP_GETFILELOCK,	 0x00000110, "MDS_OP_GETFILELOCK")  \
	V(C_MDS_OP_OPEN,	 0x00000302, "MDS_OP_OPEN")	    \
	V(C_MDS_OP_READDIR,	 0x00000305, "MDS_OP_READDIR")	    \
	V(C_MDS_OP_LOOKUPSNAP,	 0x00000400, "MDS_OP_LOOKUPSNAP")   \
	V(C_MDS_OP_LSSNAP,	 0x00000402, "MDS_OP_LSSNAP")	    \
	V(C_MDS_OP_WRITE,	 0x00001000, "MDS_OP_WRITE")	    \
	V(C_MDS_OP_SETXATTR,	 0x00001105, "MDS_OP_SETXATTR")	    \
	V(C_MDS_OP_RMXATTR,	 0x00001106, "MDS_OP_RMXATTR")	    \
	V(C_MDS_OP_SETLAYOUT,	 0x00001107, "MDS_OP_SETLAYOUT")    \
	V(C_MDS_OP_SETATTR,	 0x00001108, "MDS_OP_SETATTR")	    \
	V(C_MDS_OP_SETFILELOCK,	 0x00001109, "MDS_OP_SETFILELOCK")  \
	V(C_MDS_OP_SETDIRLAYOUT, 0x0000110a, "MDS_OP_SETDIRLAYOUT") \
	V(C_MDS_OP_MKNOD,	 0x00001201, "MDS_OP_MKNOD")	    \
	V(C_MDS_OP_LINK,	 0x00001202, "MDS_OP_LINK")	    \
	V(C_MDS_OP_UNLINK,	 0x00001203, "MDS_OP_UNLINK")	    \
	V(C_MDS_OP_RENAME,	 0x00001204, "MDS_OP_RENAME")	    \
	V(C_MDS_OP_MKDIR,	 0x00001220, "MDS_OP_MKDIR")	    \
	V(C_MDS_OP_RMDIR,	 0x00001221, "MDS_OP_RMDIR")	    \
	V(C_MDS_OP_SYMLINK,	 0x00001222, "MDS_OP_SYMLINK")	    \
	V(C_MDS_OP_CREATE,	 0x00001301, "MDS_OP_CREATE")	    \
	V(C_MDS_OP_MKSNAP,	 0x00001400, "MDS_OP_MKSNAP")	    \
	V(C_MDS_OP_RMSNAP,	 0x00001401, "MDS_OP_RMSNAP")	    \
	V(C_MDS_OP_FRAGMENTDIR,	 0x00001500, "MDS_OP_FRAGMENTDIR")  \
	V(C_MDS_OP_EXPORTDIR,	 0x00001501, "MDS_OP_EXPORTDIR")

C_MAKE_STRINGS_EXT(c_mds_op_type, 8)

#define c_cap_op_type_strings_VALUE_STRING_LIST(V) \
	V(C_CAP_OP_GRANT,	  0x00000000, "mds->client grant")		      \
	V(C_CAP_OP_REVOKE,	  0x00000001, "mds->client revoke")		      \
	V(C_CAP_OP_TRUNC,	  0x00000002, "mds->client trunc notify")	      \
	V(C_CAP_OP_EXPORT,	  0x00000003, "mds has exported the cap")	      \
	V(C_CAP_OP_IMPORT,	  0x00000004, "mds has imported the cap")	      \
	V(C_CAP_OP_UPDATE,	  0x00000005, "client->mds update")		      \
	V(C_CAP_OP_DROP,	  0x00000006, "client->mds drop cap bits")	      \
	V(C_CAP_OP_FLUSH,	  0x00000007, "client->mds cap writeback")	      \
	V(C_CAP_OP_FLUSH_ACK,	  0x00000008, "mds->client flushed")		      \
	V(C_CAP_OP_FLUSHSNAP,	  0x00000009, "client->mds flush snapped metadata")   \
	V(C_CAP_OP_FLUSHSNAP_ACK, 0x0000000A, "mds->client flushed snapped metadata") \
	V(C_CAP_OP_RELEASE,	  0x0000000B, "client->mds release (clean) cap")      \
	V(C_CAP_OP_RENEW,	  0x0000000C, "client->mds renewal request")

C_MAKE_STRINGS_EXT(c_cap_op_type, 8)

#define c_timecheck_op_strings_VALUE_STRING_LIST(V) \
	V(C_TIMECHECK_OP_PING,	 0x00000001, "Ping")   \
	V(C_TIMECHECK_OP_PONG,	 0x00000002, "Pong")   \
	V(C_TIMECHECK_OP_REPORT, 0x00000003, "Report")

C_MAKE_STRINGS_EXT(c_timecheck_op, 8)

#define c_pgpool_type_strings_VALUE_STRING_LIST(V) \
	V(C_PGPOOL_REPLICATED, 0x01, "Replicated")    \
	V(C_PGPOOL_RAID4,      0x02, "Raid4")	      \
	V(C_PGPOOL_ERASURE,    0x03, "Erasure-coded")

C_MAKE_STRINGS(c_pgpool_type, 2)

#define c_pgpool_cachemode_strings_VALUE_STRING_LIST(V) \
	V(C_PGPOOL_CACHEMODE_NONE,	0x00, "No caching")						\
	V(C_PGPOOL_CACHEMODE_WRITEBACK, 0x01, "Write to cache, flush later")				\
	V(C_PGPOOL_CACHEMODE_FORWARD,	0x02, "Forward if not in cache")				\
	V(C_PGPOOL_CACHEMODE_READONLY,	0x03, "Handle reads, forward writes [not strongly consistent]")

C_MAKE_STRINGS_EXT(c_pgpool_cachemode, 2)

#define c_hitset_params_type_strings_VALUE_STRING_LIST(V) \
	V(C_HITSET_PARAMS_TYPE_NONE,		0x00, "None")		 \
	V(C_HITSET_PARAMS_TYPE_EXPLICIT_HASH,	0x01, "Explicit Hash")	 \
	V(C_HITSET_PARAMS_TYPE_EXPLICIT_OBJECT, 0x02, "Explicit Object") \
	V(C_HITSET_PARAMS_TYPE_BLOOM,		0x03, "Bloom Filter")

C_MAKE_STRINGS_EXT(c_hitset_params_type, 2)

#define c_auth_proto_strings_VALUE_STRING_LIST(V) \
	V(C_AUTH_PROTO_UNKNOWN, 0x00, "Undecided") \
	V(C_AUTH_PROTO_NONE,	0x01, "None")	   \
	V(C_AUTH_PROTO_CEPHX,	0x02, "CephX")

C_MAKE_STRINGS(c_auth_proto, 2)

#define c_cephx_req_type_strings_VALUE_STRING_LIST(V) \
	V(C_CEPHX_REQ_AUTH_SESSIONKEY, 0x0100, "Get Auth Session Key")		 \
	V(C_CEPHX_REQ_PRINCIPAL_SESSIONKEY, 0x0200, "Get Principal Session Key") \
	V(C_CEPHX_REQ_ROTATINGKEY, 0x0400, "Get Rotating Key")

C_MAKE_STRINGS(c_cephx_req_type, 4)

/** Node type database. */
#define c_node_type_strings_LIST(V, W) \
	V(C_NODE_TYPE_UNKNOWN, 0x00, W("Unknown",		"unknown")) \
	V(C_NODE_TYPE_MON,     0x01, W("Monitor",		"mon"	 )) \
	V(C_NODE_TYPE_MDS,     0x02, W("Meta Data Server",	"mds"	 )) \
	V(C_NODE_TYPE_OSD,     0x04, W("Object Storage Daemon", "osd"	 )) \
	V(C_NODE_TYPE_CLIENT,  0x08, W("Client",		"client" )) \
	V(C_NODE_TYPE_AUTH,    0x20, W("Authentication Server", "auth"	 ))

#define C_EXTRACT_1(a, b) a
#define C_EXTRACT_2(a, b) b

/** Extract the full names to create a value_string list. */
#define c_node_type_strings_VALUE_STRING_LIST(V) \
	c_node_type_strings_LIST(V, C_EXTRACT_1)

C_MAKE_STRINGS(c_node_type, 2)

/** Extract the abbreviations to create a value_string list. */
#define c_node_type_abbr_strings_VALUE_STRING_LIST(V) \
	c_node_type_strings_LIST(V, C_EXTRACT_2)

VALUE_STRING_ARRAY(c_node_type_abbr_strings);

static
const char *c_node_type_abbr_string(c_node_type val)
{
	return val_to_str(val, c_node_type_abbr_strings, "Unknown (0x%02x)");
}

#define C_MON_SUB_FLAG_ONETIME  0x01

typedef enum _c_state {
	C_STATE_NEW,
	C_STATE_OPEN,
	C_STATE_SEQ /* Waiting for sequence number. */
} c_state;

typedef struct _c_node_name {
	const char *slug;
	const char *type_str;
	guint64 id;
	c_node_type type;
} c_entityname;

static
void c_node_name_init(c_entityname *d)
{
	d->slug	    = NULL;
	d->type_str = NULL;
	d->id	    = G_MAXUINT64;
	d->type	    = C_NODE_TYPE_UNKNOWN;
}

typedef struct _c_node {
	address addr;
	c_entityname name;
	c_state state;
	guint16 port;
} c_node;

static
void c_node_init(c_node *n)
{
	c_node_name_init(&n->name);
	n->port = 0xFFFF;
	n->state = C_STATE_NEW;
}

static
c_node *c_node_copy(c_node *src, c_node *dst)
{
	dst->name = src->name;
	copy_address_shallow(&dst->addr, &src->addr);
	dst->port = src->port;
	dst->state = src->state;

	return dst;
}

typedef struct _c_conv_data {
	c_node client; /* The node that initiated this connection. */
	c_node server; /* The other node. */
} c_conv_data;

static
void c_conv_data_init(c_conv_data *d)
{
	c_node_init(&d->client);
	c_node_init(&d->server);
}

static
c_conv_data *c_conv_data_copy(c_conv_data *src, c_conv_data *dst)
{
	c_node_copy(&src->client, &dst->client);
	c_node_copy(&src->server, &dst->server);

	return dst;
}

static
c_conv_data *c_conv_data_clone(c_conv_data *d)
{
	return c_conv_data_copy(d, wmem_new(wmem_file_scope(), c_conv_data));
}

static
c_conv_data *c_conv_data_new(void)
{
	c_conv_data *r;
	r = wmem_new(wmem_file_scope(), c_conv_data);
	c_conv_data_init(r);
	return r;
}

typedef struct _c_header {
	guint64 seq;
	guint64 tid;
	c_msg_type type;
	guint16 ver;
	guint16 priority;
	c_entityname src;
} c_header;

static
void c_header_init(c_header *h)
{
	h->seq	    = 0;
	h->tid	    = 0;
	h->type	    = C_MSG_UNKNOWN;
	h->priority = 0;
	h->ver	    = 0;
	memset(&h->src, 0, sizeof(h->src));
}

typedef struct _c_pkt_data {
	conversation_t *conv;	/* The wireshark conversation. */
	c_conv_data *convd;	/* The Ceph conversation data. */
	c_node *src;		/* The node in convd that sent this message. */
	c_node *dst;		/* The node in convd that is receiving this message. */

	proto_item  *item_root;	/* The root proto_item for the message. */
	packet_info *pinfo;

	c_header header;	/* The MSG header. */
} c_pkt_data;

/** Initialize the packet data.
 *
 * The packet data structure holds all of the Ceph-specific data that is needed
 * to dissect the protocol.  This function initializes the structure.
 *
 * This function grabs the appropriate data either from previous packets in the
 * dissection, or creating a new data for new conversations.
 *
 * Lastly this function saves the state before every packet so that if we are
 * asked to dissect the same packet again the same state will be used as when
 * it was dissected initially.
 */
static void
c_pkt_data_init(c_pkt_data *d, packet_info *pinfo, guint off)
{
	/* Get conversation to store/retrieve connection data. */
	d->conv = find_or_create_conversation(pinfo);
	DISSECTOR_ASSERT_HINT(d->conv, "find_or_create_conversation() returned NULL");

	if (pinfo->fd->flags.visited)
	{
		/* Retrieve the saved state. */
		d->convd = (c_conv_data*)p_get_proto_data(wmem_file_scope(), pinfo,
							  proto_ceph, off);
		DISSECTOR_ASSERT_HINT(d->convd, "Frame visited, but no saved state.");
		/* Make a copy and use that so we don't mess up the original. */
		d->convd = c_conv_data_copy(d->convd, wmem_new(wmem_packet_scope(), c_conv_data));
	}
	else
	{
		/*
			If there is no saved state get the state from dissecting the
			last packet.
		*/
		d->convd = (c_conv_data*)conversation_get_proto_data(d->conv, proto_ceph);
	}

	if (!d->convd) /* New conversation. */
	{
		d->convd = c_conv_data_new();
		conversation_add_proto_data(d->conv, proto_ceph, d->convd);
	}

	/*
	 * Set up src and dst pointers correctly, if the client port is
	 * already set. Otherwise, we need to wait until we have enough
	 * data to determine which is which.
	 */
	if (d->convd->client.port != 0xFFFF) {
		if (addresses_equal(&d->convd->client.addr, &pinfo->src) &&
		    d->convd->client.port == pinfo->srcport)
		{
			d->src = &d->convd->client;
			d->dst = &d->convd->server;
		}
		else
		{
			d->src = &d->convd->server;
			d->dst = &d->convd->client;
		}
		DISSECTOR_ASSERT(d->src);
		DISSECTOR_ASSERT(d->dst);
	}

	c_header_init(&d->header);
	d->item_root = NULL;
	d->pinfo    = pinfo;
}

/** Save packet data.
 *
 * This function should be called on complete PDUs to save the state so that
 * it will be available when redissecting the packet again later..
 *
 * This function only actually saves the state when necessary.
 */
static
void c_pkt_data_save(c_pkt_data *d, packet_info *pinfo, guint off)
{
	if (!pinfo->fd->flags.visited)
	{
		/*
			Save a copy of the state for next time we dissect this packet.
		*/
		p_add_proto_data(wmem_file_scope(), pinfo, proto_ceph, off,
						    c_conv_data_clone(d->convd));
	}
}

/** Check if packet is from the client.
 *
 * Returns true iff the packet is from the client.
 */
static
gboolean c_from_client(c_pkt_data *d)
{
	return d->src == &d->convd->client;
}

/** Check if packet is from the server.
 *
 * See c_from_client()
 */
static
gboolean c_from_server(c_pkt_data *d)
{
	return d->src == &d->convd->server;
}

static
void c_set_type(c_pkt_data *data, const char *type)
{
	col_add_str(data->pinfo->cinfo, COL_INFO, type);
	proto_item_append_text(data->item_root, " %s", type);
}

static
void c_append_text(c_pkt_data *data, proto_item *ti, const char *fmt, ...)
{
	va_list ap;
	char buf[ITEM_LABEL_LENGTH];
	va_start(ap, fmt);

	g_vsnprintf(buf, sizeof(buf), fmt, ap);

	proto_item_append_text(ti,		"%s", buf);
	proto_item_append_text(data->item_root, "%s", buf);

	va_end(ap);
}

/** Format a timespec.
 *
 * The returned string has packet lifetime.
 */
static
char *c_format_timespec(tvbuff_t *tvb, guint off)
{
	nstime_t t;
	t.secs	= tvb_get_letohl(tvb, off);
	t.nsecs = tvb_get_letohl(tvb, off+4);
	return abs_time_to_str(wmem_packet_scope(), &t, ABSOLUTE_TIME_LOCAL, 1);
}

/** Format a UUID
 *
 * The returned string has packet lifetime.
 */
static
char *c_format_uuid(tvbuff_t *tvb, guint off)
{
	e_guid_t uuid;
	tvb_get_guid(tvb, off, &uuid, ENC_BIG_ENDIAN);
	return guid_to_str(wmem_packet_scope(), &uuid);
}

#define C_NEEDMORE      G_MAXUINT
#define C_INVALID       0

/*** Expert info warning functions. ***/

/** Warn about unused data.
 *
 * Check if there is unused data and if there is warn about it.
 *
 * @param tree	The tree where the error should be added.
 * @param tvb	The buffer with the data.
 * @param start The start of the unused data.
 * @param end	Then end of the unused data.
 * @param data	The packet data.
 * @return True iff there was unused data.
 */
static
gboolean c_warn_unused(proto_tree *tree,
		       tvbuff_t *tvb, guint start, guint end, c_pkt_data *data)
{
	guint diff;

	DISSECTOR_ASSERT_CMPUINT(start, <=, end);

	diff = end - start;
	if (!diff) return FALSE; /* no unused space. */

	proto_tree_add_expert_format(tree, data->pinfo, &ei_unused,
				     tvb, start, diff,
				     "%u unused byte%s", diff, diff == 1? "":"s");

	return TRUE;
}

/** Warn about dissection using more data then expected.
 *
 * Check if there is an overrun and if there is warn about it.
 *
 * @param tree	The tree where the error should be added.
 * @param tvb	The buffer with the data.
 * @param start The start of the overun.
 * @param end	Then end of the overrun.
 * @param data	The packet data.
 * @return True iff there was an overrun.
 */
static
gboolean c_warn_overrun(proto_tree *tree,
			tvbuff_t *tvb, guint start, guint end, c_pkt_data *data)
{
	guint diff;

	DISSECTOR_ASSERT_CMPUINT(start, <=, end);

	diff = end - start;
	if (!diff) return FALSE; /* no unused space. */

	proto_tree_add_expert_format(tree, data->pinfo, &ei_overrun,
				     tvb, start, diff,
				     "%u overrun byte%s", diff, diff == 1? "":"s");

	return TRUE;
}

/** Warn about incorrect offset.
 *
 * Check if the offset is at the expected location, otherwise warn about it.
 *
 * @param tree The tree where the error should be added.
 * @param tvb  The buffer with the data.
 * @param act  The actual offset.
 * @param exp  The expected offset.
 * @param data The packet data.
 * @return True iff there was a mismatch.
 */
static
gboolean c_warn_size(proto_tree *tree,
		     tvbuff_t *tvb, guint act, guint exp, c_pkt_data *data)
{
	if (act < exp) return c_warn_unused (tree, tvb, act, exp, data);
	else	       return c_warn_overrun(tree, tvb, exp, act, data);
}

/** Warn about version mismatches.
 *
 * Check that the version is within the supported range, otherwise warn about
 * it.
 *
 * @param ti   The item to attach the warning to (probably the version item).
 * @param min  The minimum supported version.
 * @param max  The maximum supported version.
 * @param data The packet data.
 * @return A value less than zero if the version is to old and a value greater
 *	   then zero if the version is too new.	 Otherwise return zero.
 */
static
gshort c_warn_ver(proto_item *ti,
		  gint act, gint min, gint max, c_pkt_data *data)
{
	DISSECTOR_ASSERT_CMPINT(min, <=, max);

	if (act < min)
	{
		expert_add_info_format(data->pinfo, ti, &ei_ver_tooold,
				       "Version %d is lower then the minimum "
				       "supported version (%d).",
				       act, min);
		return -1;
	}
	if (act > max)
	{
		expert_add_info_format(data->pinfo, ti, &ei_ver_toonew,
				       "Version %d is higher then the maximum "
				       "supported version (%d).",
				       act, max);
		return 1;
	}

	return 0;
}

/***** Data Structure Dissectors *****/

/** Dissect a length-delimited binary blob.
 */
static
guint c_dissect_blob(proto_tree *root, int hf, int hf_data, int hf_len,
		     tvbuff_t *tvb, guint off)
{
	proto_item *ti;
	proto_tree *tree;
	guint32 size;

	size = tvb_get_letohl(tvb, off);

	ti = proto_tree_add_item(root, hf, tvb, off, size+4, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_data);

	proto_item_append_text(ti, ", Size: %"G_GINT32_MODIFIER"u", size);
	if (size)
	{
		proto_item_append_text(ti, ", Data: %s",
				       tvb_bytes_to_str(wmem_packet_scope(), tvb, off+4, size));
	}

	proto_tree_add_item(tree, hf_len,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_data,
			    tvb, off, size, ENC_NA);
	off += size;

	return off;
}

/** Dissect a blob of data.
 *
 * This is intended for data that is not yet being dissected but will be later.
 */
static
guint c_dissect_data(proto_tree *tree, int hf,
		     tvbuff_t *tvb, guint off)
{
	return c_dissect_blob(tree, hf, hf_data_data, hf_data_size, tvb, off);
}

typedef struct _c_str {
	char	*str;  /** The string data ('\0' terminated). */
	guint32	 size; /** The number of bytes in the string. */
} c_str;

/** Dissect a length-delimited string.
 *
 * If \a out is provided the string will be stored there.
 */
static
guint c_dissect_str(proto_tree *root, int hf, c_str *out,
		     tvbuff_t *tvb, guint off)
{
	proto_item *ti;
	proto_tree *tree;
	c_str d;

	d.size = tvb_get_letohl(tvb, off);
	d.str  = (char*)tvb_get_string_enc(wmem_packet_scope(),
					   tvb, off+4, d.size, ENC_ASCII);

	ti = proto_tree_add_string_format_value(root, hf, tvb, off, 4+d.size,
						d.str,
						"%s", d.str);
	tree = proto_item_add_subtree(ti, ett_str);

	proto_tree_add_item(tree, hf_string_size,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_string_data,
			    tvb, off, d.size, ENC_UTF_8|ENC_NA);
	off += d.size;

	if (out) *out = d;

	return off;
}

#define C_SIZE_SOCKADDR_STORAGE 128

typedef struct _c_sockaddr {
	const gchar *str;      /** A string representing the entire address. */
	const gchar *addr_str; /** A string representing the address portion. */

	c_inet af;	       /** Address family. */
	guint16 port;	       /** Network Port. */
} c_sockaddr;

/** Dissect sockaddr structure.
 *
 * If \a out is provided the data will be stored there.
 */
static
guint c_dissect_sockaddr(proto_tree *root, c_sockaddr *out,
			 tvbuff_t *tvb, guint off)
{
	proto_item *ti;
	proto_tree *tree;
	c_sockaddr d;

	/*
	struct sockaddr_storage {
		guint16 family;
		guint8	pad[???]; // Implementation defined.
	};
	struct sockaddr_in {
		guint16 family;
		guint16 port;
		guint32 addr;
		guint8	pad[8];
	};
	struct sockaddr_in6 {
		guint16 family;
		guint16 port;
		guint32 flow;
		guint8	addr[16];
		guint32 scope;
	};
	*/

	ti = proto_tree_add_item(root, hf_sockaddr,
				 tvb, off, C_SIZE_SOCKADDR_STORAGE, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_sockaddr);

	d.af = (c_inet)tvb_get_ntohs(tvb, off);

	proto_tree_add_item(tree, hf_inet_family, tvb, off, 2, ENC_BIG_ENDIAN);

	switch (d.af) {
	case C_IPv4:
		d.port	   = tvb_get_ntohs(tvb, off+2);
		d.addr_str = tvb_ip_to_str(tvb, off+4);

		proto_tree_add_item(tree, hf_port, tvb, off+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_addr_ipv4, tvb, off+4, 4, ENC_BIG_ENDIAN);
		break;
	case C_IPv6:
		d.port	   = tvb_get_ntohs (tvb, off+2);
		d.addr_str = tvb_ip6_to_str(tvb, off+8);

		proto_tree_add_item(tree, hf_port, tvb, off+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_addr_ipv6, tvb, off+8, 16, ENC_NA);
		break;
	default:
		d.port = 0;
		d.addr_str = "Unknown INET";
	}
	off += C_SIZE_SOCKADDR_STORAGE; /* Skip over sockaddr_storage. */

	d.str = wmem_strdup_printf(wmem_packet_scope(), "%s:%"G_GINT16_MODIFIER"u",
				   d.addr_str,
				   d.port);
	proto_item_append_text(ti, ": %s", d.str);

	if (out) *out = d;

	return off;
}

#define C_SIZE_ENTITY_ADDR (4 + 4 + C_SIZE_SOCKADDR_STORAGE)

typedef struct _c_entity_addr {
	c_sockaddr addr;
	const char *type_str;
	c_node_type type;
} c_entityaddr;

static
guint c_dissect_entityaddr(proto_tree *root, int hf, c_entityaddr *out,
			   tvbuff_t *tvb, guint off)
{
	proto_item *ti;
	proto_tree *tree;
	c_entityaddr d;

	/* entity_addr_t from ceph:/src/msg/msg_types.h */

	ti = proto_tree_add_item(root, hf, tvb, off, C_SIZE_ENTITY_ADDR, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_entityaddr);

	d.type = (c_node_type)tvb_get_letohl(tvb, off);
	d.type_str = c_node_type_string(d.type);
	proto_tree_add_item(tree, hf_node_type,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_node_nonce,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	off = c_dissect_sockaddr(tree, &d.addr, tvb, off);

	proto_item_append_text(ti, ", Type: %s, Address: %s",
			       d.type_str, d.addr.str);

	if (out) *out = d;

	return off;
}

#define C_SIZE_ENTITY_NAME 9

/** Dissect a ceph_entity_name.
 *
 * If \a out is provided the data is stored there.
 */
static
guint c_dissect_entityname(proto_tree *root, int hf, c_entityname *out,
			   tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	/* From ceph:/src/include/msgr.h
	struct ceph_entity_name {
		__u8 type;	// CEPH_ENTITY_TYPE_*
		__le64 num;
	} __attribute__ ((packed));
	*/

	proto_item *ti;
	proto_tree *tree;
	c_entityname d;

	ti = proto_tree_add_item(root, hf,
				 tvb, off, C_SIZE_ENTITY_NAME, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_entityname);

	d.type	   = (c_node_type)tvb_get_guint8(tvb, off);
	d.type_str = c_node_type_abbr_string(d.type);
	proto_tree_add_item(tree, hf_node_type,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	d.id   = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_node_id,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	if (d.id == G_MAXUINT64)
	{
		d.slug = d.type_str;
	}
	else
	{
		d.slug = wmem_strdup_printf(wmem_packet_scope(), "%s%"G_GINT64_MODIFIER"u",
					    d.type_str,
					    d.id);
	}

	proto_item_append_text(ti, ": %s", d.slug);

	if (out) *out = d;
	return off;
}

typedef struct _c_entityinst {
	c_entityname name;
	c_entityaddr addr;
} c_entityinst;

/** Dissect an entity_inst_t.
 */
static
guint c_dissect_entityinst(proto_tree *root, int hf, c_entityinst *out,
			   tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;

	c_entityinst d;

	ti = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_entityinst);

	off = c_dissect_entityname(tree, hf_entityinst_name, &d.name, tvb, off, data);
	off = c_dissect_entityaddr(tree, hf_entityinst_addr, &d.addr, tvb, off);

	proto_item_append_text(ti, ", Name: %s, Address: %s", d.name.slug, d.addr.addr.str);

	if (out) *out = d;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect an EntityName.
 *
 * If \a out is provided the data is stored there.
 *
 * \note This is different then c_dissect_entityname()
 */
static
guint c_dissect_EntityName(proto_tree *root,
			   tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	/* EntityName from ceph:/src/common/entity_name.h */

	proto_item *ti;
	proto_tree *tree;
	c_node_type type;
	c_str name;

	ti = proto_tree_add_item(root, hf_EntityName,
				 tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_EntityName);

	type = (c_node_type)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_EntityName_type,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_str(tree, hf_EntityName_id, &name, tvb, off);

	proto_item_append_text(ti, ": %s.%s",
			       c_node_type_abbr_string(type), name.str);

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a connection features list. */
static
guint c_dissect_features(proto_tree *tree,
			 tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	static const int *lowword[] = {
		&hf_feature_uid,
		&hf_feature_nosrcaddr,
		&hf_feature_monclockcheck,
		&hf_feature_flock,
		&hf_feature_subscribe2,
		&hf_feature_monnames,
		&hf_feature_reconnect_seq,
		&hf_feature_dirlayouthash,
		&hf_feature_objectlocator,
		&hf_feature_pgid64,
		&hf_feature_incsubosdmap,
		&hf_feature_pgpool3,
		&hf_feature_osdreplymux,
		&hf_feature_osdenc,
		&hf_feature_omap,
		&hf_feature_monenc,
		&hf_feature_query_t,
		&hf_feature_indep_pg_map,
		&hf_feature_crush_tunables,
		&hf_feature_chunky_scrub,
		&hf_feature_mon_nullroute,
		&hf_feature_mon_gv,
		&hf_feature_backfill_reservation,
		&hf_feature_msg_auth,
		&hf_feature_recovery_reservation,
		&hf_feature_crush_tunables2,
		&hf_feature_createpoolid,
		&hf_feature_reply_create_inode,
		&hf_feature_osd_hbmsgs,
		&hf_feature_mdsenc,
		&hf_feature_osdhashpspool,
		&hf_feature_mon_single_paxos,
		NULL
	};
	static const int *highword[] = {
		&hf_feature_osd_snapmapper,
		&hf_feature_mon_scrub,
		&hf_feature_osd_packed_recovery,
		&hf_feature_osd_cachepool,
		&hf_feature_crush_v2,
		&hf_feature_export_peer,
		&hf_feature_osd_erasure_codes,
		&hf_feature_osd_tmap2omap,
		&hf_feature_osdmap_enc,
		&hf_feature_mds_inline_data,
		&hf_feature_crush_tunables3,
		&hf_feature_osd_primary_affinity,
		&hf_feature_msgr_keepalive2,
		&hf_feature_reserved,
		NULL
	};

	/* Wireshark doesn't have support for 64 bit bitfields so dissect as
	   two 32 bit ones. */

	proto_tree_add_bitmask(tree, tvb, off, hf_features_low, hf_features_low,
			       lowword, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_bitmask(tree, tvb, off, hf_features_high, hf_features_high,
			       highword, ENC_LITTLE_ENDIAN);
	off += 4;

	return off;
}

/** Dissect message flags. */
static
guint c_dissect_flags(proto_tree *tree,
		      tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	static const int *flags[] = {
		&hf_flag_lossy,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, off, hf_flags, hf_flags,
			       flags, ENC_LITTLE_ENDIAN);

	return off+1;
}

#define C_OSD_FLAG_ACK		    0x00000001   /* want (or is) "ack" ack */
#define C_OSD_FLAG_ONNVRAM	    0x00000002   /* want (or is) "onnvram" ack */
#define C_OSD_FLAG_ONDISK	    0x00000004   /* want (or is) "ondisk" ack */
#define C_OSD_FLAG_RETRY	    0x00000008   /* resend attempt */
#define C_OSD_FLAG_READ		    0x00000010   /* op may read */
#define C_OSD_FLAG_WRITE	    0x00000020   /* op may write */
#define C_OSD_FLAG_ORDERSNAP	    0x00000040   /* EOLDSNAP if snapc is out of order */
#define C_OSD_FLAG_PEERSTAT_OLD	    0x00000080   /* DEPRECATED msg includes osd_peer_stat */
#define C_OSD_FLAG_BALANCE_READS    0x00000100
#define C_OSD_FLAG_PARALLELEXEC	    0x00000200   /* execute op in parallel */
#define C_OSD_FLAG_PGOP		    0x00000400   /* pg op, no object */
#define C_OSD_FLAG_EXEC		    0x00000800   /* op may exec */
#define C_OSD_FLAG_EXEC_PUBLIC	    0x00001000   /* DEPRECATED op may exec (public) */
#define C_OSD_FLAG_LOCALIZE_READS   0x00002000   /* read from nearby replica, if any */
#define C_OSD_FLAG_RWORDERED	    0x00004000   /* order wrt concurrent reads */
#define C_OSD_FLAG_IGNORE_CACHE	    0x00008000   /* ignore cache logic */
#define C_OSD_FLAG_SKIPRWLOCKS	    0x00010000   /* skip rw locks */
#define C_OSD_FLAG_IGNORE_OVERLAY   0x00020000   /* ignore pool overlay */
#define C_OSD_FLAG_FLUSH	    0x00040000   /* this is part of flush */
#define C_OSD_FLAG_MAP_SNAP_CLONE   0x00080000   /* map snap direct to clone id */
#define C_OSD_FLAG_ENFORCE_SNAPC    0x00100000   /* use snapc provided even if pool uses pool snaps */

/** Dissect OSD flags. */
static
guint c_dissect_osd_flags(proto_tree *tree,
			  tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	static const int *flags[] = {
		&hf_osd_flag_ack,
		&hf_osd_flag_onnvram,
		&hf_osd_flag_ondisk,
		&hf_osd_flag_retry,
		&hf_osd_flag_read,
		&hf_osd_flag_write,
		&hf_osd_flag_ordersnap,
		&hf_osd_flag_peerstat_old,
		&hf_osd_flag_balance_reads,
		&hf_osd_flag_parallelexec,
		&hf_osd_flag_pgop,
		&hf_osd_flag_exec,
		&hf_osd_flag_exec_public,
		&hf_osd_flag_localize_reads,
		&hf_osd_flag_rwordered,
		&hf_osd_flag_ignore_cache,
		&hf_osd_flag_skiprwlocks,
		&hf_osd_flag_ignore_overlay,
		&hf_osd_flag_flush,
		&hf_osd_flag_map_snap_clone,
		&hf_osd_flag_enforce_snapc,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, off, hf_osd_flags, hf_osd_flags,
			       flags, ENC_LITTLE_ENDIAN);

	return off+4;
}

/** Dissect a map<string,string>
 */
static
guint c_dissect_kv(proto_tree *root, int hf, int hf_k, int hf_v,
		   tvbuff_t *tvb, guint off)
{
	proto_item *ti;
	proto_tree *tree;
	c_str k, v;

	ti = proto_tree_add_item(root, hf, tvb, off, -1, ENC_LITTLE_ENDIAN);
	tree = proto_item_add_subtree(ti, ett_kv);

	off = c_dissect_str(tree, hf_k, &k, tvb, off);
	off = c_dissect_str(tree, hf_v, &v, tvb, off);

	proto_item_append_text(ti, ", %s = %s", k.str, v.str);
	proto_item_set_end(ti, tvb, off);

	return off;
}

typedef struct _c_encoded {
	guint8	version; /** The version of the struct. */
	guint8	compat;	 /** The oldest compatible version. */
	guint32 size;	 /** The size of the struct in bytes */
	guint	end;	 /** The end of the structure's data. */
} c_encoded;

/** Dissect and 'encoded' struct.
 *
 * @param enc The encoded structure to store data in.
 * @param minver The minimum version that is understood.
 * @param maxver The maximum version that is understood.
 * @return The offset of the data.
 */
static
guint c_dissect_encoded(proto_tree *tree, c_encoded *enc,
			guint8 minver, guint8 maxver,
			tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;

	DISSECTOR_ASSERT_HINT(enc, "enc out parameter must be non-null.");

	enc->version = tvb_get_guint8(tvb, off);
	ti = proto_tree_add_item(tree, hf_encoded_ver,
				 tvb, off++, 1, ENC_LITTLE_ENDIAN);
	c_warn_ver(ti, enc->version, minver, maxver, data);
	enc->compat = tvb_get_guint8(tvb, off);
	proto_tree_add_item(tree, hf_encoded_compat,
			    tvb, off++, 1, ENC_LITTLE_ENDIAN);

	enc->size = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_encoded_size,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	enc->end = off + enc->size;

	return off;
}

#define C_SIZE_TIMESPEC  (4 + 4)

#define C_SIZE_EVERSION  12

/** Dissect a eversion_t */
static
guint c_dissect_eversion(proto_tree *root, gint hf,
			 tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	guint64 ver;
	guint32 epoch;

	/** eversion_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, C_SIZE_EVERSION, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_eversion);

	/*** version_t ***/
	ver = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_version, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	/*** epoch_t ***/
	epoch = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_epoch, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_item_append_text(ti,
			       ", Version: %"G_GINT64_MODIFIER"d"
			       ", Epoch: %"G_GINT32_MODIFIER"d",
			       ver, epoch);

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect an object locator. */
static
guint c_dissect_object_locator(proto_tree *root, gint hf,
			       tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enchdr;
	c_str key, nspace;
	gint64 hash;

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_objectlocator);

	off = c_dissect_encoded(tree, &enchdr, 3, 6, tvb, off, data);

	proto_item_append_text(ti, ", Pool: %"G_GINT64_MODIFIER"d",
			       (gint64)tvb_get_letoh64(tvb, off));
	proto_tree_add_item(tree, hf_pool, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off += 4; /* Skip over preferred == -1 that old code used. */

	key.size = tvb_get_letohl(tvb, off);
	if (key.size)
	{
		off = c_dissect_str(tree, hf_key, &key, tvb, off);
		proto_item_append_text(ti, ", Key: \"%s\"", key.str);
	}
	else off += 4; /* If string is empty we should use hash. */

	if (enchdr.version >= 5)
	{
		off = c_dissect_str(tree, hf_namespace, &nspace, tvb, off);
		if (nspace.size)
			proto_item_append_text(ti, ", Namespace: \"%s\"", nspace.str);
	}

	if (enchdr.version >= 6)
	{
		hash = tvb_get_letoh64(tvb, off);
		if (hash >= 0)
		{
			proto_tree_add_item(tree, hf_hash, tvb, off, 8, ENC_LITTLE_ENDIAN);
			proto_item_append_text(ti, ", Hash: %"G_GINT64_MODIFIER"d", hash);
		}
		off += 8;
	}
	else hash = -1;

	if (key.size && hash >= 0)
	{
		proto_tree_add_expert(tree, data->pinfo, &ei_oloc_both, NULL, 0, 0);
	}

	c_warn_size(tree, tvb, off, enchdr.end, data);
	off = enchdr.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a placement group. */
static
guint c_dissect_pg(proto_tree *root, gint hf,
		   tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree;
	guint8 ver;
	gint32 preferred;

	/** pg_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_pg);

	ver = tvb_get_guint8(tvb, off);
	ti2 = proto_tree_add_item(tree, hf_pgid_ver, tvb, off, 1, ENC_LITTLE_ENDIAN);
	c_warn_ver(ti2, ver, 1, 1, data);
	off += 1;

	proto_item_append_text(ti, ", Pool: %"G_GINT64_MODIFIER"d",
			       tvb_get_letoh64(tvb, off));
	proto_tree_add_item(tree, hf_pgid_pool, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_item_append_text(ti, ", Seed: %08"G_GINT32_MODIFIER"X",
			       tvb_get_letohl(tvb, off));
	proto_tree_add_item(tree, hf_pgid_seed, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	preferred = tvb_get_letohl(tvb, off);
	if (preferred >= 0)
		proto_item_append_text(ti, ", Prefer: %"G_GINT32_MODIFIER"d", preferred);
	proto_tree_add_item(tree, hf_pgid_preferred, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a placement group creation. */
static
guint c_dissect_pg_create(proto_tree *root, gint hf,
			  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;

	/** pg_create_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_pg_create);

	off = c_dissect_encoded(tree, &enc, 1, 1, tvb, off, data);

	proto_tree_add_item(tree, hf_pg_create_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_pg(tree, hf_pg_create_parent, tvb, off, data);

	proto_tree_add_item(tree, hf_pg_create_splitbits,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a filepath. */
static
guint c_dissect_path(proto_tree *root, gint hf,
		     tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree;
	guint64 inode;
	c_str rel;
	guint v;

	/** filepath from ceph:/src/include/filepath.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_filepath);

	v = tvb_get_guint8(tvb, off);
	ti2 = proto_tree_add_item(tree, hf_path_ver, tvb, off, 1, ENC_LITTLE_ENDIAN);
	c_warn_ver(ti2, v, 1, 1, data);
	off += 1;

	inode = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_path_inode, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off = c_dissect_str(tree, hf_path_rel, &rel, tvb, off);

	if (inode)
		proto_item_append_text(ti, ", Inode: 0x%016"G_GINT64_MODIFIER"u", inode);
	if (rel.size)
		proto_item_append_text(ti, ", Rel: \"%s\"", rel.str);

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a capability release. */
static
guint c_dissect_mds_release(proto_tree *root, gint hf,
			    tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	guint64 inode;

	/** MClientRequest::Release from ceph:/src/messages/MClientRequest.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_mds_release);

	inode = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_mds_release_inode,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_mds_release_capid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_mds_release_new,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_mds_release_wanted,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_mds_release_seq,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_mds_release_seq_issue,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_mds_release_mseq,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_mds_release_dname_seq,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_str(tree, hf_mds_release_dname, NULL, tvb, off);

	proto_item_append_text(ti, ", Inode: 0x%016"G_GINT64_MODIFIER"u", inode);

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a HitSet::Params */
static
guint c_dissect_hitset_params(proto_tree *root,
			      tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree;
	c_encoded enc, encimpl;
	c_hitset_params_type type;
	guint32 i;

	/** HitSet::Params from ceph:/src/osd/HitSet.h */

	ti   = proto_tree_add_item(root, hf_hitset_params, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_hitset_params);

	off = c_dissect_encoded(tree, &enc, 1, 1, tvb, off, data);

	type = (c_hitset_params_type)tvb_get_guint8(tvb, off);
	proto_item_append_text(ti, ", Type: %s", c_hitset_params_type_string(type));
	ti2 = proto_tree_add_item(tree, hf_hitset_params_type,
				  tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	switch (type)
	{
	case C_HITSET_PARAMS_TYPE_NONE:
		break;
	case C_HITSET_PARAMS_TYPE_EXPLICIT_HASH:
		off = c_dissect_encoded(tree, &encimpl, 1, 1, tvb, off, data);

		proto_tree_add_item(tree, hf_hitset_params_exphash_count,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		i = tvb_get_letohl(tvb, off);
		off += 4;
		while (i--)
		{
			proto_tree_add_item(tree, hf_hitset_params_exphash_hit,
					    tvb, off, 4, ENC_LITTLE_ENDIAN);
			off += 4;
		}

		c_warn_size(tree, tvb, off, encimpl.end, data);
		off = encimpl.end;
		break;
	default:
		expert_add_info(data->pinfo, ti2, &ei_union_unknown);
		off = enc.end; /* Skip everything. */
	}

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	return off;
}


/** Dissect a pool_snap_info_t */
static
guint c_dissect_snapinfo(proto_tree *root,
			 tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;
	guint64 id;
	c_str name;
	char *date;

	/** pool_snap_info_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf_snapinfo, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_snapinfo);

	off = c_dissect_encoded(tree, &enc, 2, 2, tvb, off, data);

	id = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_snapinfo_id,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	date = c_format_timespec(tvb, off);
	proto_tree_add_item(tree, hf_snapinfo_time,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off = c_dissect_str(tree, hf_snapinfo_name, &name, tvb, off);

	proto_item_set_text(ti, ", ID: 0x%016"G_GINT64_MODIFIER"X"
			    ", Name: %s, Date: %s",
			    id,
			    name.str,
			    date);

	c_warn_size(tree, tvb, off, enc.size, data);
	off = enc.size;

	return off;
}

/** Dissect a pg pool. */
static
guint c_dissect_pgpool(proto_tree *root,
		       tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree, *subtree;
	c_encoded enc;
	guint32 i;
	c_pgpool_type type;
	c_pgpool_cachemode cachemode;

	static const int *flags_low[] = {
		&hf_pgpool_flag_hashpool,
		&hf_pgpool_flag_full,
		&hf_pgpool_flag_fake_ec_pool,
		NULL
	};
	static const int *flags_high[] = {
		NULL
	};

	/** pg_pool_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf_pgpool, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_pgpool);

	off = c_dissect_encoded(tree, &enc, 5, 15, tvb, off, data);

	type = (c_pgpool_type)tvb_get_guint8(tvb, off);
	proto_tree_add_item(tree, hf_pgpool_type,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_pgpool_size,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_pgpool_crush_ruleset,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_pgpool_hash,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_pgpool_pgnum,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_pgpnum,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off += 4 + 4; /* Always 0 in new code.	Ignored field. */

	proto_tree_add_item(tree, hf_pgpool_changed,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_snapseq,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_pgpool_snapepoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		ti2 = proto_tree_add_item(tree, hf_pgpool_snap,
					  tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_pgpool_snap);

		proto_tree_add_item(subtree, hf_pgpool_snap_id,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		off = c_dissect_snapinfo(subtree, tvb, off, data);

		proto_item_set_end(ti2, tvb, off);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		ti2 = proto_tree_add_item(tree, hf_pgpool_snapdel,
					  tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_pgpool_snapdel);

		proto_tree_add_item(subtree, hf_pgpool_snapdel_from,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		proto_tree_add_item(subtree, hf_pgpool_snapdel_to,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_item_set_end(ti2, tvb, off);
	}

	proto_tree_add_item(tree, hf_pgpool_uid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_bitmask(tree, tvb, off, hf_pgpool_flags_low, hf_pgpool_flags_low,
			       flags_low, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_bitmask(tree, tvb, off, hf_pgpool_flags_high, hf_pgpool_flags_high,
			       flags_high, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_crash_reply_interval,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_min_size,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_pgpool_quota_bytes,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_pgpool_quota_objects,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_pgpool_tier,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}

	proto_tree_add_item(tree, hf_pgpool_tierof,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	cachemode = (c_pgpool_cachemode)tvb_get_guint8(tvb, off);
	proto_tree_add_item(tree, hf_pgpool_cachemode,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_pgpool_readtier,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_pgpool_writetier,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		c_str k, v;

		ti2 = proto_tree_add_item(tree, hf_pgpool_property, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_pgpool_property);

		off = c_dissect_str(subtree, hf_pgpool_property_key, &k, tvb, off);
		off = c_dissect_str(subtree, hf_pgpool_property_val, &v, tvb, off);

		proto_item_append_text(ti2, ": %s=%s", k.str, v.str);

		proto_item_set_end(ti2, tvb, off);
	}

	off = c_dissect_hitset_params(tree, tvb, off, data);

	proto_tree_add_item(tree, hf_pgpool_hitset_period,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_hitset_count,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_stripewidth,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_targetmaxsize,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_pgpool_targetmaxobj,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_pgpool_cache_targetdirtyratio,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_cache_targetfullratio,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_cache_flushage_min,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pgpool_cache_evictage_min,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_str(tree, hf_pgpool_erasurecode_profile, NULL, tvb, off);

	proto_tree_add_item(tree, hf_pgpool_lastforceresend,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_append_text(ti, ", Type: %s, Cache Mode: %s",
			       c_pgpool_type_string(type),
			       c_pgpool_cachemode_string(cachemode));

	return off;
}

/** Dissect a MonMap. */
static
guint c_dissect_monmap(proto_tree *root,
		       tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree, *subtree;
	guint size, end;
	guint32 i;
	c_encoded enc;
	c_str str;
	c_entityaddr addr;

	/** MonMap from ceph:/src/mon/MonMap.cc */

	size = tvb_get_letohl(tvb, off);
	end = off + 4 + size;

	/* No data here. */
	if (!size) return end;

	ti   = proto_tree_add_item(root, hf_monmap, tvb, off, size, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_mon_map);

	off += 4;

	off = c_dissect_encoded(tree, &enc, 3, 3, tvb, off, data);
	/* Check the blob size and encoded size match. */
	c_warn_size(tree, tvb, enc.end, end, data);

	proto_tree_add_item(tree, hf_monmap_fsid, tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	proto_tree_add_item(tree, hf_monmap_epoch, tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		ti2 = proto_tree_add_item(tree, hf_monmap_address,
					  tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_mon_map_address);

		off = c_dissect_str(subtree, hf_monmap_address_name, &str, tvb, off);
		off = c_dissect_entityaddr(subtree, hf_monmap_address_addr, &addr,
					   tvb, off);

		proto_item_append_text(ti2, ", Name: %s, Address: %s",
				       str.str, addr.addr.addr_str);

		proto_item_set_end(ti2, tvb, off);
	}

	proto_tree_add_item(tree, hf_monmap_changed, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_monmap_created, tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	c_warn_size(tree, tvb, off, end, data);
	off = end;

	return off;
}

/** Dissect an osd_peer_stat_t */
static
guint c_dissect_osd_peerstat(proto_tree *root,
			     tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;

	/* osd_peer_stat_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf_osd_peerstat, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_osd_peerstat);

	off = c_dissect_encoded(tree, &enc, 1, 1, tvb, off, data);

	proto_tree_add_item(tree, hf_osd_peerstat_timestamp,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a CompatSet::FeatureSet */
static
guint c_dissect_featureset(proto_tree *root, int hf,
			   tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;
	guint32 i;
	guint64 features;

	/* CompatSet::FeatureSet from ceph:/src/include/FeatureSet.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_featureset);

	features = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_featureset_mask,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *ti2;
		proto_tree *subtree;
		guint64 val;
		c_str name;

		ti2 = proto_tree_add_item(tree, hf_featureset_name, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_featureset_name);

		val = tvb_get_letoh64(tvb, off);
		proto_tree_add_item(subtree, hf_featureset_name_val,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		off = c_dissect_str(subtree, hf_featureset_name_name, &name, tvb, off);

		proto_item_append_text(ti2, ", Value: %"G_GINT64_MODIFIER"u, Name: %s",
				       val, name.str);
		proto_item_set_end(ti2, tvb, off);
	}

	proto_item_append_text(ti, ", Features: 0x%016"G_GINT64_MODIFIER"X", features);
	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a CompatSet */
static
guint c_dissect_compatset(proto_tree *root,
			  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;

	/* CompatSet from ceph:/src/include/CompatSet.h */

	ti   = proto_tree_add_item(root, hf_compatset, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_compatset);

	off = c_dissect_featureset(tree, hf_compatset_compat,	tvb, off, data);
	off = c_dissect_featureset(tree, hf_compatset_compatro, tvb, off, data);
	off = c_dissect_featureset(tree, hf_compatset_incompat, tvb, off, data);

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect an OSDSuperblock */
static
guint c_dissect_osd_superblock(proto_tree *root,
			       tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;
	guint32 role, epoch;
	double weight;

	/* OSDSuperblock from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf_osd_superblock, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_osd_superblock);

	off = c_dissect_encoded(tree, &enc, 5, 6, tvb, off, data);

	proto_tree_add_item(tree, hf_osd_superblock_clusterfsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	role = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_osd_superblock_role,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	epoch = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_osd_superblock_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osd_superblock_map_old,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osd_superblock_map_new,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	weight = tvb_get_letohieee_double(tvb, off);
	proto_tree_add_item(tree, hf_osd_superblock_weight,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	if (enc.version >= 2)
		off = c_dissect_compatset(tree, tvb, off, data);

	proto_tree_add_item(tree, hf_osd_superblock_clean,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osd_superblock_mounted,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_item_append_text(ti, ", Role: %"G_GINT32_MODIFIER"d, Weight: %lf"
			       ", Boot Epoch: %"G_GINT32_MODIFIER"d",
			       role, weight, epoch);
	if (enc.version >= 4)
	{
		proto_item_append_text(ti, ", OSD FSID: %s", c_format_uuid(tvb, off));
		proto_tree_add_item(tree, hf_osd_superblock_osdfsid,
				    tvb, off, 16, ENC_BIG_ENDIAN);
		off += 16;
	}

	if (enc.version >= 6)
	{
		proto_tree_add_item(tree, hf_osd_superblock_full,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect an osd_info_t. */
static
guint c_dissect_osdinfo(proto_tree *root, int hf,
			tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree;
	guint8 ver;

	/* osd_info_t from ceph:/src/osd/OSDMap.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, 25, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_osd_info);

	ver = tvb_get_guint8(tvb, off);
	ti2 = proto_tree_add_item(tree, hf_osdinfo_ver,
				  tvb, off, 1, ENC_LITTLE_ENDIAN);
	c_warn_ver(ti2, ver, 1, 1, data);
	off += 1;

	proto_tree_add_item(tree, hf_osdinfo_lastclean_begin,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osdinfo_lastclean_end,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osdinfo_up_from,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osdinfo_up_through,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osdinfo_downat,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osdinfo_lostat,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	return off;
}

/** Dissect an osd_xinfo_t. */
static
guint c_dissect_osd_xinfo(proto_tree *root, int hf,
			  tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;

	/* osd_xinfo_t from ceph:/src/osd/OSDMap.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_osd_xinfo);

	off = c_dissect_encoded(tree, &enc, 1, 3, tvb, off, data);

	proto_tree_add_item(tree, hf_osdxinfo_down,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_osdxinfo_laggy_probability,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osdxinfo_laggy_interval,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	if (enc.version >= 2 )
	{
		off = c_dissect_features(tree, tvb, off, data);
	}
	if (enc.version >= 3)
	{
		proto_tree_add_item(tree, hf_osdxinfo_oldweight,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;
	proto_item_set_end(ti, tvb, off);

	return off;
}

/** Dissect an objectstore_perfstat_t. */
static
guint c_dissect_perfstat(proto_tree *root, int hf,
			 tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;

	/* objectstore_perfstat_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_perfstat);

	off = c_dissect_encoded(tree, &enc, 1, 1, tvb, off, data);

	proto_tree_add_item(tree, hf_perfstat_commitlatency,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_perfstat_applylatency,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect an osd_stat_t. */
static
guint c_dissect_osd_stat(proto_tree *root,
			 tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc, enc2;
	guint32 i;

	/* osd_stat_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf_osdstat, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_pg_stat);

	off = c_dissect_encoded(tree, &enc, 2, 4, tvb, off, data);

	proto_tree_add_item(tree, hf_osdstat_kb,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_osdstat_kbused,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_osdstat_kbavail,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_osdstat_trimqueue,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_osdstat_trimming,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_osdstat_hbin,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_osdstat_hbout,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	if (enc.version >= 3)
	{
		off = c_dissect_encoded(tree, &enc2, 1, 1, tvb, off, data);
		i = tvb_get_letohl(tvb, off);
		off += 4;
		if (i >= 1)
			proto_tree_add_item(tree, hf_osdstat_opqueue,
					    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4*i; /* Skip older values because they are unitless and meaningless. */
		c_warn_size(tree, tvb, off, enc2.end, data);
		off = enc2.end;
	}

	if (enc.version >= 4)
		off = c_dissect_perfstat(tree, hf_osdstat_fsperf, tvb, off, data);

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a CRUSH Ruleset. */
static
guint c_dissect_crush(proto_tree *root,
		      tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	off = c_dissect_data(root, hf_crush, tvb, off);

	return off;
}

/** Dissect an OSDMap. */
static
guint c_dissect_osdmap(proto_tree *root,
		       tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree, *subtree;
	guint size, end;
	guint32 i;
	c_encoded enc, enc2; /* There is an outer one, and multiple inner ones. */

	/*** Storage for values that will be formatted and
	 *** added to the root nodes.
	 ***/
	char *fsid;
	char *time_created, *time_modified;

	/* OSDMap from ceph:/src/osd/OSDMap.cc */

	size = tvb_get_letohl(tvb, off);
	end = off + 4 + size;

	ti   = proto_tree_add_item(root, hf_osdmap, tvb, off, size, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_osd_map);

	off += 4;

	off = c_dissect_encoded(tree, &enc, 7, 7, tvb, off, data);
	/* Check the blob size and encoded size match. */
	c_warn_size(tree, tvb, enc.end, end, data);

	/*** Start first inner ***/
	ti2 = proto_tree_add_item(tree, hf_osdmap_client, tvb, off, -1, ENC_NA);
	subtree = proto_item_add_subtree(ti2, ett_osd_map_client);

	off = c_dissect_encoded(subtree, &enc2, 1, 3, tvb, off, data);
	proto_item_set_len(ti2, enc2.size);

	fsid = c_format_uuid(tvb, off);
	proto_tree_add_item(subtree, hf_osdmap_fsid, tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	proto_tree_add_item(subtree, hf_osdmap_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	time_created = c_format_timespec(tvb, off);
	proto_tree_add_item(subtree, hf_osdmap_created,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	time_modified = c_format_timespec(tvb, off);
	proto_tree_add_item(subtree, hf_osdmap_modified,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *poolti;
		proto_tree *pooltree;
		guint64 id;

		poolti = proto_tree_add_item(subtree, hf_osdmap_pool,
					     tvb, off, -1, ENC_NA);
		pooltree = proto_item_add_subtree(poolti, ett_osd_map_pool);

		id = tvb_get_letoh64(tvb, off);
		proto_tree_add_item(pooltree, hf_osdmap_pool_id,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		off = c_dissect_pgpool(pooltree, tvb, off, data);

		proto_item_append_text(poolti, ", ID: 0x%016"G_GINT64_MODIFIER"X", id);

		proto_item_set_end(poolti, tvb, off);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *nameti;
		proto_tree *nametree;
		guint64 id;
		c_str name;

		nameti = proto_tree_add_item(subtree, hf_osdmap_poolname_item,
					     tvb, off, -1, ENC_NA);
		nametree = proto_item_add_subtree(nameti, ett_osd_map_poolname);

		id = tvb_get_letoh64(tvb, off);
		proto_tree_add_item(nametree, hf_osdmap_pool_id,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		off = c_dissect_str(nametree, hf_osdmap_poolname, &name, tvb, off);

		proto_item_append_text(nameti,
				       ", ID: 0x%016"G_GINT64_MODIFIER"X, Name: %s",
				       id, name.str);
		proto_item_set_end(nameti, tvb, off);
	}

	proto_tree_add_item(subtree, hf_osdmap_poolmax,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(subtree, hf_osdmap_flags,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(subtree, hf_osdmap_osdmax,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(subtree, hf_osdmap_osd_state,
				    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(subtree, hf_osdmap_osd_weight,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		off = c_dissect_entityaddr(subtree, hf_osdmap_osd_addr, NULL,
					   tvb, off);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		guint32 j;
		proto_item *pgtti;
		proto_tree *pgttree;

		pgtti = proto_tree_add_item(subtree, hf_osdmap_pgtmp,
					   tvb, off, -1, ENC_NA);
		pgttree = proto_item_add_subtree(pgtti, ett_osd_map_pgtmp);

		off = c_dissect_pg(pgttree, hf_osdmap_pgtmp_pg, tvb, off, data);

		j = tvb_get_letohl(tvb, off);
		off += 4;
		while (j--)
		{
			proto_tree_add_item(pgttree, hf_osdmap_pgtmp_val,
					    tvb, off, 4, ENC_LITTLE_ENDIAN);
			off += 4;
		}

		proto_item_set_end(pgtti, tvb, off);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *pgtti;
		proto_tree *pgttree;

		pgtti = proto_tree_add_item(subtree, hf_osdmap_primarytmp,
					   tvb, off, -1, ENC_NA);
		pgttree = proto_item_add_subtree(pgtti, ett_osd_map_primarytmp);

		off = c_dissect_pg(pgttree, hf_osdmap_primarytmp_pg, tvb, off, data);

		proto_tree_add_item(pgttree, hf_osdmap_primarytmp_val,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;

		proto_item_set_end(pgtti, tvb, off);
	}

	if (enc2.version >= 2)
	{
		i = tvb_get_letohl(tvb, off);
		off += 4;
		while (i--)
		{
			proto_tree_add_item(subtree, hf_osdmap_osd_primaryaffinity,
					    tvb, off, 4, ENC_LITTLE_ENDIAN);
			off += 4;
		}
	}

	off = c_dissect_crush(subtree, tvb, off, data);

	if (enc2.version >= 3)
	{
		i = tvb_get_letohl(tvb, off);
		off += 4;
		while (i--)
		{
			guint32 j;
			proto_item *ecti;
			proto_tree *ectree;
			c_str profile;

			ecti = proto_tree_add_item(subtree, hf_osdmap_erasurecodeprofile,
						   tvb, off, -1, ENC_NA);
			ectree = proto_item_add_subtree(ecti, ett_osd_map_erasurecodeprofile);

			off = c_dissect_str(ectree, hf_osdmap_erasurecodeprofile_name, &profile,
					    tvb, off);
			proto_item_append_text(ecti, ", Name: %s", profile.str);

			j = tvb_get_letohl(tvb, off);
			off += 4;
			while (j--)
			{
				off = c_dissect_kv(ectree, hf_osdmap_erasurecodeprofile_prop,
						   hf_osdmap_erasurecodeprofile_k,
						   hf_osdmap_erasurecodeprofile_v,
						   tvb, off);
			}

			proto_item_set_end(ecti, tvb, off);
		}
	}

	c_warn_size(subtree, tvb, off, enc2.end, data);
	off = enc2.end;
	/*** End first inner ***/

	/*** Start second inner ***/
	ti2 = proto_tree_add_item(tree, hf_osdmap_osd, tvb, off, -1, ENC_NA);
	subtree = proto_item_add_subtree(ti2, ett_osd_map_osd);
	off = c_dissect_encoded(subtree, &enc2, 1, 1, tvb, off, data);
	proto_item_set_len(ti2, enc2.size);

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		off = c_dissect_entityaddr(subtree, hf_osdmap_hbaddr_back, NULL,
					   tvb, off);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		off = c_dissect_osdinfo(subtree, hf_osdmap_osd_info, tvb, off, data);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *blti;
		proto_tree *bltree;

		blti = proto_tree_add_item(subtree, hf_osdmap_blacklist,
					   tvb, off, -1, ENC_NA);
		bltree = proto_item_add_subtree(blti, ett_osd_map_blacklist);

		off = c_dissect_entityaddr(bltree, hf_osdmap_blacklist_addr, NULL,
					   tvb, off);

		proto_tree_add_item(bltree, hf_osdmap_blacklist_time,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_item_set_end(blti, tvb, off);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		off = c_dissect_entityaddr(subtree, hf_osdmap_cluster_addr, NULL,
					   tvb, off);
	}

	proto_tree_add_item(subtree, hf_osdmap_cluster_snapepoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_str(subtree, hf_osdmap_cluster_snap, NULL, tvb, off);

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(subtree, hf_osdmap_osd_uuid,
				    tvb, off, 16, ENC_LITTLE_ENDIAN);
		off += 16;
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		off = c_dissect_osd_xinfo(subtree, hf_osdmap_osd_xinfo, tvb, off, data);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		off = c_dissect_entityaddr(subtree, hf_osdmap_hbaddr_front, NULL,
					   tvb, off);
	}

	c_warn_size(subtree, tvb, off, enc2.end, data);
	off = enc2.end;
	/*** End second inner ***/

	proto_item_append_text(ti, ", FSID: %s, Created: %s, Modified: %s",
			       fsid,
			       time_created, time_modified);

	c_warn_size(tree, tvb, off, end, data);
	off = end;

	return off;
}

/** Dissect an incremental OSDMap. */
static
guint c_dissect_osdmap_inc(proto_tree *root,
			   tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree, *subtree;
	guint size, end;
	c_encoded enc, enc2; /* There is an outer one, and multiple inner ones. */

	/** OSDMap::Incremental from ceph:/src/osd/OSDMap.cc */

	size = tvb_get_letohl(tvb, off);
	end = off + 4 + size;

	ti   = proto_tree_add_item(root, hf_osdmap_inc, tvb, off, size, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_osd_map_inc);

	off += 4;

	off = c_dissect_encoded(tree, &enc, 7, 7, tvb, off, data);
	/* Check the blob size and encoded size match. */
	c_warn_size(tree, tvb, enc.end, end, data);

	/*** Start first inner ***/
	ti2 = proto_tree_add_item(tree, hf_osdmap_inc_client, tvb, off, -1, ENC_NA);
	subtree = proto_item_add_subtree(ti2, ett_osd_map_inc_client);

	off = c_dissect_encoded(subtree, &enc2, 1, 3, tvb, off, data);
	proto_item_set_len(ti2, enc2.size);

	proto_tree_add_item(subtree, hf_osdmap_inc_fsid, tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	/* @TODO: Dissect. */

	c_warn_size(subtree, tvb, off, enc2.end, data);
	off = enc2.end;
	/*** End first inner ***/

	/*** Start second inner ***/
	ti2 = proto_tree_add_item(tree, hf_osdmap_inc_osd, tvb, off, -1, ENC_NA);
	subtree = proto_item_add_subtree(ti2, ett_osd_map_inc_osd);
	off = c_dissect_encoded(subtree, &enc2, 1, 1, tvb, off, data);
	proto_item_set_len(ti2, enc2.size);

	/* @TODO: Dissect. */

	c_warn_size(subtree, tvb, off, enc2.end, data);
	off = enc2.end;
	/*** End second inner ***/

	c_warn_size(tree, tvb, off, end, data);
	off = end;

	return off;
}

typedef struct _c_osd_op {
	c_osd_optype type;    /** The type of operation. */
	const char *type_str; /** The type of operation as a string. */
	guint32 payload_size; /** The size of the operation payload. */
} c_osd_op;

#define C_SIZE_OSD_OP_MIN 34

/** Dissect OSD Operation. */
static
guint c_dissect_osd_op(proto_tree *root, gint hf, c_osd_op *out,
		       tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree;
	c_osd_op d;

	guint64 offset, size;
	guint64 trunc_size, trunc_seq;

	/* From ceph:/src/include/rados.h
	struct ceph_osd_op {
		__le16 op;	     // CEPH_OSD_OP_*
		__le32 flags;	     // CEPH_OSD_FLAG_*
		union {
			struct {
				__le64 offset, length;
				__le64 truncate_size;
				__le32 truncate_seq;
			} __attribute__ ((packed)) extent;
			struct {
				__le32 name_len;
				__le32 value_len;
				__u8 cmp_op;	   // CEPH_OSD_CMPXATTR_OP_*
				__u8 cmp_mode;	   // CEPH_OSD_CMPXATTR_MODE_*
			} __attribute__ ((packed)) xattr;
			struct {
				__u8 class_len;
				__u8 method_len;
				__u8 argc;
				__le32 indata_len;
			} __attribute__ ((packed)) cls;
			struct {
				__le64 count;
				__le32 start_epoch; // for the pgls sequence
			} __attribute__ ((packed)) pgls;
			struct {
				__le64 snapid;
			} __attribute__ ((packed)) snap;
			struct {
				__le64 cookie;
				__le64 ver;
				__u8 flag; // 0 = unwatch, 1 = watch
			} __attribute__ ((packed)) watch;
			struct {
				__le64 unused;
				__le64 ver;
			} __attribute__ ((packed)) assert_ver;
			struct {
				__le64 offset, length;
				__le64 src_offset;
			} __attribute__ ((packed)) clonerange;
			struct {
				__le64 max;	// max data in reply
			} __attribute__ ((packed)) copy_get;
			struct {
				__le64 snapid;
				__le64 src_version;
				__u8 flags;
			} __attribute__ ((packed)) copy_from;
			struct {
				struct ceph_timespec stamp;
			} __attribute__ ((packed)) hit_set_get;
			struct {
				__u8 flags;
			} __attribute__ ((packed)) tmap2omap;
			struct {
				__le64 expected_object_size;
				__le64 expected_write_size;
			} __attribute__ ((packed)) alloc_hint;
		};
		__le32 payload_size;
	} __attribute__ ((packed));
	*/

	d.type = (c_osd_optype)tvb_get_letohs(tvb, off);

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_osd_op);

	d.type_str = c_osd_optype_string(d.type);
	proto_item_append_text(ti, ", Type: %s", d.type_str);
	proto_tree_add_item(tree, hf_osd_op_type, tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;

	off = c_dissect_osd_flags(tree, tvb, off, data);

	/***
		Stop moving off here.  The size of the individual message doesn't
		matter, only the size of the largest, which is added below.
	***/

	switch (d.type)
	{
	case C_OSD_OP_WRITE:
	case C_OSD_OP_WRITEFULL:
	case C_OSD_OP_ZERO:
	case C_OSD_OP_TRUNCATE:
	case C_OSD_OP_DELETE:
	case C_OSD_OP_READ:
	case C_OSD_OP_STAT:
		offset = tvb_get_letoh64(tvb, off);
		proto_tree_add_item(tree, hf_osd_op_extent_off,
				    tvb, off,	 8, ENC_LITTLE_ENDIAN);
		size = tvb_get_letoh64(tvb, off+8);
		proto_tree_add_item(tree, hf_osd_op_extent_size,
				    tvb, off+8,	 8, ENC_LITTLE_ENDIAN);
		trunc_size = tvb_get_letoh64(tvb, off+16);
		proto_tree_add_item(tree, hf_osd_op_extent_trunc_size,
				    tvb, off+16, 8, ENC_LITTLE_ENDIAN);
		trunc_seq = tvb_get_letohl(tvb, off+24);
		proto_tree_add_item(tree, hf_osd_op_extent_trunc_seq,
				    tvb, off+24, 4, ENC_LITTLE_ENDIAN);

		proto_item_append_text(ti, ", Offset: %"G_GINT64_MODIFIER"u"
				       ", Size: %"G_GINT64_MODIFIER"u",
				       offset, size);
		if (trunc_seq)
			proto_item_append_text(ti, ", Truncate To: %"G_GINT64_MODIFIER"u",
					       trunc_size);
		break;
	default:
		ti2 = proto_tree_add_item(tree, hf_osd_op_data, tvb, off, 28, ENC_NA);
		expert_add_info(data->pinfo, ti2, &ei_union_unknown);
	}

	off += 28;

	d.payload_size = tvb_get_letohl(tvb, off);
	proto_item_append_text(ti, ", Data Length: %"G_GINT32_MODIFIER"d",
			       d.payload_size);
	proto_tree_add_item(tree, hf_osd_op_payload_size,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_item_set_end(ti, tvb, off);

	if (out) *out = d;
	return off;
}

/** Dissect a redirect. */
static
guint c_dissect_redirect(proto_tree *root, gint hf,
			 tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;

	/** request_redirect_t from ceph:/src/osd/osd_types.h */

	ti = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_redirect);

	off = c_dissect_encoded(tree, &enc, 1, 1, tvb, off, data);

	off = c_dissect_object_locator(tree, hf_osd_redirect_oloc, tvb, off, data);

	if (tvb_get_letohl(tvb, off))
	{
		off = c_dissect_str(tree, hf_osd_redirect_obj, NULL, tvb, off);
	}
	else off += 4;

	off = c_dissect_blob(tree, hf_osd_redirect_osdinstr,
			     hf_osd_redirect_osdinstr_data, hf_osd_redirect_osdinstr_len,
			     tvb, off);

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect a statsum object. */
static
guint c_dissect_statsum(proto_tree *tree,
			tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	c_encoded enc;

	/** object_stat_sum_t from ceph:/src/osd/osd_types.h */

	off = c_dissect_encoded(tree, &enc, 3, 9, tvb, off, data);

	proto_tree_add_item(tree, hf_statsum_bytes,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_objects,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_clones,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_copies,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_missing,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_degraded,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_unfound,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_read_bytes,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_read_kbytes,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_written_bytes,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_written_kbytes,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_statsum_scrub_errors,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	if (enc.version >= 5)
	{
		proto_tree_add_item(tree, hf_statsum_recovered,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		proto_tree_add_item(tree, hf_statsum_bytes_recovered,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		proto_tree_add_item(tree, hf_statsum_keys_recovered,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	if (enc.version >= 6)
	{
		proto_tree_add_item(tree, hf_statsum_shallow_scrub_errors,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		proto_tree_add_item(tree, hf_statsum_deep_scrub_errors,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	if (enc.version >= 7)
	{
		proto_tree_add_item(tree, hf_statsum_dirty,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		proto_tree_add_item(tree, hf_statsum_whiteouts,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	if (enc.version >= 8)
	{
		proto_tree_add_item(tree, hf_statsum_omap,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	if (enc.version >= 9)
	{
		proto_tree_add_item(tree, hf_statsum_hitset_archive,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	return off;
}

/** Dissect a object_stat_collection_t object. */
static
guint c_dissect_statcollection(proto_tree *root, int key,
			       tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;
	guint32 i;

	/** object_stat_collection_t from ceph:/src/osd/osd_types.h */

	ti = proto_tree_add_item(root, hf_statcollection, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_statcollection);

	off = c_dissect_encoded(tree, &enc, 2, 2, tvb, off, data);

	off = c_dissect_statsum(tree, tvb, off, data);
	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		off = c_dissect_str(tree, key, NULL, tvb, off);
		off = c_dissect_statsum(tree, tvb, off, data);
	}

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

/** Dissect an pg_stat_t. */
static
guint c_dissect_pg_stats(proto_tree *root, int hf,
			 tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	c_encoded enc;
	guint32 i;

	/* pg_stat_t from ceph:/src/osd/osd_types.h */

	ti   = proto_tree_add_item(root, hf, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_pg_stat);

	off = c_dissect_encoded(tree, &enc, 8, 17, tvb, off, data);

	off = c_dissect_eversion(tree, hf_pg_stat_ver, tvb, off, data);

	proto_tree_add_item(tree, hf_pg_stat_seq,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_pg_stat_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pg_stat_state,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_eversion(tree, hf_pg_stat_logstart, tvb, off, data);
	off = c_dissect_eversion(tree, hf_pg_stat_logstartondisk, tvb, off, data);

	proto_tree_add_item(tree, hf_pg_stat_created,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_pg_stat_lastepochclean,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_pg(tree, hf_pg_stat_parent, tvb, off, data);

	proto_tree_add_item(tree, hf_pg_stat_parent_splitbits,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_eversion(tree, hf_pg_stat_lastscrub, tvb, off, data);

	proto_tree_add_item(tree, hf_pg_stat_lastscrubstamp,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off = c_dissect_statcollection(tree, hf_pg_stat_stats, tvb, off, data);

	proto_tree_add_item(tree, hf_pg_stat_logsize,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_pg_stat_logsizeondisk,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_pg_stat_up,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_pg_stat_acting,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	if (enc.version >= 9)
	{
		proto_tree_add_item(tree, hf_pg_stat_lastfresh,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_tree_add_item(tree, hf_pg_stat_lastchange,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_tree_add_item(tree, hf_pg_stat_lastactive,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_tree_add_item(tree, hf_pg_stat_lastclean,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_tree_add_item(tree, hf_pg_stat_lastunstale,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_tree_add_item(tree, hf_pg_stat_mappingepoch,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}
	if (enc.version >= 10)
	{
		off = c_dissect_eversion(tree, hf_pg_stat_lastdeepscrub, tvb, off, data);

		proto_tree_add_item(tree, hf_pg_stat_lastdeepscrubstamp,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	if (enc.version >= 11)
	{
		proto_tree_add_item(tree, hf_pg_stat_statsinvalid,
				    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;
	}
	if (enc.version >= 12)
	{
		proto_tree_add_item(tree, hf_pg_stat_lastcleanscrubstamp,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	if (enc.version >= 13)
	{
		proto_tree_add_item(tree, hf_pg_stat_lastbecameactive,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}
	if (enc.version >= 14)
	{
		proto_tree_add_item(tree, hf_pg_stat_dirtystatsinvalid,
				    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;
	}
	if (enc.version >= 15)
	{
		proto_tree_add_item(tree, hf_pg_stat_upprimary,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;

		proto_tree_add_item(tree, hf_pg_stat_actingprimary,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}
	if (enc.version >= 16)
	{
		proto_tree_add_item(tree, hf_pg_stat_omapstatsinvalid,
				    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;
	}
	if (enc.version >= 17)
	{
		proto_tree_add_item(tree, hf_pg_stat_hitsetstatsinvalid,
				    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;
	}

	c_warn_size(tree, tvb, off, enc.end, data);
	off = enc.end;

	proto_item_set_end(ti, tvb, off);
	return off;
}

#define C_SIZE_PAXOS 18

/** Dissect a Paxos Service Message */
static
guint c_dissect_paxos(proto_tree *root,
		      tvbuff_t *tvb, guint off, c_pkt_data *data _U_)
{
	proto_item *ti;
	proto_tree *tree;

	/** ceph:/src/messages/PaxosServiceMessage.h */

	ti = proto_tree_add_item(root, hf_paxos, tvb, off, C_SIZE_PAXOS, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_paxos);

	proto_tree_add_item(tree, hf_paxos_ver,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_paxos_mon,
			    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	proto_tree_add_item(tree, hf_paxos_mon_tid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	return off;
}


/*** Message Dissectors ***/

/** Used to handle unknown messages.
 *
 * Simply displays the front, middle and data portions as binary strings.
 */
static
guint c_dissect_msg_unknown(proto_tree *tree,
			    tvbuff_t *tvb,
			    guint front_len, guint middle_len, guint data_len,
			    c_pkt_data *data)
{
	guint off = 0;

	c_set_type(data, c_msg_type_string(data->header.type));
	proto_item_append_text(data->item_root,
			       ", Type: %s, Front Len: %u, Middle Len: %u, Data Len %u",
			       c_msg_type_string(data->header.type),
			       front_len, middle_len, data_len);
	expert_add_info(data->pinfo, tree, &ei_msg_unknown);

	if (front_len)
	{
		proto_tree_add_item(tree, hf_msg_front, tvb, off, front_len, ENC_NA);
		off += front_len;
	}
	if (middle_len)
	{
		proto_tree_add_item(tree, hf_msg_middle, tvb, off, middle_len, ENC_NA);
		off += middle_len;
	}
	if (data_len)
	{
		proto_tree_add_item(tree, hf_msg_data, tvb, off, data_len, ENC_NA);
		off += data_len;
	}

	return off;
}

/** Dissect ping 0x0002 */
static
guint c_dissect_msg_ping(proto_tree *root _U_,
			 tvbuff_t *tvb _U_,
			 guint front_len _U_, guint middle_len _U_, guint data_len _U_,
			 c_pkt_data *data)
{
	/* ceph:/src/messages/MPing.h */
	c_set_type(data, "Ping");
	return 0;
}

/** Dissect monmap message 0x0004 */
static
guint c_dissect_msg_mon_map(proto_tree *root,
			    tvbuff_t *tvb,
			    guint front_len, guint middle_len _U_, guint data_len _U_,
			    c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;

	/* ceph:/src/messages/MMonMap.h */

	c_set_type(data, "Mon Map");

	ti = proto_tree_add_item(root, hf_msg_mon_map, tvb, 0, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_map);

	return c_dissect_monmap(tree, tvb, 0, data);
}

/** Stat FS 0x000D */
static
guint c_dissect_msg_statfs(proto_tree *root,
			   tvbuff_t *tvb,
			   guint front_len, guint middle_len _U_, guint data_len _U_,
			   c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;

	/* ceph:/src/messages/MStatfs.h */

	c_set_type(data, "Stat FS");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_statfs, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_statfs);

	proto_tree_add_item(tree, hf_msg_statfs_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	return off;
}

/** Stat FS Reply 0x000E */
static
guint c_dissect_msg_statfsreply(proto_tree *root,
				tvbuff_t *tvb,
				guint front_len, guint middle_len _U_, guint data_len _U_,
				c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;

	/* ceph:/src/messages/MStatfsReply.h */

	c_set_type(data, "Stat FS Reply");

	ti = proto_tree_add_item(root, hf_msg_statfsreply, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_statfsreply);

	proto_tree_add_item(tree, hf_msg_statfsreply_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	proto_tree_add_item(tree, hf_msg_statfsreply_ver,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_statfsreply_kb,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_statfsreply_kbused,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_statfsreply_kbavail,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_statfsreply_obj,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	return off;
}

/** Mon subscribe message 0x000F */
static
guint c_dissect_msg_mon_sub(proto_tree *root,
			    tvbuff_t *tvb,
			    guint front_len, guint middle_len _U_, guint data_len _U_,
			    c_pkt_data *data)
{
	proto_item *ti, *subti, *subti2;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint len;
	c_str str;

	/* ceph:/src/messages/MMonSubscribe.h */

	c_set_type(data, "Mon Subscribe");

	ti = proto_tree_add_item(root, hf_msg_mon_sub, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_sub);

	c_append_text(data, ti, ", To: ");

	len = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_sub_item_len,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (len--)
	{
		/* From ceph:/src/include/ceph_fs.h
		struct ceph_mon_subscribe_item {
			__le64 start;
			__u8 flags;
		} __attribute__ ((packed))
		*/

		subti = proto_tree_add_item(tree, hf_msg_mon_sub_item,
				    tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(subti, ett_msg_mon_sub_item);

		off = c_dissect_str(subtree, hf_msg_mon_sub_what, &str, tvb, off);

		c_append_text(data, ti, "%s%s", str.str, len? ",":"");

		proto_item_append_text(subti, " What: %s, Starting: %"G_GUINT64_FORMAT,
				       str.str,
				       tvb_get_letoh64(tvb, off));

		proto_tree_add_item(subtree, hf_msg_mon_sub_start,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		/* Flags */
		subti2 = proto_tree_add_item(subtree, hf_msg_mon_sub_flags,
					     tvb, off, 1, ENC_LITTLE_ENDIAN);
		/* Reuse subtree variable for flags. */
		subtree = proto_item_add_subtree(subti2, ett_msg_mon_sub_flags);
		proto_tree_add_item(subtree, hf_msg_mon_sub_flags_onetime,
				    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;

		proto_item_set_end(ti, tvb, off);
	}

	return off;
}

/** Mon subscription ack 0x0010 */
static
guint c_dissect_msg_mon_sub_ack(proto_tree *root,
				tvbuff_t *tvb,
				guint front_len, guint middle_len _U_, guint data_len _U_,
				c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;

	/* ceph:/src/messages/MMonSubscribeAck.h */

	c_set_type(data, "Mon Subscribe Ack");

	ti = proto_tree_add_item(root, hf_msg_mon_sub_ack, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_sub_ack);

	proto_tree_add_item(tree, hf_msg_mon_sub_ack_interval,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_msg_mon_sub_ack_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	return off;
}

/** Authentication Request 0x0011. */
static
guint c_dissect_msg_auth(proto_tree *root,
			 tvbuff_t *tvb,
			 guint front_len, guint middle_len _U_, guint data_len _U_,
			 c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree, *subtree;
	guint off = 0, expectedoff;
	guint8 ver;
	guint32 i, len;
	c_auth_proto proto;

	/* ceph:/src/messages/MAuth.h */

	c_set_type(data, "Auth");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_auth, tvb, off, front_len-off, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_auth);

	proto = (c_auth_proto)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_auth_proto,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	expectedoff = off + 4 + tvb_get_letohl(tvb, off);
	off += 4;

	switch (proto)
	{
	case C_AUTH_PROTO_UNKNOWN:
		/* auth_payload is a set of supported protocols. */
		ti2 = proto_tree_add_item(tree, hf_msg_auth_supportedproto,
					  tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_auth_supportedproto);

		ver = tvb_get_guint8(tvb, off);
		c_warn_ver(ti2, ver, 1, 1, data);
		proto_tree_add_item(tree, hf_msg_auth_supportedproto_ver,
				    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;

		len = tvb_get_letohl(tvb, off);
		off += 4;
		for (i = 0; i < len; i++)
		{
			c_auth_proto sp;
			sp = (c_auth_proto)tvb_get_letohl(tvb, off);
			proto_item_append_text(ti2, i?",%s":": %s", c_auth_proto_string(sp));
			proto_tree_add_item(subtree, hf_msg_auth_supportedproto_proto,
					    tvb, off, 4, ENC_LITTLE_ENDIAN);
			off += 4;
		}

		off = c_dissect_EntityName(subtree, tvb, off, data);

		proto_tree_add_item(subtree, hf_msg_auth_supportedproto_gid,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		break;
	case C_AUTH_PROTO_CEPHX:
	{
		c_cephx_req_type type;

		ti2 = proto_tree_add_item(tree, hf_msg_auth_cephx, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_auth_cephx);

		type = (c_cephx_req_type)tvb_get_letohs(tvb, off);
		proto_tree_add_item(subtree, hf_msg_auth_cephx_req_type,
				    tvb, off, 2, ENC_LITTLE_ENDIAN);
		off += 2;

		switch (type)
		{
		default:
			expert_add_info(data->pinfo, ti2, &ei_union_unknown);
		}

		proto_item_append_text(ti2, ", Request Type: %s",
				       c_cephx_req_type_string(type));
		break;
	}
	default:
		expert_add_info(data->pinfo, ti, &ei_union_unknown);
	}

	c_warn_size(tree, tvb, off, expectedoff, data);
	off = expectedoff;

	if (off+4 == front_len) { /* If there is an epoch. */
		proto_tree_add_item(tree, hf_msg_auth_monmap_epoch,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	c_append_text(data, ti, ", Proto: %s", c_auth_proto_string(proto));

	return off;
}

/** Authentication response. 0x0012 */
static
guint c_dissect_msg_auth_reply(proto_tree *root,
			       tvbuff_t *tvb,
			       guint front_len, guint middle_len _U_, guint data_len _U_,
			       c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0, expectedoff;
	c_auth_proto proto;

	/* ceph:/src/messages/MAuthReply.h */

	c_set_type(data, "Auth Reply");

	ti = proto_tree_add_item(root, hf_msg_auth_reply, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_authreply);

	proto = (c_auth_proto)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_auth_reply_proto,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_msg_auth_reply_result,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_msg_auth_reply_global_id,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	expectedoff = off + 4 + tvb_get_letohl(tvb, off);
	off += 4;

	switch (proto)
	{
	default:
		expert_add_info(data->pinfo, ti, &ei_union_unknown);
	}

	c_warn_size(tree, tvb, off, expectedoff, data);
	off = expectedoff;

	off = c_dissect_str(tree, hf_msg_auth_reply_msg, NULL, tvb, off);

	c_append_text(data, ti, ", Proto: %s", c_auth_proto_string(proto));

	return off;
}

/** Get map versions. 0x0013 */
static
guint c_dissect_msg_mon_getversion(proto_tree *root,
				   tvbuff_t *tvb,
				   guint front_len, guint middle_len _U_, guint data_len _U_,
				   c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint64 tid;
	c_str what;

	/* ceph:/src/messages/MMonGetVersion.h */

	c_set_type(data, "Monitor Get Version");

	ti = proto_tree_add_item(root, hf_msg_mon_getverison, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_getversion);

	tid = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_getverison_tid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off = c_dissect_str(tree, hf_msg_mon_getverison_what, &what, tvb, off);


	c_append_text(data, ti, ", TID: %"G_GINT64_MODIFIER"u, What: %s",
		      tid, what.str);

	return off;
}


/** Get map versions response. 0x0014 */
static
guint c_dissect_msg_mon_getversionreply(proto_tree *root,
					tvbuff_t *tvb,
					guint front_len,
					guint middle_len _U_,
					guint data_len _U_,
					c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint64 tid;
	guint64 ver, veroldest;

	/* ceph:/src/messages/MMonGetVersionReply.h */

	c_set_type(data, "Monitor Get Version Reply");

	ti = proto_tree_add_item(root, hf_msg_mon_getverisonreply, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_getversionreply);

	tid = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_getverisonreply_tid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	ver = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_getverisonreply_ver,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	veroldest = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_getverisonreply_veroldest,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	c_append_text(data, ti, ", TID: %"G_GINT64_MODIFIER"u"
		      ", Version: %"G_GINT64_MODIFIER"u"
		      ", Oldest Version: %"G_GINT64_MODIFIER"u",
		      tid, ver, veroldest);

	return off;
}

/** MDS Map 0x0015 */
static
guint c_dissect_msg_mds_map(proto_tree *root,
			    tvbuff_t *tvb,
			    guint front_len, guint middle_len _U_, guint data_len _U_,
			    c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;

	/* ceph:/src/messages/MMDSMap.h */

	c_set_type(data, "MDS Map");

	ti = proto_tree_add_item(root, hf_msg_mds_map, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mds_map);

	proto_tree_add_item(tree, hf_msg_mds_map_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	proto_tree_add_item(tree, hf_msg_mds_map_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	/* @TODO: Dissect map data. */

	off = c_dissect_blob(tree, hf_msg_mds_map_datai,
			     hf_msg_mds_map_data, hf_msg_mds_map_data_size,
			     tvb, off);

	return off;
}

/** Client Session 0x0016 */
static
guint c_dissect_msg_client_sess(proto_tree *root,
				tvbuff_t *tvb,
				guint front_len, guint middle_len _U_, guint data_len _U_,
				c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	c_session_op_type op;

	/* ceph:/src/messages/MClientSession.h */

	c_set_type(data, "Client Session");

	ti = proto_tree_add_item(root, hf_msg_client_sess, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_client_sess);

	op = (c_session_op_type)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_sess_op,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_sess_seq,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_client_sess_time,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_client_sess_caps_max,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_sess_leases_max,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	c_append_text(data, ti, ", Operation: %s", c_session_op_type_string(op));

	return off;
}

/** Client Request 0x0018 */
static
guint c_dissect_msg_client_req(proto_tree *root,
			       tvbuff_t *tvb,
			       guint front_len, guint middle_len _U_, guint data_len _U_,
			       c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;
	c_mds_op_type type;

	/* ceph:/src/messages/MClientRequest.h */

	c_set_type(data, "Client Request");

	ti = proto_tree_add_item(root, hf_msg_client_req, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_client_req);

	proto_tree_add_item(tree, hf_msg_client_req_oldest_tid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_client_req_mdsmap_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_req_flags,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_req_retry,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_msg_client_req_forward,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	i = tvb_get_letohs(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_req_releases,
			    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;

	type = (c_mds_op_type)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_req_op,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_req_caller_uid,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_req_caller_gid,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_req_inode,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off += 48; /* @TODO: Message specific data. */

	off = c_dissect_path(tree, hf_msg_client_req_path_src, tvb, off, data);
	off = c_dissect_path(tree, hf_msg_client_req_path_dst, tvb, off, data);

	while (i--)
	{
		off = c_dissect_mds_release(tree, hf_msg_client_req_release,
					    tvb, off, data);
	}

	if (data->header.ver >= 2)
	{
		proto_tree_add_item(tree, hf_msg_client_req_time,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}

	c_append_text(data, ti, ", Operation: %s", c_mds_op_type_string(type));

	return off;
}

/** Client Request Forward 0x0019 */
static
guint c_dissect_msg_client_reqfwd(proto_tree *root,
				  tvbuff_t *tvb,
				  guint front_len, guint middle_len _U_, guint data_len _U_,
				  c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 to, fwd;
	guint8 resend;

	/* ceph:/src/messages/MClientRequestForward.h */

	c_set_type(data, "Client Request Forward");

	ti = proto_tree_add_item(root, hf_msg_client_reqfwd, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_client_reqfwd);

	to = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_reqfwd_dst,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	fwd = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_reqfwd_fwd,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	resend = tvb_get_guint8(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_reqfwd_resend,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	c_append_text(data, ti, ", To: mds%"G_GINT32_MODIFIER"u, Resend: %s, "
		      "Forwards: %"G_GINT32_MODIFIER"u",
		      to, resend? "True":"False", fwd);

	return off;
}

/** Client Reply 0x001A */
static
guint c_dissect_msg_client_reply(proto_tree *root,
				 tvbuff_t *tvb,
				 guint front_len, guint middle_len _U_, guint data_len _U_,
				 c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	c_mds_op_type type;

	/* ceph:/src/messages/MClientReply.h */

	c_set_type(data, "Client Reply");

	ti = proto_tree_add_item(root, hf_msg_client_reply, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_client_reply);

	type = (c_mds_op_type)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_reply_op,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_reply_result,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_reply_mdsmap_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_reply_safe,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_msg_client_reply_isdentry,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	proto_tree_add_item(tree, hf_msg_client_reply_istarget,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	/* @TODO: Dissect these. */
	off = c_dissect_data(tree, hf_msg_client_reply_trace, tvb, off);
	off = c_dissect_data(tree, hf_msg_client_reply_extra, tvb, off);
	off = c_dissect_data(tree, hf_msg_client_reply_snaps, tvb, off);

	c_append_text(data, ti, ", Operation: %s", c_mds_op_type_string(type));

	return off;
}

/** OSD Map 0x0029 */
static
guint c_dissect_msg_osd_map(proto_tree *root,
			    tvbuff_t *tvb,
			    guint front_len, guint middle_len _U_, guint data_len _U_,
			    c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint32 i;
	guint32 epoch;

	/* ceph:/src/messages/MOSDMap.h */

	c_set_type(data, "OSD Map");

	ti = proto_tree_add_item(root, hf_msg_osd_map, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_osd_map);

	proto_tree_add_item(tree, hf_msg_osd_map_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	/*** Incremental Items ***/
	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_osd_map_inc_len,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	c_append_text(data, ti, ", Incremental Items: %u", i);

	off += 4;
	while (i--)
	{
		ti2 = proto_tree_add_item(tree, hf_msg_osd_map_inc,
				    tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_osd_map_inc);

		epoch = tvb_get_letohl(tvb, off);
		proto_tree_add_item(subtree, hf_msg_osd_map_epoch,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;

		off = c_dissect_osdmap_inc(subtree, tvb, off, data);

		proto_item_append_text(ti2, ", For Epoch: %"G_GINT32_MODIFIER"u", epoch);
		proto_item_set_end(ti2, tvb, off);
	}

	/*** Non-incremental Items ***/
	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_osd_map_map_len,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	c_append_text(data, ti, ", Items: %u", i);
	off += 4;
	while (i--)
	{
		ti2 = proto_tree_add_item(tree, hf_msg_osd_map_map,
					  tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_osd_map_full);

		epoch = tvb_get_letohl(tvb, off);
		proto_tree_add_item(subtree, hf_msg_osd_map_epoch,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;

		off = c_dissect_osdmap(subtree, tvb, off, data);

		proto_item_append_text(ti2, ", For Epoch: %"G_GINT32_MODIFIER"u", epoch);
		proto_item_set_end(ti2, tvb, off);
	}

	if (data->header.ver >= 2)
	{
		proto_tree_add_item(tree, hf_msg_osd_map_oldest,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
		proto_tree_add_item(tree, hf_msg_osd_map_newest,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	return off;
}

/** OSD Operation (0x002A)
 */
static
guint c_dissect_msg_osd_op(proto_tree *root,
			   tvbuff_t *tvb,
			   guint front_len, guint middle_len _U_, guint data_len _U_,
			   c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree;
	guint off = 0;
	guint16 opslen, i;
	c_osd_op *ops;
	c_str str;

	/* ceph:/src/messages/MOSDOp.h */

	c_set_type(data, "OSD Operation");

	ti = proto_tree_add_item(root, hf_msg_osd_op, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_osd_op);

	proto_tree_add_item(tree, hf_msg_osd_op_client_inc,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_osd_op_osdmap_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_osd_flags(tree, tvb, off, data);

	proto_tree_add_item(tree, hf_msg_osd_op_mtime,
			    tvb, off, 8, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
	off += 8;

	off = c_dissect_eversion(tree, hf_msg_osd_op_reassert_version,
				 tvb, off, data);

	off = c_dissect_object_locator(tree, hf_msg_osd_op_oloc, tvb, off, data);

	off = c_dissect_pg(tree, hf_msg_osd_op_pgid, tvb, off, data);

	off = c_dissect_str(tree, hf_msg_osd_op_oid, &str, tvb, off);

	opslen = tvb_get_letohs(tvb, off);
	c_append_text(data, ti, ", Operations: %"G_GINT32_MODIFIER"d", opslen);
	ti2 = proto_tree_add_item(tree, hf_msg_osd_op_ops_len,
				  tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	if (opslen > (tvb_reported_length(tvb)-off)/C_SIZE_OSD_OP_MIN)
	{
		/*
			If the size is huge (maybe it was mangled on the wire) we want to
			avoid allocating massive amounts of memory to handle it.  So, if
			it is larger then can possibly fit in the rest of the message bail
			out.
		*/
		expert_add_info(data->pinfo, ti2, &ei_sizeillogical);
		return off;
	}
	ops = wmem_alloc_array(wmem_packet_scope(), c_osd_op, opslen);
	for (i = 0; i < opslen; i++)
	{
		off = c_dissect_osd_op(tree, hf_msg_osd_op_op, &ops[i], tvb, off, data);
	}

	proto_tree_add_item(tree, hf_msg_osd_op_snap_id,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_msg_osd_op_snap_seq,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_osd_op_snaps_len,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_msg_osd_op_snap,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}

	if (data->header.ver >= 4)
	{
		proto_tree_add_item(tree, hf_msg_osd_op_retry_attempt,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	c_warn_size(tree, tvb, off, front_len, data);

	for (i = 0; i < opslen; i++)
	{
		proto_tree_add_item(tree, hf_msg_osd_op_payload,
				    tvb, off, ops[i].payload_size, ENC_NA);
		off += ops[i].payload_size;
	}

	return off;
}

/** OSD Operation Reply (0x002B)
 */
static
guint c_dissect_msg_osd_opreply(proto_tree *root,
				tvbuff_t *tvb,
				guint front_len, guint middle_len _U_, guint data_len _U_,
				c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree;
	guint off = 0;
	c_str str;
	guint32 i;
	guint32 opslen;
	c_osd_op *ops;

	/* ceph:/src/messages/MOSDOpReply.h */

	c_set_type(data, "OSD Operation Reply");

	ti = proto_tree_add_item(root, hf_msg_osd_opreply, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_osd_opreply);

	off = c_dissect_str(tree, hf_msg_osd_opreply_oid, &str, tvb, off);

	off = c_dissect_pg(tree, hf_msg_osd_opreply_pgid, tvb, off, data);

	off = c_dissect_osd_flags(tree, tvb, off, data);
	off += 4; /* flags is 64 bit but the higher bits are ignored. */

	proto_tree_add_item(tree, hf_msg_osd_opreply_result,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_eversion(tree, hf_msg_osd_opreply_bad_replay_ver,
				 tvb, off, data);

	proto_tree_add_item(tree, hf_msg_osd_opreply_osdmap_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	opslen = tvb_get_letohl(tvb, off);
	ti2 = proto_tree_add_item(tree, hf_msg_osd_opreply_ops_len,
				  tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	if (opslen >= (tvb_reported_length(tvb)-off)/C_SIZE_OSD_OP_MIN)
	{
		/*
			If the size is huge (maybe it was mangled on the wire) we want to
			avoid allocating massive amounts of memory to handle it.  So, if
			it is larger then can possible fit in the rest of the message bail
			out.
		*/
		expert_add_info(data->pinfo, ti2, &ei_sizeillogical);
		return off;
	}
	ops = wmem_alloc_array(wmem_packet_scope(), c_osd_op, opslen);
	for (i = 0; i < opslen; i++)
	{
		off = c_dissect_osd_op(tree, hf_msg_osd_opreply_op, &ops[i],
				       tvb, off, data);
	}

	if (data->header.ver >= 3)
	{
		proto_tree_add_item(tree, hf_msg_osd_opreply_retry_attempt,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	if (data->header.ver >= 4)
	{
		for (i = 0; i < opslen; i++)
		{
			proto_tree_add_item(tree, hf_msg_osd_opreply_rval,
					    tvb, off, 4, ENC_LITTLE_ENDIAN);
			off += 4;
		}
	}

	if (data->header.ver >= 5)
	{
		off = c_dissect_eversion(tree, hf_msg_osd_opreply_replay_ver,
					 tvb, off, data);
		proto_tree_add_item(tree, hf_msg_osd_opreply_user_ver,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}

	if (data->header.ver >= 6)
	{
		off = c_dissect_redirect(tree, hf_msg_osd_opreply_redirect,
					 tvb, off, data);
	}

	c_warn_size(tree, tvb, off, front_len, data);
	off = front_len;

	if (data->header.ver >= 4)
	{
		for (i = 0; i < opslen; i++)
		{
			proto_tree_add_item(tree, hf_msg_osd_opreply_payload,
					    tvb, off, ops[i].payload_size, ENC_NA);
			off += ops[i].payload_size;
		}
	}

	return off;
}

/** Pool Op Reply 0x0030 */
static
guint c_dissect_msg_poolopreply(proto_tree *root,
				tvbuff_t *tvb,
				guint front_len, guint middle_len _U_, guint data_len _U_,
				c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	gint32 code;
	guint8 b;

	/* ceph:/src/messages/MPoolOpReply.h */

	c_set_type(data, "Pool Operation Reply");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_poolopreply, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_poolopreply);

	proto_tree_add_item(tree, hf_msg_poolopreply_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	code = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_poolopreply_code,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_poolopreply_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	b = tvb_get_guint8(tvb, off);
	off += 1;
	if (b)
		off = c_dissect_blob(tree, hf_msg_poolopreply_datai,
				     hf_msg_poolopreply_data, hf_msg_poolopreply_data_size,
				     tvb, off);

	c_append_text(data, ti, ", Response Code: %"G_GINT32_MODIFIER"u", code);

	return off;
}

/** Pool Op 0x0031
 * Why this is a higher value than the reply?  Who knows?
 */
static
guint c_dissect_msg_poolop(proto_tree *root,
			   tvbuff_t *tvb,
			   guint front_len, guint middle_len _U_, guint data_len _U_,
			   c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	gint32 pool;
	c_poolop_type type;
	c_str name;

	/* ceph:/src/messages/MPoolOp.h */

	c_set_type(data, "Pool Operation");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_poolop, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_poolop);

	proto_tree_add_item(tree, hf_msg_poolop_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	pool = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_poolop_pool,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	if (data->header.ver < 2)
		off = c_dissect_str(tree, hf_msg_poolop_name, &name, tvb, off);

	type = (c_poolop_type)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_poolop_type,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_poolop_auid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_poolop_snapid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	if (data->header.ver >= 2)
		off = c_dissect_str(tree, hf_msg_poolop_name, &name, tvb, off);

	if (data->header.ver >= 4)
	{
		off += 1; /* Skip padding byte. */
		proto_tree_add_item(tree, hf_msg_poolop_crush_rule,
				    tvb, off, 2, ENC_LITTLE_ENDIAN);
		off += 2;
	}
	else if (data->header.ver == 3)
	{
		proto_tree_add_item(tree, hf_msg_poolop_crush_rule8,
				    tvb, off, 1, ENC_LITTLE_ENDIAN);
		off += 1;
	}

	c_append_text(data, ti,
		      ", Type: %s, Name: %s, Pool: %"G_GINT32_MODIFIER"d",
		      c_poolop_type_string(type),
		      name.str,
		      pool);

	return off;
}

/** Monitor Command 0x0032 */
static
guint c_dissect_msg_mon_cmd(proto_tree *root,
			    tvbuff_t *tvb,
			    guint front_len, guint middle_len _U_, guint data_len _U_,
			    c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint32 i;
	c_str str;

	/* ceph:/src/messages/MMonCommand.h */

	c_set_type(data, "Mon Command");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_mon_cmd, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_cmd);

	proto_tree_add_item(tree, hf_msg_mon_cmd_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_cmd_arg_len,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (i--)
	{
		ti = proto_tree_add_item(tree, hf_msg_mon_cmd_arg,
					 tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, ett_msg_mon_cmd_arg);

		off = c_dissect_str(subtree, hf_msg_mon_cmd_str, &str, tvb, off);

		c_append_text(data, ti, " %s", str.str);

		proto_item_set_end(ti, tvb, off);
	}

	return off;
}

/** Mon Command ACK 0x0033 */
static
guint c_dissect_msg_mon_cmd_ack(proto_tree *root,
				tvbuff_t *tvb,
				guint front_len, guint middle_len _U_, guint data_len,
				c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint32 i;

	/* ceph:/src/messages/MMonCommandAck.h */

	c_set_type(data, "Mon Command Result");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_mon_cmd_ack,
				 tvb, off, front_len+data_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_cmdack);

	proto_tree_add_item(tree, hf_msg_mon_cmd_ack_code,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	off = c_dissect_str(tree, hf_msg_mon_cmd_ack_res, NULL, tvb, off);

	i = tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_cmd_ack_arg_len,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	while (i--)
	{
		ti = proto_tree_add_item(tree, hf_msg_mon_cmd_ack_arg, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, ett_msg_mon_cmdack_arg);

		off = c_dissect_str(subtree, hf_msg_mon_cmd_ack_arg_str, NULL,
				    tvb, off);

		proto_item_set_end(ti, tvb, off);
	}

	c_warn_size(tree, tvb, off, front_len, data);

	proto_tree_add_item(tree, hf_msg_mon_cmd_ack_data,
			    tvb, front_len, data_len, ENC_UTF_8|ENC_NA);

	return front_len+data_len;
}

/** Get Pool Stats 0x003A */
static
guint c_dissect_msg_poolstats(proto_tree *root,
			      tvbuff_t *tvb,
			      guint front_len, guint middle_len _U_, guint data_len _U_,
			      c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;
	c_str str;

	/* ceph:/src/messages/MGetPoolStats.h */

	c_set_type(data, "Pool Stats");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_poolstats, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_poolstats);

	c_append_text(data, ti, ", For: ");

	proto_tree_add_item(tree, hf_msg_poolstats_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		off = c_dissect_str(tree, hf_msg_poolstats_pool, &str, tvb, off);
		c_append_text(data, ti, "%s%s", str.str, i? ",":" ");
	}

	return off;
}

/** Pool Stats Reply 0x003B */
static
guint c_dissect_msg_poolstatsreply(proto_tree *root,
				   tvbuff_t *tvb,
				   guint front_len, guint middle_len _U_, guint data_len _U_,
				   c_pkt_data *data)
{
	proto_item *ti, *ti2;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint32 i;
	c_str str;
	c_encoded encstat;

	/* ceph:/src/messages/MGetPoolStatsReply.h */

	c_set_type(data, "Pool Stats Reply");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_poolstatsreply, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_poolstatsreply);

	c_append_text(data, ti, ", For: ");

	proto_tree_add_item(tree, hf_msg_poolstatsreply_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		ti2 = proto_tree_add_item(tree, hf_msg_poolstatsreply_stat,
					  tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_poolstatsreply_stat);

		off = c_dissect_str(subtree, hf_msg_poolstatsreply_pool, &str, tvb, off);
		c_append_text(data, ti, "%s%s", str.str, i? ",":" ");
		proto_item_append_text(ti2, ", For: %s", str.str);

		/*** pool_stat_t from ceph:/src/osd/osd_types.h ***/
		off = c_dissect_encoded(subtree, &encstat, 5, 5, tvb, off, data);

		off = c_dissect_statcollection(subtree, hf_msg_poolstatsreply_pool, tvb, off, data);

		proto_tree_add_item(subtree, hf_msg_poolstatsreply_log_size,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		proto_tree_add_item(subtree, hf_msg_poolstatsreply_log_size_ondisk,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		/*** END pool_stat_t ***/
		c_warn_size(subtree, tvb, off, encstat.end, data);
		off = encstat.end;
	}

	return off;
}

/** Monitor Global ID 0x003C */
static
guint c_dissect_msg_mon_globalid(proto_tree *root,
				 tvbuff_t *tvb,
				 guint front_len _U_, guint middle_len _U_, guint data_len _U_,
				 c_pkt_data *data)
{
	guint off = 0;

	/* ceph:/src/messages/MMonGlobalID.h */

	c_set_type(data, "Mon Global ID");

	off = c_dissect_paxos(root, tvb, off, data);
	proto_tree_add_item(root, hf_msg_mon_globalid_max,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	return off;
}

/** Monitor Election 0x0041 */
static
guint c_dissect_msg_mon_election(proto_tree *root,
				 tvbuff_t *tvb,
				 guint front_len, guint middle_len _U_, guint data_len _U_,
				 c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;
	c_mon_election_type type;

	/* ceph:/src/messages/MMonElection.h */

	c_set_type(data, "Mon Election");

	ti = proto_tree_add_item(root, hf_msg_mon_election,
			    tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_election);

	proto_tree_add_item(tree, hf_msg_mon_election_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	type = (c_mon_election_type)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_election_op,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_mon_election_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_monmap(tree, tvb, off, data);

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_msg_mon_election_quorum,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	proto_tree_add_item(tree, hf_msg_mon_election_quorum_features,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_mon_election_defunct_one,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_msg_mon_election_defunct_two,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off = c_dissect_blob(tree, hf_msg_mon_election_sharing,
			     hf_msg_mon_election_sharing_data, hf_msg_mon_election_sharing_size,
			     tvb, off);

	c_append_text(data, ti, ", Operation: %s", c_mon_election_type_string(type));

	return off;
}

/** Monitor Paxos 0x0042 */
static
guint c_dissect_msg_mon_paxos(proto_tree *root,
			      tvbuff_t *tvb,
			      guint front_len, guint middle_len _U_, guint data_len _U_,
			      c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;
	guint64 pn;
	c_mon_paxos_op op;

	/* ceph:/src/messages/MMonPaxos.h */

	c_set_type(data, "Mon Paxos");

	ti = proto_tree_add_item(root, hf_msg_mon_paxos, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_paxos);

	proto_tree_add_item(tree, hf_msg_mon_paxos_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	op = (c_mon_paxos_op)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_paxos_op,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_mon_paxos_first,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_mon_paxos_last,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_mon_paxos_pnfrom,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	pn = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_paxos_pn,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_mon_paxos_pnuncommitted,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_mon_paxos_lease,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	if (data->header.ver >= 1)
	{
		proto_tree_add_item(tree, hf_msg_mon_paxos_sent,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}

	proto_tree_add_item(tree, hf_msg_mon_paxos_latest_ver,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off = c_dissect_blob(tree, hf_msg_mon_paxos_latest_val,
			     hf_msg_mon_paxos_latest_val_data,
			     hf_msg_mon_paxos_latest_val_size,
			     tvb, off);

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *ti2;
		proto_tree *subtree;
		guint64 ver;

		ti2 = proto_tree_add_item(tree, hf_msg_mon_paxos_value, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_mon_paxos_value);

		ver = tvb_get_letoh64(tvb, off);
		proto_tree_add_item(subtree, hf_msg_mon_paxos_ver,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		off = c_dissect_blob(subtree, hf_msg_mon_paxos_val,
				     hf_msg_mon_paxos_val_data, hf_msg_mon_paxos_val_size,
				     tvb, off);

		proto_item_append_text(ti2, ", Version: %"G_GINT64_MODIFIER"u", ver);
		proto_item_set_end(ti2, tvb, off);
	}

	c_append_text(data, ti, ", Op: %s, Proposal Number: %"G_GINT64_MODIFIER"u",
		      c_mon_paxos_op_string(op), pn);

	return off;
}

/** Monitor Probe 0x0043 */
static
guint c_dissect_msg_mon_probe(proto_tree *root,
			     tvbuff_t *tvb,
			     guint front_len, guint middle_len _U_, guint data_len _U_,
			     c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;
	c_mon_probe_type type;
	c_str name;

	/* ceph:/src/messages/MMonProbe.h */

	c_set_type(data, "Mon Probe");

	ti = proto_tree_add_item(root, hf_msg_mon_probe, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_mon_probe);

	proto_tree_add_item(tree, hf_msg_mon_probe_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	type = (c_mon_probe_type)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_mon_probe_type,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_str(tree, hf_msg_mon_probe_name, &name, tvb, off);

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_tree_add_item(tree, hf_msg_mon_probe_quorum,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}

	off = c_dissect_monmap(tree, tvb, off, data);

	proto_tree_add_item(tree, hf_msg_mon_probe_ever_joined,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;
	proto_tree_add_item(tree, hf_msg_mon_probe_paxos_first_ver,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	proto_tree_add_item(tree, hf_msg_mon_probe_paxos_last_ver,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	if (data->header.ver >= 6)
	{
		proto_tree_add_item(tree, hf_msg_mon_probe_req_features,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}

	c_append_text(data, ti, ", Type: %s, Name: %s",
		      c_mon_probe_type_string(type),
		      name.str);

	return off;
}

/** OSD Ping (0x0046) */
static
guint c_dissect_msg_osd_ping(proto_tree *root,
			     tvbuff_t *tvb,
			     guint front_len, guint middle_len _U_, guint data_len _U_,
			     c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	c_osd_ping_op op;

	/* ceph:/src/messages/MOSDPing.h */

	c_set_type(data, "OSD Ping");

	ti = proto_tree_add_item(root, hf_msg_osd_ping, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_osd_ping);

	proto_tree_add_item(tree, hf_msg_osd_ping_fsid,
			    tvb, off, 16, ENC_BIG_ENDIAN);
	off += 16;

	proto_tree_add_item(tree, hf_msg_osd_ping_mapepoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_osd_ping_peerepoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	op = (c_osd_ping_op)tvb_get_guint8(tvb, off);
	proto_tree_add_item(tree, hf_msg_osd_ping_op,
			    tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	off = c_dissect_osd_peerstat(tree, tvb, off, data);

	if (data->header.ver >= 2)
	{
		proto_tree_add_item(tree, hf_msg_osd_ping_time,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
	}

	c_append_text(data, ti, ", Operation: %s", c_osd_ping_op_string(op));
	return off;
}

/** OSD Boot (0x0047) */
static
guint c_dissect_msg_osd_boot(proto_tree *root,
			     tvbuff_t *tvb,
			     guint front_len, guint middle_len _U_, guint data_len _U_,
			     c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;

	/* ceph:/src/messages/MOSDBoot.h */

	c_set_type(data, "OSD Boot");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_osd_boot, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_osd_boot);

	off = c_dissect_osd_superblock(tree, tvb, off, data);

	off = c_dissect_entityaddr(tree, hf_msg_osd_boot_addr_back, NULL, tvb, off);

	if (data->header.ver >= 2)
	{
		off = c_dissect_entityaddr(tree, hf_msg_osd_boot_addr_cluster, NULL, tvb, off);
	}
	if (data->header.ver >= 3)
	{
		proto_tree_add_item(tree, hf_msg_osd_boot_epoch,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;
	}
	if (data->header.ver >= 4)
	{
		off = c_dissect_entityaddr(tree, hf_msg_osd_boot_addr_front, NULL, tvb, off);
	}
	if (data->header.ver >= 5)
	{
		i = tvb_get_letohl(tvb, off);
		off += 4;
		while (i--)
		{
			off = c_dissect_kv(tree, hf_msg_osd_boot_metadata,
					   hf_msg_osd_boot_metadata_k, hf_msg_osd_boot_metadata_v,
					   tvb, off);
		}
	}

	return off;
}

/** PG Stats (0x0057) */
static
guint c_dissect_msg_pgstats(proto_tree *root,
			    tvbuff_t *tvb,
			    guint front_len, guint middle_len _U_, guint data_len _U_,
			    c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;

	/* ceph:/src/messages/MPGStats.h */

	c_set_type(data, "PG Stats");

	off = c_dissect_paxos(root, tvb, off, data);

	ti = proto_tree_add_item(root, hf_msg_pgstats, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_pgstats);

	proto_tree_add_item(tree, hf_msg_pgstats_fsid,
			    tvb, off, 16, ENC_LITTLE_ENDIAN);
	off += 16;

	off = c_dissect_osd_stat(tree, tvb, off, data);

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *ti2;
		proto_tree *subtree;

		ti2 = proto_tree_add_item(tree, hf_msg_pgstats_pgstat, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_pgstats_pgstat);

		off = c_dissect_pg(subtree, hf_msg_pgstats_pgstat_pg, tvb, off, data);
		off = c_dissect_pg_stats(subtree, hf_msg_pgstats_pgstat_stat, tvb, off, data);

		proto_item_set_end(ti2, tvb, off);
	}

	proto_tree_add_item(tree, hf_msg_pgstats_epoch,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_pgstats_mapfor,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	return off;
}

/** OSD PG Create (0x0059) */
static
guint c_dissect_msg_osd_pg_create(proto_tree *root,
				  tvbuff_t *tvb,
				  guint front_len, guint middle_len _U_, guint data_len _U_,
				  c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;

	/* ceph:/src/messages/MOSDPGCreate.h */

	c_set_type(data, "OSD PG Create");

	ti = proto_tree_add_item(root, hf_msg_osd_pg_create, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_osd_pg_create);

	proto_tree_add_item(tree, hf_msg_osd_pg_create_epoch,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *ti2;
		proto_tree *subtree;

		ti2 = proto_tree_add_item(tree, hf_msg_osd_pg_create_mkpg,
					  tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_osd_pg_create_mkpg);

		off = c_dissect_pg(subtree, hf_msg_osd_pg_create_mkpg_pg, tvb, off, data);
		off = c_dissect_pg_create(subtree, hf_msg_osd_pg_create_mkpg_create, tvb, off, data);

		proto_item_set_end(ti2, tvb, off);
	}

	return off;
}

/** Client Caps 0x0310 */
static
guint c_dissect_msg_client_caps(proto_tree *root,
				tvbuff_t *tvb,
				guint front_len, guint middle_len, guint data_len _U_,
				c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	c_cap_op_type op;
	guint64 inode, relam;
	guint32 snap_trace_len, xattr_len;

	/* ceph:/src/messages/MClientCaps.h */

	c_set_type(data, "Client Capabilities");

	ti = proto_tree_add_item(root, hf_msg_client_caps, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_client_caps);

	op = (c_cap_op_type)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_caps_op,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	inode = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_caps_inode,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	relam = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_client_caps_relam,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_client_caps_cap_id,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	proto_tree_add_item(tree, hf_msg_client_caps_seq,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_seq_issue,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_new,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_wanted,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_dirty,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_seq_migrate,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_snap_follows,
			    tvb, off, 8, ENC_BIG_ENDIAN);
	off += 8;

	snap_trace_len = tvb_get_letohl(tvb, off);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_uid,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_gid,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_mode,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_nlink,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	xattr_len = tvb_get_letohl(tvb, off);
	off += 4;

	proto_tree_add_item(tree, hf_msg_client_caps_xattr_ver,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	off += 84; /* @TODO: Union. */

	proto_tree_add_item(tree, hf_msg_client_caps_snap,
			    tvb, off, snap_trace_len, ENC_NA);
	off += snap_trace_len;

	if (data->header.ver >= 2)
	{
		off = c_dissect_data(tree, hf_msg_client_caps_flock, tvb, off);
	}

	if (data->header.ver >= 3 && op == C_CAP_OP_IMPORT)
	{
		/* ceph:/src/include/ceph_fs.h
		struct ceph_mds_cap_peer {
			__le64 cap_id;
			__le32 seq;
			__le32 mseq;
			__le32 mds;
			__u8   flags;
		} __attribute__ ((packed));
		*/
		/* @TODO: Parse this. */
		off += 21;
	}

	if (data->header.ver >= 4)
	{
		proto_tree_add_item(tree, hf_msg_client_caps_inline_ver,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		off = c_dissect_data(tree, hf_msg_client_caps_inline_data, tvb, off);
	}

	c_warn_size(tree, tvb, off, front_len, data);
	c_warn_size(tree, tvb, front_len+xattr_len, front_len+middle_len, data);

	proto_tree_add_item(tree, hf_msg_client_caps_xattr,
			    tvb, front_len, middle_len, ENC_NA);

	proto_item_append_text(ti, ", Op: %s"
			       ", Inode: 0x%016"G_GINT64_MODIFIER"X"
			       ", Relam: 0x%"G_GINT64_MODIFIER"X",
			       c_cap_op_type_string(op),
			       inode, relam);

	return front_len+middle_len;
}

/** Client Cap Release 0x0310 */
static
guint c_dissect_msg_client_caprel(proto_tree *root,
				  tvbuff_t *tvb,
				  guint front_len, guint middle_len, guint data_len _U_,
				  c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree, *subtree;
	guint off = 0;
	guint32 i;

	/* ceph:/src/messages/MClientCapRelease.h */

	c_set_type(data, "Client Cap Release");

	ti = proto_tree_add_item(root, hf_msg_client_caprel, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_client_caprel);

	i = (c_cap_op_type)tvb_get_letohl(tvb, off);
	proto_item_append_text(ti, ", Caps: %"G_GINT32_MODIFIER"u", i);
	off += 4;
	while (i--)
	{
		ti = proto_tree_add_item(tree, hf_msg_client_caprel_cap, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti, ett_msg_client_caprel_cap);

		proto_tree_add_item(subtree, hf_msg_client_caprel_cap_inode,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_tree_add_item(subtree, hf_msg_client_caprel_cap_id,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_tree_add_item(subtree, hf_msg_client_caprel_cap_migrate,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;

		proto_tree_add_item(subtree, hf_msg_client_caprel_cap_seq,
				    tvb, off, 4, ENC_LITTLE_ENDIAN);
		off += 4;

		proto_item_set_end(ti, tvb, off);
	}

	return front_len+middle_len;
}

/** Time Check 0x0600 */
static
guint c_dissect_msg_timecheck(proto_tree *root,
			      tvbuff_t *tvb,
			      guint front_len, guint middle_len _U_, guint data_len _U_,
			      c_pkt_data *data)
{
	proto_item *ti;
	proto_tree *tree;
	guint off = 0;
	guint32 i;
	c_timecheck_op op;
	guint64 epoch, round;

	/* ceph:/src/messages/MTimeCheck.h */

	c_set_type(data, "Time Check");

	ti = proto_tree_add_item(root, hf_msg_timecheck, tvb, off, front_len, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_msg_timecheck);

	op = (c_timecheck_op)tvb_get_letohl(tvb, off);
	proto_tree_add_item(tree, hf_msg_timecheck_op,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	epoch = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_timecheck_epoch,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	round = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(tree, hf_msg_timecheck_round,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	c_append_text(data, ti, ", Operation: %s, Epoch: %"G_GINT64_MODIFIER"u"
		      ", Round: %"G_GINT64_MODIFIER"u",
		      c_timecheck_op_string(op),
		      epoch, round);

	if (op == C_TIMECHECK_OP_PONG)
	{
		c_append_text(data, ti, ", Time: %s", c_format_timespec(tvb, off));
		proto_tree_add_item(tree, hf_msg_timecheck_time,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
	}
	off += 8; /* Still in the message, but zeroed and meaningless. */

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *ti2;
		proto_tree *subtree;
		c_entityinst inst;
		double skew;

		ti2 = proto_tree_add_item(tree, hf_msg_timecheck_skew, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_timecheck_skew);

		off = c_dissect_entityinst(subtree, hf_msg_timecheck_skew_node, &inst,
					   tvb, off, data);

		skew = tvb_get_letohieee_double(tvb, off);
		proto_tree_add_item(subtree, hf_msg_timecheck_skew_skew,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_item_append_text(ti2, ", Node: %s, Skew: %lf", inst.name.slug, skew);
		proto_item_set_end(ti2, tvb, off);
	}

	i = tvb_get_letohl(tvb, off);
	off += 4;
	while (i--)
	{
		proto_item *ti2;
		proto_tree *subtree;
		c_entityinst inst;
		double ping;

		ti2 = proto_tree_add_item(tree, hf_msg_timecheck_latency, tvb, off, -1, ENC_NA);
		subtree = proto_item_add_subtree(ti2, ett_msg_timecheck_latency);

		off = c_dissect_entityinst(subtree, hf_msg_timecheck_latency_node, &inst,
					   tvb, off, data);

		ping = tvb_get_letohieee_double(tvb, off);
		proto_tree_add_item(subtree, hf_msg_timecheck_latency_latency,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		proto_item_append_text(ti2, ", Node: %s, Latency: %lf", inst.name.slug, ping);
		proto_item_set_end(ti2, tvb, off);
	}

	return off;
}

/*** MSGR Dissectors ***/

#define C_OFF_HEAD0  0
#define C_SIZE_HEAD0 ((64+64+16+16+16)/8)

#define C_OFF_HEAD1  C_SIZE_HEAD0
#define C_SIZE_HEAD1 ((32+32+32+16)/8)

#define C_OFF_HEAD2  (C_OFF_HEAD1 + C_SIZE_HEAD1 + C_SIZE_ENTITY_NAME)
#define C_SIZE_HEAD2 ((16+16+32)/8)

#define C_SIZE_HEAD  (C_OFF_HEAD2 + C_SIZE_HEAD2)

#define C_SIZE_FOOT  ((32+32+32+64+8)/8)

/** Dissect a MSG message.
 *
 * These are Ceph's business messages and are generally sent to specific
 * node types.
 */
static
guint c_dissect_msg(proto_tree *tree,
		    tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	tvbuff_t *subtvb;
	proto_item *ti;
	proto_tree *subtree;
	c_msg_type type;
	guint32 front_len, middle_len, data_len;
	guint size, parsedsize;

	front_len  = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 0);
	middle_len = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 4);
	data_len   = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 8);

	/*** Header ***/

	/* From ceph:/src/include/msgr.h
	struct ceph_msg_header {
		__le64 seq;	  // message seq# for this session
		__le64 tid;	  // transaction id
		__le16 type;	  // message type
		__le16 priority;  // priority.	higher value == higher priority
		__le16 version;	  // version of message encoding

		__le32 front_len; // bytes in main payload
		__le32 middle_len;// bytes in middle payload
		__le32 data_len;  // bytes of data payload
		__le16 data_off;  // sender: include full offset; receiver: mask against ~PAGE_MASK

		struct ceph_entity_name src;

		// oldest code we think can decode this.  unknown if zero.
		__le16 compat_version;
		__le16 reserved;
		__le32 crc; // header crc32c
	} __attribute__ ((packed));
	*/

	ti = proto_tree_add_item(tree, hf_head, tvb, off, C_SIZE_HEAD, ENC_NA);
	subtree = proto_item_add_subtree(ti, ett_head);

	data->header.seq = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(subtree, hf_head_seq,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	data->header.tid = tvb_get_letoh64(tvb, off);
	proto_tree_add_item(subtree, hf_head_tid,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;

	data->header.type = type = (c_msg_type)tvb_get_letohs(tvb, off);
	proto_tree_add_item(subtree, hf_head_type,
			    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;

	data->header.priority = tvb_get_letohs(tvb, off);
	proto_tree_add_item(subtree, hf_head_priority,
			    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	data->header.ver = tvb_get_letohs(tvb, off);
	proto_tree_add_item(subtree, hf_head_version,
			    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;

	proto_tree_add_item(subtree, hf_head_front_size,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_head_middle_size,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_head_data_size,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_head_data_off,
			    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;

	off = c_dissect_entityname(subtree, hf_head_srcname, &data->header.src,
				   tvb, off, data);

	/*** Copy the data to the state structure. ***/

	/* Save memory by copying only if different, they are *usually* the same. */
	if (!data->src->name.slug ||
	    strcmp(data->src->name.slug, data->header.src.slug) != 0)
		data->src->name.slug = wmem_strdup(wmem_file_scope(),
						   data->header.src.slug);
	if (!data->src->name.type_str ||
	    strcmp(data->src->name.type_str, data->header.src.type_str) != 0)
		data->src->name.type_str = wmem_strdup(wmem_file_scope(),
						       data->header.src.type_str);

	data->src->name.type = data->header.src.type;
	data->src->name.id   = data->header.src.id;

	proto_tree_add_item(subtree, hf_head_compat_version,
			    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	proto_tree_add_item(subtree, hf_head_reserved,
			    tvb, off, 2, ENC_LITTLE_ENDIAN);
	off += 2;
	proto_tree_add_item(subtree, hf_head_crc,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_item_append_text(ti, ", Type: %s, From: %s",
			       c_msg_type_string(type),
			       data->header.src.slug);
	if (front_len ) proto_item_append_text(ti, ", Front Len: %d", front_len);
	if (middle_len) proto_item_append_text(ti, ", Mid Len: %d",   middle_len);
	if (data_len  ) proto_item_append_text(ti, ", Data Len: %d",  data_len);

	/*** Body ***/

	subtvb = tvb_new_subset_length(tvb, off, front_len+middle_len+data_len);

	switch (type)
	{
#define C_CALL(name) name(tree, subtvb, front_len, middle_len, data_len, data)
#define C_HANDLE(tag, name) case tag: parsedsize = C_CALL(name); break;

	C_HANDLE(C_CEPH_MSG_PING,		    c_dissect_msg_ping)
	C_HANDLE(C_CEPH_MSG_MON_MAP,		    c_dissect_msg_mon_map)
	C_HANDLE(C_CEPH_MSG_STATFS,		    c_dissect_msg_statfs)
	C_HANDLE(C_CEPH_MSG_STATFS_REPLY,	    c_dissect_msg_statfsreply)
	C_HANDLE(C_CEPH_MSG_MON_SUBSCRIBE,	    c_dissect_msg_mon_sub)
	C_HANDLE(C_CEPH_MSG_MON_SUBSCRIBE_ACK,	    c_dissect_msg_mon_sub_ack)
	C_HANDLE(C_CEPH_MSG_AUTH,		    c_dissect_msg_auth)
	C_HANDLE(C_CEPH_MSG_AUTH_REPLY,		    c_dissect_msg_auth_reply)
	C_HANDLE(C_CEPH_MSG_MON_GET_VERSION,	    c_dissect_msg_mon_getversion)
	C_HANDLE(C_CEPH_MSG_MON_GET_VERSION_REPLY,  c_dissect_msg_mon_getversionreply)
	C_HANDLE(C_CEPH_MSG_MDS_MAP,		    c_dissect_msg_mds_map)
	C_HANDLE(C_CEPH_MSG_CLIENT_SESSION,	    c_dissect_msg_client_sess)
	C_HANDLE(C_CEPH_MSG_CLIENT_REQUEST,	    c_dissect_msg_client_req)
	C_HANDLE(C_CEPH_MSG_CLIENT_REQUEST_FORWARD, c_dissect_msg_client_reqfwd)
	C_HANDLE(C_CEPH_MSG_CLIENT_REPLY,	    c_dissect_msg_client_reply)
	C_HANDLE(C_CEPH_MSG_OSD_MAP,		    c_dissect_msg_osd_map)
	C_HANDLE(C_CEPH_MSG_OSD_OP,		    c_dissect_msg_osd_op)
	C_HANDLE(C_CEPH_MSG_OSD_OPREPLY,	    c_dissect_msg_osd_opreply)
	C_HANDLE(C_MSG_POOLOPREPLY,		    c_dissect_msg_poolopreply)
	C_HANDLE(C_MSG_POOLOP,			    c_dissect_msg_poolop)
	C_HANDLE(C_MSG_MON_COMMAND,		    c_dissect_msg_mon_cmd)
	C_HANDLE(C_MSG_MON_COMMAND_ACK,		    c_dissect_msg_mon_cmd_ack)
	C_HANDLE(C_MSG_GETPOOLSTATS,		    c_dissect_msg_poolstats)
	C_HANDLE(C_MSG_GETPOOLSTATSREPLY,	    c_dissect_msg_poolstatsreply)
	C_HANDLE(C_MSG_MON_GLOBAL_ID,		    c_dissect_msg_mon_globalid)
	C_HANDLE(C_MSG_MON_ELECTION,		    c_dissect_msg_mon_election)
	C_HANDLE(C_MSG_MON_PAXOS,		    c_dissect_msg_mon_paxos)
	C_HANDLE(C_MSG_MON_PROBE,		    c_dissect_msg_mon_probe)
	C_HANDLE(C_MSG_OSD_PING,		    c_dissect_msg_osd_ping)
	C_HANDLE(C_MSG_OSD_BOOT,		    c_dissect_msg_osd_boot)
	C_HANDLE(C_MSG_PGSTATS,			    c_dissect_msg_pgstats)
	C_HANDLE(C_MSG_OSD_PG_CREATE,		    c_dissect_msg_osd_pg_create)
	C_HANDLE(C_CEPH_MSG_CLIENT_CAPS,	    c_dissect_msg_client_caps)
	C_HANDLE(C_CEPH_MSG_CLIENT_CAPRELEASE,	    c_dissect_msg_client_caprel)
	C_HANDLE(C_MSG_TIMECHECK,		    c_dissect_msg_timecheck)

	default:
		parsedsize = C_CALL(c_dissect_msg_unknown);
#undef C_CALL
#undef C_HANDLE
	}

	size = front_len + middle_len + data_len;

	/* Did the message dissector use all the data? */
	c_warn_size(tree, tvb, off+parsedsize, off+size, data);

	off += size;

	/*** Footer ***/

	/* From ceph:/src/include/msgr.h
	struct ceph_msg_footer {
		__le32 front_crc, middle_crc, data_crc;
		// sig holds the 64 bits of the digital signature for the message PLR
		__le64	sig;
		__u8 flags;
	} __attribute__ ((packed));
	*/

	ti = proto_tree_add_item(tree, hf_foot, tvb, off, C_SIZE_FOOT, ENC_NA);
	subtree = proto_item_add_subtree(ti, ett_foot);

	proto_tree_add_item(subtree, hf_foot_front_crc,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_foot_middle_crc,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(subtree, hf_foot_data_crc,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	proto_tree_add_item(subtree, hf_foot_signature,
			    tvb, off, 8, ENC_LITTLE_ENDIAN);
	off += 8;
	off = c_dissect_flags(subtree, tvb, off, data);

	return off;
}

#define C_SIZE_CONNECT          33
#define C_SIZE_CONNECT_REPLY    25
#define C_CONNECT_REPLY_OFF_OFFLEN 20
#define C_SIZE_HELLO_S          (2*C_SIZE_ENTITY_ADDR)
#define C_SIZE_HELLO_C          (C_SIZE_ENTITY_ADDR + C_SIZE_CONNECT)
#define C_HELLO_OFF_AUTHLEN     (C_SIZE_ENTITY_ADDR + 28)

/** Dissect a connection request. */
static
guint c_dissect_connect(proto_tree *root,
			tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	/* From ceph:/src/include/msgr.h
	struct ceph_msg_connect {
		__le64 features;
		__le32 host_type;
		__le32 global_seq;
		__le32 connect_seq;
		__le32 protocol_version;
		__le32 authorizer_protocol;
		__le32 authorizer_len;
		__u8  flags;
	} __attribute__(packed);
	*/

	proto_item *ti;
	proto_tree *tree;
	guint32 authsize;

	authsize = tvb_get_letohl(tvb, off+28);

	ti = proto_tree_add_item(root, hf_connect, tvb, off, C_SIZE_CONNECT, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_connect);

	off = c_dissect_features(tree, tvb, off, data);

	proto_tree_add_item(tree, hf_connect_host_type,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_seq_global,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_seq,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_proto_ver,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_auth_proto,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_auth_size,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_flags(tree, tvb, off, data);

	/* @TODO: Parse auth. */
	proto_tree_add_item(tree, hf_connect_auth,
			    tvb, off, authsize, ENC_NA);
	off += authsize;

	return off;
}

/** Dissect a connection reply. */
static
guint c_dissect_connect_reply(proto_tree *root,
			      tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	/* From ceph:/src/include/msgr.h
	struct ceph_msg_connect_reply {
		__u8 tag; // Handled outside.
		__le64 features;
		__le32 global_seq;
		__le32 connect_seq;
		__le32 protocol_version;
		__le32 authorizer_len;
		__u8 flags;
	} __attribute__ ((packed));
	*/

	proto_item *ti;
	proto_tree *tree;
	guint32 authsize;

	authsize = tvb_get_letohl(tvb, off+C_CONNECT_REPLY_OFF_OFFLEN);

	c_set_type(data, "Connect Reply");

	ti = proto_tree_add_item(root, hf_connect_reply,
				 tvb, off, C_SIZE_CONNECT_REPLY, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_connect_reply);

	off = c_dissect_features(tree, tvb, off, data);

	proto_tree_add_item(tree, hf_connect_seq_global,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_seq,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_proto_ver,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;
	proto_tree_add_item(tree, hf_connect_auth_size,
			    tvb, off, 4, ENC_LITTLE_ENDIAN);
	off += 4;

	off = c_dissect_flags(tree, tvb, off, data);

	/* @TODO: Parse auth. */
	proto_tree_add_item(tree, hf_connect_auth,
			    tvb, off, authsize, ENC_NA);
	off += authsize;

	return off;
}

/** Do the connection initiation dance.
 *
 * This handles the data that is sent before the protocol is actually started.
 */
static
guint c_dissect_new(proto_tree *tree,
		    tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	gint bansize;

	/*
		Since the packet is larger than the max banner length we can read it
		all in safely.
	*/
#ifdef G_STATIC_ASSERT
	G_STATIC_ASSERT(C_BANNER_SIZE+1 <= C_BANNER_SIZE_MIN+C_SIZE_HELLO_C);
	G_STATIC_ASSERT(C_BANNER_SIZE+1 <= C_BANNER_SIZE_MIN+C_SIZE_HELLO_S);
#endif

	if (tvb_memeql(tvb, off, C_BANNER, C_BANNER_SIZE_MIN) != 0)
		return C_INVALID;

	bansize = tvb_strnlen(tvb, off, C_BANNER_SIZE+1);
	if (bansize != C_BANNER_SIZE) /* Note -1 != C_BANNER_SIZE */
		return C_INVALID;

	proto_tree_add_item(tree, hf_banner, tvb, off, bansize, ENC_ASCII|ENC_NA);
	off += bansize;

	c_set_type(data, "Connect");

	if (c_from_server(data))
		off = c_dissect_entityaddr(tree, hf_server_info, NULL, tvb, off);

	off = c_dissect_entityaddr(tree, hf_client_info, NULL, tvb, off);

	if (c_from_client(data))
		off = c_dissect_connect(tree, tvb, off, data);

	data->src->state = C_STATE_OPEN;

	return off;
}

static
gboolean c_unknowntagnext(tvbuff_t *tvb, guint off)
{
	if (!tvb_bytes_exist(tvb, off, 1)) return FALSE;

	return (try_val_to_str_ext(tvb_get_guint8(tvb, off), &c_tag_strings_ext) == NULL);
}

/* Dissect a MSGR message.
 *
 * MSGR is Ceph's outer message protocol.
 */
static
guint c_dissect_msgr(proto_tree *tree,
		     tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti;
	c_tag tag;
	guint unknowntagcount = 1;

	tag = (c_tag)tvb_get_guint8(tvb, off);
	ti = proto_tree_add_item(tree, hf_tag, tvb, off, 1, ENC_LITTLE_ENDIAN);
	off += 1;

	switch (tag)
	{
	case C_TAG_READY:
	case C_TAG_RESETSESSION:
	case C_TAG_WAIT:
	case C_TAG_RETRY_SESSION:
	case C_TAG_RETRY_GLOBAL:
	case C_TAG_BADPROTOVER:
	case C_TAG_BADAUTHORIZER:
	case C_TAG_FEATURES:
		off = c_dissect_connect_reply(tree, tvb, off, data);
		break;
	case C_TAG_SEQ:
		off = c_dissect_connect_reply(tree, tvb, off, data);
		proto_tree_add_item(tree, hf_seq_existing,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;

		data->dst->state = C_STATE_SEQ;
		break;
	case C_TAG_CLOSE:
		c_set_type(data, "CLOSE");
		data->src->state = C_STATE_NEW;
		break;
	case C_TAG_MSG:
		off = c_dissect_msg(tree, tvb, off, data);
		break;
	case C_TAG_ACK:
		c_set_type(data, "ACK");
		proto_item_append_text(data->item_root, ", Seq: %u",
				       tvb_get_letohl(tvb, off));
		proto_tree_add_item(tree, hf_ack,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		break;
	case C_TAG_KEEPALIVE:
		c_set_type(data, "KEEPALIVE");
		/* No data. */
		break;
	case C_TAG_KEEPALIVE2:
	case C_TAG_KEEPALIVE2_ACK:
		c_set_type(data, "KEEPALIVE2");
		proto_tree_add_item(tree, hf_keepalive_time,
				    tvb, off, 8, ENC_LITTLE_ENDIAN);
		off += 8;
		break;
	default:
		/*
			The default is to do nothing.  We have no way of knowing how
			long an unknown message will be.  Our best bet is to read
			just the tag (which we did above) and try to interpret the
			next byte as a message.	 In the best case we step through
			the unknown message and when we hit the next known message
			we can continue.

			Stepping through byte-by-byte is slow, and creates a lot of
			"Unknown Tag" items (where only the first one is really
			meaningful) but we don't want to miss the next message if we
			can help it.

			Worst case is the message contains a byte that we think is a
			message.  In this case we will interpret garbage from there
			creating bogus items in the dissection results.	 After we
			"dissect" that "PDU" we go back to the start and hope we get
			lucky and find ourselves realigned.
		*/

		/* Batch multiple unknowns together. */
		while (c_unknowntagnext(tvb, off))
			off++, unknowntagcount++;

		c_set_type(data, wmem_strdup_printf(wmem_packet_scope(),
						    "UNKNOWN x%u",
						    unknowntagcount));
		expert_add_info(data->pinfo, ti, &ei_tag_unknown);
	}

	return off;
}

/* Dissect a Protocol Data Unit
 */
static
guint c_dissect_pdu(proto_tree *root,
		    tvbuff_t *tvb, guint off, c_pkt_data *data)
{
	proto_item *ti, *tif;
	proto_tree *tree, *tree_filter;

	ti = proto_tree_add_item(root, proto_ceph, tvb, off, -1, ENC_NA);
	tree = proto_item_add_subtree(ti, ett_ceph);

	data->item_root = ti;

	tif = proto_tree_add_item(tree, hf_filter_data, tvb, off, -1, ENC_NA);
	tree_filter = proto_item_add_subtree(tif, ett_filter_data);

	switch (data->src->state)
	{
		case C_STATE_NEW:
			off = c_dissect_new(tree, tvb, off, data);
			break;
		case C_STATE_SEQ:
			c_set_type(data, "Sequence Number");
			proto_item_append_text(data->item_root, ", Seq: %"G_GINT64_MODIFIER"u",
					       tvb_get_letoh64(tvb, off));
			proto_tree_add_item(tree, hf_seq_new, tvb, off, 8, ENC_LITTLE_ENDIAN);
			off += 8;
			data->src->state = C_STATE_OPEN;
			break;
		default:
			off = c_dissect_msgr(tree, tvb, off, data);
	}

	if (tree_filter) {
		proto_item *fi;
		const char *srcn, *dstn;

		/* Provide readable defaults. */
		srcn = data->src->name.slug? data->src->name.slug : "Unknown";
		dstn = data->dst->name.slug? data->dst->name.slug : "Unknown";

		/*** General Filter Data ***/
		fi = proto_tree_add_string(tree_filter, hf_src_slug,
					   NULL, 0, 0, srcn);
		PROTO_ITEM_SET_GENERATED(fi);
		fi = proto_tree_add_uint(tree_filter, hf_src_type,
					 NULL, 0, 0, data->src->name.type);
		PROTO_ITEM_SET_GENERATED(fi);
		fi = proto_tree_add_string(tree_filter, hf_dst_slug,
					   NULL, 0, 0, dstn);
		PROTO_ITEM_SET_GENERATED(fi);
		fi = proto_tree_add_uint(tree_filter, hf_dst_type,
					 NULL, 0, 0, data->dst->name.type);
		PROTO_ITEM_SET_GENERATED(fi);

		proto_item_set_end(tif, tvb, off);
	}

	proto_item_set_end(ti,	tvb, off);

	return off;
}

static
guint c_pdu_end(tvbuff_t *tvb, packet_info *pinfo, guint off, c_pkt_data *data)
{
	c_inet	af;

	/*
	 * If we don't already know, then figure out which end of the
	 * connection is the client. It's icky, but the only way to know is to
	 * see whether the info after the first entity_addr_t looks like
	 * another entity_addr_t.
	 */
	if (data->convd->client.port == 0xFFFF) {
		if (!tvb_bytes_exist(tvb, off, C_BANNER_SIZE + C_SIZE_ENTITY_ADDR + 8 + 2))
			return C_NEEDMORE;

		/* We have enough to determine client vs. server */
		af = (c_inet)tvb_get_ntohs(tvb, off + C_BANNER_SIZE + C_SIZE_ENTITY_ADDR + 8);
		if (af != C_IPv4 && af != C_IPv6) {
			/* Client */
			copy_address_wmem(wmem_file_scope(), &data->convd->client.addr, &pinfo->src);
			data->convd->client.port = pinfo->srcport;
			copy_address_wmem(wmem_file_scope(), &data->convd->server.addr, &pinfo->dst);
			data->convd->server.port = pinfo->destport;
			data->src = &data->convd->client;
			data->dst = &data->convd->server;
		} else {
			/* Server */
			copy_address_wmem(wmem_file_scope(), &data->convd->server.addr, &pinfo->src);
			data->convd->server.port = pinfo->srcport;
			copy_address_wmem(wmem_file_scope(), &data->convd->client.addr, &pinfo->dst);
			data->convd->client.port = pinfo->destport;
			data->src = &data->convd->server;
			data->dst = &data->convd->client;
		}
	}

	switch (data->src->state)
	{
	case C_STATE_NEW:
		if (c_from_client(data))
		{
			if (!tvb_bytes_exist(tvb, off+C_BANNER_SIZE+C_HELLO_OFF_AUTHLEN, 4))
				return C_NEEDMORE;
			return off + C_BANNER_SIZE + C_SIZE_HELLO_C
				   + tvb_get_letohl(tvb, off+C_BANNER_SIZE+C_HELLO_OFF_AUTHLEN);
		}
		else
			return off + C_BANNER_SIZE + C_SIZE_HELLO_S;
	case C_STATE_SEQ:
		return off + 8;
	default:
		switch ((c_tag)tvb_get_guint8(tvb, off++))
		{
		case C_TAG_READY:
		case C_TAG_RESETSESSION:
		case C_TAG_WAIT:
		case C_TAG_RETRY_SESSION:
		case C_TAG_RETRY_GLOBAL:
		case C_TAG_BADPROTOVER:
		case C_TAG_BADAUTHORIZER:
		case C_TAG_FEATURES:
			if (!tvb_bytes_exist(tvb, off+C_CONNECT_REPLY_OFF_OFFLEN, 4))
				return C_NEEDMORE;
			return off + C_SIZE_CONNECT_REPLY
				   + tvb_get_letohl(tvb, off+C_CONNECT_REPLY_OFF_OFFLEN);
		case C_TAG_SEQ:
			if (!tvb_bytes_exist(tvb, off+C_CONNECT_REPLY_OFF_OFFLEN, 4))
				return C_NEEDMORE;
			return off + C_SIZE_CONNECT_REPLY + 8
				   + tvb_get_letohl(tvb, off+C_CONNECT_REPLY_OFF_OFFLEN);
		case C_TAG_CLOSE:
			return off;
			break;
		case C_TAG_MSG:
		{
			guint32 front_len, middle_len, data_len;

			if (!tvb_bytes_exist(tvb, off+C_OFF_HEAD1, C_SIZE_HEAD1))
				return C_NEEDMORE;

			front_len  = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 0);
			middle_len = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 4);
			data_len   = tvb_get_letohl(tvb, off + C_OFF_HEAD1 + 8);

			return off + C_SIZE_HEAD+front_len+middle_len+data_len+C_SIZE_FOOT;
		}
		case C_TAG_ACK:
			return off + 8;
		case C_TAG_KEEPALIVE:
			return off;
		case C_TAG_KEEPALIVE2:
		case C_TAG_KEEPALIVE2_ACK:
			return off+C_SIZE_TIMESPEC;
		default:
			while (c_unknowntagnext(tvb, off))
				off++;

			return off;
		}
	}
}

static
int dissect_ceph(tvbuff_t *tvb, packet_info *pinfo,
		 proto_tree *tree, void *pdata _U_)
{
	guint off, offt, offt2;
	c_pkt_data data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ceph");
	col_clear(pinfo->cinfo, COL_INFO);

	off = 0;
	while (off < tvb_reported_length(tvb))
	{
		c_pkt_data_init(&data, pinfo, off);

		/* Save snapshot before dissection changes it. */
		/*
			If some data has already been dissected in this frame we *must*
			save the state so we can remember that the rest of the frame is
			an incomplete PDU.
		*/
		if (off)
			c_pkt_data_save(&data, pinfo, off);

		offt = c_pdu_end(tvb, pinfo, off, &data);
		if (offt == C_INVALID)
		{
			return 0;
		}
		if (offt == C_NEEDMORE) /* Need more data to determine PDU length. */
		{
			pinfo->desegment_offset = off;
			pinfo->desegment_len	= DESEGMENT_ONE_MORE_SEGMENT;
			return 1;
		}
		if (offt > tvb_reported_length(tvb)) /* Know PDU length, get rest */
		{
			pinfo->desegment_offset = off;
			pinfo->desegment_len	= offt - tvb_reported_length(tvb);
			return 1;
		}

		/*
			If we didn't save above, save now.  This is a complete PDU so
			we need to save the state.
		*/
		if (!off)
			c_pkt_data_save(&data, pinfo, off);

		col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "");
		col_set_fence(pinfo->cinfo, COL_INFO);

		offt2 = c_dissect_pdu(tree, tvb, off, &data);
		if (!offt2) return 0;
		DISSECTOR_ASSERT_CMPINT(offt2, ==, offt);

		off = offt;
	}

	return off; /* Perfect Fit. */
}

/** An old style dissector proxy.
 *
 * Proxies the old style dissector interface to the new style.
 */
static
int dissect_ceph_old(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	dissect_ceph(tvb, pinfo, tree, data);
	return tvb_captured_length(tvb);
}

static
gboolean dissect_ceph_heur(tvbuff_t *tvb, packet_info *pinfo,
			   proto_tree *tree, void *data)
{
	conversation_t *conv;

	if (tvb_memeql(tvb, 0, C_BANNER, C_BANNER_SIZE_MIN) != 0) return FALSE;

	/*** It's ours! ***/

	conv = find_or_create_conversation(pinfo);
	/* Mark it as ours. */
	conversation_set_dissector(conv, ceph_handle);

	dissect_ceph(tvb, pinfo, tree, data);
	return TRUE;
}

/* Register the protocol with Wireshark.
 */
void
proto_register_ceph(void)
{
	expert_module_t *expert_ceph;

	static hf_register_info hf[] = {
		{ &hf_filter_data, {
			"Filter Data", "ceph.filter",
			FT_NONE, BASE_NONE, NULL, 0,
			"A bunch of properties for convenient filtering.", HFILL
		} },
		{ &hf_node_id, {
			"ID", "ceph.node_id",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The numeric ID of the node.", HFILL
		} },
		{ &hf_node_type, {
			"Source Node Type", "ceph.node_type",
			FT_UINT8, BASE_HEX, VALS(c_node_type_strings), 0,
			"The type of source node.", HFILL
		} },
		{ &hf_node_nonce, {
			"Nonce", "ceph.node_nonce",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Meaningless number to differentiate between nodes on "
			"the same system.", HFILL
		} },
		{ &hf_entityinst_name, {
			"Name", "ceph.entityinst.name",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_entityinst_addr, {
			"Address", "ceph.entityinst.addr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_EntityName, {
			"Entity Name", "ceph.EntityName",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_EntityName_type, {
			"Type", "ceph.EntityName.type",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_EntityName_id, {
			"ID", "ceph.EntityName.id",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_src_slug, {
			"Source Node Name", "ceph.src",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_src_type, {
			"Source Node Type", "ceph.src.type",
			FT_UINT8, BASE_HEX, VALS(c_node_type_abbr_strings), 0,
			NULL, HFILL
		} },
		{ &hf_dst_slug, {
			"Destination Node Name", "ceph.dst",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_dst_type, {
			"Destination Node Type", "ceph.dst.type",
			FT_UINT8, BASE_HEX, VALS(c_node_type_abbr_strings), 0,
			NULL, HFILL
		} },
		{ &hf_banner, {
			"Version", "ceph.ver",
			FT_STRINGZ, BASE_NONE, NULL, 0,
			"The protocol version string.", HFILL
		} },
		{ &hf_client_info, {
			"Client's Identity", "ceph.client_info",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_server_info, {
			"Server's Identity", "ceph.server_info",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_sockaddr, {
			"Network Address", "ceph.sockaddr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_inet_family, {
			"Address Family", "ceph.af",
			FT_UINT16, BASE_HEX, VALS(c_inet_strings), 0,
			"The address family of the client as seen by the server.", HFILL
		} },
		{ &hf_port, {
			"Port", "ceph.client.port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"The port of the client as seen by the server.", HFILL
		} },
		{ &hf_addr_ipv4, {
			"IPv4 Address", "ceph.client.ip4",
			FT_IPv4, BASE_NONE, NULL, 0,
			"The IP address of the client as seen by the server.", HFILL
		} },
		{ &hf_addr_ipv6, {
			"IPv6 Address", "ceph.client.ipv6",
			FT_IPv6, BASE_NONE, NULL, 0,
			"The IP address of the client as seen by the server.", HFILL
		} },
		{ &hf_data_data, {
			"Data", "ceph.data.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_data_size, {
			"Size", "ceph.data.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_string_data, {
			"Data", "ceph.string.data",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_string_size, {
			"Size", "ceph.string.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_keepalive_time, {
			"Timestamp", "ceph.keepalive.time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_encoded_ver, {
			"Encoding Version", "ceph.enc.ver",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_encoded_compat, {
			"Minimum compatible version", "ceph.enc.compat",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_encoded_size, {
			"Size", "ceph.nanoseconds",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Size of encoded message.", HFILL
		} },
		{ &hf_version, {
			"Version", "ceph.version",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_epoch, {
			"Epoch", "ceph.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pool, {
			"Pool", "ceph.pool",
			FT_INT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_key, {
			"Object Key", "ceph.key",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_namespace, {
			"Namespace", "ceph.namespace",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_hash, {
			"Object Hash", "ceph.hash",
			FT_INT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgid_ver, {
			"Placement Group Version", "ceph.pg.ver",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgid_pool, {
			"Pool", "ceph.pg.pool",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgid_seed, {
			"Seed", "ceph.pg.seed",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgid_preferred, {
			"Preferred", "ceph.pg.preferred",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_create_epoch, {
			"Epoch Created", "ceph.pg_create.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_create_parent, {
			"Parent", "ceph.pg_create.parent",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_create_splitbits, {
			"Split Bits", "ceph.pg_create.splitbits",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_path_ver, {
			"Encoding Version", "ceph.path.ver",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_path_inode, {
			"Inode", "ceph.path.inode",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_path_rel, {
			"Relative component", "ceph.path.rel",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_inode, {
			"Inode", "ceph.mds_release.inode",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_capid, {
			"Capability ID", "ceph.mds_release.capid",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_new, {
			"New Capabilities", "ceph.mds_release.new",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_wanted, {
			"Wanted Capabilities", "ceph.mds_release.wanted",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_seq, {
			"Seq", "ceph.mds_release.seq",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_seq_issue, {
			"Seq Issue", "ceph.mds_release.seq_issue",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_mseq, {
			"Migration Sequence", "ceph.mds_release.mseq",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_dname_seq, {
			"DName Seq", "ceph.mds_release.dname_seq",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_mds_release_dname, {
			"DName", "ceph.mds_release.dname",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_hitset_params, {
			"HitSet Parameters", "ceph.hitset_params",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_hitset_params_type, {
			"Type", "ceph.hitset_params.type",
			FT_UINT8, BASE_HEX|BASE_EXT_STRING, &c_hitset_params_type_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_hitset_params_exphash_count, {
			"Count", "ceph.hitset_params.exphash.count",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_hitset_params_exphash_hit, {
			"Hit", "ceph.hitset_params.exphash.hit",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_snapinfo, {
			"Snapshot Info", "ceph.snapinfo",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_snapinfo_id, {
			"ID", "ceph.snapinfo.id",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_snapinfo_time, {
			"Timestamp", "ceph.snapinfo.timestamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_snapinfo_name, {
			"Name", "ceph.snapinfo.name",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool, {
			"Placement Group Pool", "ceph.pgpool",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_type, {
			"Type", "ceph.pgpool.type",
			FT_UINT8, BASE_HEX, VALS(c_pgpool_type_strings), 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_size, {
			"Size", "ceph.pgpool.size",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_crush_ruleset, {
			"CRUSH Ruleset", "ceph.pgpool.crush_ruleset",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_hash, {
			"Object Hash", "ceph.pgpool.hash",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_pgnum, {
			"PG Count", "ceph.pgpool.pgnum",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_pgpnum, {
			"PGP Count", "ceph.pgpool.pgpnum",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_changed, {
			"Last Changed", "ceph.pgpool.changed",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_snapseq, {
			"Snap Sequence", "ceph.pgpool.snapseq",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_snapepoch, {
			"Epoch", "ceph.pgpool.snapepoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_snap, {
			"Snapshot", "ceph.pgpool.snap",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_snap_id, {
			"ID", "ceph.pgpool.snap.id",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_snapdel, {
			"Deleted Snapshots", "ceph.pgpool.snapdel",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_snapdel_from, {
			"From", "ceph.pgpool.snapdel.from",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_snapdel_to, {
			"To", "ceph.pgpool.snapdel.to",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_uid, {
			"User ID", "ceph.pgpool.uid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_flags_low, {
			"Flags", "ceph.pgpool.flags",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_flags_high, {
			"Flags", "ceph.pgpool.flags",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_crash_reply_interval, {
			"Crash Replay Interval", "ceph.pgpool.crash_reply_interval",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Seconds to allow clients to replay ACKed but "
			"unCOMMITted requests.", HFILL
		} },
		{ &hf_pgpool_min_size, {
			"Minimum number of OSDs", "ceph.pgpool.min_size",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_quota_bytes, {
			"Maximum number of bytes", "ceph.pgpool.quota_bytes",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_quota_objects, {
			"Maximum number of objects", "ceph.pgpool.quota_objects",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_tier, {
			"Tier", "ceph.msg.tier",
			FT_UINT64, BASE_HEX, NULL, 0,
			"A pool that is a tier of this tier.", HFILL
		} },
		{ &hf_pgpool_tierof, {
			"Tier of", "ceph.pgpool.tierof",
			FT_UINT64, BASE_HEX, NULL, 0,
			"The pool that this pool is a tier of.", HFILL
		} },
		{ &hf_pgpool_cachemode, {
			"Cache Mode", "ceph.pgpool.cache_mode",
			FT_UINT8, BASE_HEX|BASE_EXT_STRING, &c_pgpool_cachemode_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_readtier, {
			"Read Tier", "ceph.pgpool.read_tier",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_writetier, {
			"Write Tier", "ceph.pgpool.write_tier",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_property, {
			"Property", "ceph.pgpool.property",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_property_key, {
			"Key", "ceph.pgpool.property.key",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_property_val, {
			"Value", "ceph.pgpool.property.val",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_hitset_period, {
			"HitSet Period", "ceph.hitset_period",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The period of HitSet segments in seconds.", HFILL
		} },
		{ &hf_pgpool_hitset_count, {
			"HitSet count", "ceph.pgpool.hitset_count",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The number of HitSet periods to retain.", HFILL
		} },
		{ &hf_pgpool_stripewidth, {
			"Stripe Width", "ceph.pgpool.stripewidth",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_targetmaxsize, {
			"Target Maximum Bytes", "ceph.pgpool.targetmaxsize",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_targetmaxobj, {
			"Target Maximum Objects", "ceph.pgpool.targetmaxobj",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_cache_targetdirtyratio, {
			"Cache Target Dirty Ratio", "ceph.pgpool.cache.targetdirtyratio",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Fraction of cache to leave dirty.", HFILL
		} },
		{ &hf_pgpool_cache_targetfullratio, {
			"Cache Target Full Ratio", "ceph.msg.targetfullratio",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Fraction of target to fill before evicting in earnest.", HFILL
		} },
		{ &hf_pgpool_cache_flushage_min, {
			"Cache Minimum Flush Age", "ceph.pgpool.cache.flushage_min",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_cache_evictage_min, {
			"Cache Minimum Evict Age", "ceph.pgpool.cache.evictage_min",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_erasurecode_profile, {
			"Erasure Code Profile", "ceph.pgpool.erasurecode_profile",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pgpool_lastforceresend, {
			"Last Force Resend", "ceph.pgpool.lastforceresend",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Last epoch that forced clients to resend.", HFILL
		} },
		{ &hf_pgpool_flag_hashpool, {
			"Hash Seed and Pool Together", "ceph.pgpool.flag.hashpool",
			FT_BOOLEAN, 32, TFS(&tfs_true_false), C_PGPOOL_FLAG_HASHPSPOOL,
			NULL, HFILL
		} },
		{ &hf_pgpool_flag_full, {
			"Pool Full", "ceph.pgpool.flag.full",
			FT_BOOLEAN, 32, TFS(&tfs_true_false), C_PGPOOL_FLAG_FULL,
			NULL, HFILL
		} },
		{ &hf_pgpool_flag_fake_ec_pool, {
			"Fake Erasure-Coded Pool", "ceph.pgpool.flag.fake_ec_pool",
			FT_BOOLEAN, 32, TFS(&tfs_true_false), C_PGPOOL_FLAG_FAKE_EC_POOL,
			NULL, HFILL
		} },
		{ &hf_monmap, {
			"Monmap", "ceph.monmap.data",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_monmap_fsid, {
			"FSID", "ceph.monmap.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_monmap_epoch, {
			"Epoch", "ceph.monmap.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_monmap_address, {
			"Monitor Address", "ceph.monmap.address",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_monmap_address_name, {
			"Name", "ceph.monmap.address.name",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_monmap_address_addr, {
			"Address", "ceph.monmap.address.addr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_monmap_changed, {
			"Last Changed", "ceph.monmap.changed",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_monmap_created, {
			"Time Created", "ceph.monmap.created",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_ver, {
			"Version", "ceph.pg_stat.ver",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_seq, {
			"Reported Sequence Number", "ceph.pg_stat.seq",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_epoch, {
			"Reported Epoch", "ceph.pg_stat.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_state, {
			"State", "ceph.pg_stat.state",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_logstart, {
			"Log Start", "ceph.pg_stat.logstart",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_logstartondisk, {
			"On-disk Log Start", "ceph.pg_stat.logstartondisk",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_created, {
			"Created", "ceph.pg_stat.created",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastepochclean, {
			"Last Epoch Clean", "ceph.pg_stat.lastepochclean",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_parent, {
			"Parent", "ceph.pg_stat.parent",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_parent_splitbits, {
			"Parent Split Bits", "ceph.pg_stat.parent_splitbits",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastscrub, {
			"Last Scrub", "ceph.pg_stat.lastscrub",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastscrubstamp, {
			"Last Scrub Timestamp", "ceph.pg_stat.lastscrubstamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_stats, {
			"Stats", "ceph.pg_stat.stats",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_logsize, {
			"Log Size", "ceph.pg_stat.logsize",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_logsizeondisk, {
			"Log Size On-disk", "ceph.pg_stat.logsizeondisk",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_up, {
			"Up", "ceph.pg_stat.up",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_acting, {
			"Acting", "ceph.pg_stat.acting",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastfresh, {
			"Last Fresh", "ceph.pg_stat.lastfresh",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastchange, {
			"Last Change", "ceph.pg_stat.lastchange",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastactive, {
			"Last Active", "ceph.pg_stat.lastactive",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastclean, {
			"Last Clean", "ceph.pg_stat.lastclean",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastunstale, {
			"Last Not Stale", "ceph.pg_stat.lastunstale",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_mappingepoch, {
			"Mapping Epoch", "ceph.pg_stat.mappingepoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastdeepscrub, {
			"Last Deep Scrub", "ceph.pg_stat.lastdeepscrub",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastdeepscrubstamp, {
			"Time of Last Deep Scrub", "ceph.pg_stat.lastdeepscrubstamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_statsinvalid, {
			"Stats Invalid", "ceph.pg_stat.statsinvalid",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastcleanscrubstamp, {
			"Time of Last Clean Scrub", "ceph.pg_stat.lastcleanscrubstamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_lastbecameactive, {
			"Last Became Active", "ceph.pg_stat.lastbecameactive",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_dirtystatsinvalid, {
			"Dirty Stats Invalid", "ceph.pg_stat.dirtystatusinvalid",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_upprimary, {
			"Up Primary", "ceph.pg_stat.upprimary",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_actingprimary, {
			"Acting Primary", "ceph.pg_stat.actingprimary",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_omapstatsinvalid, {
			"OMap Stats Invalid", "ceph.pg_stat.omapstatsinvalid",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_pg_stat_hitsetstatsinvalid, {
			"HitSet Stats Invalid", "ceph.pg_stat.hitsetstatsinvalid",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock, {
			"Superblock", "ceph.osd_superblock",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock_clusterfsid, {
			"Cluster FSID", "ceph.osd_superblock.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock_role, {
			"Role", "ceph.osd_superblock.role",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock_epoch, {
			"Epoch", "ceph.osd_superblock.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock_map_old, {
			"Oldest Map", "ceph.osd_superblock.map_old",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock_map_new, {
			"Newest Map", "ceph.osd_superblock.map_new",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock_weight, {
			"Weight", "ceph.osd_superblock.weight",
			FT_DOUBLE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock_mounted, {
			"Mounted", "ceph.osd_superblock.mounted",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Last epoch mounted.", HFILL
		} },
		{ &hf_osd_superblock_osdfsid, {
			"OSD FSID", "ceph.osd_superblock.osdfsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_superblock_clean, {
			"Clean Through", "ceph.osd_superblock.clean",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Last epoch active and clean.", HFILL
		} },
		{ &hf_osd_superblock_full, {
			"Last Marked Full", "ceph.osd_superblock.full",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Last epoch OSDMap was marked full.", HFILL
		} },
		{ &hf_osdinfo_ver, {
			"Encoding Version", "ceph.osdinfo.ver",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdinfo_lastclean_begin, {
			"Last Clean Begin", "ceph.osdinfo.lastclean.begin",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The start of the last interval that ended with "
			"a clean shutdown.", HFILL
		} },
		{ &hf_osdinfo_lastclean_end, {
			"Last Clean End", "ceph.osdinfo.lastclean.end",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The end of the last interval that ended with a "
			"clean shutdown.", HFILL
		} },
		{ &hf_osdinfo_up_from, {
			"Up From", "ceph.osdinfo.up.from",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Epoch OSD was marked up.", HFILL
		} },
		{ &hf_osdinfo_up_through, {
			"Up Through", "ceph.osdinfo.up.through",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Last epoch before OSD died.", HFILL
		} },
		{ &hf_osdinfo_downat, {
			"Down At", "ceph.osdinfo.downat",
			FT_UINT32, BASE_DEC, NULL, 0,
			"First epoch after OSD died.", HFILL
		} },
		{ &hf_osdinfo_lostat, {
			"Lost At", "ceph.osdinfo.lostat",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Last epoch where the data was decided \"lost\".", HFILL
		} },
		{ &hf_osdxinfo_down, {
			"Down At", "ceph.osdxinfo.downat",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			"Time when OSD was last marked down.", HFILL
		} },
		{ &hf_osdxinfo_laggy_probability, {
			"Laggy Probability", "ceph.osdxinfo.laggy.probability",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Probability that the OSD is laggy. (out of 0xFFFFFFFF)", HFILL
		} },
		{ &hf_osdxinfo_laggy_interval, {
			"Laggy Interval", "ceph.osdxinfo.laggy.interval",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Average interval between being marked laggy and recovering.", HFILL
		} },
		{ &hf_osdxinfo_oldweight, {
			"Old Weight", "ceph.osdxinfo.oldweight",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_perfstat_commitlatency, {
			"Commit Latency", "ceph.perfstat.commitlatency",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_perfstat_applylatency, {
			"Apply Latency", "ceph.perfstat.applylatency",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat, {
			"OSD Stats", "ceph.osdstat",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_kb, {
			"KiB", "ceph.osdstat.kb",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_kbused, {
			"KiB Used", "ceph.osdstat.kbused",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_kbavail, {
			"KiB Available", "ceph.osdstat.kbavail",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_trimqueue, {
			"Trim Queue", "ceph.osdstat.trimqueue",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_hbin, {
			"Heartbeats In", "ceph.osdstat.hbin",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_hbout, {
			"Heartbeats Out", "ceph.osdstat.hbout",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_opqueue, {
			"Op Queue", "ceph.osdstat.opqueue",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_fsperf, {
			"Filesystem Performance", "ceph.osdstat.fsperf",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdstat_trimming, {
			"Number Trimming", "ceph.osdstat.trimming",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap, {
			"OSD Map", "ceph.osdmap",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_client, {
			"Client-Usable Data", "ceph.osdmap.client",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_fsid, {
			"FSID", "ceph.osdmap.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_epoch, {
			"Epoch", "ceph.osdmap.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_created, {
			"Time Created", "ceph.osdmap.created",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_modified, {
			"Last Modified", "ceph.osdmap.modified",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_pool, {
			"Pool", "ceph.osdmap.pool",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_pool_id, {
			"ID", "ceph.osdmap.pool.id",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_poolname_item, {
			"Pool Name", "ceph.osdmap.poolname.item",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_poolname, {
			"Name", "ceph.osdmap.poolname",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_poolmax, {
			"Highest Pool ID", "ceph.osdmap.poolmax",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_flags, {
			"Flags", "ceph.osdmap.flags",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_osdmax, {
			"Highest OSD Number", "ceph.osdmap.osdmax",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_osd_state, {
			"OSD State", "ceph.osdmap.osd.state",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_osd_weight, {
			"OSD Weight", "ceph.osdmap.osd.weight",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_osd_addr, {
			"OSD Address", "ceph.osdmap.address",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_pgtmp, {
			"Temporary Placement Group Mapping", "ceph.osdmap.pgtmp",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_pgtmp_pg, {
			"Placement Group", "ceph.osdmap.pgtmp.pg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_pgtmp_val, {
			"Value", "ceph.osdmap.pgtmp.val",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_primarytmp, {
			"Temporary Primary Mapping", "ceph.osdmap.primarytmp",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_primarytmp_pg, {
			"Placement Group", "ceph.osdmap.primarytmp.pg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_primarytmp_val, {
			"Value", "ceph.osdmap.primarytmp.val",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_osd_primaryaffinity, {
			"Primary Affinity", "ceph.osdmap.osd.primaryaffinity",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_crush, {
			"CRUSH Rules", "ceph.crush",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_peerstat, {
			"Peer Stat", "ceph.osd.peerstat",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_peerstat_timestamp, {
			"Timestamp", "ceph.osd.peerstat.timestamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_featureset_mask, {
			"Feature Mask", "ceph.featureset.mask",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_featureset_name, {
			"Name", "ceph.featureset.name",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_featureset_name_val, {
			"Value", "ceph.featureset.name.val",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_featureset_name_name, {
			"Name", "ceph.featureset.name.name",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_compatset, {
			"Compat Set", "ceph.compatset",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_compatset_compat, {
			"Compatible", "ceph.compatset.compat",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_compatset_compatro, {
			"Read-Only Compatible", "ceph.compatset.rocompat",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_compatset_incompat, {
			"Incompatible", "ceph.compatset.incompat",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_erasurecodeprofile, {
			"Erasure Code Profile", "ceph.osdmap.erasurecodeprofile",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_erasurecodeprofile_name, {
			"Profile Name", "ceph.osdmap.erasurecodeprofile.name",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_erasurecodeprofile_prop, {
			"Property", "ceph.osdmap.erasurecodeprofile.prop",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_erasurecodeprofile_k, {
			"Key", "ceph.osdmap.erasurecodeprofile.key",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_erasurecodeprofile_v, {
			"Value", "ceph.osdmap.erasurecodeprofile.value",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_osd, {
			"OSD-Only Data", "ceph.osdmap.osd",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_hbaddr_back, {
			"Cluster-side Heartbeat Address", "ceph.osdmap.nbbackaddr",
			FT_NONE, BASE_NONE, NULL, 0,
			"The address checked to ensure the OSD is reachable by "
			"the cluster.", HFILL
		} },
		{ &hf_osdmap_osd_info, {
			"OSD Info", "ceph.osdmap.osd.info",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_blacklist, {
			"Blacklist", "ceph.osdmap.blacklist",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_blacklist_addr, {
			"Address", "ceph.osdmap.blacklist.addr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_blacklist_time, {
			"Time", "ceph.osdmap.blacklist.time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_cluster_addr, {
			"Cluster Address", "ceph.osdmap.cluster.addr",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_cluster_snapepoch, {
			"Cluster Snapshot Epoch", "ceph.osdmap.cluster.snapepoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_cluster_snap, {
			"Cluster Snapshot", "ceph.osdmap.cluster.snap",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_osd_uuid, {
			"OSD UUID", "ceph.osdmap.osd.uuid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_osd_xinfo, {
			"OSD xinfo", "ceph.osdmap.osd.xinfo",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_hbaddr_front, {
			"Client-side Heartbeat Address", "ceph.osdmap.hbfrontaddr",
			FT_NONE, BASE_NONE, NULL, 0,
			"The address checked to ensure the OSD is reachable "
			"by the client.", HFILL
		} },
		{ &hf_osdmap_inc, {
			"Incremental OSD Map", "ceph.osdmap_inc",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_inc_client, {
			"Client-Usable Data", "ceph.osdmap_inc.client",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_inc_fsid, {
			"FSID", "ceph.osdmap_inc.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osdmap_inc_osd, {
			"OSD-Only Data", "ceph.osdmap_inc.osd",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_connect, {
			"Connection Negotiation", "ceph.connect",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_features_low, {
			"Features", "ceph.connect.features.low",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_features_high, {
			"Features", "ceph.connect.features.high",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_feature_uid, {
			"UID", "ceph.features.uid",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_UID,
			NULL, HFILL
		} },
		{ &hf_feature_nosrcaddr, {
			"NOSRCADDR", "ceph.features.nosrcaddr",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_NOSRCADDR,
			NULL, HFILL
		} },
		{ &hf_feature_monclockcheck, {
			"MONCLOCKCHECK", "ceph.features.monclockcheck",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MONCLOCKCHECK,
			NULL, HFILL
		} },
		{ &hf_feature_flock, {
			"FLOCK", "ceph.features.flock",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_FLOCK,
			NULL, HFILL
		} },
		{ &hf_feature_subscribe2, {
			"SUBSCRIBE2", "ceph.features.subscribe2",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_SUBSCRIBE2,
			NULL, HFILL
		} },
		{ &hf_feature_monnames, {
			"MONNAMES", "ceph.features.monnames",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MONNAMES,
			NULL, HFILL
		} },
		{ &hf_feature_reconnect_seq, {
			"RECONNECT_SEQ", "ceph.features.reconnect_seq",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_RECONNECT_SEQ,
			NULL, HFILL
		} },
		{ &hf_feature_dirlayouthash, {
			"DIRLAYOUTHASH", "ceph.features.dirlayouthash",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_DIRLAYOUTHASH,
			NULL, HFILL
		} },
		{ &hf_feature_objectlocator, {
			"OBJECTLOCATOR", "ceph.features.objectlocator",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OBJECTLOCATOR,
			NULL, HFILL
		} },
		{ &hf_feature_pgid64, {
			"PGID64", "ceph.features.pgid64",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_PGID64,
			NULL, HFILL
		} },
		{ &hf_feature_incsubosdmap, {
			"INCSUBOSDMAP", "ceph.features.incsubosdmap",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_INCSUBOSDMAP,
			NULL, HFILL
		} },
		{ &hf_feature_pgpool3, {
			"PGPOOL3", "ceph.features.pgpool3",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_PGPOOL3,
			NULL, HFILL
		} },
		{ &hf_feature_osdreplymux, {
			"OSDREPLYMUX", "ceph.features.osdreplymux",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSDREPLYMUX,
			NULL, HFILL
		} },
		{ &hf_feature_osdenc, {
			"OSDENC", "ceph.features.osdenc",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSDENC,
			NULL, HFILL
		} },
		{ &hf_feature_omap, {
			"OMAP", "ceph.features.omap",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OMAP,
			NULL, HFILL
		} },
		{ &hf_feature_monenc, {
			"MONENC", "ceph.features.monenc",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MONENC,
			NULL, HFILL
		} },
		{ &hf_feature_query_t, {
			"QUERY_T", "ceph.features.query_t",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_QUERY_T,
			NULL, HFILL
		} },
		{ &hf_feature_indep_pg_map, {
			"INDEP_PG_MAP", "ceph.features.indep_pg_map",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_INDEP_PG_MAP,
			NULL, HFILL
		} },
		{ &hf_feature_crush_tunables, {
			"CRUSH_TUNABLES", "ceph.features.crush_tunables",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CRUSH_TUNABLES,
			NULL, HFILL
		} },
		{ &hf_feature_chunky_scrub, {
			"CHUNKY_SCRUB", "ceph.features.chunky_scrub",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CHUNKY_SCRUB,
			NULL, HFILL
		} },
		{ &hf_feature_mon_nullroute, {
			"MON_NULLROUTE", "ceph.features.mon_nullroute",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MON_NULLROUTE,
			NULL, HFILL
		} },
		{ &hf_feature_mon_gv, {
			"MON_GV", "ceph.features.mon_gv",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MON_GV,
			NULL, HFILL
		} },
		{ &hf_feature_backfill_reservation, {
			"BACKFILL_RESERVATION", "ceph.features.backfill_reservation",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_BACKFILL_RESERVATION,
			NULL, HFILL
		} },
		{ &hf_feature_msg_auth, {
			"MSG_AUTH", "ceph.features.msg_auth",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MSG_AUTH,
			NULL, HFILL
		} },
		{ &hf_feature_recovery_reservation, {
			"RECOVERY_RESERVATION", "ceph.features.recovery_reservation",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_RECOVERY_RESERVATION,
			NULL, HFILL
		} },
		{ &hf_feature_crush_tunables2, {
			"CRUSH_TUNABLES2", "ceph.features.crush_tunables2",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CRUSH_TUNABLES2,
			NULL, HFILL
		} },
		{ &hf_feature_createpoolid, {
			"CREATEPOOLID", "ceph.features.createpoolid",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CREATEPOOLID,
			NULL, HFILL
		} },
		{ &hf_feature_reply_create_inode, {
			"REPLY_CREATE_INODE", "ceph.features.reply_create_inode",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_REPLY_CREATE_INODE,
			NULL, HFILL
		} },
		{ &hf_feature_osd_hbmsgs, {
			"OSD_HBMSGS", "ceph.features.osd_hbmsgs",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_HBMSGS,
			NULL, HFILL
		} },
		{ &hf_feature_mdsenc, {
			"MDSENC", "ceph.features.mdsenc",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MDSENC,
			NULL, HFILL
		} },
		{ &hf_feature_osdhashpspool, {
			"OSDHASHPSPOOL", "ceph.features.osdhashpspool",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSDHASHPSPOOL,
			NULL, HFILL
		} },
		{ &hf_feature_mon_single_paxos, {
			"MON_SINGLE_PAXOS", "ceph.features.mon_single_paxos",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MON_SINGLE_PAXOS,
			NULL, HFILL
		} },
		{ &hf_feature_osd_snapmapper, {
			"OSD_SNAPMAPPER", "ceph.features.osd_snapmapper",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_SNAPMAPPER,
			NULL, HFILL
		} },
		{ &hf_feature_mon_scrub, {
			"MON_SCRUB", "ceph.features.mon_scrub",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MON_SCRUB,
			NULL, HFILL
		} },
		{ &hf_feature_osd_packed_recovery, {
			"OSD_PACKED_RECOVERY", "ceph.features.osd_packed_recovery",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_PACKED_RECOVERY,
			NULL, HFILL
		} },
		{ &hf_feature_osd_cachepool, {
			"OSD_CACHEPOOL", "ceph.features.osd_cachepool",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_CACHEPOOL,
			NULL, HFILL
		} },
		{ &hf_feature_crush_v2, {
			"CRUSH_V2", "ceph.features.crush_v2",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CRUSH_V2,
			NULL, HFILL
		} },
		{ &hf_feature_export_peer, {
			"EXPORT_PEER", "ceph.features.export_peer",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_EXPORT_PEER,
			NULL, HFILL
		} },
		{ &hf_feature_osd_erasure_codes, {
			"OSD_ERASURE_CODES", "ceph.features.osd_erasure_codes",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_ERASURE_CODES,
			NULL, HFILL
		} },
		{ &hf_feature_osd_tmap2omap, {
			"OSD_TMAP2OMAP", "ceph.features.osd_tmap2omap",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_TMAP2OMAP,
			NULL, HFILL
		} },
		{ &hf_feature_osdmap_enc, {
			"OSDMAP_ENC", "ceph.features.osdmap_enc",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSDMAP_ENC,
			NULL, HFILL
		} },
		{ &hf_feature_mds_inline_data, {
			"MDS_INLINE_DATA", "ceph.features.mds_inline_data",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MDS_INLINE_DATA,
			NULL, HFILL
		} },
		{ &hf_feature_crush_tunables3, {
			"CRUSH_TUNABLES3", "ceph.features.crush_tunables3",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_CRUSH_TUNABLES3,
			NULL, HFILL
		} },
		{ &hf_feature_osd_primary_affinity, {
			"OSD_PRIMARY_AFFINITY", "ceph.features.osd_primary_affinity",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_OSD_PRIMARY_AFFINITY,
			NULL, HFILL
		} },
		{ &hf_feature_msgr_keepalive2, {
			"MSGR_KEEPALIVE2", "ceph.features.msgr_keepalive2",
			FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), C_FEATURE_MSGR_KEEPALIVE2,
			NULL, HFILL
		} },
		{ &hf_feature_reserved, {
			"RESERVED", "ceph.features.reserved",
			FT_BOOLEAN, 32, TFS(&tfs_set_notset), C_FEATURE_RESERVED,
			NULL, HFILL
		} },
		{ &hf_connect_host_type, {
			"Host Type", "ceph.connect.host",
			FT_UINT32, BASE_HEX, VALS(c_node_type_strings), 0,
			"The type of host.", HFILL
		} },
		{ &hf_connect_seq_global, {
			"Global Sequence Number", "ceph.connect.global_seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The number of connections initiated by this host.", HFILL
		} },
		{ &hf_connect_seq, {
			"Sequence Number", "ceph.connect.seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The number of connections initiated this session.", HFILL
		} },
		{ &hf_connect_proto_ver, {
			"Protocol Version", "ceph.connect.ver",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The protocol version to use.", HFILL
		} },
		{ &hf_connect_auth_proto, {
			"Authentication Protocol", "ceph.connect.auth.proto",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The authentication protocol to use.", HFILL
		} },
		{ &hf_connect_auth_size, {
			"Authentication Size", "ceph.connect.auth.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The size of the authentication.", HFILL
		} },
		{ &hf_connect_auth, {
			"Authentication", "ceph.connect.auth",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Authentication data.", HFILL
		} },
		{ &hf_flags, {
			"Flags", "ceph.connect.flags",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_flag_lossy, {
			"Lossy", "ceph.flags.lossy",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), C_FLAG_LOSSY,
			"Messages may be safely dropped.", HFILL
		} },
		{ &hf_osd_flags, {
			"OSD Flags", "ceph.osd_flags",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_flag_ack, {
			"ACK", "ceph.osd_flags.ack",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ACK,
			"want (or is) \"ack\" ack", HFILL
		} },
		{ &hf_osd_flag_onnvram, {
			"ACK on NVRAM", "ceph.osd_flags.onnvram",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ONNVRAM,
			"want (or is) \"onnvram\" ack", HFILL
		} },
		{ &hf_osd_flag_ondisk, {
			"ACK on DISK", "ceph.osd_flags.ondisk",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ONDISK,
			"want (or is) \"ondisk\" ack", HFILL
		} },
		{ &hf_osd_flag_retry, {
			"Retry", "ceph.osd_flags.retry",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_RETRY,
			"resend attempt", HFILL
		} },
		{ &hf_osd_flag_read, {
			"Read", "ceph.osd_flags.read",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_READ,
			"op may read", HFILL
		} },
		{ &hf_osd_flag_write, {
			"Write", "ceph.osd_flags.write",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_WRITE,
			"op may write", HFILL
		} },
		{ &hf_osd_flag_ordersnap, {
			"ORDERSNAP", "ceph.osd_flags.ordersnap",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ORDERSNAP,
			"EOLDSNAP if snapc is out of order", HFILL
		} },
		{ &hf_osd_flag_peerstat_old, {
			"PEERSTAT_OLD", "ceph.osd_flags.peerstat_old",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_PEERSTAT_OLD,
			"DEPRECATED msg includes osd_peer_stat", HFILL
		} },
		{ &hf_osd_flag_balance_reads, {
			"BALANCE_READS", "ceph.osd_flags.balance_reads",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_BALANCE_READS,
			NULL, HFILL
		} },
		{ &hf_osd_flag_parallelexec, {
			"PARALLELEXEC", "ceph.osd_flags.parallelexec",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_PARALLELEXEC,
			"execute op in parallel", HFILL
		} },
		{ &hf_osd_flag_pgop, {
			"PGOP", "ceph.osd_flags.pgop",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_PGOP,
			"pg op, no object", HFILL
		} },
		{ &hf_osd_flag_exec, {
			"EXEC", "ceph.osd_flags.exec",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_EXEC,
			"op may exec", HFILL
		} },
		{ &hf_osd_flag_exec_public, {
			"EXEC_PUBLIC", "ceph.osd_flags.exec_public",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_EXEC_PUBLIC,
			"DEPRECATED op may exec (public)", HFILL
		} },
		{ &hf_osd_flag_localize_reads, {
			"LOCALIZE_READS", "ceph.osd_flags.localize_reads",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_LOCALIZE_READS,
			"read from nearby replica, if any", HFILL
		} },
		{ &hf_osd_flag_rwordered, {
			"RWORDERED", "ceph.osd_flags.rwordered",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_RWORDERED,
			"order wrt concurrent reads", HFILL
		} },
		{ &hf_osd_flag_ignore_cache, {
			"IGNORE_CACHE", "ceph.osd_flags.ignore_cache",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_IGNORE_CACHE,
			"ignore cache logic", HFILL
		} },
		{ &hf_osd_flag_skiprwlocks, {
			"SKIPRWLOCKS", "ceph.osd_flags.skiprwlocks",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_SKIPRWLOCKS,
			"skip rw locks", HFILL
		} },
		{ &hf_osd_flag_ignore_overlay, {
			"IGNORE_OVERLAY", "ceph.osd_flags.ignore_overlay",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_IGNORE_OVERLAY,
			"ignore pool overlay", HFILL
		} },
		{ &hf_osd_flag_flush, {
			"FLUSH", "ceph.osd_flags.flush",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_FLUSH,
			"this is part of flush", HFILL
		} },
		{ &hf_osd_flag_map_snap_clone, {
			"MAP_SNAP_CLONE", "ceph.osd_flags.map_snap_clone",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_MAP_SNAP_CLONE,
			"map snap direct to clone id", HFILL
		} },
		{ &hf_osd_flag_enforce_snapc, {
			"ENFORCE_SNAPC", "ceph.osd_flags.enforce_snapc",
			FT_BOOLEAN, 32, TFS(&tfs_yes_no), C_OSD_FLAG_ENFORCE_SNAPC,
			"use snapc provided even if pool uses pool snaps", HFILL
		} },
		{ &hf_osd_op_type, {
			"Operation", "ceph.osd_op.op",
			FT_UINT16, BASE_HEX|BASE_EXT_STRING, &c_osd_optype_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_osd_op_data, {
			"Operation Specific Data", "ceph.osd_op.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_op_extent_off, {
			"Offset", "ceph.osd_op.extent.offset",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_op_extent_size, {
			"Size", "ceph.osd_op.extent.size",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_op_extent_trunc_size, {
			"Truncate Size", "ceph.osd_op.extent.trunc_size",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_op_extent_trunc_seq, {
			"Truncate Sequence", "ceph.osd_op.extent.trunc_seq",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_op_payload_size, {
			"Payload Size", "ceph.osd_op.payload_size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_redirect_oloc, {
			"Object Locater", "ceph.osd_redirect.oloc",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_redirect_obj, {
			"Object Name", "ceph.osd_redirect.obj",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Redirect to this object.", HFILL
		} },
		{ &hf_osd_redirect_osdinstr, {
			"OSD Instructions", "ceph.osd_redirect.osd_instructions",
			FT_NONE, BASE_NONE, NULL, 0,
			"Instructions to pass to the new target.", HFILL
		} },
		{ &hf_osd_redirect_osdinstr_data, {
			"Data", "ceph.osd_redirect.osd_instructions_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_osd_redirect_osdinstr_len, {
			"Length", "ceph.osd_redirect.osd_instructions_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_bytes, {
			"Bytes", "ceph.statsum.bytes",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The space used in bytes.", HFILL
		} },
		{ &hf_statsum_objects, {
			"Objects", "ceph.statsum.objects",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The number of logical objects.", HFILL
		} },
		{ &hf_statsum_clones, {
			"Clones", "ceph.statsum.clones",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_copies, {
			"Copies", "ceph.statsum.copies",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The total number of objects including redundant "
			"copies (objects*replicas).", HFILL
		} },
		{ &hf_statsum_missing, {
			"Missing Objects", "ceph.statsum.missing",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_degraded, {
			"Degraded Objects", "ceph.statsum.degraded",
			FT_UINT64, BASE_DEC, NULL, 0,
			"Number of objects that are on at least one OSD but "
			"less then they should be.", HFILL
		} },
		{ &hf_statsum_unfound, {
			"Unfound Objects", "ceph.statsum.unfound",
			FT_UINT64, BASE_DEC, NULL, 0,
			"Number of objects with no copies.", HFILL
		} },
		{ &hf_statsum_read_bytes, {
			"Bytes Read", "ceph.statsum.read_bytes",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_read_kbytes, {
			"Kibibytes Read", "ceph.statsum.read_kbytes",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The number of KiB (2^10) read.", HFILL
		} },
		{ &hf_statsum_written_bytes, {
			"Bytes Written", "ceph.statsum.written_bytes",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_written_kbytes, {
			"Kibibytes Written", "ceph.statsum.written_kbytes",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The number of KiB (2^10) written.", HFILL
		} },
		{ &hf_statsum_scrub_errors, {
			"Scrub Errors", "ceph.statsum.scrub_errors",
			FT_UINT64, BASE_DEC, NULL, 0,
			"Total scrub errors. (shallow+deep)", HFILL
		} },
		{ &hf_statsum_recovered, {
			"Recovered Objects", "ceph.statsum.recovered",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_bytes_recovered, {
			"Recovered Bytes", "ceph.statsum.bytes_recovered",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_keys_recovered, {
			"Keys Recovered", "ceph.statsum.keys_recovered",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_shallow_scrub_errors, {
			"Shallow Scrub Errors", "ceph.statsum.shallow_scrub_errors",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_deep_scrub_errors, {
			"Deep Scrub Errors", "ceph.statsum.deep_scrub_errors",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_dirty, {
			"Dirty Objects", "ceph.statsum.dirty",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_whiteouts, {
			"Whiteouts", "ceph.statsum.whiteouts",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_omap, {
			"OMAP Objects", "ceph.statsum.omap",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statsum_hitset_archive, {
			"Hit Set Archive", "ceph.statsum.hitset_archive",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_connect_reply, {
			"Connection Negotiation Reply", "ceph.connect_reply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_tag, {
			"Tag", "ceph.tag",
			FT_UINT8, BASE_HEX|BASE_EXT_STRING, &c_tag_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_ack, {
			"Acknowledgment", "ceph.ack",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_seq_existing, {
			"Existing Sequence Number", "ceph.seq_existing",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_seq_new, {
			"Newly Acknowledged Sequence Number", "ceph.seq_new",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head, {
			"Message Header", "ceph.head",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_seq, {
			"Sequence Number", "ceph.seq",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_tid, {
			"Transaction ID", "ceph.tid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_type, {
			"Type", "ceph.type",
			FT_UINT16, BASE_HEX|BASE_EXT_STRING, &c_msg_type_strings_ext, 0,
			"Message type.", HFILL
		} },
		{ &hf_head_priority, {
			"Priority", "ceph.priority",
			FT_UINT16, BASE_DEC, NULL, 0,
			"The priority of this message, higher the more urgent.", HFILL
		} },
		{ &hf_head_version, {
			"Version", "ceph.head_version",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_front_size, {
			"Front Size", "ceph.front_size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_middle_size, {
			"Middle Size", "ceph.middle_size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_data_size, {
			"Data Size", "ceph.data_size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_data_off, {
			"Data Offset", "ceph.data_off",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_srcname, {
			"Source Name", "ceph.node",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_compat_version, {
			"Compatibility Version", "ceph.compat_version",
			FT_UINT64, BASE_DEC, NULL, 0,
			"The oldest code that can probably decode this message.", HFILL
		} },
		{ &hf_head_reserved, {
			"Reserved", "ceph.reserved",
			FT_UINT16, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_head_crc, {
			"CRC Checksum", "ceph.crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot, {
			"Message Footer", "ceph.foot",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot_front_crc, {
			"Front Checksum", "ceph.foot.front_crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot_middle_crc, {
			"Middle Checksum", "ceph.foot.middle_crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot_data_crc, {
			"Data Checksum", "ceph.foot.data_crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_foot_signature, {
			"Signature", "ceph.foot.signature",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_front, {
			"Front", "ceph.front",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_middle, {
			"Middle", "ceph.mid",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_data, {
			"Data", "ceph.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_statcollection, {
			"Stats", "ceph.statcollection",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_paxos, {
			"Paxos Message", "ceph.paxos",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_paxos_ver, {
			"Paxos Version", "ceph.paxos.ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_paxos_mon, {
			"Mon", "ceph.paxos.mon",
			FT_INT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_paxos_mon_tid, {
			"Mon Transaction ID", "ceph.paxos.tid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_map, {
			"Mon Map Message", "ceph.msg.mon_map",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfs, {
			"Stat Filesystem", "ceph.msg.statfs",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfs_fsid, {
			"FSID", "ceph.msg.statfs.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfsreply, {
			"Stat Filesystem Reply", "ceph.msg.statfsreply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfsreply_fsid, {
			"FSID", "ceph.msg.statfsreply.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfsreply_ver, {
			"Version", "ceph.msg.statfsreply.ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfsreply_kb, {
			"Kibibytes", "ceph.msg.statfsreply.kb",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfsreply_kbused, {
			"Kibibytes Used", "ceph.msg.statfsreply.kbused",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfsreply_kbavail, {
			"Kibibytes Available", "ceph.msg.statfsreply.kbavail",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_statfsreply_obj, {
			"Number of Objects", "ceph.msg.statfsreply.obj",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub, {
			"Mon Subscribe Message", "ceph.msg.mon_sub",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_item, {
			"Subscription Item", "ceph.msg.mon_sub.item",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_item_len, {
			"Number of items", "ceph.msg.mon_sub.item_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_what, {
			"What", "ceph.msg.mon_sub.what",
			FT_STRING, BASE_NONE, NULL, 0,
			"What to subscribe to.", HFILL
		} },
		{ &hf_msg_mon_sub_start, {
			"Start Time", "ceph.msg.mon_sub.start",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_flags, {
			"Flags", "ceph.msg.mon_sub.flags",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_flags_onetime, {
			"One Time", "ceph.msg.mon_sub.flags.onetime",
			FT_BOOLEAN, 8, TFS(&tfs_yes_no), C_MON_SUB_FLAG_ONETIME,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_ack, {
			"Subscription Acknowledgment", "ceph.msg.mon_sub_ack",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_ack_interval, {
			"Interval", "ceph.msg.mon_sub_ack.interval",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_sub_ack_fsid, {
			"FSID", "ceph.msg.mon_sub_ack.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth, {
			"Auth Message", "ceph.msg.auth",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_proto, {
			"Protocol", "ceph.msg.auth.proto",
			FT_UINT32, BASE_HEX, VALS(c_auth_proto_strings), 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_supportedproto, {
			"Supported Protocols", "ceph.msg.auth.supportedproto",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_supportedproto_ver, {
			"Encoding Version", "ceph.msg.auth.supportedproto.ver",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_supportedproto_proto, {
			"Supported Protocol", "ceph.msg.auth.supportedproto.proto",
			FT_UINT32, BASE_HEX, VALS(c_auth_proto_strings), 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_supportedproto_gid, {
			"Global ID", "ceph.msg.auth.supportedproto.gid",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_cephx, {
			"CephX", "ceph.msg.auth.cephx",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_cephx_req_type, {
			"Type", "ceph.msg.auth.cephx.req.type",
			FT_UINT16, BASE_HEX, VALS(c_cephx_req_type_strings), 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_monmap_epoch, {
			"Monmap epoch", "ceph.msg.auth.monmap_epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply, {
			"Auth Reply Message", "ceph.msg.auth_reply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_proto, {
			"Protocol", "ceph.msg.auth_reply.proto",
			FT_UINT32, BASE_HEX, VALS(c_auth_proto_strings), 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_result, {
			"Result", "ceph.msg.auth_reply.result",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_global_id, {
			"Global ID", "ceph.msg.auth_reply.id",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_auth_reply_msg, {
			"Message", "ceph.msg.auth_reply.msg",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_getverison, {
			"Get Version", "ceph.msg.mon.getverison",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_getverison_tid, {
			"Transaction ID", "ceph.msg.mon.getverison.tid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_getverison_what, {
			"What", "ceph.msg.mon.getverison.what",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_getverisonreply, {
			"Get Version Reply", "ceph.msg.mon.getverisonreply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_getverisonreply_tid, {
			"Transaction ID", "ceph.msg.mon.getverisonreply.tid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_getverisonreply_ver, {
			"Version", "ceph.msg.mon.getverisonreply.ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_getverisonreply_veroldest, {
			"Oldest Version", "ceph.msg.mon.getverisonreply.veroldest",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mds_map, {
			"OSD Map Message", "ceph.msg.osd_map",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mds_map_fsid, {
			"FSID", "ceph.msg.osd_map.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mds_map_epoch, {
			"Epoch", "ceph.msg.osd_map.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mds_map_datai, {
			"OSD Map Data", "ceph.msg.osd_map.datai",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mds_map_data, {
			"Data", "ceph.msg.osd_map.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mds_map_data_size, {
			"Size", "ceph.msg.osd_map.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_sess, {
			"Client Session", "ceph.msg.client_sess",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_sess_op, {
			"Operation", "ceph.msg.client_sess.op",
			FT_UINT32, BASE_HEX|BASE_EXT_STRING, &c_session_op_type_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_sess_seq, {
			"Sequence Number", "ceph.msg.client_sess.seq",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_sess_time, {
			"Timestamp", "ceph.msg.client_sess.time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_sess_caps_max, {
			"Maximum Capabilities", "ceph.msg.client_sess.caps_max",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_sess_leases_max, {
			"Maximum Leases", "ceph.msg.client_sess.leases_max",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req, {
			"Client Request", "ceph.msg.client_req",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_oldest_tid, {
			"Oldest TID", "ceph.msg.client_req.oldest_tid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_mdsmap_epoch, {
			"MDS Map Epoch", "ceph.msg.client_req.mdsmap_epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_flags, {
			"Flags", "ceph.msg.client_req.flags",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_retry, {
			"Number of Retries", "ceph.msg.client_req.retry",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_forward, {
			"Number of Forwards", "ceph.msg.client_req.forward",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_releases, {
			"Number of Releases", "ceph.msg.client_req.releases",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_op, {
			"Operation", "ceph.msg.client_req.op",
			FT_UINT32, BASE_HEX|BASE_EXT_STRING, &c_mds_op_type_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_caller_uid, {
			"Caller User ID", "ceph.msg.client_req.caller_uid",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_caller_gid, {
			"Caller Group ID", "ceph.msg.client_req.caller_gid",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_inode, {
			"Inode", "ceph.msg.client_req.inode",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_path_src, {
			"Path", "ceph.msg.client_req.path_src",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_path_dst, {
			"Second Path", "ceph.msg.client_req.path_dst",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_release, {
			"Release", "ceph.msg.client_req.release",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_req_time, {
			"Timestamp", "ceph.msg.client_req.time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reqfwd, {
			"Client Request Forward", "ceph.msg.client_reqfwd",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reqfwd_dst, {
			"Destination MDS", "ceph.msg.client_reqfwd.dst",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reqfwd_fwd, {
			"Number of Forwards", "ceph.msg.client_reqfwd.fwd",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reqfwd_resend, {
			"Resend", "ceph.msg.client_reqfwd.resend",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			"Does the client have to resend the request?", HFILL
		} },
		{ &hf_msg_client_reply, {
			"Client Reply", "ceph.msg.client_reply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_op, {
			"Operation", "ceph.msg.client_reply.op",
			FT_UINT32, BASE_DEC|BASE_EXT_STRING, &c_mds_op_type_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_result, {
			"Result", "ceph.msg.client_reply.result",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_mdsmap_epoch, {
			"MDS Map Epoch", "ceph.msg.client_reply.mdsmap_epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_isdentry, {
			"Is Dentry", "ceph.msg.client_reply.isdentry",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_istarget, {
			"Is Target", "ceph.msg.client_reply.istarget",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_trace, {
			"Trace", "ceph.msg.client_reply.trace",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_extra, {
			"Extra", "ceph.msg.client_reply.extra",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_snaps, {
			"Snapshots", "ceph.msg.client_reply.snaps",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_reply_safe, {
			"Committed to Permanent Storage", "ceph.msg.client_reply.safe",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map, {
			"OSD Map Message", "ceph.msg.osd_map",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_fsid, {
			"FSID", "ceph.msg.osd_map.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_inc, {
			"Incremental Map", "ceph.msg.osd_map.inc",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_inc_len, {
			"Incremental Map Count", "ceph.msg.osd_map.inc_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_map, {
			"Map", "ceph.msg.osd_map.map",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_map_len, {
			"Map Count", "ceph.msg.osd_map.map_size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_epoch, {
			"Epoch", "ceph.msg.osd_map.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_oldest, {
			"Oldest Map", "ceph.msg.osd_map.oldest",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_map_newest, {
			"Newest Map", "ceph.msg.osd_map.newest",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op, {
			"OSD Operation", "ceph.msg.osd_op",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_client_inc, {
			"Client Inc", "ceph.msg.osd_op.client_inc",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_osdmap_epoch, {
			"OSD Map Epoch", "ceph.msg.osd_op.osdmap_epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_mtime, {
			"Modification Time", "ceph.msg.osd_op.mtime",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_reassert_version, {
			"Reassert Version", "ceph.msg.osd_op.reassert_version",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_oloc, {
			"Object Locater", "ceph.msg.osd_op.oloc",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_pgid, {
			"Placement Group ID", "ceph.msg.osd_op.pgid",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_oid, {
			"Object ID", "ceph.msg.osd_op.oid",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_ops_len, {
			"Operation Count", "ceph.msg.osd_op.ops_len",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_op, {
			"Operation", "ceph.msg.osd_op.op",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_snap_id, {
			"Snapshot ID", "ceph.msg.osd_op.snap_id",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_snap_seq, {
			"Snapshot Sequence", "ceph.msg.osd_op.snap_seq",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_snaps_len, {
			"Snapshot Count", "ceph.msg.osd_op.snaps_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_snap, {
			"Snapshot", "ceph.msg.osd_op.snaps",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_retry_attempt, {
			"Retry Attempt", "ceph.msg.osd_op.retry",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_op_payload, {
			"Operation Payload", "ceph.msg.osd_op.op_payload",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply, {
			"OSD Operation Reply", "ceph.msg.osd_opreply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_oid, {
			"Object ID", "ceph.msg.osd_opreply.oid",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_pgid, {
			"Placement Group ID", "ceph.msg.osd_opreply.pgid",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_result, {
			"Result", "ceph.msg.osd_opreply.result",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_bad_replay_ver, {
			"Bad Replay Version", "ceph.msg.osd_opreply.bad_replay_ver",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_replay_ver, {
			"Replay Version", "ceph.msg.osd_opreply.replay_ver",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_user_ver, {
			"User Version", "ceph.msg.osd_opreply.user_ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_redirect, {
			"Redirect", "ceph.msg.osd_opreply.redirect",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_osdmap_epoch, {
			"OSD Map Epoch", "ceph.msg.osd_opreply.osdmap_epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_ops_len, {
			"Operation Count", "ceph.msg.osd_opreply.ops_len",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_op, {
			"Operation", "ceph.msg.osd_opreply.op",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_retry_attempt, {
			"Retry Attempt", "ceph.msg.osd_opreply.retry",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_rval, {
			"Operation Return Value", "ceph.msg.osd_opreply.rval",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_opreply_payload, {
			"Operation Result", "ceph.msg.osd_opreply.payload",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolopreply, {
			"Pool Operation", "ceph.msg.poolopreply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolopreply_fsid, {
			"FSID", "ceph.msg.poolopreply.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolopreply_code, {
			"Response Code", "ceph.msg.poolopreply.code",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolopreply_epoch, {
			"Epoch", "ceph.msg.poolopreply.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolopreply_datai, {
			"Data", "ceph.msg.poolopreply.datai",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolopreply_data, {
			"Data", "ceph.msg.poolopreply.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolopreply_data_size, {
			"Size", "ceph.msg.poolopreply.data_size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop, {
			"Pool Operation", "ceph.msg.poolop",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop_fsid, {
			"FSID", "ceph.msg.poolop.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop_pool, {
			"Pool", "ceph.msg.poolop.pool",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop_type, {
			"Type", "ceph.msg.poolop.type",
			FT_UINT32, BASE_HEX, VALS(c_poolop_type_strings), 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop_auid, {
			"AUID", "ceph.msg.poolop.auid",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop_snapid, {
			"Snapshot ID", "ceph.msg.poolop.snap",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop_name, {
			"Name", "ceph.msg.poolop.name",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop_crush_rule, {
			"Crush Rule", "ceph.msg.poolop.crush_rule",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolop_crush_rule8, {
			"Crush Rule", "ceph.msg.poolop.crush_rule",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd, {
			"Mon Command", "ceph.msg.mon_cmd",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_fsid, {
			"FSID", "ceph.msg.mon_cmd.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_arg, {
			"Argument", "ceph.msg.mon_cmd.arg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_arg_len, {
			"Argument Count", "ceph.msg.mon_cmd.arg_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_str, {
			"String", "ceph.msg.mon_cmd.str",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack, {
			"Mon Command Result", "ceph.msg.mon_cmd_ack",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_code, {
			"Result Code", "ceph.msg.mon_cmd_ack.code",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_res, {
			"Result String", "ceph.msg.mon_cmd_ack.result",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_arg, {
			"Argument", "ceph.msg.mon_cmd_ack.arg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_arg_len, {
			"Argument Count", "ceph.msg.mon_cmd_ack.arg_len",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_arg_str, {
			"String", "ceph.msg.mon_cmd_ack.str",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_cmd_ack_data, {
			"Data", "ceph.msg.mon_cmd_ack.data",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstats, {
			"Pool Stats", "ceph.msg.poolstats",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstats_fsid, {
			"FSID", "ceph.msg.poolstats.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstats_pool, {
			"Pool", "ceph.msg.poolstats.pool",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstatsreply, {
			"Pool Stats", "ceph.msg.poolstatsreply",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstatsreply_fsid, {
			"FSID", "ceph.msg.poolstatsreply.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstatsreply_stat, {
			"Stats", "ceph.msg.poolstatsreply.pool.stat",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstatsreply_pool, {
			"Pool", "ceph.msg.poolstatsreply.pool",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstatsreply_log_size, {
			"Log Size", "ceph.msg.poolstatsreply.log_size",
			FT_INT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_poolstatsreply_log_size_ondisk, {
			"On-Disk Log Size", "ceph.msg.poolstatsreply.log_size_ondisk",
			FT_INT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_globalid_max, {
			"Old Max ID", "ceph.msg.mon.globalid.max",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election, {
			"Monitor Election", "ceph.msg.mon_election",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_fsid, {
			"FSID", "ceph.msg.mon_election.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_op, {
			"Type", "ceph.msg.mon_election.op",
			FT_INT32, BASE_DEC|BASE_EXT_STRING, &c_mon_election_type_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_epoch, {
			"Epoch", "ceph.msg.mon_election.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_quorum, {
			"Quorum", "ceph.msg.mon_election.quorum",
			FT_INT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_quorum_features, {
			"Epoch", "ceph.msg.mon_election.quorum_features",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_defunct_one, {
			"Defunct One", "ceph.msg.mon_election.defunct_one",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_defunct_two, {
			"Defunct Two", "ceph.msg.mon_election.defunct_two",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_sharing, {
			"Sharing", "ceph.msg.mon_election.sharing",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_sharing_data, {
			"Data", "ceph.msg.mon_election.sharing_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_election_sharing_size, {
			"Size", "ceph.msg.mon_election.sharing_size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos, {
			"Paxos", "ceph.msg.mon_paxos",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_epoch, {
			"Epoch", "ceph.msg.mon_paxos.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_op, {
			"Op", "ceph.msg.mon_paxos.op",
			FT_INT32, BASE_DEC|BASE_EXT_STRING, &c_mon_paxos_op_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_first, {
			"First Committed", "ceph.msg.mon_paxos.first",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_last, {
			"Last Committed", "ceph.msg.mon_paxos.last",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_pnfrom, {
			"Greatest Seen Proposal Number", "ceph.msg.mon_paxos.pnfrom",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_pn, {
			"Proposal Number", "ceph.msg.mon_paxos.pn",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_pnuncommitted, {
			"Previous Proposal Number", "ceph.msg.mon_paxos.pnuncommitted",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_lease, {
			"Lease Timestamp", "ceph.msg.mon_paxos.lease",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_sent, {
			"Sent Timestamp", "ceph.msg.mon_paxos.sent",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_latest_ver, {
			"Latest Version", "ceph.msg.mon_paxos.latest_ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_latest_val, {
			"Latest Value", "ceph.msg.mon_paxos.latest_val",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_latest_val_data, {
			"Data", "ceph.msg.mon_paxos.latest_val.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_latest_val_size, {
			"Size", "ceph.msg.mon_paxos.latest_val.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_value, {
			"Proposal", "ceph.msg.mon_paxos.value",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_ver, {
			"Version", "ceph.msg.mon_paxos.ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_val, {
			"Value", "ceph.msg.mon_paxos.val",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_val_data, {
			"Data", "ceph.msg.mon_paxos.val.data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_paxos_val_size, {
			"Size", "ceph.msg.mon_paxos.val.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe, {
			"Monitor Probe", "ceph.msg.mon_probe",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe_fsid, {
			"FSID", "ceph.msg.mon_probe.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe_type, {
			"Type", "ceph.msg.mon_probe.type",
			FT_INT32, BASE_DEC|BASE_EXT_STRING, &c_mon_probe_type_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe_name, {
			"Name", "ceph.msg.mon_probe.name",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe_quorum, {
			"Quorum", "ceph.msg.mon_probe.quorum",
			FT_INT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe_paxos_first_ver, {
			"Paxos First Version", "ceph.msg.mon_probe.paxos_first_ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe_paxos_last_ver, {
			"Paxos Last Version", "ceph.msg.mon_probe.paxos_last_ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe_ever_joined, {
			"Has Ever Joined?", "ceph.msg.mon_probe.has_ever_joined",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_mon_probe_req_features, {
			"Required Features", "ceph.msg.mon_probe.required_features",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_ping, {
			"OSD Ping", "ceph.msg.osd.ping",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_ping_fsid, {
			"FSID", "ceph.msg.osd.ping.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_ping_mapepoch, {
			"OSD Map Epoch", "ceph.msg.osd.ping.mapepoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_ping_peerepoch, {
			"Peer as of Epoch", "ceph.msg.osd.ping.peerepoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_ping_op, {
			"Operation", "ceph.msg.osd.ping.op",
			FT_UINT8, BASE_HEX|BASE_EXT_STRING, &c_osd_ping_op_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_ping_time, {
			"Timestamp", "ceph.msg.osd.ping.time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_boot, {
			"OSD Boot", "ceph.msg.osd_boot",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_boot_addr_back, {
			"Back Address", "ceph.msg.osd_boot.addr.back",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_boot_addr_cluster, {
			"Cluster Address", "ceph.msg.osd_boot.addr.cluster",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_boot_epoch, {
			"Boot Epoch", "ceph.msg.osd_boot.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_boot_addr_front, {
			"Front Address", "ceph.msg.osd_boot.addr.front",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_boot_metadata, {
			"Metadata", "ceph.msg.osd_boot.metadata",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_boot_metadata_k, {
			"Key", "ceph.msg.osd_boot.metadata.k",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_boot_metadata_v, {
			"Value", "ceph.msg.osd_boot.metadata.v",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_pgstats, {
			"Placement Group Stats", "ceph.msg.pgstats",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_pgstats_fsid, {
			"FSID", "ceph.msg.pgstats.fsid",
			FT_GUID, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_pgstats_pgstat, {
			"PG Stats", "ceph.msg.pgstats.pgstat",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_pgstats_pgstat_pg, {
			"Placement Group", "ceph.msg.pgstats.pgstat.pg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_pgstats_pgstat_stat, {
			"Stats", "ceph.msg.pgstats.pgstat.stat",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_pgstats_epoch, {
			"Epoch", "ceph.msg.pgstats.epoch",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_pgstats_mapfor, {
			"Has Map For", "ceph.msg.pgstats.mapfor",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_pg_create, {
			"PG Create", "ceph.msg.osd.pg.create",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_pg_create_epoch, {
			"Epoch", "ceph.msg.osd.pg.create.epoch",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_pg_create_mkpg, {
			"Creation Request", "ceph.msg.osd.pg.create.mkpg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_pg_create_mkpg_pg, {
			"PG", "ceph.msg.osd.pg.create.mkpg.pg",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_osd_pg_create_mkpg_create, {
			"Creation Options", "ceph.msg.osd.pg.create.mkpg.create",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps, {
			"Client Caps", "ceph.msg.client_caps",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_op, {
			"Operation", "ceph.msg.client_caps.op",
			FT_UINT32, BASE_HEX|BASE_EXT_STRING, &c_cap_op_type_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_inode, {
			"Inode", "ceph.msg.client_caps.inode",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_relam, {
			"Relam", "ceph.msg.client_caps.relam",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_cap_id, {
			"Cap ID", "ceph.msg.client_caps.cap_id",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_seq, {
			"Sequence", "ceph.msg.client_caps.seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_seq_issue, {
			"Issue Sequence", "ceph.msg.client_caps.seq_issue",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_new, {
			"New Capabilities", "ceph.msg.client_caps.new",
			FT_UINT32, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_wanted, {
			"Wanted Capabilities", "ceph.msg.client_caps.wanted",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_dirty, {
			"Dirty Capabilities", "ceph.msg.client_caps.dirty",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_seq_migrate, {
			"Migrate Sequence", "ceph.msg.client_caps_seq.migrate",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_snap_follows, {
			"Snapshot Follows", "ceph.msg.client_caps.snap_follows",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_uid, {
			"User ID", "ceph.msg.client_caps.uid",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_gid, {
			"Group ID", "ceph.msg.client_caps.gid",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_mode, {
			"Mode", "ceph.msg.client_caps.mode",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_nlink, {
			"Number of Links", "ceph.msg.client_caps.nlink",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_xattr_ver, {
			"Xattr Version", "ceph.msg.client_caps.xattr_ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_snap, {
			"Snapshot Data", "ceph.msg.client_caps.snap",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_flock, {
			"Flock", "ceph.msg.client_caps.flock",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_inline_ver, {
			"Inline Version", "ceph.msg.client_caps.inline_ver",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_inline_data, {
			"Inline Data", "ceph.msg.client_caps.inline_data",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caps_xattr, {
			"Xattr", "ceph.msg.client_caps.xattr",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caprel, {
			"Capability Release", "ceph.msg.client_caprel",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caprel_cap, {
			"Capability", "ceph.msg.client_caprel.cap",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caprel_cap_inode, {
			"Inode", "ceph.msg.client_caprel.cap.inode",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caprel_cap_id, {
			"Capability ID", "ceph.msg.client_caprel.cap.id",
			FT_UINT64, BASE_HEX, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caprel_cap_migrate, {
			"Migrate Sequence", "ceph.msg.client_caprel_cap.migrate",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_client_caprel_cap_seq, {
			"Sequence", "ceph.msg.client_caprel_cap.seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck, {
			"Timecheck", "ceph.msg.timecheck",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_op, {
			"Operation", "ceph.msg.timecheck.op",
			FT_UINT32, BASE_HEX|BASE_EXT_STRING, &c_timecheck_op_strings_ext, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_epoch, {
			"Epoch", "ceph.msg.timecheck.epoch",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_round, {
			"Round", "ceph.msg.timecheck.round",
			FT_UINT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_time, {
			"Time", "ceph.msg.timecheck.time",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_skew, {
			"Skew", "ceph.msg.timecheck.skew",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_skew_node, {
			"Node", "ceph.msg.timecheck.skew.node",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_skew_skew, {
			"Skew", "ceph.msg.timecheck.skew.skew",
			FT_DOUBLE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_latency, {
			"Latency", "ceph.msg.timecheck.latency",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_latency_node, {
			"Node", "ceph.msg.timecheck.latency.node",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
		{ &hf_msg_timecheck_latency_latency, {
			"Latency", "ceph.msg.timecheck.latency.latency",
			FT_DOUBLE, BASE_NONE, NULL, 0,
			NULL, HFILL
		} },
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ceph,
		&ett_data,
		&ett_str,
		&ett_blob,
		&ett_sockaddr,
		&ett_entityaddr,
		&ett_entityname,
		&ett_EntityName,
		&ett_entityinst,
		&ett_kv,
		&ett_eversion,
		&ett_objectlocator,
		&ett_pg,
		&ett_pg_create,
		&ett_filepath,
		&ett_mds_release,
		&ett_hitset_params,
		&ett_snapinfo,
		&ett_pgpool,
		&ett_pgpool_snap,
		&ett_pgpool_snapdel,
		&ett_pgpool_property,
		&ett_mon_map,
		&ett_mon_map_address,
		&ett_osd_peerstat,
		&ett_featureset,
		&ett_featureset_name,
		&ett_compatset,
		&ett_osd_superblock,
		&ett_osd_info,
		&ett_osd_xinfo,
		&ett_perfstat,
		&ett_osdstat,
		&ett_pg_stat,
		&ett_osd_map,
		&ett_osd_map_client,
		&ett_osd_map_pool,
		&ett_osd_map_poolname,
		&ett_osd_map_pgtmp,
		&ett_osd_map_primarytmp,
		&ett_osd_map_erasurecodeprofile,
		&ett_osd_map_osd,
		&ett_osd_map_blacklist,
		&ett_osd_map_inc,
		&ett_osd_map_inc_client,
		&ett_osd_map_inc_osd,
		&ett_osd_op,
		&ett_redirect,
		&ett_statcollection,
		&ett_paxos,
		&ett_msg_mon_map,
		&ett_msg_statfs,
		&ett_msg_statfsreply,
		&ett_msg_mon_sub,
		&ett_msg_mon_sub_item,
		&ett_msg_mon_sub_flags,
		&ett_msg_mon_sub_ack,
		&ett_msg_auth,
		&ett_msg_auth_supportedproto,
		&ett_msg_auth_cephx,
		&ett_msg_authreply,
		&ett_msg_mon_getversion,
		&ett_msg_mon_getversionreply,
		&ett_msg_mds_map,
		&ett_msg_client_sess,
		&ett_msg_client_req,
		&ett_msg_client_reqfwd,
		&ett_msg_client_reply,
		&ett_msg_osd_map,
		&ett_msg_osd_map_inc,
		&ett_msg_osd_map_full,
		&ett_msg_osd_op,
		&ett_msg_osd_opreply,
		&ett_msg_poolopreply,
		&ett_msg_poolop,
		&ett_msg_mon_cmd,
		&ett_msg_mon_cmd_arg,
		&ett_msg_mon_cmdack,
		&ett_msg_mon_cmdack_arg,
		&ett_msg_poolstats,
		&ett_msg_poolstatsreply,
		&ett_msg_poolstatsreply_stat,
		&ett_msg_mon_election,
		&ett_msg_mon_paxos,
		&ett_msg_mon_paxos_value,
		&ett_msg_mon_probe,
		&ett_msg_osd_ping,
		&ett_msg_osd_boot,
		&ett_msg_pgstats,
		&ett_msg_pgstats_pgstat,
		&ett_msg_osd_pg_create,
		&ett_msg_osd_pg_create_mkpg,
		&ett_msg_client_caps,
		&ett_msg_client_caprel,
		&ett_msg_client_caprel_cap,
		&ett_msg_timecheck,
		&ett_msg_timecheck_skew,
		&ett_msg_timecheck_latency,
		&ett_head,
		&ett_foot,
		&ett_connect,
		&ett_connect_reply,
		&ett_filter_data,
	};

	/* Expert info items. */
	static ei_register_info ei[] = {
		{ &ei_unused, {
			"ceph.unused", PI_UNDECODED, PI_WARN,
			"Unused data in message.  This usually indicates an error by the "
			"sender or a bug in the dissector.", EXPFILL
		} },
		{ &ei_overrun, {
			"ceph.overrun", PI_UNDECODED, PI_WARN,
			"There was less data then expected.  This usually indicates an "
			"error by the sender or a bug in the dissector.", EXPFILL
		} },
		{ &ei_tag_unknown, {
			"ceph.tag_unknown", PI_UNDECODED, PI_ERROR,
			"Unknown tag.  This is either an error by the sender or an "
			"indication that the dissector is out of date.", EXPFILL
		} },
		{ &ei_msg_unknown, {
			"ceph.msg_unknown", PI_UNDECODED, PI_WARN,
			"Unknown message type. This most likely means that the dissector "
			"is out of date.  However it could also be an error by the "
			"sender ", EXPFILL
		} },
		{ &ei_union_unknown, {
			"ceph.union_unknown", PI_UNDECODED, PI_WARN,
			"This data's meaning depends on other information in the message "
			"but the dissector doesn't know what type it is.", EXPFILL
		} },
		{ &ei_ver_tooold, {
			"ceph.ver.tooold", PI_UNDECODED, PI_WARN,
			"This data is in an older format that is not supported by the "
			"dissector.", EXPFILL
		} },
		{ &ei_ver_toonew, {
			"ceph.ver.toonew", PI_UNDECODED, PI_WARN,
			"This data is in a newer format that is not supported by the "
			"dissector.", EXPFILL
		} },
		{ &ei_oloc_both, {
			"ceph.oloc.both", PI_MALFORMED, PI_ERROR,
			"Only one of the key or hash should be present, however both are.",
			EXPFILL
		} },
#if 0
		{ &ei_banner_invalid, {
			"ceph.banner.invalid", PI_MALFORMED, PI_ERROR,
			"Banner was invalid.", EXPFILL
		} },
#endif
		{ &ei_sizeillogical, {
			"ceph.sizeillogical", PI_MALFORMED, PI_ERROR,
			"The claimed size is impossible.", EXPFILL
		} },
	};

	/* Register the protocol name and description */
	proto_ceph = proto_register_protocol("Ceph", "Ceph", "ceph");

	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_ceph, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_ceph = expert_register_protocol(proto_ceph);
	expert_register_field_array(expert_ceph, ei, array_length(ei));
}

void
proto_reg_handoff_ceph(void)
{
	ceph_handle = create_dissector_handle(dissect_ceph_old, proto_ceph);

	heur_dissector_add("tcp", dissect_ceph_heur, "Ceph over TCP", "ceph_tcp", proto_ceph, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -	http://www.wireshark.org/tools/modelines.html
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
