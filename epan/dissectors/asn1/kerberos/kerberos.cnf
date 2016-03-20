# kerberos.cnf
# kerberos conformation file
# Copyright 2008 Anders Broman

#.EXPORTS
ChangePasswdData
Applications ONLY_ENUM

#.FIELD_RENAME
#EncryptedData/etype encryptedData_etype
KDC-REQ-BODY/etype kDC-REQ-BODY_etype
KRB-SAFE-BODY/user-data kRB-SAFE-BODY_user_data
EncKrbPrivPart/user-data encKrbPrivPart_user_data
EncryptedTicketData/cipher encryptedTicketData_cipher
EncryptedAuthorizationData/cipher encryptedAuthorizationData_cipher
EncryptedKDCREPData/cipher encryptedKDCREPData_cipher
PA-ENC-TIMESTAMP/cipher pA-ENC-TIMESTAMP_cipher
EncryptedAPREPData/cipher encryptedAPREPData_cipher
EncryptedKrbPrivData/cipher encryptedKrbPrivData_cipher
EncryptedKrbCredData/cipher encryptedKrbCredData_cipher
KRB-CRED/_untag/enc-part kRB_CRED_enc_part
KRB-PRIV/_untag/enc-part kRB_PRIV_enc_part
AP-REP/_untag/enc-part aP_REP_enc_part
KDC-REP/enc-part kDC_REP_enc_part
Ticket/_untag/enc-part ticket_enc_part

#.OMIT_ASSIGNMENT
AD-AND-OR
AD-KDCIssued
AD-LoginAlias
AD-MANDATORY-FOR-KDC
AUTHDATA-TYPE
ChangePasswdDataMS
EncryptedData
EtypeList
KerberosFlags
KRB5SignedPath
KRB5SignedPathData
KRB5SignedPathPrincipals
Krb5int32
Krb5uint32
PA-ClientCanonicalized
PA-ClientCanonicalizedNames
PA-ENC-TS-ENC
PA-ENC-SAM-RESPONSE-ENC
PA-PAC-REQUEST
PA-SAM-CHALLENGE-2
PA-SAM-CHALLENGE-2-BODY
PA-SAM-REDIRECT
PA-SAM-RESPONSE-2
PA-SAM-TYPE
PA-SERVER-REFERRAL-DATA
PA-ServerReferralData
PA-SvrReferralData
Principal
PROV-SRV-LOCATION
SAMFlags
TYPED-DATA

#.NO_EMIT ONLY_VALS
Applications

#.MAKE_DEFINES
ADDR-TYPE TYPE_PREFIX
Applications TYPE_PREFIX

#.FN_BODY MESSAGE-TYPE VAL_PTR = &msgtype
guint32 msgtype;

%(DEFAULT_BODY)s

#.FN_FTR MESSAGE-TYPE
	if (gbl_do_col_info) {
		col_add_str(actx->pinfo->cinfo, COL_INFO,
			val_to_str(msgtype, krb5_msg_types,
			"Unknown msg type %#x"));
	}
	gbl_do_col_info=FALSE;

##if 0
	/* append the application type to the tree */
	proto_item_append_text(tree, " %s", val_to_str(msgtype, krb5_msg_types, "Unknown:0x%x"));
##endif

#.FN_BODY ERROR-CODE VAL_PTR = &krb5_errorcode
%(DEFAULT_BODY)s

#.FN_FTR ERROR-CODE
	if(krb5_errorcode) {
		col_add_fstr(actx->pinfo->cinfo, COL_INFO,
			"KRB Error: %s",
			val_to_str(krb5_errorcode, krb5_error_codes,
			"Unknown error code %#x"));
	}

	return offset;
#.END
#.FN_BODY KRB-ERROR/_untag/e-data
	switch(krb5_errorcode){
	case KRB5_ET_KRB5KDC_ERR_BADOPTION:
	case KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED:
	case KRB5_ET_KRB5KDC_ERR_KEY_EXP:
	case KRB5_ET_KRB5KDC_ERR_POLICY:
		/* ms windows kdc sends e-data of this type containing a "salt"
		 * that contains the nt_status code for these error codes.
		 */
		offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, dissect_kerberos_PA_DATA);
		break;
	case KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED:
	case KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED:
	case KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, dissect_kerberos_SEQUENCE_OF_PA_DATA);

		break;
	default:
		offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, NULL);
	}


#.FN_BODY PADATA-TYPE VAL_PTR=&(private_data->padata_type)
	kerberos_private_data_t* private_data = kerberos_get_private_data(actx);
%(DEFAULT_BODY)s
#.FN_FTR PADATA-TYPE
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(private_data->padata_type, krb5_preauthentication_types,
			"Unknown:%d"));
	}

#.FN_BODY PA-DATA/padata-value
	proto_tree *sub_tree=tree;
	kerberos_private_data_t* private_data = kerberos_get_private_data(actx);

	if(actx->created_item){
		sub_tree=proto_item_add_subtree(actx->created_item, ett_kerberos_PA_DATA);
	}

	switch(private_data->padata_type){
	case KRB5_PA_TGS_REQ:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_Applications);
 		break;
	case KRB5_PA_PK_AS_REQ:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_pkinit_PaPkAsReq);
 		break;
 	case KRB5_PA_PK_AS_REP:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_pkinit_PaPkAsRep);
 		break;
	case KRB5_PA_PAC_REQUEST:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_KERB_PA_PAC_REQUEST);
		break;
	case KRB5_PA_S4U2SELF:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_S4U2Self);
 		break;
	case KRB5_PA_PROV_SRV_LOCATION:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_krb5_PA_PROV_SRV_LOCATION);
 		break;
	case KRB5_PA_ENC_TIMESTAMP:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_ENC_TIMESTAMP);
 		break;
	case KRB5_PA_ENCTYPE_INFO:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_ETYPE_INFO);
 		break;
	case KRB5_PA_ENCTYPE_INFO2:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_ETYPE_INFO2);
 		break;
	case KRB5_PA_PW_SALT:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_krb5_PW_SALT);
 		break;
	default:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, NULL);
	}

#.FN_BODY HostAddress/address
	gint8 appclass;
	gboolean pc;
	gint32 tag;
	guint32 len;
	const char *address_str;
	proto_item *it=NULL;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	/* read header and len for the octet string */
	offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &appclass, &pc, &tag);
	offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);

	switch(private_data->addr_type){
	case KERBEROS_ADDR_TYPE_IPV4:
		it=proto_tree_add_item(tree, hf_krb_address_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
		address_str = tvb_ip_to_str(tvb, offset);
		break;
	case KERBEROS_ADDR_TYPE_NETBIOS:
		{
		char netbios_name[(NETBIOS_NAME_LEN - 1)*4 + 1];
		int netbios_name_type;
		int netbios_name_len = (NETBIOS_NAME_LEN - 1)*4 + 1;

		netbios_name_type = process_netbios_name(tvb_get_ptr(tvb, offset, 16), netbios_name, netbios_name_len);
		address_str = wmem_strdup_printf(wmem_packet_scope(), "%s<%02x>", netbios_name, netbios_name_type);
		it=proto_tree_add_string_format(tree, hf_krb_address_netbios, tvb, offset, 16, netbios_name, "NetBIOS Name: %s (%s)", address_str, netbios_name_type_descr(netbios_name_type));
		}
		break;
	case KERBEROS_ADDR_TYPE_IPV6:
		it=proto_tree_add_item(tree, hf_krb_address_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
		address_str = tvb_ip6_to_str(tvb, offset);
		break;
	default:
		proto_tree_add_expert(tree, actx->pinfo, &ei_kerberos_address, tvb, offset, len);
		address_str = NULL;
	}

	/* push it up two levels in the decode pane */
	if(it && address_str){
		proto_item_append_text(proto_item_get_parent(it), " %s",address_str);
		proto_item_append_text(proto_item_get_parent_nth(it, 2), " %s",address_str);
	}

	offset+=len;
	return offset;


#.TYPE_ATTR
#xxx TYPE = FT_UINT16  DISPLAY = BASE_DEC  STRINGS = VALS(xx_vals)

#.FN_BODY ENCTYPE VAL_PTR=&(private_data->etype)
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
%(DEFAULT_BODY)s

#.FN_BODY EncryptedTicketData/cipher
##ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_ticket_data);
##else
%(DEFAULT_BODY)s
##endif
	return offset;

#.FN_BODY EncryptedAuthorizationData/cipher
##ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_authenticator_data);
##else
%(DEFAULT_BODY)s
##endif
	return offset;

#.FN_BODY EncryptedKDCREPData/cipher
##ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_KDC_REP_data);
##else
%(DEFAULT_BODY)s
##endif
	return offset;

#.FN_BODY PA-ENC-TIMESTAMP/cipher
##ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_PA_ENC_TIMESTAMP);
##else
%(DEFAULT_BODY)s
##endif
	return offset;

#.FN_BODY EncryptedAPREPData/cipher
##ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_AP_REP_data);
##else
%(DEFAULT_BODY)s
##endif
	return offset;

#.FN_BODY EncryptedKrbPrivData/cipher
##ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_PRIV_data);
##else
%(DEFAULT_BODY)s
##endif
	return offset;

#.FN_BODY EncryptedKrbCredData/cipher
##ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_CRED_data);
##else
%(DEFAULT_BODY)s
##endif
	return offset;


#.FN_BODY CKSUMTYPE VAL_PTR=&(private_data->checksum_type)
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
%(DEFAULT_BODY)s

#.FN_BODY Checksum/checksum
	tvbuff_t *next_tvb;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	switch(private_data->checksum_type){
	case KRB5_CHKSUM_GSSAPI:
		offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &next_tvb);
		dissect_krb5_rfc1964_checksum(actx, tree, next_tvb);
		break;
	default:
		offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, NULL);
	}
	return offset;

#.FN_BODY EncryptionKey/keytype VAL_PTR=&gbl_keytype
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
									&gbl_keytype);
	private_data->key.keytype = gbl_keytype;

#.FN_BODY EncryptionKey/keyvalue VAL_PTR=&out_tvb
	tvbuff_t *out_tvb;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

%(DEFAULT_BODY)s

	private_data->key.keylength = tvb_reported_length(out_tvb);
	private_data->key.keyvalue = tvb_get_ptr(out_tvb, 0, private_data->key.keylength);

#.FN_BODY EncryptionKey
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	%(DEFAULT_BODY)s

	if (private_data->key.keytype != 0) {
##ifdef HAVE_KERBEROS
		add_encryption_key(actx->pinfo, private_data->key.keytype, private_data->key.keylength, private_data->key.keyvalue, "key");
##endif
	}

#.FN_BODY AuthorizationData/_item/ad-type
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
									&(private_data->ad_type));
#.TYPE_ATTR
AuthorizationData/_item/ad-type STRINGS=VALS(krb5_ad_types)

#.FN_BODY AuthorizationData/_item/ad-data
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	switch(private_data->ad_type){
	case KRB5_AD_WIN2K_PAC:
		offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_krb5_AD_WIN2K_PAC);
		break;
	case KRB5_AD_IF_RELEVANT:
		offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_AD_IF_RELEVANT);
		break;
	default:
		offset=dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);
	}

#.FN_BODY ADDR-TYPE VAL_PTR=&(private_data->addr_type)
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
%(DEFAULT_BODY)s

#.FN_BODY KDC-REQ-BODY
	conversation_t *conversation;

	/*
	 * UDP replies to KDC_REQs are sent from the server back to the client's
	 * source port, similar to the way TFTP works.  Set up a conversation
	 * accordingly.
	 *
	 * Ref: Section 7.2.1 of
	 * http://www.ietf.org/internet-drafts/draft-ietf-krb-wg-kerberos-clarifications-07.txt
	 */
	if (actx->pinfo->destport == UDP_PORT_KERBEROS && actx->pinfo->ptype == PT_UDP) {
		conversation = find_conversation(actx->pinfo->num, &actx->pinfo->src, &actx->pinfo->dst, PT_UDP,
											actx->pinfo->srcport, 0, NO_PORT_B);
		if (conversation == NULL) {
			conversation = conversation_new(actx->pinfo->num, &actx->pinfo->src, &actx->pinfo->dst, PT_UDP,
											actx->pinfo->srcport, 0, NO_PORT2);
			conversation_set_dissector(conversation, kerberos_handle_udp);
		}
	}

	%(DEFAULT_BODY)s

#.FN_BODY KRB-SAFE-BODY/user-data
	tvbuff_t *new_tvb;
	offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &new_tvb);
	if (new_tvb) {
		call_kerberos_callbacks(actx->pinfo, tree, new_tvb, KRB_CBTAG_SAFE_USER_DATA, (kerberos_callbacks*)actx->private_data);
	}

#.FN_BODY EncKrbPrivPart/user-data
	tvbuff_t *new_tvb;
	offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &new_tvb);
	if (new_tvb) {
		call_kerberos_callbacks(actx->pinfo, tree, new_tvb, KRB_CBTAG_PRIV_USER_DATA, (kerberos_callbacks*)actx->private_data);
	}
