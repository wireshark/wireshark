# x509.cnf
# X509 conformation file

#.IMPORT ../x509ce/x509ce-exp.cnf
#.IMPORT ../x509if/x509if-exp.cnf
#.IMPORT ../x509sat/x509sat-exp.cnf

#.MODULE_EXPORTS
EXTENSION
ACPathData
AlgorithmIdentifier
AttCertValidityPeriod
AttributeCertificate
AttributeCertificateAssertion
AttributeCertificateInfo
AttributeCertificationPath
Certificate
Certificate_PDU
Certificates
CertificateList
CertificatePair
CertificateSerialNumber
CertificationPath
CrossCertificates
Extension
Extensions
ForwardCertificationPath
IssuerSerial
SubjectPublicKeyInfo
Time
Validity
Version

#.PDU

#.REGISTER
Certificate				B "2.5.4.36" "id-at-userCertificate"
Certificate				B "2.5.4.37" "id-at-cAcertificate"
CertificateList			B "2.5.4.38" "id-at-authorityRevocationList"
CertificateList			B "2.5.4.39" "id-at-certificateRevocationList"
CertificatePair			B "2.5.4.40" "id-at-crossCertificatePair"
CertificateList			B "2.5.4.53" "id-at-deltaRevocationList"
AttributeCertificate	B "2.5.4.58" "id-at-attributeCertificate"
CertificateList			B "2.5.4.59" "id-at-attributeCertificateRevocationList"

DSS-Params				B "1.2.840.10040.4.1" "id-dsa"

#.TYPE_RENAME
AttributeCertificateInfo/subject	InfoSubject
AttributeCertificateAssertion/subject	AssertionSubject

#.FIELD_RENAME
AttributeCertificateInfo/issuer		issuerName
AttributeCertificateInfo/subject info_subject
AttributeCertificateAssertion/subject assertion_subject

AttributeCertificateAssertion/issuer assertionIssuer

AttributeCertificateInfo/subject/subjectName      infoSubjectName
AttributeCertificateAssertion/subject/subjectName assertionSubjectName
IssuerSerial/issuer			issuerName
CertificateList/signedCertificateList/revokedCertificates/_item/userCertificate		revokedUserCertificate
#.END

#.FN_PARS AlgorithmIdentifier/algorithmId
  FN_VARIANT = _str  HF_INDEX = hf_x509af_algorithm_id  VAL_PTR = &actx->external.direct_reference

#.FN_BODY AlgorithmIdentifier/algorithmId
  const char *name;

  %(DEFAULT_BODY)s

  if (algorithm_id) {
    wmem_free(wmem_file_scope(), (void*)algorithm_id);
  }

  if(actx->external.direct_reference) {
    algorithm_id = (const char *)wmem_strdup(wmem_file_scope(), actx->external.direct_reference);

    name = oid_resolved_from_string(wmem_packet_scope(), actx->external.direct_reference);

    proto_item_append_text(tree, " (%%s)", name ? name : actx->external.direct_reference);
  } else {
    algorithm_id = NULL;
  }

#.FN_BODY AlgorithmIdentifier/parameters
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);

#.FN_HDR SubjectPublicKeyInfo
  int orig_offset = offset;
#.FN_FTR SubjectPublicKeyInfo
  x509af_export_publickey(tvb, actx, orig_offset, offset - orig_offset);
#.END

#.FN_BODY SubjectPublicKeyInfo/subjectPublicKey
  tvbuff_t *bs_tvb = NULL;
# proto_tree *subtree;

  dissect_ber_bitstring(FALSE, actx, NULL, tvb, offset,
                        NULL, -1, -1, &bs_tvb);

  /* See RFC 3279 for possible subjectPublicKey values given an Algorithm ID.
   * The contents of subjectPublicKey are always explicitly tagged. */
  if (bs_tvb && !g_strcmp0(algorithm_id, "1.2.840.113549.1.1.1")) { /* id-rsa */
    offset += dissect_pkcs1_RSAPublicKey(FALSE, bs_tvb, 0, actx, tree, hf_index);

# TODO: PKCS#1 only defines RSA; DH and DSA are from PKIX1Algorithms2008
# } else if (bs_tvb && !g_strcmp0(algorithm_id, "1.2.840.10040.4.1")) { /* id-dsa */
#   subtree = proto_item_add_subtree(actx->created_item, ett_subjectpublickey);
#   offset += dissect_DSAPublicKey(FALSE, bs_tvb, 0, actx, subtree, hf_dsa_y);
#
# } else if (bs_tvb && !g_strcmp0(algorithm_id, "1.2.840.10046.2.1")) { /* dhpublicnumber */
#   subtree = proto_item_add_subtree(actx->created_item, ett_subjectpublickey);
#   offset += dissect_DHPublicKey(FALSE, bs_tvb, 0, actx, subtree, hf_dh_y);
#
  } else {
    offset = dissect_ber_bitstring(FALSE, actx, tree, tvb, offset,
                                   NULL, hf_index, -1, NULL);
  }

#.FN_PARS Extension/extnId
  FN_VARIANT = _str  HF_INDEX = hf_x509af_extension_id  VAL_PTR = &actx->external.direct_reference

#.FN_BODY Extension/extnId
  const char *name;

  %(DEFAULT_BODY)s

  if(actx->external.direct_reference) {
    name = oid_resolved_from_string(wmem_packet_scope(), actx->external.direct_reference);

    proto_item_append_text(tree, " (%%s)", name ? name : actx->external.direct_reference);
  }

#.FN_BODY Extension/extnValue
  gint8 ber_class;
  gboolean pc, ind;
  gint32 tag;
  guint32 len;
  /* skip past the T and L  */
  offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
  offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);

#.FN_BODY SubjectName

  const char* str;
  %(DEFAULT_BODY)s

  str = x509if_get_last_dn();
  proto_item_append_text(proto_item_get_parent(tree), " (%%s)", str?str:"");

#.TYPE_ATTR
CertificateSerialNumber TYPE = FT_INT64
DSS-Params/p TYPE = FT_BYTES  DISPLAY = BASE_NONE
DSS-Params/q TYPE = FT_BYTES  DISPLAY = BASE_NONE
DSS-Params/g TYPE = FT_BYTES  DISPLAY = BASE_NONE

#.FN_PARS CertificateSerialNumber FN_VARIANT = 64

#.END
