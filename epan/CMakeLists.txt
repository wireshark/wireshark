# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

include(UseABICheck)

if (HAVE_HFI_SECTION_INIT)
	add_definitions(
		-DHAVE_HFI_SECTION_INIT
	)
endif()


if (HAVE_LIBLUA)
	include( wslua/CMakeLists.txt )
endif()
source_group(wslua FILES ${WSLUA_FILES})

add_subdirectory( dissectors/dcerpc )

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/dfilter
	${CMAKE_CURRENT_SOURCE_DIR}/dissectors
	${CMAKE_CURRENT_SOURCE_DIR}/ftypes
	${CMAKE_CURRENT_SOURCE_DIR}/wslua
)

set(CRYPT_FILES
	crypt/airpdcap.c
	crypt/airpdcap_ccmp.c
	crypt/airpdcap_debug.c
	crypt/airpdcap_rijndael.c
	crypt/airpdcap_tkip.c
)
source_group(crypt FILES ${CRYPT_FILES})

set(DFILTER_FILES
	dfilter/dfilter.c
	dfilter/dfilter-macro.c
	dfilter/dfunctions.c
	dfilter/dfvm.c
	dfilter/drange.c
	dfilter/gencode.c
	dfilter/semcheck.c
	dfilter/sttype-function.c
	dfilter/sttype-integer.c
	dfilter/sttype-pointer.c
	dfilter/sttype-range.c
	dfilter/sttype-string.c
	dfilter/sttype-test.c
	dfilter/syntax-tree.c
)
source_group(dfilter FILES ${DFILTER_FILES})

set(DFILTER_CLEAN_FILES
	${DFILTER_FILES}
)

add_lex_files(DFILTER_FILES
	dfilter/scanner.l
)

add_lemon_files(DFILTER_FILES
	dfilter/grammar.lemon
)

if (AUTOGEN_pidl)
    # TODO
endif()

if (AUTOGEN_dcerpc)
  FOREACH(PROTOCOL_NAME ${PIDL_DISSECTOR_AUTOGEN_NAMES})
    set(PIDL_DISSECTOR_AUTOGEN_SRC
	${PIDL_DISSECTOR_AUTOGEN_SRC}
	dissectors/dcerpc/${PROTOCOL_NAME}/packet-dcerpc-${PROTOCOL_NAME}.c
    )
  ENDFOREACH()

  FOREACH(PROTOCOL_NAME ${PIDL_DISSECTOR_AUTOGEN_NAMES})
    SET(CUR_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dissectors/dcerpc/${PROTOCOL_NAME})
    SET(CUR_PROTO_C_FILE packet-dcerpc-${PROTOCOL_NAME}.c)
    SET(CUR_PROTO_H_FILE packet-dcerpc-${PROTOCOL_NAME}.h)
    ADD_CUSTOM_COMMAND(
	OUTPUT
	  ${CUR_PROTO_DIR}/${CUR_PROTO_C_FILE}
	  ${CUR_PROTO_DIR}/${CUR_PROTO_H_FILE}
	COMMAND
	  idl2wrs ${PROTOCOL_NAME}
	COMMAND
	  ${CMAKE_COMMAND} -E copy_if_different ${CUR_PROTO_DIR}/${CUR_PROTO_C_FILE} ${CMAKE_CURRENT_SOURCE_DIR}/dissectors/${CUR_PROTO_C_FILE}
	COMMAND
	  ${CMAKE_COMMAND} -E copy_if_different ${CUR_PROTO_DIR}/${CUR_PROTO_H_FILE} ${CMAKE_CURRENT_SOURCE_DIR}/dissectors/${CUR_PROTO_H_FILE}
	WORKING_DIRECTORY
	  ${CUR_PROTO_DIR}
	DEPENDS
	  ${CUR_PROTO_DIR}/${PROTOCOL_NAME}.idl
	  ${CUR_PROTO_DIR}/${PROTOCOL_NAME}.cnf
	  ${CUR_PROTO_DIR}/packet-dcerpc-${PROTOCOL_NAME}-template.c
	  ${CUR_PROTO_DIR}/packet-dcerpc-${PROTOCOL_NAME}-template.h
    )
  ENDFOREACH()
else()
  FOREACH(PROTOCOL_NAME ${PIDL_DISSECTOR_AUTOGEN_NAMES})
    set(PIDL_DISSECTOR_AUTOGEN_SRC
	${PIDL_DISSECTOR_AUTOGEN_SRC}
	dissectors/packet-dcerpc-${PROTOCOL_NAME}.c
    )
  ENDFOREACH()
endif()

ADD_CUSTOM_COMMAND(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/packet-ncp2222.c
    COMMAND ${PYTHON_EXECUTABLE}
      ${CMAKE_SOURCE_DIR}/tools/ncp2222.py
      -o ${CMAKE_CURRENT_BINARY_DIR}/packet-ncp2222.c
    DEPENDS
      dissectors/packet-ncp2222.inc
      ${CMAKE_SOURCE_DIR}/tools/ncp2222.py
)

ADD_CUSTOM_COMMAND(
    OUTPUT
       x11-dissector
#      x11-declarations.h
#      x11-enum.h
#      x11-extension-errors.h
#      x11-extension-implementation.h
#      x11-fields
#      x11-glx-render-enum.h
#      x11-register-info.h
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_SOURCE_DIR}/tools/process-x11-fields.pl
      <dissectors/x11-fields
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_SOURCE_DIR}/tools/process-x11-xcb.pl
    DEPENDS
      dissectors/x11-fields
      ${CMAKE_SOURCE_DIR}/tools/process-x11-fields.pl
      ${CMAKE_SOURCE_DIR}/tools/process-x11-xcb.pl
)

# Note that some dissectors are added in dissectors/dcerpc/CMakeLists.txt
set(PIDL_DISSECTOR_SRC
	dissectors/packet-dcerpc-atsvc.c
#	dissectors/packet-dcerpc-budb.c
#	dissectors/packet-dcerpc-butc.c
#	dissectors/packet-dcerpc-drsuapi.c
	dissectors/packet-dcerpc-dssetup.c
	dissectors/packet-dcerpc-efs.c
	dissectors/packet-dcerpc-frstrans.c
	dissectors/packet-dcerpc-initshutdown.c
	dissectors/packet-dcerpc-nspi.c
	dissectors/packet-dcerpc-rfr.c
	dissectors/packet-dcerpc-srvsvc.c
	dissectors/packet-dcerpc-wkssvc.c
	dissectors/packet-dcerpc-wzcsvc.c
)
set(DIRTY_PIDL_DISSECTOR_SRC
	dissectors/packet-dcerpc-dfs.c
	dissectors/packet-dcerpc-dnsserver.c
	dissectors/packet-dcerpc-eventlog.c
	dissectors/packet-dcerpc-lsa.c
	dissectors/packet-dcerpc-mapi.c
	dissectors/packet-dcerpc-mdssvc.c
	dissectors/packet-dcerpc-misc.c
	dissectors/packet-dcerpc-winreg.c
)
set(ASN1_DISSECTOR_SRC
	dissectors/packet-acp133.c
	dissectors/packet-acse.c
	dissectors/packet-ansi_tcap.c
	dissectors/packet-c1222.c
	dissectors/packet-camel.c
	dissectors/packet-cdt.c
	dissectors/packet-charging_ase.c
	dissectors/packet-cmip.c
	dissectors/packet-cmp.c
	dissectors/packet-cms.c
	dissectors/packet-credssp.c
	dissectors/packet-crmf.c
	dissectors/packet-dap.c
	dissectors/packet-disp.c
	dissectors/packet-dop.c
	dissectors/packet-dsp.c
	dissectors/packet-ess.c
	dissectors/packet-ftam.c
	dissectors/packet-goose.c
	dissectors/packet-HI2Operations.c
	dissectors/packet-h225.c
	dissectors/packet-h235.c
	dissectors/packet-h245.c
	dissectors/packet-h248.c
	dissectors/packet-h282.c
	dissectors/packet-h283.c
	dissectors/packet-h323.c
	dissectors/packet-h450.c
	dissectors/packet-h450-ros.c
	dissectors/packet-h460.c
	dissectors/packet-h501.c
	dissectors/packet-hnbap.c
	dissectors/packet-idmp.c
	dissectors/packet-ilp.c
	dissectors/packet-inap.c
	dissectors/packet-isdn-sup.c
	dissectors/packet-kerberos.c
	dissectors/packet-lcsap.c
	dissectors/packet-logotypecertextn.c
	dissectors/packet-lpp.c
	dissectors/packet-lppa.c
	dissectors/packet-lppe.c
	dissectors/packet-lte-rrc.c
	dissectors/packet-mms.c
	dissectors/packet-mpeg-audio.c
	dissectors/packet-mpeg-pes.c
	dissectors/packet-nbap.c
	dissectors/packet-novell_pkis.c
	dissectors/packet-ns_cert_exts.c
	dissectors/packet-ocsp.c
	dissectors/packet-p22.c
	dissectors/packet-p7.c
	dissectors/packet-p772.c
	dissectors/packet-pcap.c
	dissectors/packet-pkcs1.c
	dissectors/packet-pkinit.c
	dissectors/packet-pkix1explicit.c
	dissectors/packet-pkix1implicit.c
	dissectors/packet-pkixac.c
	dissectors/packet-pkixproxy.c
	dissectors/packet-pkixqualified.c
	dissectors/packet-pkixtsp.c
	dissectors/packet-pktap.c
	dissectors/packet-q932.c
	dissectors/packet-q932-ros.c
	dissectors/packet-qsig.c
	dissectors/packet-ranap.c
	dissectors/packet-ros.c
	dissectors/packet-rrc.c
	dissectors/packet-rrlp.c
	dissectors/packet-rtse.c
	dissectors/packet-rua.c
	dissectors/packet-s1ap.c
	dissectors/packet-sabp.c
	dissectors/packet-sbc-ap.c
	dissectors/packet-smrse.c
	dissectors/packet-spnego.c
	dissectors/packet-sv.c
	dissectors/packet-t38.c
	dissectors/packet-ulp.c
	dissectors/packet-wlancertextn.c
	dissectors/packet-x2ap.c
	dissectors/packet-x509af.c
	dissectors/packet-x509ce.c
	dissectors/packet-x509if.c
	dissectors/packet-x509sat.c
)

set(DIRTY_ASN1_DISSECTOR_SRC
	dissectors/packet-ansi_map.c
	dissectors/packet-coseventcomm.c
	dissectors/packet-cosnaming.c
	dissectors/packet-gprscdr.c
	dissectors/packet-gsm_map.c
	dissectors/packet-ldap.c
	dissectors/packet-m3ap.c
	dissectors/packet-p1.c
	dissectors/packet-parlay.c
	dissectors/packet-pkcs12.c
	dissectors/packet-pres.c
	dissectors/packet-rnsap.c
	dissectors/packet-snmp.c
	dissectors/packet-t124.c
	dissectors/packet-t125.c
	dissectors/packet-tango.c
	dissectors/packet-tcap.c
	dissectors/packet-tetra.c
)

set(DISSECTOR_SRC
	dissectors/file-elf.c
	dissectors/file-file.c
	dissectors/file-gif.c
	dissectors/file-jpeg.c
	dissectors/file-mp4.c
	dissectors/file-png.c
	dissectors/packet-2dparityfec.c
	dissectors/packet-3com-njack.c
	dissectors/packet-3com-xns.c
	dissectors/packet-3g-a11.c
	dissectors/packet-6lowpan.c
	dissectors/packet-9p.c
	dissectors/packet-a21.c
	dissectors/packet-aarp.c
	dissectors/packet-aastra-aasp.c
	dissectors/packet-acap.c
	dissectors/packet-acn.c
	dissectors/packet-acr122.c
	dissectors/packet-actrace.c
	dissectors/packet-adb_cs.c
	dissectors/packet-adwin-config.c
	dissectors/packet-adwin.c
	dissectors/packet-afp.c
	dissectors/packet-afs.c
	dissectors/packet-agentx.c
	dissectors/packet-aim-admin.c
	dissectors/packet-aim-adverts.c
	dissectors/packet-aim-bos.c
	dissectors/packet-aim-buddylist.c
	dissectors/packet-aim-chat.c
	dissectors/packet-aim-chatnav.c
	dissectors/packet-aim-directory.c
	dissectors/packet-aim-email.c
	dissectors/packet-aim-generic.c
	dissectors/packet-aim-icq.c
	dissectors/packet-aim-invitation.c
	dissectors/packet-aim-location.c
	dissectors/packet-aim-messaging.c
	dissectors/packet-aim-oft.c
	dissectors/packet-aim-popup.c
	dissectors/packet-aim-signon.c
	dissectors/packet-aim-ssi.c
	dissectors/packet-aim-sst.c
	dissectors/packet-aim-stats.c
	dissectors/packet-aim-translate.c
	dissectors/packet-aim-userlookup.c
	dissectors/packet-aim.c
	dissectors/packet-ajp13.c
	dissectors/packet-alcap.c
	dissectors/packet-alljoyn.c
	dissectors/packet-amqp.c
	dissectors/packet-amr.c
	dissectors/packet-ancp.c
	dissectors/packet-ans.c
	dissectors/packet-ansi_637.c
	dissectors/packet-ansi_683.c
	dissectors/packet-ansi_801.c
	dissectors/packet-ansi_a.c
	dissectors/packet-aodv.c
	dissectors/packet-aoe.c
	dissectors/packet-aol.c
	dissectors/packet-ap1394.c
	dissectors/packet-app-pkix-cert.c
	dissectors/packet-applemidi.c
	dissectors/packet-aprs.c
	dissectors/packet-arcnet.c
	dissectors/packet-armagetronad.c
	dissectors/packet-arp.c
	dissectors/packet-artnet.c
	dissectors/packet-aruba-adp.c
	dissectors/packet-aruba-erm.c
	dissectors/packet-aruba-iap.c
	dissectors/packet-aruba-papi.c
	dissectors/packet-ar_drone.c
	dissectors/packet-asap.c
	dissectors/packet-ascend.c
	dissectors/packet-asf.c
	dissectors/packet-assa_r3.c
	dissectors/packet-asterix.c
	dissectors/packet-at.c
	dissectors/packet-atalk.c
	dissectors/packet-atm.c
	dissectors/packet-atmtcp.c
	dissectors/packet-auto_rp.c
	dissectors/packet-ax25.c
	dissectors/packet-ax25-kiss.c
	dissectors/packet-ax25-nol3.c
	dissectors/packet-ax4000.c
	dissectors/packet-ayiya.c
	dissectors/packet-babel.c
	dissectors/packet-bacapp.c
	dissectors/packet-bacnet.c
	dissectors/packet-banana.c
	dissectors/packet-bat.c
	dissectors/packet-batadv.c
	dissectors/packet-bctp.c
	dissectors/packet-beep.c
	dissectors/packet-bencode.c
	dissectors/packet-ber.c
	dissectors/packet-bfcp.c
	dissectors/packet-bfd.c
	dissectors/packet-bgp.c
	dissectors/packet-bitcoin.c
	dissectors/packet-bittorrent.c
	dissectors/packet-bjnp.c
	dissectors/packet-bmc.c
	dissectors/packet-bofl.c
	dissectors/packet-bootp.c
	dissectors/packet-bootparams.c
	dissectors/packet-bpdu.c
	dissectors/packet-bpq.c
	dissectors/packet-brdwlk.c
	dissectors/packet-brp.c
	dissectors/packet-bssap.c
	dissectors/packet-bssgp.c
	dissectors/packet-bt-dht.c
	dissectors/packet-bt-utp.c
	dissectors/packet-bt3ds.c
	dissectors/packet-btamp.c
	dissectors/packet-btatt.c
	dissectors/packet-btbnep.c
	dissectors/packet-btavctp.c
	dissectors/packet-btavdtp.c
	dissectors/packet-btavrcp.c
	dissectors/packet-bthci_acl.c
	dissectors/packet-bthci_cmd.c
	dissectors/packet-bthci_evt.c
	dissectors/packet-bthci_sco.c
	dissectors/packet-bthcrp.c
	dissectors/packet-bthfp.c
	dissectors/packet-bthid.c
	dissectors/packet-bthsp.c
	dissectors/packet-btle.c
	dissectors/packet-btle_rf.c
	dissectors/packet-btl2cap.c
	dissectors/packet-btmcap.c
	dissectors/packet-btobex.c
	dissectors/packet-btrfcomm.c
	dissectors/packet-btsap.c
	dissectors/packet-btsdp.c
	dissectors/packet-btsmp.c
	dissectors/packet-bt-oui.c
	dissectors/packet-bvlc.c
	dissectors/packet-bzr.c
	dissectors/packet-calcappprotocol.c
	dissectors/packet-canopen.c
	dissectors/packet-capwap.c
	dissectors/packet-carp.c
	dissectors/packet-cast.c
	dissectors/packet-catapult-dct2000.c
	dissectors/packet-ccsds.c
	dissectors/packet-cdp.c
	dissectors/packet-cell_broadcast.c
	dissectors/packet-cfdp.c
	dissectors/packet-cfm.c
	dissectors/packet-cgmp.c
	dissectors/packet-chargen.c
	dissectors/packet-chdlc.c
	dissectors/packet-cigi.c
	dissectors/packet-cimd.c
	dissectors/packet-cimetrics.c
	dissectors/packet-cip.c
	dissectors/packet-cipmotion.c
	dissectors/packet-cipsafety.c
	dissectors/packet-cisco-erspan.c
	dissectors/packet-cisco-metadata.c
	dissectors/packet-cisco-oui.c
	dissectors/packet-cisco-sm.c
	dissectors/packet-cisco-wids.c
	dissectors/packet-classicstun.c
	dissectors/packet-clearcase.c
	dissectors/packet-clip.c
	dissectors/packet-clique-rm.c
	dissectors/packet-clnp.c
	dissectors/packet-cmpp.c
	dissectors/packet-cnip.c
	dissectors/packet-coap.c
	dissectors/packet-collectd.c
	dissectors/packet-componentstatus.c
	dissectors/packet-cops.c
	dissectors/packet-corosync-totemnet.c
	dissectors/packet-corosync-totemsrp.c
	dissectors/packet-cosine.c
	dissectors/packet-cpfi.c
	dissectors/packet-cpha.c
	dissectors/packet-csm-encaps.c
	dissectors/packet-csn1.c
	dissectors/packet-ctdb.c
	dissectors/packet-cups.c
	dissectors/packet-daap.c
	dissectors/packet-data.c
	dissectors/packet-daytime.c
	dissectors/packet-db-lsp.c
	dissectors/packet-dbus.c
	dissectors/packet-dcc.c
	dissectors/packet-dccp.c
	dissectors/packet-dcerpc-bossvr.c
	dissectors/packet-dcerpc-browser.c
	dissectors/packet-dcerpc-cds_clerkserver.c
	dissectors/packet-dcerpc-cds_solicit.c
	dissectors/packet-dcerpc-conv.c
	dissectors/packet-dcerpc-cprpc_server.c
	dissectors/packet-dcerpc-dce122.c
	dissectors/packet-dcerpc-dtsprovider.c
	dissectors/packet-dcerpc-dtsstime_req.c
	dissectors/packet-dcerpc-epm.c
	dissectors/packet-dcerpc-fileexp.c
	dissectors/packet-dcerpc-fldb.c
	dissectors/packet-dcerpc-frsapi.c
	dissectors/packet-dcerpc-frsrpc.c
	dissectors/packet-dcerpc-ftserver.c
	dissectors/packet-dcerpc-icl_rpc.c
	dissectors/packet-dcerpc-krb5rpc.c
	dissectors/packet-dcerpc-llb.c
	dissectors/packet-dcerpc-messenger.c
	dissectors/packet-dcerpc-mgmt.c
	dissectors/packet-dcerpc-ndr.c
	dissectors/packet-dcerpc-netlogon.c
	dissectors/packet-dcerpc-pnp.c
	dissectors/packet-dcerpc-rdaclif.c
	dissectors/packet-dcerpc-rep_proc.c
	dissectors/packet-dcerpc-roverride.c
	dissectors/packet-dcerpc-rpriv.c
	dissectors/packet-dcerpc-rras.c
	dissectors/packet-dcerpc-rs_acct.c
	dissectors/packet-dcerpc-rs_attr.c
	dissectors/packet-dcerpc-rs_attr_schema.c
	dissectors/packet-dcerpc-rs_bind.c
	dissectors/packet-dcerpc-rs_misc.c
	dissectors/packet-dcerpc-rs_pgo.c
	dissectors/packet-dcerpc-rs_plcy.c
	dissectors/packet-dcerpc-rs_prop_acct.c
	dissectors/packet-dcerpc-rs_prop_acl.c
	dissectors/packet-dcerpc-rs_prop_attr.c
	dissectors/packet-dcerpc-rs_prop_pgo.c
	dissectors/packet-dcerpc-rs_prop_plcy.c
	dissectors/packet-dcerpc-rs_pwd_mgmt.c
	dissectors/packet-dcerpc-rs_repadm.c
	dissectors/packet-dcerpc-rs_replist.c
	dissectors/packet-dcerpc-rs_repmgr.c
	dissectors/packet-dcerpc-rs_unix.c
	dissectors/packet-dcerpc-rsec_login.c
	dissectors/packet-dcerpc-samr.c
	dissectors/packet-dcerpc-secidmap.c
	dissectors/packet-dcerpc-spoolss.c
	dissectors/packet-dcerpc-svcctl.c
	dissectors/packet-dcerpc-tapi.c
	dissectors/packet-dcerpc-tkn4int.c
	dissectors/packet-dcerpc-trksvr.c
	dissectors/packet-dcerpc-ubikdisk.c
	dissectors/packet-dcerpc-ubikvote.c
	dissectors/packet-dcerpc-update.c
	dissectors/packet-dcerpc.c
	dissectors/packet-dcm.c
	dissectors/packet-dcom-dispatch.c
	dissectors/packet-dcom-oxid.c
	dissectors/packet-dcom-remact.c
	dissectors/packet-dcom-remunkn.c
	dissectors/packet-dcom-sysact.c
	dissectors/packet-dcom.c
	dissectors/packet-dcp-etsi.c
	dissectors/packet-ddtp.c
	dissectors/packet-dec-bpdu.c
	dissectors/packet-dec-dnart.c
	dissectors/packet-dect.c
	dissectors/packet-devicenet.c
	dissectors/packet-dhcp-failover.c
	dissectors/packet-dhcpv6.c
	dissectors/packet-diameter.c
	dissectors/packet-diameter_3gpp.c
	dissectors/packet-diffserv-mpls-common.c
	dissectors/packet-dis.c
	dissectors/packet-distcc.c
	dissectors/packet-dlm3.c
	dissectors/packet-dlsw.c
	dissectors/packet-dmp.c
	dissectors/packet-dmx-chan.c
	dissectors/packet-dmx-sip.c
	dissectors/packet-dmx-test.c
	dissectors/packet-dmx-text.c
	dissectors/packet-dmx.c
	dissectors/packet-dnp.c
	dissectors/packet-dns.c
	dissectors/packet-dplay.c
	dissectors/packet-dpnss-link.c
	dissectors/packet-dpnss.c
	dissectors/packet-drda.c
	dissectors/packet-dsi.c
	dissectors/packet-dtcp-ip.c
	dissectors/packet-dtls.c
	dissectors/packet-dtn.c
	dissectors/packet-dtp.c
	dissectors/packet-dtpt.c
	dissectors/packet-dua.c
	dissectors/packet-dvb-ait.c
	dissectors/packet-dvb-bat.c
	dissectors/packet-dvb-data-mpe.c
	dissectors/packet-dvb-eit.c
	dissectors/packet-dvb-ipdc.c
	dissectors/packet-dvb-nit.c
	dissectors/packet-dvb-s2-bb.c
	dissectors/packet-dvb-sdt.c
	dissectors/packet-dvb-tdt.c
	dissectors/packet-dvb-tot.c
	dissectors/packet-dvbci.c
	dissectors/packet-dvmrp.c
	dissectors/packet-e100.c
	dissectors/packet-e164.c
	dissectors/packet-e212.c
	dissectors/packet-eap.c
	dissectors/packet-eapol.c
	dissectors/packet-echo.c
	dissectors/packet-ecp-oui.c
	dissectors/packet-edonkey.c
	dissectors/packet-egd.c
	dissectors/packet-ehdlc.c
	dissectors/packet-ehs.c
	dissectors/packet-eigrp.c
	dissectors/packet-eiss.c
	dissectors/packet-elcom.c
	dissectors/packet-elmi.c
	dissectors/packet-enc.c
	dissectors/packet-enip.c
	dissectors/packet-enrp.c
	dissectors/packet-enttec.c
	dissectors/packet-epl.c
	dissectors/packet-epl_v1.c
	dissectors/packet-epmd.c
	dissectors/packet-epon.c
	dissectors/packet-erf.c
	dissectors/packet-erldp.c
	dissectors/packet-esio.c
	dissectors/packet-esis.c
	dissectors/packet-etch.c
	dissectors/packet-eth.c
	dissectors/packet-etherip.c
	dissectors/packet-ethertype.c
	dissectors/packet-etsi_card_app_toolkit.c
	dissectors/packet-etv.c
	dissectors/packet-evrc.c
	dissectors/packet-exec.c
	dissectors/packet-exported_pdu.c
	dissectors/packet-extreme.c
	dissectors/packet-fc.c
	dissectors/packet-fcct.c
	dissectors/packet-fcdns.c
	dissectors/packet-fcels.c
	dissectors/packet-fcfcs.c
	dissectors/packet-fcfzs.c
	dissectors/packet-fcgi.c
	dissectors/packet-fcip.c
	dissectors/packet-fclctl.c
	dissectors/packet-fcoe.c
	dissectors/packet-fcoib.c
	dissectors/packet-fcp.c
	dissectors/packet-fcsb3.c
	dissectors/packet-fcsp.c
	dissectors/packet-fcswils.c
	dissectors/packet-fddi.c
	dissectors/packet-fefd.c
	dissectors/packet-ff.c
	dissectors/packet-finger.c
	dissectors/packet-fip.c
	dissectors/packet-fix.c
	dissectors/packet-flexnet.c
	dissectors/packet-flip.c
	dissectors/packet-fmp.c
	dissectors/packet-fmp_notify.c
	dissectors/packet-fmtp.c
	dissectors/packet-force10-oui.c
	dissectors/packet-forces.c
	dissectors/packet-foundry.c
	dissectors/packet-fp_hint.c
	dissectors/packet-fr.c
	dissectors/packet-fractalgeneratorprotocol.c
	dissectors/packet-frame.c
	dissectors/packet-ftp.c
	dissectors/packet-fw1.c
	dissectors/packet-g723.c
	dissectors/packet-gadu-gadu.c
	dissectors/packet-gdb.c
	dissectors/packet-gdsdb.c
	dissectors/packet-gearman.c
	dissectors/packet-ged125.c
	dissectors/packet-geneve.c
	dissectors/packet-gift.c
	dissectors/packet-giop.c
	dissectors/packet-git.c
	dissectors/packet-glbp.c
	dissectors/packet-gluster_cli.c
	dissectors/packet-gluster_pmap.c
	dissectors/packet-glusterd.c
	dissectors/packet-glusterfs.c
	dissectors/packet-glusterfs_hndsk.c
	dissectors/packet-gmhdr.c
	dissectors/packet-gmr1_bcch.c
	dissectors/packet-gmr1_common.c
	dissectors/packet-gmr1_dtap.c
	dissectors/packet-gmr1_rach.c
	dissectors/packet-gmr1_rr.c
	dissectors/packet-gmrp.c
	dissectors/packet-gnutella.c
	dissectors/packet-gopher.c
	dissectors/packet-gpef.c
	dissectors/packet-gprs-llc.c
	dissectors/packet-gre.c
	dissectors/packet-gsm_a_bssmap.c
	dissectors/packet-gsm_a_dtap.c
	dissectors/packet-gsm_a_gm.c
	dissectors/packet-gsm_a_rp.c
	dissectors/packet-gsm_a_rr.c
	dissectors/packet-gsm_abis_om2000.c
	dissectors/packet-gsm_abis_oml.c
	dissectors/packet-gsm_bsslap.c
	dissectors/packet-gsm_bssmap_le.c
	dissectors/packet-gsm_cbch.c
	dissectors/packet-gsm_ipa.c
	dissectors/packet-gsm_rlcmac.c
	dissectors/packet-gsm_sim.c
	dissectors/packet-gsm_sms.c
	dissectors/packet-gsm_sms_ud.c
	dissectors/packet-gsm_um.c
	dissectors/packet-gsmtap.c
	dissectors/packet-gssapi.c
	dissectors/packet-gtp.c
	dissectors/packet-gtpv2.c
	dissectors/packet-gvcp.c
	dissectors/packet-gvrp.c
	dissectors/packet-h1.c
	dissectors/packet-h221_nonstd.c
	dissectors/packet-h223.c
	dissectors/packet-h248_10.c
	dissectors/packet-h248_2.c
	dissectors/packet-h248_3gpp.c
	dissectors/packet-h248_7.c
	dissectors/packet-h248_annex_c.c
	dissectors/packet-h248_annex_e.c
	dissectors/packet-h248_q1950.c
	dissectors/packet-h261.c
	dissectors/packet-h263.c
	dissectors/packet-h263p.c
	dissectors/packet-h264.c
	dissectors/packet-hartip.c
	dissectors/packet-hazelcast.c
	dissectors/packet-hci_h1.c
	dissectors/packet-hci_h4.c
	dissectors/packet-hci_mon.c
	dissectors/packet-hci_usb.c
	dissectors/packet-hclnfsd.c
	dissectors/packet-hdcp.c
	dissectors/packet-hdcp2.c
	dissectors/packet-hdfs.c
	dissectors/packet-hdfsdata.c
	dissectors/packet-hdmi.c
	dissectors/packet-hip.c
	dissectors/packet-hislip.c
	dissectors/packet-homeplug-av.c
	dissectors/packet-homeplug.c
	dissectors/packet-hp-erm.c
	dissectors/packet-hpext.c
	dissectors/packet-hpfeeds.c
	dissectors/packet-hpsw.c
	dissectors/packet-hpteam.c
	dissectors/packet-hsr-prp-supervision.c
	dissectors/packet-hsr.c
	dissectors/packet-hsrp.c
	dissectors/packet-http.c
	dissectors/packet-http2.c
	dissectors/packet-http-urlencoded.c
	dissectors/packet-hyperscsi.c
	dissectors/packet-i2c.c
	dissectors/packet-iana-oui.c
	dissectors/packet-iapp.c
	dissectors/packet-iax2.c
	dissectors/packet-icap.c
	dissectors/packet-icep.c
	dissectors/packet-icmp.c
	dissectors/packet-icmpv6.c
	dissectors/packet-icp.c
	dissectors/packet-icq.c
	dissectors/packet-idp.c
	dissectors/packet-idrp.c
	dissectors/packet-iec104.c
	dissectors/packet-ieee1722.c
	dissectors/packet-ieee1722a.c
	dissectors/packet-ieee17221.c
	dissectors/packet-ieee80211-airopeek.c
	dissectors/packet-ieee80211-netmon.c
	dissectors/packet-ieee80211-prism.c
	dissectors/packet-ieee80211-radio.c
	dissectors/packet-ieee80211-radiotap-iter.c
	dissectors/packet-ieee80211-radiotap.c
	dissectors/packet-ieee80211-wlancap.c
	dissectors/packet-ieee80211.c
	dissectors/packet-ieee802154.c
	dissectors/packet-ieee8021ah.c
	dissectors/packet-ieee8023.c
	dissectors/packet-ieee802a.c
	dissectors/packet-ifcp.c
	dissectors/packet-igap.c
	dissectors/packet-igmp.c
	dissectors/packet-igrp.c
	dissectors/packet-imap.c
	dissectors/packet-imf.c
	dissectors/packet-infiniband.c
	dissectors/packet-infiniband_sdp.c
	dissectors/packet-interlink.c
	dissectors/packet-ip.c
	dissectors/packet-ipars.c
	dissectors/packet-ipdc.c
	dissectors/packet-ipfc.c
	dissectors/packet-ipmi.c
	dissectors/packet-ipmi-app.c
	dissectors/packet-ipmi-bridge.c
	dissectors/packet-ipmi-chassis.c
	dissectors/packet-ipmi-picmg.c
	dissectors/packet-ipmi-se.c
	dissectors/packet-ipmi-session.c
	dissectors/packet-ipmi-storage.c
	dissectors/packet-ipmi-trace.c
	dissectors/packet-ipmi-transport.c
	dissectors/packet-ipmi-pps.c
	dissectors/packet-ipmi-update.c
	dissectors/packet-ipmi-vita.c
	dissectors/packet-ipnet.c
	dissectors/packet-ipoib.c
	dissectors/packet-ipp.c
	dissectors/packet-ipsec-tcp.c
	dissectors/packet-ipsec-udp.c
	dissectors/packet-ipsec.c
	dissectors/packet-ipsi-ctl.c
	dissectors/packet-ipv6.c
	dissectors/packet-ipvs-syncd.c
	dissectors/packet-ipx.c
	dissectors/packet-ipxwan.c
	dissectors/packet-irc.c
	dissectors/packet-isakmp.c
	dissectors/packet-iscsi.c
	dissectors/packet-isdn.c
	dissectors/packet-isis-clv.c
	dissectors/packet-isis-hello.c
	dissectors/packet-isis-lsp.c
	dissectors/packet-isis-snp.c
	dissectors/packet-isis.c
	dissectors/packet-isl.c
	dissectors/packet-ismacryp.c
	dissectors/packet-ismp.c
	dissectors/packet-isns.c
	dissectors/packet-iso7816.c
	dissectors/packet-isup.c
	dissectors/packet-itdm.c
	dissectors/packet-iua.c
	dissectors/packet-iuup.c
	dissectors/packet-iwarp-ddp-rdmap.c
	dissectors/packet-iwarp-mpa.c
	dissectors/packet-ixiatrailer.c
	dissectors/packet-ixveriwave.c
	dissectors/packet-j1939.c
	dissectors/packet-jmirror.c
	dissectors/packet-jpeg.c
	dissectors/packet-json.c
	dissectors/packet-juniper.c
	dissectors/packet-jxta.c
	dissectors/packet-k12.c
	dissectors/packet-kadm5.c
	dissectors/packet-kafka.c
	dissectors/packet-kdp.c
	dissectors/packet-kdsp.c
	dissectors/packet-kerberos4.c
	dissectors/packet-kingfisher.c
	dissectors/packet-kink.c
	dissectors/packet-kismet.c
	dissectors/packet-klm.c
	dissectors/packet-knet.c
	dissectors/packet-kpasswd.c
	dissectors/packet-kt.c
	dissectors/packet-l1-events.c
	dissectors/packet-l2tp.c
	dissectors/packet-lacp.c
	dissectors/packet-lanforge.c
	dissectors/packet-lapb.c
	dissectors/packet-lapbether.c
	dissectors/packet-lapd.c
	dissectors/packet-lapdm.c
	dissectors/packet-laplink.c
	dissectors/packet-lapsat.c
	dissectors/packet-lbm.c
	dissectors/packet-lbmc.c
	dissectors/packet-lbmpdm.c
	dissectors/packet-lbmpdmtcp.c
	dissectors/packet-lbmr.c
	dissectors/packet-lbtrm.c
	dissectors/packet-lbtru.c
	dissectors/packet-lbttcp.c
	dissectors/packet-ldp.c
	dissectors/packet-ldss.c
	dissectors/packet-lg8979.c
	dissectors/packet-lge_monitor.c
	dissectors/packet-link16.c
	dissectors/packet-linx.c
	dissectors/packet-lisp-data.c
	dissectors/packet-lisp.c
	dissectors/packet-llc.c
	dissectors/packet-lldp.c
	dissectors/packet-llrp.c
	dissectors/packet-llt.c
	dissectors/packet-lltd.c
	dissectors/packet-lmi.c
	dissectors/packet-lmp.c
	dissectors/packet-logcat.c
	dissectors/packet-lon.c
	dissectors/packet-loop.c
	dissectors/packet-lpd.c
	dissectors/packet-lsc.c
	dissectors/packet-ltp.c
	dissectors/packet-lwapp.c
	dissectors/packet-lwm.c
	dissectors/packet-lwres.c
	dissectors/packet-m2pa.c
	dissectors/packet-m2tp.c
	dissectors/packet-m2ua.c
	dissectors/packet-m3ua.c
	dissectors/packet-maap.c
	dissectors/packet-mac-lte-framed.c
	dissectors/packet-mac-lte.c
	dissectors/packet-maccontrol.c
	dissectors/packet-macsec.c
	dissectors/packet-mactelnet.c
	dissectors/packet-manolito.c
	dissectors/packet-marker.c
	dissectors/packet-mausb.c
	dissectors/packet-mbim.c
	dissectors/packet-mbtcp.c
	dissectors/packet-mdshdr.c
	dissectors/packet-media.c
	dissectors/packet-megaco.c
	dissectors/packet-memcache.c
	dissectors/packet-mesh.c
	dissectors/packet-meta.c
	dissectors/packet-mgcp.c
	dissectors/packet-mih.c
	dissectors/packet-mikey.c
	dissectors/packet-mim.c
	dissectors/packet-mime-encap.c
	dissectors/packet-mint.c
	dissectors/packet-miop.c
	dissectors/packet-mip.c
	dissectors/packet-mip6.c
	dissectors/packet-mmse.c
	dissectors/packet-mndp.c
	dissectors/packet-mojito.c
	dissectors/packet-moldudp.c
	dissectors/packet-moldudp64.c
	dissectors/packet-mongo.c
	dissectors/packet-mount.c
	dissectors/packet-mp2t.c
	dissectors/packet-mp4ves.c
	dissectors/packet-mpeg-ca.c
	dissectors/packet-mpeg-descriptor.c
	dissectors/packet-mpeg-dsmcc.c
	dissectors/packet-mpeg-pat.c
	dissectors/packet-mpeg-pmt.c
	dissectors/packet-mpeg-sect.c
	dissectors/packet-mpeg1.c
	dissectors/packet-mpls-echo.c
	dissectors/packet-mpls-pm.c
	dissectors/packet-mpls-psc.c
	dissectors/packet-mplstp-oam.c
	dissectors/packet-mpls-y1711.c
	dissectors/packet-mpls.c
	dissectors/packet-mq-base.c
	dissectors/packet-mq-pcf.c
	dissectors/packet-mq.c
	dissectors/packet-mqtt.c
	dissectors/packet-mrcpv2.c
	dissectors/packet-mrdisc.c
	dissectors/packet-mrp-mmrp.c
	dissectors/packet-mrp-msrp.c
	dissectors/packet-mrp-mvrp.c
	dissectors/packet-ms-mms.c
	dissectors/packet-msdp.c
	dissectors/packet-msn-messenger.c
	dissectors/packet-msnip.c
	dissectors/packet-msnlb.c
	dissectors/packet-msproxy.c
	dissectors/packet-msrp.c
	dissectors/packet-mstp.c
	dissectors/packet-mtp2.c
	dissectors/packet-mtp3.c
	dissectors/packet-mtp3mg.c
	dissectors/packet-multipart.c
	dissectors/packet-mux27010.c
	dissectors/packet-mysql.c
	dissectors/packet-nas_eps.c
	dissectors/packet-nasdaq-itch.c
	dissectors/packet-nasdaq-soup.c
	dissectors/packet-nat-pmp.c
	dissectors/packet-nb_rtpmux.c
	dissectors/packet-nbd.c
	dissectors/packet-nbipx.c
	dissectors/packet-nbns.c
	dissectors/packet-ncp-nmas.c
	dissectors/packet-ncp-sss.c
	dissectors/packet-ncp.c
	packet-ncp2222.c
	dissectors/packet-ncs.c
	dissectors/packet-ndmp.c
	dissectors/packet-ndp.c
	dissectors/packet-ndps.c
	dissectors/packet-negoex.c
	dissectors/packet-netanalyzer.c
	dissectors/packet-netbios.c
	dissectors/packet-netdump.c
	dissectors/packet-netflow.c
	dissectors/packet-netlink-netfilter.c
	dissectors/packet-netlink-route.c
	dissectors/packet-netlink-sock_diag.c
	dissectors/packet-netlink.c
	dissectors/packet-netperfmeter.c
	dissectors/packet-netrom.c
	dissectors/packet-netsync.c
	dissectors/packet-nettl.c
	dissectors/packet-newmail.c
	dissectors/packet-nflog.c
	dissectors/packet-nfs.c
	dissectors/packet-nfsacl.c
	dissectors/packet-nfsauth.c
	dissectors/packet-nhrp.c
	dissectors/packet-nisplus.c
	dissectors/packet-nlm.c
	dissectors/packet-nlsp.c
	dissectors/packet-nntp.c
	dissectors/packet-noe.c
	dissectors/packet-nsip.c
	dissectors/packet-nsrp.c
	dissectors/packet-nstrace.c
	dissectors/packet-nt-oui.c
	dissectors/packet-nt-tpcp.c
	dissectors/packet-ntlmssp.c
	dissectors/packet-ntp.c
	dissectors/packet-null.c
	dissectors/packet-nwmtp.c
	dissectors/packet-oampdu.c
	dissectors/packet-oicq.c
	dissectors/packet-oipf.c
	dissectors/packet-olsr.c
	dissectors/packet-omapi.c
	dissectors/packet-omron-fins.c
	dissectors/packet-openflow.c
	dissectors/packet-openflow_v1.c
	dissectors/packet-openflow_v4.c
	dissectors/packet-openflow_v5.c
	dissectors/packet-opensafety.c
	dissectors/packet-openvpn.c
	dissectors/packet-openwire.c
	dissectors/packet-opsi.c
	dissectors/packet-osc.c
	dissectors/packet-osi-options.c
	dissectors/packet-osi.c
	dissectors/packet-ositp.c
	dissectors/packet-ospf.c
	dissectors/packet-ossp.c
	dissectors/packet-ouch.c
	dissectors/packet-p_mul.c
	dissectors/packet-pathport.c
	dissectors/packet-packetbb.c
	dissectors/packet-packetlogger.c
	dissectors/packet-pagp.c
	dissectors/packet-paltalk.c
	dissectors/packet-pana.c
	dissectors/packet-pcapng_block.c
	dissectors/packet-pcep.c
	dissectors/packet-pcli.c
	dissectors/packet-pcnfsd.c
	dissectors/packet-pcp.c
	dissectors/packet-pdc.c
	dissectors/packet-pdcp-lte.c
	dissectors/packet-peekremote.c
	dissectors/packet-per.c
	dissectors/packet-pflog.c
	dissectors/packet-pgm.c
	dissectors/packet-pgsql.c
	dissectors/packet-pim.c
	dissectors/packet-pingpongprotocol.c
	dissectors/packet-pktc.c
	dissectors/packet-pktgen.c
	dissectors/packet-pnrp.c
	dissectors/packet-pop.c
	dissectors/packet-portmap.c
	dissectors/packet-ppcap.c
	dissectors/packet-ppi-antenna.c
	dissectors/packet-ppi-geolocation-common.c
	dissectors/packet-ppi-gps.c
	dissectors/packet-ppi-sensor.c
	dissectors/packet-ppi-vector.c
	dissectors/packet-ppi.c
	dissectors/packet-ppp.c
	dissectors/packet-pppoe.c
	dissectors/packet-pptp.c
	dissectors/packet-prp.c
	dissectors/packet-ptp.c
	dissectors/packet-ptpip.c
	dissectors/packet-pulse.c
	dissectors/packet-pvfs2.c
	dissectors/packet-pw-atm.c
	dissectors/packet-pw-cesopsn.c
	dissectors/packet-pw-common.c
	dissectors/packet-pw-eth.c
	dissectors/packet-pw-fr.c
	dissectors/packet-pw-hdlc.c
	dissectors/packet-pw-oam.c
	dissectors/packet-pw-satop.c
	dissectors/packet-q2931.c
	dissectors/packet-q708.c
	dissectors/packet-q931.c
	dissectors/packet-q933.c
	dissectors/packet-qllc.c
	dissectors/packet-quake.c
	dissectors/packet-quake2.c
	dissectors/packet-quake3.c
	dissectors/packet-quakeworld.c
	dissectors/packet-quic.c
	dissectors/packet-radius.c
	dissectors/packet-radius_packetcable.c
	dissectors/packet-raw.c
	dissectors/packet-rdm.c
	dissectors/packet-rdp.c
	dissectors/packet-rdt.c
	dissectors/packet-redback.c
	dissectors/packet-redbackli.c
	dissectors/packet-reload-framing.c
	dissectors/packet-reload.c
	dissectors/packet-retix-bpdu.c
	dissectors/packet-rfc2190.c
	dissectors/packet-rfid-felica.c
	dissectors/packet-rfid-mifare.c
	dissectors/packet-rfid-pn532.c
	dissectors/packet-rfid-pn532-hci.c
	dissectors/packet-rgmp.c
	dissectors/packet-rip.c
	dissectors/packet-ripng.c
	dissectors/packet-rlc-lte.c
	dissectors/packet-rlc.c
	dissectors/packet-rlm.c
	dissectors/packet-rlogin.c
	dissectors/packet-rmcp.c
	dissectors/packet-rmi.c
	dissectors/packet-rmp.c
	dissectors/packet-rmt-alc.c
	dissectors/packet-rmt-fec.c
	dissectors/packet-rmt-lct.c
	dissectors/packet-rmt-norm.c
	dissectors/packet-rohc.c
	dissectors/packet-roofnet.c
	dissectors/packet-rpc.c
	dissectors/packet-rpcap.c
	dissectors/packet-rpki-rtr.c
	dissectors/packet-rpl.c
	dissectors/packet-rquota.c
	dissectors/packet-rsh.c
	dissectors/packet-rsip.c
	dissectors/packet-rsl.c
	dissectors/packet-rstat.c
	dissectors/packet-rsvp.c
	dissectors/packet-rsync.c
	dissectors/packet-rtacser.c
	dissectors/packet-rtcdc.c
	dissectors/packet-rtcp.c
	dissectors/packet-rtmpt.c
	dissectors/packet-rtnet.c
	dissectors/packet-rtp-events.c
	dissectors/packet-rtp-midi.c
	dissectors/packet-rtp.c
	dissectors/packet-rtpproxy.c
	dissectors/packet-rtps.c
	dissectors/packet-rtsp.c
	dissectors/packet-rudp.c
	dissectors/packet-rwall.c
	dissectors/packet-rx.c
	dissectors/packet-s5066sis.c
	dissectors/packet-s5066dts.c
	dissectors/packet-sadmind.c
	dissectors/packet-sametime.c
	dissectors/packet-sap.c
	dissectors/packet-sasp.c
	dissectors/packet-sbus.c
	dissectors/packet-sbc.c
	dissectors/packet-sccp.c
	dissectors/packet-sccpmg.c
	dissectors/packet-scop.c
	dissectors/packet-scriptingservice.c
	dissectors/packet-scsi-mmc.c
	dissectors/packet-scsi-osd.c
	dissectors/packet-scsi-sbc.c
	dissectors/packet-scsi-smc.c
	dissectors/packet-scsi-ssc.c
	dissectors/packet-scsi.c
	dissectors/packet-sctp.c
	dissectors/packet-sdh.c
	dissectors/packet-sdlc.c
	dissectors/packet-sdp.c
	dissectors/packet-sebek.c
	dissectors/packet-selfm.c
	dissectors/packet-sercosiii.c
	dissectors/packet-ses.c
	dissectors/packet-sflow.c
	dissectors/packet-sgsap.c
	dissectors/packet-sigcomp.c
	dissectors/packet-simulcrypt.c
	dissectors/packet-sip.c
	dissectors/packet-sipfrag.c
	dissectors/packet-sita.c
	dissectors/packet-skinny.c
	dissectors/packet-skype.c
	dissectors/packet-slimp3.c
	dissectors/packet-sll.c
	dissectors/packet-slowprotocols.c
	dissectors/packet-slsk.c
	dissectors/packet-smb-browse.c
	dissectors/packet-smb-common.c
	dissectors/packet-smb-logon.c
	dissectors/packet-smb-mailslot.c
	dissectors/packet-smb-pipe.c
	dissectors/packet-smb-sidsnooping.c
	dissectors/packet-smb-direct.c
	dissectors/packet-smb.c
	dissectors/packet-smb2.c
	dissectors/packet-sml.c
	dissectors/packet-smpp.c
	dissectors/packet-smtp.c
	dissectors/packet-sna.c
	dissectors/packet-snaeth.c
	dissectors/packet-sndcp-xid.c
	dissectors/packet-sndcp.c
	dissectors/packet-socketcan.c
	dissectors/packet-socks.c
	dissectors/packet-soupbintcp.c
	dissectors/packet-spdy.c
	dissectors/packet-spice.c
	dissectors/packet-spp.c
	dissectors/packet-spray.c
	dissectors/packet-sprt.c
	dissectors/packet-srp.c
	dissectors/packet-srvloc.c
	dissectors/packet-sscf-nni.c
	dissectors/packet-sscop.c
	dissectors/packet-ssh.c
	dissectors/packet-ssl-utils.c
	dissectors/packet-ssl.c
	dissectors/packet-stanag4607.c
	dissectors/packet-starteam.c
	dissectors/packet-stat-notify.c
	dissectors/packet-stat.c
	dissectors/packet-stun.c
	dissectors/packet-sua.c
	dissectors/packet-swipe.c
	dissectors/packet-symantec.c
	dissectors/packet-sync.c
	dissectors/packet-synergy.c
	dissectors/packet-synphasor.c
	dissectors/packet-sysex.c
	dissectors/packet-syslog.c
	dissectors/packet-t30.c
	dissectors/packet-tacacs.c
	dissectors/packet-tali.c
	dissectors/packet-tapa.c
	dissectors/packet-tcp.c
	dissectors/packet-tdmoe.c
	dissectors/packet-tds.c
	dissectors/packet-teamspeak2.c
	dissectors/packet-teimanagement.c
	dissectors/packet-teklink.c
	dissectors/packet-telkonet.c
	dissectors/packet-telnet.c
	dissectors/packet-teredo.c
	dissectors/packet-text-media.c
	dissectors/packet-tfp.c
	dissectors/packet-tftp.c
	dissectors/packet-time.c
	dissectors/packet-tipc.c
	dissectors/packet-tivoconnect.c
	dissectors/packet-tn3270.c
	dissectors/packet-tn5250.c
	dissectors/packet-tnef.c
	dissectors/packet-tns.c
	dissectors/packet-tpkt.c
	dissectors/packet-tpncp.c
	dissectors/packet-tr.c
	dissectors/packet-trill.c
	dissectors/packet-trmac.c
	dissectors/packet-tsp.c
	dissectors/packet-tte-pcf.c
	dissectors/packet-tte.c
	dissectors/packet-turbocell.c
	dissectors/packet-turnchannel.c
	dissectors/packet-tuxedo.c
	dissectors/packet-tzsp.c
	dissectors/packet-ua.c
	dissectors/packet-ua3g.c
	dissectors/packet-uasip.c
	dissectors/packet-uaudp.c
	dissectors/packet-ubertooth.c
	dissectors/packet-ucp.c
	dissectors/packet-udld.c
	dissectors/packet-udp.c
	dissectors/packet-udt.c
	dissectors/packet-uhd.c
	dissectors/packet-uma.c
	dissectors/packet-umts_fp.c
	dissectors/packet-umts_mac.c
	dissectors/packet-usb-audio.c
	dissectors/packet-usb-ccid.c
	dissectors/packet-usb-com.c
	dissectors/packet-usb-dfu.c
	dissectors/packet-usb-hid.c
	dissectors/packet-usb-hub.c
	dissectors/packet-usb-masstorage.c
	dissectors/packet-usb-video.c
	dissectors/packet-usb.c
	dissectors/packet-user_encap.c
	dissectors/packet-uts.c
	dissectors/packet-v120.c
	dissectors/packet-v150fw.c
	dissectors/packet-v52.c
	dissectors/packet-v5dl.c
	dissectors/packet-v5ef.c
	dissectors/packet-v5ua.c
	dissectors/packet-vcdu.c
	dissectors/packet-vicp.c
	dissectors/packet-vines.c
	dissectors/packet-vlan.c
	dissectors/packet-vmlab.c
	dissectors/packet-vnc.c
	dissectors/packet-vntag.c
	dissectors/packet-vp8.c
	dissectors/packet-vrrp.c
	dissectors/packet-vrt.c
	dissectors/packet-vssmonitoring.c
	dissectors/packet-vtp.c
	dissectors/packet-vuze-dht.c
	dissectors/packet-vxi11.c
	dissectors/packet-vxlan.c
	dissectors/packet-wai.c
	dissectors/packet-wap.c
	dissectors/packet-wassp.c
	dissectors/packet-waveagent.c
	dissectors/packet-wbxml.c
	dissectors/packet-wccp.c
	dissectors/packet-wcp.c
	dissectors/packet-websocket.c
	dissectors/packet-wfleet-hdlc.c
	dissectors/packet-who.c
	dissectors/packet-whois.c
	dissectors/packet-wifi-display.c
	dissectors/packet-wifi-p2p.c
	dissectors/packet-windows-common.c
	dissectors/packet-winsrepl.c
	dissectors/packet-wlccp.c
	dissectors/packet-wol.c
	dissectors/packet-wow.c
	dissectors/packet-wps.c
	dissectors/packet-wreth.c
	dissectors/packet-wsmp.c
	dissectors/packet-wsp.c
	dissectors/packet-wtls.c
	dissectors/packet-wtp.c
	dissectors/packet-x224.c
	dissectors/packet-x25.c
	dissectors/packet-x29.c
	dissectors/packet-xcsl.c
	dissectors/packet-xdmcp.c
	dissectors/packet-xmcp.c
	dissectors/packet-xml.c
	dissectors/packet-xmpp-conference.c
	dissectors/packet-xmpp-core.c
	dissectors/packet-xmpp-gtalk.c
	dissectors/packet-xmpp-jingle.c
	dissectors/packet-xmpp-other.c
	dissectors/packet-xmpp-utils.c
	dissectors/packet-xmpp.c
	dissectors/packet-xot.c
	dissectors/packet-xtp.c
	dissectors/packet-xyplex.c
	dissectors/packet-yami.c
	dissectors/packet-yhoo.c
	dissectors/packet-ymsg.c
	dissectors/packet-ypbind.c
	dissectors/packet-yppasswd.c
	dissectors/packet-ypserv.c
	dissectors/packet-ypxfr.c
	dissectors/packet-zbee-aps.c
	dissectors/packet-zbee-nwk.c
	dissectors/packet-zbee-nwk-gp.c
	dissectors/packet-zbee-security.c
	dissectors/packet-zbee-zcl.c
	dissectors/packet-zbee-zcl-general.c
	dissectors/packet-zbee-zcl-ha.c
	dissectors/packet-zbee-zcl-meas-sensing.c
	dissectors/packet-zbee-zcl-se.c
	dissectors/packet-zbee-zdp-binding.c
	dissectors/packet-zbee-zdp-discovery.c
	dissectors/packet-zbee-zdp-management.c
	dissectors/packet-zbee-zdp.c
	dissectors/packet-zebra.c
	dissectors/packet-zep.c
	dissectors/packet-ziop.c
	dissectors/packet-zrtp.c
)

set(DIRTY_DISSECTOR_SRC
	dissectors/packet-gsm_a_common.c
	dissectors/packet-x11.c
)

set(DISSECTOR_SUPPORT_SRC
	dissectors/packet-dcerpc-nt.c
	dissectors/usb.c
	register.c
)
source_group(dissector-support FILES ${DISSECTOR_SUPPORT_SRC})

set(LIBWIRESHARK_ASM_FILES
	asm_utils.c
# todo
#	!IFDEF NASM
#	asm_utils_win32_x86.obj: asm_utils_win32_x86.asm
#	        $(NASM) -f $(WIRESHARK_TARGET_PLATFORM) -o $@ $?
#	!ENDIF
#	...
#	!IF defined(NASM) && "$(WIRESHARK_TARGET_PLATFORM)" == "win32"
#	        asm_utils_win32_x86.obj
#	!ELSE
#	        asm_utils.obj
#	!ENDIF
)

set(DISSECTOR_FILES
	${DISSECTOR_SRC}
	${DIRTY_DISSECTOR_SRC}
	${PIDL_DISSECTOR_SRC}
	${PIDL_DISSECTOR_AUTOGEN_SRC}
	${DIRTY_PIDL_DISSECTOR_SRC}
	${ASN1_DISSECTOR_SRC}
	${DIRTY_ASN1_DISSECTOR_SRC}
)
source_group(dissectors FILES ${DISSECTOR_FILES})

register_dissector_files(register.c
	dissectors
	${DISSECTOR_FILES}
)

set(FTYPE_FILES
	ftypes/ftypes.c
	ftypes/ftype-bytes.c
	ftypes/ftype-double.c
	ftypes/ftype-integer.c
	ftypes/ftype-ipv4.c
	ftypes/ftype-ipv6.c
	ftypes/ftype-guid.c
	ftypes/ftype-none.c
	ftypes/ftype-pcre.c
	ftypes/ftype-string.c
	ftypes/ftype-time.c
	ftypes/ftype-tvbuff.c
)
source_group(ftype FILES ${FTYPE_FILES})

set(WMEM_FILES
	wmem/wmem_array.c
	wmem/wmem_core.c
	wmem/wmem_allocator_block.c
	wmem/wmem_allocator_block_fast.c
	wmem/wmem_allocator_simple.c
	wmem/wmem_allocator_strict.c
	wmem/wmem_list.c
	wmem/wmem_map.c
	wmem/wmem_miscutl.c
	wmem/wmem_scopes.c
	wmem/wmem_stack.c
	wmem/wmem_strbuf.c
	wmem/wmem_strutl.c
	wmem/wmem_tree.c
	wmem/wmem_user_cb.c
)
source_group(wmem FILES ${WMEM_FILES})

ADD_CUSTOM_TARGET(
    update-sminmpec
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_SOURCE_DIR}/tools/make-sminmpec.pl
    DEPENDS
      enterprise-numbers
      ${CMAKE_SOURCE_DIR}/tools/make-sminmpec.pl
)

ADD_CUSTOM_COMMAND(
	OUTPUT	ps.c
	COMMAND	${PYTHON_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/tools/rdps.py
		${CMAKE_CURRENT_SOURCE_DIR}/print.ps
		ps.c
	DEPENDS
		${CMAKE_SOURCE_DIR}/tools/rdps.py
		${CMAKE_CURRENT_SOURCE_DIR}/print.ps
)

set(LIBWIRESHARK_FILES
	addr_and_mask.c
	addr_resolv.c
	address_to_str.c
	afn.c
	aftypes.c
	app_mem_usage.c
	asn1.c
	atalk-utils.c
	charsets.c
	circuit.c
	column.c
	column-utils.c
	conversation.c
	crc16-tvb.c
	crc32-tvb.c
	crc8-tvb.c
	decode_as.c
	disabled_protos.c
	dissector_filters.c
	dvb_chartbl.c
	dwarf.c
	emem.c
	epan.c
	ex-opt.c
	except.c
	expert.c
	exported_pdu.c
	filter_expressions.c
	follow.c
	frame_data.c
	frame_data_sequence.c
	frequency-utils.c
	funnel.c
	gcp.c
	geoip_db.c
	golay.c
	guid-utils.c
	h225-persistentdata.c
	in_cksum.c
	ipproto.c
	ipv4.c
	next_tvb.c
	oids.c
	osi-utils.c
	oui.c
	packet-range.c
	packet.c
	print.c
	prefs.c
	proto.c
	ps.c
	range.c
	reassemble.c
	reedsolomon.c
	req_resp_hdrs.c
	show_exception.c
	sigcomp_state_hdlr.c
	sigcomp-udvm.c
	sminmpec.c
	sna-utils.c
	stat_cmd_args.c
	stats_tree.c
	strutil.c
	stream.c
	t35.c
	tap.c
	timestamp.c
	timestats.c
	tfs.c
	to_str.c
	tvbparse.c
	tvbuff.c
	tvbuff_base64.c
	tvbuff_composite.c
	tvbuff_real.c
	tvbuff_subset.c
	tvbuff_zlib.c
	uat.c
	value_string.c
	xdlc.c
)

set(LIBWIRESHARK_CLEAN_FILES
	${LIBWIRESHARK_FILES}
)

add_lex_files(LIBWIRESHARK_FILES
	diam_dict.l
	dtd_parse.l
	dtd_preparse.l
	radius_dict.l
	uat_load.l
)

add_lemon_files(LIBWIRESHARK_FILES
	dtd_grammar.lemon
)

set(epan_LIBS
	wiretap
	wsutil
#	@SSL_LIBS@
	${GLIB2_LIBRARIES}
	${PCAP_LIBRARIES}
#	@SOCKET_LIBS@
#	@NSL_LIBS@
	${CARES_LIBRARIES}
	${ADNS_LIBRARIES}
	${KERBEROS_LIBRARIES}
#	@FRAMEWORKS@
	${GEOIP_LIBRARIES}
	${GCRYPT_LIBRARIES}
	${GNUTLS_LIBRARIES}
	${SMI_LIBRARIES}
	${M_LIBRARIES}
	${LUA_LIBRARIES}
	${WIN_PSAPI_LIBRARY}
)

set(CLEAN_FILES
	# Needed to trigger build of the include files for x11
	#x11-declarations.h
	#x11-register-info.h
	${LIBWIRESHARK_CLEAN_FILES}
	${CRYPT_FILES}
	${DFILTER_CLEAN_FILES}
	${FTYPE_FILES}
	# ${DISSECTOR_FILES} contains dirty files
	${DISSECTOR_SRC}
	${PIDL_DISSECTOR_SRC}
	${ASN1_DISSECTOR_SRC}
	# ${DISSECTOR_FILES } end
	${DISSECTOR_SUPPORT_SRC}
	${LIBWIRESHARK_ASM_FILES}
	${WMEM_FILES}
	${WSLUA_FILES}
)

if (WERROR)
    set_source_files_properties(
	${CLEAN_FILES}
	PROPERTIES
	COMPILE_FLAGS -Werror
    )
endif()

add_library(epan ${LINK_MODE_LIB}
	# Needed to trigger build of the include files for x11
	#x11-declarations.h
	#x11-register-info.h
	${LIBWIRESHARK_FILES}
	${CRYPT_FILES}
	${DFILTER_FILES}
	${FTYPE_FILES}
	${WMEM_FILES}
	${WSLUA_FILES}
	${DISSECTOR_FILES}
	${DISSECTOR_SUPPORT_SRC}
	${LIBWIRESHARK_ASM_FILES}
	../image/libwireshark.rc
)

add_dependencies(epan gitversion)

set(FULL_SO_VERSION "0.0.0")

set_target_properties(epan PROPERTIES COMPILE_DEFINITIONS "WS_BUILD_DLL")
set_target_properties(epan PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(epan PROPERTIES VERSION ${FULL_SO_VERSION} SOVERSION 0)

ABICHECK(libwireshark)

file(GLOB CRYPT_HEADERS crypt/*.h)
file(GLOB DFILTER_HEADERS dfilter/*.h ../tools/lemon/cppmagic.h)
file(GLOB D_HEADERS dissectors/*.h)
file(GLOB FTYPES_HEADERS ftypes/*.h)
file(GLOB WMEM_HEADERS wmem/*.h)
file(MAKE_DIRECTORY ${ABICHECK_TMPDIR}
	${ABICHECK_TMPDIR}/epan
	${ABICHECK_TMPDIR}/crypt
	${ABICHECK_TMPDIR}/dfilter
	${ABICHECK_TMPDIR}/dissectors
	${ABICHECK_TMPDIR}/ftypes
	${ABICHECK_TMPDIR}/wmem)

file(COPY ../color.h ../register.h DESTINATION ${ABICHECK_TMPDIR})
file(COPY ${HEADERS} DESTINATION ${ABICHECK_TMPDIR}/epan)
file(COPY ${CRYPT_HEADERS} DESTINATION ${ABICHECK_TMPDIR}/crypt)
file(COPY ${DFILTER_HEADERS} DESTINATION ${ABICHECK_TMPDIR}/dfilter)
file(COPY ${D_HEADERS} DESTINATION ${ABICHECK_TMPDIR}/dissectors)
file(COPY ${FTYPES_HEADERS} DESTINATION ${ABICHECK_TMPDIR}/ftypes)
file(COPY ${WMEM_HEADERS} DESTINATION ${ABICHECK_TMPDIR}/wmem)

add_custom_command(OUTPUT libwireshark.abi.tar.gz
	COMMAND cp ../config.h ${ABICHECK_TMPDIR}
	COMMAND rm -f ${ABICHECK_TMPDIR}/dissectors/x11-extension-implementation.h
		${ABICHECK_TMPDIR}/dissectors/packet-rtps.h
		${ABICHECK_TMPDIR}/dissectors/x11-glx-render-enum.h
		${ABICHECK_TMPDIR}/dissectors/x11-register-info.h
		${ABICHECK_TMPDIR}/dissectors/packet-idmp.h
	COMMAND ${ABICHECK_COMMAND}
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps/libwireshark/libwireshark_* ${CMAKE_CURRENT_BINARY_DIR}/libwireshark.abi.tar.gz
	COMMAND rm -rf ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps ${ABICHECK_TMPDIR}/config.h
		${ABICHECK_TMPDIR}/epan/* ${ABICHECK_TMPDIR}/crypt/*
		${ABICHECK_TMPDIR}/dfilter/* ${ABICHECK_TMPDIR}/dissectors/*
		${ABICHECK_TMPDIR}/ftypes/* ${ABICHECK_TMPDIR}/wmem/*
	DEPENDS ${HEADERS}
		${CRYPT_HEADERS} ${DFILTER_HEADERS} ${D_HEADERS}
		${FTYPES_HEADERS} ${WMEM_HEADERS} epan)

# By default the name for a library with target name epan will be libepan,
# but Ethereal is now named Wireshark
SET_TARGET_PROPERTIES(epan PROPERTIES OUTPUT_NAME "wireshark")
set_target_properties(epan PROPERTIES FOLDER "DLLs")

target_link_libraries(epan ${epan_LIBS})

add_dependencies(epan lemon)

if(NOT ${ENABLE_STATIC})
	install(TARGETS epan
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	)
endif()

add_executable(wmem_test wmem/wmem_test.c ${WMEM_FILES})
target_link_libraries(wmem_test ${GLIB2_LIBRARIES})

add_executable(exntest exntest.c except.c)
target_link_libraries(exntest ${GLIB2_LIBRARIES})

add_executable(oids_test oids_test.c)
target_link_libraries(oids_test epan)

add_executable(reassemble_test reassemble_test.c)
target_link_libraries(reassemble_test epan)

add_executable(tvbtest tvbtest.c)
target_link_libraries(tvbtest epan)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
