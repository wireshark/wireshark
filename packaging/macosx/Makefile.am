#
# This was disabled at one point, since the contents of the
# Clearlooks-Quicksilver-OSX directory exceed the 99-character file
# name limit imposed by the old tar format.  We now use ustar format,
# which doesn't have that limitation.
#
# To re-disable this file, remove "macosx" to SUBDIRS in ../Makefile.am and
# remove the entries for this Makefile.am and Info.plist from AC_OUTPUT
# in ../../configure.in.
#
MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	ChmodBPF/ChmodBPF	\
	ChmodBPF/org.wireshark.ChmodBPF.plist \
	dmg_background.png	\
	dmg_background.svg	\
	util_background.png	\
	util_background.svg	\
	dmg_set_style.scpt	\
	Info.plist	\
	Info.plist.in	\
	osx-app.sh	\
	osx-dmg.sh.in	\
	Read_me_first.rtf	\
	Scripts/chmodbpf-postinstall.sh	\
	Scripts/cli-preinstall.sh	\
	Scripts/cli-postinstall.sh	\
	Scripts/wireshark-postinstall.sh	\
	utility-launcher	\
	root.ds_store	\
	util.ds_store	\
	Wireshark.icns	\
	Wiresharkdoc.icns	\
	Wireshark_package.pmdoc/01wireshark-contents.xml	\
	Wireshark_package.pmdoc/01wireshark.xml		\
	Wireshark_package.pmdoc/02chmodbpf-contents.xml	\
	Wireshark_package.pmdoc/02chmodbpf.xml			\
	Wireshark_package.pmdoc/03utility-contents.xml		\
	Wireshark_package.pmdoc/03utility.xml			\
	Wireshark_package.pmdoc/index.xml.in


COPYING.txt: $(top_srcdir)/COPYING
	$(AM_V_GEN)cp $(top_srcdir)/COPYING $@

all: COPYING.txt

install: all

clean-local:
	rm -rf Utilities Wireshark.app COPYING.txt \
	    *.dmg *.pkg
