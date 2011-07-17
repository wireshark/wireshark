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
	ChmodBPF/README.macosx	\
	ChmodBPF/StartupParameters.plist	\
	dmg_background.png	\
	dmg_background.svg	\
	util_background.png	\
	util_background.svg	\
	dmg_set_style.scpt	\
	Info.plist	\
	Info.plist.in	\
	native-gtk/build-gtk.sh	\
	native-gtk/config.h	\
	native-gtk/glibconfig.h	\
	osx-app.sh	\
	osx-build.sh	\
	osx-dmg.sh	\
	Read_me_first.rtf	\
	Resources/bin/getdisplay.sh	\
	Resources/bin/wireshark	\
	Resources/etc/fonts/fonts.conf	\
	Resources/MenuBar.nib/classes.nib	\
	Resources/MenuBar.nib/info.nib	\
	Resources/MenuBar.nib/objects.xib	\
	Resources/openDoc	\
	Resources/ProgressWindow.nib/classes.nib	\
	Resources/ProgressWindow.nib/info.nib	\
	Resources/ProgressWindow.nib/objects.xib	\
	Resources/script	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/gtkrc	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/pre_gtkrc	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars/stepper-down.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars/stepper-left.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars/stepper-right.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars/stepper-up.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars/trough-scrollbar-horiz.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars/trough-scrollbar-vert.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_1/copy-slider.sh	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_1/slider-horiz-prelight.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_1/slider-horiz.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_1/slider-vert-prelight.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_1/slider-vert.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_6/copy-slider.sh	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_6/slider-horiz-prelight.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_6/slider-horiz.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_6/slider-vert-prelight.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/Scrollbars_6/slider-vert.png	\
	Resources/themes/Clearlooks-Quicksilver-OSX/gtk-2.0/sync_osx_look.sh	\
	Resources/Wireshark.icns	\
	Resources/Wiresharkdoc.icns	\
	ScriptExec/English.lproj/InfoPlist.strings	\
	ScriptExec/English.lproj/main.nib/classes.nib	\
	ScriptExec/English.lproj/main.nib/info.nib	\
	ScriptExec/English.lproj/main.nib/objects.xib	\
	ScriptExec/Info.plist	\
	ScriptExec/main.c	\
	ScriptExec/MenuBar.nib/classes.nib	\
	ScriptExec/MenuBar.nib/info.nib	\
	ScriptExec/MenuBar.nib/objects.xib	\
	ScriptExec/openDoc	\
	ScriptExec/script	\
	ScriptExec/ScriptExec.xcode/project.pbxproj	\
	ScriptExec/ScriptExec.xcodeproj/project.pbxproj	\
	ScriptExec/ScriptExec_Prefix.pch	\
	ScriptExec/version.plist	\
	Scripts/chmodbpf-postinstall.sh	\
	Scripts/cli-postinstall.sh	\
	Scripts/wireshark-postinstall.sh	\
	utility-launcher	\
	root.ds_store	\
	util.ds_store

COPYING.txt: ../../COPYING
	cp $< $@

all: COPYING.txt

install: all

clean-local:
	rm -rf Utilities Wireshark.app ScriptExec/build COPYING.txt \
	    *.dmg *.pkg
