#-------------------------------------------------
#
# Project created by QtCreator 2010-12-21T11:38:10
#
#-------------------------------------------------
#
# $Id$
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



QT += core gui

TARGET = qtshark
TEMPLATE = app

# XXX - Need to autogenerate Info.plist from Info.plist.in
# QMAKE_INFO_PLIST = ../../packaging/macosx/Info.plist

xxx {
    message( )
    message(CONFIG:)
    message(  $$CONFIG)
    message( )
}

unix {

    #Check if Qt < 4.8.x (packagesExist is present in Qt >= 4.8)
    contains(QT_VERSION, ^4\\.[0-7]\\..*) {
        #Copy from mkspecs/features/qt_functions.prf (Qt 4.8)
        defineTest(packagesExist) {
            # this can't be done in global scope here because qt_functions is loaded
            # before the .pro is parsed, so if the .pro set PKG_CONFIG, we wouldn't know it
            # yet. oops.
            isEmpty(PKG_CONFIG):PKG_CONFIG = pkg-config # keep consistent with link_pkgconfig.prf! too

            for(package, ARGS) {
            !system($$PKG_CONFIG --exists $$package):return(false)
            }

        return(true)
        }
    }


    CONFIG += link_pkgconfig
    PKGCONFIG += \
        glib-2.0

    packagesExist(portaudio-2.0) {
        PKGCONFIG += portaudio-2.0
    }

    # Some versions of Ubuntu don't ship with zlib.pc
    eval(PKGCONFIG += zlib) {
        PKGCONFIG += zlib
    }
}

win32 {
    # Note:
    # Windows Wireshark is compiled with /MD and thus must
    #  be linked with the "release" versions of the Qt libraries
    #  which are also compiled with /MD.
    #
    # Also: Windows Wireshark is compiled with /Zi and linked with /DEBUG
    #  which enables source level Wireshark debugging using the
    #  Windows Visual Studio debugger.
    #  So: QMAKE_CFLAGS, QMAKE_CXXFLAGS and QMAKE_LFLAGS are set to match
    #  those used building Windows Wireshark. (See config.pri).
    #  Among other things source-level debugging of the Qt version of Wireshark
    # (including the ui/qt source) is thus enabled.
    #
    #  Note that in this case source level debugging of the Qt
    #  *libraries* will not be possible since the Qt release libs are
    #  not compiled with /Zi (and not linked with /DEBUG).
    #  The Qt "debug" libraries are compiled with /MDd. To build a
    #  Wireshark-Qt debug version with the ability to do source level debugging
    #  of the Qt libraries themselves requires that Wireshark first be built with /MDd.
    #  Presumably doing source-level Qt library debugging shoyuld rarely be needed.

    # We want to build only the QtShark linked with the QT "release" libraries
    #  so disable debug & etc.
##    CONFIG -= release
    CONFIG -= debug
    CONFIG -= debug_and_release

    # Use only Wireshark CFLAGS, CXXFLAGS and LDFLAGS from config.nmake (as provided via config.pri)
    #  for building the "release" version of Wireshark-Qt
    # (e.g., so we don't get the Qt release CFLAGS [specifically /O2]
    QMAKE_CFLAGS_RELEASE   = ""
    QMAKE_CXXFLAGS_RELEASE = ""
    QMAKE_LFLAGS_RELEASE   = ""

    # XXX We need to figure out how to pull this in from config.nmake.
    !include( config.pri ) {
        error("Can't find config.pri. Have you run 'nmake -f Makefile.nmake' two directories up?")
    }

    DESTDIR = ../../wireshark-qt

    !wireshark_manifest_info_required {
        CONFIG -= embed_manifest_dll
        CONFIG -= embed_manifest_exe
    }
}

INCLUDEPATH += ../.. ../../wiretap
win32:INCLUDEPATH += \
    $${WIRESHARK_LIB_DIR}/gtk2/include/glib-2.0 $${WIRESHARK_LIB_DIR}/gtk2/lib/glib-2.0/include \
    $${WIRESHARK_LIB_DIR}/WpdPack/Include \
    $${WIRESHARK_LIB_DIR}/AirPcap_Devpack_4_1_0_1622/Airpcap_Devpack/include \
    $${WIRESHARK_LIB_DIR}/zlib125/include

# We have to manually trigger relinking each time one of these is modified.
# Is there any way to do this automatically?
SOURCES_WS_C = \
    ../../airpcap_loader.c \
    ../../capture-pcap-util.c     \
    ../../capture.c       \
    ../../capture_ifinfo.c \
    ../../capture_info.c  \
    ../../capture_opts.c \
    ../../capture_sync.c  \
    ../../capture_ui_utils.c \
    ../../cfile.c \
    ../../clopts_common.c \
    ../../color_filters.c \
    ../../disabled_protos.c       \
    ../../file.c  \
    ../../fileset.c       \
    ../../filters.c       \
    ../../frame_data_sequence.c   \
    ../../g711.c \
    ../../merge.c \
    ../../packet-range.c  \
    ../../print.c \
    ../../proto_hier_stats.c      \
    ../../ps.c    \
    ../../recent.c \
    ../../summary.c       \
    ../../sync_pipe_write.c       \
    ../../tap-megaco-common.c     \
    ../../tap-rtp-common.c    \
    ../../tempfile.c      \
    ../../timestats.c     \
    ../../u3.c \
    ../../version_info.c

unix:SOURCES_WS_C += ../../capture-pcap-util-unix.c
win32:SOURCES_WS_C += \
    ../../capture-wpcap.c \
    ../../capture_wpcap_packet.c \
    ../../ui/win32/file_dlg_win32.c

HEADERS_WS_C  = \
    ../../wsutil/privileges.h

FORMS += main_window.ui \
    main_welcome.ui \
    import_text_dialog.ui \
    file_set_dialog.ui \
    packet_range_group_box.ui

win32 { ## These should be in config.pri ??
    !isEmpty(PORTAUDIO_DIR) {
        PA_OBJECTS = \
            ../gtk/pa_allocation.obj \
            ../gtk/pa_converters.obj \
            ../gtk/pa_cpuload.obj \
            ../gtk/pa_dither.obj \
            ../gtk/pa_front.obj \
            ../gtk/pa_process.obj \
            ../gtk/pa_skeleton.obj \
            ../gtk/pa_stream.obj \
            ../gtk/pa_trace.obj \
            ../gtk/pa_win_wmme.obj \
            ../gtk/pa_win_hostapis.obj \
            ../gtk/pa_win_util.obj \
            ../gtk/pa_win_waveformat.obj \
            ../gtk/pa_x86_plain_converters.obj
        PA_OBJECTS ~= s,/,\\,g
    }
}

HEADERS += $$HEADERS_WS_C

win32 {
    OBJECTS_WS_C = $$SOURCES_WS_C
    OBJECTS_WS_C ~= s/[.]c/.obj/g
    OBJECTS_WS_C ~= s,/,\\,g
    OBJECTS_WS_C += ../../image/file_dlg_win32.res
} else {
## XXX: Shouldn't need to (re)compile WS_C sources ??
    SOURCES += $$SOURCES_WS_C
}

DEFINES += INET6 REENTRANT
unix:DEFINES += _U_=\"__attribute__((unused))\"

macx:QMAKE_LFLAGS += \
    -framework CoreServices \
    -framework ApplicationServices -framework CoreFoundation -framework CoreServices

unix:LIBS += -L../../lib -Wl,-rpath ../../lib -lwireshark -lwiretap -lwsutil -lui \
    -lpcap
macx:LIBS += -Wl,-macosx_version_min,10.5 -liconv

# XXX Copy this only if we're linking with Lua.
EXTRA_BINFILES = \
    ../../epan/wslua/console.lua

# http://stackoverflow.com/questions/3984104/qmake-how-to-copy-a-file-to-the-output
unix: {
    EXTRA_BINFILES += \
        ../../dumpcap \
        ../../lib/*.so  \
}
unix:!macx {
    for(FILE,EXTRA_BINFILES){
        QMAKE_POST_LINK += $$quote(cp $${FILE} .$$escape_expand(\\n\\t))
    }
}
# qmake 2.01a / Qt 4.7.0 doesn't set DESTDIR on OS X.
macx {
    for(FILE,EXTRA_BINFILES){
        QMAKE_POST_LINK += $$quote(cp $${FILE} $${TARGET}.app/Contents/MacOS$$escape_expand(\\n\\t))
    }
}

win32 {
    # Add the wireshark objects to LIBS
    LIBS += $$OBJECTS_WS_C
    LIBS += $$PA_OBJECTS
    LIBS += \
        $${guilibsdll} $${HHC_LIBS} \
        -L../../epan -llibwireshark -L../../wsutil -llibwsutil -L../../wiretap -lwiretap-$${WTAP_VERSION} \
        -L.. -llibui \
        -L$${GLIB_DIR}/lib -lglib-2.0 -lgmodule-2.0

    !isEmpty(MSVCR_DLL) {
        EXTRA_BINFILES += \"$${MSVCR_DLL}\"
    }

    CONFIG(debug, debug|release) {
        EXTRA_BINFILES += \
            $$[QT_INSTALL_BINS]/QtCored4.dll \
            $$[QT_INSTALL_BINS]/QtGuid4.dll
    } else:CONFIG(release, debug|release) {
        EXTRA_BINFILES += \
            $$[QT_INSTALL_BINS]/QtCore4.dll \
            $$[QT_INSTALL_BINS]/QtGui4.dll
    }

    EXTRA_BINFILES += \
        ../../dumpcap.exe \
        ../../epan/libwireshark.dll ../../wiretap/wiretap-$${WTAP_VERSION}.dll ../../wsutil/libwsutil.dll \
        $${GLIB_DIR}/bin/libglib-2.0-0.dll $${GLIB_DIR}/bin/libgmodule-2.0-0.dll \
        $${GLIB_DIR}/bin/libgthread-2.0-0.dll $${GLIB_DIR}/bin/$${INTL_DLL} \
        $${C_ARES_DIR}/bin/libcares-2.dll $${ZLIB_DIR}/zlib1.dll \
        $${GNUTLS_DIR}/bin/libgcrypt-11.dll $${GNUTLS_DIR}/bin/libgnutls-26.dll \
        $${GNUTLS_DIR}/bin/libgpg-error-0.dll $${GNUTLS_DIR}/bin/libtasn1-3.dll \
        $${GNUTLS_DIR}/bin/libintl-8.dll $${SMI_DIR}/bin/libsmi-2.dll \
        $${LUA_DIR}/lua5.1.dll \
        $${GEOIP_DIR}/bin/libGeoIP-1.dll \
        ../../colorfilters ../../dfilters ../../cfilters

    wireshark_use_kfw {
        EXTRA_BINFILES += \
            $${KFW_DIR}/bin/comerr32.dll $${KFW_DIR}/bin/krb5_32.dll $${KFW_DIR}/bin/k5sprt32.dll
    }

    EXTRA_BINFILES ~= s,/,\\,g
    for(FILE,EXTRA_BINFILES){
        QMAKE_POST_LINK +=$$quote($(COPY_FILE) $${FILE} $(DESTDIR)$$escape_expand(\\n\\t))
    }
    PLUGINS_DIR = $(DESTDIR)\\plugins\\$${VERSION_FULL}
    QMAKE_POST_LINK +=$$quote($(CHK_DIR_EXISTS) $${PLUGINS_DIR} $(MKDIR) $${PLUGINS_DIR}$$escape_expand(\\n\\t))
    QMAKE_POST_LINK +=$$quote($(COPY_FILE) ..\\..\\wireshark-gtk2\\plugins\\$${VERSION_FULL}\\*.dll $(DESTDIR)\\plugins\\$${VERSION_FULL}$$escape_expand(\\n\\t))

    # This doesn't depend on wireshark-gtk2. It also doesn't work.
    #PLUGINS_IN_PWD=$${IN_PWD}
    #PLUGINS_OUT_PWD=$${OUT_PWD}
    #QMAKE_POST_LINK +=$$quote(cd $$replace(PLUGINS_IN_PWD, /, \\)\\..\\..\\plugins$$escape_expand(\\n\\t))
    #QMAKE_POST_LINK +=$$quote(nmake -f Makefile.nmake INSTALL_DIR=$$replace(PLUGINS_OUT_PWD, /, \\)\\$(DESTDIR)$$escape_expand(\\n\\t))
    #QMAKE_POST_LINK +=$$quote(cd $$replace(PLUGINS_IN_PWD, /, \\)$$escape_expand(\\n\\t))
}

RESOURCES += \
    ../../image/display_filter.qrc \
    ../../image/status.qrc \
    ../../image/toolbar.qrc \
    welcome.qrc \
    i18n.qrc

TRANSLATIONS = \
        qtshark_de.ts	\
        qtshark_fr.ts

ICON = ../../packaging/macosx/Resources/Wireshark.icns

RC_FILE = qtshark.rc

# http://lists.trolltech.com/qt-interest/2008-01/thread00516-0.html
# http://www.freehackers.org/thomas/2009/03/10/fixing-qmake-missing-rule-for-ts-qm/
!isEmpty(TRANSLATIONS) {

    isEmpty(QMAKE_LRELEASE) {
        win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]\lrelease.exe
        else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
    }

    isEmpty(TS_DIR):TS_DIR = Translations

    TSQM.name = lrelease ${QMAKE_FILE_IN}
    TSQM.input = TRANSLATIONS
    TSQM.output = $$TS_DIR/${QMAKE_FILE_BASE}.qm
    TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN}
    TSQM.CONFIG = no_link
    QMAKE_EXTRA_COMPILERS += TSQM
    PRE_TARGETDEPS += compiler_TSQM_make_all
} else {
    message(No translation files in project)
}

win32: QMAKE_CLEAN += *.pdb

HEADERS += \
    byte_view_tab.h \
    byte_view_text.h \
    capture_file_dialog.h \
    capture_info_dialog.h \
    capture_interface_dialog.h \
    color_dialog.h \
    color_utils.h \
    display_filter_combo.h \
    display_filter_edit.h \
    file_set_dialog.h \
    import_text_dialog.h \
    interface_tree.h \
    label_stack.h \
    main_status_bar.h \
    main_welcome.h \
    main_window.h \
    monospace_font.h \
    packet_list.h \
    packet_list_model.h \
    packet_list_record.h \
    packet_range_group_box.h \
    progress_bar.h \
    proto_tree.h \
    qt_ui_utils.h \
    qt_ui_utils.h \
    recent_file_status.h \
    simple_dialog_qt.h \
    sparkline_delegate.h \
    syntax_line_edit.h \
    wireshark_application.h

SOURCES += \
    byte_view_tab.cpp \
    byte_view_text.cpp \
    capture_file_dialog.cpp \
    capture_info_dialog.cpp \
    capture_interface_dialog.cpp \
    color_dialog.cpp \
    color_utils.cpp \
    display_filter_combo.cpp \
    display_filter_edit.cpp \
    file_set_dialog.cpp \
    import_text_dialog.cpp \
    interface_tree.cpp \
    label_stack.cpp \
    main.cpp \
    main_status_bar.cpp \
    main_welcome.cpp \
    main_window.cpp \
    main_window_slots.cpp \
    monospace_font.cpp \
    packet_list.cpp \
    packet_list_model.cpp \
    packet_list_record.cpp \
    packet_range_group_box.cpp \
    progress_bar.cpp \
    proto_tree.cpp \
    qt_ui_utils.cpp \
    recent_file_status.cpp \
    simple_dialog_qt.cpp \
    sparkline_delegate.cpp \
    syntax_line_edit.cpp \
    wireshark_application.cpp
