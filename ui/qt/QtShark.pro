#-------------------------------------------------
#
# Project created by QtCreator 2010-12-21T11:38:10
#
#-------------------------------------------------
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

isEqual(QT_MAJOR_VERSION, 4) {
    QT += core gui
} else {
    QT += core widgets printsupport
    win: QT += gui-private
}


macx {
    TARGET = Wireshark
} else {
    TARGET = qtshark
}

TEMPLATE = app

TOP_SRCDIR = "$$PWD/../.."

CONFIG(debug, debug|release) {
    DESTDIR = "$${TOP_SRCDIR}/wireshark-qt-debug"
}
CONFIG(release, debug|release) {
    DESTDIR = "$${TOP_SRCDIR}/wireshark-qt-release"
}

QMAKE_INFO_PLIST = "$$PWD/../../packaging/macosx/Info.plist"

xxx {
    message( )
    message(CONFIG:)
    message(  $$CONFIG)
    message( )
}

isEmpty (QMAKE_EXTENSION_SHLIB) {
    macx {
        QMAKE_EXTENSION_SHLIB=".dylib"
    } else: win32 {
        QMAKE_EXTENSION_SHLIB=".dll"
    } else { # Everyone else runs Linux or Solaris, right?
        QMAKE_EXTENSION_SHLIB=".so"
    }
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

    isEqual(QT_MAJOR_VERSION, 5) {
        # Hack around what appears to be a bug in the 5.0.2 SDK
        QT_CONFIG -= no-pkg-config
    }
    CONFIG += link_pkgconfig
    PKGCONFIG += \
        glib-2.0

    # Some versions of Ubuntu don't ship with zlib.pc
    !macx {
        eval(PKGCONFIG += zlib) {
            PKGCONFIG += zlib
        }
    }

    macx {
        packagesExist(Qt5MacExtras) {
            message( "Found Qt5MacExtras" )
            QT += macextras
        }
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

    !wireshark_manifest_info_required {
        CONFIG -= embed_manifest_dll
        CONFIG -= embed_manifest_exe
    }
}

SOURCES_TAP = \
    stats_tree_dialog.cpp

tap_register.name = Generate wireshark-tap-register.c
tap_register.input = SOURCES_TAP
tap_register.output = wireshark-tap-register.c
tap_register.variable_out = SOURCES
win32 {
    isEmpty(PYTHON) {
	tap_register.commands = $${SH} ../../tools/make-tapreg-dotc wireshark-tap-register.c . $$SOURCES_TAP
    } else {
	tap_register.commands = $${PYTHON} "../../tools/make-tap-reg.py" . taps $$SOURCES_TAP
    }
} else {
    tap_register.commands = python ../../tools/make-tap-reg.py . taps $$SOURCES_TAP
}
#tap_register.CONFIG += no_link
QMAKE_EXTRA_COMPILERS += tap_register

INCLUDEPATH += ../.. ../../wiretap
win32:INCLUDEPATH += \
    $${WIRESHARK_LIB_DIR}/gtk2/include/glib-2.0 $${WIRESHARK_LIB_DIR}/gtk2/lib/glib-2.0/include \
    $${WIRESHARK_LIB_DIR}/gtk3/include/glib-2.0 $${WIRESHARK_LIB_DIR}/gtk3/lib/glib-2.0/include \
    $${WIRESHARK_LIB_DIR}/WpdPack/Include \
    $${WIRESHARK_LIB_DIR}/AirPcap_Devpack_4_1_0_1622/Airpcap_Devpack/include \
    $${GNUTLS_DIR}/include \
    $${WIRESHARK_LIB_DIR}/zlib125/include

# We have to manually trigger relinking each time one of these is modified.
# Is there any way to do this automatically?
SOURCES_WS_C = \
    ../../airpcap_loader.c \
    ../../capture-pcap-util.c     \
    ../../capture.c       \
    ../../capture_info.c  \
    ../../capture_opts.c \
    ../../capture_ui_utils.c \
    ../../cfile.c \
    ../../clopts_common.c \
    ../../color_filters.c \
    ../../file.c  \
    ../../fileset.c       \
    ../../filters.c       \
    ../../frame_tvbuff.c   \
    ../../proto_hier_stats.c      \
    ../../summary.c       \
    ../../sync_pipe_write.c       \
    ../../version_info.c

unix:SOURCES_WS_C += ../../capture-pcap-util-unix.c
win32:SOURCES_WS_C += \
    ../../capture_win_ifnames.c \
    ../../capture-wpcap.c \
    ../../capture_wpcap_packet.c \
    ../../ui/win32/console_win32.c \
    ../../ui/win32/file_dlg_win32.c

HEADERS_WS_C  = \
    ../../wsutil/privileges.h

FORMS += \
    about_dialog.ui \
    capture_preferences_frame.ui \
    capture_interfaces_dialog.ui \
    column_preferences_frame.ui \
    compiled_filter_output.ui \
    decode_as_dialog.ui \
    export_object_dialog.ui \
    export_pdu_dialog.ui \
    file_set_dialog.ui \
    filter_expressions_preferences_frame.ui \
    follow_stream_dialog.ui \
    font_color_preferences_frame.ui \
    import_text_dialog.ui \
    io_graph_dialog.ui \
    layout_preferences_frame.ui \
    lbm_lbtrm_transport_dialog.ui \
    lbm_lbtru_transport_dialog.ui \
    lbm_stream_dialog.ui \
    lbm_uimflow_dialog.ui \
    main_welcome.ui \
    main_window.ui \
    main_window_preferences_frame.ui \
    module_preferences_scroll_area.ui \
    packet_comment_dialog.ui \
    packet_format_group_box.ui \
    packet_range_group_box.ui \
    preferences_dialog.ui \
    print_dialog.ui \
    profile_dialog.ui \
    sctp_all_assocs_dialog.ui   \
    sctp_assoc_analyse_dialog.ui \
    sctp_chunk_statistics_dialog.ui  \
    sctp_graph_dialog.ui  \
    sctp_graph_arwnd_dialog.ui  \
    sctp_graph_byte_dialog.ui  \
    search_frame.ui \
    sequence_dialog.ui \
    splash_overlay.ui \
    stats_tree_dialog.ui \
    summary_dialog.ui \
    time_shift_dialog.ui \
    uat_dialog.ui \
    tcp_stream_dialog.ui

HEADERS += $$HEADERS_WS_C \
    about_dialog.h \
    accordion_frame.h \
    capture_interfaces_dialog.h \
    capture_preferences_frame.h \
    column_preferences_frame.h \
    compiled_filter_output.h \
    decode_as_dialog.h \
    elided_label.h \
    export_dissection_dialog.h \
    export_object_dialog.h \
    export_pdu_dialog.h \
    filter_expressions_preferences_frame.h \
    follow_stream_dialog.h \
    follow_stream_text.h \
    font_color_preferences_frame.h \
    layout_preferences_frame.h \
    lbm_lbtrm_transport_dialog.h \
    lbm_lbtru_transport_dialog.h \
    lbm_stream_dialog.h \
    lbm_uimflow_dialog.h \
    main_window_preferences_frame.h \
    module_preferences_scroll_area.h \
    packet_comment_dialog.h \
    packet_format_group_box.h \
    preferences_dialog.h \
    print_dialog.h \
    profile_dialog.h \
    sctp_all_assocs_dialog.h  \
    sctp_assoc_analyse_dialog.h \
    sctp_chunk_statistics_dialog.h  \
    sctp_graph_dialog.h  \
    sctp_graph_arwnd_dialog.h  \
    sctp_graph_byte_dialog.h  \
    search_frame.h \
    splash_overlay.h \
    stats_tree_dialog.h \
    summary_dialog.h \
    tango_colors.h \
    uat_dialog.h \
    elided_label.h \
    tcp_stream_dialog.h

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
    -framework ApplicationServices \
    -framework CoreFoundation \
    -framework SystemConfiguration

unix {
    exists(../../epan/.libs/libw*) {
        message( "Assuming Autotools library paths" )
        LIBS += \
            -L.. \
            -L../../epan/.libs -Wl,-rpath ../../epan/.libs \
            -L../../wiretap/.libs -Wl,-rpath ../../wiretap/.libs \
            -L../../wsutil/.libs -Wl,-rpath ../../wsutil/.libs
    } else:exists(../../run/libw*) {
        message( "Assuming CMake library path" )
        LIBS += -L../../run -Wl,-rpath ../../run
    }

    LIBS += -lwireshark -lwiretap -lcapchild -lui -lcodecs -lwsutil \
    -lpcap

    exists(../libui_dirty.a) {
        LIBS += -lui_dirty
    }
}

macx:LIBS += -Wl,-macosx_version_min,10.6 -liconv -lz

# XXX Copy this only if we're linking with Lua.
EXTRA_BINFILES = \
    ../../epan/wslua/console.lua

# http://stackoverflow.com/questions/3984104/qmake-how-to-copy-a-file-to-the-output
unix: {

    exists(../../.libs/dumpcap) {
        EXTRA_BINFILES += \
            ../../.libs/dumpcap
        EXTRA_LIBFILES += \
            ../../epan/.libs/libwireshark*$$QMAKE_EXTENSION_SHLIB* \
            ../../wiretap/.libs/libwiretap*$$QMAKE_EXTENSION_SHLIB* \
            ../../wsutil/.libs/libwsutil*$$QMAKE_EXTENSION_SHLIB*
    } else:exists(../../run/libw*) {
        EXTRA_BINFILES += \
            ../../run/dumpcap
        EXTRA_LIBFILES += ../../run/libwireshark*$$QMAKE_EXTENSION_SHLIB* \
                        ../../run/libwiretap*$$QMAKE_EXTENSION_SHLIB* \
                        ../../run/libwsutil*$$QMAKE_EXTENSION_SHLIB*
    }

}
unix:!macx {
    EXTRA_BINFILES += $$EXTRA_LIBFILES
    for(FILE,EXTRA_BINFILES){
        QMAKE_POST_LINK += $$quote(cp $${FILE} .$$escape_expand(\\n\\t))
    }
}
# qmake 2.01a / Qt 4.7.0 doesn't set DESTDIR on OS X.
macx {
    MACOS_DIR = "$${DESTDIR}/$${TARGET}.app/Contents/MacOS"
    FRAMEWORKS_DIR = "$${DESTDIR}/$${TARGET}.app/Contents/Frameworks"

    for(FILE,EXTRA_BINFILES){
        QMAKE_POST_LINK += $$quote(cp -R $${FILE} $${MACOS_DIR}/$$escape_expand(\\n\\t))
    }

#    QMAKE_POST_LINK += $$quote($(MKDIR) $${FRAMEWORKS_DIR}/$$escape_expand(\\n\\t))
#    for(FILE,EXTRA_LIBFILES){
#        QMAKE_POST_LINK += $$quote(cp -R $${FILE} $${FRAMEWORKS_DIR}/$$escape_expand(\\n\\t))
#    }

    # Homebrew installs libraries read-only, which makes macdeployqt fail when
    # it tries to adjust paths. Work around this by running it twice.
    QMAKE_POST_LINK += $$quote(macdeployqt \"$${DESTDIR}/$${TARGET}.app\" || /bin/true$$escape_expand(\\n\\t))
    QMAKE_POST_LINK += $$quote(chmod 644 \"$${FRAMEWORKS_DIR}/\"*.dylib$$escape_expand(\\n\\t))
    QMAKE_POST_LINK += $$quote(macdeployqt -executable=\"$${MACOS_DIR}/dumpcap\" \"$${DESTDIR}/$${TARGET}.app\"$$escape_expand(\\n\\t))
    QMAKE_POST_LINK += $$quote(chmod 444 \"$${FRAMEWORKS_DIR}/\"*.dylib$$escape_expand(\\n\\t))
}

win32 {
    # Add the wireshark objects to LIBS
    LIBS += $$OBJECTS_WS_C
    LIBS += $$PA_OBJECTS
    LIBS += \
        $${guilibsdll} $${HHC_LIBS} \
        -L../../epan -llibwireshark -L../../wsutil -llibwsutil -L../../wiretap -lwiretap-$${WTAP_VERSION} \
        -L../../capchild -llibcapchild -L.. -llibui -L../../codecs -lcodecs \
        -L$${GLIB_DIR}/lib -lglib-2.0 -lgmodule-2.0 \
        -L$${ZLIB_DIR}/lib -lzdll \
        -L$${WINSPARKLE_DIR} -lWinSparkle

    !isEmpty(MSVCR_DLL) {
        EXTRA_BINFILES += \"$${MSVCR_DLL}\"
    }

    PLATFORM_DLL_DIR = $(DESTDIR)\\platforms
    CONFIG(debug, debug|release) {
        isEqual(QT_MAJOR_VERSION, 4) {
            EXTRA_DLLS = QtCored4 QtGuid4
        } else {
            EXTRA_DLLS = Qt5Cored Qt5Guid Qt5Widgetsd Qt5PrintSupportd
            EXTRA_PLATFORM_DLLS = qwindowsd
            QMAKE_POST_LINK +=$$quote($(CHK_DIR_EXISTS) $${PLATFORM_DLL_DIR} $(MKDIR) $${PLATFORM_DLL_DIR}$$escape_expand(\\n\\t))
        }
    }
    CONFIG(release, debug|release) {
        isEqual(QT_MAJOR_VERSION, 4) {
            EXTRA_DLLS = QtCore4 QtGui4
        } else {
            EXTRA_DLLS = Qt5Core Qt5Gui Qt5Widgets Qt5PrintSupport
            EXTRA_PLATFORM_DLLS = qwindows
            QMAKE_POST_LINK +=$$quote($(CHK_DIR_EXISTS) $${PLATFORM_DLL_DIR} $(MKDIR) $${PLATFORM_DLL_DIR}$$escape_expand(\\n\\t))
        }
    }
    for(DLL,EXTRA_DLLS){
        EXTRA_BINFILES += $$[QT_INSTALL_BINS]/$${DLL}.dll
    }
    INSTALL_PLATFORM_DIR = $$[QT_INSTALL_PLUGINS]/platforms
    INSTALL_PLATFORM_DIR ~= s,/,\\,g
    for(DLL,EXTRA_PLATFORM_DLLS){
        QMAKE_POST_LINK +=$$quote($(COPY_FILE) $${INSTALL_PLATFORM_DIR}\\$${DLL}.dll $${PLATFORM_DLL_DIR}$$escape_expand(\\n\\t))
        EXTRA_BINFILES +=
    }

    EXTRA_BINFILES += \
        ../../dumpcap.exe \
        ../../epan/libwireshark.dll ../../wiretap/wiretap-$${WTAP_VERSION}.dll ../../wsutil/libwsutil.dll \
        $${GLIB_DIR}/bin/libglib-2.0-0.dll $${GLIB_DIR}/bin/libgmodule-2.0-0.dll \
        $${GLIB_DIR}/bin/libgthread-2.0-0.dll $${GLIB_DIR}/bin/$${INTL_DLL} \
        $${C_ARES_DIR}/bin/libcares-2.dll $${ZLIB_DIR}/zlib1.dll \
        $${GNUTLS_DIR}/bin/libffi-6.dll $${GNUTLS_DIR}/bin/$$(GCC_DLL) \
        $${GNUTLS_DIR}/bin/libgcrypt-20.dll $${GNUTLS_DIR}/bin/libgmp-10.dll \
        $${GNUTLS_DIR}/bin/libgnutls-28.dll $${GNUTLS_DIR}/bin/$$(GPGERROR_DLL) \
        $${GNUTLS_DIR}/bin/libhogweed-2-4.dll $${GNUTLS_DIR}/bin/libnettle-4-6.dll \
        $${GNUTLS_DIR}/bin/libp11-kit-0.dll $${GNUTLS_DIR}/bin/libtasn1-6.dll \
        $${GNUTLS_DIR}/bin/libintl-8.dll $${SMI_DIR}/bin/libsmi-2.dll \
        $${LUA_DIR}/lua52.dll \
        $${GEOIP_DIR}/bin/libGeoIP-1.dll \
        $${WINSPARKLE_DIR}/WinSparkle.dll \
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
    QMAKE_POST_LINK +=$$quote($(COPY_FILE) ..\\..\\$${INSTALL_DIR}\\plugins\\$${VERSION_FULL}\\*.dll $(DESTDIR)\\plugins\\$${VERSION_FULL}$$escape_expand(\\n\\t))

    # This doesn't depend on wireshark-gtk2. It also doesn't work.
    #PLUGINS_IN_PWD=$${IN_PWD}
    #PLUGINS_OUT_PWD=$${OUT_PWD}
    #QMAKE_POST_LINK +=$$quote(cd $$replace(PLUGINS_IN_PWD, /, \\)\\..\\..\\plugins$$escape_expand(\\n\\t))
    #QMAKE_POST_LINK +=$$quote(nmake -f Makefile.nmake INSTALL_DIR=$$replace(PLUGINS_OUT_PWD, /, \\)\\$(DESTDIR)$$escape_expand(\\n\\t))
    #QMAKE_POST_LINK +=$$quote(cd $$replace(PLUGINS_IN_PWD, /, \\)$$escape_expand(\\n\\t))
}

RESOURCES += \
    ../../image/about.qrc \
    ../../image/display_filter.qrc \
    ../../image/layout.qrc \
    ../../image/status.qrc \
    ../../image/toolbar.qrc \
    i18n.qrc \
    welcome.qrc \


# qtshark_en should be pluralonly.
TRANSLATIONS = \
        qtshark_de.ts \
        qtshark_en.ts \
        qtshark_fr.ts \
        qtshark_pl.ts \
        qtshark_zh_CN.ts

ICON = ../../packaging/macosx/Resources/Wireshark.icns

RC_FILE = ../../image/wireshark.rc

# http://lists.trolltech.com/qt-interest/2008-01/thread00516-0.html
# http://www.freehackers.org/thomas/2009/03/10/fixing-qmake-missing-rule-for-ts-qm/
!isEmpty(TRANSLATIONS) {

    isEmpty(QMAKE_LRELEASE) {
        win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]\\lrelease.exe
        else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
    }

    isEmpty(TS_DIR):TS_DIR = Translations

    TSQM.name = lrelease ${QMAKE_FILE_IN}
    TSQM.input = TRANSLATIONS
    TSQM.output = $$TS_DIR/${QMAKE_FILE_BASE}.qm
    TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN}
    TSQM.CONFIG = no_link
#    QMAKE_EXTRA_COMPILERS += TSQM
#    PRE_TARGETDEPS += compiler_TSQM_make_all
} else {
    message(No translation files in project)
}

win32: QMAKE_CLEAN += *.pdb

HEADERS += \
    byte_view_tab.h \
    byte_view_text.h \
    capture_file_dialog.h \
    capture_filter_combo.h \
    capture_filter_edit.h \
    capture_filter_syntax_worker.h \
    capture_info_dialog.h \
    capture_interface_dialog.h \
    color_dialog.h \
    color_utils.h \
    display_filter_combo.h \
    display_filter_edit.h \
    file_set_dialog.h \
    import_text_dialog.h \
    interface_tree.h \
    io_graph_dialog.h \
    label_stack.h \
    main_status_bar.h \
    main_welcome.h \
    main_window.h \
    packet_list.h \
    packet_list_model.h \
    packet_list_record.h \
    packet_range_group_box.h \
    progress_bar.h \
    proto_tree.h \
    qt_ui_utils.h \
    qt_ui_utils.h \
    qcustomplot.h \
    recent_file_status.h \
    related_packet_delegate.h \
    sequence_diagram.h \
    sequence_dialog.h \
    simple_dialog_qt.h \
    sparkline_delegate.h \
    syntax_line_edit.h \
    time_shift_dialog.h \
    wireshark_application.h \


SOURCES += \
    about_dialog.cpp \
    accordion_frame.cpp \
    byte_view_tab.cpp \
    byte_view_text.cpp \
    capture_file_dialog.cpp \
    capture_filter_combo.cpp \
    capture_filter_edit.cpp \
    capture_filter_syntax_worker.cpp \
    capture_info_dialog.cpp \
    capture_interface_dialog.cpp \
    capture_interfaces_dialog.cpp \
    capture_preferences_frame.cpp \
    color_dialog.cpp \
    color_utils.cpp \
    column_preferences_frame.cpp \
    compiled_filter_output.cpp \
    decode_as_dialog.cpp \
    display_filter_combo.cpp \
    display_filter_edit.cpp \
    elided_label.cpp \
    export_dissection_dialog.cpp \
    export_object_dialog.cpp \
    export_pdu_dialog.cpp \
    file_set_dialog.cpp \
    filter_expressions_preferences_frame.cpp \
    follow_stream_dialog.cpp \
    follow_stream_text.cpp \
    font_color_preferences_frame.cpp \
    import_text_dialog.cpp \
    interface_tree.cpp \
    io_graph_dialog.cpp \
    label_stack.cpp \
    layout_preferences_frame.cpp \
    lbm_lbtrm_transport_dialog.cpp \
    lbm_lbtru_transport_dialog.cpp \
    lbm_stream_dialog.cpp \
    lbm_uimflow_dialog.cpp \
    main.cpp \
    main_status_bar.cpp \
    main_welcome.cpp \
    main_window.cpp \
    main_window_preferences_frame.cpp \
    main_window_slots.cpp \
    module_preferences_scroll_area.cpp \
    packet_comment_dialog.cpp \
    packet_format_group_box.cpp \
    packet_list.cpp \
    packet_list_model.cpp \
    packet_list_record.cpp \
    packet_range_group_box.cpp \
    preferences_dialog.cpp \
    print_dialog.cpp \
    profile_dialog.cpp \
    progress_bar.cpp \
    proto_tree.cpp \
    qcustomplot.cpp \
    qt_ui_utils.cpp \
    recent_file_status.cpp \
    related_packet_delegate.cpp \
    sctp_all_assocs_dialog.cpp  \
    sctp_assoc_analyse_dialog.cpp \
    sctp_chunk_statistics_dialog.cpp  \
    sctp_graph_dialog.cpp  \
    sctp_graph_arwnd_dialog.cpp  \
    sctp_graph_byte_dialog.cpp  \
    search_frame.cpp \
    sequence_diagram.cpp \
    sequence_dialog.cpp \
    simple_dialog_qt.cpp \
    sparkline_delegate.cpp \
    splash_overlay.cpp \
    stats_tree_dialog.cpp \
    summary_dialog.cpp \
    syntax_line_edit.cpp \
    time_shift_dialog.cpp \
    uat_dialog.cpp \
    wireshark_application.cpp \
    tcp_stream_dialog.cpp
