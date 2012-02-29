#-------------------------------------------------
#
# Project created by QtCreator 2010-12-21T11:38:10
#
#-------------------------------------------------

QT += core gui

TARGET = qtshark
TEMPLATE = app

xxx {
    message( )
    message(CONFIG:)
    message(  $$CONFIG)
    message( )
}

unix {
    CONFIG += link_pkgconfig
    PKGCONFIG += \
        glib-2.0

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

    DESTDIR = wireshark-qt

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

SOURCES_WS_C = \
    ../../airpcap_loader.c \
    ../../alert_box.c     \
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
    ../../ui/util.c  \
    ../../version_info.c

unix:SOURCES_WS_C += ../../capture-pcap-util-unix.c
win32:SOURCES_WS_C += ../../capture-wpcap.c ../../capture_wpcap_packet.c

SOURCES_QT_CPP = \
    byte_view_tab.cpp \
    byte_view_text.cpp \
    capture_file_dialog.cpp \
    capture_info_dialog.cpp \
    capture_interface_dialog.cpp \
    color_dialog.cpp \
    color_utils.cpp \
    display_filter_combo.cpp \
    display_filter_edit.cpp \
    fileset_dialog.cpp \
    interface_tree.cpp \
    main.cpp \
    main_status_bar.cpp \
    main_welcome.cpp \
    main_window.cpp \
    monospace_font.cpp \
    packet_list.cpp \
    packet_list_model.cpp \
    packet_list_record.cpp \
    progress_dialog.cpp \
    proto_tree.cpp \
    qt_ui_utils.cpp \
    recent_file_status.cpp \
    simple_dialog_qt.cpp \
    wireshark_application.cpp \
    label_stack.cpp


HEADERS_WS_C  = \
    ../../wsutil/privileges.h

HEADERS_QT_CPP = \
    byte_view_tab.h \
    byte_view_text.h \
    capture_file_dialog.h \
    capture_info_dialog.h \
    capture_interface_dialog.h \
    color_dialog.h \
    color_utils.h \
    display_filter_combo.h \
    display_filter_edit.h \
    fileset_dialog.h \
    interface_tree.h \
    main_status_bar.h \
    main_welcome.h \
    main_window.h \
    monospace_font.h \
    packet_list.h \
    packet_list_model.h \
    packet_list_record.h \
    progress_dialog.h \
    proto_tree.h \
    qt_ui_utils.h \
    qt_ui_utils.h \
    recent_file_status.h \
    simple_dialog_qt.h \
    wireshark_application.h \
    label_stack.h

FORMS += main_window.ui

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

win32 {
    SOURCES += $$SOURCES_QT_CPP
    HEADERS += $$HEADERS_WS_C
    HEADERS += $$HEADERS_QT_CPP
    OBJECTS_WS_C = $$SOURCES_WS_C
    OBJECTS_WS_C ~= s/[.]c/.obj/g
    OBJECTS_WS_C ~= s,/,\\,g
} else {
## XXX: Shouldn't need to (re)compile WS_C sources ??
    SOURCES += $$SOURCES_WS_C
    SOURCES += $$SOURCES_QT_CPP
    HEADERS += $$HEADERS_WS_C
    HEADERS += $$HEADERS_QT_CPP
}

DEFINES += HAVE_CONFIG_H INET6 REENTRANT
unix:DEFINES += _U_=\"__attribute__((unused))\"

macx:QMAKE_LFLAGS += \
    -framework CoreServices \
    -framework ApplicationServices -framework CoreFoundation -framework CoreServices

unix:LIBS += -L../../lib -Wl,-rpath ../../lib -lwireshark -lwiretap -lwsutil \
    -lpcap -lportaudio
macx:LIBS += -Wl,-macosx_version_min,10.5 -liconv

# http://stackoverflow.com/questions/3984104/qmake-how-to-copy-a-file-to-the-output
unix: {
    EXTRA_BINFILES = \
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
        QMAKE_POST_LINK += $$quote(cp $${FILE} Wireshark.app/Contents/MacOS$$escape_expand(\\n\\t))
    }
}

win32 {
    # Add the wireshark objects to LIBS
    LIBS += $$OBJECTS_WS_C
    LIBS += $$PA_OBJECTS
    LIBS += \
        wsock32.lib user32.lib shell32.lib comctl32.lib \
        -L../../epan -llibwireshark -L../../wsutil -llibwsutil -L../../wiretap -lwiretap-1.7.0 \
        -L$${GLIB_DIR}/lib -lglib-2.0 -lgmodule-2.0

    EXTRA_BINFILES = \
        ../../dumpcap.exe \
        ../../epan/libwireshark.dll ../../wiretap/wiretap-1.7.0.dll ../../wsutil/libwsutil.dll \
        $${GLIB_DIR}/bin/libglib-2.0-0.dll $${GLIB_DIR}/bin/libgmodule-2.0-0.dll \
        $${GLIB_DIR}/bin/libgthread-2.0-0.dll $${GLIB_DIR}/bin/intl.dll \
        $${C_ARES_DIR}/bin/libcares-2.dll $${ZLIB_DIR}/zlib1.dll \
        $${GNUTLS_DIR}/bin/libgcrypt-11.dll $${GNUTLS_DIR}/bin/libgnutls-26.dll \
        $${GNUTLS_DIR}/bin/libgpg-error-0.dll $${GNUTLS_DIR}/bin/ $${GNUTLS_DIR}/bin/libtasn1-3.dll \
        $${GNUTLS_DIR}/bin/libintl-8.dll $${SMI_DIR}/bin/libsmi-2.dll \
        $${KFW_DIR}/bin/comerr32.dll $${KFW_DIR}/bin/krb5_32.dll $${KFW_DIR}/bin/k5sprt32.dll \
        $${LUA_DIR}/lua5.1.dll \
        ../../colorfilters ../../dfilters ../../cfilters

    EXTRA_BINFILES ~= s,/,\\,g
    for(FILE,EXTRA_BINFILES){
        QMAKE_POST_LINK +=$$quote($(COPY_FILE) $${FILE} $(DESTDIR)$$escape_expand(\\n\\t))
    }
    PLUGINS_DIR = $(DESTDIR)\\plugins\\$${VERSION}
    QMAKE_POST_LINK +=$$quote($(CHK_DIR_EXISTS) $${PLUGINS_DIR} $(MKDIR) $${PLUGINS_DIR}$$escape_expand(\\n\\t))
    QMAKE_POST_LINK +=$$quote($(COPY_FILE) ..\\..\\wireshark-gtk2\\plugins\\$${VERSION}\\*.dll $(DESTDIR)\\plugins\\$${VERSION}$$escape_expand(\\n\\t))

    # This doesn't depend on wireshark-gtk2. It also doesn't work.
    #PLUGINS_IN_PWD=$${IN_PWD}
    #PLUGINS_OUT_PWD=$${OUT_PWD}
    #QMAKE_POST_LINK +=$$quote(cd $$replace(PLUGINS_IN_PWD, /, \\)\\..\\..\\plugins$$escape_expand(\\n\\t))
    #QMAKE_POST_LINK +=$$quote(nmake -f Makefile.nmake INSTALL_DIR=$$replace(PLUGINS_OUT_PWD, /, \\)\\$(DESTDIR)$$escape_expand(\\n\\t))
    #QMAKE_POST_LINK +=$$quote(cd $$replace(PLUGINS_IN_PWD, /, \\)$$escape_expand(\\n\\t))

}


RESOURCES += \
    toolbar.qrc \
    welcome.qrc \
    display_filter.qrc

ICON = ../../packaging/macosx/Resources/Wireshark.icns

win32: QMAKE_CLEAN += *.pdb
