#-------------------------------------------------
#
# Project created by QtCreator 2010-12-21T11:38:10
#
#-------------------------------------------------

QT += core gui

TARGET = Wireshark
TEMPLATE = app

unix {
    CONFIG += link_pkgconfig
    PKGCONFIG += \
        glib-2.0

    # Some versions of Ubuntu don't ship with zlib.pc
    eval(PKGCONFIG += zlib) {
        PKGCONFIG += zlib
    }
}

# XXX We need to figure out how to pull this in from config.nmake.
win32:WIRESHARK_LIB_DIR = c:/wireshark-win32-libs
win32:GLIB_DIR = $${WIRESHARK_LIB_DIR}/gtk2
win32:C_ARES_DIR = $${WIRESHARK_LIB_DIR}/c-ares-1.7.1-win32ws
win32:ZLIB_DIR = $${WIRESHARK_LIB_DIR}/zlib125
win32:GNUTLS_DIR = $${WIRESHARK_LIB_DIR}/gnutls-2.10.3-1.11-win32ws
win32:SMI_DIR = $${WIRESHARK_LIB_DIR}/libsmi-svn-40773-win32ws
win32:KFW_DIR = $${WIRESHARK_LIB_DIR}/kfw-3-2-2-i386-ws-vc6
win32:LUA_DIR = $${WIRESHARK_LIB_DIR}/lua5.1.4

INCLUDEPATH += ../.. ../../wiretap
win32:INCLUDEPATH += \
    $${WIRESHARK_LIB_DIR}/gtk2/include/glib-2.0 $${WIRESHARK_LIB_DIR}/gtk2/lib/glib-2.0/include \
    $${WIRESHARK_LIB_DIR}/WpdPack/Include \
    $${WIRESHARK_LIB_DIR}/AirPcap_Devpack_4_1_0_1622/Airpcap_Devpack/include \
    $${WIRESHARK_LIB_DIR}/zlib125/include

# XXX - If we add ../../gtk/recent.c to SOURCES, jom will try to compile everything
# in ../../gtk. Until we move the things we need in recent.c to a common file, simply
# copy it to our current directory.
recent.target = recent.c
!win32:recent.commands = $$QMAKE_COPY ../../gtk/$$recent.target .
win32:recent.commands = $$QMAKE_COPY ..\\..\\gtk\\$$recent.target .
recent.depends = ../../gtk/$$recent.target
QMAKE_EXTRA_TARGETS += recent

SOURCES += \
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
    ../../summary.c       \
    ../../sync_pipe_write.c       \
    ../../tap-megaco-common.c     \
    ../../tap-rtp-common.c    \
    ../../tempfile.c      \
    ../../timestats.c     \
    ../../u3.c \
    ../../util.c  \
    ../../version_info.c \
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
    recent.c \
    recent_file_status.cpp \
    simple_dialog_qt.cpp \
    wireshark_application.cpp \


unix:SOURCES += ../../capture-pcap-util-unix.c
win32:SOURCES += ../../capture-wpcap.c ../../capture_wpcap_packet.c

HEADERS  += \
    ../../wsutil/privileges.h \
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


FORMS += main_window.ui

DEFINES += HAVE_CONFIG_H INET6 REENTRANT
unix:DEFINES += _U_=\"__attribute__((unused))\"
win32:DEFINES += \
    MSVC_VARIANT=MSVC2010 MSC_VER_REQUIRED=1600 \
    _U_= _NEED_VAR_IMPORT_ \
    _CRT_SECURE_NO_DEPRECATE _CRT_NONSTDC_NO_DEPRECATE _BIND_TO_CURRENT_CRT_VERSION=1 \


# We need to pull in config.nmake somehow.
#win32:DEFINES += MSC_VER_REQUIRED=1600 _U_= IPV6STRICT
win32:WIRESHARK_LOCAL_CFLAGS = \
    /Zi /W3 /MD /DWIN32_LEAN_AND_MEAN \
    /MP /GS
win32:QMAKE_CFLAGS += $${WIRESHARK_LOCAL_CFLAGS}
win32:QMAKE_CXXFLAGS += $${WIRESHARK_LOCAL_CFLAGS}

# http://stackoverflow.com/questions/3984104/qmake-how-to-copy-a-file-to-the-output
unix:!mac {
    EXTRA_BINFILES = \
        ../../dumpcap \

    for(FILE,EXTRA_BINFILES){
        QMAKE_POST_LINK += $$quote(cp $${FILE} .$$escape_expand(\n\t))
    }
}
# qmake 2.01a / Qt 4.7.0 doesn't set DESTDIR on OS X.
mac {
    EXTRA_BINFILES = \
        ../../dumpcap \

    for(FILE,EXTRA_BINFILES){
        QMAKE_POST_LINK += $$quote(cp $${FILE} Wireshark.app/Contents/MacOS$$escape_expand(\n\t))
    }
}
win32 {
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
        message("$${DESTDIR_WIN}")
        QMAKE_POST_LINK +=$$quote(cmd /c copy /y $${FILE} $(DESTDIR)$$escape_expand(\n\t))
    }
}

macx:QMAKE_LFLAGS += \
    -framework CoreServices \
    -framework ApplicationServices -framework CoreFoundation -framework CoreServices

unix:LIBS += -L../../lib -Wl,-rpath ../../lib -lwireshark -lwiretap -lwsutil \
    -lpcap
macx:LIBS += -Wl,-macosx_version_min,10.5 -liconv

win32:LIBS += \
    wsock32.lib user32.lib shell32.lib comctl32.lib \
    -L../../epan -llibwireshark -L../../wsutil -llibwsutil -L../../wiretap -lwiretap-1.7.0 \
    -L$${GLIB_DIR}/lib -lglib-2.0 -lgmodule-2.0

RESOURCES += \
    toolbar.qrc \
    welcome.qrc \
    display_filter.qrc

ICON = ../../packaging/macosx/Resources/Wireshark.icns
