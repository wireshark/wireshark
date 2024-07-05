/* qt_ui_utils.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include <epan/addr_resolv.h>
#include <epan/range.h>
#include <epan/to_str.h>
#include <epan/value_string.h>

#include <ui/recent.h>
#include <ui/util.h>
#include "ui/ws_ui_util.h"

#include <wsutil/str_util.h>
#include <wsutil/file_util.h>

#include <QAction>
#include <QApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QFontDatabase>
#include <QProcess>
#include <QUrl>
#include <QScreen>

#if defined(Q_OS_MAC)
#include <ui/macosx/cocoa_bridge.h>
#elif !defined(Q_OS_WIN) && defined(QT_DBUS_LIB)
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusUnixFileDescriptor>
#endif

/*
 * We might want to create our own "wsstring" class with convenience
 * methods for handling g_malloc()ed strings, GStrings, and a shortcut
 * to .toUtf8().constData().
 */

char *qstring_strdup(QString q_string) {
    return g_strdup(qUtf8Printable(q_string));
}

QString gchar_free_to_qstring(char *glib_string) {
    return QString(gchar_free_to_qbytearray(glib_string));
}

QByteArray gchar_free_to_qbytearray(char *glib_string)
{
    QByteArray qt_bytearray(glib_string);
    g_free(glib_string);
    return qt_bytearray;
}

QByteArray gstring_free_to_qbytearray(GString *glib_gstring)
{
    QByteArray qt_ba(glib_gstring->str);
    g_string_free(glib_gstring, TRUE);
    return qt_ba;
}

QByteArray gbytearray_free_to_qbytearray(GByteArray *glib_array)
{
    QByteArray qt_ba(reinterpret_cast<char *>(glib_array->data), glib_array->len);
    g_byte_array_free(glib_array, true);
    return qt_ba;
}

const QString int_to_qstring(qint64 value, int field_width, int base)
{
    // Qt deprecated QString::sprintf in Qt 5.0, then added ::asprintf in
    // Qt 5.5. Rather than navigate a maze of QT_VERSION_CHECKs, just use
    // QString::arg.
    QString int_qstr;

    switch (base) {
    case 8:
        int_qstr = "0";
        break;
    case 16:
        int_qstr = "0x";
        break;
    default:
        break;
    }

    int_qstr += QString("%1").arg(value, field_width, base, QChar('0'));
    return int_qstr;
}

const QString address_to_qstring(const _address *address, bool enclose)
{
    QString address_qstr = QString();
    if (address) {
        if (enclose && address->type == AT_IPv6) address_qstr += "[";
        char *address_gchar_p = address_to_str(NULL, address);
        address_qstr += address_gchar_p;
        wmem_free(NULL, address_gchar_p);
        if (enclose && address->type == AT_IPv6) address_qstr += "]";
    }
    return address_qstr;
}

const QString address_to_display_qstring(const _address *address)
{
    QString address_qstr = QString();
    if (address) {
        char *address_gchar_p = address_to_display(NULL, address);
        address_qstr = address_gchar_p;
        wmem_free(NULL, address_gchar_p);
    }
    return address_qstr;
}

const QString val_to_qstring(const uint32_t val, const value_string *vs, const char *fmt)
{
    QString val_qstr;
    char* gchar_p = val_to_str_wmem(NULL, val, vs, fmt);
    val_qstr = gchar_p;
    wmem_free(NULL, gchar_p);

    return val_qstr;
}

const QString val_ext_to_qstring(const uint32_t val, value_string_ext *vse, const char *fmt)
{
    QString val_qstr;
    char* gchar_p = val_to_str_ext_wmem(NULL, val, vse, fmt);
    val_qstr = gchar_p;
    wmem_free(NULL, gchar_p);

    return val_qstr;
}

const QString range_to_qstring(const range_string *range)
{
    QString range_qstr = QString();
    if (range) {
        range_qstr += QString("%1-%2").arg(range->value_min).arg(range->value_max);
    }
    return range_qstr;
}

const QString bits_s_to_qstring(const double bits_s)
{
    return gchar_free_to_qstring(
                format_size(bits_s, FORMAT_SIZE_UNIT_NONE, FORMAT_SIZE_PREFIX_SI));
}

const QString file_size_to_qstring(const int64_t size)
{
    return gchar_free_to_qstring(
                format_size(size, FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI));
}

const QString time_t_to_qstring(time_t ti_time)
{
    QDateTime date_time = QDateTime::fromSecsSinceEpoch(qint64(ti_time));
    QString time_str = date_time.toLocalTime().toString("yyyy-MM-dd hh:mm:ss");
    return time_str;
}

QString html_escape(const QString plain_string) {
    return plain_string.toHtmlEscaped();
}


void smooth_font_size(QFont &font) {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QList<int> size_list = QFontDatabase::smoothSizes(font.family(), font.styleName());
#else
    QFontDatabase fdb;
    QList<int> size_list = fdb.smoothSizes(font.family(), font.styleName());
#endif

    if (size_list.size() < 2) return;

    int last_size = size_list.takeFirst();
    foreach (int cur_size, size_list) {
        if (font.pointSize() > last_size && font.pointSize() <= cur_size) {
            font.setPointSize(cur_size);
            return;
        }
        last_size = cur_size;
    }
}

bool qActionLessThan(const QAction * a1, const QAction * a2) {
    return a1->text().compare(a2->text()) < 0;
}

bool qStringCaseLessThan(const QString &s1, const QString &s2)
{
    return s1.compare(s2, Qt::CaseInsensitive) < 0;
}

void desktop_show_in_folder(const QString file_path)
{
    bool success = false;

    // https://stackoverflow.com/questions/3490336/how-to-reveal-in-finder-or-show-in-explorer-with-qt

#if defined(Q_OS_WIN)
    //
    // See
    //
    //    https://stackoverflow.com/questions/13680415/how-to-open-explorer-with-a-specific-file-selected
    //
    // for a way to do this using Windows Shell APIs, rather than having
    // to fire up a separate instance of Windows Explorer.
    //
    QString command = "explorer.exe";
    QStringList arguments;
    QString path = QDir::toNativeSeparators(file_path);
    arguments << "/select," << path + "";
    success = QProcess::startDetached(command, arguments);
#elif defined(Q_OS_MAC)
    CocoaBridge::showInFinder(file_path.toUtf8());
    success = true;
#elif defined(QT_DBUS_LIB)
    // First, try the FileManager1 DBus interface's "ShowItems" method.
    // https://www.freedesktop.org/wiki/Specifications/file-manager-interface/
    QDBusMessage message = QDBusMessage::createMethodCall(QLatin1String("org.freedesktop.FileManager1"),
                                                          QLatin1String("/org/freedesktop/FileManager1"),
                                                          QLatin1String("org.freedesktop.FileManager1"),
                                                          QLatin1String("ShowItems"));
    QStringList uris(QUrl::fromLocalFile(file_path).toString());
    message << uris << QString();

    message = QDBusConnection::sessionBus().call(message);
    success = message.type() == QDBusMessage::ReplyMessage;

    // If that failed, perhaps we are sandboxed.  Try using Portal Services.
    // https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.OpenURI.html
    if (!success) {
        const int fd = ws_open(QFile::encodeName(file_path), O_CLOEXEC | O_PATH, 0000);
        if (fd != -1) {
            QDBusUnixFileDescriptor descriptor;
            descriptor.giveFileDescriptor(fd);
            QDBusMessage message = QDBusMessage::createMethodCall(QLatin1String("org.freedesktop.portal.Desktop"),
                                                                  QLatin1String("/org/freedesktop/portal/desktop"),
                                                                  QLatin1String("org.freedesktop.portal.OpenURI"),
                                                                  QLatin1String("OpenDirectory"));
            message << QString() << QVariant::fromValue(descriptor) << QVariantMap();

            message = QDBusConnection::sessionBus().call(message);
            success = message.type() == QDBusMessage::ReplyMessage;
            ws_close(fd);
        }
    }
#else
    // Any other possibilities to highlight the file before falling back to showing the folder?
#endif
    if (!success) {
        QFileInfo file_info(file_path);
        QDesktopServices::openUrl(QUrl::fromLocalFile(file_info.dir().absolutePath()));
    }
}

bool rect_on_screen(const QRect &rect)
{
    foreach (QScreen *screen, qApp->screens()) {
        if (screen->availableGeometry().contains(rect)) {
            return true;
        }
    }

    return false;
}

void set_action_shortcuts_visible_in_context_menu(QList<QAction *> actions)
{
#if QT_VERSION < QT_VERSION_CHECK(5, 13, 0)
    // For QT_VERSION >= 5.13.0 we call styleHints()->setShowShortcutsInContextMenus(true)
    // in WiresharkApplication.
    // QTBUG-71471
    // QTBUG-61181
    foreach (QAction *action, actions) {
        action->setShortcutVisibleInContextMenu(true);
    }
#else
    Q_UNUSED(actions)
#endif
}

QVector<rtpstream_id_t *>qvector_rtpstream_ids_copy(QVector<rtpstream_id_t *> stream_ids)
{
    QVector<rtpstream_id_t *>new_ids;

    foreach(rtpstream_id_t *id, stream_ids) {
        rtpstream_id_t *new_id = g_new0(rtpstream_id_t, 1);
        rtpstream_id_copy(id, new_id);
        new_ids << new_id;
    }

    return new_ids;
}

void qvector_rtpstream_ids_free(QVector<rtpstream_id_t *> stream_ids)
{
    foreach(rtpstream_id_t *id, stream_ids) {
        rtpstream_id_free(id);
    }
}

QString make_filter_based_on_rtpstream_id(QVector<rtpstream_id_t *> stream_ids)
{
    QStringList stream_filters;
    QString filter;

    foreach(rtpstream_id_t *id, stream_ids) {
        QString ip_proto = id->src_addr.type == AT_IPv6 ? "ipv6" : "ip";
        stream_filters << QString("(%1.src==%2 && udp.srcport==%3 && %1.dst==%4 && udp.dstport==%5 && rtp.ssrc==0x%6)")
                         .arg(ip_proto) // %1
                         .arg(address_to_qstring(&id->src_addr)) // %2
                         .arg(id->src_port) // %3
                         .arg(address_to_qstring(&id->dst_addr)) // %4
                         .arg(id->dst_port) // %5
                         .arg(id->ssrc, 0, 16);
    }
    if (stream_filters.length() > 0) {
        filter = stream_filters.join(" || ");
    }

    return filter;
}

QString openDialogInitialDir()
{
    QString result;

    result = QString(get_open_dialog_initial_dir());
    QDir ld(result);
    if (ld.exists())
        return result;

    return QString();
}

void storeLastDir(QString dir)
{
    /* XXX - printable? */
    if (dir.length() > 0)
        set_last_open_dir(qUtf8Printable(dir));
}

