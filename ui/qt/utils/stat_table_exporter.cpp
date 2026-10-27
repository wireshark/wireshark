/* stat_table_exporter.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/stat_table_exporter.h>

#include <errno.h>

#ifdef Q_OS_WIN
#include <windows.h>
#include "ui/win32/file_dlg_win32.h"
#endif

#include "ui/util.h"
#include "wsutil/file_util.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"

#include <ui/qt/widgets/wireshark_file_dialog.h>

#include <QMessageBox>

QString StatTableExporter::plainCell(const QVariant &var, int width)
{
    QString plain_str;
    int align_mul = 1;

    switch (var.userType()) {
    case QMetaType::QString:
        align_mul = -1;
        // Fall through
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::LongLong:
    case QMetaType::ULongLong:
        plain_str = var.toString();
        break;
    case QMetaType::Double:
        plain_str = QString::number(var.toDouble(), 'f', 6);
        break;
    default:
        break;
    }

    if (plain_str.length() < width) {
        plain_str = QStringLiteral("%1").arg(plain_str, width * align_mul);
    }
    return plain_str;
}

const QString plain_sep_ = "  ";
QByteArray StatTableExporter::toByteArray(st_format_type format, const Table &table)
{
    QByteArray ba;

    QList<int> col_widths;
    QByteArray footer;

    // Title + header
    switch (format) {
    case ST_FORMAT_PLAIN:
    {
        // Column widths are only computed when there are rows.
        QString plain_header;
        if (!table.rows.isEmpty()) {
            for (int col = 0; col < table.headers.size(); col++) {
                col_widths.append(static_cast<int>(table.headers.at(col).length()));
                col_widths[col] = qMax(col_widths[col], static_cast<int>(plainCell(table.headers.at(col)).length()));
            }
        }
        QStringList ph_parts;
        for (int col = 0; col < table.headers.size() && col < col_widths.length(); col++) {
            ph_parts << table.headers.at(col);
        }
        plain_header = ph_parts.join(plain_sep_);

        QByteArray top_separator;
        top_separator.fill('=', plain_header.length());
        top_separator.append('\n');
        QString file_header = QStringLiteral("%1 - %2:\n").arg(table.title, table.file_name);
        footer.fill('-', plain_header.length());
        footer.append('\n');
        plain_header.append('\n');

        ba.append(top_separator);
        ba.append(file_header.toUtf8());
        ba.append(plain_header.toUtf8());
        ba.append(footer);
        break;
    }
    case ST_FORMAT_CSV:
    {
        QString csv_header;
        QStringList ch_parts;
        for (int col = 0; col < table.headers.size(); col++) {
            ch_parts << QStringLiteral("\"%1\"").arg(table.headers.at(col));
        }
        csv_header = ch_parts.join(",");
        csv_header.append('\n');
        ba.append(csv_header.toUtf8().constData());
        break;
    }
    case ST_FORMAT_XML:
    {
        // XXX What's a useful format? This mostly conforms to DocBook.
        ba.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        QString title = html_escape(table.title);
        QString xml_header = QStringLiteral("<table>\n<title>%1</title>\n").arg(title);
        ba.append(xml_header.toUtf8());
        ba.append("<thead>\n<row>\n");
        for (int col = 0; col < table.headers.size(); col++) {
            title = html_escape(table.headers.at(col));
            title = QStringLiteral("  <entry>%1</entry>\n").arg(title);
            ba.append(title.toUtf8());
        }
        ba.append("</row>\n</thead>\n");
        ba.append("<tbody>\n");
        footer = "</tbody>\n</table>\n";
        break;
    }
    case ST_FORMAT_YAML:
    {
        QString yaml_header;
        ba.append("---\n");
        yaml_header = QStringLiteral("Description: \"%1\"\nFile: \"%2\"\nItems:\n").arg(table.title).arg(table.file_name);
        ba.append(yaml_header.toUtf8());
        break;
    }
    default:
        break;
    }

    // Data
    for (const QList<QVariant> &tid : table.rows) {
        if (tid.length() < 1) {
            continue;
        }

        // Assume var length == columnCount
        QString line;
        QStringList parts;

        switch (format) {
        case ST_FORMAT_PLAIN:
        {
            int i = 0;
            foreach (QVariant var, tid) {
                parts << plainCell(var, col_widths[i]);
                i++;
            }
            line = parts.join(plain_sep_);
            line.append('\n');
            break;
        }
        case ST_FORMAT_CSV:
            foreach (QVariant var, tid) {
                if (var.userType() == QMetaType::QString) {
                    parts << QStringLiteral("\"%1\"").arg(var.toString());
                } else {
                    parts << var.toString();
                }
            }
            line = parts.join(",");
            line.append('\n');
            break;
        case ST_FORMAT_XML:
        {
            line = "<row>\n";
            foreach (QVariant var, tid) {
                QString entry = html_escape(var.toString());
                line.append(QStringLiteral("  <entry>%1</entry>\n").arg(entry));
            }
            line.append("</row>\n");
            break;
        }
        case ST_FORMAT_YAML:
        {
            int col = 0;
            QString indent = "-";
            foreach (QVariant var, tid) {
                QString entry;
                if (var.userType() == QMetaType::QString) {
                    entry = QStringLiteral("\"%1\"").arg(var.toString());
                } else {
                    entry = var.toString();
                }
                line.append(QStringLiteral("  %1 %2: %3\n").arg(indent).arg(table.headers.at(col), entry));
                indent = " ";
                col++;
            }
            break;
        }
        default:
            break;
        }

        ba.append(line.toUtf8());
    }

    // Footer
    ba.append(footer); // plain only?
    return ba;
}

void StatTableExporter::saveAs(QWidget *parent, std::function<QByteArray(st_format_type)> serialize)
{
    QString selectedFilter;
    st_format_type format;
    const char *file_ext;
    FILE *f;
    bool success = false;
    int last_errno;

#ifdef Q_OS_WIN
    HANDLE da_ctx = set_thread_per_monitor_v2_awareness();
#endif
    WiresharkFileDialog SaveAsDialog(parent, mainApp->windowTitleString(tr("Save Statistics As…")),
                                                            get_open_dialog_initial_dir());
    SaveAsDialog.setNameFilter(tr("Plain text file (*.txt);;"
                                    "Comma separated values (*.csv);;"
                                    "XML document (*.xml);;"
                                    "YAML document (*.yaml)"));
    SaveAsDialog.selectNameFilter(tr("Plain text file (*.txt)"));
    SaveAsDialog.setAcceptMode(QFileDialog::AcceptSave);
    int result = SaveAsDialog.exec();
#ifdef Q_OS_WIN
    revert_thread_per_monitor_v2_awareness(da_ctx);
#endif
    if (!result) {
        return;
    }
    selectedFilter= SaveAsDialog.selectedNameFilter();
    if (selectedFilter.contains("*.yaml", Qt::CaseInsensitive)) {
        format = ST_FORMAT_YAML;
        file_ext = ".yaml";
    }
    else if (selectedFilter.contains("*.xml", Qt::CaseInsensitive)) {
        format = ST_FORMAT_XML;
        file_ext = ".xml";
    }
    else if (selectedFilter.contains("*.csv", Qt::CaseInsensitive)) {
        format = ST_FORMAT_CSV;
        file_ext = ".csv";
    }
    else {
        format = ST_FORMAT_PLAIN;
        file_ext = ".txt";
    }

    // Get selected filename and add extension of necessary
    QString file_name = SaveAsDialog.selectedNativePath();
    if (!file_name.endsWith(file_ext, Qt::CaseInsensitive)) {
        file_name.append(file_ext);
    }

    QByteArray tree_as_ba = serialize(format);

    // actually save the file
    f = ws_fopen (file_name.toUtf8().constData(), "w");
    last_errno = errno;
    if (f) {
        if (fputs(tree_as_ba.data(), f) != EOF) {
            success = true;
        }
        last_errno = errno;
        fclose(f);
    }
    if (!success) {
        QMessageBox::warning(parent, tr("Error saving file %1").arg(file_name),
                             g_strerror (last_errno));
    }
}
