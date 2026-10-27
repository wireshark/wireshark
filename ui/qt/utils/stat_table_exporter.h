/** @file
 *
 * Serialisation and file export of statistics tables
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STAT_TABLE_EXPORTER_H
#define STAT_TABLE_EXPORTER_H

#include <config.h>

#include <epan/stat_tap_ui.h>

#include <functional>

#include <QByteArray>
#include <QCoreApplication>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVariant>

class QWidget;

/**
 * @brief Serialises a statistics table to plain text, CSV, XML and YAML and saves it to a file.
 *
 * Shared by TapParameterDialog and the Distribution dialog so both produce identical output.
 */
class StatTableExporter
{
    Q_DECLARE_TR_FUNCTIONS(StatTableExporter)

public:
    /**
     * @brief A statistics table: title, headers and one list of cell values per row.
     */
    struct Table {
        QString title;                  ///< Table title, usually the window subtitle.
        QString file_name;              ///< Display name of the capture file.
        QStringList headers;            ///< Column header texts.
        QList<QList<QVariant>> rows;    ///< Cell values per row; empty rows are skipped on export.
    };

    /**
     * @brief Serialises a table in the given format.
     * @param format Target format (plain text, CSV, XML or YAML).
     * @param table The table to serialise.
     * @return The serialised table.
     */
    static QByteArray toByteArray(st_format_type format, const Table &table);

    /**
     * @brief Converts a QVariant cell value to a plain-text string.
     * @param var   The QVariant value to convert.
     * @param width Minimum field width for padding; 0 for no padding.
     * @return Plain-text representation of @p var.
     */
    static QString plainCell(const QVariant &var, int width = 0);

    /**
     * @brief Asks for a file name and format, serialises and writes the file.
     * @param parent    Parent widget of the file dialog and the error box.
     * @param serialize Called with the chosen format to produce the file contents.
     */
    static void saveAs(QWidget *parent, std::function<QByteArray(st_format_type)> serialize);
};

#endif // STAT_TABLE_EXPORTER_H
