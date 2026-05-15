/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IO_GRAPH_ACTION_H
#define IO_GRAPH_ACTION_H

#include <ui/qt/utils/field_information.h>
#include <ui/io_graph_item.h>

#include <QAction>

/**
 * @brief An action to open the IO Graph dialog with specific unit and field configurations.
 */
class IOGraphAction : public QAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new IOGraphAction with a specific unit and field.
     * @param parent The parent QObject.
     * @param unit The IO graph item unit type (defaults to IOG_ITEM_UNIT_PACKETS).
     * @param field The specific protocol field string (defaults to an empty string).
     */
    explicit IOGraphAction(QObject *parent, io_graph_item_unit_t unit = IOG_ITEM_UNIT_PACKETS, QString field = QString());

    /**
     * @brief Constructs a new basic IOGraphAction.
     * @param parent The parent QObject.
     */
    explicit IOGraphAction(QObject *parent);

    /**
     * @brief Retrieves the configured IO graph item unit type.
     * @return The io_graph_item_unit_t value.
     */
    io_graph_item_unit_t unit() const { return unit_; }

    /**
     * @brief Retrieves the configured protocol field string.
     * @return The field string.
     */
    QString valueField() const { return field_; }

    /**
     * @brief Retrieves the string name of a specific IO graph unit type.
     * @param unit The IO graph item unit type.
     * @return The string name of the unit.
     */
    static const QString unitName(io_graph_item_unit_t unit);

    /**
     * @brief Retrieves a list of applicable unit types for a given header field.
     * @param headerinfo The header field information.
     * @return A list of valid io_graph_item_unit_t values.
     */
    static QList<io_graph_item_unit_t> unitTypes(const FieldInformation::HeaderInfo& headerinfo);

    /**
     * @brief Creates a context menu containing IO graph actions appropriate for a specific header field.
     * @param headerinfo The header field information.
     * @param parent The parent widget.
     * @return A pointer to the created QMenu.
     */
    static QMenu * createMenu(const FieldInformation::HeaderInfo& headerinfo, QWidget * parent);

signals:
    /**
     * @brief Signal emitted to open the IO Graph dialog with the specified parameters.
     * @param unit The IO graph item unit type to configure.
     * @param field The protocol field string to configure.
     */
    void openIOGraphDialog(io_graph_item_unit_t unit, QString field);

public slots:

private:
    /** The configured IO graph item unit type. */
    io_graph_item_unit_t unit_;

    /** The configured protocol field string. */
    QString field_;

private slots:

};

#endif // IO_GRAPH_ACTION_H
