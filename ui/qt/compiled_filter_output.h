/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COMPILEDFILTEROUTPUT_H
#define COMPILEDFILTEROUTPUT_H

#include "geometry_state_dialog.h"

#include <config.h>

#include <QList>
#include <QHash>
#include <QListWidgetItem>

typedef struct interface_tag interface_t;
typedef QList<interface_t *> InterfaceList;

namespace Ui {
class CompiledFilterOutput;
}

/**
 * @brief A dialog for displaying compiled capture filters for various network interfaces.
 */
class CompiledFilterOutput : public GeometryStateDialog
{
    Q_OBJECT

private:
    /** The list of network interfaces. */
    InterfaceList intList_;

    /** Pointer to the generated UI elements. */
    Ui::CompiledFilterOutput *ui;

    /** Hash map storing compiled filter results, keyed by interface name. */
    QHash<QString, QString> compile_results;

    /** Pointer to the copy push button. */
    QPushButton *copy_bt_;

    /**
     * @brief Sets the title of the dialog based on the context.
     */
    void setTitle();

#ifdef HAVE_LIBPCAP
    /**
     * @brief Compiles the capture filter for a specific network interface.
     * @param interface Pointer to the interface to compile the filter for.
     * @return True if compilation was successful, false otherwise.
     */
    bool compileFilter(const interface_t *interface);

    /**
     * @brief Compiles the capture filters for all loaded interfaces.
     */
    void compileFilters();
#endif

public:
    /**
     * @brief Constructs a new CompiledFilterOutput dialog.
     * @param parent The parent widget, defaults to 0.
     * @param intList Reference to the list of interfaces, defaults to a newly allocated InterfaceList.
     */
    explicit CompiledFilterOutput(QWidget *parent = 0, InterfaceList &intList = *new InterfaceList());

    /**
     * @brief Destroys the CompiledFilterOutput dialog.
     */
    ~CompiledFilterOutput();

private slots:
    /**
     * @brief Slot triggered when the currently selected interface in the list changes.
     * @param current The newly selected list widget item.
     * @param previous The previously selected list widget item.
     */
    void on_interfaceList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous);

    /**
     * @brief Slot triggered to copy the compiled filter text to the clipboard.
     */
    void copyFilterText();
};

#endif // COMPILEDFILTEROUTPUT_H
