/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TAP_PARAMETER_DIALOG_H
#define TAP_PARAMETER_DIALOG_H

/*
 * @file Base class for statistics and analysis dialogs.
 * Provides convenience classes for command-line tap parameters ("-z ...")
 * and general tapping.
 */

#include "config.h"

#include <epan/stat_groups.h>
#include <epan/stat_tap_ui.h>

#include <QMenu>

#include "filter_action.h"
#include "wireshark_dialog.h"

class QHBoxLayout;
class QLineEdit;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;

namespace Ui {
class TapParameterDialog;
}

class TapParameterDialog;
/**
 * @brief Factory function signature for creating TapParameterDialog subclass instances.
 * @param parent  Parent widget for the new dialog.
 * @param cfg_str Configuration string identifying the tap (e.g. "afp,srt").
 * @param arg     Optional "-z" argument string passed on the command line.
 * @param cf      The current capture file.
 * @return        Pointer to the newly constructed TapParameterDialog subclass.
 */
typedef TapParameterDialog *(*tpdCreator)(QWidget &parent, const QString cfg_str,
                                          const QString arg, CaptureFile &cf);


/**
 * @brief Base class for statistics dialogs driven by a tap and an optional
 *        display filter, presenting results in a QTreeWidget and supporting
 *        filter actions, clipboard copy, and save-as export.
 */
class TapParameterDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the tap parameter dialog and registers it for retapping.
     * @param parent     Parent widget; must be a valid window.
     * @param cf         The current capture file to tap.
     * @param help_topic Wireshark help topic ID opened by the Help button; 0 for none.
     */
    explicit TapParameterDialog(QWidget &parent, CaptureFile &cf, int help_topic = 0);

    /**
     * @brief Destroys the dialog, deregisters the tap, and releases UI resources.
     */
    ~TapParameterDialog();

    /**
     * @brief Returns the action name string used to identify this dialog type in menus.
     * @return Reference to the static action name string.
     */
    static const QString &actionName() { return action_name_; }

    /**
     * @brief Registers a TapParameterDialog subclass so it can be opened via the
     *        statistics menu or the "-z" command-line option.
     * @param title      Menu display title for the statistics dialog.
     * @param cfg_abbr   Short configuration abbreviation used in "-z" arguments.
     * @param group      Statistics menu group the dialog belongs to.
     * @param tap_init_cb Tap initialisation callback invoked when the tap is registered.
     * @param creator    Factory function used to instantiate the dialog.
     */
    static void registerDialog(const QString title, const char *cfg_abbr,
                                register_stat_group_t group,
                                stat_tap_init_cb tap_init_cb,
                                tpdCreator creator);

    /**
     * @brief Finds or creates and shows the tap statistics dialog matching @p cfg_str.
     * @param parent  Parent widget for the dialog.
     * @param cf      The current capture file.
     * @param cfg_str Configuration string identifying the registered tap dialog.
     * @param arg     Optional "-z" argument string.
     * @return        Pointer to the shown TapParameterDialog, or @c nullptr on failure.
     */
    static TapParameterDialog *showTapParameterStatistics(QWidget &parent, CaptureFile &cf,
                                                           const QString cfg_str,
                                                           const QString arg, void *);

    // Needed by static member functions in subclasses. Should we just make
    // "ui" available instead?
    /**
     * @brief Returns the statistics results tree widget for use by subclasses.
     * @return Pointer to the internal QTreeWidget.
     */
    QTreeWidget *statsTreeWidget();

    /**
     * @brief Returns the display filter line edit widget for use by subclasses.
     * @return Pointer to the internal QLineEdit.
     */
    QLineEdit *displayFilterLineEdit();

    /**
     * @brief Returns the Apply Filter button for use by subclasses.
     * @return Pointer to the internal QPushButton.
     */
    QPushButton *applyFilterButton();

    /**
     * @brief Returns the main vertical layout for use by subclasses that need to
     *        insert additional widgets.
     * @return Pointer to the internal QVBoxLayout.
     */
    QVBoxLayout *verticalLayout();

    /**
     * @brief Returns the filter bar horizontal layout for use by subclasses.
     * @return Pointer to the internal QHBoxLayout.
     */
    QHBoxLayout *filterLayout();

    /**
     * @brief Triggers a full redraw of all tree items, typically called after the
     *        tap has finished accumulating data.
     */
    void drawTreeItems();

signals:
    /**
     * @brief Emitted when the user triggers a filter action from the context menu.
     * @param filter The filter expression to apply.
     * @param action The action to perform (apply, prepare, etc.).
     * @param type   The action type (selected, not selected, etc.).
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /**
     * @brief Emitted to push a new display filter to the main window filter bar.
     * @param filter The filter expression to apply.
     */
    void updateFilter(QString filter);

public slots:

protected:
    /**
     * @brief Shows the context menu with filter and tree collapse/expand actions.
     * @param event The context menu event carrying the cursor position.
     */
    void contextMenuEvent(QContextMenuEvent *event);

    /**
     * @brief Populates the context menu with filter actions for the selected tree item.
     */
    void addFilterActions();

    /**
     * @brief Adds "Collapse All" and "Expand All" actions to the context menu.
     */
    void addTreeCollapseAllActions();

    /**
     * @brief Returns the current display filter string from the filter line edit.
     * @return Current display filter expression, or an empty string if none is set.
     */
    QString displayFilter();

    /**
     * @brief Sets the display filter line edit to the given expression.
     * @param filter Filter expression to display.
     */
    void setDisplayFilter(const QString &filter);

    /**
     * @brief Sets the hint text shown below the tree widget.
     * @param hint Hint string to display; may be empty to clear the hint.
     */
    void setHint(const QString &hint);

    /**
     * @brief Controls whether packets are retapped when the dialog is first shown.
     *        RPC statistics dialogs should disable this to manage their own retap timing.
     * @param retap @c true to retap on first show (default); @c false to suppress.
     */
    void setRetapOnShow(bool retap);

    /**
     * @brief Retrieves the UI object.
     * @return Pointer to the UI object.
     */
    Ui::TapParameterDialog * getUI(void)
    {
        return (ui);
    }

protected slots:
    /**
     * @brief Applies the filter action associated with the triggered context menu action.
     */
    void filterActionTriggered();

    /** @brief Collapses all items in the statistics tree. */
    void collapseAllActionTriggered();

    /** @brief Expands all items in the statistics tree. */
    void expandAllActionTriggered();

    /**
     * @brief Refreshes the enabled/disabled state of UI widgets based on current
     *        capture and filter state.
     */
    void updateWidgets();

private:
    Ui::TapParameterDialog *ui;                  /**< Qt Designer-generated UI object. */
    QMenu                   ctx_menu_;            /**< Right-click context menu. */
    QList<QAction *>        filter_actions_;      /**< Filter actions added to the context menu. */
    int                     help_topic_;          /**< Wireshark help topic ID; 0 if none. */
    static const QString    action_name_;         /**< Static action name used for menu registration. */
    QTimer                 *show_timer_;          /**< Timer used to defer the initial retap until the dialog is visible. */

    /**
     * @brief Returns the display-filter expression derived from the currently selected
     *        tree item. Subclasses override this to provide item-specific filter strings.
     * @return Filter expression string, or an empty string if no filter applies.
     */
    virtual const QString filterExpression() { return QString(); }

    /**
     * @brief Converts a QVariant cell value to a plain-text string for clipboard export.
     * @param var   The QVariant value to convert.
     * @param width Minimum field width for padding; 0 for no padding.
     * @return Plain-text representation of @p var.
     */
    QString itemDataToPlain(QVariant var, int width = 0);

    /**
     * @brief Returns the column data for a tree item as an ordered list of QVariants,
     *        used for clipboard copy and save-as export. Subclasses may override to
     *        customise column ordering or formatting.
     * @return Ordered list of column values.
     */
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *) const;

    /**
     * @brief Serialises the full tree contents to a byte array in the given format.
     * @param format Target format (plain text, CSV, YAML, etc.).
     * @return Byte array containing the serialised tree data.
     */
    virtual QByteArray getTreeAsString(st_format_type format);

private slots:
    /**
     * @brief Pure virtual slot called by the constructor; subclasses must implement
     *        this to register their tap and populate the statistics tree.
     */
    virtual void fillTree() = 0;

    /**
     * @brief Applies the display filter entered in the filter line edit and retaps packets.
     */
    void on_applyFilterButton_clicked();

    /**
     * @brief Copies the tree contents as plain text to the system clipboard.
     */
    void on_actionCopyToClipboard_triggered();

    /**
     * @brief Opens a save-as dialog and exports the tree contents to a file.
     */
    void on_actionSaveAs_triggered();

    /**
     * @brief Opens the Wireshark help page for this dialog's registered help topic.
     */
    void on_buttonBox_helpRequested();
};

#endif // TAP_PARAMETER_DIALOG_H
