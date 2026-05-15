/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAYFILTEREDIT_H
#define DISPLAYFILTEREDIT_H

#include <QDrag>
#include <QActionGroup>
#include <QPointer>

#include <ui/qt/widgets/syntax_line_edit.h>

class QEvent;
class StockIconToolButton;

typedef enum {
    DisplayFilterToApply,
    DisplayFilterToEnter,
    ReadFilterToApply,
    CustomColumnToEnter,
} DisplayFilterEditType;

/**
 * @brief A line edit widget specialized for entering, validating, and managing display filters.
 */
class DisplayFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new DisplayFilterEdit widget.
     * @param parent The parent widget, defaults to 0.
     * @param type The display filter edit type, defaults to DisplayFilterToEnter.
     */
    explicit DisplayFilterEdit(QWidget *parent = 0, DisplayFilterEditType type = DisplayFilterToEnter);

    /**
     * @brief Sets the type of the display filter edit widget.
     * @param type The display filter edit type to set.
     */
    void setType(DisplayFilterEditType type);

protected:
    /**
     * @brief Handles paint events for the widget.
     * @param evt The paint event details.
     */
    void paintEvent(QPaintEvent *evt);

    /**
     * @brief Handles resize events for the widget.
     */
    void resizeEvent(QResizeEvent *);

    /**
     * @brief Handles key press events and forwards them to the completion logic.
     * @param event The key press event details.
     */
    void keyPressEvent(QKeyEvent *event) { completionKeyPressEvent(event); }

    /**
     * @brief Handles focus in events and forwards them to the completion logic.
     * @param event The focus event details.
     */
    void focusInEvent(QFocusEvent *event) { completionFocusInEvent(event); }

    /**
     * @brief Handles focus out events for the widget.
     * @param event The focus event details.
     */
    void focusOutEvent(QFocusEvent *event);

    /**
     * @brief Handles drag enter events to accept valid drops.
     * @param event The drag enter event details.
     */
    virtual void dragEnterEvent(QDragEnterEvent *event);

    /**
     * @brief Handles drag move events for visual feedback.
     * @param event The drag move event details.
     */
    virtual void dragMoveEvent(QDragMoveEvent *event);

    /**
     * @brief Handles drop events containing filter data.
     * @param event The drop event details.
     */
    virtual void dropEvent(QDropEvent *event);

    /**
     * @brief Handles context menu events to display appropriate actions.
     * @param menu The context menu event details.
     */
    virtual void contextMenuEvent(QContextMenuEvent *menu);

public slots:
    /**
     * @brief Validates the syntax of the current display filter.
     * @return True if the filter is valid, false otherwise.
     */
    bool checkFilter();

    /**
     * @brief Updates the bookmark menu with current saved filters.
     */
    void updateBookmarkMenu();

    /**
     * @brief Applies the currently entered display filter.
     */
    void applyDisplayFilter();

    /**
     * @brief Updates the UI state indicating whether the display filter was successfully applied.
     * @param success True if the application succeeded, false otherwise.
     */
    void displayFilterSuccess(bool success);

    /**
     * @brief Sets the widget's style sheet.
     * @param style_sheet The style sheet string to apply.
     */
    void setStyleSheet(const QString &style_sheet);

private slots:
    /**
     * @brief Validates the syntax of a specific filter string.
     * @param filter_text The filter string to validate.
     */
    void checkFilter(const QString &filter_text);

    /**
     * @brief Clears the current display filter text.
     */
    void clearFilter();

    /**
     * @brief Handles generic state change events.
     * @param event The state change event details.
     */
    void changeEvent(QEvent* event);

    /**
     * @brief Opens the display filter expression dialog.
     */
    void displayFilterExpression();

    /**
     * @brief Saves the current filter to the bookmarks/saved list.
     */
    void saveFilter();

    /**
     * @brief Removes the current filter from the saved list.
     */
    void removeFilter();

    /**
     * @brief Displays the list of available display filters.
     */
    void showFilters();

    /**
     * @brief Opens the filter expression preferences dialog.
     */
    void showExpressionPrefs();

    /**
     * @brief Applies or prepares the currently entered filter based on its context.
     */
    void applyOrPrepareFilter();

    /**
     * @brief Triggers an action to adjust the alignment of the buttons.
     */
    void triggerAlignementAction();

    /**
     * @brief Connects necessary signals and slots to the main application window.
     */
    void connectToMainWindow();

private:
    /** The type classification of the display filter edit widget. */
    DisplayFilterEditType type_;

    /** The placeholder text displayed when the line edit is empty. */
    QString placeholder_text_;

    /** Action to save the current filter. */
    QAction *save_action_;

    /** Action to remove the current filter. */
    QAction *remove_action_;

    /** Group of related filter management actions. */
    QActionGroup * actions_;

    /** Pointer to the bookmark tool button. */
    QPointer<StockIconToolButton> bookmark_button_;

    /** Pointer to the clear tool button. */
    QPointer<StockIconToolButton> clear_button_;

    /** Pointer to the apply tool button. */
    QPointer<StockIconToolButton> apply_button_;

    /** Flag indicating whether action buttons are aligned to the left. */
    bool leftAlignActions_;

    /** The text of the last successfully applied filter. */
    QString last_applied_;

    /** Preamble text before the current word being completed. */
    QString filter_word_preamble_;

    /** Flag indicating if the autocompletion currently accepts a field. */
    bool autocomplete_accepts_field_;

    /** The active style sheet string applied to the widget. */
    QString style_sheet_;

    /**
     * @brief Sets the default placeholder text for the widget.
     */
    void setDefaultPlaceholderText();

    /**
     * @brief Builds a list of auto-completion suggestions for the given field word.
     * @param field_word The word currently being typed.
     * @param preamble The preceding text before the field word.
     */
    void buildCompletionList(const QString &field_word, const QString &preamble);

    /**
     * @brief Creates and displays a menu when a filter string is dropped on the widget.
     * @param event The drop event.
     * @param prepare True to only prepare the filter without applying.
     * @param filterText The text of the filter being dropped (defaults to an empty string).
     */
    void createFilterTextDropMenu(QDropEvent *event, bool prepare, QString filterText = QString());

    /**
     * @brief Aligns the action buttons within the widget layout.
     */
    void alignActionButtons();

    /**
     * @brief Updates the visibility and state of the clear button.
     */
    void updateClearButton();

signals:
    /**
     * @brief Signal emitted to push a status message regarding filter syntax.
     * @param msg The status message string.
     */
    void pushFilterSyntaxStatus(const QString& msg);

    /**
     * @brief Signal emitted to pop (remove) the last filter syntax status message.
     */
    void popFilterSyntaxStatus();

    /**
     * @brief Signal emitted to request packet filtering with a new filter string.
     * @param new_filter The new filter string to apply.
     * @param force True to force the application even if the string hasn't changed.
     */
    void filterPackets(QString new_filter, bool force);

    /**
     * @brief Signal emitted to request displaying the preferences dialog.
     * @param pane_name The specific preference pane to open.
     */
    void showPreferencesDialog(QString pane_name);

};

#endif // DISPLAYFILTEREDIT_H
