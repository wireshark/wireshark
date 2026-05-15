/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_EDIT_H
#define CAPTURE_FILTER_EDIT_H

#include <QThread>
#include <QToolButton>
#include <QActionGroup>

#include <ui/qt/widgets/syntax_line_edit.h>

class CaptureFilterSyntaxWorker;
class StockIconToolButton;

/**
 * @brief A line edit widget specialized for editing, validating, and managing capture filters.
 */
class CaptureFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new CaptureFilterEdit widget.
     * @param parent The parent widget, defaults to 0.
     * @param plain If true, creates a plain line edit without extra filter action buttons; defaults to false.
     */
    explicit CaptureFilterEdit(QWidget *parent = 0, bool plain = false);

    /**
     * @brief Destroys the CaptureFilterEdit widget.
     */
    ~CaptureFilterEdit();

    /**
     * @brief Sets the visual conflict state of the capture filter edit.
     * @param conflict True to indicate a conflict state, false otherwise (defaults to false).
     */
    void setConflict(bool conflict = false);

    /**
     * @brief Gets the currently selected filter from the UI state.
     *
     * Returns varying pairs based on selection state:
     * - No selections: (QString(), false)
     * - Selections, same filter: (filter, false)
     * - Selections, different filters: (QString(), true)
     *
     * @return A QPair containing the filter string and a boolean indicating if multiple differing filters are selected.
     */
    static QPair<const QString, bool> getSelectedFilter();

protected:
    /**
     * @brief Handles paint events for the widget.
     * @param evt The paint event.
     */
    void paintEvent(QPaintEvent *evt);

    /**
     * @brief Handles resize events for the widget.
     * @param event The resize event.
     */
    void resizeEvent(QResizeEvent *event);

    /**
     * @brief Handles key press events, forwarding to completion logic.
     * @param event The key press event.
     */
    void keyPressEvent(QKeyEvent *event) { completionKeyPressEvent(event); }

    /**
     * @brief Handles focus in events, forwarding to completion logic.
     * @param event The focus event.
     */
    void focusInEvent(QFocusEvent *event) { completionFocusInEvent(event); }

public slots:
    /**
     * @brief Triggers a syntax check of the current filter text.
     */
    void checkFilter();

    /**
     * @brief Updates the bookmark menu with current saved filters.
     */
    void updateBookmarkMenu();

    /**
     * @brief Saves the current filter to the bookmarks/saved filters list.
     */
    void saveFilter();

    /**
     * @brief Removes the current filter from the saved filters list.
     */
    void removeFilter();

    /**
     * @brief Displays the list of available filters.
     */
    void showFilters();

    /**
     * @brief Prepares the filter string for application.
     */
    void prepareFilter();

private slots:
    /**
     * @brief Applies the currently entered capture filter.
     */
    void applyCaptureFilter();

    /**
     * @brief Checks the syntax of a specific filter string.
     * @param filter The filter string to check.
     */
    void checkFilter(const QString &filter);

    /**
     * @brief Sets the syntax validation state for a filter.
     * @param filter The filter string.
     * @param state The syntax state code.
     * @param err_msg Error message if the syntax is invalid.
     */
    void setFilterSyntaxState(QString filter, int state, QString err_msg);

    /**
     * @brief Handles a click on the bookmark button.
     */
    void bookmarkClicked();

    /**
     * @brief Clears the current filter text.
     */
    void clearFilter();

private:
    /**
     * @brief Updates internal filter state based on user input.
     */
    void updateFilter();

    bool plain_;                                 /**< Flag indicating if the widget is in plain mode. */
    bool field_name_only_;                       /**< Flag indicating if only field names are allowed. */
    bool enable_save_action_;                    /**< Flag enabling the save filter action. */
    QString placeholder_text_;                   /**< The placeholder text displayed when empty. */
    QAction *save_action_;                       /**< Action to save the current filter. */
    QAction *remove_action_;                     /**< Action to remove the current filter. */
    QActionGroup * actions_;                     /**< Group of actions for filter management. */
    StockIconToolButton *bookmark_button_;       /**< Button to access filter bookmarks. */
    StockIconToolButton *clear_button_;          /**< Button to clear the filter text. */
    StockIconToolButton *apply_button_;          /**< Button to apply the capture filter. */
    CaptureFilterSyntaxWorker *syntax_worker_;   /**< Worker object for background syntax checking. */
    QThread *syntax_thread_;                     /**< Thread running the syntax checking worker. */
    QTimer *line_edit_timer_;                    /**< Timer used to delay syntax checks during typing. */

    /**
     * @brief Builds a list of auto-completion suggestions.
     * @param primitive_word The base primitive word being typed.
     * @param preamble The preceding text before the primitive word.
     */
    void buildCompletionList(const QString &primitive_word, const QString &preamble);

signals:
    /**
     * @brief Signal emitted when the filter syntax validity changes.
     * @param valid True if the current filter syntax is valid, false otherwise.
     */
    void captureFilterSyntaxChanged(bool valid);

    /**
     * @brief Signal emitted when the capture filter text changes.
     * @param filter The new filter string.
     */
    void captureFilterChanged(const QString filter);

    /**
     * @brief Signal emitted to request starting a capture using the current filter.
     */
    void startCapture();

    /**
     * @brief Signal emitted to request adding a bookmark for the given filter.
     * @param filter The filter string to bookmark.
     */
    void addBookmark(const QString filter);

};

#endif // CAPTURE_FILTER_EDIT_H
