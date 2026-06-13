/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SEARCH_FRAME_H
#define SEARCH_FRAME_H

#include <config.h>

#include "accordion_frame.h"

#include <epan/cfile.h>

#include <QComboBox>
#include <QTimer>

class InPacketSearch;

namespace Ui {
class SearchFrame;
}

/**
 * @brief Collapsible search bar that allows searching packet data by display
 *        filter, hex value, string, or regular expression, with forward and
 *        backward navigation through matching frames.
 */
class SearchFrame : public AccordionFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a SearchFrame in its collapsed (hidden) state.
     * @param parent Optional parent widget.
     */
    explicit SearchFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the SearchFrame and releases all associated resources.
     */
    virtual ~SearchFrame();

    /**
     * @brief Expands the frame with an animation and focuses the search input.
     */
    void animatedShow();

    /**
     * @brief Navigates to the next frame matching the current search criteria.
     */
    void findNext();

    /**
     * @brief Navigates to the previous frame matching the current search criteria.
     */
    void findPrevious();

    /**
     * @brief Transfers keyboard focus to the search input field.
     */
    void setFocus();

    /**
     * @brief Attach in-packet search engine for the main-window proto tree.
     */
    void setInPacketSearch(InPacketSearch *search);

    /**
     * @brief Enable or disable in-packet search mode on the Find toolbar.
     */
    void setInPacketMode(bool enabled);

    /**
     * @brief Reflect whether exactly one packet is selected in the packet list.
     */
    void setPacketSelected(bool selected);

    bool inPacketMode() const;

public slots:
    /**
     * @brief Updates the capture file pointer used for frame searches.
     * @param cf New capture file; may be @c NULL when no file is open.
     */
    void setCaptureFile(capture_file *cf);

    /**
     * @brief Refreshes widget enablement and validation state.
     */
    void refreshWidgets();

    /**
     * @brief Populates the search field with @p filter, switches the search
     *        type to display filter, and immediately executes a forward search.
     * @param filter Display filter expression to search for.
     */
    void findFrameWithFilter(QString &filter);

    /**
     * @brief Collapses the search frame and clears any active search highlight.
     */
    void cancelSearch();

protected:
    /**
     * @brief Handles key press events; maps Enter/Return to findNext() and
     *        Escape to collapsing the frame.
     * @param event The key event to process.
     */
    virtual void keyPressEvent(QKeyEvent *event) override;

    /**
     * @brief Responds to language or palette change events by retranslating
     *        and refreshing the UI.
     * @param event The change event.
     */
    void changeEvent(QEvent *event) override;

    /**
     * @brief Enables or disables UI controls based on the current search type,
     *        direction, and validity of the search expression.
     */
    void updateWidgets();

    /**
     * @brief Returns the "Search In" combo box widget for use by subclasses or tests.
     * @return Pointer to the searchInComboBox widget.
     */
    QComboBox *searchInComboBox() const;

    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    /**
     * @brief Compiles the current search text as a regular expression into @c regex_.
     * @return @c true if compilation succeeded; @c false if the pattern is invalid,
     *         with @c regex_error_ populated with the error message.
     */
    bool regexCompile();

    /**
     * @brief Restores the search type, direction, and encoding selections from
     *        the recent-settings store.
     */
    void applyRecentSearchSettings();

    /**
     * @brief Run a within-packet search using Find toolbar settings.
     */
    void executeInPacketSearch();

    /**
     * @brief Search if needed, then move to the next or previous in-packet match.
     */
    void advanceInPacketSearch(bool backward);

    /**
     * @brief Current search type (display filter, hex, string, or regex).
     */
    int searchTypeIndex() const;

    /**
     * @brief Limit or restore search-type combo items for in-packet mode.
     */
    void configureSearchTypeComboBox(bool in_packet_mode);

    /**
     * @brief Update the search-type combo tooltip for the highlighted item.
     */
    void updateSearchTypeToolTip(int combo_index);

    /**
     * @brief Set Find toolbar syntax tint while in-packet mode is active.
     */
    void updateInPacketSearchSyntax();

    /**
     * @brief Update the status bar find-in-packet match counter prefix.
     */
    void updateInPacketFindCounter();

    InPacketSearch *in_packet_search_;
    QTimer *in_packet_debounce_timer_;
    Ui::SearchFrame *sf_ui_;   /**< Qt Designer-generated UI object for this frame. */
    capture_file    *cap_file_; /**< Capture file currently being searched. */
    ws_regex_t      *regex_;    /**< Compiled regular expression, or @c nullptr if not in regex mode. */
    QString          regex_error_; /**< Human-readable error from the last failed regex compilation. */
    QString          in_packet_last_pattern_; /**< Last in-packet search pattern (Enter navigation). */
    QString          full_search_type_tooltip_; /**< Tooltip for all search types. */
    QString          in_packet_string_tooltip_; /**< In-packet string search tooltip. */
    QString          in_packet_regex_tooltip_; /**< In-packet regex search tooltip. */
    bool             packet_selected_; /**< Exactly one packet is selected in the list. */

private slots:
    /**
     * @brief Updates visible controls when the "Search In" selection changes
     *        (packet list, packet details, or packet bytes).
     * @param idx New combo-box index.
     */
    void on_searchInComboBox_currentIndexChanged(int idx);

    /**
     * @brief Updates the character encoding used for string searches.
     * @param idx New combo-box index.
     */
    void on_charEncodingComboBox_currentIndexChanged(int idx);

    /**
     * @brief Toggles case-sensitive matching and re-validates the current expression.
     * @param checked @c true for case-sensitive; @c false for case-insensitive.
     */
    void on_caseCheckBox_toggled(bool checked);

    /**
     * @brief Switches the search type (display filter, hex, string, regex) and
     *        updates visible controls and expression validation accordingly.
     * @param idx New combo-box index.
     */
    void on_searchTypeComboBox_currentIndexChanged(int idx);

    /**
     * @brief Recompiles the regex (if applicable) and updates the Find button
     *        state as the user types in the search field.
     */
    void on_searchLineEdit_textChanged(const QString &);

    /**
     * @brief Toggles the search direction between forward and backward.
     * @param checked @c true for backward search; @c false for forward.
     */
    void on_dirCheckBox_toggled(bool checked);

    /**
     * @brief Toggles whether all matches are highlighted simultaneously.
     * @param checked @c true to highlight all matches; @c false for single-match mode.
     */
    void on_multipleCheckBox_toggled(bool checked);

    /**
     * @brief Toggles in-packet search mode (search current packet proto tree).
     * @param checked Checked state of the checkbox.
     */
    void inPacketCheckBoxToggled(bool checked);

    /**
     * @brief Called when application focus changes so the checkbox can update.
     */
    void onApplicationFocusChanged(QWidget *old, QWidget *now);

    /**
     * @brief Executes a search in the current direction using the current criteria.
     */
    void executeSearch();
};

#endif // SEARCH_FRAME_H
