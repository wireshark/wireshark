/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <config.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

#include <ui/qt/utils/field_information.h>

#include <epan/cfile.h>

#include <QTabWidget>
#include <QColor>
#include <QString>
#include <QVector>


#include <ui/qt/widgets/base_data_source_view.h>

class HexDataSourceView;

/**
 * @brief A tab widget that manages and displays different data sources for a packet (e.g., Hex, Text).
 */
class DataSourceTab : public QTabWidget
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new DataSourceTab.
     * @param parent The parent widget, defaults to 0.
     * @param edt_fixed Fixed epan_dissect data for a specific packet dialog context, defaults to 0.
     */
    explicit DataSourceTab(QWidget *parent = 0, epan_dissect_t *edt_fixed = 0);

public slots:
    /**
     * @brief Set the capture file.
     * @param cf Pointer to the capture file structure.
     */
    void setCaptureFile(capture_file *cf);

    /**
     * @brief Creates the tabs and data, depends on a dissection which has already run.
     * @param frames List of frame numbers indicating the selection change.
     */
    void selectedFrameChanged(QList<int> frames);

    /**
     * @brief Selects or marks a field in the view based on the tree selection.
     * @param field Pointer to the field information.
     */
    void selectedFieldChanged(FieldInformation *field);

    /**
     * @brief Highlights a field in the view based on tree hover state.
     * @param field Pointer to the field information.
     */
    void highlightedFieldChanged(FieldInformation *field);

    /**
     * @brief Slot triggered when the underlying capture file is closing.
     */
    void captureFileClosing(void);

signals:
    /**
     * @brief Signal emitted when a field is selected within the view.
     * @param field Pointer to the selected field information.
     */
    void fieldSelected(FieldInformation *field);

    /**
     * @brief Signal emitted when a field is highlighted (hovered) within the view.
     * @param field Pointer to the highlighted field information.
     */
    void fieldHighlight(FieldInformation *field);

    /**
     * @brief Signal emitted when byte view settings have been modified.
     */
    void byteViewSettingsChanged(void);

    /**
     * @brief Signal emitted to request unmarking a field in the byte view.
     */
    void byteViewUnmarkField(void);

    /**
     * @brief Signal emitted to request detaching the current data view into a new window.
     */
    void detachData(void);

private:
    /**
     * @brief Structure defining a user annotation on specific bytes.
     */
    struct FrameByteAnnotation {
        /** The frame number annotated. */
        int frame;
        /** The starting byte offset. */
        int start;
        /** The length of the annotated segment. */
        int length;
        /** The color assigned to the annotation. */
        QColor color;
        /** The text comment for the annotation. */
        QString comment;
    };

    /** Pointer to the underlying capture file structure. */
    capture_file *cap_file_;

    /** true if this byte view is related to a single
        packet in the packet dialog and false if the
        packet dissection context can change. */
    bool is_fixed_packet_;

    /** Packet dissection result for the currently selected packet. */
    epan_dissect_t *edt_;

    /** Flag to temporarily disable hover effects. */
    bool disable_hover_;

    /** Collection of active byte annotations. */
    QVector<FrameByteAnnotation> annotations_;

    /** The color used for the last created annotation. */
    QColor last_annotation_color_;

    /**
     * @brief Shadow of the theme's ExpertComment color as of last refresh.
     *
     * Used to detect user customization: if @c last_annotation_color_ still
     * equals this value when the theme changes, the user hasn't picked a
     * custom color in the annotation dialog yet, so it's safe to refresh
     * @c last_annotation_color_ to the new theme's ExpertComment.
     */
    QColor last_themed_annotation_color_;

    /** Flag tracking if the session notice for annotations has been shown. */
    bool annotations_session_notice_shown_;

    /**
     * @brief Updates the visibility of tabs based on available data sources.
     */
    void setTabsVisible();

    /**
     * @brief Finds the data source view associated with a specific tvbuff.
     * @param search The tvbuff to search for.
     * @param idx Optional pointer to store the found index.
     * @return A pointer to the data source view, or nullptr if not found.
     */
    BaseDataSourceView * findDataSourceViewForTvb(tvbuff_t * search, int * idx = 0);

    /**
     * @brief Adds a new tab for a data source.
     * @param name The name to display on the tab.
     * @param source Pointer to the underlying data source structure.
     */
    void addTab(const char *name = "", const struct data_source *source = nullptr);

    /**
     * @brief Applies all active annotations to the current views.
     */
    void applyAnnotationsToViews();

    /**
     * @brief Retrieves the frame number currently displayed.
     * @return The current frame number.
     */
    int currentFrameNumber() const;

    /**
     * @brief Finds an annotation covering a specific byte in a frame.
     * @param frame The frame number.
     * @param byte The byte offset.
     * @return The index of the annotation, or -1 if none found.
     */
    int findAnnotationIndexAt(int frame, int byte) const;

    /**
     * @brief Finds an annotation intersecting with a specified range.
     * @param frame The frame number.
     * @param start The starting byte offset.
     * @param length The length of the range.
     * @return The index of the annotation, or -1 if none found.
     */
    int findAnnotationIndexIntersecting(int frame, int start, int length) const;

    /**
     * @brief Retrieves the active hex data source view.
     * @return A pointer to the active hex view.
     */
    HexDataSourceView *activeHexView() const;

    /**
     * @brief Displays a notice regarding annotation persistence during the session.
     */
    void showAnnotationsSessionNotice();

protected:
    /**
     * @brief Called when a new tab is inserted.
     * @param tab_index The index of the new tab.
     */
    void tabInserted(int tab_index);

    /**
     * @brief Called when a tab is removed.
     * @param tab_index The index of the removed tab.
     */
    void tabRemoved(int tab_index);

private slots:
    /**
     * @brief Slot triggered when text in the byte view is hovered.
     * @param idx The byte index hovered.
     */
    void byteViewTextHovered(int idx);

    /**
     * @brief Slot triggered when text in the byte view is marked.
     * @param idx The byte index marked.
     */
    void byteViewTextMarked(int idx);

    /**
     * @brief Slot triggered to handle adding a new annotation.
     */
    void handleAddAnnotation();

    /**
     * @brief Slot triggered to handle editing an existing annotation.
     */
    void handleEditAnnotation();

    /**
     * @brief Slot triggered to handle removing an annotation.
     */
    void handleRemoveAnnotation();

    /**
     * @brief Slot triggered to mark the start offset for selection.
     * @param byte The start byte offset.
     */
    void handleSetOffsetStart(int byte);

    /**
     * @brief Slot triggered to mark the end offset for selection.
     * @param byte The end byte offset.
     */
    void handleSetOffsetEnd(int byte);

    /**
     * @brief Slot triggered to clear offset selection markers.
     */
    void handleClearOffsetMarkers();

    /**
     * @brief Connects necessary signals to the main application window.
     */
    void connectToMainWindow();

    /**
     * @brief Slot triggered to update state when a capture becomes active or inactive.
     * @param cap Non-zero if active, zero otherwise.
     */
    void captureActive(int cap);
};
