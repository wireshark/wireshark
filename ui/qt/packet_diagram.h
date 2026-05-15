/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_DIAGRAM_H
#define PACKET_DIAGRAM_H

#include <config.h>

#include <epan/proto.h>

#include <epan/cfile.h>

#include <ui/qt/utils/field_information.h>

#include <QGraphicsView>

class DiagramLayout;

/**
 * @brief A graphics view widget for displaying protocol packet diagrams.
 */
class PacketDiagram : public QGraphicsView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new PacketDiagram.
     * @param parent The parent widget, defaults to nullptr.
     */
    PacketDiagram(QWidget *parent = nullptr);

    /**
     * @brief Destroys the PacketDiagram.
     */
    ~PacketDiagram();

    /**
     * @brief Sets the root protocol node to generate the diagram from.
     * @param root_node Pointer to the root protocol node.
     */
    void setRootNode(proto_node *root_node);

    /**
     * @brief Clears the diagram view.
     */
    void clear();

signals:
    /**
     * @brief Signal emitted when a field is selected in the diagram.
     * @param finfo Pointer to the selected field information.
     */
    void fieldSelected(FieldInformation *finfo);

public slots:
    /**
     * @brief Sets the active capture file.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf);

    /**
     * @brief Sets the font used for rendering the diagram text.
     * @param font The font to apply.
     */
    void setFont(const QFont &font);

    /**
     * @brief Slot triggered when the selected field changes.
     * @param finfo Pointer to the new field information.
     */
    void selectedFieldChanged(FieldInformation *finfo);

    /**
     * @brief Slot triggered when the selected frame changes.
     * @param frames List of selected frame numbers.
     */
    void selectedFrameChanged(QList<int> frames);

protected:
    /**
     * @brief Core Qt event handler override.
     * @param event The event to process.
     * @return True if the event was handled, false otherwise.
     */
    virtual bool event(QEvent *event) override;

    /**
     * @brief Handles context menu events.
     * @param event The context menu event.
     */
    virtual void contextMenuEvent(QContextMenuEvent *event) override;

private slots:
    /**
     * @brief Connects the diagram's signals to the main window.
     */
    void connectToMainWindow();

    /**
     * @brief Slot triggered when the selection within the graphics scene changes.
     */
    void sceneSelectionChanged();

private:
    /**
     * @brief Resets the graphics scene.
     * @param reset_root True to also reset the root node, defaults to true.
     */
    void resetScene(bool reset_root = true);

    /**
     * @brief Adds a diagram based on a top-level protocol node.
     * @param tl_node Pointer to the top-level protocol node.
     */
    void addDiagram(proto_node *tl_node);

    /**
     * @brief Visually sets a specific field as selected.
     * @param fi Pointer to the field information to select.
     */
    void setSelectedField(field_info *fi);

    /**
     * @brief Exports the current diagram to a raster image.
     * @return The exported QImage.
     */
    QImage exportToImage();

#if defined(QT_SVG_LIB) && 0
    /**
     * @brief Exports the current diagram to SVG format.
     * @return The SVG data as a QByteArray.
     */
    QByteArray exportToSvg();
#endif

    /**
     * @brief Slot triggered to toggle the display of fields in the diagram.
     * @param checked True to show fields, false to hide them.
     */
    void showFieldsToggled(bool checked);

    /**
     * @brief Slot triggered by the "Save As" action.
     */
    void saveAsTriggered();

    /**
     * @brief Slot triggered to copy the diagram as a raster image.
     */
    void copyAsRasterTriggered();

#if defined(QT_SVG_LIB) && !defined(Q_OS_MAC) && 0
    /**
     * @brief Slot triggered to copy the diagram as an SVG graphic.
     */
    void copyAsSvgTriggered();
#endif

    /** Diagram layout manager. */
    DiagramLayout *layout_;

    /** Pointer to the active capture file. */
    capture_file *cap_file_;

    /** Pointer to the root protocol node being visualized. */
    proto_node *root_node_;

    /** Pointer to the currently selected field info. */
    field_info *selected_field_;

    /** The current vertical position used for layout rendering. */
    int y_pos_;
};

#endif // PACKET_DIAGRAM_H
