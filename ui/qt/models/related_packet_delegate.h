/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RELATED_PACKET_DELEGATE_H
#define RELATED_PACKET_DELEGATE_H

#include <config.h>

#include "epan/conversation.h"

#include <QHash>
#include <QStyledItemDelegate>

class QPainter;
struct conversation;

/**
 * @brief Item delegate that visually annotates packet-list rows with relationship
 *        indicators — arrows, chevrons, and check marks — showing how each packet
 *        relates to the currently selected frame and its conversation.
 */
class RelatedPacketDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a RelatedPacketDelegate with no related frames or conversation.
     * @param parent Optional parent widget.
     */
    RelatedPacketDelegate(QWidget *parent = 0);

    /**
     * @brief Clears all related frame entries and resets the conversation pointer.
     */
    void clear();

    /**
     * @brief Sets the frame number of the currently selected packet.
     *
     * Used to determine which relationship indicators to draw relative to
     * the selection.
     *
     * @param current_frame Frame number of the selected packet.
     */
    void setCurrentFrame(uint32_t current_frame);

    /**
     * @brief Associates a conversation with the delegate so that conversation
     *        membership can be reflected in the rendered indicators.
     * @param conv Pointer to the libwireshark conversation, or @c nullptr to clear.
     */
    void setConversation(struct conversation *conv);

public slots:
    /**
     * @brief Registers a frame as related to the current selection.
     * @param frame_num    Frame number to mark as related.
     * @param framenum_type Relationship type that controls which indicator is drawn
     *                     (e.g. request, response, reassembly); defaults to FT_FRAMENUM_NONE.
     */
    void addRelatedFrame(int frame_num, ft_framenum_type_t framenum_type = FT_FRAMENUM_NONE);

protected:
    /**
     * @brief Initialises the style option for a row, suppressing the default
     *        focus/selection highlight in the indicator column.
     * @param option Style option to populate.
     * @param index  Model index of the item being rendered.
     */
    void initStyleOption(QStyleOptionViewItem *option,
        const QModelIndex &index) const;

    /**
     * @brief Paints the relationship indicator for the packet at @p index.
     * @param painter Painter to draw with.
     * @param option  Style option providing geometry and state.
     * @param index   Model index of the item being painted.
     */
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const;

    /**
     * @brief Returns the preferred size for the indicator cell.
     * @param option Style option providing font metrics and state.
     * @param index  Model index of the item being measured.
     * @return Recommended QSize for the indicator column cell.
     */
    QSize sizeHint(const QStyleOptionViewItem &option,
        const QModelIndex &index) const;

private:
    QHash<int, ft_framenum_type_t> related_frames_; /**< Map from frame number to its relationship type. */
    struct conversation *conv_;                      /**< Active conversation used for membership checks; may be @c nullptr. */
    uint32_t current_frame_;                         /**< Frame number of the currently selected packet. */

    /**
     * @brief Draws a single-headed arrow from @p tail to @p head.
     * @param painter   Painter to draw with.
     * @param tail      Start point of the arrow shaft.
     * @param head      End point; where the arrowhead is rendered.
     * @param head_size Length of the arrowhead's barbs in pixels.
     */
    void drawArrow(QPainter *painter, const QPoint tail, const QPoint head, int head_size) const;

    /**
     * @brief Draws a double-chevron (>>) indicator between @p tail and @p head.
     * @param painter   Painter to draw with.
     * @param tail      Start point of the chevron sequence.
     * @param head      End point of the chevron sequence.
     * @param head_size Controls the size of each chevron in pixels.
     */
    void drawChevrons(QPainter *painter, const QPoint tail, const QPoint head, int head_size) const;

    /**
     * @brief Draws a check-mark glyph centred within @p bbox.
     * @param painter Painter to draw with.
     * @param bbox    Bounding rectangle within which the check mark is drawn.
     */
    void drawCheckMark(QPainter *painter, const QRect bbox) const;
};

#endif // RELATED_PACKET_DELEGATE_H
