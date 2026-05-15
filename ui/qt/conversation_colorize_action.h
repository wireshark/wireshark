/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CONVERSATIONCOLORIZEACTION_H
#define CONVERSATIONCOLORIZEACTION_H

#include <QAction>

struct conversation_filter_s;
struct _packet_info;

// Actions for "Conversation Filter" and "Colorize with Filter" menu items.

/**
 * @brief An action representing a conversation filter to be applied.
 */
class ConversationAction : public QAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ConversationAction.
     * @param parent The parent QObject.
     * @param conv_filter Pointer to the underlying conversation filter structure, defaults to NULL.
     */
    ConversationAction(QObject *parent, struct conversation_filter_s *conv_filter = NULL);

    /**
     * @brief Checks if the conversation filter is valid for the provided packet information.
     * @param pinfo Pointer to the packet information structure.
     * @return True if the filter is valid, false otherwise.
     */
    bool isFilterValid(struct _packet_info *pinfo);

    /**
     * @brief Retrieves the filter string as a byte array.
     * @return The filter byte array.
     */
    const QByteArray filter() { return filter_ba_; }

    /**
     * @brief Sets the color number associated with this action.
     * @param color_number The color number to apply.
     */
    void setColorNumber(int color_number) { color_number_ = color_number; }

    /**
     * @brief Retrieves the color number associated with this action.
     * @return The current color number.
     */
    int colorNumber() { return color_number_; }

public slots:
    // Exactly one of these should be connected.
    /**
     * @brief Sets the packet information used to build the filter.
     * @param pinfo Pointer to the packet information structure.
     */
    void setPacketInfo(struct _packet_info *pinfo);

    /**
     * @brief Sets the field filter directly.
     * @param field_filter The filter string as a byte array.
     */
    void setFieldFilter(const QByteArray field_filter);

private:
    /** Pointer to the underlying conversation filter structure. */
    struct conversation_filter_s *conv_filter_;

    /** The filter string represented as a byte array. */
    QByteArray filter_ba_;

    /** The color number assigned to this conversation action. */
    int color_number_;
};

/**
 * @brief An action for applying colorization based on a specific filter.
 */
class ColorizeAction : public QAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ColorizeAction.
     * @param parent The parent QObject.
     */
    ColorizeAction(QObject *parent) : QAction(parent),
        color_number_(-1)
    {}

    /**
     * @brief Retrieves the filter string as a byte array.
     * @return The filter byte array.
     */
    const QByteArray filter() { return filter_ba_; }

    /**
     * @brief Sets the color number associated with this action.
     * @param color_number The color number to apply.
     */
    void setColorNumber(int color_number) { color_number_ = color_number; }

    /**
     * @brief Retrieves the color number associated with this action.
     * @return The current color number.
     */
    int colorNumber() { return color_number_; }

public slots:
    /**
     * @brief Sets the field filter directly.
     * @param field_filter The filter string as a byte array.
     */
    void setFieldFilter(const QByteArray field_filter) { filter_ba_ = field_filter; }

private:
    /** The filter string represented as a byte array. */
    QByteArray filter_ba_;

    /** The color number assigned to this colorize action. */
    int color_number_;
};

#endif // CONVERSATIONCOLORIZEACTION_H
