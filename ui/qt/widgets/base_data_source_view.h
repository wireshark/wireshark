/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QAbstractScrollArea>

struct tvbuff;

/**
 * @brief Abstract base class for widgets that display raw packet byte data.
 */
class BaseDataSourceView : public QAbstractScrollArea
{
    Q_OBJECT

public:
    /**
     * @brief Construct a BaseDataSourceView.
     * @param data   The raw packet bytes to display. The data is held by
     *               value; call @c detachData() before modifying the source
     *               array if copy-on-write sharing is undesirable.
     * @param parent The parent widget; may be nullptr.
     */
    explicit BaseDataSourceView(const QByteArray &data, QWidget *parent = nullptr) :
        QAbstractScrollArea(parent),
        data_(data),
        tvb_(nullptr),
        tab_index_(0)
    {}

    /**
     * @brief Return the minimum size hint for the view.
     * @return An empty @c QSize().
     */
    virtual QSize minimumSizeHint() const { return QSize(); }

    /**
     * @brief Return whether the view contains no displayable data.
     * @return true if @c data_ is empty; false if there are bytes to show.
     */
    virtual bool isEmpty() const { return data_.isEmpty(); }

    /**
     * @brief Return the @c tvbuff associated with this data source.
     *
     * @return A pointer to the associated @c tvbuff, or nullptr if none has
     *         been set.
     */
    struct tvbuff *tvb() const { return tvb_; }

    /**
     * @brief Associate a Wireshark @c tvbuff with this data source.
     * @param tvb Pointer to the @c tvbuff for the current packet.
     */
    void setTvb(struct tvbuff *tvb) { tvb_ = tvb; }

    /**
     * @brief Return the tab index of this view within the byte-view panel.
     * @return The zero-based tab index.
     */
    int tabIndex() const { return tab_index_; }

    /**
     * @brief Set the tab index for this view.
     * @param tab_index The zero-based tab index assigned by the parent panel.
     */
    void setTabIndex(int tab_index) { tab_index_ = tab_index; }

signals:
    /**
     * @brief Emitted when the cursor moves over a byte in the view.
     *
     * @param pos Zero-based byte offset within @c data_, or -1 when the
     *            cursor leaves the data area.
     */
    void byteHovered(int pos);

    /**
     * @brief Emitted when the user clicks a byte in the view.
     *
     * @param pos Zero-based byte offset within @c data_ of the selected byte.
     */
    void byteSelected(int pos);

public slots:
    /**
     * @brief Update the monospace font used to render byte values.
     * @param mono_font The new monospace @c QFont to apply.
     */
    virtual void setMonospaceFont(const QFont &mono_font) = 0;

    /**
     * @brief Detach the internal @c QByteArray from any shared copy.
     */
    virtual void detachData() { data_.detach(); }

    /**
     * @brief Highlight the byte range belonging to the enclosing protocol layer.
     * @param start  Zero-based byte offset of the first byte in the protocol span.
     * @param length Number of bytes in the protocol span.
     */
    virtual void markProtocol(int start, int length) = 0;

    /**
     * @brief Highlight the byte range for a specific dissected field.
     *
     * @param start     Zero-based byte offset of the first byte in the field.
     * @param length    Number of bytes in the field.
     * @param scroll_to true to scroll the field into view (default); false
     *                  to update the highlight without scrolling.
     * @param hover     true to apply the hover colour; false (default) to
     *                  apply the selection colour.
     */
    virtual void markField(int start, int length, bool scroll_to = true,
                           bool hover = false) = 0;

    /**
     * @brief Highlight the appendix byte range for the selected field.
     *
     * @param start  Zero-based byte offset of the first appendix byte.
     * @param length Number of bytes in the appendix.
     */
    virtual void markAppendix(int start, int length) = 0;

    /**
     * @brief Clear all field and appendix highlights.
     */
    virtual void unmarkField() = 0;

protected:
    /**
     * @brief The raw packet bytes displayed by this view.
     */
    QByteArray data_;

private:
    struct tvbuff *tvb_; /**< Wireshark tvbuff for this data source; not owned. */
    int tab_index_;      /**< Zero-based index of this view's tab in the byte-view panel. */
};
