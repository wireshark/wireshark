/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SEQUENCE_DIAGRAM_H
#define SEQUENCE_DIAGRAM_H

#include <config.h>

#include <epan/address.h>

#include <QObject>
#include <QMultiMap>
#include <ui/qt/widgets/qcustomplot.h>

struct _seq_analysis_info;
struct _seq_analysis_item;

// Some of this is probably unnecessary
/**
 * @brief Key-value pair associating a plot key coordinate with a sequence
 *        analysis item, used as the value type in WSCPSeqDataMap.
 */
class WSCPSeqData
{
public:
    /** @brief Constructs a default WSCPSeqData with a zero key and null value. */
    WSCPSeqData();

    /**
     * @brief Constructs a WSCPSeqData with the given key and sequence analysis item.
     * @param key   Plot key coordinate (typically a time or sequence value).
     * @param value Pointer to the sequence analysis item for this data point.
     */
    WSCPSeqData(double key, _seq_analysis_item *value);

    double                    key;   /**< Plot key coordinate for this data point. */
    struct _seq_analysis_item *value; /**< Sequence analysis item associated with this key. */
};


/** @brief Multi-map keyed by plot coordinate, storing WSCPSeqData entries for the sequence diagram. */
typedef QMultiMap<double, WSCPSeqData> WSCPSeqDataMap;


/**
 * @brief QCustomPlot plottable that renders a Wireshark sequence diagram,
 *        drawing arrows and comments between participant columns for each
 *        analysed protocol exchange.
 */
class SequenceDiagram : public QCPAbstractPlottable
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a SequenceDiagram plottable with three axes.
     * @param keyAxis     Axis used for the key (time/sequence) dimension.
     * @param valueAxis   Axis used for the value (participant column) dimension.
     * @param commentAxis Axis used to render per-arrow comment text.
     */
    explicit SequenceDiagram(QCPAxis *keyAxis, QCPAxis *valueAxis, QCPAxis *commentAxis);

    /**
     * @brief Destroys the SequenceDiagram and frees the internal data map.
     */
    virtual ~SequenceDiagram();

    // ── Getters ──────────────────────────────────────────────────────────

    /**
     * @brief Returns the frame number of the packet adjacent to the current selection.
     * @param next @c true to retrieve the next packet; @c false for the previous.
     * @return Frame number of the adjacent packet, or -1 if none exists.
     */
    int adjacentPacket(bool next);

    /**
     * @brief Returns the plot key coordinate of the currently selected data point.
     * @return Selected key value, or 0.0 if nothing is selected.
     */
    double selectedKey() { return selected_key_; }

    // ── Setters ──────────────────────────────────────────────────────────

    /**
     * @brief Replaces the diagram's data with the contents of @p sainfo and
     *        triggers a replot.
     * @param sainfo Pointer to the sequence analysis info structure to visualise.
     */
    void setData(struct _seq_analysis_info *sainfo);

    // ── Queries ──────────────────────────────────────────────────────────

    /**
     * @brief Returns the sequence analysis item rendered at the given vertical
     *        pixel position in the plot.
     * @param ypos Y pixel coordinate (in widget space) to hit-test.
     * @return Pointer to the matching _seq_analysis_item, or @c nullptr if none.
     */
    struct _seq_analysis_item *itemForPosY(int ypos);

    /**
     * @brief Returns whether @p pos falls within a comment text region.
     * @param pos Point in widget coordinates to test.
     * @return @c true if the point is over a comment label.
     */
    bool inComment(QPoint pos) const;

    /**
     * @brief Returns @p text elided to fit within the comment axis width.
     * @param text Full comment string to elide.
     * @return Elided string with a trailing ellipsis if truncation was needed.
     */
    QString elidedComment(const QString &text) const;

    // ── Reimplemented virtual methods ─────────────────────────────────────

    /**
     * @brief Removes all data points from the internal data map.
     */
    virtual void clearData() { data_->clear(); }

    /**
     * @brief Returns the distance from @p pos to the nearest data point for
     *        hit-testing and selection purposes.
     * @param pos            Position in plot coordinates to test.
     * @param onlySelectable If @c true, only consider selectable plottables.
     * @param details        Optional output for selection detail data.
     * @return Distance in pixels, or a negative value if the position is not near any point.
     */
    virtual double selectTest(const QPointF &pos, bool onlySelectable, QVariant *details = 0) const Q_DECL_OVERRIDE;

public slots:
    /**
     * @brief Selects the data point corresponding to @p selected_packet and
     *        updates @c selected_key_ and @c selected_packet_ accordingly.
     * @param selected_packet Frame number of the packet to select.
     */
    void setSelectedPacket(int selected_packet);

protected:
    /**
     * @brief Draws all sequence diagram arrows, participant labels, and comment
     *        text onto @p painter.
     * @param painter QCustomPlot painter to render with.
     */
    virtual void draw(QCPPainter *painter) Q_DECL_OVERRIDE;

    /**
     * @brief Draws a small representative icon for the legend entry.
     * @param painter QCustomPlot painter to render with.
     * @param rect    Bounding rectangle allocated for the legend icon.
     */
    virtual void drawLegendIcon(QCPPainter *painter, const QRectF &rect) const Q_DECL_OVERRIDE;

    /**
     * @brief Returns the key-axis range spanned by the data.
     * @param validRange   Set to @c true if a non-empty range was found.
     * @param inSignDomain Restricts the range to positive or negative values.
     * @return QCPRange covering all key values in the data map.
     */
    virtual QCPRange getKeyRange(bool &validRange, QCP::SignDomain inSignDomain = QCP::sdBoth) const Q_DECL_OVERRIDE;

    /**
     * @brief Returns the value-axis range spanned by the data.
     * @param validRange   Set to @c true if a non-empty range was found.
     * @param inSignDomain Restricts the range to positive or negative values.
     * @param inKeyRange   Optional key range to restrict which data points are considered.
     * @return QCPRange covering all value (participant column) positions in the data map.
     */
    virtual QCPRange getValueRange(bool &validRange, QCP::SignDomain inSignDomain=QCP::sdBoth, const QCPRange &inKeyRange = QCPRange()) const Q_DECL_OVERRIDE;

private:
    QCPAxis              *key_axis_;     /**< Axis for the key (time/sequence) dimension. */
    QCPAxis              *value_axis_;   /**< Axis for the value (participant column) dimension. */
    QCPAxis              *comment_axis_; /**< Axis used to position and clip comment text. */
    WSCPSeqDataMap       *data_;         /**< Internal map of all sequence diagram data points. */
    struct _seq_analysis_info *sainfo_;  /**< Source sequence analysis info driving the diagram. */
    uint32_t              selected_packet_; /**< Frame number of the currently selected packet. */
    double                selected_key_;   /**< Plot key coordinate of the currently selected data point. */
};

#endif // SEQUENCE_DIAGRAM_H
