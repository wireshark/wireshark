/* mka_ca_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mka_ca_dialog.h"

#include "ui/qt/ui_tap_parameter_dialog.h"

#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/addr_resolv.h>

#include "main_application.h"
#include "utils/font_manager.h"
#include "file.h"
#include "capture_file.h"

#include <QTreeWidget>
#include <QFont>
#include <QFontDialog>
#include <QSettings>
#include <QStyledItemDelegate>
#include <QPainter>
#include <QTextDocument>
#include <QAbstractTextDocumentLayout>
#include <QApplication>
#include <QTreeWidgetItemIterator>
#include <QLineEdit>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QSet>
#include <QRegularExpression>

extern "C" {
#include "ui/mka_ca_stat.h"
}

// Tree columns.
enum {
    col_item_ = 0,   // CA / peer / episode label
    col_detail_,     // value / detail
    col_timing_      // formation time or last-heard
};

// Tree item data role carrying a frame number for go-to-packet.
static const int frame_num_role_ = Qt::UserRole + 1;

// Tree item data role carrying a display filter for the find/filter menu.
static const int filter_role_ = Qt::UserRole + 2;

// Marks a formation's "Peers" folder so it auto-expands when its parent
// formation item is expanded.
static const int form_peers_role_ = Qt::UserRole + 3;

// Custom data role holding a column's rich-text (HTML) rendering, used by
// MkaCaHtmlDelegate to bold the longest per-metric time in a peer's summary.
static const int html_role_ = Qt::UserRole + 4;

// Renders a tree column as rich text (HTML) when the item carries an
// html_role_ string, so part of a cell (the longest per-metric time) can be
// bolded. Falls back to default rendering otherwise.
class MkaCaHtmlDelegate : public QStyledItemDelegate
{
public:
    explicit MkaCaHtmlDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent) {}

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
    {
        QVariant html = index.data(html_role_);
        if (!html.isValid()) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        QStyleOptionViewItem opt = option;
        initStyleOption(&opt, index);
        opt.text.clear();   // text is drawn by the document below

        const QWidget *w = opt.widget;
        QStyle *style = w ? w->style() : QApplication::style();
        style->drawControl(QStyle::CE_ItemViewItem, &opt, painter, w);

        QTextDocument doc;
        doc.setDefaultFont(opt.font);
        doc.setDocumentMargin(0);   // match the default cell's text metrics
        doc.setHtml(html.toString());

        painter->save();
        QRect text_rect = style->subElementRect(QStyle::SE_ItemViewItemText, &opt, w);
        doc.setTextWidth(text_rect.width());
        // Vertically center the document in the text rect so a bold cell
        // aligns with the default-rendered (centered) neighboring cells.
        qreal y_off = (text_rect.height() - doc.size().height()) / 2.0;
        if (y_off < 0) {
            y_off = 0;
        }

        painter->translate(text_rect.left(), text_rect.top() + y_off);
        painter->setClipRect(QRectF(0, 0, text_rect.width(), text_rect.height()));

        QColor color = (opt.state & QStyle::State_Selected)
            ? opt.palette.color(QPalette::HighlightedText)
            : opt.palette.color(QPalette::Text);
        QAbstractTextDocumentLayout::PaintContext ctx;
        ctx.palette.setColor(QPalette::Text, color);
        doc.documentLayout()->draw(painter, ctx);
        painter->restore();
    }
};


static const char *mka_ca_stat_cfg = "mka,ca";

// Format a byte array as lowercase hex.
static QString bytesToHex(const uint8_t *data, unsigned len)
{
    QString out;

    for (unsigned i = 0; i < len; i++) {
        out += QString("%1").arg(data[i], 2, 16, QChar('0'));
    }

    return out;
}

// Format a byte array as colon-separated hex, as required for FT_BYTES
// display filter comparisons.
static QString bytesToColonHex(const uint8_t *data, unsigned len)
{
    QString out;

    for (unsigned i = 0; i < len; i++) {
        if (i != 0) {
            out += QChar(':');
        }

        out += QString("%1").arg(data[i], 2, 16, QChar('0'));
    }

    return out;
}

// Raw SCI: 6-byte MAC system id (hex) / 4-digit hex port number, never
// resolved.
static QString sciRawStr(const uint8_t *sci)
{
    return QString("%1:%2:%3:%4:%5:%6/%7")
        .arg(sci[0], 2, 16, QChar('0')).arg(sci[1], 2, 16, QChar('0'))
        .arg(sci[2], 2, 16, QChar('0')).arg(sci[3], 2, 16, QChar('0'))
        .arg(sci[4], 2, 16, QChar('0')).arg(sci[5], 2, 16, QChar('0'))
        .arg((sci[6] << 8) | sci[7], 4, 16, QChar('0'));
}

// SCI label for display. With physical address resolution on, the MAC
// portion is replaced by Wireshark's resolved name (matching the packet
// view). With it off, the raw SCI is shown with the OUI vendor appended.
static QString sciToStr(const uint8_t *sci)
{
    QString port = QString("%1").arg((sci[6] << 8) | sci[7], 4, 16, QChar('0'));

    if (gbl_resolv_flags.mac_name) {
        const char *name = get_ether_name(sci);
        if (name != NULL && name[0] != '\0') {
            return QString("%1/%2").arg(name).arg(port);
        }
        return sciRawStr(sci);
    }

    QString s = sciRawStr(sci);
    // OUI vendor lookup works regardless of the resolution preference.
    const char *manuf = get_manuf_name_if_known(sci, MKA_CA_SCI_LEN - 2);
    if (manuf != NULL) {
        s += QString(" (%1)").arg(manuf);
    }
    return s;
}

// Display filter selecting one peer's MKPDUs by SCI.
static QString sciToFilter(const uint8_t *sci)
{
    unsigned port = (sci[6] << 8) | sci[7];

    return QString("mka.sci.system_identifier == %1:%2:%3:%4:%5:%6 && "
                   "mka.sci.port_identifier == %7")
        .arg(sci[0], 2, 16, QChar('0')).arg(sci[1], 2, 16, QChar('0'))
        .arg(sci[2], 2, 16, QChar('0')).arg(sci[3], 2, 16, QChar('0'))
        .arg(sci[4], 2, 16, QChar('0')).arg(sci[5], 2, 16, QChar('0'))
        .arg(port);
}

// Display filter selecting frames in which a given MI appears as the actor or peer,
// bounded to the frame range over which that MI was observed.
static QString miToFilter(const uint8_t *mi, uint32_t first_frame, uint32_t last_frame)
{
    QString m = bytesToColonHex(mi, MKA_CA_MI_LEN);

    return QString("(mka.actor_mi == %1 || mka.peer_mi == %1) && frame.number >= %2 && frame.number <= %3")
        .arg(m).arg(first_frame).arg(last_frame);
}

// Display filter selecting the conversation involving a key server identity
// (its own MKPDUs and every SAK Use frame that names it as the key server).
static QString ksToFilter(const uint8_t *ks_mi)
{
    QString m = bytesToColonHex(ks_mi, MKA_CA_MI_LEN);

    return QString("mka.actor_mi == %1 || mka.latest_key_server_mi == %1 || "
                   "mka.old_key_server_mi == %1").arg(m);
}

// As ksToFilter, bounded to the frame range over which the key server identity was observed.
static QString ksToFilterRange(const uint8_t *ks_mi, uint32_t first_frame, uint32_t last_frame)
{
    return QString("(%1) && frame.number >= %2 && frame.number <= %3")
        .arg(ksToFilter(ks_mi)).arg(first_frame).arg(last_frame);
}

// Display filter for a formation conversation: all MKPDUs of this CA within the formation's frame range.
static QString formToFilter(const QString &ckn_colon_hex, uint32_t trigger_frame, uint32_t end_frame)
{
    // Scope by CKN when known; otherwise fall back to any MKA frame.
    QString scope = ckn_colon_hex.isEmpty() ? QString("mka") : QString("mka.cak_name == %1").arg(ckn_colon_hex);

    return QString("%1 && frame.number >= %2 && frame.number <= %3")
        .arg(scope).arg(trigger_frame).arg(end_frame);
}

MkaCaDialog::MkaCaDialog(QWidget &parent, CaptureFile &cf, const char *filter) :
    TapParameterDialog(parent, cf),
    stat_(NULL),
    tap_registered_(false),
    auto_refresh_button_(NULL)
{
    setWindowSubtitle(tr("MKA Connectivity Associations"));
    loadGeometry(parent.width() * 4 / 5, parent.height() * 3 / 4, "MkaCaDialog");

    QStringList header_names = QStringList() << tr("CA | Peer | Event") << tr("Details") << tr("Install / Activate / Retire Timings | Frames");

    statsTreeWidget()->setHeaderLabels(header_names);
    // Dialog-local font, scaled by the application zoom (Ctrl++/Ctrl+-/Ctrl+0).
    // Default to the application regular font; restore a saved choice.
    base_font_ = FontManager::font();
    {
        QSettings settings;
        QString saved = settings.value("MkaCaDialog/font").toString();
        QFont f;
        if (!saved.isEmpty() && f.fromString(saved)) {
            base_font_ = f;
        }
    }

    applyFont();
    connect(FontManager::instance(), &FontManager::zoomChanged, this, &MkaCaDialog::applyFont);

    statsTreeWidget()->setColumnWidth(col_item_, fontMetrics().height() * 22);
    statsTreeWidget()->setColumnWidth(col_detail_, fontMetrics().height() * 22);
    statsTreeWidget()->setSortingEnabled(false);

    // Render the timing column as rich text so the longest per-metric time
    // in a peer summary can be bolded.
    statsTreeWidget()->setItemDelegateForColumn(col_timing_, new MkaCaHtmlDelegate(this));

    QPushButton *font_bt = getUI()->buttonBox->addButton(tr("Font\u2026"), QDialogButtonBox::ActionRole);
    font_bt->setToolTip(tr("Choose the font and size for this dialog."));
    connect(font_bt, &QPushButton::clicked, this, &MkaCaDialog::chooseFont);

    QPushButton *refresh_bt = getUI()->buttonBox->addButton(tr("Refresh"), QDialogButtonBox::ActionRole);
    connect(refresh_bt, &QPushButton::clicked, this, &MkaCaDialog::fillTree);

    auto_refresh_button_ = getUI()->buttonBox->addButton(tr("Auto Refresh"), QDialogButtonBox::ActionRole);
    auto_refresh_button_->setCheckable(true);
    auto_refresh_button_->setToolTip(tr("Re-run the analysis as new packets are captured."));

    connect(statsTreeWidget(), &QTreeWidget::itemDoubleClicked, this, &MkaCaDialog::itemDoubleClicked);
    connect(statsTreeWidget(), &QTreeWidget::itemExpanded, this, &MkaCaDialog::itemExpanded);
    connect(&cap_file_, &CaptureFile::captureEvent, this, &MkaCaDialog::mkaCaptureEvent);

    // Re-render names when Wireshark's address resolution setting changes;
    // drawTree() rebuilds from existing engine state without re-tapping.
    connect(mainApp, &MainApplication::addressResolutionChanged, this, &MkaCaDialog::drawTree);

    stat_ = mka_ca_stat_new();

    addFilterActions();
    if (filter) {
        setDisplayFilter(filter);
    }

    GString *error_string = registerTap();
    if (error_string != NULL) {
        setHint(QString::fromUtf8(error_string->str));
        g_string_free(error_string, TRUE);
    }
}

MkaCaDialog::~MkaCaDialog()
{
    removeTap();
    mka_ca_stat_free(stat_);
    stat_ = NULL;
}

void MkaCaDialog::captureFileClosing()
{
    removeTap();
    WiresharkDialog::captureFileClosing();
}

void MkaCaDialog::applyFont()
{
    // Scale the dialog-local base font by the current application zoom factor.
    QFont f = base_font_;
    qreal pt = base_font_.pointSizeF();
    if (pt > 0) {
        f.setPointSizeF(pt * FontManager::zoomFactor());
    }
    statsTreeWidget()->setFont(f);
}

void MkaCaDialog::chooseFont()
{
    bool ok = false;
    QFont f = QFontDialog::getFont(&ok, base_font_, this, tr("MKA Connectivity Associations Font"));
    if (ok) {
        base_font_ = f;
        applyFont();
        QSettings settings;
        settings.setValue("MkaCaDialog/font", base_font_.toString());
    }
}

void MkaCaDialog::mkaCaptureEvent(CaptureEvent e)
{
    // When a new capture file finishes loading (e.g. drag-and-drop or
    // File > Open into the running application), the previous file closed and
    // removed the tap; re-register it against the new file and refresh.
    if (e.captureContext() == CaptureEvent::File && e.eventType() == CaptureEvent::Finished) {
        file_closed_ = false;

        if (!tap_registered_) {
            GString *error_string = registerTap();
            if (error_string != NULL) {
                setHint(QString::fromUtf8(error_string->str));
                g_string_free(error_string, TRUE);
                return;
            }
        }

        fillTree();
    }
}

GString *MkaCaDialog::registerTap()
{
    GString *error_string = register_tap_listener("mka_ca", this, displayFilter().toUtf8().constData(),
                                                   TL_REQUIRES_NOTHING, tapReset, tapPacket, tapDraw, NULL);
    if (error_string == NULL) {
        tap_registered_ = true;
    }

    return error_string;
}

void MkaCaDialog::removeTap()
{
    if (tap_registered_) {
        remove_tap_listener(this);
        tap_registered_ = false;
    }
}

void MkaCaDialog::tapReset(void *tapdata)
{
    MkaCaDialog *dlg = static_cast<MkaCaDialog *>(tapdata);
    mka_ca_stat_reset(dlg->stat_);
}

tap_packet_status MkaCaDialog::tapPacket(void *tapdata, _packet_info *, epan_dissect *, const void *data, tap_flags_t)
{
    MkaCaDialog *dlg = static_cast<MkaCaDialog *>(tapdata);
    const mka_ca_tap_t *tap = (const mka_ca_tap_t *)data;

    if (tap->ckn_len == 0) {
        return TAP_PACKET_DONT_REDRAW;
    }

    mka_ca_stat_process(dlg->stat_, tap);

    return TAP_PACKET_REDRAW;
}

void MkaCaDialog::tapDraw(void *tapdata)
{
    MkaCaDialog *dlg = static_cast<MkaCaDialog *>(tapdata);
    // The tap framework invokes this after each retap pass (including live
    // capture updates). Auto-redraw only when the user enabled it.
    if (dlg->auto_refresh_button_ && dlg->auto_refresh_button_->isChecked()) {
        dlg->drawTree();
    }
}

void MkaCaDialog::rescan()
{
    capture_file *cf = cap_file_.capFile();
    if (cf == NULL) {
        return;
    }

    // Do not start a retap while the capture file is being read/retapped (e.g. a live capture update).
    if (cf->read_lock) {
        return;
    }

    mka_ca_stat_reset(stat_);
    cf_retap_packets(cf);
}

// Append a simple "label : value" child under parent.
static QTreeWidgetItem *addChild(QTreeWidgetItem *parent, const QString &label, const QString &detail = QString(), const QString &timing = QString())
{
    QTreeWidgetItem *item = new QTreeWidgetItem(parent);

    item->setText(col_item_, label);
    item->setText(col_detail_, detail);
    item->setText(col_timing_, timing);

    return item;
}

// Bolds the item and detail columns of a tree item to flag the SCI/MI of a
// peer that is new to the group (a reset node with a new MI). The timing
// column is left to its own delegate.
static void setItemBold(QTreeWidgetItem *item)
{
    for (int c : {col_item_, col_detail_}) {
        QFont f = item->font(c);
        f.setBold(true);
        item->setFont(c, f);
    }
}

static void fillPeer(QTreeWidgetItem *ca_item, mka_ca_peer_t *peer, const mka_ca_stat_t *st)
{
    QString label = QString("%1%2").arg(sciToStr(peer->sci)).arg(peer->key_server ? QObject::tr(" [Key Server]") : QString());
    QTreeWidgetItem *peer_item = addChild(ca_item, label);

    peer_item->setData(col_item_, filter_role_, sciToFilter(peer->sci));

    // With resolution on, the label shows the resolved name; add the raw SCI
    // as a detail row so the underlying identifier stays visible.
    if (gbl_resolv_flags.mac_name) {
        QTreeWidgetItem *sci_item = addChild(peer_item, QObject::tr("SCI"), sciRawStr(peer->sci));
        sci_item->setData(col_item_, filter_role_, sciToFilter(peer->sci));
    }

    // Detected MIs for this SCI; each shows its own last-heard time and
    // filters the frames that MI appears in.
    unsigned n_mis = peer->mis ? peer->mis->len : 0;
    QTreeWidgetItem *mis_folder = addChild(peer_item, QObject::tr("Detected MIs (%1)").arg(n_mis));

    for (unsigned i = 0; i < n_mis; i++) {
        const mka_ca_mi_t *m = (const mka_ca_mi_t *)g_ptr_array_index(peer->mis, i);
        QString frame_range;

        if (m->first_frame == m->last_frame) {
            frame_range = QString("Frame %1").arg(m->first_frame);
        } else {
            frame_range = QString("Frames %1 - %2").arg(m->first_frame).arg(m->last_frame);
        }

        QString time_range;
        if (st->have_start) {
            nstime_t first_rel, last_rel;
            nstime_delta(&first_rel, &m->first_seen, &st->start_time);
            nstime_delta(&last_rel, &m->last_seen, &st->start_time);
            time_range = QString("+%1 s - +%2 s").arg(nstime_to_sec(&first_rel), 0, 'f', 6).arg(nstime_to_sec(&last_rel), 0, 'f', 6);
        } else {
            time_range = QString("");
        }

        QTreeWidgetItem *mi_item = addChild(mis_folder, bytesToHex(m->mi, MKA_CA_MI_LEN), frame_range, time_range);

        mi_item->setData(col_item_, filter_role_, miToFilter(m->mi, m->first_frame, m->last_frame));
        mi_item->setData(col_item_, frame_num_role_, (uint)m->first_frame);
    }
}

static void fillForm(QTreeWidgetItem *ca_item, const mka_form_t *form,
                     const QString &ckn_colon_hex)
{
    QString label = QString::fromUtf8(mka_form_kind_str(form->kind));

    unsigned activated, total;
    double max_sec = mka_form_time(form, NULL, &activated, &total);
    QString timing;

    if (total == 0) {
        timing = QObject::tr("no peers");
    } else if (activated == 0) {
        timing = QObject::tr("no peers activated (0/%1 peers)").arg(total);
    } else {
        // Show the longest activation time among the peers that activated,
        // with the activated/total count.
        timing = QObject::tr("Formation Time %1 ms (%2/%3 Peers)").arg(max_sec * 1000.0, 0, 'f', 3).arg(activated).arg(total);
    }

    QTreeWidgetItem *form_item = addChild(ca_item, label,
        QObject::tr("KN %1  AN %2  Frames %3 - %4")
            .arg(form->kn).arg(form->an).arg(form->trigger_frame).arg(form->end_frame), timing);

    form_item->setData(col_item_, frame_num_role_, (uint)form->trigger_frame);
    form_item->setData(col_item_, filter_role_, formToFilter(ckn_colon_hex, form->trigger_frame, form->end_frame));

    QTreeWidgetItem *ks_sci_item = addChild(form_item, QObject::tr("Key Server SCI"), sciToStr(form->ks_sci));
    ks_sci_item->setData(col_item_, filter_role_, ksToFilter(form->ks_mi));

    QTreeWidgetItem *ks_mi_item = addChild(form_item, QObject::tr("Key Server MI"), bytesToHex(form->ks_mi, MKA_CA_MI_LEN));
    ks_mi_item->setData(col_item_, filter_role_, ksToFilter(form->ks_mi));

    if (form->sak_len != 0) {
        addChild(form_item, QObject::tr("Target SAK"), bytesToHex(form->sak, form->sak_len));
    } else {
        addChild(form_item, QObject::tr("Target SAK"), QObject::tr("<Unable to unwrap SAK>"));
    }

    // Each peer is collected under a 'Peers' folder. Its timings column
    // summarizes install / formation / retirement times.
    QTreeWidgetItem *peers_folder = addChild(form_item, QObject::tr("Peers (%1)").arg(g_hash_table_size(form->peers)));
    peers_folder->setData(col_item_, form_peers_role_, true);

    // Find the longest install / formation / retirement time so those
    // worst-case values can be shown in bold. Compare on the same value that
    // is displayed (milliseconds rounded to 3 decimals) so every peer showing
    // the longest displayed time is bolded consistently. A negative sentinel
    // means no peer has that value yet.
    double max_itime = -1.0, max_ftime = -1.0, max_rtime = -1.0;
    {
        GHashTableIter mit;
        void *mk, *mv;

        g_hash_table_iter_init(&mit, form->peers);

        while (g_hash_table_iter_next(&mit, &mk, &mv)) {
            mka_form_peer_t *p = (mka_form_peer_t *)mv;
            if (p->has_installed) {
                nstime_t t; nstime_delta(&t, &p->installed, &form->trigger_time);
                double ms = qRound64(nstime_to_sec(&t) * 1000.0 * 1000.0) / 1000.0;
                if (ms > max_itime) max_itime = ms;
            }

            if (p->has_activated) {
                nstime_t t; nstime_delta(&t, &p->activated, &form->trigger_time);
                double ms = qRound64(nstime_to_sec(&t) * 1000.0 * 1000.0) / 1000.0;
                if (ms > max_ftime) max_ftime = ms;
            }

            if (p->has_latest_slot && p->has_demoted) {
                nstime_t t; nstime_delta(&t, &p->demoted, &p->latest_slot);
                double ms = qRound64(nstime_to_sec(&t) * 1000.0 * 1000.0) / 1000.0;
                if (ms > max_rtime) max_rtime = ms;
            }
        }
    }

    GHashTableIter iter;
    void *k, *v;

    g_hash_table_iter_init(&iter, form->peers);

    while (g_hash_table_iter_next(&iter, &k, &v)) {
        mka_form_peer_t *fp = (mka_form_peer_t *)v;
        QString ftime;

        if (fp->has_activated) {
            nstime_t d;
            nstime_delta(&d, &fp->activated, &form->trigger_time);
            ftime = QString("%1 ms").arg(nstime_to_sec(&d) * 1000.0, 0, 'f', 3);
        } else {
            ftime = QObject::tr("not activated");
        }

        QString itime;
        if (fp->has_installed) {
            nstime_t in;
            nstime_delta(&in, &fp->installed, &form->trigger_time);
            itime = QString("%1 ms").arg(nstime_to_sec(&in) * 1000.0, 0, 'f', 3);
        } else {
            itime = QObject::tr("not installed");
        }

        QString rtime;
        bool has_retirement = fp->has_latest_slot && fp->has_demoted;
        if (fp->has_demoted && !fp->has_latest_slot) {
            // Moved to the old slot without a latest-slot sighting first.
            rtime = QObject::tr("immediate");
        } else if (has_retirement) {
            // Latest slot until the SAK is rotated to the old slot.
            nstime_t r;
            nstime_delta(&r, &fp->demoted, &fp->latest_slot);
            rtime = QString("%1 ms").arg(nstime_to_sec(&r) * 1000.0, 0, 'f', 3);
        } else {
            rtime = QObject::tr("not retired");
        }

        bool is_ks = (memcmp(fp->sci, form->ks_sci, MKA_CA_SCI_LEN) == 0);
        // New to the group if this peer's MI was not in the prior formation (presents a new MI).
        bool is_new = !is_ks && fp->is_new;
        QString peer_label = QString("%1%2").arg(sciToStr(fp->sci)).arg(is_ks ? QObject::tr(" [KS]") : QString());

        // Timings column: install / formation / retirement. The segment(s)
        // holding the formation's longest value are bolded.
        bool itime_max = false, ftime_max = false, rtime_max = false;
        if (fp->has_installed) {
            nstime_t t; nstime_delta(&t, &fp->installed, &form->trigger_time);
            double ms = qRound64(nstime_to_sec(&t) * 1000.0 * 1000.0) / 1000.0;
            itime_max = (ms >= max_itime);
        }

        if (fp->has_activated) {
            nstime_t t; nstime_delta(&t, &fp->activated, &form->trigger_time);
            double ms = qRound64(nstime_to_sec(&t) * 1000.0 * 1000.0) / 1000.0;
            ftime_max = (ms >= max_ftime);
        }

        if (fp->has_latest_slot && fp->has_demoted) {
            nstime_t t; nstime_delta(&t, &fp->demoted, &fp->latest_slot);
            double ms = qRound64(nstime_to_sec(&t) * 1000.0 * 1000.0) / 1000.0;
            rtime_max = (ms >= max_rtime);
        }

        QString peer_timing = QObject::tr("%1 / %2 / %3")
                                  .arg(itime).arg(ftime).arg(rtime);
        QString peer_timing_html = QString("%1 / %2 / %3")
            .arg(itime_max ? "<b>" + itime.toHtmlEscaped() + "</b>" : itime.toHtmlEscaped())
            .arg(ftime_max ? "<b>" + ftime.toHtmlEscaped() + "</b>" : ftime.toHtmlEscaped())
            .arg(rtime_max ? "<b>" + rtime.toHtmlEscaped() + "</b>" : rtime.toHtmlEscaped());
        QTreeWidgetItem *peer_item = addChild(peers_folder, peer_label, QString(), peer_timing);

        if (itime_max || ftime_max || rtime_max) {
            peer_item->setData(col_timing_, html_role_, peer_timing_html);
        }

        // Bold the peer row when it is new to the group (new MI).
        if (is_new) {
            setItemBold(peer_item);
        }

        // The peer row navigates to its activation frame when known.
        if (fp->has_activated) {
            peer_item->setData(col_item_, frame_num_role_, (uint)fp->activated_frame);
        }

        // Filter on this peer's MKPDUs within the formation's frame range.
        peer_item->setData(col_item_, filter_role_,
            QString("(%1) && frame.number >= %2 && frame.number <= %3")
                .arg(sciToFilter(fp->sci)).arg(form->trigger_frame).arg(form->end_frame));

        // With resolution on, the label shows the resolved name; add the raw
        // SCI as a detail row so the underlying identifier stays visible.
        if (gbl_resolv_flags.mac_name) {
            addChild(peer_item, QObject::tr("SCI"), sciRawStr(fp->sci));
        }

        if (fp->have_mi) {
            QTreeWidgetItem *mi_item = addChild(peer_item, QObject::tr("MI"), bytesToHex(fp->mi, MKA_CA_MI_LEN));
            // Bold the new MI that makes this peer new to the group.
            if (is_new) {
                setItemBold(mi_item);
            }
        }

        QTreeWidgetItem *itime_item = addChild(peer_item, QObject::tr("Installation Time"), QString(), itime);
        if (fp->has_installed) {
            itime_item->setData(col_item_, frame_num_role_, (uint)fp->installed_frame);
        }

        QTreeWidgetItem *ftime_item = addChild(peer_item, QObject::tr("Formation Time"), QString(), ftime);
        if (fp->has_activated) {
            ftime_item->setData(col_item_, frame_num_role_, (uint)fp->activated_frame);
        }

        QTreeWidgetItem *rtime_item = addChild(peer_item, QObject::tr("Retirement Time"), QString(), rtime);
        if (has_retirement) {
            rtime_item->setData(col_item_, frame_num_role_, (uint)fp->demoted_frame);
        }
    }
}

// Stable path key for a tree item: for each of it and its ancestors, the
// item-column text (with any trailing " (N)" count stripped so folder labels
// match as counts grow) plus a stabilized detail column, which distinguishes
// sibling rows that share a label (e.g. formation episodes named only by
// kind, with the frame range in the detail column). A trailing " - N" in the
// detail (an episode end frame that grows during live capture) is stripped so
// the key stays stable across refreshes. Used to preserve expansion state.
static QString itemPathKey(QTreeWidgetItem *item)
{
    static const QRegularExpression count_re(" \\(\\d+\\)$");
    static const QRegularExpression end_re(" - \\d+$");
    QStringList parts;

    for (QTreeWidgetItem *it = item; it != NULL; it = it->parent()) {
        QString t = it->text(col_item_);
        t.remove(count_re);

        QString d = it->text(col_detail_);
        d.remove(end_re);

        parts.prepend(d.isEmpty() ? t : (t + QChar('\x1f') + d));
    }

    return parts.join(QChar('/'));
}

void MkaCaDialog::fillTree()
{
    // Full refresh: re-tap the capture, then rebuild the tree. Only safe when
    // not already inside a capture-driven retap (see mkaCaptureEvent, which
    // redraws without re-tapping).
    rescan();
    drawTree();
}

void MkaCaDialog::drawTree()
{
    displayFilterLineEdit()->setEnabled(false);
    applyFilterButton()->setEnabled(false);

    // Preserve expansion and selection across the rebuild.
    QSet<QString> expanded;
    QString selected;
    for (QTreeWidgetItemIterator it(statsTreeWidget()); *it; ++it) {
        if ((*it)->isExpanded()) {
            expanded.insert(itemPathKey(*it));
        }
        if ((*it)->isSelected()) {
            selected = itemPathKey(*it);
        }
    }

    bool had_items = statsTreeWidget()->topLevelItemCount() > 0;

    // Keep items in insertion order (ascending by frame); the tree default
    // sorting would otherwise reorder episodes alphabetically.
    statsTreeWidget()->setSortingEnabled(false);
    statsTreeWidget()->clear();

    GHashTableIter ca_iter;
    void *ck, *cv;

    g_hash_table_iter_init(&ca_iter, stat_->cas);

    while (g_hash_table_iter_next(&ca_iter, &ck, &cv)) {
        mka_ca_t *ca = (mka_ca_t *)cv;
        const mka_ckn_info_t *info = ca->ckn_info;

        QString name = (info && info->name) ? QString::fromUtf8(info->name) : tr("<CKN not in table>");
        QTreeWidgetItem *ca_item = new QTreeWidgetItem(statsTreeWidget());

        ca_item->setText(col_item_, QString("CA: %1").arg(name));

        if (ca->ckn_len > 0) {
            ca_item->setText(col_detail_, QString("CKN %1").arg(bytesToHex(ca->ckn, ca->ckn_len)));
        }

        QTreeWidgetItem *peers_folder = addChild(ca_item, tr("Peers (%1)").arg(g_hash_table_size(ca->peers)));
        GHashTableIter piter;
        void *pk, *pv;

        g_hash_table_iter_init(&piter, ca->peers);

        while (g_hash_table_iter_next(&piter, &pk, &pv)) {
            fillPeer(peers_folder, (mka_ca_peer_t *)pv, stat_);
        }

        QTreeWidgetItem *ks_folder = addChild(ca_item, tr("Key Server History (%1)").arg(ca->key_servers->len));

        for (unsigned i = 0; i < ca->key_servers->len; i++) {
            mka_ks_t *ks = (mka_ks_t *)g_ptr_array_index(ca->key_servers, i);
            QString frame_range;

            if (ks->first_frame == ks->last_frame) {
                frame_range = QString("Frame %1").arg(ks->first_frame);
            } else {
                frame_range = QString("Frames %1 - %2").arg(ks->first_frame).arg(ks->last_frame);
            }

            QTreeWidgetItem *ks_item = addChild(ks_folder, sciToStr(ks->sci), QString("MI %1").arg(bytesToHex(ks->mi, MKA_CA_MI_LEN)),
                                                frame_range);
            ks_item->setData(col_item_, frame_num_role_, (uint)ks->first_frame);
            ks_item->setData(col_item_, filter_role_, ksToFilterRange(ks->mi, ks->first_frame, ks->last_frame));
        }

        QTreeWidgetItem *form_folder = addChild(ca_item, tr("Peer Group Formations (%1)").arg(ca->forms->len));
        QString ckn_colon_hex;
        if (ca->ckn_len > 0) {
            ckn_colon_hex = bytesToColonHex(ca->ckn, ca->ckn_len);
        }

        for (unsigned i = 0; i < ca->forms->len; i++) {
            fillForm(form_folder, (mka_form_t *)g_ptr_array_index(ca->forms, i),
                     ckn_colon_hex);
        }

        // Expand CA nodes by default only on the first draw.
        if (!had_items) {
            ca_item->setExpanded(true);
        }
    }

    // Restore the expansion and selection captured before the rebuild.
    if (had_items) {
        for (QTreeWidgetItemIterator it(statsTreeWidget()); *it; ++it) {
            QString key = itemPathKey(*it);
            if (expanded.contains(key)) {
                (*it)->setExpanded(true);
            }
            if (!selected.isEmpty() && key == selected) {
                (*it)->setSelected(true);
            }
        }
    }

    displayFilterLineEdit()->setEnabled(true);
    applyFilterButton()->setEnabled(true);
}

QList<QVariant> MkaCaDialog::treeItemData(QTreeWidgetItem *ti) const
{
    QList<QVariant> row_data;

    row_data << ti->text(col_item_) << ti->text(col_detail_) << ti->text(col_timing_);
    return row_data;
}

const QString MkaCaDialog::filterExpression()
{
    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];
        QVariant f = ti->data(col_item_, filter_role_);

        if (f.isValid()) {
            return f.toString();
        }
    }

    return QString();
}

void MkaCaDialog::itemDoubleClicked(QTreeWidgetItem *item, int)
{
    if (item == NULL) {
        return;
    }

    QVariant frame = item->data(col_item_, frame_num_role_);
    if (frame.isValid() && frame.toUInt() > 0) {
        emit goToPacket((int)frame.toUInt());
    }
}

void MkaCaDialog::itemExpanded(QTreeWidgetItem *item)
{
    if (item == NULL) {
        return;
    }

    // Auto-expand a formation's 'Peers' folder when the formation is opened.
    for (int i = 0; i < item->childCount(); i++) {
        QTreeWidgetItem *child = item->child(i);
        if (child->data(col_item_, form_peers_role_).toBool()) {
            child->setExpanded(true);
        }
    }
}

TapParameterDialog *MkaCaDialog::createMkaCaDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf)
{
    if (cfg_str != mka_ca_stat_cfg) {
        return NULL;
    }

    return new MkaCaDialog(parent, cf, filter.toUtf8().constData());
}

extern "C" {

static bool
mka_ca_dialog_init(const char *args, void*)
{
    QStringList args_l = QString(args).split(',');
    QByteArray filter;

    if (args_l.length() > 2) {
        filter = QStringList(args_l.mid(2)).join(",").toUtf8();
    }
    mainApp->emitTapParameterSignal(mka_ca_stat_cfg, filter.constData(), NULL);

    return true;
}

void register_tap_listener_qt_mka_ca(void);

void
register_tap_listener_qt_mka_ca(void)
{
    TapParameterDialog::registerDialog(
                "EAPOL-MKA Connectivity Associations",
                mka_ca_stat_cfg,
                REGISTER_STAT_GROUP_GENERIC,
                mka_ca_dialog_init,
                MkaCaDialog::createMkaCaDialog);
}

}
