/* distribution_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "distribution_dialog.h"

#include <cmath>

#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/tap.h>
#include <epan/epan_dissect.h>

#include "main_application.h"
#include "ui/qt/ui_tap_parameter_dialog.h"

enum {
    col_fvalue_,
    col_counter_,
    col_percent_
};

/*
 * Some aggregated FTs as if they were coming from an FT_IS_ macro.
 * Helps sorting the Field Name column.
 */
enum {
    AGG_FT_INT,
    AGG_FT_STRING,
    AGG_FT_IP
};

struct _tap_elts {
    int count;
    QTreeWidgetItem *item;
};

/*
 * Return true if the given field supports this distribution stats, false otherwise.
 */
static int
hfi_supports_distribution(const header_field_info *hfi) {
    if (FT_IS_STRING(hfi->type)) {
        return FT_STRING;
    }
    else if(FT_IS_INTEGER(hfi->type))  {
        return FT_INT32;
    }
    else {
        switch (hfi->type) {
        case FT_IPv4:
        case FT_IPv6:
            return FT_IPv4;
        default:
            /* not supported FT, return false */
            return 0;
        }
    }
}

static gboolean
alwaysTrue(void *key _U_, void *value _U_, void *data _U_) {
    return true;
}

/* Normalized Shannon */
double normalized_shannon(const int *freq, size_t n_symbols, size_t total) {

    /* ensure we have enough data or there's not much sense to compute */
    if (total == 0 || n_symbols < 2) {
        return 0.0;
    }

    double H = 0.0;
    for (size_t i = 0; i < n_symbols; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)total;
        H -= p * log2(p);
    }

    return H / log2((double)n_symbols);
}

class DistributionStatTreeWidgetItem : public QTreeWidgetItem
{
public:
    DistributionStatTreeWidgetItem (QTreeWidget *parent, QString field_name, int field_type) :
        QTreeWidgetItem (parent)
    {
        field_name_ = field_name;
        field_type_ = field_type;
    }

    ~DistributionStatTreeWidgetItem()
    {
    }

    void draw() {
    }

    bool isMatch(const char *fieldName) {
        return fieldName == field_name_;
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        const DistributionStatTreeWidgetItem *other_row = static_cast<const DistributionStatTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {

        /* typically sorting based on an aggregate FT value */
        case col_fvalue_:
            switch (field_type_) {

            case AGG_FT_INT:
                return field_name_.toInt() < other_row-> field_name_.toInt();
                break;

            /* no specific handling for Strings and IPs,
             * though the latter would benefit of a better sorting */
            case AGG_FT_STRING:
            case AGG_FT_IP:
                break;

            default:
                break;
            }

            break;

        case col_counter_:
            return count() < other_row->count();
        case col_percent_:
            return percent() < other_row->percent();
        default:
            break;
        }
        return QTreeWidgetItem::operator< (other);
    }

    void update(int new_count) {
        count_ = new_count;
        setText(col_counter_, QString::number(count_));
        setTextAlignment(col_counter_, Qt::AlignRight);
    }

    void updatePercentage(int new_count) {
        percent_ = count_ * 100.0 / new_count;
        setText(col_percent_, QString::number(percent_, 'f', 2));
        setTextAlignment(col_percent_, Qt::AlignRight);
    }

    QList<QVariant> rowData() {
        return QList<QVariant>()
                << field_name_
                << occurrences()
                << data(col_percent_, Qt::UserRole).toDouble();
    }

    const QString filterExpression(QString f, bool quotes) {
        QString filter_expr;

        if(quotes) {
            filter_expr = QStringLiteral("%1==\"%2\"")
                .arg(f).arg(field_name_.constData());
        }
        else {
            filter_expr = QStringLiteral("%1==%2")
                .arg(f).arg(field_name_.constData());
        }

        return filter_expr;
    }

    int count() const {
        return count_;
    }
    double percent() const {
        return percent_;
    }

protected:
    int occurrences() const { return count_; }

private:
    QString field_name_;
    int field_type_ = 0;
    int count_ = 0;
    double percent_ = 0;

};

DistributionDialog::DistributionDialog(QWidget &parent, CaptureFile &cf, const QString &filter) :
    TapParameterDialog(parent, cf, 0),
    packet_count_(0),
    displayFilter_(""), // no default value when opening from the stats menu
    needsQuotes_(0)
{
    hf_index_ = -1;
    fvalues_map = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);

    if (!registerTapListener("frame",
                             this,
                             displayFilter_.toUtf8().data(),
                             TL_REQUIRES_PROTO_TREE,
                             tapReset,
                             tapPacket,
                             tapDraw)) {
        tap_registered_ = false;
        return;
    }
    else {
        tap_registered_ = true;
    }

    setWindowSubtitle(tr("Field Values Distribution"));
    loadGeometry(parent.width() * 4 / 5, parent.height() * 3 / 4, "DistributionDialog");

    /* Override the inherited Display Filter label */
    getUI()->label->setText("Distribution Field");

    QStringList header_labels = QStringList()
            << tr("Field Value") << tr("Occurrences") << tr("Percent");
    statsTreeWidget()->setHeaderLabels(header_labels);

    for (int col = 0; col < statsTreeWidget()->columnCount(); col++) {
        if (col == col_fvalue_ ) continue;
        statsTreeWidget()->headerItem()->setTextAlignment(col, Qt::AlignRight);
    }

    // Set handler for when display filter string is changed.
    connect(this, SIGNAL(updateFilter(QString)),
            this, SLOT(filterUpdated(QString)));
    connect(this, SIGNAL(updateFilter(QString)),
            this, SLOT(updateLabels()));

    addFilterActions();

    if (!filter.isEmpty()) {
        setDisplayFilter(filter);
    }
}

DistributionDialog::~DistributionDialog() { }

void DistributionDialog::updateLabels()
{
    /* update the window subtitle */
    setWindowSubtitle(tr("Distribution:") + displayFilter());
}

/*
 * Inherited buttons behavior,
 * overloaded with the named field type check to decide if conditions
 * for calculating the distributions are met.
 */
void DistributionDialog::updateWidgets()
{
    int supports_distribution = 0;
    const header_field_info* hfi = proto_registrar_get_byname(displayFilter().toUtf8().data());
    if (hfi) {
        hf_index_ = hfi->id;
        supports_distribution = hfi_supports_distribution(hfi);
        if(supports_distribution) {
            /* Remember if quotes are needed for a display filter,
             * and the field type then we can sort the column properly.
             */
            setFilterQuotes(supports_distribution);
            setFieldType(supports_distribution);
        }
    }

    bool edit_enable = true;
    bool apply_enable = true;

    if (file_closed_ || !cap_file_.isValid()) {
        edit_enable = false;
        apply_enable = false;
    } else if (!supports_distribution || !getUI()->displayFilterLineEdit->checkFilter()) {
        // XXX Tell the user why the filter is invalid.
        apply_enable = false;
    }

    getUI()->displayFilterLineEdit->setEnabled(edit_enable);
    getUI()->applyFilterButton->setEnabled(apply_enable);

    WiresharkDialog::updateWidgets();
}

void DistributionDialog::tapRemoveAll(void *ws_dlg_ptr)
{
    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    if (!ws_dlg->fvalues_map) return;

    wmem_map_foreach_remove(ws_dlg->fvalues_map, alwaysTrue, NULL);
}

void DistributionDialog::tapReset(void *ws_dlg_ptr)
{
    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    tapRemoveAll(ws_dlg_ptr);
    ws_dlg->statsTreeWidget()->clear();
    ws_dlg->packet_count_ = 0;
}

tap_packet_status DistributionDialog::tapPacket(void *tap_data, _packet_info *, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t)
{
    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(tap_data);

    // ensure the tap dfilter was consistently managed
    if(!edt)
        return TAP_PACKET_FAILED;
    else {

        // ensure we really have a display filter - XXX manage this by storing a longer lasting value ?
        // All unexpected cases (no display filter, nothing returned by finfo,.. are just ignored 
        if(!ws_dlg->displayFilter_.isEmpty()) {

            /* While tolerated technically, different fields with the same abbreviation can
             * give unpredictable or weird results.
             * One way to handle this, is to declare the "real" field last in its dissector,
             * if the ambiguity is in the same dissector.
             * Or loop through all possible head_field_info matching the abbrev, skip the ones which
             * don't have values, which is what is done here.
             */
            const header_field_info* hfi = proto_registrar_get_byname(ws_dlg->displayFilter_.toUtf8().constData());
            if(hfi) {
                while (hfi->same_name_prev_id != -1) {
                    /* Rewind (shouldn't be necessary.) */
                    hfi = proto_registrar_get_nth(hfi->same_name_prev_id);
                }

                for (; hfi; hfi = hfi->same_name_next) {
                    epan_dissect_prime_with_hfid(edt, hfi->id);
                    GPtrArray *finfos = proto_get_finfo_ptr_array(edt->tree, hfi->id);
                    if( (finfos != NULL) && (g_ptr_array_len(finfos) != 0) ) {
                        for (unsigned i = 0; i < finfos->len; i++) {

                            const char* value;
                            const field_info* fip = static_cast<field_info*>(finfos->pdata[i]);
                            if (fip) {
                                value = fvalue_to_string_repr(NULL, fip->value, FTREPR_DISPLAY, 0);

                                /* if the key is known, just increment the counter */
                                if(wmem_map_contains(ws_dlg->fvalues_map, value)) {

                                    _tap_elts *tap_elt = static_cast<_tap_elts*>(wmem_map_lookup(ws_dlg->fvalues_map, value));
                                    tap_elt->count++;
                                }
                                else { /* otherwise insert the key, initialize counter to 0 */

                                    _tap_elts *p_new_tap_elt = wmem_new0(wmem_epan_scope(), struct _tap_elts);
                                    p_new_tap_elt->count = 1;
                                    wmem_map_insert(ws_dlg->fvalues_map, wmem_strdup(wmem_epan_scope(), value), p_new_tap_elt);
                                }

                                /* percentages tracking */
                                ws_dlg->packet_count_++;
                            }
                        }
                    }
                    // else : just ignore/skip, as there is not data to handle (possibly because of multiple hfi matching
                }
            }
        }
    }
    return TAP_PACKET_REDRAW;
}

void DistributionDialog::createItem(void *key, void *value, void *user_data) {

    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(user_data);
    QTreeWidget *tree = ws_dlg->statsTreeWidget();

    DistributionStatTreeWidgetItem *item = new DistributionStatTreeWidgetItem(tree, QString((char *)key), ws_dlg->field_type_ );
    item->setText(0 , QString ((char *)key) );
    item->update(static_cast<_tap_elts *>(value)->count);
}

void DistributionDialog::insertOccurence(void *key _U_, void *value, void *user_data) {
    wmem_array_t *arr = static_cast<wmem_array_t *>(user_data);
    wmem_array_append(arr, &static_cast<_tap_elts *>(value)->count, 1);
}

void DistributionDialog::setFilterQuotes(int type_filter) {
    switch (type_filter) {
    case FT_STRING:
        needsQuotes_ = true;
        break;
    default:
        needsQuotes_ = false;
        break;
    }
}

/* raw types are converted to their aggregate type, or defaults to String */
void DistributionDialog::setFieldType(int raw_type) {

    if (FT_IS_STRING(raw_type)) {
        field_type_ = AGG_FT_STRING;
    }
    else if (FT_IS_INTEGER(raw_type)) {
        field_type_ = AGG_FT_INT;
    }
    else {
        switch (raw_type) {
        case FT_IPv4:
        case FT_IPv6:
            field_type_ = AGG_FT_IP;
            break;
        default:
            field_type_ = AGG_FT_STRING;
        }
    }
}

void DistributionDialog::tapDraw(void *ws_dlg_ptr)
{

    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    ws_dlg->statsTreeWidget()->clear();

    /* create the items - 1 item for 1 named field */
    wmem_map_foreach(ws_dlg->fvalues_map, createItem, ws_dlg);

    QTreeWidgetItemIterator it(ws_dlg->statsTreeWidget());
    while (*it) {
        DistributionStatTreeWidgetItem *fvd_ts_ti = static_cast<DistributionStatTreeWidgetItem *>((*it));
        if(fvd_ts_ti) {
            fvd_ts_ti->updatePercentage(ws_dlg->packet_count_);
        }
        ++it;
    }

    /*
     * Override the HintLabel and indicate an entropy factor (H), (Normalized Shannon)
     * First, build an array with the distribution values,
     * then send it to the dedicated function which computes this H indicator.
     */
    wmem_array_t *arr = wmem_array_new(wmem_epan_scope(), sizeof(int));
    wmem_map_foreach(ws_dlg->fvalues_map, insertOccurence, arr);

    int *freq  = (int *)wmem_array_get_raw(arr);
    int nsym  = wmem_array_get_count(arr);

    int total = 0;
    for (int i = 0; i < nsym; i++)
        total += freq[i];

    double h = normalized_shannon(freq, nsym, total);

    ws_dlg->setHint(QString("Entropy (Normalized Shannon): " + QString::number( h ) ));
}

const QString DistributionDialog::filterExpression()
{
    QString filter_expr;
    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];

        DistributionStatTreeWidgetItem *fvd_ti = static_cast<DistributionStatTreeWidgetItem *>(ti);
        filter_expr = fvd_ti->filterExpression(displayFilter_, needsQuotes_);
    }
    return filter_expr;
}

void DistributionDialog::fillTree()
{
    if(!displayFilter_.isEmpty())
        set_tap_dfilter(this, displayFilter_.toUtf8().data() );
    else {
        set_tap_dfilter(this, "tcp.completeness.str" );
    }

    statsTreeWidget()->setSortingEnabled(false);
    cap_file_.retapPackets();
    tapDraw(this);
    statsTreeWidget()->setSortingEnabled(true);
}

void DistributionDialog::captureFileClosing()
{
    remove_tap_listener(this);

    WiresharkDialog::captureFileClosing();
}

// Store filter from signal.
void DistributionDialog::filterUpdated(QString filter)
{
    /* don't overwrite the default value when starting */
    if(!filter.isEmpty()) {
        displayFilter_ = filter;
    }
}

// This is how an item is represented for exporting.
QList<QVariant> DistributionDialog::treeItemData(QTreeWidgetItem *it) const
{
    // Cast up to our type.
    DistributionStatTreeWidgetItem *nit = dynamic_cast<DistributionStatTreeWidgetItem *>(it);
    if (nit) {
        return nit->rowData();
    }

    return QList<QVariant>();
}

static bool
distribution_statistics_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    QByteArray filter;
    if (args_l.length() > 2) {
        filter = QStringList(args_l.mid(2)).join(",").toUtf8();
    }
    mainApp->emitStatCommandSignal("Distribution", filter.constData(), NULL);
    return true;
}

static stat_tap_ui distribution_statistics_ui = {
    REGISTER_PACKET_ANALYZE_GROUP_UNSORTED,
    NULL,
    "distribution,stat",
    distribution_statistics_init,
    0,
    NULL
};

extern "C" {

void register_tap_listener_qt_distribution_statistics(void);

void
register_tap_listener_qt_distribution_statistics(void)
{
    register_stat_tap_ui(&distribution_statistics_ui, NULL);
}

}
