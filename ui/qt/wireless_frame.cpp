/* wireless_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wireless_frame.h"
#include <ui_wireless_frame.h>

#include "config.h"

#include <capture/capture_session.h>
#include <capture/capture_sync.h>

#include <capture/ws80211_utils.h>

#include "ui/ws_ui_util.h"
#include <wsutil/utf8_entities.h>
#include <wsutil/802_11-utils.h>
#include "main_application.h"
#include "utils/qt_ui_utils.h"

#include <QProcess>
#include <QAbstractItemView>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>

// To do:
// - Push more status messages ("switched to...") to the status bar.
// - Add a "Decrypt in the driver" checkbox?
// - Check for frequency and channel type changes.
// - Figure out some way to handle 80+80 channels
// - Find something appropriate to run from the helperToolButton on Linux.

// Questions:
// - From our perspective, what's the difference between "NOHT" and "HT20"?

const int update_interval_ = 1500; // ms

/* The various itemData(), findData(), currentData() functions in QComboBox
 * default to Qt::UserRole, whereas the similar functions in QStandardItem
 * default to Qt::UserRole + 1 (so they won't collide, I suppose), and
 * functions in QStandardItemModel/QAbstractItemModel to Qt::DisplayRole,
 * so for clarity explicitly pass a role.
 */
const int DataRole = Qt::UserRole + 1;
const int BandRole = Qt::UserRole + 2;

Q_DECLARE_METATYPE(struct ws80211_frequency)
Q_DECLARE_METATYPE(enum ws80211_channel_type)
Q_DECLARE_METATYPE(enum ws80211_band_type)

class BandProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    BandProxyModel(QObject *parent = nullptr)
        : QSortFilterProxyModel(parent), m_band(WS80211_BAND_2GHZ)
    {
        QStandardItemModel* model = new QStandardItemModel(this);
        setSourceModel(model);
    }
    void setBand(enum ws80211_band_type band)
    {
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
        beginFilterChange();
#endif
        m_band = band;
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
        endFilterChange(QSortFilterProxyModel::Direction::Rows);
#elif QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        invalidateRowsFilter();
#else
        invalidateFilter();
#endif
    }
    void addItem(const QString& text, enum ws80211_band_type band, const QVariant &data = QVariant())
    {
        QStandardItemModel* model = qobject_cast<QStandardItemModel*>(sourceModel());
        if (model != nullptr) {
            QStandardItem *item = new QStandardItem(text);
            item->setData(data, DataRole);
            item->setData(band, BandRole);
            model->appendRow(item);
        }
    }
    void clearSourceModel()
    {
        QStandardItemModel* model = qobject_cast<QStandardItemModel*>(sourceModel());
        if (model != nullptr)
            model->clear();
    }

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex&) const override
    {
        QStandardItemModel* model = qobject_cast<QStandardItemModel*>(sourceModel());
        if (model != nullptr) {
            QStandardItem* item = model->item(sourceRow);

            QVariant myBand = item->data(BandRole);
            if (qvariant_cast<enum ws80211_band_type>(myBand) == m_band) {
                return true;
            }
        }
        return false;
    }

private:
    enum ws80211_band_type m_band;
};

class ChanTypeProxyModel : public BandProxyModel
{
    Q_OBJECT

public:
    ChanTypeProxyModel(QObject *parent = nullptr)
        : BandProxyModel(parent), m_mask(0)
    {
        QStandardItemModel* model = new QStandardItemModel(this);
        setSourceModel(model);
    }
    void setMask(int mask)
    {
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
        beginFilterChange();
#endif
        m_mask = mask;
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
        endFilterChange(QSortFilterProxyModel::Direction::Rows);
#elif QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        invalidateRowsFilter();
#else
        invalidateFilter();
#endif
    }

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override
    {
        QStandardItemModel* model = qobject_cast<QStandardItemModel*>(sourceModel());
        if (model != nullptr) {
            QStandardItem* item = model->item(sourceRow);

            if (m_mask) {
                QVariant myData = item->data(DataRole);
                enum ws80211_channel_type chan_type = qvariant_cast<enum ws80211_channel_type>(myData);
                if (m_mask & (1 << chan_type)) {
                    return false;
                }
            }
        }
        return BandProxyModel::filterAcceptsRow(sourceRow, sourceParent);
    }

private:
    int m_mask; // QFlags? (easier to use Qt >= 6.2)
};

WirelessFrame::WirelessFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::WirelessFrame),
    interfaces_(NULL),
    capture_in_progress_(false),
    iface_timer_id_(-1)
{
    ui->setupUi(this);

    ui->helperToolButton->hide();

    if (ws80211_init() == WS80211_OK) {
        ui->stackedWidget->setEnabled(true);
        ui->stackedWidget->setCurrentWidget(ui->interfacePage);
    } else {
        ui->stackedWidget->setEnabled(false);
        ui->stackedWidget->setCurrentWidget(ui->noWirelessPage);
    }

    ui->fcsFilterFrame->setVisible(ws80211_has_fcs_filter());

    QSortFilterProxyModel *proxy = new BandProxyModel(this);
    ui->channelComboBox->setModel(proxy);

    proxy = new ChanTypeProxyModel(this);
    ui->channelTypeComboBox->setModel(proxy);

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    connect(ui->bandComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
#else
    connect(ui->bandComboBox, &QComboBox::currentIndexChanged,
#endif
            this, &WirelessFrame::bandComboBoxIndexChanged);

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    connect(ui->channelComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
#else
    connect(ui->channelComboBox, &QComboBox::currentIndexChanged,
#endif
            this, &WirelessFrame::channelComboBoxIndexChanged);

    updateInterfaceList();
    connect(mainApp, &MainApplication::localInterfaceEvent,
            this, &WirelessFrame::handleInterfaceEvent);
}

WirelessFrame::~WirelessFrame()
{
    ws80211_free_interfaces(interfaces_);
    delete ui;
}

void WirelessFrame::setCaptureInProgress(bool capture_in_progress)
{
    capture_in_progress_ = capture_in_progress;
    updateWidgets();
}


int WirelessFrame::startTimer(int interval)
{
    if (iface_timer_id_ != -1) {
        killTimer(iface_timer_id_);
        iface_timer_id_ = -1;
    }
    iface_timer_id_ = QFrame::startTimer(interval);
    return iface_timer_id_;
}

void WirelessFrame::handleInterfaceEvent(const char *ifname _U_, int added, int up _U_)
{
    if (!added) {
        // Unfortunately when an interface removed event is received the network
        // interface is still present for a while in the system.
        // To overcome this update the interface list after a while.
        startTimer(update_interval_);
    } else {
        updateInterfaceList();
    }
}

void WirelessFrame::timerEvent(QTimerEvent *event)
{
    if (event->timerId() != iface_timer_id_) {
        QFrame::timerEvent(event);
        return;
    }
    killTimer(iface_timer_id_);
    iface_timer_id_ = -1;
    updateInterfaceList();
}

// Check to see if the ws80211 interface list matches the one in our
// combobox. Rebuild ours if necessary and select the first interface if
// the current selection goes away.
void WirelessFrame::updateInterfaceList()
{
    ws80211_free_interfaces(interfaces_);
    interfaces_ = ws80211_find_interfaces();
    const QString old_iface = ui->interfaceComboBox->currentText();
    unsigned iface_count = 0;
    bool list_changed = false;

    // Don't interfere with user activity.
    if (ui->interfaceComboBox->view()->isVisible()
        || ui->channelComboBox->view()->isVisible()
        || ui->channelTypeComboBox->view()->isVisible()
        || ui->fcsComboBox->view()->isVisible()) {
        startTimer(update_interval_);
        return;
    }

    if (interfaces_ && interfaces_->len > 0) {
        iface_count = interfaces_->len;
    }

    if ((int) iface_count != ui->interfaceComboBox->count()) {
        list_changed = true;
    } else {
        for (unsigned i = 0; i < iface_count; i++) {
            struct ws80211_interface *iface = g_array_index(interfaces_, struct ws80211_interface *, i);
            if (ui->interfaceComboBox->itemText(i).compare(iface->ifname) != 0) {
                list_changed = true;
                break;
            }
        }
    }

    if (list_changed) {
        ui->interfaceComboBox->clear();
        for (unsigned i = 0; i < iface_count; i++) {
            struct ws80211_interface *iface = g_array_index(interfaces_, struct ws80211_interface *, i);
            ui->interfaceComboBox->addItem(iface->ifname);
            if (old_iface.compare(iface->ifname) == 0) {
                ui->interfaceComboBox->setCurrentIndex(ui->interfaceComboBox->count() - 1);
            }
        }
    }

    if (ui->interfaceComboBox->currentText().compare(old_iface) != 0) {
        getInterfaceInfo();
    }
}

void WirelessFrame::updateWidgets()
{
    bool enable_interface = false;
    bool enable_channel = false;
    bool enable_offset = false;
    bool enable_show_fcs = false;

    if (ui->interfaceComboBox->count() > 0) {
        enable_interface = true;
        enable_show_fcs = true;
    }

    if (enable_interface && ui->channelComboBox->count() > 0) {
        enable_channel = true;
    }

    if (enable_channel && ui->channelTypeComboBox->count() > 1) {
        enable_offset = true;
    }

    ui->interfaceComboBox->setEnabled(enable_interface);
    ui->channelComboBox->setEnabled(enable_channel);
    ui->channelTypeComboBox->setEnabled(enable_offset);
    ui->fcsComboBox->setEnabled(!capture_in_progress_ && enable_show_fcs);
}

void WirelessFrame::on_helperToolButton_clicked()
{
    const QString helper_path = ws80211_get_helper_path();
    if (helper_path.isEmpty()) return;

    QString command = QStringLiteral("\"%1\"").arg(helper_path);
    QProcess::startDetached(command, QStringList());
}

void WirelessFrame::on_prefsToolButton_clicked()
{
    emit showWirelessPreferences("wlan");
}

void WirelessFrame::getInterfaceInfo()
{
    const QString cur_iface = ui->interfaceComboBox->currentText();

    ui->bandComboBox->clear();
    // ui->channelComboBox->clear() would clear the proxy model (not its source
    // model), which wouldn't clear the values from the other bands that are
    // currently filtered out.
    BandProxyModel* proxy = qobject_cast<BandProxyModel* >(ui->channelComboBox->model());
    proxy->clearSourceModel();
    //ui->channelTypeComboBox->clear();
    proxy = qobject_cast<BandProxyModel* >(ui->channelTypeComboBox->model());
    proxy->clearSourceModel();
    ui->fcsComboBox->clear();

    if (cur_iface.isEmpty()) {
        updateWidgets();
        return;
    }

    for (unsigned i = 0; i < interfaces_->len; i++) {
        struct ws80211_interface *iface = g_array_index(interfaces_, struct ws80211_interface *, i);
        if (cur_iface.compare(iface->ifname) == 0) {
            struct ws80211_iface_info iface_info;
            struct ws80211_band *band;
            QString units = " GHz";

            ws80211_get_iface_info(iface->ifname, &iface_info);

            for (unsigned k = 0; k < iface->bands->len; k++) {
                band = &g_array_index(iface->bands, struct ws80211_band, k);
                if (band->frequencies == nullptr || band->frequencies->len == 0) continue;
                enum ws80211_band_type band_type = (enum ws80211_band_type)k;
                ui->bandComboBox->addItem(QString::fromUtf8(ws80211_band_type_to_str(band_type)), band_type);
                proxy = qobject_cast<BandProxyModel* >(ui->channelComboBox->model());
                for (unsigned j = 0; j < band->frequencies->len; j++) {
                    struct ws80211_frequency myfreq = g_array_index(band->frequencies, struct ws80211_frequency, j);
                    uint32_t frequency = myfreq.freq;
                    double ghz = frequency / 1000.0;
                    QString chan_str = QStringLiteral("%1 %2 %3%4")
                            .arg(ieee80211_mhz_to_chan(frequency))
                            .arg(UTF8_MIDDLE_DOT)
                            .arg(ghz, 0, 'f', 3)
                            .arg(units);
                    proxy->addItem(chan_str, band_type, QVariant::fromValue(myfreq));
                    if ((int)frequency == iface_info.current_freq) {
                        ui->bandComboBox->setCurrentIndex(k);
                        ui->channelComboBox->setCurrentIndex(ui->channelComboBox->count() - 1);
                    }
                    units = QString();
                }
                proxy = qobject_cast<BandProxyModel* >(ui->channelTypeComboBox->model());
                // XXX - Do we need to make a distinction between WS80211_CHAN_NO_HT
                // and WS80211_CHAN_HT20? E.g. is there a driver that won't capture
                // HT frames if you use WS80211_CHAN_NO_HT?
                proxy->addItem("20 MHz", band_type, WS80211_CHAN_NO_HT);
                if (iface_info.current_chan_type == WS80211_CHAN_NO_HT || iface_info.current_chan_type == WS80211_CHAN_HT20) {
                    ui->channelTypeComboBox->setCurrentIndex(0);
                }
                if (band->channel_types & (1 << WS80211_CHAN_HT40MINUS)) {
                    proxy->addItem("HT 40-", band_type, WS80211_CHAN_HT40MINUS);
                }
                if (band->channel_types & (1 << WS80211_CHAN_HT40PLUS)) {
                    proxy->addItem("HT 40+", band_type, WS80211_CHAN_HT40PLUS);
                }
                if (band->channel_types & (1 << WS80211_CHAN_HE40)) {
                    if (!(band->channel_types & ((1 << WS80211_CHAN_HT40MINUS) | (1 << WS80211_CHAN_HT40PLUS)))) {
                        proxy->addItem("HE 40", band_type, WS80211_CHAN_HE40);
                    }
                }
                if (band->channel_types & (1 << WS80211_CHAN_VHT80)) {
                    proxy->addItem("VHT 80", band_type, WS80211_CHAN_VHT80);
                }
                if (band->channel_types & (1 << WS80211_CHAN_VHT160)) {
                    proxy->addItem("VHT 160", band_type, WS80211_CHAN_VHT160);
                }
                if (band->channel_types & (1 << WS80211_CHAN_EHT320)) {
                    proxy->addItem("EHT 320", band_type, WS80211_CHAN_EHT320);
                }
            }
            int dataIdx = ui->channelTypeComboBox->findData(iface_info.current_chan_type, DataRole);
            /* Some drivers will report the current channel type as HT40- or
             * HT40+ even in the 6 GHz band that can only be tuned using the
             * center frequency. */
            if (dataIdx == -1 && (iface_info.current_chan_type == WS80211_CHAN_HT40MINUS || iface_info.current_chan_type == WS80211_CHAN_HT40PLUS)) {
                dataIdx = ui->channelTypeComboBox->findData(WS80211_CHAN_HE40, DataRole);
            }
            if (dataIdx > -1) {
                ui->channelTypeComboBox->setCurrentIndex(dataIdx);
            }

            if (ws80211_has_fcs_filter()) {
                ui->fcsComboBox->setCurrentIndex(iface_info.current_fcs_validation);
            }
        }
    }

    updateWidgets();
}

void WirelessFrame::setInterfaceInfo()
{
    QString cur_iface = ui->interfaceComboBox->currentText();
    int cur_chan_idx = ui->channelComboBox->currentIndex();
    int cur_type_idx = ui->channelTypeComboBox->currentIndex();
    int cur_fcs_idx = ui->fcsComboBox->currentIndex();

    if (cur_iface.isEmpty() || cur_chan_idx < 0 || cur_type_idx < 0) return;

    QString err_str;

#if defined(HAVE_LIBNL) && defined(HAVE_NL80211) && defined(HAVE_LIBPCAP)
    if (!ui->channelComboBox->currentData(DataRole).isValid())
        return;
    if (!ui->channelTypeComboBox->currentData(DataRole).isValid())
        return;
    struct ws80211_frequency myfreq = qvariant_cast<struct ws80211_frequency>(ui->channelComboBox->currentData(DataRole));
    int frequency = myfreq.freq;
    enum ws80211_channel_type chan_type = qvariant_cast<enum ws80211_channel_type>(ui->channelTypeComboBox->currentData(DataRole));
    int center_freq = ws80211_get_center_frequency(frequency, chan_type);
    const char *chan_type_s = ws80211_chan_type_to_str(chan_type);
    char *center_freq_s = NULL;
    char *data, *primary_msg, *secondary_msg;
    int ret;

    if (frequency < 0 || chan_type < 0) return;

    if (center_freq != -1) {
        center_freq_s = qstring_strdup(QString::number(center_freq));
    }

    ret = sync_interface_set_80211_chan(cur_iface.toUtf8().constData(),
                                        QString::number(frequency).toUtf8().constData(), chan_type_s,
                                        center_freq_s, NULL,
                                        &data, &primary_msg, &secondary_msg, main_window_update);

    g_free(center_freq_s);
    g_free(data);
    g_free(primary_msg);
    g_free(secondary_msg);

    /* Parse the error msg */
    if (ret) {
        // XXX - We should do something with the primary msg before freeing it
        err_str = tr("Unable to set channel or offset.");
    }
#endif

    if (cur_fcs_idx >= 0) {
        if (ws80211_set_fcs_validation(cur_iface.toUtf8().constData(), (enum ws80211_fcs_validation) cur_fcs_idx) != 0) {
            err_str = tr("Unable to set FCS validation behavior.");
        }
    }

    if (!err_str.isEmpty()) {
        mainApp->pushStatus(MainApplication::TemporaryStatus, err_str);
    }

    getInterfaceInfo();
}

void WirelessFrame::on_interfaceComboBox_activated(int)
{
    getInterfaceInfo();
}

void WirelessFrame::on_channelComboBox_activated(int)
{
    setInterfaceInfo();
}

void WirelessFrame::on_channelTypeComboBox_activated(int)
{
    setInterfaceInfo();
}

void WirelessFrame::on_fcsComboBox_activated(int)
{
    setInterfaceInfo();
}

void WirelessFrame::channelComboBoxIndexChanged(int)
{
    struct ws80211_frequency freq = qvariant_cast<struct ws80211_frequency>(ui->channelComboBox->currentData(DataRole));
    qobject_cast<ChanTypeProxyModel*>(ui->channelTypeComboBox->model())->setMask(freq.channel_mask);
}

void WirelessFrame::bandComboBoxIndexChanged(int)
{
    enum ws80211_band_type band = qvariant_cast<enum ws80211_band_type>(ui->bandComboBox->currentData());
    qobject_cast<BandProxyModel*>(ui->channelComboBox->model())->setBand(band);
    qobject_cast<BandProxyModel*>(ui->channelTypeComboBox->model())->setBand(band);
}

#include "wireless_frame.moc"
