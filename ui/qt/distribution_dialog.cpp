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
#include <ui_distribution_dialog.h>

#include <app/application_flavor.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <wsutil/utf8_entities.h>

#include "main_application.h"
#include "main_window.h"
#include "progress_frame.h"
#include <ui/qt/models/distribution_model.h>
#include <ui/qt/models/percent_bar_delegate.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/plot_theme.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/widgets/qcustomplot.h>

#include <QClipboard>
#include <QEvent>
#include <QFontMetrics>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QScrollBar>
#include <QSortFilterProxyModel>
#include <QTimer>
#include <QVBoxLayout>

DistributionDialog::DistributionDialog(QWidget &parent, CaptureFile &cf, const QString &fields) :
    WiresharkDialog(parent, cf),
    ui(new Ui::DistributionDialog),
    model_(new DistributionModel(this)),
    proxy_(new QSortFilterProxyModel(this)),
    percent_delegate_(nullptr),
    percent_column_(-1),
    empty_hint_label_(nullptr),
    copy_button_(nullptr),
    save_button_(nullptr),
    io_graph_button_(nullptr),
    chart_bars_(nullptr),
    chart_sized_(false),
    columns_sized_(false)
{
    ui->setupUi(this);

    setWindowSubtitle(tr("Distribution"));
    loadGeometry(parent.width() * 4 / 5, parent.height() * 3 / 4, "DistributionDialog");

    ui->applyButton->setToolTip(flavorText(FlavorText::ApplyToolTip));

    proxy_->setSourceModel(model_);
    proxy_->setSortRole(DistributionModel::SortRole);
    proxy_->setDynamicSortFilter(true);
    proxy_->setSortCaseSensitivity(Qt::CaseInsensitive);

    QTreeView *view = ui->distributionTreeView;
    view->setModel(proxy_);
    view->sortByColumn(model_->countColumn(), Qt::DescendingOrder);
    percent_delegate_ = new PercentBarDelegate(view);
    updatePercentDelegate();

    /* The hint is laid out on the viewport, so it follows the viewport size
     * and lets the header above it stay visible. */
    QWidget *viewport = view->viewport();
    QVBoxLayout *hint_layout = new QVBoxLayout(viewport);
    empty_hint_label_ = new QLabel(flavorText(FlavorText::EmptyHint), viewport);
    empty_hint_label_->setAlignment(Qt::AlignCenter);
    empty_hint_label_->setWordWrap(true);
    empty_hint_label_->setAttribute(Qt::WA_TransparentForMouseEvents);
    empty_hint_label_->setForegroundRole(QPalette::PlaceholderText);
    hint_layout->addWidget(empty_hint_label_);

    /* Ctrl+C belongs to the table only, so the line edits keep copying
     * their own text; Ctrl+S works anywhere in the dialog. */
    view->addAction(ui->actionCopy);
    addAction(ui->actionSaveAs);

    copy_button_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect(copy_button_, &QPushButton::clicked, this, &DistributionDialog::copyTable);
    save_button_ = ui->buttonBox->addButton(ui->actionSaveAs->text(), QDialogButtonBox::ActionRole);
    connect(save_button_, &QPushButton::clicked, ui->actionSaveAs, &QAction::trigger);
    ui->actionShowInIOGraph->setToolTip(tr("Open an I/O Graph with a graph for each selected row (at most %1)")
                                        .arg(MainWindow::maxIOGraphFilters));
    io_graph_button_ = ui->buttonBox->addButton(ui->actionShowInIOGraph->text(), QDialogButtonBox::ActionRole);
    io_graph_button_->setToolTip(ui->actionShowInIOGraph->toolTip());
    connect(io_graph_button_, &QPushButton::clicked, ui->actionShowInIOGraph, &QAction::trigger);
    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    connect(view, &QTreeView::customContextMenuRequested, this, &DistributionDialog::showContextMenu);
    connect(view->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &DistributionDialog::updateWidgets);
    connect(view->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &DistributionDialog::updateChart);
    connect(model_, &DistributionModel::summaryChanged, this, &DistributionDialog::updateSummary);

    connect(ui->applyButton, &QPushButton::clicked, this, &DistributionDialog::apply);
    connect(ui->fieldsLineEdit, &QLineEdit::returnPressed, this, &DistributionDialog::apply);
    connect(ui->displayFilterLineEdit, &QLineEdit::returnPressed, this, &DistributionDialog::apply);
    connect(ui->displayFilterLineEdit, &QLineEdit::textChanged, this, &DistributionDialog::updateWidgets);

    ui->fieldsLineEdit->setFieldListMode(true);
    ui->fieldsLineEdit->setMaxFields(DistributionModel::maxFields);
    /* FieldFilterEdit connects its own check in its constructor, so this
     * one runs after it and sees the result. */
    connect(ui->fieldsLineEdit, &QLineEdit::textChanged, this, &DistributionDialog::checkFields);
    ui->fieldsLineEdit->setText(fields);

    QCustomPlot *plot = ui->chartPlot;
    chart_bars_ = new QCPBars(plot->yAxis, plot->xAxis);
    chart_bars_->setSelectable(QCP::stMultipleDataRanges);
    plot->yAxis->setRangeReversed(true);
    plot->yAxis->grid()->setVisible(false);
    plot->xAxis->setLabel(tr("Count"));
    connect(plot, &QCustomPlot::plottableClick, this, &DistributionDialog::chartBarClicked);
    PlotTheme::track(plot, [this]() {
        const QColor color = ThemeManager::instance()->graphColor(0);
        const QColor selected = palette().color(QPalette::Highlight);
        chart_bars_->setBrush(color);
        chart_bars_->setPen(QPen(color));
        chart_bars_->selectionDecorator()->setBrush(selected);
        chart_bars_->selectionDecorator()->setPen(QPen(selected));
    });
    plot->installEventFilter(this);

    updateWidgets();

    if (ui->applyButton->isEnabled()) {
        QTimer::singleShot(0, this, &DistributionDialog::apply);
    }
}

DistributionDialog::~DistributionDialog()
{
    delete ui;
}

QString DistributionDialog::flavorText(FlavorText id)
{
    const bool wireshark = application_flavor_is_wireshark();

    switch (id) {
    case FlavorText::SummaryOneField:
        return wireshark
                ? tr("%1 distinct values " UTF8_MIDDLE_DOT " %2 packets containing %3 " UTF8_MIDDLE_DOT " %4 observations " UTF8_MIDDLE_DOT " Entropy %5 (normalized Shannon)")
                : tr("%1 distinct values " UTF8_MIDDLE_DOT " %2 events containing %3 " UTF8_MIDDLE_DOT " %4 observations " UTF8_MIDDLE_DOT " Entropy %5 (normalized Shannon)");
    case FlavorText::SummaryAllFields:
        return wireshark
                ? tr("%1 distinct values " UTF8_MIDDLE_DOT " %2 packets containing all fields " UTF8_MIDDLE_DOT " %3 observations " UTF8_MIDDLE_DOT " Entropy %4 (normalized Shannon)")
                : tr("%1 distinct values " UTF8_MIDDLE_DOT " %2 events containing all fields " UTF8_MIDDLE_DOT " %3 observations " UTF8_MIDDLE_DOT " Entropy %4 (normalized Shannon)");
    case FlavorText::MultipleObservations:
        return wireshark
                ? tr("A packet can contain a field more than once, so the percentages (of packets) add up to more than 100 %.")
                : tr("An event can contain a field more than once, so the percentages (of events) add up to more than 100 %.");
    case FlavorText::EmptyHint:
        return wireshark
                ? tr("Enter one or more fields above and press Apply, for example ip.ttl, or ip.src, tcp.dstport for a joint distribution.")
                : tr("Enter one or more fields above and press Apply, for example evt.type, or evt.type, proc.name for a joint distribution.");
    case FlavorText::ApplyToolTip:
        return wireshark
                ? tr("Count the field values in the packets matching the display filter")
                : tr("Count the field values in the events matching the display filter");
    }
    return QString();
}

QStringList DistributionDialog::summaryTexts() const
{
    QStringList lines;
    if (!model_->hasResult()) {
        return lines;
    }

    const QString distinct = QString::number(model_->distinctValues());
    const QString packets = QString::number(model_->packets());
    const QString observations = QString::number(model_->observations());
    const QString entropy = QString::number(model_->entropy(), 'f', 3);
    const QStringList names = model_->fieldNames();

    if (names.size() == 1) {
        lines << flavorText(FlavorText::SummaryOneField)
                 .arg(distinct, packets, names.first(), observations, entropy);
    } else {
        lines << flavorText(FlavorText::SummaryAllFields)
                 .arg(distinct, packets, observations, entropy);
    }
    if (model_->observations() > model_->packets()) {
        lines << flavorText(FlavorText::MultipleObservations);
    }
    return lines;
}

StatTableExporter::Table DistributionDialog::table(bool selected_only)
{
    StatTableExporter::Table table;
    table.title = windowSubtitle();
    table.file_name = cap_file_.fileDisplayName();
    for (int column = 0; column < model_->columnCount(); column++) {
        table.headers << model_->headerData(column, Qt::Horizontal).toString();
    }

    for (int row : sourceRows(selected_only)) {
        table.rows << model_->rowData(row);
    }
    return table;
}

QList<int> DistributionDialog::sourceRows(bool selected_only) const
{
    QList<int> rows;
    QItemSelectionModel *selection = ui->distributionTreeView->selectionModel();
    for (int row = 0; row < proxy_->rowCount(); row++) {
        if (selected_only && !selection->isRowSelected(row, QModelIndex())) {
            continue;
        }
        rows << proxy_->mapToSource(proxy_->index(row, 0)).row();
    }
    return rows;
}

void DistributionDialog::updatePercentDelegate()
{
    const int column = model_->percentColumn();
    if (column == percent_column_) {
        return;
    }
    if (percent_column_ >= 0) {
        ui->distributionTreeView->setItemDelegateForColumn(percent_column_, nullptr);
    }
    ui->distributionTreeView->setItemDelegateForColumn(column, percent_delegate_);
    percent_column_ = column;
}

void DistributionDialog::updateWidgets()
{
    const bool busy = retapDepth() > 0;
    const bool file_open = !file_closed_ && cap_file_.isValid();
    const SyntaxLineEdit::SyntaxState fields_state = ui->fieldsLineEdit->syntaxState();
    const bool fields_ok = fields_state == SyntaxLineEdit::Valid
            || fields_state == SyntaxLineEdit::Deprecated;
    const bool filter_ok = ui->displayFilterLineEdit->syntaxState() != SyntaxLineEdit::Invalid;

    ui->applyButton->setEnabled(fields_ok && filter_ok && file_open && !busy);
    ui->resolveCheckBox->setEnabled(!busy);
    ui->chartCheckBox->setEnabled(!busy);

    const bool no_data = model_->rowCount() == 0 || busy;
    copy_button_->setEnabled(!no_data);
    save_button_->setEnabled(!no_data);
    ui->actionSaveAs->setEnabled(!no_data);
    const bool has_selection = ui->distributionTreeView->selectionModel()->hasSelection();
    ui->actionCopy->setEnabled(!no_data && has_selection);
    io_graph_button_->setEnabled(!no_data && has_selection);
    ui->actionShowInIOGraph->setEnabled(!no_data && has_selection);

    WiresharkDialog::updateWidgets();
}

void DistributionDialog::beginRetapPackets()
{
    WiresharkDialog::beginRetapPackets();
    updateWidgets();
}

void DistributionDialog::endRetapPackets()
{
    WiresharkDialog::endRetapPackets();
    if (dialogClosed()) {
        return;
    }
    /* Retaps started elsewhere reach this as well; without fields there is
     * nothing to describe. */
    if (model_->hasFields()) {
        model_->publish();
    }
    updateWidgets();
    sizeColumns();
    updateChart();
}

void DistributionDialog::sizeColumns()
{
    if (columns_sized_ || model_->rowCount() == 0) {
        return;
    }
    for (int column = 0; column < model_->percentColumn(); column++) {
        ui->distributionTreeView->resizeColumnToContents(column);
    }
    columns_sized_ = true;
}

bool DistributionDialog::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == ui->chartPlot && event->type() == QEvent::Resize) {
        updateChart();
    }
    return WiresharkDialog::eventFilter(obj, event);
}

void DistributionDialog::checkFields()
{
    FieldFilterEdit *edit = ui->fieldsLineEdit;
    QString message = edit->fieldListMessage();
    const SyntaxLineEdit::SyntaxState state = edit->syntaxState();

    if (state == SyntaxLineEdit::Valid || state == SyntaxLineEdit::Deprecated) {
        QList<DistributionField> fields;
        const QString count_message = DistributionModel::parseFields(edit->fieldList(), fields);
        if (!count_message.isEmpty()) {
            edit->setSyntaxState(SyntaxLineEdit::Invalid);
            message = count_message;
        }
    }

    if (message.isEmpty()) {
        ui->fieldsErrorLabel->clear();
        ui->fieldsErrorLabel->hide();
    } else {
        ui->fieldsErrorLabel->setText(message);
        ui->fieldsErrorLabel->setStyleSheet(QStringLiteral(
                    "QLabel {"
                    "  background-color: %1;"
                    "}"
                    )
                .arg(ColorUtils::warningBackground().name())
                );
        ui->fieldsErrorLabel->show();
    }
    updateWidgets();
}

void DistributionDialog::apply()
{
    if (retapDepth() > 0 || !ui->applyButton->isEnabled()) {
        return;
    }

    QList<DistributionField> fields;
    if (!DistributionModel::parseFields(ui->fieldsLineEdit->fieldList(), fields).isEmpty()) {
        return;
    }

    removeTapListeners();
    model_->setFields(fields);
    const QStringList names = model_->fieldNames();

    /* Only packets containing every field are counted; the display filter
     * limits them further. */
    QString filter = names.join(QStringLiteral(" && "));
    const QString limit = ui->displayFilterLineEdit->text().trimmed();
    if (!limit.isEmpty()) {
        filter = QStringLiteral("(%1) && (%2)").arg(filter, limit);
    }

    applied_limit_ = limit;
    columns_sized_ = false;
    updatePercentDelegate();
    empty_hint_label_->setVisible(!model_->hasFields());
    setWindowSubtitle(tr("Distribution of %1").arg(names.join(QStringLiteral(", "))));

    const QByteArray tap_filter = filter.toUtf8();
    if (!registerTapListener("frame",
                             this,
                             tap_filter.constData(),
                             TL_REQUIRES_PROTO_TREE,
                             tapReset,
                             tapPacket,
                             tapDraw)) {
        updateWidgets();
        return;
    }

    ui->distributionTreeView->sortByColumn(model_->countColumn(), Qt::DescendingOrder);
    cap_file_.retapPackets();
}

void DistributionDialog::updateSummary()
{
    ui->summaryLabel->setText(summaryTexts().join('\n'));
}

void DistributionDialog::showContextMenu(const QPoint &pos)
{
    const QModelIndex index = ui->distributionTreeView->indexAt(pos);
    if (!index.isValid()) {
        return;
    }
    const QString filter = model_->filterExpression(proxy_->mapToSource(index).row());

    QMenu *menu = new QMenu(this);
    menu->setAttribute(Qt::WA_DeleteOnClose);

    for (FilterAction *fa : FilterAction::addActionSubmenus(menu)) {
        connect(fa, &QAction::triggered, this, [this, fa, filter]() {
            emit filterAction(filter, fa->action(), fa->actionType());
        });
    }
    menu->addSeparator();
    menu->addAction(ui->actionCopy);
    QAction *copy_filter = FilterAction::copyFilterAction(filter, menu);
    copy_filter->setText(tr("Copy as Filter"));
    menu->addAction(copy_filter);
    menu->addAction(ui->actionSaveAs);
    menu->addSeparator();
    menu->addAction(ui->actionShowInIOGraph);

    menu->popup(ui->distributionTreeView->viewport()->mapToGlobal(pos));
}

void DistributionDialog::on_actionShowInIOGraph_triggered()
{
    QVector<QString> filters;
    QVector<QString> names;
    const QList<int> rows = sourceRows(true).mid(0, MainWindow::maxIOGraphFilters);
    for (int source_row : rows) {
        QString filter = model_->filterExpression(source_row);
        if (!applied_limit_.isEmpty()) {
            filter = QStringLiteral("(%1) && (%2)").arg(applied_limit_, filter);
        }
        filters << filter;
        names << model_->rowLabel(source_row);
    }
    if (filters.isEmpty()) {
        return;
    }
    emit showIOGraph(applied_limit_, filters, names);
}

void DistributionDialog::copyTable()
{
    mainApp->clipboard()->setText(QString::fromUtf8(
            StatTableExporter::toByteArray(ST_FORMAT_PLAIN, table(false))));
}

void DistributionDialog::on_actionCopy_triggered()
{
    mainApp->clipboard()->setText(QString::fromUtf8(
            StatTableExporter::toByteArray(ST_FORMAT_PLAIN, table(true))));
}

void DistributionDialog::on_actionSaveAs_triggered()
{
    StatTableExporter::saveAs(this, [this](st_format_type format) {
        return StatTableExporter::toByteArray(format, table(false));
    });
}

void DistributionDialog::on_resolveCheckBox_toggled(bool checked)
{
    model_->setResolveValues(checked);
    columns_sized_ = false;
    sizeColumns();
    updateChart();
}

void DistributionDialog::on_chartCheckBox_toggled(bool checked)
{
    ui->chartPlot->setVisible(checked);
    if (checked && !chart_sized_) {
        /* The chart gets about 42 % of the width, less when the table
         * columns need more, so the Percent column stays readable. */
        QTreeView *view = ui->distributionTreeView;
        const int total = ui->splitter->width();
        int table_width = total - total * 42 / 100;
        if (columns_sized_) {
            const int percent = model_->percentColumn();
            const int needed = view->header()->sectionPosition(percent)
                    + static_cast<QAbstractItemView *>(view)->sizeHintForColumn(percent)
                    + view->verticalScrollBar()->sizeHint().width()
                    + 2 * view->frameWidth();
            table_width = qBound(table_width, needed,
                                 total - static_cast<QWidget *>(ui->chartPlot)->minimumSizeHint().width());
        }
        ui->splitter->setSizes({table_width, total - table_width});
        chart_sized_ = true;
    }
    updateChart();
}

void DistributionDialog::updateChart()
{
    if (!ui->chartCheckBox->isChecked()) {
        return;
    }

    QCustomPlot *plot = ui->chartPlot;
    chart_rows_ = model_->topRows(chartRows);

    QSharedPointer<QCPAxisTickerText> ticker(new QCPAxisTickerText);
    const int label_space = plot->width() / 3;
    const QFontMetrics fm(plot->yAxis->tickLabelFont());
    QVector<double> keys, values;
    QCPDataSelection selection;
    QItemSelectionModel *sel = ui->distributionTreeView->selectionModel();
    double max_count = 0;
    for (int i = 0; i < chart_rows_.size(); i++) {
        const int row = chart_rows_.at(i);
        const double count = static_cast<double>(model_->count(row));
        keys << i + 1;
        values << count;
        max_count = qMax(max_count, count);
        ticker->addTick(i + 1, fm.elidedText(model_->rowLabel(row), Qt::ElideMiddle, label_space));
        if (sel->isRowSelected(proxy_->mapFromSource(model_->index(row, 0)).row())) {
            selection.addDataRange(QCPDataRange(i, i + 1));
        }
    }

    /* One label width of space between the x-axis tick labels keeps them
     * apart on a narrow plot; ".5" covers the half steps of small counts. */
    const QFontMetrics x_fm(plot->xAxis->tickLabelFont());
    const int x_label_width = x_fm.horizontalAdvance(
            QString::number(qRound64(max_count)) + QStringLiteral(".5"));
    plot->xAxis->ticker()->setTickCount(
            qMax(2, (plot->width() - label_space) / (2 * x_label_width)));
    plot->yAxis->setTicker(ticker);
    plot->yAxis->setRange(0.5, qMax(static_cast<int>(chart_rows_.size()), 1) + 0.5);
    plot->xAxis->setRange(0, max_count > 0 ? max_count * 1.05 : 1);
    chart_bars_->setData(keys, values);
    chart_bars_->setSelection(selection);
    plot->replot();
}

void DistributionDialog::chartBarClicked(QCPAbstractPlottable *, int dataIndex)
{
    if (dataIndex < 0 || dataIndex >= chart_rows_.size()) {
        return;
    }

    const QModelIndex index = proxy_->mapFromSource(model_->index(chart_rows_.at(dataIndex), 0));
    QTreeView *view = ui->distributionTreeView;
    view->selectionModel()->select(index,
            QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    view->scrollTo(index);
}

void DistributionDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STATS_DISTRIBUTION_DIALOG);
}

void DistributionDialog::tapReset(void *tapdata)
{
    DistributionDialog *dialog = static_cast<DistributionDialog *>(tapdata);
    if (!dialog) return;

    dialog->model_->clear();
    dialog->updateChart();
}

tap_packet_status DistributionDialog::tapPacket(void *tapdata, _packet_info *, epan_dissect_t *edt,
                                                const void *, tap_flags_t)
{
    DistributionDialog *dialog = static_cast<DistributionDialog *>(tapdata);
    if (!dialog || !edt) {
        return TAP_PACKET_FAILED;
    }

    return dialog->model_->addPacket(edt->tree) ? TAP_PACKET_REDRAW : TAP_PACKET_DONT_REDRAW;
}

void DistributionDialog::tapDraw(void *tapdata)
{
    DistributionDialog *dialog = static_cast<DistributionDialog *>(tapdata);
    if (!dialog) return;

    dialog->model_->publish();
    dialog->sizeColumns();
    dialog->updateWidgets();
    dialog->updateChart();
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
