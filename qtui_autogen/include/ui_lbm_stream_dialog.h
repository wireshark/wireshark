/********************************************************************************
** Form generated from reading UI file 'lbm_stream_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_LBM_STREAM_DIALOG_H
#define UI_LBM_STREAM_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include "widgets/display_filter_edit.h"

QT_BEGIN_NAMESPACE

class Ui_LBMStreamDialog
{
public:
    QAction *actionCopyAsCSV;
    QAction *actionCopyAsYAML;
    QVBoxLayout *verticalLayout;
    QTreeWidget *lbm_stream_TreeWidget;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    DisplayFilterEdit *displayFilterLineEdit;
    QPushButton *applyFilterButton;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *LBMStreamDialog)
    {
        if (LBMStreamDialog->objectName().isEmpty())
            LBMStreamDialog->setObjectName(QString::fromUtf8("LBMStreamDialog"));
        LBMStreamDialog->resize(652, 459);
        actionCopyAsCSV = new QAction(LBMStreamDialog);
        actionCopyAsCSV->setObjectName(QString::fromUtf8("actionCopyAsCSV"));
#ifndef QT_NO_SHORTCUT
        actionCopyAsCSV->setShortcut(QString::fromUtf8("Ctrl+C"));
#endif // QT_NO_SHORTCUT
        actionCopyAsYAML = new QAction(LBMStreamDialog);
        actionCopyAsYAML->setObjectName(QString::fromUtf8("actionCopyAsYAML"));
#ifndef QT_NO_SHORTCUT
        actionCopyAsYAML->setShortcut(QString::fromUtf8("Ctrl+Y"));
#endif // QT_NO_SHORTCUT
        verticalLayout = new QVBoxLayout(LBMStreamDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        lbm_stream_TreeWidget = new QTreeWidget(LBMStreamDialog);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setTextAlignment(3, Qt::AlignLeft|Qt::AlignVCenter);
        lbm_stream_TreeWidget->setHeaderItem(__qtreewidgetitem);
        lbm_stream_TreeWidget->setObjectName(QString::fromUtf8("lbm_stream_TreeWidget"));

        verticalLayout->addWidget(lbm_stream_TreeWidget);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(LBMStreamDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        displayFilterLineEdit = new DisplayFilterEdit(LBMStreamDialog);
        displayFilterLineEdit->setObjectName(QString::fromUtf8("displayFilterLineEdit"));

        horizontalLayout->addWidget(displayFilterLineEdit);

        applyFilterButton = new QPushButton(LBMStreamDialog);
        applyFilterButton->setObjectName(QString::fromUtf8("applyFilterButton"));

        horizontalLayout->addWidget(applyFilterButton);


        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(LBMStreamDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(LBMStreamDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), LBMStreamDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), LBMStreamDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(LBMStreamDialog);
    } // setupUi

    void retranslateUi(QDialog *LBMStreamDialog)
    {
        LBMStreamDialog->setWindowTitle(QApplication::translate("LBMStreamDialog", "Dialog", nullptr));
        actionCopyAsCSV->setText(QApplication::translate("LBMStreamDialog", "Copy as CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCopyAsCSV->setToolTip(QApplication::translate("LBMStreamDialog", "Copy the tree as CSV", nullptr));
#endif // QT_NO_TOOLTIP
        actionCopyAsYAML->setText(QApplication::translate("LBMStreamDialog", "Copy as YAML", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCopyAsYAML->setToolTip(QApplication::translate("LBMStreamDialog", "Copy the tree as YAML", nullptr));
#endif // QT_NO_TOOLTIP
        QTreeWidgetItem *___qtreewidgetitem = lbm_stream_TreeWidget->headerItem();
        ___qtreewidgetitem->setText(6, QApplication::translate("LBMStreamDialog", "Last Frame", nullptr));
        ___qtreewidgetitem->setText(5, QApplication::translate("LBMStreamDialog", "First Frame", nullptr));
        ___qtreewidgetitem->setText(4, QApplication::translate("LBMStreamDialog", "Bytes", nullptr));
        ___qtreewidgetitem->setText(3, QApplication::translate("LBMStreamDialog", "Messages", nullptr));
        ___qtreewidgetitem->setText(2, QApplication::translate("LBMStreamDialog", "Endpoint B", nullptr));
        ___qtreewidgetitem->setText(1, QApplication::translate("LBMStreamDialog", "Endpoint A", nullptr));
        ___qtreewidgetitem->setText(0, QApplication::translate("LBMStreamDialog", "Stream", nullptr));
        label->setText(QApplication::translate("LBMStreamDialog", "Display filter:", nullptr));
#ifndef QT_NO_TOOLTIP
        applyFilterButton->setToolTip(QApplication::translate("LBMStreamDialog", "Regenerate statistics using this display filter", nullptr));
#endif // QT_NO_TOOLTIP
        applyFilterButton->setText(QApplication::translate("LBMStreamDialog", "Apply", nullptr));
    } // retranslateUi

};

namespace Ui {
    class LBMStreamDialog: public Ui_LBMStreamDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_LBM_STREAM_DIALOG_H
