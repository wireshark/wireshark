/********************************************************************************
** Form generated from reading UI file 'voip_calls_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_VOIP_CALLS_DIALOG_H
#define UI_VOIP_CALLS_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_VoipCallsDialog
{
public:
    QAction *actionSelect_All;
    QAction *actionCopyAsCsv;
    QAction *actionCopyAsYaml;
    QVBoxLayout *verticalLayout;
    QTreeView *callTreeView;
    QLabel *hintLabel;
    QHBoxLayout *horizontalLayout;
    QSpacerItem *horizontalSpacer;
    QCheckBox *todCheckBox;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *VoipCallsDialog)
    {
        if (VoipCallsDialog->objectName().isEmpty())
            VoipCallsDialog->setObjectName(QString::fromUtf8("VoipCallsDialog"));
        VoipCallsDialog->resize(750, 430);
        actionSelect_All = new QAction(VoipCallsDialog);
        actionSelect_All->setObjectName(QString::fromUtf8("actionSelect_All"));
#ifndef QT_NO_SHORTCUT
        actionSelect_All->setShortcut(QString::fromUtf8("Ctrl+A"));
#endif // QT_NO_SHORTCUT
        actionCopyAsCsv = new QAction(VoipCallsDialog);
        actionCopyAsCsv->setObjectName(QString::fromUtf8("actionCopyAsCsv"));
        actionCopyAsYaml = new QAction(VoipCallsDialog);
        actionCopyAsYaml->setObjectName(QString::fromUtf8("actionCopyAsYaml"));
        verticalLayout = new QVBoxLayout(VoipCallsDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        callTreeView = new QTreeView(VoipCallsDialog);
        callTreeView->setObjectName(QString::fromUtf8("callTreeView"));
        callTreeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        callTreeView->setTextElideMode(Qt::ElideMiddle);
        callTreeView->setRootIsDecorated(false);
        callTreeView->setUniformRowHeights(true);
        callTreeView->setItemsExpandable(false);

        verticalLayout->addWidget(callTreeView);

        hintLabel = new QLabel(VoipCallsDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));

        verticalLayout->addWidget(hintLabel);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        todCheckBox = new QCheckBox(VoipCallsDialog);
        todCheckBox->setObjectName(QString::fromUtf8("todCheckBox"));

        horizontalLayout->addWidget(todCheckBox);


        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(VoipCallsDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Help|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(VoipCallsDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), VoipCallsDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), VoipCallsDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(VoipCallsDialog);
    } // setupUi

    void retranslateUi(QDialog *VoipCallsDialog)
    {
        VoipCallsDialog->setWindowTitle(QApplication::translate("VoipCallsDialog", "VoIP Calls", nullptr));
        actionSelect_All->setText(QApplication::translate("VoipCallsDialog", "Select &All", nullptr));
#ifndef QT_NO_TOOLTIP
        actionSelect_All->setToolTip(QApplication::translate("VoipCallsDialog", "Select all calls", nullptr));
#endif // QT_NO_TOOLTIP
        actionCopyAsCsv->setText(QApplication::translate("VoipCallsDialog", "Copy as CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCopyAsCsv->setToolTip(QApplication::translate("VoipCallsDialog", "Copy stream list as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionCopyAsYaml->setText(QApplication::translate("VoipCallsDialog", "Copy as YAML", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCopyAsYaml->setToolTip(QApplication::translate("VoipCallsDialog", "Copy stream list as YAML.", nullptr));
#endif // QT_NO_TOOLTIP
        hintLabel->setText(QApplication::translate("VoipCallsDialog", "<small></small>", nullptr));
        todCheckBox->setText(QApplication::translate("VoipCallsDialog", "Time of Day", nullptr));
    } // retranslateUi

};

namespace Ui {
    class VoipCallsDialog: public Ui_VoipCallsDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_VOIP_CALLS_DIALOG_H
