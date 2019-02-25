/********************************************************************************
** Form generated from reading UI file 'expert_info_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_EXPERT_INFO_DIALOG_H
#define UI_EXPERT_INFO_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMenu>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include "widgets/elided_label.h"
#include "widgets/expert_info_view.h"

QT_BEGIN_NAMESPACE

class Ui_ExpertInfoDialog
{
public:
    QAction *actionShowError;
    QAction *actionShowWarning;
    QAction *actionShowNote;
    QAction *actionShowChat;
    QAction *actionShowComment;
    QVBoxLayout *verticalLayout;
    ExpertInfoTreeView *expertInfoTreeView;
    ElidedLabel *hintLabel;
    QHBoxLayout *horizontalLayout_2;
    QCheckBox *limitCheckBox;
    QSpacerItem *horizontalSpacer_2;
    QCheckBox *groupBySummaryCheckBox;
    QSpacerItem *horizontalSpacer;
    QLabel *label;
    QLineEdit *searchLineEdit;
    QSpacerItem *horizontalSpacer_3;
    QPushButton *severitiesPushButton;
    QMenu *menuShowExpert;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ExpertInfoDialog)
    {
        if (ExpertInfoDialog->objectName().isEmpty())
            ExpertInfoDialog->setObjectName(QString::fromUtf8("ExpertInfoDialog"));
        ExpertInfoDialog->resize(620, 540);
        actionShowError = new QAction(ExpertInfoDialog);
        actionShowError->setObjectName(QString::fromUtf8("actionShowError"));
        actionShowError->setCheckable(true);
        actionShowError->setChecked(true);
        actionShowWarning = new QAction(ExpertInfoDialog);
        actionShowWarning->setObjectName(QString::fromUtf8("actionShowWarning"));
        actionShowWarning->setCheckable(true);
        actionShowWarning->setChecked(true);
        actionShowNote = new QAction(ExpertInfoDialog);
        actionShowNote->setObjectName(QString::fromUtf8("actionShowNote"));
        actionShowNote->setCheckable(true);
        actionShowNote->setChecked(true);
        actionShowChat = new QAction(ExpertInfoDialog);
        actionShowChat->setObjectName(QString::fromUtf8("actionShowChat"));
        actionShowChat->setCheckable(true);
        actionShowChat->setChecked(true);
        actionShowComment = new QAction(ExpertInfoDialog);
        actionShowComment->setObjectName(QString::fromUtf8("actionShowComment"));
        actionShowComment->setCheckable(true);
        actionShowComment->setChecked(true);
        verticalLayout = new QVBoxLayout(ExpertInfoDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        expertInfoTreeView = new ExpertInfoTreeView(ExpertInfoDialog);
        expertInfoTreeView->setObjectName(QString::fromUtf8("expertInfoTreeView"));
        expertInfoTreeView->setUniformRowHeights(true);
        expertInfoTreeView->setSortingEnabled(true);

        verticalLayout->addWidget(expertInfoTreeView);

        hintLabel = new ElidedLabel(ExpertInfoDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));

        verticalLayout->addWidget(hintLabel);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        limitCheckBox = new QCheckBox(ExpertInfoDialog);
        limitCheckBox->setObjectName(QString::fromUtf8("limitCheckBox"));

        horizontalLayout_2->addWidget(limitCheckBox);

        horizontalSpacer_2 = new QSpacerItem(20, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);

        groupBySummaryCheckBox = new QCheckBox(ExpertInfoDialog);
        groupBySummaryCheckBox->setObjectName(QString::fromUtf8("groupBySummaryCheckBox"));
        groupBySummaryCheckBox->setChecked(true);

        horizontalLayout_2->addWidget(groupBySummaryCheckBox);

        horizontalSpacer = new QSpacerItem(20, 10, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        label = new QLabel(ExpertInfoDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout_2->addWidget(label);

        searchLineEdit = new QLineEdit(ExpertInfoDialog);
        searchLineEdit->setObjectName(QString::fromUtf8("searchLineEdit"));

        horizontalLayout_2->addWidget(searchLineEdit);

        horizontalSpacer_3 = new QSpacerItem(40, 10, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_3);

        severitiesPushButton = new QPushButton(ExpertInfoDialog);
        severitiesPushButton->setObjectName(QString::fromUtf8("severitiesPushButton"));
        menuShowExpert = new QMenu(severitiesPushButton);
        menuShowExpert->setObjectName(QString::fromUtf8("menuShowExpert"));

        horizontalLayout_2->addWidget(severitiesPushButton);

        horizontalLayout_2->setStretch(5, 1);

        verticalLayout->addLayout(horizontalLayout_2);

        buttonBox = new QDialogButtonBox(ExpertInfoDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help);

        verticalLayout->addWidget(buttonBox);


        menuShowExpert->addAction(actionShowError);
        menuShowExpert->addAction(actionShowWarning);
        menuShowExpert->addAction(actionShowChat);
        menuShowExpert->addAction(actionShowNote);
        menuShowExpert->addAction(actionShowComment);

        retranslateUi(ExpertInfoDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), ExpertInfoDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), ExpertInfoDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(ExpertInfoDialog);
    } // setupUi

    void retranslateUi(QDialog *ExpertInfoDialog)
    {
        ExpertInfoDialog->setWindowTitle(QApplication::translate("ExpertInfoDialog", "Dialog", nullptr));
        actionShowError->setText(QApplication::translate("ExpertInfoDialog", "Error", nullptr));
#ifndef QT_NO_TOOLTIP
        actionShowError->setToolTip(QApplication::translate("ExpertInfoDialog", "Show error packets.", nullptr));
#endif // QT_NO_TOOLTIP
        actionShowWarning->setText(QApplication::translate("ExpertInfoDialog", "Warning", nullptr));
#ifndef QT_NO_TOOLTIP
        actionShowWarning->setToolTip(QApplication::translate("ExpertInfoDialog", "Show warning packets.", nullptr));
#endif // QT_NO_TOOLTIP
        actionShowNote->setText(QApplication::translate("ExpertInfoDialog", "Note", nullptr));
#ifndef QT_NO_TOOLTIP
        actionShowNote->setToolTip(QApplication::translate("ExpertInfoDialog", "Show note packets.", nullptr));
#endif // QT_NO_TOOLTIP
        actionShowChat->setText(QApplication::translate("ExpertInfoDialog", "Chat", nullptr));
#ifndef QT_NO_TOOLTIP
        actionShowChat->setToolTip(QApplication::translate("ExpertInfoDialog", "Show chat packets.", nullptr));
#endif // QT_NO_TOOLTIP
        actionShowComment->setText(QApplication::translate("ExpertInfoDialog", "Comment", nullptr));
#ifndef QT_NO_TOOLTIP
        actionShowComment->setToolTip(QApplication::translate("ExpertInfoDialog", "Show comment packets.", nullptr));
#endif // QT_NO_TOOLTIP
        hintLabel->setText(QApplication::translate("ExpertInfoDialog", "<small><i>A hint.</i></small>", nullptr));
        limitCheckBox->setText(QApplication::translate("ExpertInfoDialog", "Limit to Display Filter", nullptr));
        groupBySummaryCheckBox->setText(QApplication::translate("ExpertInfoDialog", "Group by summary", nullptr));
#ifndef QT_NO_TOOLTIP
        label->setToolTip(QApplication::translate("ExpertInfoDialog", "Search expert summaries.", nullptr));
#endif // QT_NO_TOOLTIP
        label->setText(QApplication::translate("ExpertInfoDialog", "Search:", nullptr));
#ifndef QT_NO_TOOLTIP
        searchLineEdit->setToolTip(QApplication::translate("ExpertInfoDialog", "Search expert summaries.", nullptr));
#endif // QT_NO_TOOLTIP
        severitiesPushButton->setText(QApplication::translate("ExpertInfoDialog", "Show\342\200\246", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ExpertInfoDialog: public Ui_ExpertInfoDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_EXPERT_INFO_DIALOG_H
