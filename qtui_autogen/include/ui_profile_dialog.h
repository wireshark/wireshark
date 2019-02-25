/********************************************************************************
** Form generated from reading UI file 'profile_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PROFILE_DIALOG_H
#define UI_PROFILE_DIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include "widgets/elided_label.h"

QT_BEGIN_NAMESPACE

class Ui_ProfileDialog
{
public:
    QVBoxLayout *verticalLayout;
    QTreeWidget *profileTreeWidget;
    QHBoxLayout *horizontalLayout;
    QToolButton *newToolButton;
    QToolButton *deleteToolButton;
    QToolButton *copyToolButton;
    QSpacerItem *horizontalSpacer;
    ElidedLabel *infoLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ProfileDialog)
    {
        if (ProfileDialog->objectName().isEmpty())
            ProfileDialog->setObjectName(QString::fromUtf8("ProfileDialog"));
        ProfileDialog->resize(470, 300);
        verticalLayout = new QVBoxLayout(ProfileDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        profileTreeWidget = new QTreeWidget(ProfileDialog);
        profileTreeWidget->setObjectName(QString::fromUtf8("profileTreeWidget"));
        profileTreeWidget->setRootIsDecorated(false);
        profileTreeWidget->setUniformRowHeights(true);
        profileTreeWidget->setItemsExpandable(false);
        profileTreeWidget->setHeaderHidden(true);
        profileTreeWidget->setExpandsOnDoubleClick(false);
        profileTreeWidget->setColumnCount(1);

        verticalLayout->addWidget(profileTreeWidget);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        newToolButton = new QToolButton(ProfileDialog);
        newToolButton->setObjectName(QString::fromUtf8("newToolButton"));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/stock/plus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        newToolButton->setIcon(icon);

        horizontalLayout->addWidget(newToolButton);

        deleteToolButton = new QToolButton(ProfileDialog);
        deleteToolButton->setObjectName(QString::fromUtf8("deleteToolButton"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/stock/minus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        deleteToolButton->setIcon(icon1);

        horizontalLayout->addWidget(deleteToolButton);

        copyToolButton = new QToolButton(ProfileDialog);
        copyToolButton->setObjectName(QString::fromUtf8("copyToolButton"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/stock/copy-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        copyToolButton->setIcon(icon2);

        horizontalLayout->addWidget(copyToolButton);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        infoLabel = new ElidedLabel(ProfileDialog);
        infoLabel->setObjectName(QString::fromUtf8("infoLabel"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(1);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(infoLabel->sizePolicy().hasHeightForWidth());
        infoLabel->setSizePolicy(sizePolicy);
        infoLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        infoLabel->setOpenExternalLinks(true);

        horizontalLayout->addWidget(infoLabel);

        horizontalLayout->setStretch(4, 1);

        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(ProfileDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Help|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(ProfileDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), ProfileDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), ProfileDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(ProfileDialog);
    } // setupUi

    void retranslateUi(QDialog *ProfileDialog)
    {
        QTreeWidgetItem *___qtreewidgetitem = profileTreeWidget->headerItem();
        ___qtreewidgetitem->setText(0, QApplication::translate("ProfileDialog", "Name", nullptr));
#ifndef QT_NO_TOOLTIP
        newToolButton->setToolTip(QApplication::translate("ProfileDialog", "Create a new profile using default settings.", nullptr));
#endif // QT_NO_TOOLTIP
        newToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        deleteToolButton->setToolTip(QApplication::translate("ProfileDialog", "Remove this profile. System provided profiles cannot be removed.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        copyToolButton->setToolTip(QApplication::translate("ProfileDialog", "Copy this profile.", nullptr));
#endif // QT_NO_TOOLTIP
        copyToolButton->setText(QString());
        infoLabel->setText(QString());
        Q_UNUSED(ProfileDialog);
    } // retranslateUi

};

namespace Ui {
    class ProfileDialog: public Ui_ProfileDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROFILE_DIALOG_H
