/********************************************************************************
** Form generated from reading UI file 'splash_overlay.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SPLASH_OVERLAY_H
#define UI_SPLASH_OVERLAY_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_SplashOverlay
{
public:
    QVBoxLayout *verticalLayout_2;
    QSpacerItem *verticalSpacer_2;
    QFrame *progressBand;
    QHBoxLayout *horizontalLayout;
    QSpacerItem *horizontalSpacer;
    QVBoxLayout *verticalLayout;
    QLabel *actionLabel;
    QProgressBar *progressBar;
    QSpacerItem *horizontalSpacer_2;
    QSpacerItem *verticalSpacer;

    void setupUi(QWidget *SplashOverlay)
    {
        if (SplashOverlay->objectName().isEmpty())
            SplashOverlay->setObjectName(QString::fromUtf8("SplashOverlay"));
        SplashOverlay->setEnabled(true);
        SplashOverlay->resize(400, 300);
        verticalLayout_2 = new QVBoxLayout(SplashOverlay);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        verticalLayout_2->setContentsMargins(0, -1, 0, -1);
        verticalSpacer_2 = new QSpacerItem(20, 53, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_2->addItem(verticalSpacer_2);

        progressBand = new QFrame(SplashOverlay);
        progressBand->setObjectName(QString::fromUtf8("progressBand"));
        progressBand->setFrameShape(QFrame::NoFrame);
        progressBand->setFrameShadow(QFrame::Plain);
        progressBand->setLineWidth(0);
        horizontalLayout = new QHBoxLayout(progressBand);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalSpacer = new QSpacerItem(116, 50, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        actionLabel = new QLabel(progressBand);
        actionLabel->setObjectName(QString::fromUtf8("actionLabel"));

        verticalLayout->addWidget(actionLabel);

        progressBar = new QProgressBar(progressBand);
        progressBar->setObjectName(QString::fromUtf8("progressBar"));
        progressBar->setValue(24);
        progressBar->setTextVisible(false);

        verticalLayout->addWidget(progressBar);


        horizontalLayout->addLayout(verticalLayout);

        horizontalSpacer_2 = new QSpacerItem(116, 50, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);


        verticalLayout_2->addWidget(progressBand);

        verticalSpacer = new QSpacerItem(20, 108, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_2->addItem(verticalSpacer);

        verticalLayout_2->setStretch(0, 3);
        verticalLayout_2->setStretch(2, 6);

        retranslateUi(SplashOverlay);

        QMetaObject::connectSlotsByName(SplashOverlay);
    } // setupUi

    void retranslateUi(QWidget *SplashOverlay)
    {
        actionLabel->setText(QString());
        Q_UNUSED(SplashOverlay);
    } // retranslateUi

};

namespace Ui {
    class SplashOverlay: public Ui_SplashOverlay {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SPLASH_OVERLAY_H
