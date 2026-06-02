/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DIS_AUDIO_STREAM_H
#define DIS_AUDIO_STREAM_H

#include "config.h"

#ifdef QT_MULTIMEDIA_LIB

#include <QAudio>
#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVector>

#include "ui/tap-dis-common.h"

class QBuffer;
class QTimer;
class QAudioSink;

class DisAudioStream : public QObject
{
    Q_OBJECT
public:
    explicit DisAudioStream(QObject *parent = nullptr);
    ~DisAudioStream();

    bool playDisStream(const disstream_info_t *stream_info, QString &error_message);
    bool prepareVisualData(const disstream_info_t *stream_info, QString &error_message);
    void stopPlayback(bool call_stop = true);
    void pausePlayback();
    void resumePlayback();
    void setPlaybackStartTime(double start_time_secs) { playback_start_time_ = start_time_secs; }
    bool isPlaying() const;
    bool isPaused() const;
    QAudio::State playbackState() const;
    const disstream_info_t *currentStream() const { return current_stream_; }
    double playbackDurationSeconds() const { return total_playback_secs_; }
    const QVector<double> &visualTimestamps() const { return visual_timestamps_; }
    const QVector<double> &visualSamples() const { return visual_samples_; }
    const QVector<double> &jitterTimestamps() const { return jitter_timestamps_; }
    const QVector<double> &jitterSamples() const { return jitter_samples_; }
    const QVector<double> &lossTimestamps() const { return loss_timestamps_; }
    const QVector<double> &lossSamples() const { return loss_samples_; }
    const QVector<double> &problemTimestamps() const { return problem_timestamps_; }
    const QVector<double> &problemSamples() const { return problem_samples_; }

signals:
    void playbackStateChanged(QAudio::State state);
    void playbackProgress(double position_secs, double duration_secs);

private:
    bool decodeToPcm(const disstream_info_t *stream_info, QString &error_message,
        unsigned &sample_rate, unsigned &channels);
    void buildVisualData(const disstream_info_t *stream_info);

private slots:
    void onPlaybackStateChanged(QAudio::State state);
    void updatePlaybackProgress();

private:
    QByteArray pcm_buffer_;
    QBuffer *playback_buffer_;
    QAudioSink *audio_sink_;
    QTimer *progress_timer_;
    unsigned sample_rate_;
    unsigned channels_;
    double total_playback_secs_;
    double playback_start_time_;
    const disstream_info_t *current_stream_;
    bool stopping_playback_;
    QVector<double> visual_timestamps_;
    QVector<double> visual_samples_;
    QVector<double> jitter_timestamps_;
    QVector<double> jitter_samples_;
    QVector<double> loss_timestamps_;
    QVector<double> loss_samples_;
    QVector<double> problem_timestamps_;
    QVector<double> problem_samples_;
};

#endif

#endif /* DIS_AUDIO_STREAM_H */
