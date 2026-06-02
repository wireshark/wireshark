/* dis_audio_stream.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "dis_audio_stream.h"

#ifdef QT_MULTIMEDIA_LIB

#include <cmath>
#include <cstring>
#include <limits>

#include <QBuffer>
#include <QString>
#include <QTimer>

#include "epan/dissectors/packet-rtp.h"
#include "epan/dissectors/packet-rtp_pt.h"

#include "ui/rtp_media.h"

#include <QAudioDevice>
#include <QAudioFormat>
#include <QAudioSink>
#include <QMediaDevices>

static bool
map_dis_payload_to_rtp_codec(uint8_t dis_payload_type, unsigned *rtp_payload_type,
    const char **rtp_payload_name, unsigned *sample_rate, unsigned *channels)
{
    switch (dis_payload_type) {
    case 1: /* 8-bit mu-law (ITU-T G.711) */
        *rtp_payload_type = PT_PCMU;
        *rtp_payload_name = "PCMU";
        *sample_rate = 8000;
        *channels = 1;
        return true;
    case 8: /* GSM Full-Rate */
        *rtp_payload_type = PT_GSM;
        *rtp_payload_name = "GSM";
        *sample_rate = 8000;
        *channels = 1;
        return true;
    case 4: /* 16-bit linear PCM (big endian) */
        *rtp_payload_type = PT_L16_MONO;
        *rtp_payload_name = "L16";
        *sample_rate = 8000;
        *channels = 1;
        return true;
    default:
        return false;
    }
}

static QByteArray
resample_int16_mono(const QByteArray &src_pcm, unsigned in_rate, unsigned out_rate, unsigned out_channels)
{
    if (in_rate == 0 || out_rate == 0 || (out_channels != 1 && out_channels != 2)) {
        return QByteArray();
    }

    const qsizetype input_sample_count = src_pcm.size() / SAMPLE_BYTES;
    if (input_sample_count <= 0 || input_sample_count > std::numeric_limits<int>::max()) {
        return QByteArray();
    }
    const int in_samples = static_cast<int>(input_sample_count);

    int out_frames = (int)std::lround(((double)in_samples * out_rate) / in_rate);
    out_frames = qMax(1, out_frames);

    QByteArray out_pcm;
    out_pcm.resize(out_frames * (int)out_channels * SAMPLE_BYTES);

    const SAMPLE *in_data = reinterpret_cast<const SAMPLE *>(src_pcm.constData());
    SAMPLE *out_data = reinterpret_cast<SAMPLE *>(out_pcm.data());

    for (int frame = 0; frame < out_frames; frame++) {
        const double src_pos = ((double)frame * in_rate) / out_rate;
        const int idx = (int)std::floor(src_pos);
        const int idx_next = qMin(in_samples - 1, idx + 1);
        const double frac = src_pos - idx;

        const double s0 = in_data[qBound(0, idx, in_samples - 1)];
        const double s1 = in_data[idx_next];
        const SAMPLE sample = (SAMPLE)std::lround(s0 + (s1 - s0) * frac);

        out_data[frame * out_channels] = sample;
        if (out_channels == 2) {
            out_data[frame * out_channels + 1] = sample;
        }
    }

    return out_pcm;
}

static QByteArray
convert_int16_pcm_to_format(const QByteArray &src_pcm, QAudioFormat::SampleFormat sample_format)
{
    if (sample_format == QAudioFormat::Int16) {
        return src_pcm;
    }

    const qsizetype sample_count = src_pcm.size() / SAMPLE_BYTES;
    if (sample_count <= 0 || sample_count > std::numeric_limits<int>::max()) {
        return QByteArray();
    }

    const SAMPLE *in_data = reinterpret_cast<const SAMPLE *>(src_pcm.constData());
    QByteArray out_pcm;

    switch (sample_format) {
    case QAudioFormat::UInt8:
        out_pcm.resize(sample_count);
        for (int i = 0; i < sample_count; i++) {
            const int value = qBound(0, ((int)in_data[i] + 32768) >> 8, 255);
            out_pcm[i] = static_cast<char>(value);
        }
        return out_pcm;
    case QAudioFormat::Int32:
        out_pcm.resize(sample_count * (qsizetype)sizeof(qint32));
        for (int i = 0; i < sample_count; i++) {
            const qint32 value = ((qint32)in_data[i]) << 16;
            memcpy(out_pcm.data() + (i * (int)sizeof(qint32)), &value, sizeof(value));
        }
        return out_pcm;
    case QAudioFormat::Float:
        out_pcm.resize(sample_count * (qsizetype)sizeof(float));
        for (int i = 0; i < sample_count; i++) {
            const float value = (float)in_data[i] / 32768.0f;
            memcpy(out_pcm.data() + (i * (int)sizeof(float)), &value, sizeof(value));
        }
        return out_pcm;
    default:
        return QByteArray();
    }
}

DisAudioStream::DisAudioStream(QObject *parent) :
    QObject(parent),
    playback_buffer_(nullptr),
    audio_sink_(nullptr),
    progress_timer_(new QTimer(this)),
    sample_rate_(0),
    channels_(1),
    total_playback_secs_(0.0),
    playback_start_time_(0.0),
    current_stream_(nullptr),
    stopping_playback_(false)
{
    progress_timer_->setInterval(50);
    connect(progress_timer_, &QTimer::timeout, this, &DisAudioStream::updatePlaybackProgress);
}

DisAudioStream::~DisAudioStream()
{
    stopPlayback();
}

bool
DisAudioStream::decodeToPcm(const disstream_info_t *stream_info, QString &error_message,
    unsigned &sample_rate, unsigned &channels)
{
    GHashTable *decoders_hash;

    pcm_buffer_.clear();
    sample_rate = 0;
    channels = 1;

    if (!stream_info || !stream_info->signal_packets || stream_info->signal_packets->len == 0) {
        error_message = tr("No DIS signal payload is available for playback.");
        return false;
    }

    decoders_hash = rtp_decoder_hash_table_new();
    for (guint i = 0; i < stream_info->signal_packets->len; i++) {
        disstream_packet_t *packet = (disstream_packet_t *)g_ptr_array_index(stream_info->signal_packets, i);
        struct _rtp_info rtp_info;
        rtp_packet_t rtp_packet;
        SAMPLE *decoded = nullptr;
        unsigned rtp_payload_type = 0;
        const char *rtp_payload_name = nullptr;
        unsigned packet_channels = 0;
        unsigned packet_sample_rate = 0;
        size_t decoded_bytes;

        if (!packet || !packet->payload_data || packet->payload_len == 0) {
            continue;
        }

        memset(&rtp_info, 0, sizeof(rtp_info));
        memset(&rtp_packet, 0, sizeof(rtp_packet));

        if (!map_dis_payload_to_rtp_codec(packet->payload_type, &rtp_payload_type,
                &rtp_payload_name, &packet_sample_rate, &packet_channels)) {
            continue;
        }

        rtp_info.info_payload_type = rtp_payload_type;
        rtp_info.info_payload_type_str = rtp_payload_name;
        rtp_info.info_payload_rate = (int)packet_sample_rate;
        rtp_info.info_payload_channels = packet_channels;
        rtp_info.info_payload_len = packet->payload_len;
        rtp_info.info_all_data_present = true;

        rtp_packet.frame_num = packet->frame_num;
        rtp_packet.info = &rtp_info;
        rtp_packet.payload_data = packet->payload_data;

        decoded_bytes = decode_rtp_packet(&rtp_packet, &decoded, decoders_hash, &packet_channels, &packet_sample_rate);
        if (decoded_bytes > 0 && decoded) {
            if (sample_rate == 0 && packet_sample_rate > 0) {
                sample_rate = packet_sample_rate;
            }
            if (packet_channels > 0) {
                channels = packet_channels;
            }

            pcm_buffer_.append((const char *)decoded, (int)decoded_bytes);
        }

        g_free(decoded);
    }

    g_hash_table_destroy(decoders_hash);

    if (pcm_buffer_.isEmpty()) {
        error_message = tr("Unable to decode DIS audio payload for this stream.");
        return false;
    }

    if (sample_rate == 0) {
        sample_rate = 8000;
    }

    if (channels == 0) {
        channels = 1;
    }

    return true;
}

void
DisAudioStream::buildVisualData(const disstream_info_t *stream_info)
{
    static constexpr double visual_sample_rate = 1000.0;

    visual_timestamps_.clear();
    visual_samples_.clear();
    jitter_timestamps_.clear();
    jitter_samples_.clear();
    loss_timestamps_.clear();
    loss_samples_.clear();
    problem_timestamps_.clear();
    problem_samples_.clear();

    if (!stream_info || sample_rate_ == 0 || pcm_buffer_.isEmpty()) {
        return;
    }

    const SAMPLE *samples = reinterpret_cast<const SAMPLE *>(pcm_buffer_.constData());
    const qint64 total_values = pcm_buffer_.size() / SAMPLE_BYTES;
    const int channel_count = channels_ > 0 ? static_cast<int>(channels_) : 1;
    const qint64 total_frames = total_values / channel_count;
    const int bucket_size = qMax(1, static_cast<int>(std::lround(sample_rate_ / visual_sample_rate)));
    const double start_time = nstime_to_sec(&stream_info->start_rel_time);

    for (qint64 frame = 0; frame < total_frames; frame += bucket_size) {
        qint64 end_frame = qMin(total_frames, frame + bucket_size);
        int peak_sample = 0;

        for (qint64 current_frame = frame; current_frame < end_frame; current_frame++) {
            int sample_value = samples[current_frame * channel_count];
            if (std::abs(sample_value) > std::abs(peak_sample)) {
                peak_sample = sample_value;
            }
        }

        visual_timestamps_.append(start_time + static_cast<double>(frame) / sample_rate_);
        visual_samples_.append(static_cast<double>(peak_sample) / INT16_MAX);
    }

    const double jitter_threshold = qMax(stream_info->mean_jitter_ms * 2.0, 5.0);
    for (guint i = 0; stream_info->signal_packets && i < stream_info->signal_packets->len; i++) {
        disstream_packet_t *packet = static_cast<disstream_packet_t *>(g_ptr_array_index(stream_info->signal_packets, i));
        if (!packet) {
            continue;
        }

        double timestamp = nstime_to_sec(&packet->rel_time);
        if (packet->jitter_ms >= jitter_threshold) {
            jitter_timestamps_.append(timestamp);
            jitter_samples_.append(1.10);
        }
        if (packet->estimated_lost_added > 0) {
            loss_timestamps_.append(timestamp);
            loss_samples_.append(1.20);
        }
        if (packet->problem) {
            problem_timestamps_.append(timestamp);
            problem_samples_.append(1.30);
        }
    }
}

bool
DisAudioStream::prepareVisualData(const disstream_info_t *stream_info, QString &error_message)
{
    unsigned sample_rate = 0;
    unsigned channels = 1;

    if (!decodeToPcm(stream_info, error_message, sample_rate, channels)) {
        visual_timestamps_.clear();
        visual_samples_.clear();
        jitter_timestamps_.clear();
        jitter_samples_.clear();
        loss_timestamps_.clear();
        loss_samples_.clear();
        problem_timestamps_.clear();
        problem_samples_.clear();
        return false;
    }

    sample_rate_ = sample_rate;
    channels_ = channels;
    total_playback_secs_ = (sample_rate_ > 0 && channels_ > 0)
        ? (double)pcm_buffer_.size() / (SAMPLE_BYTES * channels_ * sample_rate_)
        : 0.0;
    buildVisualData(stream_info);
    return true;
}

bool
DisAudioStream::playDisStream(const disstream_info_t *stream_info, QString &error_message)
{
    unsigned sample_rate = 0;
    unsigned channels = 1;

    if (!decodeToPcm(stream_info, error_message, sample_rate, channels)) {
        return false;
    }

    sample_rate_ = sample_rate;
    channels_ = channels;
    buildVisualData(stream_info);

    stopPlayback();

    QAudioFormat format;
    format.setSampleRate((int)sample_rate);
    format.setChannelCount((int)channels);
    QByteArray playback_pcm = pcm_buffer_;
    if (stream_info && sample_rate_ > 0 && channels_ > 0 && playback_start_time_ > 0.0) {
        const double stream_start_time = nstime_to_sec(&stream_info->start_rel_time);
        const double stream_end_time = nstime_to_sec(&stream_info->stop_rel_time);
        const double bounded_start = qBound(stream_start_time, playback_start_time_, stream_end_time);
        const double start_offset_secs = bounded_start - stream_start_time;
        const qint64 start_frame = qBound<qint64>(0,
            (qint64)std::floor(start_offset_secs * sample_rate_),
            pcm_buffer_.size() / (SAMPLE_BYTES * channels_));
        const qint64 start_byte = start_frame * channels_ * SAMPLE_BYTES;

        if (start_byte > 0 && start_byte < playback_pcm.size()) {
            playback_pcm = playback_pcm.mid(start_byte);
        } else if (start_byte >= playback_pcm.size()) {
            playback_pcm.clear();
        }
    }
    total_playback_secs_ = (sample_rate_ > 0 && channels_ > 0)
        ? (double)playback_pcm.size() / (SAMPLE_BYTES * channels_ * sample_rate_)
        : 0.0;
    format.setSampleFormat(QAudioFormat::Int16);
    QAudioDevice output_device = QMediaDevices::defaultAudioOutput();

    if (!output_device.isFormatSupported(format)) {
        const QAudioFormat preferred = output_device.preferredFormat();
        if ((preferred.sampleFormat() == QAudioFormat::UInt8 ||
                preferred.sampleFormat() == QAudioFormat::Int16 ||
                preferred.sampleFormat() == QAudioFormat::Int32 ||
                preferred.sampleFormat() == QAudioFormat::Float) &&
            preferred.sampleRate() > 0 &&
            (preferred.channelCount() == 1 || preferred.channelCount() == 2)) {
            QByteArray adapted_pcm = resample_int16_mono(
                pcm_buffer_, sample_rate,
                (unsigned)preferred.sampleRate(),
                (unsigned)preferred.channelCount());
            if (!adapted_pcm.isEmpty()) {
                playback_pcm = convert_int16_pcm_to_format(adapted_pcm, preferred.sampleFormat());
                format = preferred;
            }
        }
    }
    if (playback_pcm.isEmpty() || !output_device.isFormatSupported(format)) {
        error_message = tr("Audio format is not supported by the current output device.");
        stopPlayback();
        return false;
    }

    audio_sink_ = new QAudioSink(output_device, format, this);
    connect(audio_sink_, &QAudioSink::stateChanged, this, &DisAudioStream::onPlaybackStateChanged);

    playback_buffer_ = new QBuffer(this);
    playback_buffer_->setData(playback_pcm);
    if (!playback_buffer_->open(QIODevice::ReadOnly)) {
        error_message = tr("Unable to open playback buffer.");
        stopPlayback();
        return false;
    }

    audio_sink_->start(playback_buffer_);
    current_stream_ = stream_info;
    progress_timer_->start();
    emit playbackProgress(0.0, total_playback_secs_);
    emit playbackStateChanged(audio_sink_->state());
    return true;
}

void
DisAudioStream::stopPlayback(bool call_stop)
{
    if (stopping_playback_) {
        return;
    }

    stopping_playback_ = true;

    if (progress_timer_) {
        progress_timer_->stop();
    }

    if (audio_sink_) {
        disconnect(audio_sink_, &QAudioSink::stateChanged, this, &DisAudioStream::onPlaybackStateChanged);
        if (call_stop && (audio_sink_->state() == QAudio::ActiveState || audio_sink_->state() == QAudio::SuspendedState)) {
            audio_sink_->stop();
        }
        audio_sink_->deleteLater();
        audio_sink_ = nullptr;
    }

    if (playback_buffer_) {
        playback_buffer_->close();
        playback_buffer_->deleteLater();
        playback_buffer_ = nullptr;
    }

    current_stream_ = nullptr;

    stopping_playback_ = false;
}

void
DisAudioStream::pausePlayback()
{
    if (!audio_sink_ || audio_sink_->state() != QAudio::ActiveState) {
        return;
    }

    audio_sink_->suspend();
}

void
DisAudioStream::resumePlayback()
{
    if (!audio_sink_ || audio_sink_->state() != QAudio::SuspendedState) {
        return;
    }

    audio_sink_->resume();
}

bool
DisAudioStream::isPlaying() const
{
    return audio_sink_ &&
        (audio_sink_->state() == QAudio::ActiveState || audio_sink_->state() == QAudio::SuspendedState);
}

bool
DisAudioStream::isPaused() const
{
    return audio_sink_ && audio_sink_->state() == QAudio::SuspendedState;
}

QAudio::State
DisAudioStream::playbackState() const
{
    return audio_sink_ ? audio_sink_->state() : QAudio::StoppedState;
}

void
DisAudioStream::onPlaybackStateChanged(QAudio::State state)
{
    if (state == QAudio::ActiveState) {
        if (progress_timer_) {
            progress_timer_->start();
        }
    } else if (state == QAudio::SuspendedState) {
        if (progress_timer_) {
            progress_timer_->stop();
        }
    } else if (state == QAudio::IdleState || state == QAudio::StoppedState) {
        updatePlaybackProgress();
        stopPlayback(false);
    }

    emit playbackStateChanged(state);
}

void
DisAudioStream::updatePlaybackProgress()
{
    if (!playback_buffer_) {
        return;
    }

    double position_secs = 0.0;
    if (total_playback_secs_ > 0.0 && playback_buffer_->size() > 0) {
        position_secs = total_playback_secs_ * (double)playback_buffer_->pos() / playback_buffer_->size();
    }
    if (position_secs < 0.0) {
        position_secs = 0.0;
    }
    if (total_playback_secs_ > 0.0 && position_secs > total_playback_secs_) {
        position_secs = total_playback_secs_;
    }

    emit playbackProgress(position_secs, total_playback_secs_);
}

#endif
