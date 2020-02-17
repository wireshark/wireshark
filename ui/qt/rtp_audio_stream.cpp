/* rtp_audio_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_audio_stream.h"

#ifdef QT_MULTIMEDIA_LIB

#ifdef HAVE_SPEEXDSP
#include <speex/speex_resampler.h>
#else
#include "../../speexdsp/speex_resampler.h"
#endif /* HAVE_SPEEXDSP */

#include <epan/rtp_pt.h>

#include <epan/dissectors/packet-rtp.h>

#include <ui/rtp_media.h>
#include <ui/rtp_stream.h>

#include <wsutil/nstime.h>

#include <QAudioFormat>
#include <QAudioOutput>
#include <QDir>
#include <QTemporaryFile>
#include <QVariant>

// To do:
// - Only allow one rtpstream_info_t per RtpAudioStream?

static spx_int16_t default_audio_sample_rate_ = 8000;
static const spx_int16_t visual_sample_rate_ = 1000;

RtpAudioStream::RtpAudioStream(QObject *parent, rtpstream_info_t *rtpstream) :
    QObject(parent),
    decoders_hash_(rtp_decoder_hash_table_new()),
    global_start_rel_time_(0.0),
    start_abs_offset_(0.0),
    start_rel_time_(0.0),
    stop_rel_time_(0.0),
    audio_stereo_(false),
    audio_left_(false),
    audio_right_(false),
    audio_out_rate_(0),
    audio_resampler_(0),
    audio_output_(0),
    max_sample_val_(1),
    color_(0),
    jitter_buffer_size_(50),
    timing_mode_(RtpAudioStream::JitterBuffer),
    start_play_time_(0)
{
    rtpstream_id_copy(&rtpstream->id, &id_);

    // We keep visual samples in memory. Make fewer of them.
    visual_resampler_ = speex_resampler_init(1, default_audio_sample_rate_,
                                                visual_sample_rate_, SPEEX_RESAMPLER_QUALITY_MIN, NULL);
    speex_resampler_skip_zeros(visual_resampler_);

    QString tempname = QString("%1/wireshark_rtp_stream").arg(QDir::tempPath());
    tempfile_ = new QTemporaryFile(tempname, this);
    tempfile_->open();

    // RTP_STREAM_DEBUG("Writing to %s", tempname.toUtf8().constData());
}

RtpAudioStream::~RtpAudioStream()
{
    for (int i = 0; i < rtp_packets_.size(); i++) {
        rtp_packet_t *rtp_packet = rtp_packets_[i];
        g_free(rtp_packet->info);
        g_free(rtp_packet->payload_data);
        g_free(rtp_packet);
    }
    g_hash_table_destroy(decoders_hash_);
    if (audio_resampler_) speex_resampler_destroy (audio_resampler_);
    speex_resampler_destroy (visual_resampler_);
    rtpstream_id_free(&id_);
}

bool RtpAudioStream::isMatch(const rtpstream_info_t *rtpstream) const
{
    if (rtpstream
        && rtpstream_id_equal(&id_, &(rtpstream->id), RTPSTREAM_ID_EQUAL_SSRC))
        return true;
    return false;
}

bool RtpAudioStream::isMatch(const _packet_info *pinfo, const _rtp_info *rtp_info) const
{
    if (pinfo && rtp_info
        && rtpstream_id_equal_pinfo_rtp_info(&id_, pinfo, rtp_info))
        return true;
    return false;
}

// XXX We add multiple RTP streams here because that's what the GTK+ UI does.
// Should we make these distinct, with their own waveforms? It seems like
// that would simplify a lot of things.
// TODO: It is not used
/*
void RtpAudioStream::addRtpStream(const rtpstream_info_t *rtpstream)
{
    if (!rtpstream) return;

    // RTP_STREAM_DEBUG("added %d:%u packets", g_list_length(rtpstream->rtp_packet_list), rtpstream->packet_count);
    // TODO: It is not used
    //rtpstreams_ << rtpstream;
}
*/

void RtpAudioStream::addRtpPacket(const struct _packet_info *pinfo, const struct _rtp_info *rtp_info)
{
    // gtk/rtp_player.c:decode_rtp_packet
    if (!rtp_info) return;

    rtp_packet_t *rtp_packet = g_new0(rtp_packet_t, 1);
    rtp_packet->info = (struct _rtp_info *) g_memdup(rtp_info, sizeof(struct _rtp_info));
    if (rtp_info->info_all_data_present && (rtp_info->info_payload_len != 0)) {
        rtp_packet->payload_data = (guint8 *) g_memdup(&(rtp_info->info_data[rtp_info->info_payload_offset]), rtp_info->info_payload_len);
    }

    if (rtp_packets_.size() < 1) { // First packet
        start_abs_offset_ = nstime_to_sec(&pinfo->abs_ts) - start_rel_time_;
        start_rel_time_ = stop_rel_time_ = nstime_to_sec(&pinfo->rel_ts);
    }
    rtp_packet->frame_num = pinfo->num;
    rtp_packet->arrive_offset = nstime_to_sec(&pinfo->rel_ts) - start_rel_time_;

    rtp_packets_ << rtp_packet;
}

void RtpAudioStream::reset(double global_start_time, bool stereo, bool left, bool right)
{
    global_start_rel_time_ = global_start_time;
    stop_rel_time_ = start_rel_time_;
    audio_stereo_ = stereo;
    audio_left_ = left;
    audio_right_ = right;
    audio_out_rate_ = 0;
    max_sample_val_ = 1;
    packet_timestamps_.clear();
    visual_samples_.clear();
    out_of_seq_timestamps_.clear();
    jitter_drop_timestamps_.clear();

    if (audio_resampler_) {
        speex_resampler_reset_mem(audio_resampler_);
    }
    if (visual_resampler_) {
        speex_resampler_reset_mem(visual_resampler_);
    }
    tempfile_->seek(0);
}

static const int sample_bytes_ = sizeof(SAMPLE) / sizeof(char);
/* Fix for bug 4119/5902: don't insert too many silence frames.
 * XXX - is there a better thing to do here?
 */
static const qint64 max_silence_samples_ = MAX_SILENCE_FRAMES;

void RtpAudioStream::decode()
{
    if (rtp_packets_.size() < 1) return;

    // gtk/rtp_player.c:decode_rtp_stream
    // XXX This is more messy than it should be.

    gsize resample_buff_len = 0x1000;
    SAMPLE *resample_buff = (SAMPLE *) g_malloc(resample_buff_len);
    spx_uint32_t cur_in_rate = 0, visual_out_rate = 0;
    char *write_buff = NULL;
    qint64 write_bytes = 0;
    unsigned channels = 0;
    unsigned sample_rate = 0;
    int last_sequence = 0;

    double rtp_time_prev = 0.0;
    double arrive_time_prev = 0.0;
    double pack_period = 0.0;
    double start_time = 0.0;
    double start_rtp_time = 0.0;
    guint32 start_timestamp = 0;

    size_t decoded_bytes_prev = 0;

    for (int cur_packet = 0; cur_packet < rtp_packets_.size(); cur_packet++) {
        SAMPLE *decode_buff = NULL;
        // XXX The GTK+ UI updates a progress bar here.
        rtp_packet_t *rtp_packet = rtp_packets_[cur_packet];

        stop_rel_time_ = start_rel_time_ + rtp_packet->arrive_offset;
        speex_resampler_get_rate(visual_resampler_, &cur_in_rate, &visual_out_rate);

        QString payload_name;
        if (rtp_packet->info->info_payload_type_str) {
            payload_name = rtp_packet->info->info_payload_type_str;
        } else {
            payload_name = try_val_to_str_ext(rtp_packet->info->info_payload_type, &rtp_payload_type_short_vals_ext);
        }
        if (!payload_name.isEmpty()) {
            payload_names_ << payload_name;
        }

        if (cur_packet < 1) { // First packet
            start_timestamp = rtp_packet->info->info_timestamp;
            start_rtp_time = 0;
            rtp_time_prev = 0;
            last_sequence = rtp_packet->info->info_seq_num - 1;
        }

        size_t decoded_bytes = decode_rtp_packet(rtp_packet, &decode_buff, decoders_hash_, &channels, &sample_rate);

        unsigned rtp_clock_rate = sample_rate;
        if (rtp_packet->info->info_payload_type == PT_G722) {
            // G.722 sample rate is 16kHz, but RTP clock rate is 8kHz for historic reasons.
            rtp_clock_rate = 8000;
        }

        if (decoded_bytes == 0 || sample_rate == 0) {
            // We didn't decode anything. Clean up and prep for the next packet.
            last_sequence = rtp_packet->info->info_seq_num;
            g_free(decode_buff);
            continue;
        }

        if (audio_out_rate_ == 0) {
            // Use the first non-zero rate we find. Ajust it to match our audio hardware.
            QAudioDeviceInfo cur_out_device = QAudioDeviceInfo::defaultOutputDevice();
            QString cur_out_name = parent()->property("currentOutputDeviceName").toString();
            foreach (QAudioDeviceInfo out_device, QAudioDeviceInfo::availableDevices(QAudio::AudioOutput)) {
                if (cur_out_name == out_device.deviceName()) {
                    cur_out_device = out_device;
                }
            }

            QAudioFormat format;
            format.setSampleRate(sample_rate);
            format.setSampleSize(sample_bytes_ * 8); // bits
            format.setSampleType(QAudioFormat::SignedInt);
            if (audio_stereo_) {
                format.setChannelCount(2);
            } else {
                format.setChannelCount(1);
            }
            format.setCodec("audio/pcm");

            if (!cur_out_device.isFormatSupported(format)) {
                sample_rate = cur_out_device.nearestFormat(format).sampleRate();
            }

            audio_out_rate_ = sample_rate;
            RTP_STREAM_DEBUG("Audio sample rate is %u", audio_out_rate_);

            // Prepend silence to match our sibling streams.
            tempfile_->seek(0);
            qint64 prepend_samples = (start_rel_time_ - global_start_rel_time_) * audio_out_rate_;
            if (prepend_samples > 0) {
                writeSilence(prepend_samples);
            }
        }

        if (rtp_packet->info->info_seq_num != last_sequence+1) {
            out_of_seq_timestamps_.append(stop_rel_time_);
        }
        last_sequence = rtp_packet->info->info_seq_num;

        double rtp_time = (double)(rtp_packet->info->info_timestamp-start_timestamp)/rtp_clock_rate - start_rtp_time;
        double arrive_time;
        if (timing_mode_ == RtpTimestamp) {
            arrive_time = rtp_time;
        } else {
            arrive_time = rtp_packet->arrive_offset - start_time;
        }

        double diff = qAbs(arrive_time - rtp_time);
        if (diff*1000 > jitter_buffer_size_ && timing_mode_ != Uninterrupted) {
            // rtp_player.c:628

            jitter_drop_timestamps_.append(stop_rel_time_);
            RTP_STREAM_DEBUG("Packet drop by jitter buffer exceeded %f > %d", diff*1000, jitter_buffer_size_);

            /* if there was a silence period (more than two packetization period) resync the source */
            if ((rtp_time - rtp_time_prev) > pack_period*2) {
                qint64 silence_samples;
                RTP_STREAM_DEBUG("Resync...");

                silence_samples = (qint64)((arrive_time - arrive_time_prev)*sample_rate - decoded_bytes_prev / sample_bytes_);
                /* Fix for bug 4119/5902: don't insert too many silence frames.
                 * XXX - is there a better thing to do here?
                 */
                silence_samples = qMin(silence_samples, max_silence_samples_);
                writeSilence(silence_samples);
                silence_timestamps_.append(stop_rel_time_);

                decoded_bytes_prev = 0;
/* defined start_timestamp to avoid overflow in timestamp. TODO: handle the timestamp correctly */
/* XXX: if timestamps (RTP) are missing/ignored try use packet arrive time only (see also "rtp_time") */
                start_timestamp = rtp_packet->info->info_timestamp;
                start_rtp_time = 0;
                start_time = rtp_packet->arrive_offset;
                rtp_time_prev = 0;
            }

        } else {
            // rtp_player.c:664
            /* Add silence if it is necessary */
            qint64 silence_samples;

            if (timing_mode_ == Uninterrupted) {
                silence_samples = 0;
            } else {
                silence_samples = (int)((rtp_time - rtp_time_prev)*sample_rate - decoded_bytes_prev / sample_bytes_);
            }

            if (silence_samples != 0) {
                wrong_timestamp_timestamps_.append(stop_rel_time_);
            }

            if (silence_samples > 0) {
                /* Fix for bug 4119/5902: don't insert too many silence frames.
                 * XXX - is there a better thing to do here?
                 */
                silence_samples = qMin(silence_samples, max_silence_samples_);
                writeSilence(silence_samples);
                silence_timestamps_.append(stop_rel_time_);
            }

            // XXX rtp_player.c:696 adds audio here.

            rtp_time_prev = rtp_time;
            pack_period = (double) decoded_bytes / sample_bytes_ / sample_rate;
            decoded_bytes_prev = decoded_bytes;
            arrive_time_prev = arrive_time;
        }

        // Write samples to our file.
        write_buff = (char *) decode_buff;
        write_bytes = decoded_bytes;

        if (audio_out_rate_ != sample_rate) {
            // Resample the audio to match our previous output rate.
            if (!audio_resampler_) {
                audio_resampler_ = speex_resampler_init(1, sample_rate, audio_out_rate_, 10, NULL);
                speex_resampler_skip_zeros(audio_resampler_);
                RTP_STREAM_DEBUG("Started resampling from %u to (out) %u Hz.", sample_rate, audio_out_rate_);
            } else {
                spx_uint32_t audio_out_rate;
                speex_resampler_get_rate(audio_resampler_, &cur_in_rate, &audio_out_rate);

                // Adjust rates if needed.
                if (sample_rate != cur_in_rate) {
                    speex_resampler_set_rate(audio_resampler_, sample_rate, audio_out_rate);
                    speex_resampler_set_rate(visual_resampler_, sample_rate, visual_out_rate);
                    RTP_STREAM_DEBUG("Changed input rate from %u to %u Hz. Out is %u.", cur_in_rate, sample_rate, audio_out_rate_);
                }
            }
            spx_uint32_t in_len = (spx_uint32_t)rtp_packet->info->info_payload_len;
            spx_uint32_t out_len = (audio_out_rate_ * (spx_uint32_t)rtp_packet->info->info_payload_len / sample_rate) + (audio_out_rate_ % sample_rate != 0);
            if (out_len * sample_bytes_ > resample_buff_len) {
                while ((out_len * sample_bytes_ > resample_buff_len))
                    resample_buff_len *= 2;
                resample_buff = (SAMPLE *) g_realloc(resample_buff, resample_buff_len);
            }

            speex_resampler_process_int(audio_resampler_, 0, decode_buff, &in_len, resample_buff, &out_len);
            write_buff = (char *) resample_buff;
            write_bytes = out_len * sample_bytes_;
        }

        // Write the decoded, possibly-resampled audio to our temp file.
        gint64 silence = 0;
        if (audio_stereo_) {
            // Process audio mute/left/right settings
            for(qint64 i=0; i<write_bytes; i+=sample_bytes_) {
                if (audio_left_) {
                    tempfile_->write(write_buff+i, sample_bytes_);
                } else {
                    tempfile_->write((char *)&silence, sample_bytes_);
                }
                if (audio_right_) {
                    tempfile_->write(write_buff+i, sample_bytes_);
                } else {
                    tempfile_->write((char *)&silence, sample_bytes_);
                }
            }
        } else {
            // Process audio mute/unmute settings
            if (audio_left_) {
                tempfile_->write(write_buff, write_bytes);
            } else {
                writeSilence(write_bytes / sample_bytes_);
            }
        }

        // Collect our visual samples.
        spx_uint32_t in_len = (spx_uint32_t)rtp_packet->info->info_payload_len;
        spx_uint32_t out_len = (visual_out_rate * in_len / sample_rate) + (visual_out_rate % sample_rate != 0);
        if (out_len * sample_bytes_ > resample_buff_len) {
            while ((out_len * sample_bytes_ > resample_buff_len))
                resample_buff_len *= 2;
            resample_buff = (SAMPLE *) g_realloc(resample_buff, resample_buff_len);
        }

        speex_resampler_process_int(visual_resampler_, 0, decode_buff, &in_len, resample_buff, &out_len);
        for (unsigned i = 0; i < out_len; i++) {
            packet_timestamps_[stop_rel_time_ + (double) i / visual_out_rate] = rtp_packet->frame_num;
            if (qAbs(resample_buff[i]) > max_sample_val_) max_sample_val_ = qAbs(resample_buff[i]);
            visual_samples_.append(resample_buff[i]);
        }

        // Finally, write the resampled audio to our temp file and clean up.
        g_free(decode_buff);
    }
    g_free(resample_buff);
}

const QStringList RtpAudioStream::payloadNames() const
{
    QStringList payload_names = payload_names_.values();
    payload_names.sort();
    return payload_names;
}

const QVector<double> RtpAudioStream::visualTimestamps(bool relative)
{
    QVector<double> ts_keys = packet_timestamps_.keys().toVector();
    if (relative) return ts_keys;

    QVector<double> adj_timestamps;
    for (int i = 0; i < ts_keys.size(); i++) {
        adj_timestamps.append(ts_keys[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

// Scale the height of the waveform (max_sample_val_) and adjust its Y
// offset so that they overlap slightly (stack_offset_).

// XXX This means that waveforms can be misleading with respect to relative
// amplitude. We might want to add a "global" max_sample_val_.
static const double stack_offset_ = G_MAXINT16 / 3;
const QVector<double> RtpAudioStream::visualSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_;
    for (int i = 0; i < visual_samples_.size(); i++) {
        adj_samples.append(((double)visual_samples_[i] * G_MAXINT16 / max_sample_val_) + scaled_offset);
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::outOfSequenceTimestamps(bool relative)
{
    if (relative) return out_of_seq_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < out_of_seq_timestamps_.size(); i++) {
        adj_timestamps.append(out_of_seq_timestamps_[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::outOfSequenceSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_;  // XXX Should be different for seq, jitter, wrong & silence
    for (int i = 0; i < out_of_seq_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::jitterDroppedTimestamps(bool relative)
{
    if (relative) return jitter_drop_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < jitter_drop_timestamps_.size(); i++) {
        adj_timestamps.append(jitter_drop_timestamps_[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::jitterDroppedSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_; // XXX Should be different for seq, jitter, wrong & silence
    for (int i = 0; i < jitter_drop_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::wrongTimestampTimestamps(bool relative)
{
    if (relative) return wrong_timestamp_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < wrong_timestamp_timestamps_.size(); i++) {
        adj_timestamps.append(wrong_timestamp_timestamps_[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::wrongTimestampSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_; // XXX Should be different for seq, jitter, wrong & silence
    for (int i = 0; i < wrong_timestamp_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::insertedSilenceTimestamps(bool relative)
{
    if (relative) return silence_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < silence_timestamps_.size(); i++) {
        adj_timestamps.append(silence_timestamps_[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::insertedSilenceSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_;  // XXX Should be different for seq, jitter, wrong & silence
    for (int i = 0; i < silence_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

quint32 RtpAudioStream::nearestPacket(double timestamp, bool is_relative)
{
    if (packet_timestamps_.keys().count() < 1) return 0;

    if (!is_relative) timestamp -= start_abs_offset_;
    QMap<double, quint32>::const_iterator it = packet_timestamps_.lowerBound(timestamp);
    if (it == packet_timestamps_.end()) return 0;
    return it.value();
}

QAudio::State RtpAudioStream::outputState() const
{
    if (!audio_output_) return QAudio::IdleState;
    return audio_output_->state();
}

const QString RtpAudioStream::formatDescription(const QAudioFormat &format)
{
    QString fmt_descr = QString("%1 Hz, ").arg(format.sampleRate());
    switch (format.sampleType()) {
    case QAudioFormat::SignedInt:
        fmt_descr += "Int";
        break;
    case QAudioFormat::UnSignedInt:
        fmt_descr += "UInt";
        break;
    case QAudioFormat::Float:
        fmt_descr += "Float";
        break;
    default:
        fmt_descr += "Unknown";
        break;
    }
    fmt_descr += QString::number(format.sampleSize());
    fmt_descr += format.byteOrder() == QAudioFormat::BigEndian ? "BE" : "LE";

    return fmt_descr;
}

void RtpAudioStream::startPlaying()
{
    qint64 start_pos;

    if (audio_output_) return;

    if (audio_out_rate_ == 0) {
        emit playbackError(tr("RTP stream is empty or codec is unsupported."));
        return;
    }

    QAudioDeviceInfo cur_out_device = QAudioDeviceInfo::defaultOutputDevice();
    QString cur_out_name = parent()->property("currentOutputDeviceName").toString();
    foreach (QAudioDeviceInfo out_device, QAudioDeviceInfo::availableDevices(QAudio::AudioOutput)) {
        if (cur_out_name == out_device.deviceName()) {
            cur_out_device = out_device;
        }
    }

    QAudioFormat format;
    format.setSampleRate(audio_out_rate_);
    format.setSampleSize(sample_bytes_ * 8); // bits
    format.setSampleType(QAudioFormat::SignedInt);
    if (audio_stereo_) {
        format.setChannelCount(2);
    } else {
        format.setChannelCount(1);
    }
    format.setCodec("audio/pcm");

    // RTP_STREAM_DEBUG("playing %s %d samples @ %u Hz",
    //                 tempfile_->fileName().toUtf8().constData(),
    //                 (int) tempfile_->size(), audio_out_rate_);

    if (!cur_out_device.isFormatSupported(format)) {
        QString playback_error = tr("%1 does not support PCM at %2. Preferred format is %3")
                .arg(cur_out_device.deviceName())
                .arg(formatDescription(format))
                .arg(formatDescription(cur_out_device.nearestFormat(format)));
        emit playbackError(playback_error);
    }

    audio_output_ = new QAudioOutput(cur_out_device, format, this);
    audio_output_->setNotifyInterval(65); // ~15 fps
    connect(audio_output_, SIGNAL(stateChanged(QAudio::State)), this, SLOT(outputStateChanged(QAudio::State)));
    connect(audio_output_, SIGNAL(notify()), this, SLOT(outputNotify()));
    start_pos = (qint64)(start_play_time_ * sample_bytes_ * audio_out_rate_);
    // Round to sample_bytes_ boundary
    start_pos = (start_pos / sample_bytes_) * sample_bytes_;
    if (audio_stereo_) {
        // There is 2x more samples for stereo
        start_pos *= 2;
    }
    if (start_pos < tempfile_->size()) {
        tempfile_->seek(start_pos);
        audio_output_->start(tempfile_);
        emit startedPlaying();
        // QTBUG-6548 StoppedState is not always emitted on error, force a cleanup
        // in case playback fails immediately.
        if (audio_output_ && audio_output_->state() == QAudio::StoppedState) {
            outputStateChanged(QAudio::StoppedState);
        }
    } else {
        // Report stopped audio if start position is later than stream ends
        outputStateChanged(QAudio::StoppedState);
    }
}

void RtpAudioStream::stopPlaying()
{
    if (audio_output_) {
        audio_output_->stop();
    }
}

void RtpAudioStream::writeSilence(qint64 samples)
{
    if (samples < 1 || audio_out_rate_ == 0) return;

    qint64 silence_bytes = samples * sample_bytes_;
    char *silence_buff = (char *) g_malloc0(silence_bytes);

    RTP_STREAM_DEBUG("Writing %llu silence samples", samples);
    if (audio_stereo_) {
        // Silence for left and right channel
        tempfile_->write(silence_buff, silence_bytes);
        tempfile_->write(silence_buff, silence_bytes);
    } else {
        tempfile_->write(silence_buff, silence_bytes);
    }
    g_free(silence_buff);

    // Silence is inserted to audio file only.
    // If inserted to visual_samples_ too, it shifts whole waveset
    //QVector<qint16> visual_fill(samples * visual_sample_rate_ / audio_out_rate_, 0);
    //visual_samples_ += visual_fill;
}

void RtpAudioStream::outputStateChanged(QAudio::State new_state)
{
    if (!audio_output_) return;

    // On some platforms including macOS and Windows, the stateChanged signal
    // is emitted while a QMutexLocker is active. As a result we shouldn't
    // delete audio_output_ here.
    switch (new_state) {
    case QAudio::StoppedState:
        // RTP_STREAM_DEBUG("stopped %f", audio_output_->processedUSecs() / 100000.0);
        // Detach from parent (RtpAudioStream) to prevent deleteLater from being
        // run during destruction of this class.
        audio_output_->setParent(0);
        audio_output_->disconnect();
        audio_output_->deleteLater();
        audio_output_ = NULL;
        emit finishedPlaying();
        break;
    case QAudio::IdleState:
        audio_output_->stop();
        break;
    default:
        break;
    }
}

void RtpAudioStream::outputNotify()
{
    emit processedSecs((audio_output_->processedUSecs() / 1000000.0) + start_play_time_);
}

#endif // QT_MULTIMEDIA_LIB

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
