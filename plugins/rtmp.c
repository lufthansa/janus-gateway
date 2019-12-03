#include "rtmp.h"
#include "debug.h"
#include "../rtp.h"
// #include <libavutil/error.h>
#include <assert.h>

void print_malloc(char* dest, char* log)
{
    unsigned long* a;
    a = (char*)dest - sizeof(long)*4;
    printf("print_malloc 44444 %s is 0x%lx\n",log ,*a);
    a = (char*)dest - sizeof(long)*3;
    printf("print_malloc 33333 %s is 0x%lx\n",log, *a);
    a = (char*)dest - sizeof(long)*2;
    printf("print_malloc 22222 %s is 0x%lx\n",log, *a);
    a = (char*)dest - sizeof(long)*1;
    printf("print_malloc 11111 %s is 0x%lx\n",log, *a);
}

void rtmp_module_init() {
    // hashtable
    context_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)context_destroy);
    if (!context_table) {
        assert(context_table != NULL);
    }
    JANUS_LOG(LOG_INFO, "rtmp module init success\n");
    return;
}

int rtmp_stream_open(char* room_id, char* url, Audio_Param* ap) {
    JANUS_LOG(LOG_INFO, "rtmp open, roomid[%s], url[%s]\n", room_id, url);
    janus_mutex_lock(&context_mutex);  
    Stream_Context* ctx = context_create(ap, url);
    if (!ctx) {
        JANUS_LOG(LOG_ERR, "stream_context create fail\n");
        janus_mutex_unlock(&context_mutex);
        return -1;
    }
    // 插入hashtable
    g_hash_table_insert(context_table, g_strdup(room_id), ctx);
    JANUS_LOG(LOG_INFO, "insert stream_context:[%s:%p]\n", room_id, ctx);
    janus_mutex_unlock(&context_mutex);
    return 0;
}

void rtmp_stream_close(char* room_id) {
    JANUS_LOG(LOG_INFO, "room[%s] stream push over, release resources\n", room_id);
    janus_mutex_lock(&context_mutex);
    if (!g_hash_table_contains(context_table, room_id)) {
        JANUS_LOG(LOG_WARN, "room_id[%s] not exist, stream close error\n", room_id);
        janus_mutex_unlock(&context_mutex);
        return;
    }
    // 从hashtable中删除
    g_hash_table_remove(context_table, room_id);
    janus_mutex_unlock(&context_mutex);
    return;
}

int rtmp_stream_push(char* room_id, char* buf, int len, Media_Type av) {
    // 找到对应的ctx
    janus_mutex_lock(&context_mutex);
    Stream_Context* ctx = g_hash_table_lookup(context_table, room_id);
    if (!ctx) {
        JANUS_LOG(LOG_WARN, "room_id[%s] not exist, stream push error, tablesize=%d\n", room_id, g_hash_table_size(context_table));
        janus_mutex_unlock(&context_mutex);
        return -1;
    }
    janus_rtp_header *rtp_header = (janus_rtp_header *)buf;
    if (av == Media_Video) {
        if (!ctx->rtp_ctx) {
            ctx->rtp_ctx = rtp_parse_open(rtp_header->type, 5 * 1024 * 1024);
            if (!ctx->rtp_ctx) {
                JANUS_LOG(LOG_ERR, "rtp parse open fail\n");
                return -1;
            }
        }
        // 解rtp包
        int rv = 0;
        do {
            Packet* pkt = create_packet();
            rv = rtp_parse_packet(ctx->rtp_ctx, pkt, rv == 1 ? NULL : &buf, len);
            if (rv < 0) {
                JANUS_LOG(LOG_ERR, "room[%s] rtp parse fail\n", room_id);
                release_packet(&pkt);
                break;
            }
            // 找到nalu头
            if (pkt->buf[0] == 0x00 && pkt->buf[1] == 0x00 && pkt->buf[2] == 0x00 && pkt->buf[3] == 0x01) {
                if (ctx->avdata.v_buf && ctx->rtmp) {
                    // 使用srslibrtmp推流，不考虑b帧情况
                    // JANUS_LOG(LOG_INFO, "h264 type = %d\n", pkt->buf[5] & 0x1f);
                    int ret = srs_h264_write_raw_frames(ctx->rtmp, ctx->avdata.v_buf, ctx->avdata.v_len, ctx->avdata.v_pts, ctx->avdata.v_pts);
                    if (ret != 0) {
                        JANUS_LOG(LOG_ERR, "h264 frame push to rtmp server fail: %d\n", ret);
                        JANUS_LOG(LOG_INFO, "raw frames, size=%d, pts=%lld, dts=%lld\n", ctx->avdata.v_len, ctx->avdata.v_pts, ctx->avdata.v_pts);
                    }
                    // 无论发送成功失败都要释放缓存
                    g_free(ctx->avdata.v_buf);
                    ctx->avdata.v_buf = NULL;
                    ctx->avdata.v_len = 0;
                }
                ctx->avdata.v_buf = g_malloc0(pkt->size);
                memcpy(ctx->avdata.v_buf, pkt->buf, pkt->size);
                ctx->avdata.v_len += pkt->size;
                ctx->avdata.v_pts = ntohl(rtp_header->timestamp) / 90;
            } else {
                if (!ctx->avdata.v_buf) {
                    release_packet(&pkt);
                    break;
                }
                // 组装完整的nal单元
                ctx->avdata.v_buf = g_realloc(ctx->avdata.v_buf, ctx->avdata.v_len + pkt->size);
                memcpy(ctx->avdata.v_buf + ctx->avdata.v_len, pkt->buf, pkt->size);
                ctx->avdata.v_len += pkt->size;
            }
            release_packet(&pkt);
        } while(rv == 1);

        // JANUS_LOG(LOG_INFO, "rtp h264 seq=%u, pts_raw=%lu, pts_calc=%lu ms\n", 
        //     ntohs(rtp_header->seq_number), ntohl(rtp_header->timestamp), ntohl(rtp_header->timestamp) / 90);
    } else if (av == Media_Audio) {
        // 找到rtp的payload
        int plen = 0;
        char *payload = janus_rtp_payload(buf, len, &plen);
        if(!payload) {
            janus_mutex_unlock(&context_mutex);
            return -1;
        }
        // 解码
        int frame_size = ctx->ap.sample_rate / 50 * ctx->ap.channels;
        opus_uint16 pcmbuf[1024 * 1024] = {0};
        int pcmlen = frame_size * 1 * sizeof(opus_int16);   // 字节长度
        int ret = opus_decode(ctx->opus_dec, payload, plen, pcmbuf, frame_size, 0);
        if (ret <= 0) {
            JANUS_LOG(LOG_ERR, "room[%s] opus decode fail\n", room_id);
            janus_mutex_unlock(&context_mutex);
            return -1;
        }
        // 重采样
        int pcm_samples = pcmlen / 2;   // 16bit为一个sample
        float* fpcmbuf = g_malloc0(sizeof(float) * pcm_samples);   // 类型转换，长度不变
        src_short_to_float_array(pcmbuf, fpcmbuf, pcm_samples);
        float* fpcm44buf = g_malloc0(sizeof(float) * pcm_samples);
        SRC_DATA data = {
            .data_in = fpcmbuf,
            .input_frames = pcm_samples,
            .data_out = fpcm44buf,
            .output_frames = pcm_samples,
            .src_ratio = ctx->sample_ratio
        };
        ret = src_process(ctx->sample_handle, &data);
        if (0 != ret || 0 == data.output_frames_gen) {
            JANUS_LOG(LOG_ERR, "audio resample from %d to 44100 fail\n", ctx->ap.sample_rate);
            g_free(fpcmbuf), fpcmbuf = NULL;
            g_free(fpcm44buf), fpcm44buf = NULL;
            janus_mutex_unlock(&context_mutex);
            return -1;
        }
        // JANUS_LOG(LOG_INFO, "resample pcm_samples=%d, used=%d, gen=%d\n", pcm_samples, data.input_frames_used, data.output_frames_gen);
        uint16_t* pcm44buf = g_malloc0(sizeof(uint16_t) * data.output_frames_gen);
        src_float_to_short_array(fpcm44buf, pcm44buf, data.output_frames_gen);
        // 缓存音频数据
        memcpy(ctx->avdata.a_buf + ctx->avdata.a_end, pcm44buf, data.output_frames_gen * 2);
        ctx->avdata.a_end += data.output_frames_gen * 2;
        // 释放重采样数据
        g_free(fpcmbuf), fpcmbuf = NULL;
        g_free(fpcm44buf), fpcm44buf = NULL;
        g_free(pcm44buf), pcm44buf = NULL;
        // 累积足够的pcm再进行aac编码
        if (ctx->avdata.a_end - ctx->avdata.a_begin >= ctx->avdata.a_input_samples * 2) {
            // aac编码
            uint8_t* aacbuf = g_malloc0(ctx->avdata.a_max_output_bytes);
            if (!aacbuf) {
                JANUS_LOG(LOG_ERR, "room[%s] aacbuf g_malloc0 fail\n", room_id);
                janus_mutex_unlock(&context_mutex);
                return -1;
            }
            uint aaclen = faacEncEncode(ctx->aac_enc, (int32_t*)ctx->avdata.a_buf, ctx->avdata.a_input_samples, aacbuf, ctx->avdata.a_max_output_bytes);
            // rtmp推送
            if (aaclen > 0 && ctx->rtmp) {
                // 10[format AAC] 3[rate 44khz] 1[size 16bit] 0[type Mono]
                ret = srs_audio_write_raw_frame(ctx->rtmp, 10, 3, 1, 0, aacbuf, aaclen, ctx->avdata.a_pts);
                if (ret != 0) {
                    JANUS_LOG(LOG_ERR, "rtmp send audio frame fail:%d\n", ret);
                    g_free(aacbuf), aacbuf = NULL;
                    janus_mutex_unlock(&context_mutex);
                    return -1;
                }
            }
            g_free(aacbuf), aacbuf = NULL; 
            // 数据移位
            ctx->avdata.a_begin += ctx->avdata.a_input_samples * 2;
            memcpy(ctx->avdata.a_buf, ctx->avdata.a_buf + ctx->avdata.a_begin, ctx->avdata.a_end - ctx->avdata.a_begin);
            ctx->avdata.a_begin = 0;
            ctx->avdata.a_end -= ctx->avdata.a_input_samples * 2;
            ctx->avdata.a_pts = ntohl(rtp_header->timestamp) / (ctx->ap.sample_rate / 1000);
        }
    }
    janus_mutex_unlock(&context_mutex);
    return 0;
}

Stream_Context* context_create(Audio_Param* ap, char* url) {
    int ret = 0;
    if (!ap || !url) {
        JANUS_LOG(LOG_ERR, "stream context create input error\n");
        return -1;
    }
    Stream_Context* ctx = g_malloc0(sizeof(Stream_Context));
    if (!ctx) {
        JANUS_LOG(LOG_ERR, "Stream_Context malloc fail\n");
        return NULL;
    }
    JANUS_LOG(LOG_INFO, "context create ctx=%p\n", ctx);
    do {
        // 参数赋值
        ctx->ap.channels = ap->channels;
        ctx->ap.input_format = ap->input_format;
        ctx->ap.sample_rate = ap->sample_rate;
        // rtp
        ret = rtp_decoder_create_(ctx);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "ffmpeg decoder create fail, err=%d\n", ret);
            break;
        }
        // opus
        ret = opus_decoder_create_(ctx, ap);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "opus decoder create fail, err=%d\n", ret);
            break;
        }
        // resample
        ret = resample_create_(ctx, ap);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "resample create fail, err=%d\n", ret);
            break;
        }
        // faac
        ret = faac_encoder_create_(ctx, ap);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "faac encoder create fail, err=%d\n", ret);
            break;
        }
        // srs-librtmp
        ret = srs_rtmp_create_(ctx, url);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "srs-librtmp create fail, err=%d\n", ret);
            break;
        }
        return ctx;
    } while(0);
    // 释放资源
    rtp_decoder_destroy_(ctx);
    opus_decoder_destroy_(ctx);
    resample_destroy_(ctx);
    faac_encoder_destroy_(ctx);
    srs_rtmp_destroy_(ctx);
    JANUS_LOG(LOG_INFO, "context create fail, release sources\n");
    g_free(ctx);
    ctx = NULL;
    return NULL;
}

void context_destroy(Stream_Context* ctx) {
	JANUS_LOG(LOG_INFO, "context destroy ctx=%p\n", ctx);
	if (!ctx) {
        return;
    }
    // 释放编解码器
    rtp_decoder_destroy_(ctx);
    opus_decoder_destroy_(ctx);
    resample_destroy_(ctx);
    faac_encoder_destroy_(ctx);
    srs_rtmp_destroy_(ctx);
    // 释放视频缓存
    if (ctx->avdata.v_buf) {
        JANUS_LOG(LOG_INFO, "g_free ctx[%p] avdata.v_buf=%p\n", ctx, ctx->avdata.v_buf);
        g_free(ctx->avdata.v_buf);
        ctx->avdata.v_buf = NULL;
    }
    // 释放音频缓存
    if (ctx->avdata.a_buf) {
        JANUS_LOG(LOG_INFO, "g_free ctx[%p] avdata.a_buf=%p\n", ctx, ctx->avdata.a_buf);
        g_free(ctx->avdata.a_buf);
        ctx->avdata.a_buf = NULL;
    }
    // 释放param资源
    JANUS_LOG(LOG_WARN, "ctx[%p] free\n", ctx);
    g_free(ctx);
    return;
}

int rtp_decoder_create_(Stream_Context* ctx) {
    if (!ctx) {
        JANUS_LOG(LOG_ERR, "rtp decoder create input error\n");
        return -1;
    }
    ctx->rtp_ctx = NULL;
    return 0;
}

void rtp_decoder_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->rtp_ctx) {
        rtp_parse_close(ctx->rtp_ctx);
        ctx->rtp_ctx = NULL;
    }
}

int opus_decoder_create_(Stream_Context* ctx, Audio_Param* ap) {
    if (!ctx || !ap) {
        JANUS_LOG(LOG_ERR, "srs rtmp create input error\n");
        return -1;
    }
    int err = 0;
    ctx->opus_dec = opus_decoder_create(ap->sample_rate, ap->channels, &err);
    if (err != OPUS_OK) {
        JANUS_LOG(LOG_ERR, "opus decoder create fail, err=%d\n", err);
        return -1;
    }
    JANUS_LOG(LOG_INFO, "opus decoder create success %p\n", ctx->opus_dec);
    return 0;
}

void opus_decoder_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->opus_dec) {
        JANUS_LOG(LOG_INFO, "destroy ctx[%p] opus_dec %p\n", ctx, ctx->opus_dec);
        opus_decoder_destroy(ctx->opus_dec);
        ctx->opus_dec = NULL;
    }
    return;
}

int resample_create_(Stream_Context* ctx, Audio_Param* ap) {
    if (!ctx || !ap) {
        JANUS_LOG(LOG_ERR, "resample create input error\n");
        return -1;
    }
    int err = 0;
    ctx->sample_handle = src_new(SRC_LINEAR, ctx->ap.channels, &err);
    if (!ctx->sample_handle || err) {
        JANUS_LOG(LOG_ERR, "src_new fail, err=%d\n", err);
        return -1;
    }
    ctx->sample_ratio = (double)44100 / (double)ctx->ap.sample_rate;
    JANUS_LOG(LOG_INFO, "samplerate create success, handle=%p\n", ctx->sample_handle);
    return 0;
}

void resample_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->sample_handle) {
        src_delete(ctx->sample_handle);
        ctx->sample_handle = NULL;
    }
    return;
}

int faac_encoder_create_(Stream_Context* ctx, Audio_Param* ap) {
    if (!ctx || !ap) {
        JANUS_LOG(LOG_ERR, "faac encoder create input error\n");
        return -1;
    }
    // 打开编码器
    ctx->aac_enc = faacEncOpen(ap->sample_rate, ap->channels, &ctx->avdata.a_input_samples, &ctx->avdata.a_max_output_bytes);
    if (!ctx->aac_enc) {
        JANUS_LOG(LOG_ERR, "faac enc open fail\n");
        return -1;
    }
	// 设置编码配置信息
    faacEncConfigurationPtr pConfiguration = NULL;
	pConfiguration = faacEncGetCurrentConfiguration(ctx->aac_enc);
	pConfiguration->inputFormat = ap->input_format;
	pConfiguration->outputFormat = ADTS_STREAM;
	pConfiguration->aacObjectType = LOW;
	pConfiguration->allowMidside = 0;
	pConfiguration->useLfe = 0;
    pConfiguration->useTns = 1;
    pConfiguration->shortctl = SHORTCTL_NORMAL;
    pConfiguration->quantqual = 100;
	pConfiguration->bitRate = 0;
	pConfiguration->bandWidth = 0;
	// 重置编码器的配置信息
	faacEncSetConfiguration(ctx->aac_enc, pConfiguration);
    JANUS_LOG(LOG_INFO, "faac enc open success, a_input_samples=%lu, a_max_output_bytes=%lu\n", ctx->avdata.a_input_samples, ctx->avdata.a_max_output_bytes);
    // 分配缓存、初始化参数
    ctx->avdata.a_buf = g_malloc0(ctx->avdata.a_input_samples * 2 * 2);
    ctx->avdata.a_begin = 0;
    ctx->avdata.a_end = 0;
    return 0;
}

void faac_encoder_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->aac_enc) {
        JANUS_LOG(LOG_INFO, "destroy ctx[%p] aac_enc %p\n", ctx, ctx->aac_enc);
        faacEncClose(ctx->aac_enc);
        ctx->aac_enc = NULL;
    }
    return;
}

int srs_rtmp_create_(Stream_Context* ctx, char* url) {
    if (!ctx || !url) {
        JANUS_LOG(LOG_ERR, "srs rtmp create input error\n");
        return -1;
    }
    ctx->rtmp = srs_rtmp_create(url);
    if (!ctx->rtmp) {
        JANUS_LOG(LOG_ERR, "srs rtmp create fail\n");
        return -1;
    }
    int ret = srs_rtmp_handshake(ctx->rtmp);
    if (0 != ret) {
        JANUS_LOG(LOG_ERR, "srs librtmp handshake fail, err:%d\n", ret);
        srs_rtmp_destroy(ctx->rtmp);
        ctx->rtmp = NULL;
        return -1;
    }
    ret = srs_rtmp_connect_app(ctx->rtmp);
    if (0 != ret) {
        JANUS_LOG(LOG_ERR, "srs rtmp connect app fail, err:%d\n", ret);
        srs_rtmp_destroy(ctx->rtmp);
        ctx->rtmp = NULL;
        return -1;
    }
    ret = srs_rtmp_publish_stream(ctx->rtmp);
    if (0 != ret) {
        JANUS_LOG(LOG_ERR, "srs rtmp publish stream fail, err:%d\n", ret);
        srs_rtmp_destroy(ctx->rtmp);
        ctx->rtmp = NULL;
        return -1;
    }
    JANUS_LOG(LOG_INFO, "librtmp publish success\n");
    return 0;
}

void srs_rtmp_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->rtmp) {
        JANUS_LOG(LOG_INFO, "destroy ctx[%p] rtmp %p\n", ctx, ctx->rtmp);
        srs_rtmp_destroy(ctx->rtmp);
        ctx->rtmp = NULL;
    }
    return;
}