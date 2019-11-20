#include "rtmp.h"
#include "debug.h"
#include "../rtp.h"
#include <libavutil/error.h>
#include <assert.h>

void rtmp_module_init() {
    // ffmpeg
    avcodec_register_all();
    avformat_network_init();
    // hashtable
    context_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)context_destroy);
    if (!context_table) {
        assert(context_table != NULL);
    }
    JANUS_LOG(LOG_INFO, "rtmp module init success\n");
    return;
}

int rtmp_stream_open(char* room_id, char* url, Video_Param* vp, Audio_Param* ap) {
    JANUS_LOG(LOG_INFO, "rtmp open, roomid[%s], url[%s]\n", room_id, url);
    janus_mutex_lock(&context_mutex);  
    Stream_Context* ctx = context_create(vp, ap, url);
    if (!ctx) {
        JANUS_LOG(LOG_ERR, "stream_context create fail\n");
        janus_mutex_unlock(&context_mutex);
        return -1;
    }
    // 插入hashtable
    ctx->init_flag = TRUE;
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
    // 判断ctx是否有效
    if (!ctx->init_flag) {
        JANUS_LOG(LOG_WARN, "room[%s] wait for context init\n", room_id);
        janus_mutex_unlock(&context_mutex);
        return -1;
    }

    if (av == Media_Video) {
        int rv = 0;
        janus_rtp_header *rtp_header = (janus_rtp_header *)buf;
        // rtp解包
        if (!ctx->ff_rtp_demux_ctx) {
            ctx->ff_rtp_demux_ctx = ff_rtp_parse_open(ctx->ff_ofmt_ctx, ctx->ff_stream, rtp_header->type, 5 * 1024 * 1024);
            if (!ctx->ff_rtp_demux_ctx) {
                JANUS_LOG(LOG_ERR, "ctx[%p] video ff_rtp_parse_open fail\n", ctx);
                janus_mutex_unlock(&context_mutex);
                return -1;
            }
            RTPDynamicProtocolHandler* dpHandler = ff_rtp_handler_find_by_name("H264", AVMEDIA_TYPE_VIDEO);
            if (!dpHandler) {
                JANUS_LOG(LOG_ERR, "ctx[%p] ff_rtp_handler_find_by_id h264 fail\n", ctx);
                janus_mutex_unlock(&context_mutex);
                return -1;
            }
            ff_rtp_parse_set_dynamic_protocol(ctx->ff_rtp_demux_ctx, NULL, dpHandler);
            JANUS_LOG(LOG_INFO, "room[%s] video rtp parse prepared\n", room_id);
        }
        do {
            // 解rtp包
            AVPacket pkt;
            av_init_packet(&pkt);
            rv = ff_rtp_parse_packet(ctx->ff_rtp_demux_ctx, &pkt, rv == 1 ? NULL : &buf, len);
            if (rv == -1 || pkt.size == 0) {
                JANUS_LOG(LOG_ERR, "room[%s] rtp parse fail\n", room_id);
                av_packet_unref(&pkt);
                break;
            }
            // 找到nalu头
            if (pkt.data[0] == 0x00 && pkt.data[1] == 0x00 && ((pkt.data[2] == 0x00 && pkt.data[3] == 0x01) || pkt.data[2] == 0x01)) {
                if (ctx->avdata.v_buf && ctx->rtmp) {
                    // 使用srslibrtmp推流，不考虑b帧情况
                    int ret = srs_h264_write_raw_frames(ctx->rtmp, ctx->avdata.v_buf, ctx->avdata.v_len, ctx->avdata.v_pts, ctx->avdata.v_pts);
                    if (ret != 0) {
                        JANUS_LOG(LOG_ERR, "h264 frame push to rtmp server fail: %d\n", ret);
                        JANUS_LOG(LOG_INFO, "raw frames, size=%d, pts=%lld, dts=%lld\n", ctx->avdata.v_len, ctx->avdata.v_pts, ctx->avdata.v_pts);
                    }
                    // 无论发送成功失败都要释放缓存
                    free(ctx->avdata.v_buf);
                    ctx->avdata.v_buf = NULL;
                    ctx->avdata.v_len = 0;
                    // pts必须放在此处计算
                    ctx->avdata.v_pts = janus_get_monotonic_time() / 1000;
                }
                ctx->avdata.v_buf = malloc(pkt.size);
                memcpy(ctx->avdata.v_buf, pkt.data, pkt.size);
                ctx->avdata.v_len += pkt.size;
            } else {
                if (!ctx->avdata.v_buf) {
                    av_packet_unref(&pkt);
                    break;
                }
                // 组装完整的nal单元
                ctx->avdata.v_buf = realloc(ctx->avdata.v_buf, ctx->avdata.v_len + pkt.size);
                memcpy(ctx->avdata.v_buf + ctx->avdata.v_len, pkt.data, pkt.size);
                ctx->avdata.v_len += pkt.size;
            }
            av_packet_unref(&pkt);
        } while(rv == 1);
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
        int pcmlen = frame_size * 1 * sizeof(opus_int16);
        int ret = opus_decode(ctx->opus_dec, payload, plen, pcmbuf, frame_size, 0);
        if (ret <= 0) {
            JANUS_LOG(LOG_ERR, "room[%s] opus decode fail\n", room_id);
            janus_mutex_unlock(&context_mutex);
            return -1;
        }
        // 缓存音频数据
        memcpy(ctx->avdata.a_buf + ctx->avdata.a_end, pcmbuf, pcmlen);
        ctx->avdata.a_end += pcmlen;
        if (ctx->avdata.a_end - ctx->avdata.a_begin >= ctx->avdata.a_input_samples * 2) {
            // aac编码
            uint8_t* aacbuf = malloc(ctx->avdata.a_max_output_bytes);
            if (!aacbuf) {
                JANUS_LOG(LOG_ERR, "room[%s] aacbuf malloc fail\n", room_id);
                janus_mutex_unlock(&context_mutex);
                return -1;
            }
            uint aaclen = faacEncEncode(ctx->aac_enc, (int32_t*)ctx->avdata.a_buf, ctx->avdata.a_input_samples, aacbuf, ctx->avdata.a_max_output_bytes);
            ctx->avdata.a_begin += ctx->avdata.a_input_samples * 2;
            // 数据移位
            memcpy(ctx->avdata.a_buf, ctx->avdata.a_buf + ctx->avdata.a_begin, ctx->avdata.a_end - ctx->avdata.a_begin);
            ctx->avdata.a_begin = 0;
            ctx->avdata.a_end -= ctx->avdata.a_input_samples * 2;
            // rtmp推送
            if (aaclen > 0 && ctx->rtmp) {
                // 10[AAC] 3[44khz] 1[16bit] 0[Mono]
                ret = srs_audio_write_raw_frame(ctx->rtmp, 10, 3, 1, 0, aacbuf, aaclen, janus_get_monotonic_time() / 1000);
                if (ret != 0) {
                    JANUS_LOG(LOG_ERR, "rtmp send audio frame fail:%d\n", ret);
                    free(aacbuf);
                    aacbuf = NULL;
                    janus_mutex_unlock(&context_mutex);
                    return -1;
                }
            }
            free(aacbuf);
            aacbuf = NULL; 
        }
    }
    janus_mutex_unlock(&context_mutex);
    return 0;
}

Stream_Context* context_create(Video_Param* vp, Audio_Param* ap, char* url) {
    Stream_Context* ctx = (Stream_Context*)malloc(sizeof(Stream_Context));
    memset(ctx, 0, sizeof(Stream_Context));
    int ret = 0;
    JANUS_LOG(LOG_INFO, "context create ctx=%p\n", ctx);
    do {
        // 参数赋值
        ctx->ap.channels = ap->channels;
        ctx->ap.input_format = ap->input_format;
        ctx->ap.sample_rate = ap->sample_rate;
        // ffmpeg
        ret = ffmpeg_decoder_create(ctx, vp);
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
    ffmpeg_decoder_destroy(ctx);
    opus_decoder_destroy(ctx);
    faac_encoder_destroy_(ctx);
    srs_rtmp_destroy_(ctx);
    JANUS_LOG(LOG_INFO, "##@@ context create fail, release sources\n");
    free(ctx);
    ctx = NULL;
    return NULL;
}

void context_destroy(Stream_Context* ctx) {
	JANUS_LOG(LOG_INFO, "context destroy ctx=%p\n", ctx);
	if (!ctx) {
        return;
    }
    // 释放编解码器
    ffmpeg_decoder_destroy(ctx);
    opus_decoder_destroy(ctx);
    faac_encoder_destroy_(ctx);
    srs_rtmp_destroy_(ctx);
    // 释放视频缓存
    if (ctx->avdata.v_buf) {
        JANUS_LOG(LOG_INFO, "free ctx[%p] avdata.v_buf=%p\n", ctx, ctx->avdata.v_buf);
        free(ctx->avdata.v_buf);
        ctx->avdata.v_buf = NULL;
    }
    // 释放音频缓存
    if (ctx->avdata.a_buf) {
        JANUS_LOG(LOG_INFO, "free ctx[%p] avdata.a_buf=%p\n", ctx, ctx->avdata.a_buf);
        free(ctx->avdata.a_buf);
        ctx->avdata.a_buf = NULL;
    }
    // 释放param资源
    JANUS_LOG(LOG_INFO, "##@@ free ctx=%p\n", ctx);
    free(ctx);
    JANUS_LOG(LOG_INFO, "##@@ after free ctx\n");
    return;
}

int ffmpeg_decoder_create(Stream_Context* ctx, Video_Param* vp) {
    // ffmpeg ctx
    int ret = avformat_alloc_output_context2(&ctx->ff_ofmt_ctx, NULL, "flv", "");
    if (ret < 0) {
        JANUS_LOG(LOG_ERR, "avformat alloc output context2 fail, err:%s\n", av_err2str(ret));
        return -1;
    }
    // ffmpeg video
    AVCodec* pCodec = avcodec_find_encoder(AV_CODEC_ID_H264);
    if (!pCodec) {
        JANUS_LOG(LOG_ERR, "avcodec h264 not found\n");
        avformat_free_context(ctx->ff_ofmt_ctx);
        return -1;
    }
    ctx->ff_stream = avformat_new_stream(ctx->ff_ofmt_ctx, pCodec);
    if (!ctx->ff_stream) {
        JANUS_LOG(LOG_ERR, "avformat new stream video fail\n");
        avformat_free_context(ctx->ff_ofmt_ctx);
        return -1;
    }
    ctx->ff_stream->time_base = (AVRational){1, 1000};
    ctx->ff_stream->codec->codec_id = pCodec->id;
    ctx->ff_stream->codec->codec_type = AVMEDIA_TYPE_VIDEO;
    ctx->ff_stream->codec->pix_fmt = AV_PIX_FMT_YUV420P;
    ctx->ff_stream->codec->width = vp->width;
    ctx->ff_stream->codec->height = vp->height;
    ctx->ff_stream->codec->time_base = (AVRational){1, 1000};
    if (ctx->ff_ofmt_ctx->oformat->flags & AVFMT_GLOBALHEADER) {
        ctx->ff_stream->codec->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    }
    if (avcodec_open2(ctx->ff_stream->codec, pCodec, NULL) < 0) {
        JANUS_LOG(LOG_ERR, "avcodec open fail\n");
        avformat_free_context(ctx->ff_ofmt_ctx);
        return -1;
    }
    JANUS_LOG(LOG_INFO, "ffmpeg video avcodec open2 success\n");
    return 0;
}

void ffmpeg_decoder_destroy(Stream_Context* ctx) {
    if (!ctx) {
        return;
    }
    // 释放ffmpeg的rtp解码器
    if (ctx->ff_rtp_demux_ctx) {
        JANUS_LOG(LOG_INFO, "free ctx[%p] ff_rtp_demux_ctx %p\n", ctx, ctx->ff_rtp_demux_ctx);
        ff_rtp_parse_close(ctx->ff_rtp_demux_ctx);
        ctx->ff_rtp_demux_ctx = NULL;
    }
    // 释放ffmpeg的codec上下文
    if (ctx->ff_stream && ctx->ff_stream->codec) {
        JANUS_LOG(LOG_INFO, "free ctx[%p] codec %p\n", ctx, ctx->ff_stream->codec);
        avcodec_close(ctx->ff_stream->codec);
        ctx->ff_stream->codec = NULL;
    }
    // 释放ffmpeg解码器上下文
    if (ctx->ff_ofmt_ctx) {
        JANUS_LOG(LOG_INFO, "free ctx[%p] ff_ofmt_ctx %p\n", ctx, ctx->ff_ofmt_ctx);
        avformat_free_context(ctx->ff_ofmt_ctx);
        ctx->ff_ofmt_ctx = NULL;
    }
    return;
}

int opus_decoder_create_(Stream_Context* ctx, Audio_Param* ap) {
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
    if (ctx->opus_dec) {
        JANUS_LOG(LOG_INFO, "free ctx[%p] opus_dec %p\n", ctx, ctx->opus_dec);
        opus_decoder_destroy(ctx->opus_dec);
        ctx->opus_dec = NULL;
    }
    return;
}

int faac_encoder_create_(Stream_Context* ctx, Audio_Param* ap) {
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
    ctx->avdata.a_buf = malloc(ctx->avdata.a_input_samples * 2 * 2);
    ctx->avdata.a_begin = 0;
    ctx->avdata.a_end = 0;
    return 0;
}

void faac_encoder_destroy_(Stream_Context* ctx) {
    if (ctx->aac_enc) {
        JANUS_LOG(LOG_INFO, "free ctx[%p] aac_enc %p\n", ctx, ctx->aac_enc);
        faacEncClose(ctx->aac_enc);
        ctx->aac_enc = NULL;
    }
    return;
}

int srs_rtmp_create_(Stream_Context* ctx, char* url) {
    ctx->rtmp = srs_rtmp_create(url);
    if (!ctx->rtmp) {
        JANUS_LOG(LOG_ERR, "srs rtmp create fail\n");
        return -1;
    }
    int ret = srs_rtmp_handshake(ctx->rtmp);
    if (0 != ret) {
        JANUS_LOG(LOG_ERR, "srs librtmp handshake fail, err:%d\n", ret);
        srs_rtmp_destroy_(ctx->rtmp);
        return -1;
    }
    ret = srs_rtmp_connect_app(ctx->rtmp);
    if (0 != ret) {
        JANUS_LOG(LOG_ERR, "srs rtmp connect app fail, err:%d\n", ret);
        srs_rtmp_destroy_(ctx->rtmp);
        return -1;
    }
    ret = srs_rtmp_publish_stream(ctx->rtmp);
    if (0 != ret) {
        JANUS_LOG(LOG_ERR, "srs rtmp publish stream fail, err:%d\n", ret);
        srs_rtmp_destroy_(ctx->rtmp);
        return -1;
    }
    JANUS_LOG(LOG_INFO, "librtmp publish success\n");
    return 0;
}

void srs_rtmp_destroy_(Stream_Context* ctx) {
    if (ctx->rtmp) {
        JANUS_LOG(LOG_INFO, "free ctx[%p] rtmp %p\n", ctx, ctx->rtmp);
        srs_rtmp_destroy(ctx->rtmp);
        ctx->rtmp = NULL;
    }
    return;
}