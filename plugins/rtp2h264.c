#include "rtp2h264.h"
#include <glib.h>
#include "../rtp.h"
#include "../debug.h"

RTPDemuxContext *rtp_parse_open(int payload_type, int queue_size)
{
    RTPDemuxContext* s = g_malloc0(sizeof(RTPDemuxContext));
    if (!s)
        return NULL;
    s->payload_type        = payload_type;
    s->queue_size          = queue_size;

    return s;
}

void rtp_parse_close(RTPDemuxContext *s)
{
    while (s->queue) {
        RTPPacket *next = s->queue->next;
        g_free(s->queue->buf), s->queue->buf = NULL;
        g_free(s->queue), s->queue = NULL;
        s->queue = next;
    }
    s->seq       = 0;
    s->queue_len = 0;
    s->prev_ret  = 0;
    g_free(s);
}

int rtp_parse_packet(RTPDemuxContext *s, Packet *pkt, uint8_t **buf, int len)
{
    int rv = rtp_parse_one_packet(s, pkt, buf, len);
    s->prev_ret = rv;
    while (rv < 0 && has_next_packet(s))
        rv = rtp_parse_queued_packet(s, pkt);
    return rv ? rv : has_next_packet(s);
}

Packet* create_packet(void)
{
    return g_malloc0(sizeof(Packet)); 
}

void release_packet(Packet** pkt)
{
    if (pkt && *pkt) {
        if ((*pkt)->buf) {
            g_free((*pkt)->buf), (*pkt)->buf = NULL, (*pkt)->size = 0;
        }
        g_free(*pkt), *pkt = NULL;
    }
}

int rtp_parse_one_packet(RTPDemuxContext *s, Packet *pkt, uint8_t **bufptr, int len)
{
    uint8_t *buf = bufptr ? *bufptr : NULL;
    int flags = 0;
    int rv = 0;

    if (!buf) {
        /* If parsing of the previous packet actually returned 0 or an error,
         * there's nothing more to be parsed from that packet, but we may have
         * indicated that we can return the next enqueued packet. */
        if (s->prev_ret <= 0)
            return rtp_parse_queued_packet(s, pkt);
        /* return the next packets, if any */
        rv = h264_handle_packet(pkt, NULL, 0, 0, flags);
        return rv;
    }

    if (len < 12) {
        JANUS_LOG(LOG_ERR, "rtp buf lenth[%d] < 12\n", len);
        return -1;
    }

    if ((buf[0] & 0xc0) != (RTP_VERSION << 6)) {
        JANUS_LOG(LOG_ERR, "rtp version error\n");
        return -1;
    }

    if ((s->seq == 0 && !s->queue) || s->queue_size <= 1) {
        /* First packet, or no reordering */
        return rtp_parse_packet_internal(s, pkt, buf, len);
    } else {
        uint16_t seq = (uint16_t)buf[2] << 8 | (uint16_t)buf[3];

        int16_t diff = seq - s->seq;
        if (diff < 0) {
            /* Packet older than the previously emitted one, drop */
            JANUS_LOG(LOG_WARN, "RTP: dropping old packet received too late\n");
            return -1;
        } else if (diff <= 1) {
            /* Correct packet */
            rv = rtp_parse_packet_internal(s, pkt, buf, len);
            return rv;
        } else {
            /* Still missing some packet, enqueue this one. */
            rv = enqueue_packet(s, buf, len);
            if (rv < 0) {
                JANUS_LOG(LOG_ERR, "rtp packet encqueue fail, rv=%d\n", rv);
                return rv;
            }
            *bufptr = NULL;
            /* Return the first enqueued packet if the queue is full,
             * even if we're missing something */
            if (s->queue_len >= s->queue_size) {
                JANUS_LOG(LOG_WARN, "jitter buffer full\n");
                return rtp_parse_queued_packet(s, pkt);
            }
            JANUS_LOG(LOG_ERR, "rtp still mission packet\n");
            return -1;
        }
    }
}

int has_next_packet(RTPDemuxContext *s)
{
    return s->queue && s->queue->seq == (uint16_t) (s->seq + 1);
}

int rtp_parse_queued_packet(RTPDemuxContext *s, Packet *pkt)
{
    int rv;
    RTPPacket *next;

    if (s->queue_len <= 0) {
        JANUS_LOG(LOG_WARN, "rtp queue_len[%d] < 0\n", s->queue_len);
        return -1;
    }

    if (!has_next_packet(s))
        JANUS_LOG(LOG_ERR, "RTP: missed %d packets\n", s->queue->seq - s->seq - 1);

    JANUS_LOG(LOG_WARN, "rtp to parse queue packet\n");
    /* Parse the first packet in the queue, and dequeue it */
    rv  = rtp_parse_packet_internal(s, pkt, s->queue->buf, s->queue->len);
    next = s->queue->next;
    g_free(s->queue->buf), s->queue->buf = NULL;
    g_free(s->queue), s->queue = NULL;
    s->queue = next;
    s->queue_len--;
    return rv;
}

void rtp_init_sequence(RTPStatistics *s, uint16_t seq)
{
    s->max_seq        = seq;
    s->cycles         = 0;
    s->base_seq       = seq - 1;
    s->bad_seq        = RTP_SEQ_MOD + 1;
    s->received       = 0;
    s->expected_prior = 0;
    s->received_prior = 0;
    s->jitter         = 0;
    s->transit        = 0;
}

int rtp_valid_packet_in_sequence(RTPStatistics *s, uint16_t seq)
{
    uint16_t udelta = seq - s->max_seq;
    const int MAX_DROPOUT    = 3000;
    const int MAX_MISORDER   = 100;
    const int MIN_SEQUENTIAL = 2;

    /* source not valid until MIN_SEQUENTIAL packets with sequence
     * seq. numbers have been received */
    if (s->probation) {
        if (seq == s->max_seq + 1) {
            s->probation--;
            s->max_seq = seq;
            if (s->probation == 0) {
                rtp_init_sequence(s, seq);
                s->received++;
                return 1;
            }
        } else {
            s->probation = MIN_SEQUENTIAL - 1;
            s->max_seq   = seq;
        }
    } else if (udelta < MAX_DROPOUT) {
        // in order, with permissible gap
        if (seq < s->max_seq) {
            // sequence number wrapped; count another 64k cycles
            s->cycles += RTP_SEQ_MOD;
        }
        s->max_seq = seq;
    } else if (udelta <= RTP_SEQ_MOD - MAX_MISORDER) {
        // sequence made a large jump...
        if (seq == s->bad_seq) {
            /* two sequential packets -- assume that the other side
             * restarted without telling us; just resync. */
            rtp_init_sequence(s, seq);
        } else {
            s->bad_seq = (seq + 1) & (RTP_SEQ_MOD - 1);
            return 0;
        }
    } else {
        // duplicate or reordered packet...
    }
    s->received++;
    return 1;
}

int rtp_parse_packet_internal(RTPDemuxContext *s, Packet *pkt, const uint8_t *buf, int len)
{
    unsigned int ssrc;
    int payload_type, seq, flags = 0;
    int ext, csrc;

    janus_rtp_header *rtp = (janus_rtp_header *)buf;
    csrc = rtp->csrccount;
    ext = ntohs(rtp->extension);
    payload_type = rtp->type;
    if (buf[1] & 0x80)
        flags |= RTP_FLAG_MARKER;
    seq  = ntohs(rtp->seq_number);
    ssrc = ntohl(rtp->ssrc);

    /* store the ssrc in the RTPDemuxContext */
    s->ssrc = ssrc;

    /* NOTE: we can handle only one payload type */
    if (s->payload_type != payload_type) {
        JANUS_LOG(LOG_ERR, "rtp type error, expect[%d], cur[%d]\n", s->payload_type, payload_type);
        return -1;
    }

    // only do something with this if all the rtp checks pass...
    if (!rtp_valid_packet_in_sequence(&s->statistics, seq)) {
        JANUS_LOG(LOG_WARN, "RTP: PT=%02x: bad cseq %04x expected=%04x\n", payload_type, seq, ((s->seq + 1) & 0xffff));
        return -1;
    }

    if (buf[0] & 0x20) {
        int padding = buf[len - 1];
        if (len >= 12 + padding)
            len -= padding;
    }

    s->seq = seq;
    len   -= 12;
    buf   += 12;

    len   -= 4 * csrc;
    buf   += 4 * csrc;
    if (len < 0) {
        JANUS_LOG(LOG_INFO, "rtp packet len=%d, err\n", len);
        return -1;
    }

    /* RFC 3550 Section 5.3.1 RTP Header Extension handling */
    if (ext) {
        if (len < 4) {
            JANUS_LOG(LOG_INFO, "rtp packet has ext but len[%d] < 4\n", len);
            return -1;
        }
        /* calculate the header extension length (stored as number
         * of 32-bit words) */
        uint16_t tmp = (uint16_t)buf[2] << 8 | (uint16_t)buf[3];
        ext = (tmp + 1) << 2;

        if (len < ext) {
            JANUS_LOG(LOG_ERR, "rtp packet len[%d] < ext[%d]\n", len, ext);
            return -1;
        }
        // skip past RTP header extension
        len -= ext;
        buf += ext;
    }

    return h264_handle_packet(pkt, buf, len, seq, flags);
}

int h264_handle_packet(Packet *pkt, const uint8_t *buf, int len, uint16_t seq, int flags)
{
    uint8_t nal;
    uint8_t type;
    int result = 0;

    if (!len) {
        JANUS_LOG(LOG_ERR, "Empty H.264 RTP packet\n");
        return -1;
    }
    nal  = buf[0];
    type = nal & 0x1f;

    /* Simplify the case (these are all the NAL types used internally by
     * the H.264 codec). */
    if (type >= 1 && type <= 23)
        type = 1;
    switch (type) {
    case 0:                    // undefined, but pass them through
    case 1:
        pkt->buf = g_malloc0(len + sizeof(start_sequence));
        if (!pkt->buf) {
            result = -1;
            break;
        }
        pkt->size = len + sizeof(start_sequence);
        memcpy(pkt->buf, start_sequence, sizeof(start_sequence));
        memcpy(pkt->buf + sizeof(start_sequence), buf, len);
        break;

    case 24:                   // STAP-A (one packet, multiple nals)
        // consume the STAP-A NAL
        buf++;
        len--;
        result = h264_handle_aggregated_packet(pkt, buf, len, 0, NAL_COUNTERS, NAL_MASK);
        break;

    case 25:                   // STAP-B
    case 26:                   // MTAP-16
    case 27:                   // MTAP-24
    case 29:                   // FU-B
        JANUS_LOG(LOG_ERR, "RTP H.264 NAL unit type %d not support yet\n", type);
        result = -1;
        break;

    case 28:                   // FU-A (fragmented nal)
        result = h264_handle_packet_fu_a(pkt, buf, len, NAL_COUNTERS, NAL_MASK);
        break;

    case 30:                   // undefined
    case 31:                   // undefined
    default:
        JANUS_LOG(LOG_ERR, "Undefined type (%d)\n", type);
        result = -1;
        break;
    }

    return result;
}

int h264_handle_frag_packet(Packet *pkt, const uint8_t *buf, int len,
                               int start_bit, const uint8_t *nal_header,
                               int nal_header_len)
{
    int ret;
    int tot_len = len;
    int pos = 0;
    if (start_bit)
        tot_len += sizeof(start_sequence) + nal_header_len;
    pkt->buf = g_malloc0(tot_len);
    if (!pkt->buf) {
        JANUS_LOG(LOG_ERR, "rtp pkt buf malloc fail\n");
        return -1;
    }
    pkt->size = tot_len;
    if (start_bit) {
        memcpy(pkt->buf + pos, start_sequence, sizeof(start_sequence));
        pos += sizeof(start_sequence);
        memcpy(pkt->buf + pos, nal_header, nal_header_len);
        pos += nal_header_len;
    }
    memcpy(pkt->buf + pos, buf, len);
    return 0;
}

int h264_handle_packet_fu_a(Packet *pkt, const uint8_t *buf, int len, int *nal_counters, int nal_mask)
{
    uint8_t fu_indicator, fu_header, start_bit, nal_type, nal;

    if (len < 3) {
        JANUS_LOG(LOG_ERR, "Too short data for FU-A H.264 RTP packet\n");
        return -1;
    }

    fu_indicator = buf[0];
    fu_header    = buf[1];
    start_bit    = fu_header >> 7;
    nal_type     = fu_header & 0x1f;
    nal          = fu_indicator & 0xe0 | nal_type;

    // skip the fu_indicator and fu_header
    buf += 2;
    len -= 2;

    if (start_bit && nal_counters)
        nal_counters[nal_type & nal_mask]++;
    return h264_handle_frag_packet(pkt, buf, len, start_bit, &nal, 1);
}

int h264_handle_aggregated_packet(Packet *pkt,
                                     const uint8_t *buf, int len,
                                     int skip_between, int *nal_counters,
                                     int nal_mask)
{
    int pass         = 0;
    int total_length = 0;
    uint8_t *dst     = NULL;
    int ret;

    // first we are going to figure out the total size
    for (pass = 0; pass < 2; pass++) {
        const uint8_t *src = buf;
        int src_len        = len;

        while (src_len > 2) {
            uint16_t nal_size = (uint16_t)src[0] << 8 | (uint16_t)src[1];
            // consume the length of the aggregate
            src     += 2;
            src_len -= 2;

            if (nal_size <= src_len) {
                if (pass == 0) {
                    // counting
                    total_length += sizeof(start_sequence) + nal_size;
                } else {
                    // copying
                    memcpy(dst, start_sequence, sizeof(start_sequence));
                    dst += sizeof(start_sequence);
                    memcpy(dst, src, nal_size);
                    if (nal_counters)
                        nal_counters[(*src) & nal_mask]++;
                    dst += nal_size;
                }
            } else {
                JANUS_LOG(LOG_ERR, "nal size exceeds length: %d %d\n", nal_size, src_len);
                return -1;
            }

            // eat what we handled
            src     += nal_size + skip_between;
            src_len -= nal_size + skip_between;
        }

        if (pass == 0) {
            /* now we know the total size of the packet (with the
             * start sequences added) */
            pkt->buf = g_malloc0(total_length);
            if (!pkt->buf) {
                JANUS_LOG(LOG_ERR, "rtp pkt buf malloc fail\n");
                return -1;
            }
            pkt->size = total_length;
            dst = pkt->buf;
        }
    }

    return 0;
}

int enqueue_packet(RTPDemuxContext *s, uint8_t *buf, int len)
{
    janus_rtp_header *rtp_header = (janus_rtp_header *)buf;
    uint16_t seq   = ntohs(rtp_header->seq_number);
    RTPPacket **cur = &s->queue, *packet;

    /* Find the correct place in the queue to insert the packet */
    while (*cur) {
        int16_t diff = seq - (*cur)->seq;
        if (diff < 0)
            break;
        cur = &(*cur)->next;
    }

    packet = g_malloc0(sizeof(*packet));
    if (!packet) {
        JANUS_LOG(LOG_ERR, "rtp pkt buf malloc fail\n");
        return -1;
    }
    packet->recvtime = janus_get_monotonic_time() / 1000;
    packet->seq      = seq;
    packet->len      = len;
    // 拷贝buf
    uint8_t* tmp_buf = g_malloc0(len);
    memcpy(tmp_buf, buf, len);
    packet->buf      = tmp_buf;
    packet->next     = *cur;
    *cur = packet;
    s->queue_len++;

    return 0;
}

