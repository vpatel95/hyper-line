#ifndef _AVD_MESSAGE_H_
#define _AVD_MESSAGE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "avd_log.h"

#define  __INT8_NUM_BYTES__     (1)
#define  __INT16_NUM_BYTES__    (2)
#define  __INT32_NUM_BYTES__    (4)
#define  __FLOAT_NUM_BYTES__    (4)
#define  __INT64_NUM_BYTES__    (8)
#define  __DOUBLE_NUM_BYTES__   (8)

#define  __boolean_encoded_array_size           __int8_t_encoded_array_size
#define  __boolean_encode_array                 __int8_t_encode_array
#define  __boolean_decode_array                 __int8_t_decode_array
#define  __boolean_encode_little_endian_array   __int8_t_encode_little_endian_array
#define  __boolean_decode_little_endian_array   __int8_t_decode_little_endian_array
#define  __boolean_clone_array                  __int8_t_clone_array

// Message type flags
#define AVD_MSG_F_NEW_CON       (1 << 0)
#define AVD_MSG_F_RE_CON        (1 << 1)
#define AVD_MSG_F_TASK          (1 << 2)
#define AVD_MSG_F_FILE_TSK      (1 << 3)
#define AVD_MSG_F_FILE_TSK_FIN  (1 << 4)
#define AVD_MSG_F_FILE_IN       (1 << 5)
#define AVD_MSG_F_FILE_IN_FIN   (1 << 6)
#define AVD_MSG_F_FILE_OUT      (1 << 7)
#define AVD_MSG_F_FILE_OUT_FIN  (1 << 8)
#define AVD_MSG_F_TASK_POLL     (1 << 9)
#define AVD_MSG_F_TASK_POLL_TR  (1 << 10)
#define AVD_MSG_F_TASK_POLL_FL  (1 << 11)
#define AVD_MSG_F_TASK_STG      (1 << 12)
#define AVD_MSG_F_PEER_ID       (1 << 13)
#define AVD_MSG_F_PEER_ID_TR    (1 << 14)
#define AVD_MSG_F_PEER_ID_FL    (1 << 15)
#define AVD_MSG_F_CTRL          (1 << 30)
#define AVD_MSG_F_CLOSE         (1 << 31)

#define reset_msg_type(type)        (type = 0)
#define set_msg_type(type, flag)    (type |= flag)
#define unset_msg_type(type, flag)  (type &= (~flag))
#define is_msg_type(type, flag)     (type & flag)

#define MSG_HDR_SZ          sizeof(msg_hdr_t)
#define MAX_BUF_SZ          2048
#define MAX_CHUNK_SZ        256
#define MAX_STG             3

/* Message Header
 *  1. Type : type of message - e.g new user, reconnect etc
 *  2. Seq Number : this will be used in sending chunked messages e.g file transfer
 *  3. Size : size of whole message i.e MSG_HDR_SZ + size of encoded message
 */
typedef struct msg_hdr_s {
    int32_t      type;
    int32_t     seq_no;
    size_t      size;
} __attribute__((packed)) msg_hdr_t;

typedef struct message_s {
    msg_hdr_t   hdr;
    char        buf[MAX_BUF_SZ];
} __attribute__((packed)) message_t;

// User Message : NewConnect (nc)
typedef struct umsg_nc_s {
    char        *uname;
} umsg_nc_t;

// User Message : Reconnect (rc)
typedef struct umsg_rc_s {
    int32_t     uid;
    char        *uname;
} umsg_rc_t;

// Worker Message : New Connect (nc)
typedef struct wmsg_nc_s {
    int32_t     peer_port;
    char        *peer_addr;
    char        *uname;
} wmsg_nc_t;

// Worker Message : Reconnect (rc)
typedef struct wmsg_rc_s {
    int32_t     wid;
    char        *uname;
} wmsg_rc_t;

// Worker Message : Task Ready Poll (tr)
typedef struct wmsg_tr_s {
    int32_t     wid;
    char        *uname;
} wmsg_tr_t;

// Worker Message : Peers Identification Poll (pi)
typedef struct wmsg_pi_s {
    int32_t     wid;
    int32_t     tid;
    int32_t     num;
    char        *uname;
} wmsg_pi_t;

// Server Message : User Re-Connect (nuc)
typedef struct smsg_urc_s {
    int32_t     uid;
    int32_t     poll_id;
} smsg_urc_t;

// Server Message :  Worker Re-Connect (wrc)
typedef struct smsg_wrc_s {
    int32_t     wid;
    int32_t     poll_id;
} smsg_wrc_t;

typedef struct smsg_ts_s {
    int32_t     tid;
    int32_t     stg_num;
    int32_t     total_stg;
    char        *func;
} smsg_ts_t;

// Server Message : Worker Peer Identification (wpi)
typedef struct smsg_wpi_s {
    int32_t     pid;
    char        *peer_addr;
    int32_t     peer_port;
} smsg_wpi_t;

typedef struct tmsg_file_s {
    char    *buf;
} tmsg_file_t;

typedef struct tmsg_stage_s {
    int32_t     num;
    char        *func;
} tmsg_stage_t;

typedef struct tmsg_args_s {
    int32_t         num_stages;
    char            *task_name;
    tmsg_stage_t    stages[MAX_STG];
} tmsg_args_t;

static inline size_t fsize (FILE *f) {
    size_t  c = ftell(f);
    size_t  l;
    fseek(f, 0L, SEEK_END);
    l = ftell(f);
    fseek(f, c, SEEK_SET);
    return l;
}

ssize_t recvn(int32_t fd, void *vptr, size_t n, int32_t flag) {
    size_t  nleft;
    ssize_t nrecv;
    char    *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ( (nrecv = recv(fd, ptr, nleft, flag)) < 0) {
            if (errno == EINTR)
                nrecv = 0;
            else
                return -1;
        } else if (nrecv == 0)
            break;

        nleft -= nrecv;
        ptr   += nrecv;
    }
    return(n - nleft);
}

int32_t recv_avd_hdr(int32_t sockfd, msg_hdr_t *h) {
    int32_t     rc = -1;

    rc = recvn(sockfd, h, MSG_HDR_SZ, 0);

    if (MSG_HDR_SZ != rc && 0 != rc) {
        avd_log_error("Error receiving avd_hdr");
        avd_log_debug("Error : %s", strerror(errno));
        return -1;
    }

    avd_log_debug("Received Header of size :%d", rc);
    return rc;
}

int32_t recv_avd_msg(int32_t sockfd, char *buf, size_t sz) {
    int32_t     rc;

    if (0 >= (rc = recvn(sockfd, buf, sz, 0))) {
        avd_log_error("Error receiving avd_msg");
        avd_log_debug("Error : %s", strerror(errno));
        return -1;
    }

    avd_log_debug("sz : %d, rc : %d", sz, rc);
    avd_log_debug("Received Msg of size :%d", rc);
    return rc;
}

static inline uint32_t __int8_t_encoded_array_sz(const int8_t *msg, uint32_t n_ele) {
    (void) msg;
    return (__INT8_NUM_BYTES__ * n_ele);
}

static inline int32_t __int8_t_encode_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                            const int8_t *p, uint32_t n_ele) {
    if (maxlen < n_ele)
        return -1;

    uint8_t    *buf = (uint8_t *) _buf;

    memcpy(&buf[offset], p, n_ele);

    return n_ele;
}

static inline int32_t __int8_t_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                        int8_t *p, uint32_t n_ele) {
    if (maxlen < n_ele)
        return -1;

    uint8_t    *buf = (uint8_t *) _buf;

    memcpy(p, &buf[offset], n_ele);

    return n_ele;
}

static inline int32_t __int8_t_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                                      const int8_t *p, uint32_t n_ele) {
    return __int8_t_encode_array(_buf, offset, maxlen, p, n_ele);
}

static inline int32_t __int8_t_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                                          int8_t *p, uint32_t n_ele) {
    return __int8_t_decode_array(_buf, offset, maxlen, p, n_ele);
}

static inline uint32_t __int8_t_clone_array(const int8_t *p, int8_t *q, uint32_t n_ele) {
    uint32_t    n = n_ele * sizeof(int8_t);

    memcpy(q, p, n);

    return n;
}

static inline uint32_t __int16_t_encoded_array_sz(const int16_t *p, uint32_t n_ele) {
    (void) p;
    return (__INT16_NUM_BYTES__ * n_ele);
}

static inline int32_t __int16_t_encode_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                             const int16_t *p, uint32_t n_ele) {
    uint32_t        total_size = (__INT16_NUM_BYTES__ * n_ele);
    uint32_t        pos = offset;
    uint32_t        i;
    uint8_t            *buf = (uint8_t *) _buf;
    const uint16_t  *unsigned_p = (uint16_t *)p;

    if (maxlen < total_size)
        return -1;

    for (i = 0; i < n_ele; ++i) {
        uint16_t v = unsigned_p[i];
        buf[pos++] = (v >> 8) & 0xff;
        buf[pos++] = (v & 0xff);
    }

    return total_size;
}

static inline int32_t __int16_t_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                             int16_t *p, uint32_t n_ele) {
    u_int32_t   total_size = (__INT16_NUM_BYTES__ * n_ele);
    uint8_t        *buf = (uint8_t *) _buf;
    uint32_t    pos = offset;
    uint32_t    i;

    if (maxlen < total_size)
        return -1;

    for (i = 0; i < n_ele; ++i) {
        p[i] = (buf[pos] << 8) + buf[pos + 1];
        pos += 2;
    }

    return total_size;
}

static inline int32_t __int16_t_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                                           const int16_t *p, uint32_t n_ele) {
    uint32_t        total_size = (__INT16_NUM_BYTES__ * n_ele);
    uint32_t        pos = offset;
    uint32_t        i;
    uint8_t            *buf = (uint8_t *) _buf;
    const uint16_t  *unsigned_p = (uint16_t *)p;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        uint16_t v = unsigned_p[i];
        buf[pos++] = (v & 0xff);
        buf[pos++] = (v >> 8) & 0xff;
    }

    return total_size;
}

static inline int32_t __int16_t_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                                           int16_t *p, uint32_t n_ele) {
    uint32_t    total_size = (__INT16_NUM_BYTES__ * n_ele);
    uint8_t        *buf = (uint8_t *) _buf;
    uint32_t    pos = offset;
    uint32_t    i;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        p[i] = (buf[pos + 1] << 8) + buf[pos];
        pos += 2;
    }

    return total_size;
}

static inline uint32_t __int16_t_clone_array(const int16_t *p, int16_t *q, uint32_t n_ele) {
    uint32_t    n = n_ele * sizeof(int16_t);

    memcpy(q, p, n);

    return n;
}

static inline uint32_t __int32_t_encoded_array_sz(const int32_t *p, uint32_t n_ele) {
    (void) p;
    return (__INT32_NUM_BYTES__ * n_ele);
}

static inline int32_t __int32_t_encode_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                         const int32_t *msg, uint32_t n_ele) {
    uint32_t        total_size = (__INT32_NUM_BYTES__ * n_ele);
    uint32_t        pos = offset;
    uint32_t        i;
    uint8_t            *buf = (uint8_t *) _buf;
    const uint32_t * unsigned_msg = (uint32_t *)msg;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        uint32_t v = unsigned_msg[i];
        buf[pos++] = (v >> 24) & 0xff;
        buf[pos++] = (v >> 16) & 0xff;
        buf[pos++] = (v >> 8) & 0xff;
        buf[pos++] = (v & 0xff);
    }

    return total_size;
}

static inline int32_t __int32_t_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                         int32_t *msg, uint32_t n_ele) {
    uint32_t    total_size = (__INT32_NUM_BYTES__ * n_ele);
    uint8_t        *buf = (uint8_t *) _buf;
    uint32_t    pos = offset;
    uint32_t    i;

    if (maxlen < total_size)
        return -1;

    for (i = 0; i < n_ele; ++i) {
        msg[i] = (((uint32_t)buf[pos + 0]) << 24) +
                       (((uint32_t)buf[pos + 1]) << 16) +
                       (((uint32_t)buf[pos + 2]) << 8) +
                       ((uint32_t)buf[pos + 3]);
        pos += 4;
    }

    return total_size;
}

static inline int32_t __int32_t_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                                           const int32_t *p, uint32_t n_ele) {
    uint32_t        total_size = (__INT32_NUM_BYTES__ * n_ele);
    uint32_t        pos = offset;
    uint32_t        i;
    uint8_t            *buf = (uint8_t *) _buf;
    const uint32_t  *unsigned_p = (uint32_t*)p;

    if (maxlen < total_size)
        return -1;

    for (i = 0; i < n_ele; ++i) {
        uint32_t v = unsigned_p[i];
        buf[pos++] = (v & 0xff);
        buf[pos++] = (v >> 8) & 0xff;
        buf[pos++] = (v >> 16) & 0xff;
        buf[pos++] = (v >> 24) & 0xff;
    }

    return total_size;
}

static inline int32_t __int32_t_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, int32_t *p, uint32_t n_ele) {
    uint32_t    total_size = (__INT32_NUM_BYTES__ * n_ele);
    uint32_t    pos = offset;
    uint32_t    i;
    uint8_t        *buf = (uint8_t *) _buf;

    if (maxlen < total_size)
        return -1;

    for (i = 0; i < n_ele; ++i) {
        p[i] = (((uint32_t)buf[pos + 3]) << 24) +
                      (((uint32_t)buf[pos + 2]) << 16) +
                      (((uint32_t)buf[pos + 1]) << 8) +
                       ((uint32_t)buf[pos + 0]);
        pos += 4;
    }

    return total_size;
}

static inline uint32_t __int32_t_clone_array(const int32_t *p, int32_t *q, uint32_t n_ele) {
    uint32_t    n = n_ele * sizeof(int32_t);

    memcpy(q, p, n);

    return n;
}


static inline uint32_t __int64_t_encoded_array_sz(const int64_t *p, uint32_t n_ele) {
    (void)p;
    return __INT64_NUM_BYTES__ * n_ele;
}

static inline int32_t __int64_t_encode_array(void *_buf, uint32_t offset, uint32_t maxlen, const int64_t *p, uint32_t n_ele) {
    uint32_t total_size = __INT64_NUM_BYTES__ * n_ele;
    uint8_t *buf = (uint8_t *) _buf;
    uint32_t pos = offset;
    uint32_t i;

    if (maxlen < total_size) return -1;

    const uint64_t* unsigned_p = (uint64_t*)p;
    for (i = 0; i < n_ele; ++i) {
        uint64_t v = unsigned_p[i];
        buf[pos++] = (v>>56)&0xff;
        buf[pos++] = (v>>48)&0xff;
        buf[pos++] = (v>>40)&0xff;
        buf[pos++] = (v>>32)&0xff;
        buf[pos++] = (v>>24)&0xff;
        buf[pos++] = (v>>16)&0xff;
        buf[pos++] = (v>>8)&0xff;
        buf[pos++] = (v & 0xff);
    }

    return total_size;
}

static inline int32_t __int64_t_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen, int64_t *p, uint32_t n_ele) {
    uint32_t total_size = __INT64_NUM_BYTES__ * n_ele;
    uint8_t *buf = (uint8_t *) _buf;
    uint32_t pos = offset;
    uint32_t i;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        uint64_t a = (((uint32_t)buf[pos+0])<<24) +
                     (((uint32_t)buf[pos+1])<<16) +
                     (((uint32_t)buf[pos+2])<<8) +
                      ((uint32_t)buf[pos+3]);
        pos+=4;
        uint64_t b = (((uint32_t)buf[pos+0])<<24) +
                     (((uint32_t)buf[pos+1])<<16) +
                     (((uint32_t)buf[pos+2])<<8) +
                      ((uint32_t)buf[pos+3]);
        pos+=4;
        p[i] = (a<<32) + (b&0xffffffff);
    }

    return total_size;
}

static inline int32_t __int64_t_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen, const int64_t *p, uint32_t n_ele) {
    uint32_t total_size = __INT64_NUM_BYTES__ * n_ele;
    uint8_t *buf = (uint8_t *) _buf;
    uint32_t pos = offset;
    uint32_t i;

    if (maxlen < total_size) return -1;

    const uint64_t* unsigned_p = (uint64_t*)p;
    for (i = 0; i < n_ele; ++i) {
        uint64_t v = unsigned_p[i];
        buf[pos++] = (v & 0xff);
        buf[pos++] = (v>>8)&0xff;
        buf[pos++] = (v>>16)&0xff;
        buf[pos++] = (v>>24)&0xff;
        buf[pos++] = (v>>32)&0xff;
        buf[pos++] = (v>>40)&0xff;
        buf[pos++] = (v>>48)&0xff;
        buf[pos++] = (v>>56)&0xff;
    }

    return total_size;
}

static inline int32_t __int64_t_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, int64_t *p, uint32_t n_ele) {
    uint32_t total_size = __INT64_NUM_BYTES__ * n_ele;
    uint8_t *buf = (uint8_t *) _buf;
    uint32_t pos = offset;
    uint32_t i;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        uint64_t b = (((uint32_t)buf[pos+3])<<24) +
                     (((uint32_t)buf[pos+2])<<16) +
                     (((uint32_t)buf[pos+1])<<8) +
                      ((uint32_t)buf[pos+0]);
        pos+=4;
        uint64_t a = (((uint32_t)buf[pos+3])<<24) +
                     (((uint32_t)buf[pos+2])<<16) +
                     (((uint32_t)buf[pos+1])<<8) +
                      ((uint32_t)buf[pos+0]);
        pos+=4;
        p[i] = (a<<32) + (b&0xffffffff);
    }

    return total_size;
}

static inline uint32_t __int64_t_clone_array(const int64_t *p, int64_t *q, uint32_t n_ele) {
    uint32_t n = n_ele * sizeof(int64_t);
    memcpy(q, p, n);
    return n;
}

/**
 * FLOAT
 */
typedef union __avd__float_uint32_t {
    float       flt;
    uint32_t    uint;
} __avd__float_uint32_t;

static inline uint32_t __float_encoded_array_sz(const float *p, uint32_t n_ele) {
    (void)p;
    return __FLOAT_NUM_BYTES__ * n_ele;
}

static inline int32_t __float_encode_array(void *_buf, uint32_t offset, uint32_t maxlen, const float *p, uint32_t n_ele) {
    uint32_t total_size = __FLOAT_NUM_BYTES__ * n_ele;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t i;
    __avd__float_uint32_t tmp;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        tmp.flt = p[i];
        buf[pos++] = (tmp.uint >> 24) & 0xff;
        buf[pos++] = (tmp.uint >> 16) & 0xff;
        buf[pos++] = (tmp.uint >>  8) & 0xff;
        buf[pos++] = (tmp.uint      ) & 0xff;
    }

    return total_size;
}

static inline int32_t __float_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen, float *p, uint32_t n_ele) {
    uint32_t total_size = __FLOAT_NUM_BYTES__ * n_ele;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t i;
    __avd__float_uint32_t tmp;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        tmp.uint = (((uint32_t)buf[pos + 0]) << 24) |
                   (((uint32_t)buf[pos + 1]) << 16) |
                   (((uint32_t)buf[pos + 2]) <<  8) |
                    ((uint32_t)buf[pos + 3]);
        p[i] = tmp.flt;
        pos += 4;
    }

    return total_size;
}

static inline int32_t __float_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen, const float *p, uint32_t n_ele) {
    uint32_t total_size = __FLOAT_NUM_BYTES__ * n_ele;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t i;
    __avd__float_uint32_t tmp;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        tmp.flt = p[i];
        buf[pos++] = (tmp.uint      ) & 0xff;
        buf[pos++] = (tmp.uint >>  8) & 0xff;
        buf[pos++] = (tmp.uint >> 16) & 0xff;
        buf[pos++] = (tmp.uint >> 24) & 0xff;
    }

    return total_size;
}

static inline int32_t __float_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, float *p, uint32_t n_ele) {
    uint32_t total_size = __FLOAT_NUM_BYTES__ * n_ele;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t i;
    __avd__float_uint32_t tmp;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        tmp.uint = (((uint32_t)buf[pos + 3]) << 24) |
                   (((uint32_t)buf[pos + 2]) << 16) |
                   (((uint32_t)buf[pos + 1]) <<  8) |
                    ((uint32_t)buf[pos + 0]);
        p[i] = tmp.flt;
        pos += 4;
    }

    return total_size;
}

static inline uint32_t __float_clone_array(const float *p, float *q, uint32_t n_ele) {
    uint32_t n = n_ele * sizeof(float);
    memcpy(q, p, n);
    return n;
}

/**
 * DOUBLE
 */
typedef union __avd__double_uint64_t {
    double      dbl;
    uint64_t    uint;
} __avd__double_uint64_t;

static inline uint32_t __double_encoded_array_sz(const double *p, uint32_t n_ele) {
    (void)p;
    return __DOUBLE_NUM_BYTES__ * n_ele;
}

static inline int32_t __double_encode_array(void *_buf, uint32_t offset, uint32_t maxlen, const double *p, uint32_t n_ele) {
    uint32_t total_size = __DOUBLE_NUM_BYTES__ * n_ele;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t i;
    __avd__double_uint64_t tmp;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        tmp.dbl = p[i];
        buf[pos++] = (tmp.uint >> 56) & 0xff;
        buf[pos++] = (tmp.uint >> 48) & 0xff;
        buf[pos++] = (tmp.uint >> 40) & 0xff;
        buf[pos++] = (tmp.uint >> 32) & 0xff;
        buf[pos++] = (tmp.uint >> 24) & 0xff;
        buf[pos++] = (tmp.uint >> 16) & 0xff;
        buf[pos++] = (tmp.uint >>  8) & 0xff;
        buf[pos++] = (tmp.uint      ) & 0xff;
    }

    return total_size;
}

static inline int32_t __double_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen, double *p, uint32_t n_ele) {
    uint32_t total_size = __DOUBLE_NUM_BYTES__ * n_ele;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t i;
    __avd__double_uint64_t tmp;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        uint64_t a = (((uint32_t) buf[pos + 0]) << 24) +
                     (((uint32_t) buf[pos + 1]) << 16) +
                     (((uint32_t) buf[pos + 2]) <<  8) +
                      ((uint32_t) buf[pos + 3]);
        pos += 4;
        uint64_t b = (((uint32_t) buf[pos + 0]) << 24) +
                     (((uint32_t) buf[pos + 1]) << 16) +
                     (((uint32_t) buf[pos + 2]) <<  8) +
                      ((uint32_t) buf[pos + 3]);
        pos += 4;
        tmp.uint = (a << 32) + (b & 0xffffffff);
        p[i] = tmp.dbl;
    }

    return total_size;
}

static inline int32_t __double_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen, const double *p, uint32_t n_ele) {
    uint32_t total_size = __DOUBLE_NUM_BYTES__ * n_ele;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t i;
    __avd__double_uint64_t tmp;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        tmp.dbl = p[i];
        buf[pos++] = (tmp.uint      ) & 0xff;
        buf[pos++] = (tmp.uint >>  8) & 0xff;
        buf[pos++] = (tmp.uint >> 16) & 0xff;
        buf[pos++] = (tmp.uint >> 24) & 0xff;
        buf[pos++] = (tmp.uint >> 32) & 0xff;
        buf[pos++] = (tmp.uint >> 40) & 0xff;
        buf[pos++] = (tmp.uint >> 48) & 0xff;
        buf[pos++] = (tmp.uint >> 56) & 0xff;
    }

    return total_size;
}

static inline int32_t __double_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, double *p, uint32_t n_ele) {
    uint32_t total_size = __DOUBLE_NUM_BYTES__ * n_ele;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t i;
    __avd__double_uint64_t tmp;

    if (maxlen < total_size) return -1;

    for (i = 0; i < n_ele; ++i) {
        uint64_t b = (((uint32_t)buf[pos + 3]) << 24) +
                     (((uint32_t)buf[pos + 2]) << 16) +
                     (((uint32_t)buf[pos + 1]) <<  8) +
                      ((uint32_t)buf[pos + 0]);
        pos += 4;
        uint64_t a = (((uint32_t)buf[pos + 3]) << 24) +
                     (((uint32_t)buf[pos + 2]) << 16) +
                     (((uint32_t)buf[pos + 1]) <<  8) +
                      ((uint32_t)buf[pos + 0]);
        pos += 4;
        tmp.uint = (a << 32) + (b & 0xffffffff);
        p[i] = tmp.dbl;
    }

    return total_size;
}

static inline uint32_t __double_clone_array(const double *p, double *q, uint32_t n_ele) {
    uint32_t n = n_ele * sizeof(double);
    memcpy(q, p, n);
    return n;
}

/**
 * STRING
 */
static inline int32_t __string_decode_array_cleanup(char **s, uint32_t n_ele) {
    uint32_t i;
    for (i = 0; i < n_ele; ++i)
        free(s[i]);
    return 0;
}

static inline uint32_t __string_encoded_array_sz(char * const *s, uint32_t n_ele) {
    uint32_t    size = 0, i;

    for (i = 0; i < n_ele; ++i)
        size += __INT32_NUM_BYTES__ + strlen(s[i]) + __INT8_NUM_BYTES__;

    return size;
}

static inline int32_t __string_encode_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                            char * const *p, uint32_t n_ele) {
    uint32_t    pos = 0, i;
    int32_t     len;

    for (i = 0; i < n_ele; ++i) {
        int32_t length = strlen(p[i]) + __INT8_NUM_BYTES__; // length includes \0

        len = __int32_t_encode_array(_buf, offset + pos, maxlen - pos, &length, 1);
        if (len < 0) return len; else pos += len;

        len = __int8_t_encode_array(_buf, offset + pos, maxlen - pos, (int8_t*) p[i], length);
        if (len < 0) return len; else pos += len;
    }

    return pos;
}

static inline int32_t __string_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen, char **p, uint32_t n_ele) {
    uint32_t pos = 0, i;
    int len;

    for (i = 0; i < n_ele; ++i) {
        int32_t length;

        // read length including \0
        len = __int32_t_decode_array(_buf, offset + pos, maxlen - pos, &length, 1);
        if (len < 0) return len; else pos += len;

        p[i] = (char*) malloc(length);
        len = __int8_t_decode_array(_buf, offset + pos, maxlen - pos, (int8_t*) p[i], length);
        if (len < 0) return len; else pos += len;
    }

    return pos;
}

static inline int32_t __string_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen, char * const *p, uint32_t n_ele) {
    uint32_t pos = 0, i;
    int len;

    for (i = 0; i < n_ele; ++i) {
        int32_t length = strlen(p[i]) + 1; // length includes \0

        len = __int32_t_encode_little_endian_array(_buf, offset + pos, maxlen - pos, &length, 1);
        if (len < 0) return len; else pos += len;

        len = __int8_t_encode_little_endian_array(_buf, offset + pos, maxlen - pos, (int8_t*) p[i], length);
        if (len < 0) return len; else pos += len;
    }

    return pos;
}

static inline int32_t __string_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, char **p, uint32_t n_ele) {
    uint32_t pos = 0, i;
    int len;

    for (i = 0; i < n_ele; ++i) {
        int32_t length;

        // read length including \0
        len = __int32_t_decode_little_endian_array(_buf, offset + pos, maxlen - pos, &length, 1);
        if (len < 0) return len; else pos += len;

        p[i] = (char*) malloc(length);
        len = __int8_t_decode_little_endian_array(_buf, offset + pos, maxlen - pos, (int8_t*) p[i], length);
        if (len < 0) return len; else pos += len;
    }

    return pos;
}

/******************************************************
 *                 HELPER FUNCTIONS                   *
 ******************************************************/
uint32_t __umsg_nc_t_encoded_sz(const umsg_nc_t *msg) {
    uint32_t    sz = 0;

    sz += __string_encoded_array_sz(&(msg->uname), 1);

    return sz;
}

int32_t __umsg_nc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const umsg_nc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __umsg_nc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, umsg_nc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __umsg_rc_t_encoded_sz(const umsg_rc_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->uid), 1);
    sz += __string_encoded_array_sz(&(msg->uname), 1);

    return sz;
}

int32_t __umsg_rc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const umsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->uid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __umsg_rc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, umsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->uid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __wmsg_nc_t_encoded_sz(const wmsg_nc_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->peer_port), 1);
    sz += __string_encoded_array_sz(&(msg->uname), 1);
    sz += __string_encoded_array_sz(&(msg->peer_addr), 1);

    return sz;
}

int32_t __wmsg_nc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const wmsg_nc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos,
                                               &(msg->peer_port), 1);
    if (len < 0) return len; else pos += len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->peer_addr), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __wmsg_nc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, wmsg_nc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos,
                                               &(msg->peer_port), 1);
    if (len < 0) return len; else pos += len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->peer_addr), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __wmsg_rc_t_encoded_sz(const wmsg_rc_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->wid), 1);
    sz += __string_encoded_array_sz(&(msg->uname), 1);

    return sz;
}

int32_t __wmsg_rc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const wmsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->wid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __wmsg_rc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, wmsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->wid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __wmsg_tr_t_encoded_sz(const wmsg_tr_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->wid), 1);
    sz += __string_encoded_array_sz(&(msg->uname), 1);

    return sz;
}

int32_t __wmsg_tr_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const wmsg_tr_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->wid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __wmsg_tr_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, wmsg_tr_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->wid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __wmsg_pi_t_encoded_sz(const wmsg_pi_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->wid), 1);
    sz += __int32_t_encoded_array_sz(&(msg->tid), 1);
    sz += __int32_t_encoded_array_sz(&(msg->num), 1);
    sz += __string_encoded_array_sz(&(msg->uname), 1);

    return sz;
}

int32_t __wmsg_pi_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const wmsg_pi_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->wid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->tid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->num), 1);
    if (len < 0) return len; else pos += len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __wmsg_pi_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, wmsg_pi_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->wid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->tid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->num), 1);
    if (len < 0) return len; else pos += len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->uname), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __smsg_urc_t_encoded_sz(const smsg_urc_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->uid), 1);
    sz += __int32_t_encoded_array_sz(&(msg->poll_id), 1);

    return sz;
}

int32_t __smsg_urc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_urc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->uid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->poll_id), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __smsg_urc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, smsg_urc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->uid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->poll_id), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __smsg_wrc_t_encoded_sz(const smsg_wrc_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->wid), 1);
    sz += __int32_t_encoded_array_sz(&(msg->poll_id), 1);

    return sz;
}

int32_t __smsg_wrc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_wrc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->wid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->poll_id), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __smsg_wrc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, smsg_wrc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->wid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->poll_id), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __smsg_wpi_t_encoded_sz(const smsg_wpi_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->pid), 1);
    sz += __int32_t_encoded_array_sz(&(msg->peer_port), 1);
    sz += __string_encoded_array_sz(&(msg->peer_addr), 1);

    return sz;
}

int32_t __smsg_wpi_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_wpi_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->pid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->peer_addr), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->peer_port), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __smsg_wpi_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, smsg_wpi_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->pid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->peer_addr), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->peer_port), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

uint32_t __smsg_ts_t_encoded_sz(const smsg_ts_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->tid), 1);
    sz += __int32_t_encoded_array_sz(&(msg->stg_num), 1);
    sz += __int32_t_encoded_array_sz(&(msg->total_stg), 1);
    sz += __string_encoded_array_sz(&(msg->func), 1);

    return sz;
}

int32_t __smsg_ts_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_ts_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->tid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &(msg->func), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->stg_num), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->total_stg), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __smsg_ts_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, smsg_ts_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->tid), 1);
    if (len < 0) return len; else pos += len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &(msg->func), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->stg_num), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->total_stg), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __tmsg_file_t_encoded_sz (const tmsg_file_t *msg) {
    uint32_t    sz = 0;

    sz += __string_encoded_array_sz(&msg->buf, 1);

    return sz;
}

int32_t __tmsg_file_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const tmsg_file_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __string_encode_array(buf, offset + pos, maxlen - pos, &msg->buf, 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __tmsg_file_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, tmsg_file_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __string_decode_array(buf, offset + pos, maxlen - pos, &msg->buf, 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __tmsg_stage_t_encoded_array_sz(const tmsg_stage_t *msg, int32_t n_ele) {
    uint32_t    sz = 0;
    int32_t     i;

    for (i = 0; i < n_ele; i++) {
        sz += __int32_t_encoded_array_sz(&msg[i].num, 1);
        sz += __string_encoded_array_sz(&msg[i].func, 1);
    }

    return sz;
}

int32_t __tmsg_stage_t_encode_array(void *buf, uint32_t offset, uint32_t maxlen, const tmsg_stage_t *msg, int32_t n_ele) {
    uint32_t    pos = 0;
    int32_t     len, i;

    for (i = 0; i < n_ele; i++) {
        len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &msg[i].num, 1);
        if (len < 0) return len; else pos += len;

        len = __string_encode_array(buf, offset + pos, maxlen - pos, &msg[i].func, 1);
        if (len < 0) return len; else pos += len;
    }

    return pos;
}

int32_t __tmsg_stage_t_decode_array(const void *buf, uint32_t offset, uint32_t maxlen, tmsg_stage_t *msg, int32_t n_ele) {
    uint32_t    pos = 0;
    int32_t     len, i;

    for (i = 0; i < n_ele; i++) {
        len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &msg[i].num, 1);
        if (len < 0) return len; else pos += len;

        len = __string_decode_array(buf, offset + pos, maxlen - pos, &msg[i].func, 1);
        if (len < 0) return len; else pos += len;
    }

    return pos;
}

int32_t __tmsg_args_t_encoded_array_sz(const tmsg_args_t *msg, int32_t n_ele) {
    uint32_t    sz = 0;
    int32_t     i;

    for (i = 0; i < n_ele; i++) {
        sz += __int32_t_encoded_array_sz(&msg[i].num_stages, 1);
        sz += __string_encoded_array_sz(&msg[i].task_name, 1);
        sz += __tmsg_stage_t_encoded_array_sz(msg[i].stages, msg[i].num_stages);
    }

    return sz;
}

int32_t __tmsg_args_t_encode_array(void *buf, uint32_t offset, uint32_t maxlen, const tmsg_args_t *msg, int32_t n_ele) {
    uint32_t    pos = 0;
    int32_t     len, i;

    for (i = 0; i < n_ele; i++) {
        len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &msg[i].num_stages, 1);
        if (len < 0) return len; else pos += len;

        len = __string_encode_array(buf, offset + pos, maxlen - pos, &msg[i].task_name, 1);
        if (len < 0) return len; else pos += len;

        len = __tmsg_stage_t_encode_array(buf, offset + pos, maxlen - pos, msg[i].stages, msg[i].num_stages);
        if (len < 0) return len; else pos += len;
    }

    return pos;
}

int32_t __tmsg_args_t_decode_array(const void *buf, uint32_t offset, uint32_t maxlen, tmsg_args_t *msg, int32_t n_ele) {
    uint32_t    pos = 0;
    int32_t     len, i;

    for (i = 0; i < n_ele; i++) {
        len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &msg[i].num_stages, 1);
        if (len < 0) return len; else pos += len;

        len = __string_decode_array(buf, offset + pos, maxlen - pos, &msg[i].task_name, 1);
        if (len < 0) return len; else pos += len;

        len = __tmsg_stage_t_decode_array(buf, offset + pos, maxlen - pos, msg[i].stages, msg[i].num_stages);
        if (len < 0) return len; else pos += len;
    }

    return pos;
}

/* User New Connect */
uint32_t umsg_nc_t_encoded_sz (const umsg_nc_t *msg) {
    return 8 + __umsg_nc_t_encoded_sz(msg);
}

int32_t umsg_nc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const umsg_nc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __umsg_nc_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t umsg_nc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, umsg_nc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __umsg_nc_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* User Reconnect */
uint32_t umsg_rc_t_encoded_sz (const umsg_rc_t *msg) {
    return 8 + __umsg_rc_t_encoded_sz(msg);
}

int32_t umsg_rc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const umsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __umsg_rc_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t umsg_rc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, umsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __umsg_rc_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Worker New connect */
uint32_t wmsg_nc_t_encoded_sz (const wmsg_nc_t *msg) {
    return 8 + __wmsg_nc_t_encoded_sz(msg);
}

int32_t wmsg_nc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const wmsg_nc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __wmsg_nc_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t wmsg_nc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, wmsg_nc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __wmsg_nc_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Worker Reconnect */
uint32_t wmsg_rc_t_encoded_sz (const wmsg_rc_t *msg) {
    return 8 + __wmsg_rc_t_encoded_sz(msg);
}

int32_t wmsg_rc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const wmsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __wmsg_rc_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t wmsg_rc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, wmsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __wmsg_rc_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Worker Task Ready */
uint32_t wmsg_tr_t_encoded_sz (const wmsg_tr_t *msg) {
    return 8 + __wmsg_tr_t_encoded_sz(msg);
}

int32_t wmsg_tr_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const wmsg_tr_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __wmsg_tr_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t wmsg_tr_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, wmsg_tr_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __wmsg_tr_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Worker Peer Identification */
uint32_t wmsg_pi_t_encoded_sz (const wmsg_pi_t *msg) {
    return 8 + __wmsg_pi_t_encoded_sz(msg);
}

int32_t wmsg_pi_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const wmsg_pi_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __wmsg_pi_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t wmsg_pi_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, wmsg_pi_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __wmsg_pi_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Server User Reconnect Reply */
uint32_t smsg_urc_t_encoded_sz (const smsg_urc_t *msg) {
    return 8 + __smsg_urc_t_encoded_sz(msg);
}

int32_t smsg_urc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_urc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_urc_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t smsg_urc_t_decode(const void* buf, uint32_t offset, uint32_t maxlen, smsg_urc_t* msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_urc_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Server Worker Reconnect Reply */
uint32_t smsg_wrc_t_encoded_sz (const smsg_wrc_t *msg) {
    return 8 + __smsg_wrc_t_encoded_sz(msg);
}

int32_t smsg_wrc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_wrc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_wrc_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t smsg_wrc_t_decode(const void* buf, uint32_t offset, uint32_t maxlen, smsg_wrc_t* msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_wrc_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Server Worker Peer Identification */
uint32_t smsg_wpi_t_encoded_sz (const smsg_wpi_t *msg) {
    return 8 + __smsg_wpi_t_encoded_sz(msg);
}

int32_t smsg_wpi_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_wpi_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_wpi_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t smsg_wpi_t_decode(const void* buf, uint32_t offset, uint32_t maxlen, smsg_wpi_t* msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_wpi_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Server Worker Send Task Stage */
uint32_t smsg_ts_t_encoded_sz (const smsg_ts_t *msg) {
    return 8 + __smsg_ts_t_encoded_sz(msg);
}

int32_t smsg_ts_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_ts_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_ts_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t smsg_ts_t_decode(const void* buf, uint32_t offset, uint32_t maxlen, smsg_ts_t* msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_ts_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Task Message File */
int32_t tmsg_file_t_encoded_sz (const tmsg_file_t *msg) {
    return 8 + __tmsg_file_t_encoded_sz(msg);
}

int32_t tmsg_file_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const tmsg_file_t *msg) {
    uint32_t     pos = 0;
    int32_t     len;

    len = __tmsg_file_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t tmsg_file_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, tmsg_file_t *msg) {
    uint32_t     pos = 0;
    int32_t     len;

    len = __tmsg_file_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Task Stage Message */
int32_t tmsg_stage_t_encoded_sz(const tmsg_stage_t *msg) {
    return 8 + __tmsg_stage_t_encoded_array_sz(msg, 1);
}

int32_t tmsg_stage_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const tmsg_stage_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __tmsg_stage_t_encode_array(buf, offset + pos, maxlen - pos, msg, 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t tmsg_stage_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, tmsg_stage_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __tmsg_stage_t_decode_array(buf, offset + pos, maxlen - pos, msg, 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Task Attributes Message */
int32_t tmsg_args_t_encoded_sz(const tmsg_args_t *msg) {
    return 8 + __tmsg_args_t_encoded_array_sz(msg, 1);
}

int32_t tmsg_args_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const tmsg_args_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __tmsg_args_t_encode_array(buf, offset + pos, maxlen - pos, msg, 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t tmsg_args_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, tmsg_args_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __tmsg_args_t_decode_array(buf, offset + pos, maxlen - pos, msg, 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Send Task Files */
int32_t send_task_file (const char *filename, int32_t sockfd, int32_t flag) {
    int32_t     rc;
    FILE        *fp = fopen(filename, "rb");
    size_t      len = fsize(fp);
    size_t      curr = ftell(fp);
    int32_t     seq = 1;

    while (curr < len) {
        int32_t     r = (len - curr);
        int32_t     n = (r < MAX_BUF_SZ) ? r : MAX_BUF_SZ;
        message_t   msg;

        memset(&msg, 0, sizeof(msg));

        if (1 != (rc = fread(msg.buf, n, 1, fp))) {
            avd_log_error("Expected : %d | Actual : %d", n, sizeof(msg.buf));
            goto bail;
        }

        if (n == MAX_BUF_SZ) {
            set_msg_type(msg.hdr.type, flag);
        } else {
            set_msg_type(msg.hdr.type, (flag << 1));
        }

        msg.hdr.seq_no = seq++;
        msg.hdr.size = MSG_HDR_SZ + n;

        curr = ftell(fp);

        rc = send(sockfd, &msg, msg.hdr.size, 0);
        avd_log_info("Bytes send %d, expected %d", rc, msg.hdr.size);
        if (rc < 0) {
            avd_log_error("Error sending the files: %s", strerror(errno));
            goto bail;
        }

    }

    return 0;

bail:
    return -1;
}

#endif
