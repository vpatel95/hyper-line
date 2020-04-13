#include <stdio.h>
#include <inttypes.h>

#include "avd_pipe.h"
#include "avd_message.h"
#include "avd_session.h"

int32_t ps_init(conn_info_t *conn) {
    int32_t             rc;
    struct sockaddr_in  ps_addr;

    if (0 > (conn->sockfd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))) {
        rc = -errno;
        avd_log_error("Peer Server socket setup failed: %s", strerror(errno));
        return rc;
    }

    rc = inet_pton(AF_INET, conn->addr, &ps_addr.sin_addr.s_addr);
    if (rc == 0) {
        rc = -errno;
        avd_log_error("Peer server IP address invalid format: %s",
                      strerror(errno));
        goto bail;
    }

    if (rc < 0) {
        avd_log_error("Peer server inet_pton error: %s", strerror(errno));
        goto bail;
    }

    ps_addr.sin_family = AF_INET;
    ps_addr.sin_port = htons(conn->port);

    rc = bind(conn->sockfd, (struct sockaddr *)&ps_addr, sizeof(ps_addr));
    if (rc < 0) {
        avd_log_error("Peer server socket bind error: %s", strerror(errno));
        goto bail;
    }

    rc = listen(conn->sockfd, 3);
    if (rc < 0) {
        avd_log_error("Peer server socket listen fail: %s", strerror(errno));
        goto bail;
    }

    avd_log_info("Peer server listening on %s:%d",conn->addr,conn->port);

    return 0;

bail:
    close(conn->sockfd);
    return rc;
}

int32_t send_input_wait_to_peer(int32_t sockfd) {
    int32_t     rc;
    message_t   res;

    memset(&res, 0, sizeof(res));

    set_msg_type(res.hdr.type, AVD_MSG_F_IN_POLL_FL);
    res.hdr.size = MSG_HDR_SZ;
    res.hdr.seq_no = 1;

    if (0 > (rc = send(sockfd, &res, res.hdr.size, 0))) {
        avd_log_error("Send error: %s\n", strerror(errno));
        return rc;
    }

    return 0;
}

int32_t send_input_to_peer(int32_t sockfd, char *filename) {
    int32_t     rc;
    message_t   res;

    memset(&res, 0, sizeof(res));

    set_msg_type(res.hdr.type, AVD_MSG_F_IN_POLL_TR);
    res.hdr.size = MSG_HDR_SZ;
    res.hdr.seq_no = 1;

    if (0 > (rc = send(sockfd, &res, res.hdr.size, 0))) {
        avd_log_error("Send error: %s\n", strerror(errno));
        goto bail;
    }

    if (0 != (rc = send_file(filename, sockfd, AVD_MSG_F_FILE_IN))) {
        avd_log_error("Failed to send task files to the server");
        goto bail;
    }

bail:
    return rc;
}

int32_t process_ps_msg(int32_t sockfd, message_t *msg, peer_server_t *ps) {
    avd_log_debug("Header received ::: [Type : %d] | [Size : %ld]",
                  msg->hdr.type, msg->hdr.size);

    switch(msg->hdr.type) {
        case AVD_MSG_F_IN_POLL:{
            int32_t rc;
            avd_log_warn("Recevied input poll");
            if (worker_output_ready_w_sess() && (!worker_output_sent_w_sess())) {
                if (0 != (rc = send_input_to_peer(sockfd, ps->output_file))) {
                    avd_log_debug("Cannot send file : %s:%s", ps->output_file, strerror(errno));
                    return -1;
                }
                avd_log_warn("Send input file. Updated output_sent to true");
                update_worker_w_sess("output_sent", cJSON_CreateTrue());
            } else {
                send_input_wait_to_peer(sockfd);
            }
            break;
        }
        default:
            avd_log_error("Error");
    }

    return 0;
}

void peer_communication (peer_server_t *ps) {
    int32_t         rc;
    conn_info_t     *p = &ps->peer;
    message_t       rmsg;

    memset(&rmsg, 0, sizeof(rmsg));

#define sockfd p->sockfd
    if (sockfd < 0)
        return;

    while (true) {
        if (0 < recv_avd_hdr(sockfd, &rmsg.hdr)) {
            if (0 > (rc = process_ps_msg(sockfd, &rmsg, ps))) {
                avd_log_error("Error receiving message");
                close_fd(sockfd);
            }
        } else {
            avd_log_error("Error receiving header");
            close_fd(sockfd);
        }
    }
#undef sockfd
}

bool get_file_details(peer_server_t *ps) {
    int32_t     rc;
    char        *str = NULL;

    if (0 > (rc = get_worker_type_w_sess())) {
        avd_log_info("Waiting for worker type");
        goto bail;
    }
    ps->type = rc;

    if (NULL == (str = get_worker_out_file_w_sess())) {
        avd_log_info("Waiting for worker output file");
        goto bail;
    }
    ps->output_file = (char *)malloc(strlen(str)+1);
    snprintf(ps->output_file, strlen(str)+1, "%s", str);

    if (NULL == (str = get_worker_in_file_w_sess())) {
        avd_log_info("Waiting for worker input file");
        goto bail;
    }
    ps->input_file = (char *)malloc(strlen(str)+1);
    snprintf(ps->input_file, strlen(str)+1, "%s", str);

    return true;

bail:
    return false;
}

void * peer_server_routine (void *arg) {
    int32_t             rc;
    socklen_t           sz;
    peer_server_t       *ps = (peer_server_t *)(arg);
    conn_info_t         *conn = &ps->conn;
    conn_info_t         *p = &ps->peer;
    struct sockaddr_in  p_addr;

    if (0 > (rc = ps_init(conn))) {
        avd_log_error("Peer server init failed: %s", strerror(errno));
        close(conn->sockfd);
        exit(EXIT_FAILURE);
    }

    while(!get_file_details(ps)) {
        avd_log_debug("Waiting for worker id");
        msleep(1000);
    }

    rc = accept(conn->sockfd, (struct sockaddr *)&p_addr, &sz);
    if (rc < 0) {
        rc = -errno;
        avd_log_error("Peer accept connection failed: %s", strerror(errno));
        goto bail;
    }

    p->sockfd = rc;
    p->port = sock_ntop_port(&p_addr);

    p->addr = (char *)malloc(INET_ADDRSTRLEN);
    snprintf(p->addr, INET_ADDRSTRLEN, "%s",sock_ntop_addr(&p_addr));

    avd_log_info("Peer connected: %s:%d", p->addr, p->port);
    avd_log_debug("\tPeer Info:\n\t\tsockfd: %d", p->sockfd);

    peer_communication (ps);

bail:
    return NULL;
}
