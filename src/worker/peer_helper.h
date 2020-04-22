#include <stdio.h>
#include <inttypes.h>

#include "avd_pipe.h"
#include "avd_message.h"
#include "avd_session.h"

int32_t peer_init () {
    int32_t             rc;
    int32_t             fd;

    fd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Worker socket setup failed: %s\n",
                strerror(errno));
        goto error;
    }

    return fd;

error:
    close_fd(fd);
    return rc;
}

int32_t connect_peer_server(peer_t *p) {

    int32_t             rc = -1;
    conn_info_t         *ps = &p->ps;
    struct sockaddr_in  ps_addr;

    ps->sockfd = peer_init();

    if (0 == (rc = inet_pton(AF_INET, ps->addr,
                             &ps_addr.sin_addr.s_addr))) {
        avd_log_error("Peer server IP inet_pton error:%s", strerror(errno));
        goto bail;
    }
    ps_addr.sin_family = AF_INET;
    ps_addr.sin_port = htons(ps->port);

    avd_log_debug("Connecting to peer server on %s:%d",
                  ps->addr, ps->port);
    if (0 > (rc = connect(ps->sockfd, (struct sockaddr *)&ps_addr,
                          sizeof(ps_addr)))) {
        avd_log_fatal("Error connecting to the server at \"%s:%d\" : %s",
                      ps->addr, ps->port, strerror(errno));
        goto bail;
    }

    avd_log_info("Connected to peer server on %s", sock_ntop(&ps_addr));

    return 0;

bail:
    close_fd(ps->sockfd);
    return rc;
}

int32_t get_peer_server(peer_t *p) {
    int32_t     rc = -1;
    cJSON       *v = NULL;
    cJSON       *ps = get_peer_server_w_sess();

    v = cJSON_GetObjectItem(ps, "port");
    if ((!v) || (!v->valueint)) {
        avd_log_debug("Cannot find port in peer server");
        goto bail;
    }
    p->ps.port = v->valueint;

    v = cJSON_GetObjectItem(ps, "addr");
    if ((!v) || (!v->valuestring)) {
        avd_log_debug("Cannot find addr in peer server");
        goto bail;
    }
    p->ps.addr = (char *)malloc(strlen(v->valuestring)+1);
    snprintf(p->ps.addr, strlen(v->valuestring)+1, "%s", v->valuestring);

    rc = 0;

bail:
    return rc;
}

bool peer_server_id() {
    return is_peer_id_w_sess();
}

bool get_worker_details(peer_t *p) {
    int32_t     rc;
    char        *str = NULL;

    if (0 > (rc = get_worker_id_w_sess())) {
        avd_log_info("Waiting for worker id");
        goto bail;
    }
    p->wid = rc;

    if (0 > (rc = get_worker_type_w_sess())) {
        avd_log_info("Waiting for worker type");
        goto bail;
    }
    p->type = rc;

    if (NULL == (str = get_worker_out_file_w_sess())) {
        avd_log_info("Waiting for worker output file");
        goto bail;
    }
    p->output_file = (char *)malloc(strlen(str)+1);
    snprintf(p->output_file, strlen(str)+1, "%s", str);

    if (NULL == (str = get_worker_in_file_w_sess())) {
        avd_log_info("Waiting for worker input file");
        goto bail;
    }
    p->input_file = (char *)malloc(strlen(str)+1);
    snprintf(p->input_file, strlen(str)+1, "%s", str);

    return true;

bail:
    return false;
}

bool input_ready(peer_t *p) {
    int32_t         rc, sz;
    message_t       msg;
    message_t       rmsg;
    conn_info_t     *ps = &p->ps;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    if (worker_shutdown_w_sess()) {
        set_msg_type(msg.hdr.type, AVD_MSG_F_CLOSE);
        msg.hdr.size = MSG_HDR_SZ;
        msg.hdr.seq_no = 1;

        if (0 > (rc = send(ps->sockfd, &msg, msg.hdr.size, 0))) {
            avd_log_error("Task poll error: %s", strerror(errno));
            goto bail;
        }

        close(ps->sockfd);
        pthread_exit(NULL);
    }

    if(!worker_get_input_w_sess() && !worker_task_fin_w_sess()) {
        goto bail;
    }

    set_msg_type(msg.hdr.type, AVD_MSG_F_IN_POLL);
    msg.hdr.size = MSG_HDR_SZ;
    msg.hdr.seq_no = 1;

    if (0 > (rc = send(ps->sockfd, &msg, msg.hdr.size, 0))) {
        avd_log_error("Task poll error: %s", strerror(errno));
        goto bail;
    }
    avd_log_debug("Input Poll");

    if (0 < recv_avd_hdr(ps->sockfd, &rmsg.hdr)) {
        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_TASK_FIN)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(ps->sockfd, rmsg.buf, sz);
            }

            update_worker_w_sess("task_fin", cJSON_CreateTrue());
            update_worker_w_sess("input_recv", cJSON_CreateTrue());
            return true;
        }

        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_IN_POLL_TR)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(ps->sockfd, rmsg.buf, sz);
            }

            if (0 != recv_file(p->input_file, ps->sockfd, AVD_MSG_F_FILE_IN)) {
                avd_log_error("Error occured while receiving input from peer");
                return false;
            }
            avd_log_debug("Updated get_input to false");
            update_worker_w_sess("get_input", cJSON_CreateFalse());
            avd_log_debug("Recevied input file. Updated input_recv to true");
            update_worker_w_sess("input_recv", cJSON_CreateTrue());

            return true;
        }else if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_IN_POLL_FL)) {
            return false;
        } else {
            avd_log_error("Unexpected message type received %d", rmsg.hdr.type);
            goto bail;
        }
    }

bail:
    return false;
}

static void * peer_routine (void * arg) {
    int32_t     rc;
    peer_t      *p = (peer_t *)(arg);

    while (!get_worker_details(p)) {
        avd_log_debug("Waiting for worker id");
        msleep(1000);
    }

    if (p->type == BASE_WORKER) {
        pthread_exit(NULL);
    }

    while (!peer_server_id()) {
        avd_log_debug("Waiting for peer server");
        sleep(5);
    }

    if (0 > (rc = get_peer_server(p))) {
        avd_log_error("Cannot get peer server details");
        goto bail;
    }

    if (0 > (rc = connect_peer_server(p))) {
        avd_log_error("Cannot establish connection with peer server: %s",
                      strerror(errno));
        goto bail;
    }

    while (true) {
        msleep(500);

        while (!input_ready(p)) {
            msleep(200);
        }
    }

bail:
    pthread_exit(NULL);;
}
