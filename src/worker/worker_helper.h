#include <stdio.h>
#include <inttypes.h>

#include "avd_pipe.h"
#include "avd_message.h"
#include "avd_session.h"

int32_t worker_init () {

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

int32_t recv_task_stage(worker_t *w, message_t *rmsg) {
    smsg_ts_t   m;

    smsg_ts_t_decode(rmsg->buf, 0, sizeof(rmsg->buf), &m);

    cJSON *task = cJSON_CreateObject();

    w->tid = m.tid;
    cJSON_AddItemToObject(task, "id", cJSON_CreateNumber(m.tid));

    w->stg_num = m.stg_num;
    cJSON_AddItemToObject(task, "num", cJSON_CreateNumber(m.stg_num));

    w->total_stg = m.total_stg;
    cJSON_AddItemToObject(task, "num_stages", cJSON_CreateNumber(m.total_stg));

    w->func = (char *)malloc(strlen(m.func)+1);
    snprintf(w->func, strlen(m.func)+1, "%s", m.func);
    cJSON_AddItemToObject(task, "func", cJSON_CreateString(m.func));

    if (w->stg_num == 1)
        w->type = BASE_WORKER;
    else if (w->stg_num == w->total_stg)
        w->type = END_WORKER;
    else
        w->type = MID_WORKER;

    update_worker_w_sess("type", cJSON_CreateNumber(w->type));
    update_worker_w_sess("assigned", cJSON_CreateTrue());
    update_worker_w_sess("task", task);

    return 0;

}

bool task_ready(worker_t *w) {
    int32_t         rc;
    int32_t         wmsg_sz;
    int32_t         data_sz;
    int32_t         sz;
    message_t       msg;
    message_t       rmsg;
    wmsg_tr_t       wmsg;
    conn_info_t     *conn = &w->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    wmsg.uname = (char *)malloc(strlen(w->uname)+1);

    wmsg.wid = w->id;
    snprintf(wmsg.uname, strlen(w->uname)+1, "%s", w->uname);

    wmsg_sz = wmsg_tr_t_encoded_sz(&wmsg);
    data_sz = wmsg_tr_t_encode(msg.buf, 0, wmsg_sz, &wmsg);

    set_msg_type(msg.hdr.type, AVD_MSG_F_TASK_POLL);
    msg.hdr.size = MSG_HDR_SZ + data_sz;
    msg.hdr.seq_no = 1;

    if (0 > (rc = send(conn->sockfd, &msg, msg.hdr.size, 0))) {
        avd_log_error("Task poll error: %s", strerror(errno));
        goto bail;
    }
    avd_log_debug("Task Ready Poll ::: wid:%d | uname:%s", w->id, w->uname);

    if (0 < recv_avd_hdr(conn->sockfd, &rmsg.hdr)) {
        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_TASK_POLL_TR)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(conn->sockfd, rmsg.buf, sz);
            }

            recv_task_stage(w, &rmsg);
            return true;
        }else if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_TASK_POLL_FL)) {
            return false;
        } else {
            avd_log_error("Unexpected message type received %d", rmsg.hdr.type);
            goto bail;
        }
    }

bail:
    return false;
}

bool peers_identified (worker_t *w) {
    int32_t         rc;
    int32_t         wmsg_sz;
    int32_t         data_sz;
    int32_t         sz;
    message_t       msg;
    message_t       rmsg;
    wmsg_pi_t       wmsg;
    conn_info_t     *conn = &w->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    wmsg.uname = (char *)malloc(strlen(w->uname)+1);

    wmsg.wid = w->id;
    wmsg.num = w->stg_num;
    wmsg.tid = w->tid;
    snprintf(wmsg.uname, strlen(w->uname)+1, "%s", w->uname);

    wmsg_sz = wmsg_pi_t_encoded_sz(&wmsg);
    data_sz = wmsg_pi_t_encode(msg.buf, 0, wmsg_sz, &wmsg);

    set_msg_type(msg.hdr.type, AVD_MSG_F_PEER_ID);
    msg.hdr.size = MSG_HDR_SZ + data_sz;
    msg.hdr.seq_no = 1;

    if (0 > (rc = send(conn->sockfd, &msg, msg.hdr.size, 0))) {
        avd_log_error("Task poll error: %s", strerror(errno));
        goto bail;
    }
    avd_log_debug("Task Peer Identification ::: wid:%d | uname:%s",
                  w->id, w->uname);

    if (0 < recv_avd_hdr(conn->sockfd, &rmsg.hdr)) {
        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_PEER_ID_TR)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(conn->sockfd, rmsg.buf, sz);
            }

            smsg_wpi_t  m;
            cJSON       *p = cJSON_CreateObject();

            smsg_wpi_t_decode(rmsg.buf, 0, sizeof(rmsg.buf), &m);

            w->ps_id = m.pid;
            cJSON_AddItemToObject(p, "pid", cJSON_CreateNumber(m.pid));

            w->ps.port = m.peer_port;
            cJSON_AddItemToObject(p, "port", cJSON_CreateNumber(m.peer_port));

            snprintf(w->ps.addr, strlen(m.peer_addr)+1, "%s", m.peer_addr);
            cJSON_AddItemToObject(p, "addr", cJSON_CreateString(m.peer_addr));

            update_worker_w_sess("peer_server", p);
            update_worker_w_sess("peer_id", cJSON_CreateTrue());
            w->peer_id = true;

            return true;
        }else if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_PEER_ID_FL)) {
            return false;
        } else {
            avd_log_error("Unexpected message type received %d",
                          rmsg.hdr.type);
            goto bail;
        }
    }

bail:
    return false;
}

void server_communication (worker_t *w) {
    message_t       rmsg;
    conn_info_t     *conn = &w->conn;

    memset(&rmsg, 0, sizeof(rmsg));

#define sockfd conn->sockfd
    if (sockfd < 0)
        return;

    while (!task_ready(w)) {
        sleep(5);
    }

    if (w->stg_num != 1 && !w->peer_id) {
        while (!peers_identified(w)) {
            sleep(5);
        }
    } else {
        w->peer_id = true;
        update_worker_w_sess("peer_id", cJSON_CreateTrue());
    }

    while (true) {
        usleep(1000);
    }
#undef sockfd
}

int32_t reconnect(worker_t *worker) {
    int32_t         rc = -1;
    int32_t         wmsg_sz;
    int32_t         data_sz;
    int32_t         sz;
    message_t       msg;
    message_t       rmsg;
    conn_info_t     *conn = &worker->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    set_msg_type(msg.hdr.type, AVD_MSG_F_RE_CON);
    avd_log_info("Restored user session");

    wmsg_rc_t wmsg;
    wmsg.wid = worker->id;
    wmsg.uname = (char *)malloc(strlen(worker->uname)+1);
    snprintf(wmsg.uname, strlen(worker->uname)+1, "%s", worker->uname);

    wmsg_sz = wmsg_rc_t_encoded_sz(&wmsg);
    data_sz = wmsg_rc_t_encode(msg.buf, 0, wmsg_sz, &wmsg);
    msg.hdr.size = MSG_HDR_SZ + data_sz;

    if (0 > (rc = send(conn->sockfd, &msg, msg.hdr.size, 0))) {
        avd_log_error("Send error: %s\n", strerror(errno));
        goto bail;
    }

    if (0 < recv_avd_hdr(conn->sockfd, &rmsg.hdr)) {
        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_RE_CON)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(conn->sockfd, rmsg.buf, sz);
            }
        } else {
            avd_log_error("Expecting message type %d, received %d",
                           AVD_MSG_F_RE_CON, rmsg.hdr.type);
            goto bail;
        }
    }

    smsg_wrc_t m;
    smsg_wrc_t_decode(rmsg.buf, 0, sizeof(rmsg.buf), &m);

    worker->id = m.wid;
    worker->poll_id = m.poll_id;

    update_worker_w_sess("id", cJSON_CreateNumber(worker->id));
    update_worker_w_sess("poll_id", cJSON_CreateNumber(worker->poll_id));

    return 0;

bail:
    close_fd(conn->sockfd);
    return rc;

}

int32_t new_connection(worker_t *w) {
    int32_t         rc = -1;
    int32_t         wmsg_sz, data_sz;
    int32_t         sz;
    wmsg_nc_t       wmsg;
    message_t       msg;
    message_t       rmsg;
    conn_info_t     *conn = &w->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    set_msg_type(msg.hdr.type, AVD_MSG_F_NEW_CON);
    avd_log_info("Worker session not found. Creating new connection");

    wmsg.uname = (char *)malloc(strlen(w->uname)+1);
    snprintf(wmsg.uname, strlen(w->uname)+1, "%s", w->uname);

    wmsg.peer_addr = (char *)malloc(strlen(w->peer.addr)+1);
    snprintf(wmsg.peer_addr, strlen(w->peer.addr)+1,
             "%s", w->peer.addr);

    wmsg.peer_port = w->peer.port;
    wmsg_sz = wmsg_nc_t_encoded_sz(&wmsg);
    data_sz = wmsg_nc_t_encode(msg.buf, 0, wmsg_sz, &wmsg);

    avd_log_debug("EC_SZ : %d | AC_SZ : %d",wmsg_sz, data_sz);
    msg.hdr.size = MSG_HDR_SZ + data_sz;

    avd_log_debug("NCON Msg ::: Size : %ld\n\tName : %s\n\tPeer %s:%d",
                  msg.hdr.size, wmsg.uname, wmsg.peer_addr, wmsg.peer_port);
    rc = send(conn->sockfd, &msg, msg.hdr.size, 0);
    if (rc < 0) {
        avd_log_error("Send error: %s\n", strerror(errno));
        goto bail;
    }

    if (0 < recv_avd_hdr(conn->sockfd, &rmsg.hdr)) {
        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_NEW_CON)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(conn->sockfd, rmsg.buf, sz);
            }
        } else {
            avd_log_error("Expecting message type %d, received %d",
                           AVD_MSG_F_NEW_CON, rmsg.hdr.type);
            goto bail;
        }
    }

    smsg_wrc_t m;
    smsg_wrc_t_decode(rmsg.buf, 0, sizeof(rmsg.buf), &m);

    w->id = m.wid;
    w->poll_id = m.poll_id;

    create_worker_w_sess(w);

    return 0;
bail:
    return rc;
}

int32_t connect_server(worker_t *w) {

    int32_t             rc = -1;
    conn_info_t         *conn = &w->conn;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = worker_init();

    if (0 == (rc = inet_pton(AF_INET, conn->addr,
                             &srvr_addr.sin_addr.s_addr))) {
        avd_log_error("Server IP inet_pton error:%s", strerror(errno));
        goto bail;
    }
    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    avd_log_debug("Connecting to server on %s:%d",
                  conn->addr, conn->port);
    if (0 > (rc = connect(conn->sockfd, (struct sockaddr *)&srvr_addr,
                          sizeof(srvr_addr)))) {
        avd_log_fatal("Error connecting to the server at \"%s:%d\" : %s",
                      conn->addr, conn->port, strerror(errno));
        goto bail;
    }

    avd_log_info("Connected to server on %s", sock_ntop(&srvr_addr));

    if (0 != (rc = check_and_get_w_sess(w))) {
        new_connection(w);
    } else {
        reconnect(w);
    }

    return 0;

bail:
    close_fd(conn->sockfd);
    return rc;
}

static void * worker_routine (void *arg) {
    int32_t         rc;
    worker_t        *w = (worker_t *)(arg);
    rc = connect_server(w);
    if (rc < 0) {
        avd_log_error("Cannot establish connection with server: %s",
                      strerror(errno));
        goto bail;
    }

    server_communication(w);

bail:
    return NULL;
}

void setup_logger(log_info_t *logger) {
    set_log_file(logger->log_file);
    set_log_level(logger->level);
    set_log_quiet(logger->quiet);
};

