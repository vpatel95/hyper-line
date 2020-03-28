#include "avd_pipe.h"
#include "avd_log.h"
#include "avd_message.h"
#include "avd_session.h"

char    *g_conf_file_name = NULL;

int32_t worker_init () {

    int32_t             rc;
    int32_t             srvr_fd;

    srvr_fd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (srvr_fd < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Worker socket setup failed: %s\n",
                strerror(errno));

        goto error;
    }

    return srvr_fd;

error:
    close_fd(srvr_fd);
    return rc;
}

int32_t recv_task_stage(worker_t *worker, message_t *rmsg) {
    smsg_ts_t   m;

    smsg_ts_t_decode(rmsg->buf, 0, sizeof(rmsg->buf), &m);

    cJSON *task = cJSON_CreateObject();

    worker->tid = m.tid;
    cJSON_AddItemToObject(task, "id", cJSON_CreateNumber(m.tid));

    worker->stg_num = m.stg_num;
    cJSON_AddItemToObject(task, "num", cJSON_CreateNumber(m.stg_num));

    worker->func = (char *)malloc(strlen(m.func)+1);
    snprintf(worker->func, strlen(m.func)+1, "%s", m.func);
    cJSON_AddItemToObject(task, "func", cJSON_CreateString(m.func));

    update_worker_w_sess("assigned", cJSON_CreateTrue());
    update_worker_w_sess("task", task);

    return 0;

}

bool task_ready(worker_t *worker) {
    int32_t         rc;
    int32_t         wmsg_sz;
    int32_t         sz;
    message_t       msg;
    message_t       rmsg;
    wmsg_tr_t       wmsg;
    conn_info_t     *conn = &worker->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    wmsg.uname = (char *)malloc(strlen(worker->uname)+1);

    wmsg.wid = worker->id;
    snprintf(wmsg.uname, strlen(worker->uname)+1, "%s", worker->uname);

    wmsg_sz = wmsg_tr_t_encoded_sz(&wmsg);
    wmsg_tr_t_encode(msg.buf, 0, wmsg_sz, &wmsg);

    set_msg_type(msg.hdr.type, AVD_MSG_F_TASK_POLL);
    msg.hdr.size = msg_sz(wmsg);
    msg.hdr.seq_no = 1;

    if (0 > (rc = send(conn->sockfd, &msg, msg.hdr.size, 0))) {
        avd_log_error("Task poll error: %s", strerror(errno));
        goto bail;
    }
    avd_log_debug("Task Ready Poll ::: wid:%d | uname:%s", worker->id, worker->uname);

    if (0 < recv_avd_hdr(conn->sockfd, &rmsg.hdr)) {
        if (is_msg_type(rmsg.hdr.type, AVD_MSG_F_TASK_POLL_TR)) {
            if (0 < (sz = (rmsg.hdr.size - MSG_HDR_SZ))) {
                rc = recv_avd_msg(conn->sockfd, rmsg.buf, sz);
            }

            recv_task_stage(worker, &rmsg);
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

void server_communication (worker_t *worker) {
    message_t       rmsg;
    conn_info_t     *conn = &worker->conn;

    memset(&rmsg, 0, sizeof(rmsg));

#define sockfd conn->sockfd
    if (sockfd < 0)
        return;

    while (!task_ready(worker)) {
        sleep(5);
    }

    while (true) {
        usleep(1000);
    }
#undef sockfd
}

int32_t reconnect(worker_t *worker) {
    int32_t         rc = -1;
    int32_t         wmsg_sz;
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
    wmsg_rc_t_encode(msg.buf, 0, wmsg_sz, &wmsg);
    msg.hdr.size = msg_sz(wmsg_rc_t);

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

int32_t new_connection(worker_t *worker) {
    int32_t         rc = -1;
    int32_t         wmsg_sz;
    int32_t         sz;
    message_t       msg;
    message_t       rmsg;
    conn_info_t     *conn = &worker->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    set_msg_type(msg.hdr.type, AVD_MSG_F_NEW_CON);
    avd_log_info("Worker session not found. Creating new connection");

    wmsg_nc_t wmsg;
    wmsg.uname = (char *)malloc(strlen(worker->uname)+1);
    snprintf(wmsg.uname, strlen(worker->uname)+1, "%s", worker->uname);

    wmsg_sz = wmsg_nc_t_encoded_sz(&wmsg);
    wmsg_nc_t_encode(msg.buf, 0, wmsg_sz, &wmsg);
    msg.hdr.size = msg_sz(wmsg_nc_t);

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

    worker->id = m.wid;
    worker->poll_id = m.poll_id;

    create_worker_w_sess(worker);

    return 0;
bail:
    return rc;
}

int32_t connect_server(worker_t *worker) {

    int32_t             rc = -1;
    conn_info_t         *conn = &worker->conn;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = worker_init();

    if (0 == (rc = inet_pton(AF_INET, conn->ip_addr_s, &srvr_addr.sin_addr.s_addr))) {
        avd_log_error("Server IP inet_pton error:%s", strerror(errno));
        goto bail;
    }
    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    avd_log_debug("Connecting to server on %s:%d", conn->ip_addr_s, conn->port);
    if (0 > (rc = connect(conn->sockfd, (struct sockaddr *)&srvr_addr, sizeof(srvr_addr)))) {
        avd_log_fatal("Error connecting to the server at \"%s:%d\" : %s",
                conn->ip_addr_s, conn->port, strerror(errno));
        goto bail;
    }

    avd_log_info("Connected to server on %s", sock_ntop((struct sockaddr *)&srvr_addr));

    if (0 != (rc = check_and_get_w_sess(worker))) {
        new_connection(worker);
    } else {
        reconnect(worker);
    }

    return 0;

bail:
    close_fd(conn->sockfd);
    return rc;
}

int32_t start_worker (worker_t *worker) {
    int32_t         rc;

    rc = connect_server(worker);
    if (rc < 0) {
        avd_log_error("Cannot establish connection with server: %s\n.", strerror(errno));
        goto bail;
    }

    server_communication(worker);

bail:
    return rc;
}

void setup_logger(log_info_t *logger) {
    set_log_file(logger->log_file);
    set_log_level(logger->level);
    set_log_quiet(logger->quiet);
};


int32_t main (int32_t argc, char *argv[]) {

    worker_t        worker;
    memset(&worker, 0, sizeof(worker));

    signal_intr(SIGINT, sig_int_handler);

    g_conf_file_name = (char *)argv[1];

    if (argc < 2)
        exit(EXIT_FAILURE);

    if (0 != process_config_file(g_conf_file_name, WORKER, &worker)) {
        print("Failed to parse config file %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    setup_logger(&worker.logger);

    start_worker(&worker);
    return EXIT_SUCCESS;
}
