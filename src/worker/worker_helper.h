#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>

#include "avd_pipe.h"
#include "avd_message.h"
#include "avd_session.h"

typedef int32_t (*stage_process)(FILE *in, FILE *op, int32_t offset);

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

int32_t recv_task_stage(worker_t *w, message_t *rmsg, int32_t sockfd) {
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

    if (0 != recv_file(w->bin_file, sockfd, AVD_MSG_F_FILE_TSK)) {
        avd_log_error("Error receiving Task File");
        return -1;
    }

    if (w->stg_num == 1) {
        if (0 != recv_file(w->input_file, sockfd, AVD_MSG_F_FILE_IN)) {
            avd_log_error("Error receiving Task File");
            return -1;
        }
    }

    update_worker_w_sess("task_rcvd", cJSON_CreateTrue());
    return 0;

}

bool task_ready(worker_t *w) {
    int32_t         rc, sz;
    int32_t         wmsg_sz;
    int32_t         data_sz;
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

            if (0 != recv_task_stage(w, &rmsg, conn->sockfd)) {
                avd_log_error("Error occured while receiving task");
                return false;
            }

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

            w->ps.addr = (char *)malloc(strlen(m.peer_addr)+1);
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

int32_t reconnect(worker_t *w) {
    int32_t         rc = -1;
    int32_t         wmsg_sz;
    int32_t         data_sz;
    int32_t         sz;
    message_t       msg;
    message_t       rmsg;
    conn_info_t     *conn = &w->conn;

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    set_msg_type(msg.hdr.type, AVD_MSG_F_RE_CON);
    avd_log_info("Restored user session");

    wmsg_rc_t wmsg;
    wmsg.wid = w->id;
    wmsg.uname = (char *)malloc(strlen(w->uname)+1);
    snprintf(wmsg.uname, strlen(w->uname)+1, "%s", w->uname);

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

    w->id = m.wid;
    w->poll_id = m.poll_id;

    int32_t len = ar_len + tf_len + 2;
    w->bin_file = (char *)malloc(len);
    snprintf(w->bin_file, len, "%s/%s", APP_ROOT, TASK_FILE);

    len = ar_len + in_len + 2;
    w->input_file = (char *)malloc(len);
    snprintf(w->input_file, len, "%s/%s", APP_ROOT, INPUT_FILE);

    len = ar_len + op_len + 2;
    w->output_file = (char *)malloc(len);
    snprintf(w->output_file, len, "%s/%s", APP_ROOT, OUTPUT_FILE);

    update_worker_w_sess("id", cJSON_CreateNumber(w->id));
    update_worker_w_sess("poll_id", cJSON_CreateNumber(w->poll_id));

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

    int32_t len = ar_len + tf_len + 2;
    w->bin_file = (char *)malloc(len);
    snprintf(w->bin_file, len, "%s/%s", APP_ROOT, TASK_FILE);

    len = ar_len + in_len + 2;
    w->input_file = (char *)malloc(len);
    snprintf(w->input_file, len, "%s/%s", APP_ROOT, INPUT_FILE);

    len = ar_len + op_len + 2;
    w->output_file = (char *)malloc(len);
    snprintf(w->output_file, len, "%s/%s", APP_ROOT, OUTPUT_FILE);

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

void server_communication (worker_t *w) {
    bool            process = true;
    message_t       rmsg;
    conn_info_t     *conn = &w->conn;

    memset(&rmsg, 0, sizeof(rmsg));

#define sockfd conn->sockfd
    if (sockfd < 0)
        return;

    while (!task_ready(w)) {
        msleep(200);
    }

    if (w->stg_num != 1 && !w->peer_id) {
        while (!peers_identified(w)) {
            sleep(5);
        }
    } else {
        w->peer_id = true;
        update_worker_w_sess("peer_id", cJSON_CreateTrue());
    }

    void *stage_injector = dlopen(w->bin_file, (RTLD_LAZY | RTLD_GLOBAL));
    if (NULL == stage_injector) {
        avd_log_error("dlopen error: %s", dlerror());
        exit(EXIT_FAILURE);
    }

    stage_process stage_executer = (stage_process)dlsym(stage_injector, w->func);

    int32_t     i = 1;
    int32_t     offset = 0;
    while(process) {

        switch ( w->type ) {
            case BASE_WORKER:{
                update_worker_w_sess("output_sent", cJSON_CreateFalse());
                update_worker_w_sess("output_ready", cJSON_CreateFalse());

                FILE        *in = fopen(w->input_file, "rb+");
                FILE        *op = fopen(w->output_file, "wb+");

                if (0 > (offset = stage_executer(in, op, offset))) {
                    avd_log_error("Error executing during task: %s", dlerror());
                    exit(EXIT_FAILURE);
                }

                fclose(in);
                fclose(op);

                avd_log_info("Executed stage %d, %d-th time, offset : %d",
                            w->stg_num, i++, offset);

                update_worker_w_sess("output_ready", cJSON_CreateTrue());

                while (!worker_output_sent_w_sess()) {
                    msleep(200);
                }

                if (offset == 0) {
                    avd_log_info("Task completed");
                    update_worker_w_sess("task_fin", cJSON_CreateTrue());
                    process = false;
                    break;
                }

                break;
            }
            case MID_WORKER:{
                while (!worker_input_recv_w_sess()) {
                    msleep(200);
                }

                if (worker_task_fin_w_sess()) {
                    avd_log_info("Task completed");
                    process = false;
                    break;
                }

                update_worker_w_sess("input_recv", cJSON_CreateFalse());
                update_worker_w_sess("output_sent", cJSON_CreateFalse());
                update_worker_w_sess("output_ready", cJSON_CreateFalse());

                FILE        *in = fopen(w->input_file, "rb+");
                FILE        *op = fopen(w->output_file, "wb+");

                if (0 > (offset = stage_executer(in, op, offset))) {
                    avd_log_error("Error executing during task: %s", dlerror());
                    exit(EXIT_FAILURE);
                }

                fclose(in);
                fclose(op);

                avd_log_info("Executed stage %d, %d-th time, offset : %d",
                            w->stg_num, i++, offset);


                update_worker_w_sess("output_ready", cJSON_CreateTrue());

                while (!worker_output_sent_w_sess()) {
                    msleep(200);
                }

                avd_log_debug("Updated get_input to true");
                update_worker_w_sess("get_input", cJSON_CreateTrue());

                break;
            }
            case END_WORKER:{
                int32_t     rc;

                while (!worker_input_recv_w_sess()) {
                    msleep(200);
                }

                if (worker_task_fin_w_sess()) {
                    avd_log_info("Task completed");

                    int32_t     wmsg_sz;
                    int32_t     data_sz;
                    wmsg_tf_t   wmsg;
                    message_t   res;

                    memset(&res, 0, sizeof(res));

                    wmsg.wid = w->id;
                    wmsg.tid = w->tid;
                    wmsg.uname = (char *)malloc(strlen(w->uname)+1);
                    snprintf(wmsg.uname, strlen(w->uname)+1, "%s", w->uname);

                    wmsg_sz = wmsg_tf_t_encoded_sz(&wmsg);
                    data_sz = wmsg_tf_t_encode(res.buf, 0, wmsg_sz, &wmsg);

                    set_msg_type(res.hdr.type, AVD_MSG_F_TASK_FIN);
                    res.hdr.size = MSG_HDR_SZ + data_sz;
                    res.hdr.seq_no = 1;

                    if (0 > (rc = send(sockfd, &res, res.hdr.size, 0))) {
                        avd_log_error("Send error: %s\n", strerror(errno));
                    }

                    if (0 != send_file(w->output_file, sockfd, AVD_MSG_F_FILE_OUT)) {
                        avd_log_error("Cannot send consolidated output to server");
                        return;
                    }

                    process = false;
                    break;
                }

                FILE        *in = fopen(w->input_file, "rb+");
                FILE        *op = fopen(w->output_file, "ab+");

                update_worker_w_sess("input_recv", cJSON_CreateFalse());

                if (0 > (offset = stage_executer(in, op, offset))) {
                    avd_log_error("Error executing during task: %s", dlerror());
                    exit(EXIT_FAILURE);
                }

                fclose(in);
                fclose(op);

                avd_log_info("Executed stage %d, %d-th time, offset : %d",
                            w->stg_num, i++, offset);

                avd_log_debug("Updated get_input to true");
                update_worker_w_sess("get_input", cJSON_CreateTrue());

                break;
            }
            default:
                avd_log_error("Unexpected worker type : %d", w->type);
                exit(EXIT_FAILURE);
                break;
        }

    }
#undef sockfd
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

