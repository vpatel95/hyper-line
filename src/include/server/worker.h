#include <stdio.h>
#include <inttypes.h>

#include "avd_pipe.h"
#include "avd_message.h"
#include "avd_session.h"

worker_t * get_worker_from_sockfd(server_t *srvr, int32_t sockfd) {
    int32_t     idx;
    worker_t    *w;
    for (idx = 0; idx < srvr->n_clients; idx++) {
        w= &srvr->workers[idx];
        if (w->conn.sockfd == sockfd) {
            return w;
        }
    }

    return NULL;
}

void close_worker_connection(server_t *srvr, int32_t sockfd, int32_t poll_id, worker_t * w) {

    srvr->n_clients--;
    close(sockfd);
    srvr->poller[poll_id].fd = -1;

    if (NULL == w) {
        avd_log_info("Cleared stale connection\n\tsockfd : %d\n\tpoll_id : %d",sockfd, poll_id);
        return;
    }

    avd_log_info("Worker connection closed. Worker id : %d", w->id);
    avd_log_debug("sockfd : %d, ", w->conn.sockfd);
    avd_log_debug("poll_id : %d", w->poll_id);

    memset(w, 0, sizeof(worker_t));
}

int32_t task_poll_response_not_ready(int32_t sockfd) {
    int32_t     rc;
    message_t   res;

    memset(&res, 0, sizeof(res));

    set_msg_type(res.hdr.type, AVD_MSG_F_TASK_POLL_FL);
    res.hdr.size = MSG_HDR_SZ;
    res.hdr.seq_no = 1;

    if (0 > (rc = send(sockfd, &res, res.hdr.size, 0))) {
        avd_log_error("Send error: %s\n", strerror(errno));
        return rc;
    }

    return 0;
}

int32_t task_poll_response_ready(worker_t *w, int32_t sockfd, int32_t idx) {
    int32_t     k, rc;
    int32_t     smsg_sz;
    message_t   res;
    smsg_ts_t   smsg;
    cJSON       *task = cJSON_CreateObject();

    memset(&res, 0, sizeof(res));

    cJSON *name = get_task_field_by_idx_s_sess(w->uname, idx, "name");
    w->tname = (char *)malloc(strlen(name->valuestring)+1);
    snprintf(w->tname, strlen(name->valuestring)+1, "%s", name->valuestring);

    cJSON_AddItemToObject(task, "name", cJSON_CreateString(w->tname));

    cJSON *tid = get_task_field_by_idx_s_sess(w->uname, idx, "id");
    w->tid = tid->valueint;
    smsg.tid = w->tid;

    cJSON_AddItemToObject(task, "id", cJSON_CreateNumber(smsg.tid));

    cJSON *stages = get_task_field_by_idx_s_sess(w->uname, idx, "stages");
    for (k = 0; k < cJSON_GetArraySize(stages); k++) {
        cJSON *stg = cJSON_GetArrayItem(stages, k);

        if(cJSON_IsFalse(cJSON_GetObjectItem(stg, "assigned"))) {
            cJSON *v = cJSON_GetObjectItem(stg, "num");
            if ((!v) || (!v->valueint)) {
                avd_log_error("Cannot get stage number");
                rc = -1;
                goto bail;
            }
            w->stg_num = v->valueint;
            smsg.stg_num = w->stg_num;

            cJSON_AddItemToObject(task, "stg_num", cJSON_CreateNumber(smsg.stg_num));

            v = cJSON_GetObjectItem(stg, "func");
            if ((!v) || (!v->valuestring)) {
                avd_log_error("Cannot get func of the stage");
                rc = -1;
                goto bail;
            }
            w->func = (char *)malloc(strlen(v->valuestring)+1);
            snprintf(w->func, strlen(v->valuestring)+1, "%s", v->valuestring);

            smsg.func = (char *)malloc(strlen(w->func)+1);
            snprintf(smsg.func, strlen(w->func)+1, "%s", w->func);

            cJSON_AddItemToObject(task, "func", cJSON_CreateString(smsg.func));
            update_stage_field_by_idx_s_sess(w->uname, idx, k, "assigned", cJSON_CreateTrue());
            update_stage_field_by_idx_s_sess(w->uname, idx, k, "wid", cJSON_CreateNumber(w->id));

            v = get_task_field_by_idx_s_sess(w->uname, idx, "unassigned_stages");
            update_task_field_by_idx_s_sess(w->uname, idx, "unassigned_stages",
                                            cJSON_CreateNumber(v->valueint - 1));

            v = get_user_field_s_sess(w->uname, "unassigned_workers");
            update_user_s_sess(w->uname, "unassigned_workers", cJSON_CreateNumber(v->valueint-1));


            break;
        }
    }

    update_worker_s_sess(w->id, "task", task);
    update_worker_s_sess(w->id, "assigned", cJSON_CreateTrue());

    smsg_sz = smsg_ts_t_encoded_sz(&smsg);
    smsg_ts_t_encode(res.buf, 0, smsg_sz, &smsg);

    set_msg_type(res.hdr.type, AVD_MSG_F_TASK_POLL_TR);
    res.hdr.size = msg_sz(smsg_ts_t);
    res.hdr.seq_no = 1;

    if (0 > (rc = send(sockfd, &res, res.hdr.size, 0))) {
        avd_log_error("Send error: %s\n", strerror(errno));
        goto bail;
    }
bail:
    return rc;
}

int32_t process_worker_msg(server_t *srvr, int32_t sockfd, message_t *msg, worker_t *w) {
    int32_t     rc = -1;
    size_t      sz;
    size_t      smsg_sz;
    message_t   res;

    memset(&res, 0, sizeof(res));

    avd_log_debug("Header received ::: [Type : %d] | [Size : %ld]",
            msg->hdr.type, msg->hdr.size);

    switch (msg->hdr.type) {
        case AVD_MSG_F_NEW_CON: {
            char            *dir = NULL;
            wmsg_nc_t       m;
            smsg_wrc_t      nc_smsg;

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            wmsg_nc_t_decode(msg->buf, 0, sizeof(msg->buf), &m);

            avd_log_debug("NCON Msg ::: Name : %s | Size : %ld", m.uname, sz);

            if (0 > (rc = add_worker_s_sess(srvr, w, m.uname))) {
                return rc;
            }

            w->uname = (char *)malloc(strlen(m.uname)+1);
            snprintf(w->uname, strlen(m.uname)+1, "%s", m.uname);

            set_msg_type(res.hdr.type, AVD_MSG_F_NEW_CON);
            res.hdr.seq_no = 1;

            nc_smsg.wid = w->id;
            nc_smsg.poll_id = w->poll_id;

            smsg_sz = smsg_wrc_t_encoded_sz(&nc_smsg);
            smsg_wrc_t_encode(res.buf, 0, smsg_sz, &nc_smsg);
            res.hdr.size = msg_sz(smsg_wrc_t);

            if (NULL == (dir = get_or_create_worker_dir(w))) {
                avd_log_error("Failed to create the worker directory");
                //TODO handle the error
                return -1;
            }

            w->dir = dir;

            rc = send(sockfd, &res, res.hdr.size, 0);
            if (rc < 0) {
                rc = -errno;
                avd_log_error("Send error: %s\n", strerror(errno));
                return rc;;
            }
            break;
        }
        case AVD_MSG_F_RE_CON: {
            char        *dir = NULL;
            wmsg_rc_t   m;
            smsg_wrc_t  rc_smsg;

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                if (0 > (rc = recv_avd_msg(sockfd, msg->buf, sz))) {
                    return rc;
                }
            }

            wmsg_rc_t_decode(msg->buf, 0, sizeof(msg->buf), &m);

            avd_log_debug("RCON Msg ::: Wid : %d | Size : %ld", m.wid, sz);

            if (!worker_exists_s_sess(m.wid)) {
                avd_log_error("Failed to find worker session with reconnect id %d", m.wid);
                return -1;
            }

            w->id = m.wid;
            w->uname = (char *)malloc(strlen(m.uname)+1);
            snprintf(w->uname, strlen(m.uname)+1, "%s", m.uname);

            update_user_s_sess(m.uname, "poll_id", cJSON_CreateNumber(w->poll_id));


            rc_smsg.wid = w->id;
            rc_smsg.poll_id = w->poll_id;

            smsg_sz = smsg_wrc_t_encoded_sz(&rc_smsg);
            smsg_wrc_t_encode(res.buf, 0, smsg_sz, &rc_smsg);

            set_msg_type(res.hdr.type, AVD_MSG_F_RE_CON);
            res.hdr.size = msg_sz(smsg_wrc_t);
            res.hdr.seq_no = 1;

            if (NULL == (dir = get_or_create_worker_dir(w))) {
                avd_log_error("Failed to create the worker directory");
                //TODO handle the error
                return -1;
            }

            w->dir = dir;

            if (0 > (rc = send(sockfd, &res, res.hdr.size, 0))) {
                avd_log_error("Send error: %s\n", strerror(errno));
                return rc;
            }

            break;
        }
        case AVD_MSG_F_TASK_POLL: {
            wmsg_tr_t   m;
            int32_t     i;
            int32_t     unassigned_wrk;
            int32_t     unassigned_stg;
            int32_t     num_tasks;

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                if (0 > (rc = recv_avd_msg(sockfd, msg->buf, sz))) {
                    return rc;
                }
            }

            wmsg_tr_t_decode(msg->buf, 0, sizeof(msg->buf), &m);
            avd_log_debug("Task Poll Msg ::: Wid : %d | Uname : %s", m.wid, m.uname);

            num_tasks = get_user_task_num_s_sess(w->uname);
            unassigned_wrk = get_user_unassigned_worker_num_s_sess(w->uname);
            for (i = 0; i < num_tasks; i++) {
                if (0 < (unassigned_stg = get_task_unassigned_stage_num_s_sess(w->uname, i))) {
                    avd_log_debug("t:%d, w:%d | s:%d", num_tasks, unassigned_wrk, unassigned_stg);
                    if (unassigned_wrk >= unassigned_stg) {
                        task_poll_response_ready(w, sockfd, i);
                        break;
                    }
                }

            }

            if (i == num_tasks) {
                task_poll_response_not_ready(sockfd);
            }

            break;
        }
        case AVD_MSG_F_CLOSE: {
            remove_worker_s_sess(w->id);
            close_worker_connection(srvr, sockfd, w->poll_id, w);
            break;
        }
        default:
            avd_log_error("Error");
    }
    return 0;
}

void worker_communications(server_t *srvr, int nready) {

    int32_t         i;
    int32_t         rc;
    message_t       rmsg;

    memset(&rmsg, 0, sizeof(rmsg));

#define w_poll srvr->poller
    for (i = 1; i <= srvr->curr_poll_sz; i++) {
#define sockfd w_poll[i].fd
        if (sockfd < 0) {
            continue;
        }

        worker_t *w= get_worker_from_sockfd(srvr, sockfd);
        if (NULL == w) {
            close_worker_connection(srvr, sockfd, i, w);
            continue;
        }

        if (w_poll[i].revents & (POLLRDNORM | POLLERR)) {
            if (0 < recv_avd_hdr(sockfd, &rmsg.hdr)) {
                if (0 > (rc = process_worker_msg(srvr, sockfd, &rmsg, w))) {
                    avd_log_error("Error receiving message");
                    close_worker_connection(srvr, sockfd, i, w);
                }
            } else {
                avd_log_error("Error receiving header");
                close_worker_connection(srvr, sockfd, i, w);
            }

            nready -= 1;

            if (nready <= 0) {
                break;
            }
        }
#undef sockfd
    }
#undef w_poll
}

int32_t connect_worker(server_t *srvr) {

    int32_t             i, j, rc = 0;
    int32_t             nready;
    int32_t             worker_fd;
    socklen_t           worker_addr_sz;
    struct sockaddr_in  worker_addr;
    conn_info_t         *s_conn = &srvr->conn;
    worker_t            *w;

#define w_poll srvr->poller

    nready = poll(w_poll, srvr->curr_poll_sz + 1, INFTIM);

    if (w_poll[0].revents & POLLRDNORM) {

        worker_addr_sz = sizeof(worker_addr);

        worker_fd = accept(s_conn->sockfd, (struct sockaddr *)&worker_addr, &worker_addr_sz);
        if (worker_fd < 0) {
            rc = -errno;
            avd_log_error("Worker Accept connection failed: %s\n", strerror(errno));
            goto bail;
        }

        for (j = 0; j < MAX_WORKER; j++) {
            if (srvr->workers[j].id == 0) {
                w= &srvr->workers[j];
                break;
            }
        }

        if (j == MAX_WORKER) {
            avd_log_warn("Too many Workers connected");
            memset(w, 0, sizeof(worker_t));
            goto bail;
        }

        for (i = 1; i < srvr->max_poll_sz; i++) {
            if (w_poll[i].fd < 0) {

                w_poll[i].fd = worker_fd;
                w_poll[i].events = POLLRDNORM;

                w->file_seq_no = 1;
                w->conn.sockfd = worker_fd;
                w->poll_id = i;
                w->conn.port = sock_ntop_port((struct sockaddr *)&worker_addr);
                snprintf(w->conn.ip_addr_s, INET_ADDRSTRLEN, "%s",
                         sock_ntop_addr((struct sockaddr *)&worker_addr));

                srvr->n_clients += 1;

                avd_log_info("New Worker connected: %s",
                              sock_ntop((struct sockaddr *)&worker_addr));
                avd_log_debug("\tWorker Info:\n\t\tsockfd : %d\n\t\tpoll_id : %d",
                               w->conn.sockfd, w->poll_id);
                break;
            }
        }

#undef worker_poll

        if (i == srvr->max_poll_sz) {
            avd_log_warn("Too many Workers connected\n");
            memset(w, 0, sizeof(worker_t));
            goto bail;
        }


        if (i > srvr->curr_poll_sz)
            srvr->curr_poll_sz = i;

        nready--;

    }

bail:
    return rc;
}

int32_t worker_task_dispatch_poll() {
    return 0;
}
