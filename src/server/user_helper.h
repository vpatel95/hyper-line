#include <stdio.h>
#include <inttypes.h>

#include "avd_pipe.h"
#include "avd_message.h"
#include "avd_session.h"

user_t * get_user_from_sockfd(server_t *srvr, int32_t sockfd) {
    int32_t     idx;
    user_t      *u;
    for (idx = 0; idx < MAX_USER; idx++) {
        u= &srvr->users[idx];
        if (u->conn.sockfd == sockfd) {
            return u;
        }
    }

    return NULL;
}

void close_user_connection(server_t *srvr, int32_t sockfd,
                           int32_t poll_id, user_t *u) {

    srvr->n_clients--;
    close(sockfd);
    srvr->poller[poll_id].fd = -1;

    if (NULL == u) {
        avd_log_info("Cleared stale\n\tsockfd : %d\n\tpoll_id : %d",
                     sockfd, poll_id);
        return;
    }

    avd_log_info("User connection closed. User id : %d", u->id);
    avd_log_debug("sockfd : %d, ", u->conn.sockfd);
    avd_log_debug("poll_id : %d", u->poll_id);

    memset(u, 0, sizeof(user_t));

}

//TODO : Break this into smaller functions
int32_t process_user_msg(server_t *srvr, int32_t sockfd,
                         message_t *msg, user_t *u) {
    int32_t     i, j, rc = -1;
    size_t      sz;
    size_t      smsg_sz;
    int32_t     data_sz;
    message_t   res;

    memset(&res, 0, sizeof(res));

    avd_log_debug("Header received ::: [Type : %d] | [Size : %ld]",
            msg->hdr.type, msg->hdr.size);

    switch (msg->hdr.type) {
        case AVD_MSG_F_NEW_CON: {
            char        *dir = NULL;
            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            umsg_nc_t m;
            umsg_nc_t_decode(msg->buf, 0, sizeof(msg->buf), &m);

            avd_log_debug("NCON Msg ::: Name : %s | Size : %ld", m.uname, sz);

            if (0 > (rc = add_user_s_sess(srvr, u, m.uname))) {
                return rc;
            }

            set_msg_type(res.hdr.type, AVD_MSG_F_NEW_CON);
            res.hdr.seq_no = 1;

            u->uname = (char *)malloc(strlen(m.uname)+1);
            snprintf(u->uname, strlen(m.uname)+1, "%s", m.uname);

            smsg_urc_t nc_smsg;
            nc_smsg.uid = u->id;
            nc_smsg.poll_id = u->poll_id;

            smsg_sz = smsg_urc_t_encoded_sz(&nc_smsg);
            data_sz = smsg_urc_t_encode(res.buf, 0, smsg_sz, &nc_smsg);
            res.hdr.size = MSG_HDR_SZ + data_sz;

            if (NULL == (dir = get_or_create_user_dir(u->uname))) {
                avd_log_error("Failed to create the task directory");
                //TODO handle the error
                return -1;
            }

            u->dir = dir;

            if (0 > (rc = send(sockfd, &res, res.hdr.size, 0))) {
                rc = -errno;
                avd_log_error("Send error: %s\n", strerror(errno));
                return rc;;
            }

            break;
        }
        case AVD_MSG_F_RE_CON: {
            char        *dir = NULL;
            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            umsg_rc_t m;
            umsg_rc_t_decode(msg->buf, 0, sizeof(msg->buf), &m);

            avd_log_debug("RCON Msg ::: Uname : %s | Uid : %d", m.uname, m.uid);

            if (!user_exists_s_sess(m.uname)) {
                avd_log_error("Reconnect User session with name %s not found",
                              m.uname);
                return -1;
            }

            u->id = m.uid;
            u->uname = (char *)malloc(strlen(m.uname)+1);
            snprintf(u->uname, strlen(m.uname)+1, "%s", m.uname);

            update_user_s_sess(m.uname, "poll_id",
                               cJSON_CreateNumber(u->poll_id));

            set_msg_type(res.hdr.type, AVD_MSG_F_RE_CON);
            res.hdr.seq_no = 1;

            smsg_urc_t rc_smsg;
            rc_smsg.uid = u->id;
            rc_smsg.poll_id = u->poll_id;

            smsg_sz = smsg_urc_t_encoded_sz(&rc_smsg);
            data_sz = smsg_urc_t_encode(res.buf, 0, smsg_sz, &rc_smsg);
            res.hdr.size = MSG_HDR_SZ + data_sz;

            if (NULL == (dir = get_or_create_user_dir(u->uname))) {
                avd_log_error("Failed to create the task directory");
                //TODO handle the error
                return -1;
            }

            u->dir = dir;

            rc = send(sockfd, &res, res.hdr.size, 0);
            if (rc < 0) {
                rc = -errno;
                avd_log_error("Send error: %s\n", strerror(errno));
                return rc;
            }

            break;
        }
        case AVD_MSG_F_TASK: {
            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            tmsg_args_t tmsg;
            tmsg_args_t_decode(msg->buf, 0, sizeof(msg->buf), &tmsg);

            for (i = 0; i < MAX_TASK; i++) {
                if (u->tasks[i].id == 0) {
                    break;
                }
            }

            if (i == MAX_TASK) {
                avd_log_error("Task limit reached! Task not added!");
                return -1;
            }


#define task u->tasks[i]
            cJSON   *new_task =cJSON_CreateObject();
            cJSON   *stage_arr = cJSON_CreateArray();

            u->tasks[i].id = u->num_tasks + 1;
            u->num_tasks += 1;
            update_user_s_sess(u->uname, "num_tasks",
                               cJSON_CreateNumber(u->num_tasks));

            cJSON_AddItemToObject(new_task, "id",
                                  cJSON_CreateNumber(task.id));

            snprintf(task.name, MAX_TASK_NAME_SZ, "%s", tmsg.task_name);
            cJSON_AddItemToObject(new_task, "name",
                                  cJSON_CreateString(task.name));

            snprintf(task.filename, MAX_FILE_NAME_SZ,
                     "%s/%s", u->dir, TASK_FILE);
            cJSON_AddItemToObject(new_task, "bin_file",
                                  cJSON_CreateString(task.filename));

            snprintf(task.input_file, MAX_FILE_NAME_SZ,
                     "%s/%s", u->dir, INPUT_FILE );
            cJSON_AddItemToObject(new_task, "input_file",
                                  cJSON_CreateString(task.input_file));

            task.num_stages = tmsg.num_stages;
            cJSON_AddItemToObject(new_task, "num_stages",
                                  cJSON_CreateNumber(task.num_stages));

            task.num_unassigned_stages = task.num_stages;
            cJSON_AddItemToObject(new_task, "unassigned_stages",
                                  cJSON_CreateNumber(task.num_unassigned_stages));

            cJSON_AddItemToObject(new_task, "peers_ready",
                                  cJSON_CreateNumber(0));

            cJSON_AddItemToObject(new_task, "peers_identified",
                                  cJSON_CreateFalse());

            for (j = 0; j < task.num_stages; j++) {
#define stage task.stages[j]
                cJSON   *stg = cJSON_CreateObject();

                stage.num = tmsg.stages[j].num;
                cJSON_AddItemToObject(stg, "num", cJSON_CreateNumber(stage.num));

                snprintf(stage.func_name,strlen(tmsg.stages[j].func)+1, "%s", tmsg.stages[j].func);
                cJSON_AddItemToObject(stg, "func", cJSON_CreateString(stage.func_name));

                stage.assigned = false;
                cJSON_AddItemToObject(stg, "assigned", cJSON_CreateBool(stage.assigned));

                stage.wid = -1;
                cJSON_AddItemToObject(stg, "wid", cJSON_CreateNumber(stage.wid));

                cJSON_AddItemToArray(stage_arr, stg);
#undef stage
            }
            cJSON_AddItemToObject(new_task, "stages", stage_arr);

            add_task_s_sess(u->uname, new_task);
#undef task
            break;
        }
        case AVD_MSG_F_FILE_TSK:
        case AVD_MSG_F_FILE_TSK_FIN: {
            char        file[MAX_FILE_NAME_SZ];
            FILE        *fp;

            if (u->file_seq_no != msg->hdr.seq_no) {
                avd_log_error("Out of order message. Expecting seq %d, Received %d",
                        u->file_seq_no, msg->hdr.seq_no);
                return -1;
            }

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            snprintf(file, MAX_FILE_NAME_SZ, "%s/%s", u->dir, TASK_FILE);

            fp = fopen(file, "ab+");

            if (u->file_seq_no == 1) {
                fseek(fp, 0L, SEEK_SET);
            }

            fwrite(msg->buf, rc, 1, fp);

            if (is_msg_type(msg->hdr.type, AVD_MSG_F_FILE_TSK_FIN)) {
                if(chmod(file, S_IRUSR | S_IWUSR | S_IXUSR
                         | S_IXGRP | S_IRGRP | S_IWGRP | S_IXOTH
                         | S_IROTH | S_IWOTH) != 0) {
                    avd_log_error("Error changing file mode to executable for file %s", file);
                    return -1;
                }
                u->file_seq_no = 1;
                avd_log_info("Created Task file : %s", file);
            } else {
                u->file_seq_no += 1;
            }

            fclose(fp);

            break;
        }
        case AVD_MSG_F_FILE_IN:
        case AVD_MSG_F_FILE_IN_FIN: {
            char        file[MAX_FILE_NAME_SZ];
            FILE        *fp;

            if (u->file_seq_no != msg->hdr.seq_no) {
                avd_log_error("Out of order message. Expecting seq %d, Received %d",
                        u->file_seq_no, msg->hdr.seq_no);
                return -1;
            }

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            snprintf(file, MAX_FILE_NAME_SZ, "%s/%s", u->dir, INPUT_FILE);

            fp = fopen(file, "ab+");

            if (u->file_seq_no == 1) {
                fseek(fp, 0L, SEEK_SET);
            }

            fwrite(msg->buf, rc, 1, fp);

            if (is_msg_type(msg->hdr.type, AVD_MSG_F_FILE_IN_FIN)) {
                u->file_seq_no = 1;
                avd_log_info("Created Input file : %s", file);
            } else {
                u->file_seq_no += 1;
            }

            fclose(fp);

            break;
        }
        case AVD_MSG_F_FILE_OUT:
        case AVD_MSG_F_FILE_OUT_FIN: {
            FILE        *fp;
            char        file[MAX_FILE_NAME_SZ];

            if (u->file_seq_no != msg->hdr.seq_no) {
                avd_log_error("Out of order message. Expecting seq %d, Received %d",
                        u->file_seq_no, msg->hdr.seq_no);
                return -1;
            }

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            snprintf(file, MAX_FILE_NAME_SZ, "%s/%s", u->dir, OUTPUT_FILE);

            fp = fopen(file, "ab+");

            if (u->file_seq_no == 1) {
                fseek(fp, 0L, SEEK_SET);
            }

            fwrite(msg->buf, rc, 1, fp);

            if (is_msg_type(msg->hdr.type, AVD_MSG_F_FILE_OUT_FIN)) {
                u->file_seq_no = 1;
                avd_log_info("Created Output file : %s", file);
            } else {
                u->file_seq_no += 1;
            }

            fclose(fp);

            break;
        }
        case AVD_MSG_F_CLOSE: {
            remove_user_s_sess(u->uname);
            close_user_connection(srvr, sockfd, u->poll_id, u);
            break;
        }
        case AVD_MSG_F_CTRL:
            break;
        default:
            avd_log_error("Error");
    }

    return 0;
}

void user_communications(server_t *srvr, int nready) {

    int32_t         i;
    int32_t         rc;
    message_t       rmsg;
    user_t          *u = NULL;

    memset(&rmsg, 0, sizeof(rmsg));

#define u_poll srvr->poller
    for (i = 1; i <= srvr->curr_poll_sz; i++) {
#define sockfd u_poll[i].fd
        if (sockfd < 0) {
            continue;
        }

        if (NULL == (u = get_user_from_sockfd(srvr, sockfd))) {
            close_user_connection(srvr, sockfd, i, u);
            continue;
        }

        if (u_poll[i].revents & (POLLRDNORM | POLLERR)) {
            if (0 < recv_avd_hdr(sockfd, &rmsg.hdr)) {
                if (0 > (rc = process_user_msg(srvr, sockfd, &rmsg, u))) {
                    avd_log_error("Error receiving message");
                    close_user_connection(srvr, sockfd, i, u);
                }
            } else {
                avd_log_error("Error receiving header");
                close_user_connection(srvr, sockfd, i, u);
            }

            nready -= 1;

            if (nready <= 0) {
                break;
            }
        }
#undef sockfd
    }
#undef u_poll
}

int32_t connect_user(server_t *srvr) {

    int32_t             i, j, rc = 0;
    int32_t             nready;
    int32_t             user_fd;
    socklen_t           sz;
    struct sockaddr_in  user_addr;
    conn_info_t         *s_conn = &srvr->conn;
    user_t              *u;

#define u_poll srvr->poller

    nready = poll(u_poll, srvr->curr_poll_sz + 1, INFTIM);

    if (u_poll[0].revents & POLLRDNORM) {
        sz = sizeof(user_addr);
        user_fd = accept(s_conn->sockfd, (struct sockaddr *)&user_addr, &sz);
        if (user_fd < 0) {
            rc = -errno;
            avd_log_error("User Accept connection failed: %s", strerror(errno));
            goto bail;
        }

        for (j = 0; j < MAX_USER; j++) {
            if (srvr->users[j].id == 0) {
                u= &srvr->users[j];
                break;
            }
        }

        if (j == MAX_USER) {
            avd_log_warn("Too many Users connected");
            memset(u, 0, sizeof(user_t));
            goto bail;
        }

        for (i = 1; i < srvr->max_poll_sz; i++) {
            if (u_poll[i].fd < 0) {

                u_poll[i].fd = user_fd;
                u_poll[i].events = POLLRDNORM;

                u->file_seq_no = 1;
                u->conn.sockfd = user_fd;
                u->poll_id = i;
                u->conn.port = sock_ntop_port(&user_addr);
                snprintf(u->conn.addr, INET_ADDRSTRLEN, "%s",
                         sock_ntop_addr(&user_addr));

                srvr->n_clients += 1;

                avd_log_info("New User connected: %s",
                              sock_ntop(&user_addr));
                avd_log_debug("\tUser Info:\n\t\tsockfd: %d\n\t\tpoll_id: %d",
                               u->conn.sockfd, u->poll_id);
                break;
            }
        }

#undef user_poll

        if (i == srvr->max_poll_sz) {
            avd_log_warn("Too many Users connected");
            memset(u, 0, sizeof(user_t));
            goto bail;
        }


        if (i > srvr->curr_poll_sz)
            srvr->curr_poll_sz = i;

        nready--;

    }

    return nready;

bail:
    return rc;
}

