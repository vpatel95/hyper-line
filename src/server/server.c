#include "avd_pipe.h"
#include "avd_log.h"
#include "avd_session.h"
#include "avd_message.h"

#define num_threads         2
#define init_processing     0
#define all_threads_ready   num_threads
#define enter_processing    all_threads_ready + 1

// Global variable definitions
char                            *g_conf_file_name = NULL;
uint32_t                        g_start_processing = init_processing;
int32_t                         g_seq_in = 1;
int32_t                         g_seq_out = 1;
int32_t                         g_seq_tsk = 1;
extern avd_server_session_t     g_srvr_session;

int32_t server_init(conn_info_t *conn, int32_t type) {

    int32_t             rc;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (conn->sockfd < 0) {
        rc = -errno;
        avd_log_error("%s Server socket setup failed: %s\n",
                CLIENT_TYPE(type), strerror(-rc));

        return rc;
    }

    rc = inet_pton(AF_INET, conn->ip_addr_s, &srvr_addr.sin_addr.s_addr);
    if (rc == 0) {
        avd_log_error("%s Server IP invalid format: %s\n",
                CLIENT_TYPE(type), strerror(errno));
        goto bail;
    }

    if (rc < 0) {
        avd_log_error("%s Server IP inet_pton error: %s\n",
                CLIENT_TYPE(type), strerror(errno));

        goto bail;
    }

    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    rc = bind(conn->sockfd, (struct sockaddr*)&srvr_addr, sizeof(srvr_addr));
    if (rc < 0) {
        avd_log_error("%s Server socket bind error: %s\n",
                CLIENT_TYPE(type), strerror(errno));

        goto bail;
    }

    rc = listen(conn->sockfd, 3);
    if (rc < 0) {
        avd_log_error("%s Server socket listen failed: %s\n",
                CLIENT_TYPE(type), strerror(errno));

        goto bail;
    }

    avd_log_info("%s Server listening on %s:%d\n", CLIENT_TYPE(type),
                  conn->ip_addr_s, conn->port);

    return 0;

bail:
    close(conn->sockfd);
    return rc;
}

int32_t get_worker_idx_from_sockfd(server_t *srvr, int32_t sockfd) {
    int32_t     idx;
    worker_t    *worker;
    for (idx = 0; idx < srvr->n_clients; idx++) {
        worker = &srvr->workers[idx];
        if (worker->conn.sockfd == sockfd) {
            return idx;
        }
    }

    return -1;
}

void close_worker_connection(server_t *srvr, int32_t worker_idx) {
    worker_t  *worker = &srvr->workers[worker_idx];

    avd_log_info("Worker connection closed. Worker id : %d", worker->id);

    srvr->n_clients--;
    close(worker->conn.sockfd);
    srvr->poller[worker->poll_id].fd = -1;
    remove_user_s_session(worker->id);
    memset(worker, 0, sizeof(worker_t));
}

// TODO:
int32_t process_worker_message(server_t *srvr, int32_t sockfd,
                        message_t *msg, int32_t worker_idx) {
    (void) (msg);
    (void) (worker_idx);
    (void) (srvr);
    (void) (sockfd);
    return 0;
}

void worker_communications(server_t *srvr, int *nready) {

    int32_t         i;
    int32_t         rc;
    int32_t         worker_idx;
    message_t       rmsg;

    memset(&rmsg, 0, sizeof(rmsg));

#define worker srvr->poller
    for (i = 1; i <= srvr->curr_poll_sz; i++) {
#define sockfd worker[i].fd
        if (sockfd < 0) {
            continue;
        }

        if (worker[i].revents & (POLLRDNORM | POLLERR)) {
            worker_idx = get_worker_idx_from_sockfd(srvr, sockfd);
            if (0 < recv_avd_hdr(sockfd, &rmsg.hdr)) {
                if (0 > (rc = process_worker_message(srvr, sockfd, &rmsg, worker_idx))) {
                    close_worker_connection(srvr, worker_idx);
                }
            } else {
                close_worker_connection(srvr, worker_idx);
            }

            *nready -= 1;

            if (*nready <= 0) {
                break;
            }
        }
#undef sockfd
    }
#undef worker
}

int32_t get_user_idx_from_sockfd(server_t *srvr, int32_t sockfd) {
    int32_t     idx;
    user_t      *user;
    for (idx = 0; idx < MAX_USER; idx++) {
        user = &srvr->users[idx];
        if (user->conn.sockfd == sockfd) {
            return idx;
        }
    }

    return -1;
}

void close_user_connection(server_t *srvr, int32_t sockfd,
                           int32_t poll_id, int32_t user_idx) {

    srvr->n_clients--;
    close(sockfd);
    srvr->poller[poll_id].fd = -1;

    if (user_idx < 0) {
        avd_log_info("Cleared stale\n\tsockfd : %d\n\tpoll_id : %d", sockfd, poll_id);
        return;
    }

    user_t *user = &srvr->users[user_idx];

    avd_log_info("User connection closed. User id : %d", user->id);
    avd_log_fatal("sockfd : %d, ", user->conn.sockfd);
    avd_log_fatal("poll_id : %d", user->poll_id);

    memset(user, 0, sizeof(user_t));

}

int32_t process_user_message(server_t *srvr, int32_t sockfd,
                        message_t *msg, int32_t user_idx) {

    int32_t     i, j, rc = -1;
    size_t      sz;
    size_t      smsg_sz;
    FILE        *fp;
    message_t   res;
    user_t      *user = &srvr->users[user_idx];

    memset(&res, 0, sizeof(res));

    avd_log_debug("Header received ::: [Type : %d] | [Size : %ld]",
            msg->hdr.type, msg->hdr.size);

    switch (msg->hdr.type) {
        case AVD_MSG_F_NEW_CON:
            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            if (0 > (rc = create_user_s_session(srvr, user_idx))) {
                return rc;
            }

            set_msg_type(res.hdr.type, AVD_MSG_F_NEW_CON);
            res.hdr.seq_no = 1;

            smsg_conn_t nc_smsg;
            nc_smsg.uid = user->id;
            nc_smsg.poll_id = user->poll_id;

            smsg_sz = smsg_conn_t_encoded_sz(&nc_smsg);
            smsg_conn_t_encode(res.buf, 0, smsg_sz, &nc_smsg);
            res.hdr.size = msg_sz(smsg_conn_t);

            rc = send(sockfd, &res, res.hdr.size, 0);
            if (rc < 0) {
                rc = -errno;
                avd_log_error("Send error: %s\n", strerror(errno));
                return rc;;
            }

            break;
        case AVD_MSG_F_RE_CON:
            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            umsg_rc_t m;
            umsg_rc_t_decode(msg->buf, 0, sizeof(msg->buf), &m);

            avd_log_debug("RCON Msg ::: Uid : %d | Size : %ld", m.uid, sz);

            if (!user_s_session_exists(m.uid)) {
                avd_log_error("Failed to find user session with reconnect id %d", m.uid);
                return -1;
            }

            user->id = m.uid;
            update_user_s_session(m.uid, "poll_id", cJSON_CreateNumber(user->poll_id));

            set_msg_type(res.hdr.type, AVD_MSG_F_RE_CON);
            res.hdr.seq_no = 1;

            smsg_conn_t rc_smsg;
            rc_smsg.uid = user->id;
            rc_smsg.poll_id = user->poll_id;

            smsg_sz = smsg_conn_t_encoded_sz(&rc_smsg);
            smsg_conn_t_encode(res.buf, 0, smsg_sz, &rc_smsg);
            res.hdr.size = msg_sz(smsg_conn_t);

            rc = send(sockfd, &res, res.hdr.size, 0);
            if (rc < 0) {
                rc = -errno;
                avd_log_error("Send error: %s\n", strerror(errno));
                return rc;
            }

            break;
        case AVD_MSG_F_TASK:
            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            tmsg_args_t tmsg;
            tmsg_args_t_decode(msg->buf, 0, sizeof(msg->buf), &tmsg);

            for (i = 0; i < MAX_TASK; i++) {
                if (user->tasks[i].id == 0) {
                    break;
                }
            }

            if (i == MAX_TASK) {
                avd_log_error("Task limit reached! Task not added!");
                return -1;
            }

            user->tasks[i].id = user->num_tasks + 1;
            user->num_tasks += 1;

#define task user->tasks[i]
            snprintf(task.name, MAX_TASK_NAME_SZ, "%s", tmsg.task_name);
            task.num_stages = tmsg.num_stages;

            for (j = 0; j < task.num_stages; j++) {
                task.stages[j].num = tmsg.stages[j].num;
                snprintf(task.stages[j].func_name, MAX_STAGE_FUNC_NAME_SZ,
                         "%s", tmsg.stages[j].func);
            }
#undef task
            break;
        case AVD_MSG_F_FILE_TSK:
        case AVD_MSG_F_FILE_TSK_FIN:
            if (user->file_seq_no != msg->hdr.seq_no) {
                avd_log_error("Out of order message. Expecting seq %d, Received %d",
                        user->file_seq_no, msg->hdr.seq_no);
                return -1;
            }

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            fp = fopen(TASK_FILE, "ab+");

            if (user->file_seq_no == 1) {
                fseek(fp, 0L, SEEK_SET);
            }

            fwrite(msg->buf, rc, 1, fp);

            if (is_msg_type(msg->hdr.type, AVD_MSG_F_FILE_TSK_FIN)) {
                if(chmod(TASK_FILE, S_IRUSR | S_IWUSR | S_IXUSR
                         | S_IXGRP | S_IRGRP | S_IWGRP | S_IXOTH
                         | S_IROTH | S_IWOTH) != 0) {
                    avd_log_error("Error changing file mode to executable for file %s", TASK_FILE);
                    return -1;
                }
                user->file_seq_no = 1;
            } else {
                user->file_seq_no += 1;
            }

            fclose(fp);

            break;
        case AVD_MSG_F_FILE_IN:
        case AVD_MSG_F_FILE_IN_FIN:
            if (user->file_seq_no != msg->hdr.seq_no) {
                avd_log_error("Out of order message. Expecting seq %d, Received %d",
                        user->file_seq_no, msg->hdr.seq_no);
                return -1;
            }

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            fp = fopen(INPUT_FILE, "ab+");

            if (user->file_seq_no == 1) {
                fseek(fp, 0L, SEEK_SET);
            }

            fwrite(msg->buf, rc, 1, fp);

            if (is_msg_type(msg->hdr.type, AVD_MSG_F_FILE_IN_FIN)) {
                user->file_seq_no = 1;
            } else {
                user->file_seq_no += 1;
            }

            fclose(fp);

            break;
        case AVD_MSG_F_FILE_OUT:
        case AVD_MSG_F_FILE_OUT_FIN:
            if (user->file_seq_no != msg->hdr.seq_no) {
                avd_log_error("Out of order message. Expecting seq %d, Received %d",
                        user->file_seq_no, msg->hdr.seq_no);
                return -1;
            }

            if (0 < (sz = msg->hdr.size - MSG_HDR_SZ)) {
                rc = recv_avd_msg(sockfd, msg->buf, sz);
                if (0 > rc) {
                    return rc;
                }
            }

            fp = fopen(OUTPUT_FILE, "ab+");

            if (user->file_seq_no == 1) {
                fseek(fp, 0L, SEEK_SET);
            }

            fwrite(msg->buf, rc, 1, fp);

            if (is_msg_type(msg->hdr.type, AVD_MSG_F_FILE_OUT_FIN)) {
                user->file_seq_no = 1;
            } else {
                user->file_seq_no += 1;
            }

            fclose(fp);

            break;
        case AVD_MSG_F_CLOSE:
            remove_user_s_session(user->id);
            close_user_connection(srvr, sockfd, user->poll_id, user_idx);
            break;
        case AVD_MSG_F_CTRL:
            break;
        default:
            avd_log_error("Error");
    }

    return 0;
}

void user_communications(server_t *srvr, int *nready) {

    int32_t         i;
    int32_t         rc;
    int32_t         user_idx;
    message_t       rmsg;

    memset(&rmsg, 0, sizeof(rmsg));

#define user_poll srvr->poller
    for (i = 1; i <= srvr->curr_poll_sz; i++) {
#define sockfd user_poll[i].fd
        if (sockfd < 0) {
            continue;
        }

        if (user_poll[i].revents & (POLLRDNORM | POLLERR)) {
            if (0 > (user_idx = get_user_idx_from_sockfd(srvr, sockfd))) {
                close_user_connection(srvr, sockfd, i, user_idx);
                continue;
            }

            if (0 < recv_avd_hdr(sockfd, &rmsg.hdr)) {
                if (0 > (rc = process_user_message(srvr, sockfd, &rmsg, user_idx))) {
                    avd_log_error("Error receiving message");
                    close_user_connection(srvr, sockfd, i, user_idx);
                }
            } else {
                avd_log_error("Error receiving header");
                close_user_connection(srvr, sockfd, i, user_idx);
            }

            *nready -= 1;

            if (*nready <= 0) {
                break;
            }
        }
#undef sockfd
    }
#undef user_poll
}

int32_t connect_worker(server_t *srvr) {

    int32_t             i, rc = 0;
    int32_t             nready;
    int32_t             worker_fd;

    socklen_t           worker_addr_sz;
    struct sockaddr_in  worker_addr;
    conn_info_t         *s_conn = &srvr->conn;
    worker_t            *worker = &srvr->workers[srvr->new_client_id];

#define worker_poll srvr->poller

    nready = poll(worker_poll, (uint32_t)(srvr->curr_poll_sz), INFTIM);

    if (worker_poll[0].revents & POLLRDNORM) {

        worker_addr_sz = sizeof(worker_addr);

        worker_fd = accept(s_conn->sockfd, (struct sockaddr *)&worker_addr, &worker_addr_sz);
        if (worker_fd < 0) {
            rc = -errno;
            print("[ERROR][CRITICAL] ::: Worker Accept connection failed: %s\n",
                    strerror(errno));

            goto error;
        }

        for (i = 1; i < srvr->max_poll_sz; i++) {
            if (worker_poll[i].fd < 0) {

                worker_poll[i].fd = worker_fd;
                worker_poll[i].events = POLLRDNORM;

                worker->conn.sockfd = worker_fd;
                worker->conn.port = sock_ntop_port((struct sockaddr *)&worker_addr);
                snprintf(worker->conn.ip_addr_s, INET_ADDRSTRLEN, "%s",
                         sock_ntop_addr((struct sockaddr *)&worker_addr));

                srvr->n_clients += 1;

                print("New Worker connected: %s, ID: %d, (Total workers: %d)\n",
                        sock_ntop((struct sockaddr *)&worker_addr),
                        worker->id, srvr->n_clients);

                break;
            }
        }

#undef worker_poll

        if (i == srvr->max_poll_sz) {
            print("[ERROR][CRITICAL] ::: Too many Workers connected\n");
            goto error;
        }


        if (i > srvr->curr_poll_sz)
            srvr->curr_poll_sz = i;

    }

    worker_communications(srvr, &nready);

error:
    return rc;
}


int32_t connect_user(server_t *srvr) {

    int32_t             i, j, rc = 0;
    int32_t             nready;
    int32_t             user_fd;
    socklen_t           user_addr_sz;
    struct sockaddr_in  user_addr;
    conn_info_t         *s_conn = &srvr->conn;
    user_t              *user;


#define user_poll srvr->poller

    nready = poll(user_poll, srvr->curr_poll_sz + 1, INFTIM);

    if (user_poll[0].revents & POLLRDNORM) {

        user_addr_sz = sizeof(user_addr);

        user_fd = accept(s_conn->sockfd, (struct sockaddr *)&user_addr, &user_addr_sz);
        if (user_fd < 0) {
            rc = -errno;
            avd_log_error("Accept connection failed: %s\n", strerror(errno));
            goto bail;
        }

        for (j = 0; j < MAX_USER; j++) {
            if (srvr->users[j].id == 0) {
                user = &srvr->users[j];
                break;
            }
        }

        if (j == MAX_USER) {
            avd_log_warn("Too many Users connected\n");
            memset(user, 0, sizeof(user_t));
            goto bail;
        }

        for (i = 1; i < srvr->max_poll_sz; i++) {
            if (user_poll[i].fd < 0) {

                user_poll[i].fd = user_fd;
                user_poll[i].events = POLLRDNORM;

                user->conn.sockfd = user_fd;
                user->poll_id = i;
                user->conn.port = sock_ntop_port((struct sockaddr *)&user_addr);
                snprintf(user->conn.ip_addr_s, INET_ADDRSTRLEN, "%s",
                         sock_ntop_addr((struct sockaddr *)&user_addr));

                srvr->n_clients += 1;

                avd_log_info("New User connected: %s", sock_ntop((struct sockaddr *)&user_addr));
                avd_log_fatal("\tUser Info:\n\t\tsockfd : %d\n\t\tpoll_id : %d", user->conn.sockfd, user->poll_id);
                break;
            }
        }

#undef user_poll

        if (i == srvr->max_poll_sz) {
            avd_log_warn("Too many Users connected\n");
            memset(user, 0, sizeof(user_t));
            goto bail;
        }


        if (i > srvr->curr_poll_sz)
            srvr->curr_poll_sz = i;

        nready--;

    }

    user_communications(srvr, &nready);
bail:
    return rc;
}

static void * start_server(void * args) {

    int32_t         i, rc;
    args_t          *arg = (args_t *) args;

    server_t        *srvr = &arg->srvr;
    uint16_t        port = arg->port;
    conn_info_t     *conn = &srvr->conn;

    snprintf(conn->ip_addr_s, INET_ADDRSTRLEN, "%s", arg->addr);
    conn->port = port;

    rc = server_init(conn, srvr->type);
    if (rc < 0) {
        avd_log_error("Server init failed: %s\n", strerror(errno));
        goto error;
    }

    srvr->poller[0].fd = conn->sockfd;
    srvr->poller[0].events = POLLRDNORM;

    switch(srvr->type) {
        case USER:

            for (i = 1; i < MAX_USER_POLL; i++) {
                srvr->poller[i].fd = -1;
            }

            srvr->max_poll_sz = MAX_USER_POLL;
            srvr->curr_poll_sz = 0;
            srvr->new_client_id = 1;

            __sync_add_and_fetch(&g_start_processing, 1);

            /*
             * Ensure the main thread has started other threads
             * and now its time to go for real processing loop.
             * For this wait till main thread signals to enter the 
             * processing loop.
             */
            while (enter_processing != *(volatile uint32_t *)&g_start_processing) {
                usleep(1);
            }

            while (true) {
                rc = connect_user(srvr);
            }
            break;
        case WORKER:

            for (i = 1; i < MAX_WORKER_POLL; i++) {
                srvr->poller[i].fd = -1;
            }

            srvr->max_poll_sz = MAX_WORKER_POLL;
            srvr->curr_poll_sz = 0;
            srvr->new_client_id = 1;

            __sync_add_and_fetch(&g_start_processing, 1);
            /*
             * Ensure the main thread has started other threads
             * and now its time to go for real processing loop.
             * For this wait till main thread signals to enter the 
             * processing loop.
             */

            while (enter_processing != *(volatile uint32_t *)&g_start_processing) {
                usleep(1);
            }

            while (true) {
                rc = connect_worker(srvr);
            }
            break;
    }

    return NULL;

error:
    close(conn->sockfd);
    return NULL;
}

void setup_logger(char *log_file, int32_t level, int32_t quiet) {
    set_log_file(log_file);
    set_log_level(level);
    set_log_quiet(quiet);
}

int32_t main (int32_t argc, char const *argv[]) {
    pthread_t               threads[2];
    conf_parse_info_t       cfg;
    args_t                  args[2];
#define u_args              args[0]
#define w_args              args[1]
    server_t                srvr[2];
#define u_srvr              srvr[0]
#define w_srvr              srvr[1]

    if (argc < 2) {
        print("Usage %s <run-time>\n", basename((char *)argv[0]));
        exit(EXIT_FAILURE);
    }

    signal_intr(SIGINT, sig_int_handler);

    memset(&u_srvr, 0, sizeof(u_srvr));
    memset(&w_srvr, 0, sizeof(u_srvr));
    memset(&cfg, 0, sizeof(cfg));

    g_conf_file_name = (char *)argv[1];

    if (0 != process_config_file(g_conf_file_name, SERVER, &cfg)) {
        avd_log_fatal("Failed to parse config file");
        exit(EXIT_FAILURE);
    }

    setup_logger(cfg.sconf.log_ufile, cfg.sconf.log_level, cfg.sconf.log_quiet);

    u_srvr.type = USER;
    w_srvr.type = WORKER;
    w_srvr.max_poll_sz = MAX_WORKER_POLL;

    u_args.srvr = u_srvr;
    snprintf(u_args.addr,INET_ADDRSTRLEN, "%s", cfg.sconf.addr);
    u_args.port = cfg.sconf.uport;

    w_args.srvr = w_srvr;
    snprintf(w_args.addr,INET_ADDRSTRLEN, "%s", cfg.sconf.addr);
    w_args.port = cfg.sconf.wport;

    if (0 != pthread_create(&threads[0], NULL, start_server, (void *)&u_args)) {
        avd_log_fatal("User server thread creation failed");
        exit(EXIT_FAILURE);
    }

    if (0 != pthread_create(&threads[1], NULL, start_server, (void *)&w_args)) {
        avd_log_fatal("Worker server thread creation failed");
        exit(EXIT_FAILURE);
    }

    while (all_threads_ready != *(volatile uint32_t *)&g_start_processing) {
        usleep(10);
    }

    g_start_processing = enter_processing;
    __sync_synchronize();

    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);

    exit(EXIT_SUCCESS);
}
