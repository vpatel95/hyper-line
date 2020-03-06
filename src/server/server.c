#include "avd_pipe.h"
#include "log.h"
#include "session.h"

#define num_threads         2
#define init_processing     0
#define all_threads_ready   num_threads
#define enter_processing    all_threads_ready + 1

// Global variable definitions
char                            *g_conf_file_name = NULL;
uint32_t                        g_start_processing = init_processing;
extern avd_server_session_t     g_srvr_session;

int32_t server_init(conn_info_t *conn, int32_t type) {

    int32_t             rc;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (conn->sockfd < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: %s Server socket setup failed: %s\n",
                CLIENT_TYPE(type), strerror(-rc));

        return rc;
    }

    rc = inet_pton(AF_INET, conn->ip_addr_s, &srvr_addr.sin_addr.s_addr);
    if (rc == 0) {
        print("[ERROR][CRITICAL] ::: %s Server IP invalid format: %s\n",
                CLIENT_TYPE(type), strerror(errno));

        goto error;
    }

    if (rc < 0) {
        print("[ERROR]{CRITICAL] ::: %s Server IP inet_pton error: %s\n",
                CLIENT_TYPE(type), strerror(errno));

        goto error;
    }

    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    rc = bind(conn->sockfd, (struct sockaddr*)&srvr_addr, sizeof(srvr_addr));
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: %s Server socket bind error: %s\n",
                CLIENT_TYPE(type), strerror(errno));

        goto error;
    }

    rc = listen(conn->sockfd, 3);
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: %s Server socket listen failed: %s\n",
                CLIENT_TYPE(type), strerror(errno));

        goto error;
    }

    print("%s Server listening on %s:%d\n", CLIENT_TYPE(type),
            conn->ip_addr_s, conn->port);

    return 0;

error:
    close(conn->sockfd);
    return rc;
}

int32_t get_user_session() {

    return 0;
}

void worker_communications(server_t *srvr, int *nready) {

    int32_t         i;
    int32_t         n;
    char            rbuf[MAX_BUF_SZ];

#define worker srvr->poller
    for (i = 1; i <= srvr->curr_poll_sz; i++) {
#define sockfd worker[i].fd
        if (sockfd < 0) {
            continue;
        }

        if (worker[i].revents & (POLLRDNORM | POLLERR)) {
            if ((n = recv(sockfd, rbuf, MAX_BUF_SZ, 0)) < 0) {
                if (errno == ECONNRESET) {
                    print("[ERROR][CRITICAL] ::: Connection reset by worker");
                    close_fd(sockfd);
                    return;
                } else {
                    print("[ERROR][CRITICAL] ::: Read error occured: %s\n",
                            strerror(errno));
                    close_fd(sockfd);
                    return;
                }
            } else if (n == 0) {
                print("Connection closed by worker\n");
                srvr->n_clients--;
                close_fd(sockfd);
                return;
            } else {
                print("RECV: %s\n", rbuf);
                send(sockfd, rbuf, n, 0);
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
    for (idx = 0; idx < srvr->n_clients; idx++) {
        user = &srvr->users[idx];
        if (user->conn.sockfd == sockfd) {
            return idx;
        }
    }

    return -1;
}

int32_t receive_message(server_t *srvr, int32_t sockfd, message_t *m, int32_t user_idx) {
    int32_t     n = -1;
    user_t      *user = &srvr->users[user_idx];

    if (0 > (n = recv(sockfd, m, sizeof(message_t), 0))) {
        if (errno == ECONNRESET) {
            avd_log_warn("Connection reset by user");
            srvr->n_clients--;
            close_fd(user->conn.sockfd);
            remove_user_s_session(user->id);
            memset(user, 0, sizeof(user_t));
            return -1;
        } else {
            avd_log_error("Read error occured: %s\n", strerror(errno));
            srvr->n_clients--;
            close_fd(user->conn.sockfd);
            remove_user_s_session(user->id);
            memset(user, 0, sizeof(user_t));
            return -1;
        }
    } else if (n == 0) {
        avd_log_info("Connection closed by user\n");
        srvr->n_clients--;
        close_fd(user->conn.sockfd);
        remove_user_s_session(user->id);
        memset(&srvr->users[user_idx], 0, sizeof(user_t));
        return -1;
    }
    avd_log_debug("Recv %ld data", n);

    return 0;
}

int32_t process_message(server_t *srvr, int32_t sockfd,
                        const message_t *msg, int32_t user_idx) {
    if (user_idx < 0) {
        avd_log_debug("User with sockfd '%d' not found", sockfd);
        return -1;
    }
    avd_log_info("Message received ::: [Type : %d] | [Size : %ld] | [ CNT : %s]",
            msg->type, msg->size, msg->content.data);

    switch (msg->type) {
        case AVD_MSG_F_CTRL:
            break;
        case AVD_MSG_F_NEW_CON:
            create_user_s_session(srvr, user_idx);
            break;
        case AVD_MSG_F_FILE:
            break;
        case AVD_MSG_F_RE_CON:
            break;
        default:
            avd_log_error("Error");
    }

    send(sockfd, msg, sizeof(message_t), 0);
    avd_log_debug("Sent %ld data", sizeof(message_t));

    return 0;
}

void user_communications(server_t *srvr, int *nready) {

    int32_t         i;
    int32_t         rc;
    int32_t         user_idx;
    message_t rmsg;
    memset(&rmsg, 0, sizeof(rmsg));

#define user srvr->poller
    for (i = 1; i <= srvr->curr_poll_sz; i++) {
#define sockfd user[i].fd
        if (sockfd < 0) {
            continue;
        }

        if (user[i].revents & (POLLRDNORM | POLLERR)) {
            user_idx = get_user_idx_from_sockfd(srvr, sockfd);
            if (0 == receive_message(srvr, sockfd, &rmsg, user_idx)) {
                if (0 > (rc = process_message(srvr, sockfd, &rmsg, user_idx))) {
                    avd_log_error("Error while processing received message");
                    return;
                }
            } else {
                sockfd = -1;
            }

            *nready -= 1;

            if (*nready <= 0) {
                break;
            }
        }
#undef sockfd
    }
#undef user
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

                avd_log_info("New User connected: %s, (Total users: %d)\n",
                        sock_ntop((struct sockaddr *)&user_addr), srvr->n_clients);
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

    cfg.type = SERVER;
    g_conf_file_name = (char *)argv[1];

    if (0 != process_config_file(g_conf_file_name, &cfg)) {
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
