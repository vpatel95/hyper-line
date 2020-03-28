#define _GNU_SOURCE
#include "avd_pipe.h"
#include "avd_log.h"
#include "avd_session.h"
#include "avd_message.h"

#include "server/user.h"
#include "server/worker.h"

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

    avd_log_info("%s Server listening on %s:%d", CLIENT_TYPE(type),
                  conn->ip_addr_s, conn->port);

    return 0;

bail:
    close(conn->sockfd);
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
        avd_log_error("Server init failed: %s", strerror(errno));
        close(conn->sockfd);
        exit(EXIT_FAILURE);
    }

    srvr->poller[0].fd = conn->sockfd;
    srvr->poller[0].events = POLLRDNORM;

    switch(srvr->type) {
        case USER: {
            int32_t nready;
            for (i = 1; i < MAX_USER_POLL; i++) {
                srvr->poller[i].fd = -1;
            }

            srvr->max_poll_sz = MAX_USER_POLL;
            srvr->curr_poll_sz = 0;
            srvr->new_client_id = get_max_user_id_s_sess();

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
                nready = connect_user(srvr);
                if (nready < 0) {
                    avd_log_error("Error occurred 'connect_user': %s", strerror(errno));
                }
                user_communications(srvr, nready);
            }
            break;
        }
        case WORKER: {
            int32_t nready;
            for (i = 1; i < MAX_WORKER_POLL; i++) {
                srvr->poller[i].fd = -1;
            }

            srvr->max_poll_sz = MAX_WORKER_POLL;
            srvr->curr_poll_sz = 0;
            srvr->new_client_id = get_max_worker_id_s_sess();

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
                nready = connect_worker(srvr);
                if (nready < 0) {
                    avd_log_error("Error occurred 'connect_worker': %s", strerror(errno));
                }
                worker_communications(srvr, nready);
            }
            break;
        }
    }

    return NULL;
}

void setup_logger(char *log_file, int32_t level, int32_t quiet) {
    set_log_file(log_file);
    set_log_level(level);
    set_log_quiet(quiet);
}

int32_t main (int32_t argc, char const *argv[]) {
    pthread_t               threads[3];
#define u_thrd              threads[0]
#define w_thrd              threads[1]
#define s_thrd              threads[2]
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

    if (0 != pthread_create(&u_thrd, NULL, start_server, (void *)&u_args)) {
        avd_log_fatal("User server thread creation failed");
        exit(EXIT_FAILURE);
    }
    pthread_setname_np(u_thrd, "avd_user_server");

    if (0 != pthread_create(&w_thrd, NULL, start_server, (void *)&w_args)) {
        avd_log_fatal("Worker server thread creation failed");
        exit(EXIT_FAILURE);
    }
    pthread_setname_np(w_thrd, "avd_worker_server");

    while (all_threads_ready != *(volatile uint32_t *)&g_start_processing) {
        usleep(10);
    }

    g_start_processing = enter_processing;
    __sync_synchronize();

    pthread_join(u_thrd, NULL);
    pthread_join(w_thrd, NULL);

    exit(EXIT_SUCCESS);
}
