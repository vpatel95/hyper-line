#include "avd_pipe.h"
#include "log.h"

char    *g_conf_file_name = NULL;

int32_t user_init () {
    int32_t     conn_fd;

    conn_fd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (conn_fd < 0) {
        avd_log_fatal("Client socket setup failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return conn_fd;
}

/* TODO: Add Multiplexing I/O in server communication

void server_communication (conn_into_t *conn) {
    int32_t     maxfd;
    fdset       rset, wset;

    FD_ZERO(&rset);
    FD_ZERO(&wset);

error:
    close_fd(conn->sockfd);
    return;
}
*/

int32_t get_user_session (user_t *user) {
    int32_t     i, j;
    cJSON       *obj = NULL;
    cJSON       *v = NULL;
    cJSON       *tobj = NULL;
    cJSON       *sobj = NULL;
    int32_t     rc = -1;

    if (NULL == (obj = parse_json(SESSION_FILE))) {
        avd_log_error("Failed to parse %s file", SESSION_FILE);
        goto bail;
    }

    v = cJSON_GetObjectItem(obj, "id");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find 'id' in session file");
        goto bail;
    }
    user->id = v->valueint;

    v = cJSON_GetObjectItem(obj, "poll_id");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find 'poll_id' in session file");
        goto bail;
    }
    user->poll_id = v->valueint;

    tobj = cJSON_GetObjectItem(obj, "tasks");
    if (!tobj) {
        goto bail;
    }

    for (i = 0; i < cJSON_GetArraySize(tobj); i++) {
#define task user->tasks[i]
        cJSON *t = cJSON_GetArrayItem(tobj, i);

        v = cJSON_GetObjectItem(t, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_error("Failed to find 'id' in 'tasks' object in session file");
            goto bail;
        }
        task.id = v->valueint;

        v = cJSON_GetObjectItem(t, "num_stages");
        if ((!v) || (!v->valueint)) {
            avd_log_error("Failed to find 'num_stages' in 'tasks' object in session file");
            goto bail;
        }
        task.num_stages = v->valueint;

        sobj = cJSON_GetObjectItem(t, "stages");
        if (!sobj) {
            goto bail;
        }

        for (j = 0; j < cJSON_GetArraySize(sobj); j++) {
#define stage task.stages[j]
#define wrkr stage.worker
            cJSON *s = cJSON_GetArrayItem(sobj, j);

            v = cJSON_GetObjectItem(s, "id");
            if ((!v) || (!v->valueint)) {
                avd_log_error("Failed to find 'id' in 'stages' object in session file");
                goto bail;
            }
            stage.id = v->valueint;

            v = cJSON_GetObjectItem(s, "w_id");
            if ((!v) || (!v->valueint)) {
                avd_log_error("Failed to find 'w_id' in 'stages' object in session file");
                goto bail;
            }
            wrkr.id = v->valueint;
#undef wrkr
#undef stage
        }
#undef task
    }

    rc = 0;

bail:
    return rc;
}

int32_t check_and_get_session(user_t *user) {
    int32_t     rc = -1;
    if (file_exists(SESSION_FILE, F_OK)) {
        if (0 != (rc = get_user_session(user))) {
            avd_log_fatal("Failed to restore user session");
            exit(EXIT_FAILURE);
        }
    }

    return rc;
}

int32_t connect_server(user_t *user) {

    int32_t             rc = 0;
    message_t msg;
    message_t rmsg;
    conn_info_t         *conn = &user->conn;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = user_init();

    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    if (0 == (rc = check_and_get_session(user))) {
        set_msg_type(msg.type, AVD_MSG_F_RE_CON);
        avd_log_info("Restored user session");
    } else {
        set_msg_type(msg.type, AVD_MSG_F_NEW_CON);
        avd_log_info("User session not found. Creating new connection");
    }
    msg.size = 0;

    if (0 == (rc = inet_pton(AF_INET, conn->ip_addr_s, &srvr_addr.sin_addr.s_addr))) {
        avd_log_error("Server IP inet_pton error\n");
        goto error;
    }

    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    avd_log_debug("Connecting to server on %s:%d", conn->ip_addr_s, conn->port);
    rc = connect(conn->sockfd, (struct sockaddr *)&srvr_addr, sizeof(srvr_addr));
    if (rc < 0) {
        avd_log_fatal("Error connecting to the server at \"%s:%d\" : %s\n",
                conn->ip_addr_s, conn->port, strerror(errno));
        goto error;
    }

    print("Connected to server on %s\n", sock_ntop((struct sockaddr *)&srvr_addr));

    rc = send(conn->sockfd, &msg, sizeof(msg), 0);
    if (rc < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Send error: %s\n",
                strerror(errno));

        goto error;
    }

    rc = recv(conn->sockfd, &rmsg, sizeof(msg), 0);
    if (rc < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Recv error: %s\n",
                strerror(errno));

        goto error;
    }

    print("RECV MSG\n\tFlag : %d\n\tSize : %ld\n\tCNT : %s\n",
            rmsg.type, rmsg.size, rmsg.content.data);

error:
    close_fd(conn->sockfd);
    return rc;
}

int32_t start_user (user_t *user) {
    int32_t         rc;

    rc = connect_server(user);
    if (rc < 0) {
        avd_log_error("Cannot establish connection with server: %s\n.", strerror(errno));
    }

    return rc;
}

void setup_logger(char *log_file, int32_t level, int32_t quiet) {
    set_log_file(log_file);
    set_log_level(level);
    set_log_quiet(quiet);
}

int32_t main (int32_t argc, char *argv[]) {

    user_t              user;
    conn_info_t         *conn = &user.conn;
    conf_parse_info_t   cfg;

    signal_intr(SIGINT, sig_int_handler);

    memset(&user, 0, sizeof(user));
    memset(&cfg, 0, sizeof(cfg));

    cfg.type = USER;
    g_conf_file_name = (char *)argv[1];

    if (0 != process_config_file(g_conf_file_name, &cfg)) {
        avd_log_fatal("Failed to parse config file %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    setup_logger(cfg.uconf.log_file, cfg.uconf.log_level, cfg.uconf.log_quiet);

    snprintf(conn->ip_addr_s, INET_ADDRSTRLEN, "%s", cfg.uconf.addr);
    conn->port = cfg.uconf.port;

    start_user(&user);
    return EXIT_SUCCESS;
}
