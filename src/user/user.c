#include "avd_pipe.h"

char    *g_conf_file_name = NULL;

int32_t user_init () {

    int32_t             rc;
    int32_t             srvr_fd;

    srvr_fd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (srvr_fd < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Client socket setup failed: %s\n",
                strerror(errno));

        goto error;
    }

    return srvr_fd;

error:
    close_fd(srvr_fd);
    return rc;
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

int32_t connect_server(user_t *user) {

    int32_t             rc = 0;
    conn_info_t         *conn = &user->conn;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = user_init();

    rc = inet_pton(AF_INET, conn->ip_addr_s, &srvr_addr.sin_addr.s_addr);
    if (rc == 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Server IP inet_pton error: %s\n",
                strerror(errno));

        goto error;
    }

    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    rc = connect(conn->sockfd, (struct sockaddr *)&srvr_addr, sizeof(srvr_addr));
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: Error connecting to the server at \"%s:%d\" : %s\n",
                conn->ip_addr_s, conn->port, strerror(errno));

        goto error;
    }

    print("Connected to server on %s\n", sock_ntop((struct sockaddr *)&srvr_addr));

    message_t msg;
    message_t rmsg;
    memset(&msg, 0, sizeof(msg));
    memset(&rmsg, 0, sizeof(rmsg));

    set_type(msg.type, AVD_MSG_F_CTRL);
    sprintf(msg.content.data, "Hello from Client");
    msg.size = strlen(msg.content.data);

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
        print("[ERROR][CRITICAL] ::: Cannot establish connection with server: %s\n",
                strerror(errno));

        goto error;
    }

error:
    return rc;
}


int32_t main (int32_t argc, char *argv[]) {

    user_t              *user = (user_t *)malloc(sizeof(user_t *));
    conn_info_t         *conn = &user->conn;
    conf_parse_info_t   cfg;

    signal_intr(SIGINT, sig_int_handler);

    memset(&cfg, 0, sizeof(cfg));

    cfg.type = USER;
    g_conf_file_name = (char *)argv[1];

    if (0 != process_config_file(g_conf_file_name, &cfg)) {
        print("Failed to parse config file %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    snprintf(conn->ip_addr_s, INET_ADDRSTRLEN, "%s", cfg.uconf.addr);
    conn->port = cfg.uconf.port;

    start_user(user);
    return EXIT_SUCCESS;
}
