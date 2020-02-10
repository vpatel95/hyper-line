#include "avd_pipe.h"

int32_t server_init(conn_info_t *conn) {

    int32_t             rc;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (conn->sockfd < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Server socket setup failed: %s\n",
                strerror(-rc));

        return rc;
    }

    rc = inet_pton(AF_INET, conn->ip_addr_s, &srvr_addr.sin_addr.s_addr);
    if (rc == 0) {
        print("[ERROR][CRITICAL] ::: Server IP invalid format: %s\n",
                strerror(errno));

        goto error;
    }

    if (rc < 0) {
        print("[ERROR]{CRITICAL] ::: Server IP inet_pton error: %s\n",
                strerror(errno));

        goto error;
    }

    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    rc = bind(conn->sockfd, (struct sockaddr*)&srvr_addr, sizeof(srvr_addr));
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: Server socket bind error: %s\n",
                strerror(errno));

        goto error;
    }

    rc = listen(conn->sockfd, 3);
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: Server socket listen failed: %s\n",
                strerror(errno));

        goto error;
    }

    print("Server listening on %s:%d\n", conn->ip_addr_s, conn->port);

    return 0;

error:
    close(conn->sockfd);
    return rc;
}

int32_t connect_client(server_t *srvr, int32_t *max_idx, int32_t *max_user_idx) {

    int32_t             i, rc;
    int32_t             nready;
    int32_t             client_fd;
    int32_t             max_poll_sz = MAX_POLL_SZ(srvr->type);


    socklen_t           client_addr_sz;
    struct sockaddr_in  client_addr;
    conn_info_t         *s_conn = &srvr->conn;
    user_t              *user = &srvr->users[*max_user_idx];

#define client srvr->poller

again:
    nready = poll(client, (uint32_t)(*max_idx + 1), INFTIM);

    if (client[0].revents & POLLRDNORM) {

        client_addr_sz = sizeof(client_addr);

        client_fd = accept(s_conn->sockfd, (struct sockaddr *)&client_addr, &client_addr_sz);
        if (client_fd < 0) {
            rc = -errno;
            print("[ERROR][CRITICAL] ::: Accept connection failed: %s\n",
                    strerror(errno));

            goto error;
        }

        for (i = 1; i < max_poll_sz; i++) {
            if (client[i].fd < 0) {

                print("Here : %d\n", i);

                client[i].fd = client_fd;
                client[i].events = POLLRDNORM;

                user->id = i;
                snprintf(user->conn.ip_addr_s, INET_ADDRSTRLEN, "%s",
                         sock_ntop_addr((struct sockaddr *)&client_addr));
                user->conn.port = sock_ntop_port((struct sockaddr *)&client_addr);
                user->conn.sockfd = client_fd;
                *max_user_idx += 1;

                print("New %s connected: %s\n", CLIENT_TYPE(srvr->type),
                        sock_ntop((struct sockaddr *)&client_addr));

                break;
            }
        }

#undef client

        print ("Also here %d\n", i);

        if (i == max_poll_sz) {
            print("[ERROR][CRITICAL] ::: Too many %s connected\n", CLIENT_TYPE(srvr->type));

            goto error;
        }


        if (i > *max_idx)
            *max_idx = i;

        if (--nready <= 0)
            goto again;
    }

    return client_fd;

error:
    close_fd(client_fd);
    return rc;
}

int32_t start_server(server_t *srvr, char *ip_addr, uint16_t port) {

    int32_t         i, rc;
    int32_t         max_idx, max_user_idx, max_worker_idx;
    // char                r_buf[MAX_BUF_SZ], s_buf[MAX_BUF_SZ];
    conn_info_t     *conn = &srvr->conn;

    snprintf(conn->ip_addr_s, INET_ADDRSTRLEN, "%s", ip_addr);
    conn->port = port;

    rc = server_init(conn);
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: Server init failed: %s\n",
                strerror(errno));

        goto error;
    }

    srvr->poller[0].fd = conn->sockfd;
    srvr->poller[0].events = POLLRDNORM;

    switch(srvr->type) {
        case USER:

            for (i = 1; i < MAX_USER_POLL; i++) {
                srvr->poller[i].fd = -1;
            }

            max_idx = 0;
            max_user_idx = 0;

            while (true) {
                rc = connect_client(srvr, &max_idx, &max_user_idx);
            }
            break;
        case WORKER:

            for (i = 1; i < MAX_WORKER_POLL; i++) {
                srvr->poller[i].fd = -1;
            }

            max_idx = 0;
            max_worker_idx = 0;

            while (true) {
                rc = connect_client(srvr, &max_idx, &max_worker_idx);
            }
            break;
    }

    return 0;

error:
    close(conn->sockfd);
    return rc;
}

int32_t main (int32_t argc, char const *argv[]) {
    server_t    *srvr = (server_t *)malloc(sizeof(server_t *));

    signal_intr(SIGINT, sig_int_handler);
    srvr->type = USER;
    start_server(srvr, "192.168.1.200", 1110);
    return EXIT_SUCCESS;
}
