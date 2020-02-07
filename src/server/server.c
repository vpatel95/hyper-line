#include "avd_pipe.h"
#include <time.h>

int32_t get_socket(int32_t family, int32_t type, int32_t protocol) {

    int rc;
    int sockfd;

    sockfd = socket(family, type, protocol);
    if (sockfd < 0) {
        rc = sockfd;
        print("[ERROR][CRITICAL] ::: Failed to open socket: %s\n",
                strerror(errno));

        goto error;
    }

    return sockfd;

error:
    close(sockfd);
    return rc;
}

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
        print("[ERROR]{CRITICAL] ::: Server IP invalid format: %s\n",
                strerror(-errno));

        goto error;
    }

    if (rc < 0) {
        print("[ERROR]{CRITICAL] ::: Server IP inet_pton error: %s\n",
                strerror(-errno));

        goto error;
    }

    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(conn->port);

    rc = bind(conn->sockfd, (struct sockaddr*)&srvr_addr, sizeof(srvr_addr));
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: Server socket bind error: %s\n",
                strerror(-errno));

        goto error;
    }

    rc = listen(conn->sockfd, 3);
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: Server socket listen failed: %s\n",
                strerror(-errno));

        goto error;
    }

    print("Server listening on %s:%d\n", conn->ip_addr_s, conn->port);

    return 0;

error:
    close(conn->sockfd);
    return rc;
}

int32_t start_server(server_t *srvr, char *ip_addr, uint16_t port) {

    int32_t             rc;
    int32_t             connfd;
    conn_info_t         *conn = &srvr->conn;
    struct sockaddr_in  conn_addr;


    snprintf(conn->ip_addr_s, INET_ADDRSTRLEN, "%s", ip_addr);
    conn->port = port;

    rc = server_init(conn);
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: Server init failed: %s\n",
                strerror(-errno));

        goto error;
    }

    while (true) {

        connfd = accept(conn->sockfd,(struct sockaddr *)(&conn_addr), (socklen_t *)sizeof(struct sockaddr_in));
        if (connfd < 0) {
            rc = -errno;
            print("[ERROR][CRITICAL] ::: Server connection accept failed: %s\n",
                    strerror(-errno));

            goto error;
        }
    }

    return 0;

error:
    close(conn->sockfd);
    return rc;
}

int32_t main (int32_t argc, char const *argv[]) {
    server_t    *srvr = (server_t *)malloc(sizeof(server_t *));

    start_server(srvr, "192.168.1.200", 9000);
    return EXIT_SUCCESS;
}
