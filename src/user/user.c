#include "avd_pipe.h"

int32_t user_init (user_t *user, char *ip_addr, uint16_t port) {

    int32_t             rc;
    conn_info_t         *conn = &user->conn;
    struct sockaddr_in  srvr_addr;

    conn->sockfd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (conn->sockfd < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Client socket setup failed: %s\n",
                strerror(errno));

        goto error;
    }

    rc = inet_pton(AF_INET, ip_addr, &srvr_addr.sin_addr.s_addr);
    if (rc == 0) {
        print("[ERROR][CRITICAL] ::: Server IP inet_pton error: %s\n",
                strerror(-errno));

        goto error;
    }

    srvr_addr.sin_family = AF_INET;
    srvr_addr.sin_port = htons(port);

    rc = connect(conn->sockfd, (struct sockaddr *)&srvr_addr, sizeof(srvr_addr));
    if (rc < 0) {
        print("[ERROR][CRITICAL] ::: Error connecting to the server at \"%s:%d\" : %s\n",
                conn->ip_addr_s, conn->port, strerror(-errno));

        goto error;
    }

    close_fd(conn->sockfd);
    return 0;

error:
    close_fd(conn->sockfd);
    return rc;
}


int32_t main (int32_t argc, char *argv[]) {

    user_t      *user = (user_t *)malloc(sizeof(user_t *));

    user_init(user, "71.114.127.203", 1110);
    return EXIT_SUCCESS;
}
