#include <stdio.h>
#include <inttypes.h>

#include "avd_pipe.h"
#include "avd_message.h"
#include "avd_session.h"

int32_t ps_init(conn_info_t *conn) {
    int32_t             rc;
    struct sockaddr_in  ps_addr;

    if (0 > (conn->sockfd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))) {
        rc = -errno;
        avd_log_error("Peer Server socket setup failed: %s", strerror(errno));
        return rc;
    }

    rc = inet_pton(AF_INET, conn->addr, &ps_addr.sin_addr.s_addr);
    if (rc == 0) {
        rc = -errno;
        avd_log_error("Peer server IP address invalid format: %s",
                      strerror(errno));
        goto bail;
    }

    if (rc < 0) {
        avd_log_error("Peer server inet_pton error: %s", strerror(errno));
        goto bail;
    }

    ps_addr.sin_family = AF_INET;
    ps_addr.sin_port = htons(conn->port);

    rc = bind(conn->sockfd, (struct sockaddr *)&ps_addr, sizeof(ps_addr));
    if (rc < 0) {
        avd_log_error("Peer server socket bind error: %s", strerror(errno));
        goto bail;
    }

    rc = listen(conn->sockfd, 3);
    if (rc < 0) {
        avd_log_error("Peer server socket listen fail: %s", strerror(errno));
        goto bail;
    }

    avd_log_info("Peer server listening on %s:%d",conn->addr,conn->port);

    return 0;

bail:
    close(conn->sockfd);
    return rc;
}

void peer_communication (peer_server_t *ps) {
    conn_info_t     *conn = &ps->conn;
#define sockfd conn->sockfd
    if (sockfd < 0)
        return;

    while (true) {
        avd_log_debug("Future peer comm");
        sleep(2);
    }
#undef sockfd
}

void * peer_server_routine (void *arg) {
    int32_t             rc;
    socklen_t           sz;
    peer_server_t       *ps = (peer_server_t *)(arg);
    conn_info_t         *conn = &ps->conn;
    conn_info_t         *p = &ps->peer;
    struct sockaddr_in  p_addr;

    if (0 > (rc = ps_init(conn))) {
        avd_log_error("Peer server init failed: %s", strerror(errno));
        close(conn->sockfd);
        exit(EXIT_FAILURE);
    }

    rc = accept(conn->sockfd, (struct sockaddr *)&p_addr, &sz);
    if (rc < 0) {
        rc = -errno;
        avd_log_error("Peer accept connection failed: %s", strerror(errno));
        goto bail;
    }

    p->sockfd = rc;
    p->port = sock_ntop_port(&p_addr);
    snprintf(p->addr, INET_ADDRSTRLEN, "%s",sock_ntop_addr(&p_addr));

    avd_log_info("Peer connected: %s", sock_ntop(&p_addr));
    avd_log_debug("\tPeer Info:\n\t\tsockfd: %d", p->sockfd);

    peer_communication (ps);

bail:
    return NULL;
}
