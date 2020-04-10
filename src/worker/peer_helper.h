#include <stdio.h>
#include <inttypes.h>

#include "avd_pipe.h"
#include "avd_message.h"
#include "avd_session.h"

int32_t peer_init () {
    int32_t             rc;
    int32_t             fd;

    fd = get_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0) {
        rc = -errno;
        print("[ERROR][CRITICAL] ::: Worker socket setup failed: %s\n",
                strerror(errno));
        goto error;
    }

    return fd;

error:
    close_fd(fd);
    return rc;
}

int32_t connect_peer_server(peer_t *p) {

    int32_t             rc = -1;
    conn_info_t         *ps = &p->ps;
    struct sockaddr_in  ps_addr;

    ps->sockfd = peer_init();

    if (0 == (rc = inet_pton(AF_INET, ps->addr,
                             &ps_addr.sin_addr.s_addr))) {
        avd_log_error("Peer server IP inet_pton error:%s", strerror(errno));
        goto bail;
    }
    ps_addr.sin_family = AF_INET;
    ps_addr.sin_port = htons(ps->port);

    avd_log_debug("Connecting to peer server on %s:%d",
                  ps->addr, ps->port);
    if (0 > (rc = connect(ps->sockfd, (struct sockaddr *)&ps_addr,
                          sizeof(ps_addr)))) {
        avd_log_fatal("Error connecting to the server at \"%s:%d\" : %s",
                      ps->addr, ps->port, strerror(errno));
        goto bail;
    }

    avd_log_info("Connected to peer server on %s", sock_ntop(&ps_addr));

    return 0;

bail:
    close_fd(ps->sockfd);
    return rc;
}

int32_t get_peer_server(peer_t *p) {
    int32_t     rc = -1;
    cJSON       *v = NULL;
    cJSON       *ps = get_peer_server_w_sess();

    v = cJSON_GetObjectItem(ps, "port");
    if ((!v) || (!v->valueint)) {
        avd_log_debug("Cannot find port in peer server");
        goto bail;
    }
    p->ps.port = v->valueint;

    v = cJSON_GetObjectItem(ps, "addr");
    if ((!v) || (!v->valuestring)) {
        avd_log_debug("Cannot find addr in peer server");
        goto bail;
    }
    snprintf(p->ps.addr, strlen(v->valuestring)+1, "%s", v->valuestring);

    rc = 0;

bail:
    return rc;
}

bool peer_server_id() {
    return is_peer_id_w_sess();
}

bool get_worker_details(peer_t *p) {
    int32_t     rc;

    if (0 > (rc = get_worker_id_w_sess())) {
        avd_log_error("Invalid worker id");
        goto bail;
    }
    p->wid = rc;

    if (0 > (rc = get_worker_type_w_sess())) {
        avd_log_error("Invalid worker type");
        goto bail;
    }
    p->type = rc;

    return true;

bail:
    return false;
}

static void * peer_routine (void * arg) {
    int32_t     rc;
    peer_t      *p = (peer_t *)(arg);

    while (!get_worker_details(p)) {
        avd_log_debug("Waiting for worker id");
        sleep(3);
    }

    while (!peer_server_id()) {
        avd_log_debug("Waiting for peer server");
        sleep(5);
    }

    if (p->type == BASE_WORKER) {
        goto bail;
    }

    if (0 > (rc = get_peer_server(p))) {
        avd_log_error("Cannot get peer server details");
        goto bail;
    }

    if (0 > (rc = connect_peer_server(p))) {
        avd_log_error("Cannot establish connection with peer server: %s",
                      strerror(errno));
        goto bail;
    }

    while(true) {
        avd_log_info("Dummy peer communication");
        sleep(10);
    }

bail:
    return NULL;
}
