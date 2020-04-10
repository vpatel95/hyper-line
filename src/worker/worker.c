#define _GNU_SOURCE
#include "avd_pipe.h"
#include "avd_log.h"
#include "avd_message.h"
#include "avd_session.h"
#include "peer_helper.h"
#include "worker_helper.h"
#include "peer_server_helper.h"

char    *g_conf_file_name = NULL;

int32_t main (int32_t argc, char *argv[]) {
    pthread_t           threads[3];
#define w_thrd          threads[0]
#define ps_thrd         threads[1]
#define p_thrd          threads[2]
    conf_parse_info_t   cfg;
    peer_t              p;
    worker_t            w;
    peer_server_t       ps;

    signal_intr(SIGINT, sig_int_handler);

    memset(&p, 0, sizeof(p));
    memset(&w, 0, sizeof(w));
    memset(&ps, 0, sizeof(ps));
    memset(&cfg, 0, sizeof(cfg));

    g_conf_file_name = (char *)argv[1];

    if (argc < 2)
        exit(EXIT_FAILURE);

    if (0 != process_config_file(g_conf_file_name, WORKER, &cfg)) {
        print("Failed to parse config file %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    w.peer_id = false;
    w.uname = (char *)malloc(strlen(cfg.wconf.uname)+1);
    snprintf(w.uname, strlen(cfg.wconf.uname)+1, "%s", cfg.wconf.uname);

    w.conn.port = cfg.wconf.srvr_port;
    snprintf(w.conn.addr, strlen(cfg.wconf.srvr_addr)+1,
             "%s", cfg.wconf.srvr_addr);

    ps.conn.port = cfg.wconf.peer_port;
    snprintf(ps.conn.addr, strlen(cfg.wconf.peer_addr)+1,
             "%s", cfg.wconf.peer_addr);

    w.peer.port = cfg.wconf.peer_port;
    snprintf(w.peer.addr, strlen(cfg.wconf.peer_addr)+1,
             "%s", cfg.wconf.peer_addr);

    setup_logger(&cfg.wconf.logger);

    if (0 != pthread_create(&w_thrd, NULL, worker_routine, &w)) {
        avd_log_fatal("Worker thread creation failed");
        exit(EXIT_FAILURE);
    }
    pthread_setname_np(w_thrd, "avdw_worker");

    if (0 != pthread_create(&ps_thrd, NULL, peer_server_routine, &ps)) {
        avd_log_fatal("Worker thread creation failed");
        exit(EXIT_FAILURE);
    }
    pthread_setname_np(ps_thrd, "avdw_peer_srv");

    if (0 != pthread_create(&p_thrd, NULL, peer_routine, &p)) {
        avd_log_fatal("Peer thread creation failed");
        exit(EXIT_FAILURE);
    }
    pthread_setname_np(p_thrd, "avdw_peer");

    pthread_join(w_thrd, NULL);
    pthread_join(ps_thrd, NULL);
    pthread_join(p_thrd, NULL);

    int i=1;
    while (true) {
        avd_log_info("MAIN THREAD :::: %d", i++);
        sleep(10);
    }

    exit(EXIT_SUCCESS);
}
