#ifndef _AVD_PIPE_H_
#define _AVD_PIPE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <poll.h>
#include <limits.h>

#include <pthread.h>

#include "cJSON.h"
#include "log.h"

#ifndef INFTIM
#define INFTIM      (-1)
#endif


#ifndef abs
#define abs(x)      ((x) < 0 ? -(x) : (x))
#endif

#ifndef min
#define min(a,b)    ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b)    ((a) > (b) ? (a) : (b))
#endif

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#define print(__fmt, ...)   do {                \
    fprintf(stdout, __fmt, ##__VA_ARGS__);      \
    fflush(stdout);                             \
} while(0)

#ifndef close_fd
#define close_fd(__fd) if(__fd > 0) {   \
    close(__fd);                        \
    __fd = -1;                          \
}
#endif

#define err_sys(__err) {    \
    perror(__err);          \
    exit(1);                \
}

#define USER            1
#define WORKER          2
#define SERVER          3

#define MAX_USER        2
#define MAX_TASK        2
#define MAX_STAGES      5
#define MAX_WORKER      5

#define MAX_USER_POLL   MAX_USER + 1
#define MAX_WORKER_POLL MAX_WORKER + 1
#define MAX_POLLER_SZ   max(MAX_USER_POLL,MAX_WORKER_POLL)

#define CLIENT_TYPE(type) ((type == USER) ? "User" : "Worker") 

#define MAX_BUF_SZ          2048
#define MAX_CHUNK_SZ        256
#define MAX_FILE_NAME_SZ    50

// Message type flags
#define AVD_MSG_F_NEW_CON   (1 << 0)
#define AVD_MSG_F_RE_CON    (1 << 1)
#define AVD_MSG_F_FILE      (1 << 2)
#define AVD_MSG_F_CTRL      (1 << 3)

#define reset_msg_type(type)        (type = 0)
#define set_msg_type(type, flag)    (type |= flag)
#define unset_msg_type(type, flag)  (type &= (~flag))
#define is_msg_type(type, flag)     (type & flag)

typedef void (sigfunc)(int);

typedef struct conn_info_s {
    uint16_t            port;
    int32_t             sockfd;
    char                ip_addr_s[INET_ADDRSTRLEN];
} __attribute__((packed)) conn_info_t;

// TODO
typedef struct input_s {
    char    *input;
} __attribute__((packed)) input_t;

// TODO
typedef struct result_s {
    int result;
} __attribute__((packed)) result_t;

// TODO
typedef struct peer_s {
    int peer;
} __attribute__((packed)) peer_t;

typedef struct worker_s {
    int32_t         id;
    peer_t          peers[2];
    conn_info_t     conn;
} __attribute__((packed)) worker_t;

typedef struct stage_s {
    int32_t     id;
    worker_t    worker;
    input_t     input;
    result_t    result;
} __attribute__((packed)) stage_t;

typedef struct task_s {
    int32_t     id;
    int32_t     num_stages;
    stage_t     stages[MAX_STAGES];
} __attribute__((packed)) task_t;

typedef struct user_s {
    int32_t         id;
    int32_t         poll_id;
    int32_t         num_tasks;
    task_t          tasks[MAX_TASK];
    conn_info_t     conn;
} __attribute__((packed)) user_t;

typedef struct server_s {
    uint8_t             type;
    int32_t             n_clients;
    int32_t             new_client_id;
    int32_t             max_poll_sz;
    int32_t             curr_poll_sz;
    struct pollfd       poller[MAX_POLLER_SZ];
    conn_info_t         conn;
    union {
        user_t          users[MAX_USER];
        worker_t        workers[MAX_WORKER];
    };
} __attribute__((packed)) server_t;

typedef struct content_s {
    char        data[MAX_CHUNK_SZ];
} __attribute__((packed)) content_t;

typedef struct message_s {
    int8_t      type;
    size_t      size;
    content_t   content;
} __attribute__((packed)) message_t;

typedef struct args_s {
    server_t    srvr;
    char        addr[INET_ADDRSTRLEN];
    int         port;
} __attribute__((packed)) args_t;

typedef struct server_conf_s {
    uint16_t    uport;
    uint16_t    wport;
    char        addr[INET_ADDRSTRLEN];
    char        log_ufile[MAX_FILE_NAME_SZ];
    char        log_wfile[MAX_FILE_NAME_SZ];
    int32_t     log_level;
    int32_t     log_quiet;
} __attribute__((packed)) server_conf_t;

typedef struct user_conf_s {
    uint16_t    port;
    char        addr[INET_ADDRSTRLEN];
    char        log_file[MAX_FILE_NAME_SZ];
    int32_t     log_level;
    int32_t     log_quiet;
} __attribute__((packed)) user_conf_t;

typedef struct worker_conf_s {
    uint16_t    port;
    char        addr[INET_ADDRSTRLEN];
    char        log_file[MAX_FILE_NAME_SZ];
    int32_t     log_level;
    int32_t     log_quiet;
} __attribute__((packed)) worker_conf_t;

typedef struct conf_parse_info_s {
    int8_t      type;
    union {
        server_conf_t   sconf;
        user_conf_t     uconf;
        worker_conf_t   wconf;
    };
} __attribute__((packed)) conf_parse_info_t;

int32_t get_socket(int32_t family, int32_t type, int32_t protocol) {

    int32_t     rc;
    int32_t     sockfd;

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

char * sock_ntop (const struct sockaddr *sa) {
    char            portstr[8];
    static char     str[128];

    struct sockaddr_in  *sin = (struct sockaddr_in *) sa;

    if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
        return NULL;

    if (ntohs(sin->sin_port) != 0) {
        snprintf(portstr, sizeof(portstr), ":%d", ntohs(sin->sin_port));
        strcat(str, portstr);
    }

    return str;
}

char * sock_ntop_addr (const struct sockaddr *sa) {
    static char     str[128];

    struct sockaddr_in  *sin = (struct sockaddr_in *) sa;

    if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
        return NULL;

    return str;
}

uint16_t sock_ntop_port (const struct sockaddr *sa) {
    struct sockaddr_in  *sin = (struct sockaddr_in *) sa;

    return ntohs(sin->sin_port);
}

sigfunc * signal_helper(int32_t signo, sigfunc *func) {
    struct sigaction        act, oact;

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (signo == SIGALRM) {
#ifdef  SA_INTERRUPT
        act.sa_flags |= SA_INTERRUPT;
#endif
    } else {
#ifdef SA_RESTART
        act.sa_flags |= SA_RESTART;
#endif
    }

    if (sigaction(signo, &act, &oact) < 0) {
        return SIG_ERR;
    }

    return oact.sa_handler;
}

sigfunc * signal (int32_t signo, sigfunc *func) {
    sigfunc *sigfn;

    if ((sigfn = signal_helper(signo, func)) == SIG_ERR) {
        err_sys("signal_error");
    }

    return sigfn;
}


sigfunc * signal_intr_helper(int32_t signo, sigfunc *func) {
    struct sigaction        act, oact;

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
#ifdef  SA_INTERRUPT
        act.sa_flags |= SA_INTERRUPT;
#endif

    if (sigaction(signo, &act, &oact) < 0) {
        return SIG_ERR;
    }

    return oact.sa_handler;
}

sigfunc * signal_intr (int32_t signo, sigfunc *func) {
    sigfunc *sigfn;

    if ((sigfn = signal_intr_helper(signo, func)) == SIG_ERR) {
        err_sys("signal_error");
    }

    return sigfn;
}

void sig_int_handler(int32_t signo) {
    print("\nClosing server in 1 secs\n");
    sleep(1);
    exit(EXIT_SUCCESS);
}

static size_t filesize (FILE *f) {
    size_t  c = ftell(f);
    size_t  l;
    fseek(f, 0L, SEEK_END);
    l = ftell(f);
    fseek(f, c, SEEK_SET);
    return l;
}

cJSON * parse_json (char *fname) {
    FILE        *fp = fopen(fname, "r");
    char        *buf = NULL;
    cJSON       *json_obj = NULL;
    size_t      len;

    if (NULL == fp) {
        avd_log_fatal("Failed to open config file");
        goto bail;
    }

    len = filesize(fp);
    buf = (char *)malloc(len);
    if (!buf) {
        avd_log_error("Failed to allocate memory while reading file");
        goto bail;
    }

    memset(buf, 0, sizeof(len));
    if (len != fread(buf, 1, len, fp)) {
        avd_log_error("Failed to read all the data from the file");
        goto bail;
    }

    json_obj = cJSON_Parse(buf);

bail:
    if (buf) { free(buf); buf = NULL; }
    if (fp) { fclose(fp); fp = NULL; }

    return json_obj;
}


static int32_t parse_srvr_cfg (cJSON *obj, conf_parse_info_t *cfg) {
    cJSON   *v, *tobj;

    tobj = cJSON_GetObjectItem(obj, "server");
    if (!tobj) {
        return -1;
    }

    v = cJSON_GetObjectItem(tobj, "log_user_file");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find 'log_user_file' in server config");
        return -1;
    }
    snprintf(cfg->sconf.log_ufile, strlen(v->valuestring)+1, "%s", v->valuestring);

    v = cJSON_GetObjectItem(tobj, "log_worker_file");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find 'log_worker_file' in server config");
        return -1;
    }
    snprintf(cfg->sconf.log_wfile, strlen(v->valuestring)+1, "%s", v->valuestring);

    v = cJSON_GetObjectItem(tobj, "log_level");
    if (!v) {
        avd_log_error("Failed to find 'log_level' in server config");
        return -1;
    }
    cfg->sconf.log_level = v->valueint;

    v = cJSON_GetObjectItem(tobj, "log_quiet");
    if (!v) {
        avd_log_error("Failed to find 'log_quiet' in server config");
        return -1;
    }
    cfg->sconf.log_quiet = v->valueint;

    v = cJSON_GetObjectItem(tobj, "uport");
    if (!v) {
        avd_log_error("Failed to find 'uport' in server config");
        return -1;
    }
    cfg->sconf.uport = v->valueint;

    v = cJSON_GetObjectItem(tobj, "wport");
    if (!v) {
        avd_log_error("Failed to find 'wport' in server config");
        return -1;
    }
    cfg->sconf.wport = v->valueint;

    v = cJSON_GetObjectItem(tobj, "addr");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find 'addr' in server config");
        return -1;
    }
    snprintf(cfg->sconf.addr, INET_ADDRSTRLEN, "%s", v->valuestring);

    return 0;
}

static int32_t parse_user_cfg (cJSON *obj, conf_parse_info_t *cfg) {
    cJSON   *v, *tobj;

    tobj = cJSON_GetObjectItem(obj, "user");
    if (!tobj) {
        return -1;
    }

    v = cJSON_GetObjectItem(tobj, "log_file");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find 'log_file' in user config");
        return -1;
    }
    snprintf(cfg->uconf.log_file, strlen(v->valuestring)+1, "%s", v->valuestring);

    v = cJSON_GetObjectItem(tobj, "log_level");
    if (!v) {
        avd_log_error("Failed to find 'log_level' in user config");
        return -1;
    }
    cfg->uconf.log_level = v->valueint;

    v = cJSON_GetObjectItem(tobj, "log_quiet");
    if (!v) {
        avd_log_error("Failed to find 'log_quiet' in user config");
        return -1;
    }
    cfg->uconf.log_quiet = v->valueint;

    v = cJSON_GetObjectItem(tobj, "srvr_port");
    if (!v) {
        avd_log_error("Failed to find 'srvr_port' in user config");
        return -1;
    }
    cfg->uconf.port = v->valueint;

    v = cJSON_GetObjectItem(tobj, "srvr_addr");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find 'srvr_addr' in user config");
        return -1;
    }
    snprintf(cfg->uconf.addr, strlen(v->valuestring)+1, "%s", v->valuestring);

    return 0;
}

static int32_t parse_wrkr_cfg (cJSON *obj, conf_parse_info_t *cfg) {
    cJSON   *v, *tobj;

    tobj = cJSON_GetObjectItem(obj, "worker");
    if (!tobj) {
        return -1;
    }

    v = cJSON_GetObjectItem(tobj, "log_file");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find 'log_file' in worker config");
        return -1;
    }
    snprintf(cfg->wconf.log_file, strlen(v->valuestring)+1, "%s", v->valuestring);

    v = cJSON_GetObjectItem(tobj, "log_level");
    if (!v) {
        avd_log_error("Failed to find 'log_level' in worker config");
        return -1;
    }
    cfg->wconf.log_level = v->valueint;

    v = cJSON_GetObjectItem(tobj, "log_quiet");
    if (!v) {
        avd_log_error("Failed to find 'log_quiet' in worker config");
        return -1;
    }
    cfg->wconf.log_quiet = v->valueint;

    v = cJSON_GetObjectItem(tobj, "port");
    if (!v) {
        avd_log_error("Failed to find 'port' in worker config");
        return -1;
    }
    cfg->wconf.port = v->valueint;

    v = cJSON_GetObjectItem(tobj, "addr");
    if ((!v) || (!v->valuestring)) {
        avd_log_error("Failed to find 'addr' in worker config");
        return -1;
    }
    snprintf(cfg->wconf.addr, INET_ADDRSTRLEN, "%s", v->valuestring);

    return 0;
}

int32_t process_config_file (char *fname, conf_parse_info_t *cfg) {
    cJSON       *json_obj = NULL;
    int32_t     rc = -1;

    if (NULL == (json_obj = parse_json(fname))) {
        avd_log_error("Failed to parse JSON of config");
        goto bail;
    }

    switch (cfg->type) {
        case SERVER:
            rc = parse_srvr_cfg(json_obj, cfg);
            break;
        case USER:
            rc = parse_user_cfg(json_obj, cfg);
            break;
        case WORKER:
            rc = parse_wrkr_cfg(json_obj, cfg);
            break;
    }


bail:
    if (json_obj) { cJSON_Delete(json_obj); json_obj = NULL; }

    return rc;
}

bool file_exists(char *fname, int flag) {
    if (0 == access(fname, flag))
        return true;
    return false;
}

#endif
