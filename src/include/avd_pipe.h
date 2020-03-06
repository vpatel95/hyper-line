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
#include <sys/time.h>

#include <pthread.h>

#include "cJSON.h"

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


#define INFO     "INFO"
#define WARN     "WARN"
#define ERROR    "ERROR"
#define CRITICAL "CRITICAL"
#define L_SRVR   "SERVER"
#define L_USER   "USER"
#define L_WORKER "WORKER"
#define log(proc, level, msg) print("[%s][%s][%s] ::: %s ", get_curr_time(), proc, level, msg)

#define USER            1
#define WORKER          2
#define SERVER          3

#define MAX_USER        2
#define MAX_TASK        2
#define MAX_SUBTASK     5
#define MAX_WORKER      5

#define MAX_USER_POLL   MAX_USER + 1
#define MAX_WORKER_POLL MAX_WORKER + 1
#define MAX_POLLER_SZ   max(MAX_USER_POLL,MAX_WORKER_POLL)

#define MAX_POLL_SZ(type) ((type == USER) ? MAX_USER_POLL : MAX_WORKER_POLL)
#define CLIENT_TYPE(type) ((type == USER) ? "User" : "Worker")

#define MAX_CHUNK_SZ    256
#define MAX_BUF_SZ      2048

// Message type flags
#define AVD_MSG_F_FILE  (1 << 0)
#define AVD_MSG_F_CTRL  (1 << 1)

#define reset_type(type)        (type = 0)
#define set_type(type, flag)    (type |= flag)
#define unset_type(type, flag)  (type &= (~flag))
#define is_type(type, flag)     (type & flag)

typedef void (sigfunc)(int);

typedef struct conn_info_s {
    uint16_t            port;
    int32_t             sockfd;
    char                ip_addr_s[INET_ADDRSTRLEN];
} __attribute__((packed)) conn_info_t;

// TODO
typedef struct input_s {
    int input;
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
    worker_t    worker;
    input_t    input;
    result_t    result;
} __attribute__((packed)) stage_t;

typedef struct task_s {
    int32_t     id;
    int32_t     num_subtasks;
    stage_t     stages;
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
    union {
        int32_t             n_users;
        int32_t             n_workers;
    };
    union {
        user_t          users[MAX_USER];
        worker_t        workers[MAX_WORKER];
    };
    struct pollfd       poller[MAX_POLLER_SZ];
    conn_info_t         conn;
} __attribute__((packed)) server_t;

typedef struct content_s {
    char        data[256];
} __attribute__((packed)) content_t;

typedef struct message_s {
    int8_t      type;
    size_t      size;
    content_t   content;
} __attribute__((packed)) message_t;

typedef struct args_s {
    server_t    srvr;
    char        addr[16];
    int         port;
} __attribute__((packed)) args_t;

typedef struct server_conf_s {
    uint16_t    uport;
    uint16_t    wport;
    char        addr[INET_ADDRSTRLEN];
} __attribute__((packed)) server_conf_t;

typedef struct user_conf_s {
    uint16_t    port;
    char        addr[INET_ADDRSTRLEN];
} __attribute__((packed)) user_conf_t;

typedef struct worker_conf_s {
    uint16_t    port;
    char        addr[INET_ADDRSTRLEN];
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

char * get_curr_time() {
    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    return asctime(timeinfo);
}

static size_t filesize (FILE *f) {
    size_t  c = ftell(f);
    size_t  l;
    fseek(f, 0L, SEEK_END);
    l = ftell(f);
    fseek(f, c, SEEK_SET);
    return l;
}

static int32_t parse_srvr_cfg (cJSON *obj, conf_parse_info_t *cfg) {
    cJSON   *v, *tobj;

    tobj = cJSON_GetObjectItem(obj, "server");
    if (!tobj) {
        return -1;
    }

    v = cJSON_GetObjectItem(tobj, "uport");
    if ((!v) || (!v->valueint)) {
        log(L_SRVR, ERROR, "Failed to find 'uport' in server config");
        return -1;
    }
    cfg->sconf.uport = v->valueint;

    v = cJSON_GetObjectItem(tobj, "wport");
    if ((!v) || (!v->valueint)) {
        log(L_SRVR, ERROR, "Failed to find 'wport' in server config");
        return -1;
    }
    cfg->sconf.wport = v->valueint;

    v = cJSON_GetObjectItem(tobj, "addr");
    if ((!v) || (!v->valuestring)) {
        log(L_SRVR, ERROR, "Failed to find 'addr' in server config");
        return -1;
    }
    snprintf(cfg->sconf.addr, INET_ADDRSTRLEN, "%s", v->valuestring);

    return 0;
}

// TODO:
static int32_t parse_user_cfg (cJSON *obj, conf_parse_info_t *cfg) {
    cJSON   *v, *tobj;

    tobj = cJSON_GetObjectItem(obj, "user");
    if (!tobj) {
        return -1;
    }

    v = cJSON_GetObjectItem(tobj, "port");
    if ((!v) || (!v->valueint)) {
        log(L_SRVR, ERROR, "Failed to find 'port' in user config");
        return -1;
    }
    cfg->uconf.port = v->valueint;

    v = cJSON_GetObjectItem(tobj, "addr");
    if ((!v) || (!v->valuestring)) {
        log(L_SRVR, ERROR, "Failed to find 'addr' in user config");
        return -1;
    }
    snprintf(cfg->uconf.addr, INET_ADDRSTRLEN, "%s", v->valuestring);

    return 0;
}

// TODO:
static int32_t parse_wrkr_cfg (cJSON *obj, conf_parse_info_t *cfg) {
    cJSON   *v, *tobj;

    tobj = cJSON_GetObjectItem(obj, "worker");
    if (!tobj) {
        return -1;
    }

    v = cJSON_GetObjectItem(tobj, "port");
    if ((!v) || (!v->valueint)) {
        log(L_SRVR, ERROR, "Failed to find 'port' in worker config");
        return -1;
    }
    cfg->wconf.port = v->valueint;

    v = cJSON_GetObjectItem(tobj, "addr");
    if ((!v) || (!v->valuestring)) {
        log(L_SRVR, ERROR, "Failed to find 'addr' in worker config");
        return -1;
    }
    snprintf(cfg->wconf.addr, INET_ADDRSTRLEN, "%s", v->valuestring);

    return 0;
}

int32_t process_config_file (char *fname, conf_parse_info_t *cfg) {
    FILE        *fp = fopen(fname, "r");
    char        *buf = NULL;
    cJSON       *json_obj = NULL;
    size_t      len;
    int32_t     rc = -1;

    if (NULL == fp) {
        log(L_SRVR, CRITICAL, "Failed to open config file");
        goto bail;
    }

    len = filesize(fp);
    buf = (char *)malloc(len);
    if (!buf) {
        log(L_SRVR, ERROR, "Failed to allocate memory while reading file");
        goto bail;
    }

    memset(buf, 0, sizeof(len));
    if (len != fread(buf, 1, len, fp)) {
        log(L_SRVR, ERROR, "Failed to read all the data from the file");
        goto bail;
    }

    if (NULL == (json_obj = cJSON_Parse(buf))) {
        log(L_SRVR, ERROR, "Failed to parse JSON of config");
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
    if (buf) { free(buf); buf = NULL; }
    if (fp) { fclose(fp); fp = NULL; }

    return rc;
}

#endif