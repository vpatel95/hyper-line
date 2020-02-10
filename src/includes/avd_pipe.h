#ifndef _AVD_PIPE_H_
#define _AVD_PIPE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

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

#ifndef INFTIM
#define INFTIM      (-1)
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#define USER            1
#define WORKER          2

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

#ifndef abs
#define abs(x)      ((x) < 0 ? -(x) : (x))
#endif

#ifndef min
#define min(a,b)    ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b)    ((a) > (b) ? (a) : (b))
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

typedef void (sigfunc)(int);

typedef struct conn_info_s {
    int32_t             sockfd;
    uint16_t            port;
    char                ip_addr_s[INET_ADDRSTRLEN];
} conn_info_t;

// TODO
typedef struct input_s {
    int input;
} input_t;

// TODO
typedef struct result_s {
    int result;
} result_t;

// TODO
typedef struct peer_s {
    int peer;
} peer_t;

typedef struct worker_s {
    int32_t         id;
    peer_t          peers[2];
    conn_info_t     conn;
} worker_t;

typedef struct stage_s {
    worker_t    worker;
    input_t    input;
    result_t    result;
} stage_t;

typedef struct task_s {
    int32_t     id;
    int32_t     num_subtasks;
    stage_t     stages;
} task_t;

typedef struct user_s {
    int32_t         id;
    int32_t         num_tasks;
    task_t          tasks[MAX_TASK];
    conn_info_t     conn;
} user_t;

typedef struct server_s {
    uint8_t             type;
    int32_t             n_users;
    int32_t             n_workers;
    union {
        user_t          users[MAX_USER];
        worker_t        workers[MAX_WORKER];
    };
    struct pollfd       poller[MAX_POLLER_SZ];
    conn_info_t         conn;
} server_t;

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
    print("\nClosing server in 5 secs\n");
    sleep(5);
    exit(1);
}

#endif
