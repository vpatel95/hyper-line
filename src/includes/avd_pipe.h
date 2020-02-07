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

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#define MAX_USERS       1
#define MAX_TASKS       2
#define MAX_SUBTASKS    5
#define MAX_WORKERS     5

#define MAX_CHUNK_SZ    256

#define print(__fmt, ...)   do {                \
    fprintf(stdout, __fmt, ##__VA_ARGS__);      \
    fflush(stdout);                             \
} while(0)

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
    task_t          tasks[MAX_TASKS];
    conn_info_t     conn;
} user_t;

typedef struct server_s {
    int32_t             n_users;
    int32_t             n_workers;
    user_t              users[MAX_USERS];
    worker_t            workers[MAX_WORKERS];
    conn_info_t         conn;
} server_t;

#endif
