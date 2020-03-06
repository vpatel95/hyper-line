#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "log.h"
#include "cJSON.h"
#include "avd_pipe.h"

#define SESSION_FILE    "/opt/avd-pipe/session.json"

typedef struct avd_user_session_s {
    cJSON   *root;
    cJSON   *tasks;
} avd_user_session_t;

typedef struct avd_worker_session_s {

} avd_worker_session_t;

typedef struct avd_server_session_s {
    cJSON                   *root;
    avd_user_session_t      usess;
    avd_worker_session_t    wsess;
} avd_server_session_t;

avd_server_session_t     g_srvr_session;

int32_t remove_user_s_session(int32_t user_id) {
    int32_t     i, rc = -1;
    int32_t     uobj_sz;
    FILE        *fp = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    cJSON   *uobj_arr = cJSON_GetObjectItem(sess->root, "users");
    if (!uobj_arr) {
        avd_log_debug("Failed to parse 'user' field from session file");
        goto bail;
    }

    uobj_sz = cJSON_GetArraySize(uobj_arr);
    for (i = 0; i < uobj_sz; i++) {
        cJSON *uobj = cJSON_GetArrayItem(uobj_arr, i);
        if (!uobj) {
            avd_log_debug("Failed to retrieve user from 'users' object");
            goto bail;
        }

        cJSON *v = cJSON_GetObjectItem(uobj, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from user object");
            goto bail;
        }

        if (v->valueint == user_id) {
            cJSON_DeleteItemFromArray(uobj_arr, i);
            break;
        }
    }

    if (!file_exists(SESSION_FILE, F_OK)) {
        avd_log_debug("Failed to find session file");
        goto bail;
    }

    fp = fopen(SESSION_FILE, "w+");
    if (!fp) {
        avd_log_debug("Failed to create session file");
        goto bail;
    }

    fprintf(fp, "%s", cJSON_Print(sess->root));
    fflush(fp);

    rc = 0;
bail:
    return rc;
}

int32_t create_user_s_session(server_t *srvr, int32_t user_idx) {
    int                     rc = -1;
    char                    *sess_str;
    FILE                    *fp = NULL;
    cJSON                   *u_arr = NULL;
    cJSON                   *u = NULL;
    cJSON                   *u_id = NULL;
    cJSON                   *tasks = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;
    user_t                  *user = &srvr->users[user_idx];

    if (file_exists(SESSION_FILE, F_OK)) {
        sess->root = parse_json(SESSION_FILE);

        u_arr = cJSON_GetObjectItem(sess->root, "users");
        avd_log_debug("%s", cJSON_Print(sess->root));
    } else {
        sess->root = cJSON_CreateObject();
        if (!sess->root) goto bail;

        u_arr = cJSON_CreateArray();
        if (!u_arr) goto bail;

        cJSON_AddItemToObject(sess->root, "users", u_arr);
    }

    u = cJSON_CreateObject();
    if (!u) goto bail;

    u_id = cJSON_CreateNumber(srvr->new_client_id);
    if (!u_id) goto bail;

    tasks = cJSON_CreateArray();
    if (!tasks) goto bail;

    cJSON_AddItemToObject(u, "id", u_id);
    cJSON_AddItemToObject(u, "tasks", tasks);
    cJSON_AddItemToArray(u_arr, u);

    sess_str = cJSON_Print(sess->root);
    if (!sess_str) {
        avd_log_debug("Failed to print json");
        goto bail;
    }

    fp = fopen(SESSION_FILE, "w+");
    if (!fp) {
        avd_log_debug("Failed to create session file");
        goto bail;
    }

    fprintf(fp, "%s", sess_str);
    fflush(fp);

    user->id = srvr->new_client_id++;

    rc = 0;

bail:
    if (fp) { fclose(fp); fp = NULL; }
    return rc;
}


