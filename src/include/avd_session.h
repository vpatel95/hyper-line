#ifndef _AVD_SESSION_H_
#define _AVD_SESSION_H_

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "cJSON.h"
#include "avd_log.h"
#include "avd_pipe.h"

#define SESSION_FILE    APP_ROOT "/session.json"

typedef struct avd_user_session_s {
    cJSON       *root;
    cJSON       *tasks[MAX_TASK];
    int32_t     num_tasks;
} avd_user_session_t;

typedef struct avd_worker_session_s {
    cJSON   *root;
} avd_worker_session_t;

typedef struct avd_server_session_s {
    cJSON                   *root;
    int32_t                 num_users;
    int32_t                 num_workers;
    avd_user_session_t      usess[MAX_USER];
    avd_worker_session_t    wsess[MAX_WORKER];
} avd_server_session_t;

avd_server_session_t    g_srvr_session;
avd_user_session_t      g_user_session;
avd_worker_session_t    g_wrkr_session;

int32_t write_to_sess_file (cJSON *root) {
    int32_t         rc = -1;
    FILE            *fp = NULL;
    char            *str;

    str = cJSON_Print(root);
    if (!str) {
        avd_log_debug("Failed to print json");
        goto bail;
    }

    fp = fopen(SESSION_FILE, "w+");
    if (!fp) {
        avd_log_debug("Failed to create session file");
        goto bail;
    }

    fprintf(fp, "%s", str);
    fflush(fp);

    rc = 0;

bail:
    if (fp) { fclose(fp); fp = NULL; }
    return rc;
}

int32_t build_server_sess() {
    int32_t     i, j, rc = -1;
    int32_t     uobj_sz;
    int32_t     wobj_sz;
    avd_server_session_t    *sess = (avd_server_session_t *) &g_srvr_session;

    if (file_exists(SESSION_FILE, F_OK)) {
        if (NULL == (sess->root = parse_json(SESSION_FILE))) {
            goto bail;
        }
    } else {
        avd_log_error("Failed to locate config file");
        goto bail;
    }

    cJSON *uobj_arr = cJSON_GetObjectItem(sess->root, "users");
    if (uobj_arr) {
        uobj_sz = cJSON_GetArraySize(uobj_arr);
        sess->num_users = uobj_sz;

        if (uobj_sz > MAX_USER) {
            avd_log_error("Users in session exceeded limit");
            goto bail;
        }

        for (i = 0; i < uobj_sz; i++) {
            avd_user_session_t      *usess = &sess->usess[i];
            usess->root = cJSON_GetArrayItem(uobj_arr, i);

            cJSON *task_arr = cJSON_GetObjectItem(usess->root, "tasks");
            usess->num_tasks = cJSON_GetArraySize(task_arr);
            for (j = 0; j < usess->num_tasks; j++) {
                usess->tasks[j] = cJSON_GetArrayItem(task_arr, j);
            }
        }
    }

    cJSON *wobj_arr = cJSON_GetObjectItem(sess->root, "workers");
    if (wobj_arr) {
        wobj_sz = cJSON_GetArraySize(wobj_arr);
        sess->num_workers = wobj_sz;

        if (wobj_sz > MAX_WORKER) {
            avd_log_error("Workers in session exceeded limit");
            goto bail;
        }

        for (i = 0; i < wobj_sz; i++) {
            avd_worker_session_t    *wsess = &sess->wsess[i];
            wsess->root = cJSON_GetArrayItem(wobj_arr, i);
        }
    }

    rc = 0;

bail:
    return rc;
}

int32_t get_max_user_id_s_sess() {
    int max_id = 1;
    int32_t                 i;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        cJSON *v = cJSON_GetObjectItem(usess->root, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from user object");
            goto bail;
        }

        if (v->valueint > max_id) {
            max_id = v->valueint;
        }
    }

bail:
    return max_id;
}

bool user_exists_s_sess(int32_t user_id) {
    int32_t                 i;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        cJSON *v = cJSON_GetObjectItem(usess->root, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from user object");
            goto bail;
        }

        if (v->valueint == user_id) {
            return true;
            break;
        }
    }

bail:
    return false;
}

int32_t add_user_s_sess(server_t *srvr, int32_t user_idx) {
    int32_t                 rc = -1;
    cJSON                   *u_arr = NULL;
    cJSON                   *u = NULL;
    cJSON                   *u_id = NULL;
    cJSON                   *num_tasks = NULL;
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

    num_tasks = cJSON_CreateNumber(user->num_tasks);
    if (!num_tasks) goto bail;

    tasks = cJSON_CreateArray();
    if (!tasks) goto bail;

    cJSON_AddItemToObject(u, "id", u_id);
    cJSON_AddItemToObject(u, "num_tasks", num_tasks);
    cJSON_AddItemToObject(u, "tasks", tasks);
    cJSON_AddItemToArray(u_arr, u);

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    build_server_sess();

    user->id = srvr->new_client_id++;

    rc = 0;

bail:
    return rc;
}

bool task_exists_s_sess (int32_t uid, char *name) {
    int32_t                 i, j;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (uid == 0 || name == NULL) {
        avd_log_error("Invalid params received");
        goto bail;
    }

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from user object");
            goto bail;
        }

        if (v->valueint == uid) {
            for (j = 0; j < usess->num_tasks; j++) {
#define task usess->tasks[j]

                v = cJSON_GetObjectItem(task, "name");
                if ((!v) || (!v->valuestring)) {
                    avd_log_error("Malformed task in session file");
                    goto bail;
                }

                if (0 == strcmp(name, v->valuestring)) {
                    return true;
                }
#undef task
            }
        }
    }

bail:
    return false;
}

int32_t add_user_task_s_sess(int32_t uid, cJSON *task) {
    int32_t                 i, rc = -1;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if(!task) {
        avd_log_error("Failed to update session. value is empty");
        goto bail;
    }

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from user object");
            goto bail;
        }

        if (v->valueint == uid) {
            cJSON *task_arr = cJSON_GetObjectItem(usess->root, "tasks");
            cJSON_AddItemToArray(task_arr, task);

            if (0 != write_to_sess_file(sess->root)) {
                goto bail;
            }

            build_server_sess();
            return 0;
        }
    }

bail:
    return rc;
}

int32_t update_user_s_sess(int32_t uid, char *field, cJSON *value) {
    int32_t                 i, rc = -1;
    cJSON                   *v = NULL;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if(!value) {
        avd_log_error("Failed to update session. value is empty");
        goto bail;
    }

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

    for (i = 0; i < sess->num_users; i++) {
        avd_user_session_t  *usess = &sess->usess[i];

        v = cJSON_GetObjectItem(usess->root, "id");
        if ((!v) || (!v->valueint)) {
            avd_log_debug("cannot extract 'id' from user object");
            goto bail;
        }

        if (v->valueint == uid) {
            cJSON_ReplaceItemInObject(usess->root, field, value);

            if (0 != write_to_sess_file(sess->root)) {
                goto bail;
            }

            break;
        }
    }

    rc = 0;

bail:
    return rc;
}

int32_t remove_user_s_sess(int32_t uid) {
    int32_t                 i, rc = -1;
    int32_t                 uobj_sz;
    avd_server_session_t    *sess = (avd_server_session_t *)&g_srvr_session;

    if (!sess->root) {
        if (0 != build_server_sess()) {
            avd_log_error("Failed to build server session");
            goto bail;
        }
    }

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

        if (v->valueint == uid) {
            cJSON_DeleteItemFromArray(uobj_arr, i);

            if (0 != write_to_sess_file(sess->root)) {
                goto bail;
            }

            break;
        }
    }

    build_server_sess();
    rc = 0;
bail:
    return rc;
}

int32_t create_user_u_session(user_t *user) {
    int32_t                 i, rc = -1;
    cJSON                   *u_id = NULL;
    cJSON                   *poll_id = NULL;
    cJSON                   *task_arr = NULL;
    avd_user_session_t      *sess = (avd_user_session_t *)&g_user_session;

    if (file_exists(SESSION_FILE, F_OK)) {
        sess->root = parse_json(SESSION_FILE);
    } else {
        sess->root = cJSON_CreateObject();
        if (!sess->root) goto bail;

        u_id = cJSON_CreateNumber(user->id);
        if (!u_id) goto bail;

        poll_id = cJSON_CreateNumber(user->poll_id);
        if (!u_id) goto bail;

        task_arr = cJSON_CreateArray();
        if(!task_arr) goto bail;

        for (i = 0; i < user->num_tasks; i++) {
            cJSON *task = cJSON_CreateObject();

            cJSON_AddItemToObject(task, "name", cJSON_CreateString(user->tasks[i].name));
            cJSON_AddItemToObject(task, "sent", cJSON_CreateFalse());

            cJSON_AddItemToArray(task_arr, task);
        }

        cJSON_AddItemToObject(sess->root, "id", u_id);
        cJSON_AddItemToObject(sess->root, "poll_id", poll_id);
        cJSON_AddItemToObject(sess->root, "tasks", task_arr);
    }

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    rc = 0;

bail:
    return rc;
}

bool get_task_sent_u_sess (char *name) {
    int32_t                 i;
    cJSON                   *task_arr = NULL;
    avd_user_session_t      *sess = (avd_user_session_t *)&g_user_session;

    if (!sess->root) {
        if (file_exists(SESSION_FILE, F_OK)) {
            if (NULL == (sess->root = parse_json(SESSION_FILE))) {
                avd_log_error("Failed parsing JSON config");
                goto bail;
            }
        } else {
            avd_log_error("Failed to locate config file");
            goto bail;
        }
    }

    task_arr = cJSON_GetObjectItem(sess->root, "tasks");
    if(!task_arr) {
        avd_log_error("Cannot find 'tasks' in session object");
        goto bail;
    }

    for (i = 0; i < cJSON_GetArraySize(task_arr); i++) {
        cJSON   *task = cJSON_GetArrayItem(task_arr, i);

        cJSON   *v = cJSON_GetObjectItem(task, "name");
        if ((!v) || (!v->valuestring)) {
            avd_log_error("Failed to find 'name' in task %d", i);
            goto bail;
        }

        if (0 == strcmp(name, v->valuestring)) {
            if (cJSON_IsTrue(cJSON_GetObjectItem(task, "sent"))) {
                return true;
            }
        }
    }

bail:
    return false;
}

int32_t set_task_sent_u_sess (char *name) {
    int32_t                 i, rc = -1;
    cJSON                   *task_arr = NULL;
    avd_user_session_t      *sess = (avd_user_session_t *)&g_user_session;

    if (!sess->root) {
        if (file_exists(SESSION_FILE, F_OK)) {
            if (NULL == (sess->root = parse_json(SESSION_FILE))) {
                avd_log_error("Failed parsing JSON config");
                goto bail;
            }
        } else {
            avd_log_error("Failed to locate config file");
            goto bail;
        }
    }

    task_arr = cJSON_GetObjectItem(sess->root, "tasks");
    if(!task_arr) {
        avd_log_error("Cannot find 'tasks' in session object");
        goto bail;
    }

    for (i = 0; i < cJSON_GetArraySize(task_arr); i++) {
        cJSON   *task = cJSON_GetArrayItem(task_arr, i);

        cJSON   *v = cJSON_GetObjectItem(task, "name");
        if ((!v) || (!v->valuestring)) {
            avd_log_error("Failed to find 'name' in task %d", i);
            goto bail;
        }

        if (0 == strcmp(name, v->valuestring)) {
            cJSON_ReplaceItemInObject(task, "sent", cJSON_CreateTrue());
            rc = 0;
            break;
        }
    }

bail:
    return rc;
}

int32_t get_user_u_sess(user_t *user) {
    cJSON       *v = NULL;
    int32_t     rc = -1;
    avd_user_session_t      *sess = (avd_user_session_t *)&g_user_session;

    if (!sess->root) {
        if (file_exists(SESSION_FILE, F_OK)) {
            if (NULL == (sess->root = parse_json(SESSION_FILE))) {
                avd_log_error("Failed parsing JSON config");
                goto bail;
            }
        } else {
            avd_log_error("Failed to locate config file");
            goto bail;
        }
    }

    v = cJSON_GetObjectItem(sess->root, "id");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find 'id' in session file");
        goto bail;
    }
    user->id = v->valueint;

    v = cJSON_GetObjectItem(sess->root, "poll_id");
    if ((!v) || (!v->valueint)) {
        avd_log_error("Failed to find 'poll_id' in session file");
        goto bail;
    }
    user->poll_id = v->valueint;

    rc = 0;

bail:
    return rc;
}

int32_t update_user_u_session(char *field, cJSON *value) {
    int32_t                 rc = -1;
    avd_user_session_t    *sess = (avd_user_session_t *)&g_user_session;

    if(!value) {
        avd_log_error("Failed to update session. value is empty");
        goto bail;
    }

    if (!sess->root) {
        if (file_exists(SESSION_FILE, F_OK)) {
            if (NULL == (sess->root = parse_json(SESSION_FILE))) {
                avd_log_error("Failed parsing JSON config");
                goto bail;
            }
        } else {
            avd_log_error("Failed to locate config file");
            goto bail;
        }
    }

    cJSON_ReplaceItemInObject(sess->root, field, value);

    if (0 != write_to_sess_file(sess->root)) {
        goto bail;
    }

    rc = 0;

bail:
    return rc;
}

#endif
